// Docker label discovery (Traefik-style). Polls the Docker socket, reads
// `archetype.*` labels off running containers, maps them to Routes.
//
// Security: access to the Docker socket is root-equivalent on the host. Gated
// behind `[discovery] docker = true` (off by default). Prefer a read-only
// docker-socket-proxy. See README.
//
// If the socket is absent or Docker is down, the provider logs a warning and
// keeps polling; the proxy continues serving file/env routes.

use std::collections::BTreeMap;
use std::time::Duration;

use bollard::Docker;
use bollard::query_parameters::ListContainersOptions;
use tokio::sync::mpsc;

use super::labels::routes_from_labels;
use super::{DiscoveryProvider, ProviderUpdate};
use crate::config::Route;

pub struct DockerProvider {
    socket: String,
    poll: Duration,
}

impl DockerProvider {
    pub fn new(socket: String, poll_secs: u64) -> Self {
        Self {
            socket,
            poll: Duration::from_secs(poll_secs.max(1)),
        }
    }

    fn connect(&self) -> Result<Docker, bollard::errors::Error> {
        match socket_kind(&self.socket) {
            SocketKind::Unix => {
                Docker::connect_with_unix(&self.socket, 120, bollard::API_DEFAULT_VERSION)
            }
            SocketKind::Http => {
                Docker::connect_with_http(&self.socket, 120, bollard::API_DEFAULT_VERSION)
            }
        }
    }

    async fn poll_once(docker: &Docker) -> Result<Vec<Route>, bollard::errors::Error> {
        let opts = ListContainersOptions {
            all: false,
            ..Default::default()
        };
        let containers = docker.list_containers(Some(opts)).await?;
        let mut routes = Vec::new();
        for c in containers {
            let labels: BTreeMap<String, String> = c.labels.unwrap_or_default().into_iter().collect();
            let id = c.id.unwrap_or_default();
            let (mut r, warnings) = routes_from_labels(&id, &labels);
            for w in warnings {
                tracing::warn!(container = %short(&id), "{w}");
            }
            routes.append(&mut r);
        }
        Ok(routes)
    }
}

fn short(id: &str) -> String {
    id.chars().take(12).collect()
}

#[derive(Debug, PartialEq, Eq)]
enum SocketKind {
    Unix,
    Http,
}

/// Choose the bollard connector for a socket string. `unix://` => Unix socket,
/// anything else (http://, tcp://) => HTTP.
fn socket_kind(socket: &str) -> SocketKind {
    if socket.starts_with("unix://") {
        SocketKind::Unix
    } else {
        SocketKind::Http
    }
}

#[async_trait::async_trait]
impl DiscoveryProvider for DockerProvider {
    fn name(&self) -> &'static str {
        "docker"
    }

    async fn run(self: Box<Self>, tx: mpsc::Sender<ProviderUpdate>) {
        // Connect lazily in the loop so a socket that appears after startup is
        // picked up on a later poll. The provider retries indefinitely; the
        // proxy serves file/env routes meanwhile.
        let mut docker: Option<Docker> = None;
        let mut last: Option<Vec<Route>> = None;
        let mut warned_connect = false;
        loop {
            if docker.is_none() {
                match self.connect() {
                    Ok(d) => {
                        if warned_connect {
                            tracing::info!(socket = %self.socket, "docker discovery: connected");
                        }
                        warned_connect = false;
                        docker = Some(d);
                    }
                    Err(e) => {
                        if !warned_connect {
                            tracing::warn!(socket = %self.socket, error = %e,
                                "docker discovery: cannot connect; serving file/env routes only, will retry");
                            warned_connect = true;
                        }
                        tokio::time::sleep(self.poll).await;
                        continue;
                    }
                }
            }

            match Self::poll_once(docker.as_ref().expect("docker connected")).await {
                Ok(routes) => {
                    let changed = last.as_ref() != Some(&routes);
                    if changed {
                        if tx
                            .send(ProviderUpdate {
                                provider: "docker",
                                routes: routes.clone(),
                            })
                            .await
                            .is_err()
                        {
                            return; // route manager dropped the receiver
                        }
                        last = Some(routes);
                    }
                }
                Err(e) => {
                    // Drop the client; the next iteration reconnects, handling
                    // daemon restarts and dropped sockets.
                    tracing::warn!(error = %e, "docker discovery poll failed; will reconnect and retry");
                    docker = None;
                }
            }
            tokio::time::sleep(self.poll).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_kind_dispatch() {
        assert_eq!(socket_kind("unix:///var/run/docker.sock"), SocketKind::Unix);
        assert_eq!(socket_kind("http://127.0.0.1:2375"), SocketKind::Http);
        assert_eq!(socket_kind("tcp://127.0.0.1:2375"), SocketKind::Http);
    }

    #[test]
    fn short_truncates_to_12() {
        assert_eq!(short("deadbeefcafe0000"), "deadbeefcafe");
        assert_eq!(short("abc"), "abc");
    }
}
