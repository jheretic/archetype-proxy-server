// Discovery: providers yield dynamic Routes that are hot-merged into the live
// route table. Static config (server/attestation/which providers are enabled)
// is resolved once at boot and never reloads here.

pub mod docker;
pub mod k8s;
pub mod labels;

use std::collections::BTreeMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio::sync::mpsc;

use crate::config::{Route, RouteTable};

/// A provider's full current snapshot of routes. Providers send a complete
/// replacement set (not deltas) so the manager can recompute deterministically.
#[derive(Debug, Clone)]
pub struct ProviderUpdate {
    pub provider: &'static str,
    pub routes: Vec<Route>,
}

/// A discovery source that pushes route snapshots until cancelled.
#[async_trait::async_trait]
pub trait DiscoveryProvider: Send + Sync {
    fn name(&self) -> &'static str;

    /// Run until the channel closes or the provider gives up. Implementations
    /// MUST NOT panic on transient backend errors — log and keep the proxy
    /// serving file/env routes.
    async fn run(self: Box<Self>, tx: mpsc::Sender<ProviderUpdate>);
}

/// Owns the live route table and merges file routes with per-provider snapshots.
pub struct RouteManager {
    file_routes: Vec<Route>,
    provider_routes: BTreeMap<&'static str, Vec<Route>>,
    table: Arc<ArcSwap<RouteTable>>,
}

impl RouteManager {
    pub fn new(file_routes: Vec<Route>) -> Self {
        let table = Arc::new(ArcSwap::from_pointee(RouteTable::new(file_routes.clone())));
        Self {
            file_routes,
            provider_routes: BTreeMap::new(),
            table,
        }
    }

    /// Shared handle the proxy reads on every request.
    pub fn handle(&self) -> Arc<ArcSwap<RouteTable>> {
        self.table.clone()
    }

    fn recompute(&self) {
        let mut all = self.file_routes.clone();
        for routes in self.provider_routes.values() {
            all.extend(routes.iter().cloned());
        }
        self.table.store(Arc::new(RouteTable::new(all)));
    }

    /// Consume provider updates until all senders drop. Runs on its own task.
    pub async fn run(mut self, mut rx: mpsc::Receiver<ProviderUpdate>) {
        while let Some(update) = rx.recv().await {
            let count = update.routes.len();
            self.provider_routes.insert(update.provider, update.routes);
            self.recompute();
            tracing::info!(
                provider = update.provider,
                routes = count,
                total = self.table.load().routes().len(),
                "route table updated"
            );
        }
    }
}

/// Build the enabled providers from static config. Returns an empty vec when
/// discovery is disabled. Errors constructing a provider are logged and the
/// provider is skipped (the proxy still serves file/env routes).
pub fn build_providers(cfg: &crate::config::DiscoveryConfig) -> Vec<Box<dyn DiscoveryProvider>> {
    let mut providers: Vec<Box<dyn DiscoveryProvider>> = Vec::new();

    if cfg.docker.enabled {
        providers.push(Box::new(docker::DockerProvider::new(
            cfg.docker.socket.clone(),
            cfg.docker.poll_secs,
        )));
    }
    if cfg.kubernetes.enabled {
        providers.push(Box::new(k8s::KubernetesProvider::new(
            cfg.kubernetes.namespace.clone(),
        )));
    }
    providers
}
