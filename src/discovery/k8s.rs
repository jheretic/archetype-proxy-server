// Kubernetes discovery — annotation-based, via `archetype.li/*` annotations on
// Services/Ingresses.
//
// The pure annotation -> Route mapping (`route_from_annotations`) is always
// compiled and unit-tested. The live kube-rs watcher is gated behind the
// `kubernetes` cargo feature (task #15): the DEFAULT build does NOT pull the
// heavy `kube` + `k8s-openapi` dependency tree and keeps the warn-and-yield
// stub, so `[discovery] kubernetes = true` still doesn't crash a lean build.
// Build the watcher with `cargo build --features kubernetes`.
//
// Annotation schema (per Service/Ingress):
//   archetype.li/enable = "true"            (required to opt in)
//   archetype.li/upstream = "http://svc:80" (required)
//   archetype.li/host = "api.internal"      (optional)
//   archetype.li/path-prefix = "/v1"        (optional)
//   archetype.li/strict = "true"            (optional)
//
// RBAC (when the feature is enabled): the ServiceAccount the proxy runs as needs
// get/list/watch on `services` (core API group, "") and `ingresses`
// (networking.k8s.io). Namespace-scoped when a namespace filter is set, cluster
// scoped (ClusterRole + ClusterRoleBinding) when watching all namespaces. See
// README "Kubernetes discovery".

use std::collections::BTreeMap;

// Only the stub impl (feature off) uses these directly; the live watcher in the
// `watch` submodule imports its own. Gate to avoid unused-import warnings under
// `--features kubernetes`.
#[cfg(not(feature = "kubernetes"))]
use super::{DiscoveryProvider, ProviderUpdate};
#[cfg(not(feature = "kubernetes"))]
use tokio::sync::mpsc;

use crate::config::{Route, Source, parse_bool_token};

const ENABLE: &str = "archetype.li/enable";
const UPSTREAM: &str = "archetype.li/upstream";
const HOST: &str = "archetype.li/host";
const PATH_PREFIX: &str = "archetype.li/path-prefix";
const STRICT: &str = "archetype.li/strict";

/// Pure mapping from a K8s object's name + annotations to an optional Route.
/// Returns None if not enabled or missing an upstream.
pub fn route_from_annotations(
    object_name: &str,
    annotations: &BTreeMap<String, String>,
) -> Option<Route> {
    if annotations.get(ENABLE).and_then(|v| parse_bool_token(v)) != Some(true) {
        return None;
    }
    let upstream = annotations.get(UPSTREAM)?.clone();
    Some(Route {
        name: format!("k8s/{object_name}"),
        host: annotations.get(HOST).cloned().unwrap_or_default(),
        path_prefix: annotations.get(PATH_PREFIX).cloned().unwrap_or_default(),
        upstream,
        strict_attestation: annotations.get(STRICT).and_then(|v| parse_bool_token(v)),
        source: Source::Discovered,
    })
}

pub struct KubernetesProvider {
    namespace: Option<String>,
}

impl KubernetesProvider {
    pub fn new(namespace: Option<String>) -> Self {
        Self { namespace }
    }
}

// ---------------------------------------------------------------------------
// Stub provider — compiled when the `kubernetes` feature is OFF (default).
// Keeps `[discovery] kubernetes = true` non-fatal on a lean build.
// ---------------------------------------------------------------------------
#[cfg(not(feature = "kubernetes"))]
#[async_trait::async_trait]
impl DiscoveryProvider for KubernetesProvider {
    fn name(&self) -> &'static str {
        "kubernetes"
    }

    async fn run(self: Box<Self>, _tx: mpsc::Sender<ProviderUpdate>) {
        tracing::warn!(
            namespace = ?self.namespace,
            "kubernetes discovery is enabled but this binary was built WITHOUT the `kubernetes` \
             cargo feature; the watcher is not compiled in. Rebuild with \
             `--features kubernetes` to enable it. Running with file/env routes only."
        );
    }
}

// ---------------------------------------------------------------------------
// Live watcher — compiled when the `kubernetes` feature is ON.
// ---------------------------------------------------------------------------
#[cfg(feature = "kubernetes")]
mod watch {
    use std::collections::BTreeMap;

    use futures_util::StreamExt;
    use k8s_openapi::api::core::v1::Service;
    use k8s_openapi::api::networking::v1::Ingress;
    use kube::runtime::watcher::{self, Event};
    use kube::{Api, Client, Resource};
    use tokio::sync::mpsc;

    use super::{KubernetesProvider, route_from_annotations};
    use crate::config::Route;
    use crate::discovery::{DiscoveryProvider, ProviderUpdate};

    /// Which resource kind a store update came from.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Kind {
        Service,
        Ingress,
    }

    /// A kind-tagged, K-type-erased reconciliation operation derived from a
    /// single watcher event. Erasing the object type here lets us merge the
    /// Service and Ingress streams into one processing loop.
    #[derive(Debug, Clone)]
    enum Op {
        /// Watch (re)started: begin buffering a fresh snapshot for this kind.
        Init,
        /// An object observed during (re)list. `route` is None if the object
        /// is not opted in (no/invalid annotations).
        InitApply { key: String, route: Option<Route> },
        /// Initial list complete: atomically replace this kind's store.
        InitDone,
        /// An object was added/modified after init.
        Apply { key: String, route: Option<Route> },
        /// An object was deleted.
        Delete { key: String },
    }

    /// Stable per-object key (`namespace/name`) for store bookkeeping.
    fn object_key<K: Resource>(obj: &K) -> String {
        let meta = obj.meta();
        let ns = meta.namespace.as_deref().unwrap_or("");
        let name = meta.name.as_deref().unwrap_or("");
        format!("{ns}/{name}")
    }

    /// Reconcile a single object to an optional Route via the shared annotation
    /// mapping. Pure; unit-tested against synthetic objects (see tests below).
    fn route_from_object<K: Resource>(obj: &K) -> Option<Route> {
        let meta = obj.meta();
        let name = meta.name.clone().unwrap_or_default();
        let annotations = meta.annotations.clone().unwrap_or_default();
        route_from_annotations(&name, &annotations)
    }

    /// Convert a typed watcher event into a type-erased `Op`.
    fn to_op<K: Resource>(event: Event<K>) -> Op {
        match event {
            Event::Init => Op::Init,
            Event::InitDone => Op::InitDone,
            Event::InitApply(obj) => Op::InitApply {
                key: object_key(&obj),
                route: route_from_object(&obj),
            },
            Event::Apply(obj) => Op::Apply {
                key: object_key(&obj),
                route: route_from_object(&obj),
            },
            Event::Delete(obj) => Op::Delete {
                key: object_key(&obj),
            },
        }
    }

    /// Holds the committed routes for one kind plus an in-flight (re)list
    /// buffer. `Init`/`InitApply`/`InitDone` fill the buffer then swap it in
    /// atomically, so a reconnect never exposes a partial snapshot.
    #[derive(Default)]
    struct KindStore {
        committed: BTreeMap<String, Route>,
        buffer: Option<BTreeMap<String, Route>>,
    }

    impl KindStore {
        /// Apply one op; returns true if the committed set changed.
        fn apply(&mut self, op: Op) -> bool {
            match op {
                Op::Init => {
                    self.buffer = Some(BTreeMap::new());
                    false
                }
                Op::InitApply { key, route } => {
                    if let Some(buf) = self.buffer.as_mut()
                        && let Some(r) = route
                    {
                        buf.insert(key, r);
                    }
                    false
                }
                Op::InitDone => {
                    let new = self.buffer.take().unwrap_or_default();
                    let changed = new != self.committed;
                    self.committed = new;
                    changed
                }
                Op::Apply { key, route } => match route {
                    Some(r) => {
                        let changed = self.committed.get(&key) != Some(&r);
                        self.committed.insert(key, r);
                        changed
                    }
                    // Object lost its opt-in annotations: drop any prior route.
                    None => self.committed.remove(&key).is_some(),
                },
                Op::Delete { key } => self.committed.remove(&key).is_some(),
            }
        }

        fn routes(&self) -> impl Iterator<Item = &Route> {
            self.committed.values()
        }
    }

    #[async_trait::async_trait]
    impl DiscoveryProvider for KubernetesProvider {
        fn name(&self) -> &'static str {
            "kubernetes"
        }

        async fn run(self: Box<Self>, tx: mpsc::Sender<ProviderUpdate>) {
            // RESILIENT: failure to build a client (no kubeconfig, no in-cluster
            // SA, unreachable API) must NOT crash the proxy. Log and return; the
            // proxy keeps serving file/env routes.
            let client = match Client::try_default().await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(
                        namespace = ?self.namespace,
                        error = %e,
                        "kubernetes discovery: cannot construct API client (no kubeconfig / \
                         in-cluster SA / API unreachable); serving file/env routes only"
                    );
                    return;
                }
            };

            let (services, ingresses): (Api<Service>, Api<Ingress>) = match &self.namespace {
                Some(ns) => (
                    Api::namespaced(client.clone(), ns),
                    Api::namespaced(client, ns),
                ),
                None => (Api::all(client.clone()), Api::all(client)),
            };

            tracing::info!(
                namespace = ?self.namespace,
                "kubernetes discovery: watching Services and Ingresses"
            );

            // kube-rs `watcher` handles list+watch, resync, and reconnect with
            // backoff internally; an `Err` item is a transient watch failure we
            // log and ride through (the stream re-`Init`s on recovery).
            let svc_stream = watcher::watcher(services, watcher::Config::default())
                .map(|res| res.map(|ev| (Kind::Service, to_op(ev))));
            let ing_stream = watcher::watcher(ingresses, watcher::Config::default())
                .map(|res| res.map(|ev| (Kind::Ingress, to_op(ev))));
            // The watcher streams are `!Unpin`; pin the merged stream on the
            // heap so we can poll it in the loop below.
            let mut merged = Box::pin(futures_util::stream::select(svc_stream, ing_stream));

            let mut svc_store = KindStore::default();
            let mut ing_store = KindStore::default();
            let mut last_sent: Option<Vec<Route>> = None;

            while let Some(item) = merged.next().await {
                let (kind, op) = match item {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "kubernetes discovery: watch error; kube-rs will resync/reconnect"
                        );
                        continue;
                    }
                };

                let changed = match kind {
                    Kind::Service => svc_store.apply(op),
                    Kind::Ingress => ing_store.apply(op),
                };
                if !changed {
                    continue;
                }

                let routes: Vec<Route> = svc_store
                    .routes()
                    .chain(ing_store.routes())
                    .cloned()
                    .collect();
                if last_sent.as_ref() == Some(&routes) {
                    continue;
                }
                if tx
                    .send(ProviderUpdate {
                        provider: "kubernetes",
                        routes: routes.clone(),
                    })
                    .await
                    .is_err()
                {
                    return; // manager gone
                }
                last_sent = Some(routes);
            }

            tracing::warn!(
                "kubernetes discovery: watch streams ended; serving file/env routes only"
            );
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use k8s_openapi::api::core::v1::Service;
        use k8s_openapi::api::networking::v1::Ingress;
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

        fn annotations(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect()
        }

        fn service(ns: &str, name: &str, ann: &[(&str, &str)]) -> Service {
            Service {
                metadata: ObjectMeta {
                    name: Some(name.to_owned()),
                    namespace: Some(ns.to_owned()),
                    annotations: Some(annotations(ann)),
                    ..Default::default()
                },
                ..Default::default()
            }
        }

        fn ingress(ns: &str, name: &str, ann: &[(&str, &str)]) -> Ingress {
            Ingress {
                metadata: ObjectMeta {
                    name: Some(name.to_owned()),
                    namespace: Some(ns.to_owned()),
                    annotations: Some(annotations(ann)),
                    ..Default::default()
                },
                ..Default::default()
            }
        }

        #[test]
        fn object_key_is_namespace_slash_name() {
            let s = service("prod", "api", &[]);
            assert_eq!(object_key(&s), "prod/api");
        }

        #[test]
        fn synthetic_service_reconciles_to_route() {
            let s = service(
                "prod",
                "api",
                &[
                    ("archetype.li/enable", "true"),
                    ("archetype.li/upstream", "http://api:80"),
                    ("archetype.li/host", "api.internal"),
                ],
            );
            let r = route_from_object(&s).expect("opted-in service yields a route");
            assert_eq!(r.name, "k8s/api");
            assert_eq!(r.upstream, "http://api:80");
            assert_eq!(r.host, "api.internal");
        }

        #[test]
        fn synthetic_ingress_reconciles_to_route() {
            let i = ingress(
                "prod",
                "web",
                &[
                    ("archetype.li/enable", "true"),
                    ("archetype.li/upstream", "http://web:8080"),
                    ("archetype.li/path-prefix", "/app"),
                ],
            );
            let r = route_from_object(&i).expect("opted-in ingress yields a route");
            assert_eq!(r.name, "k8s/web");
            assert_eq!(r.path_prefix, "/app");
        }

        #[test]
        fn not_opted_in_object_yields_no_route() {
            let s = service("prod", "api", &[("archetype.li/enable", "false")]);
            assert!(route_from_object(&s).is_none());
            let bare = service("prod", "other", &[]);
            assert!(route_from_object(&bare).is_none());
        }

        // -- KindStore reconciliation: the object -> Vec<Route> snapshot logic --

        fn opted(ns: &str, name: &str, upstream: &str) -> Service {
            service(
                ns,
                name,
                &[
                    ("archetype.li/enable", "true"),
                    ("archetype.li/upstream", upstream),
                ],
            )
        }

        fn collect(store: &KindStore) -> Vec<String> {
            store.routes().map(|r| r.name.clone()).collect()
        }

        #[test]
        fn init_buffer_swaps_in_atomically() {
            let mut store = KindStore::default();
            // Pre-existing committed route from a prior session.
            assert!(store.apply(to_op(Event::Apply(opted("prod", "old", "http://old:80")))));
            assert_eq!(collect(&store), vec!["k8s/old"]);

            // A relist begins: Init clears the buffer but committed is untouched
            // until InitDone, so we never expose a partial snapshot.
            assert!(!store.apply(to_op(Event::<Service>::Init)));
            assert_eq!(collect(&store), vec!["k8s/old"], "committed stable during relist");
            assert!(!store.apply(to_op(Event::InitApply(opted("prod", "new", "http://new:80")))));
            assert_eq!(collect(&store), vec!["k8s/old"], "buffer not yet committed");

            // InitDone swaps the buffer in: old is gone, new is present.
            assert!(store.apply(to_op(Event::<Service>::InitDone)));
            assert_eq!(collect(&store), vec!["k8s/new"]);
        }

        #[test]
        fn apply_then_delete_round_trips() {
            let mut store = KindStore::default();
            assert!(store.apply(to_op(Event::Apply(opted("prod", "api", "http://api:80")))));
            assert_eq!(collect(&store), vec!["k8s/api"]);
            // Re-applying an identical object is a no-op (no spurious snapshot).
            assert!(!store.apply(to_op(Event::Apply(opted("prod", "api", "http://api:80")))));
            // Delete removes it.
            assert!(store.apply(to_op(Event::Delete(opted("prod", "api", "http://api:80")))));
            assert!(collect(&store).is_empty());
            // Deleting again changes nothing.
            assert!(!store.apply(to_op(Event::Delete(opted("prod", "api", "http://api:80")))));
        }

        #[test]
        fn losing_optin_annotations_drops_the_route() {
            let mut store = KindStore::default();
            assert!(store.apply(to_op(Event::Apply(opted("prod", "api", "http://api:80")))));
            // Object updated to disable: Apply with no route must drop it.
            let disabled = service("prod", "api", &[("archetype.li/enable", "false")]);
            assert!(store.apply(to_op(Event::Apply(disabled))));
            assert!(collect(&store).is_empty());
        }

        #[test]
        fn empty_initdone_clears_committed() {
            let mut store = KindStore::default();
            assert!(store.apply(to_op(Event::Apply(opted("prod", "api", "http://api:80")))));
            assert!(!store.apply(to_op(Event::<Service>::Init)));
            // No InitApply objects this time -> InitDone with empty buffer clears.
            assert!(store.apply(to_op(Event::<Service>::InitDone)));
            assert!(collect(&store).is_empty());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn disabled_yields_none() {
        assert!(route_from_annotations("svc", &map(&[("archetype.li/enable", "false")])).is_none());
        assert!(route_from_annotations("svc", &map(&[])).is_none());
    }

    #[test]
    fn enabled_without_upstream_none() {
        let a = map(&[("archetype.li/enable", "true")]);
        assert!(route_from_annotations("svc", &a).is_none());
    }

    #[test]
    fn full_annotation_set() {
        let a = map(&[
            ("archetype.li/enable", "true"),
            ("archetype.li/upstream", "http://svc:80"),
            ("archetype.li/host", "api.internal"),
            ("archetype.li/path-prefix", "/v1"),
            ("archetype.li/strict", "true"),
        ]);
        let r = route_from_annotations("api-svc", &a).unwrap();
        assert_eq!(r.name, "k8s/api-svc");
        assert_eq!(r.upstream, "http://svc:80");
        assert_eq!(r.host, "api.internal");
        assert_eq!(r.path_prefix, "/v1");
        assert_eq!(r.strict_attestation, Some(true));
        assert_eq!(r.source, Source::Discovered);
    }
}
