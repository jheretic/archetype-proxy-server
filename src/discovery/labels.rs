// Pure parsing of `archetype.*` container labels into Routes. No I/O here so
// the mapping is unit-testable without a live Docker daemon.
//
// Label schema (per container):
//   archetype.enable = true                      (required to opt in)
//   archetype.attestation.strict = true          (optional, container-global default)
//   archetype.route.<name>.host = api.internal   (optional)
//   archetype.route.<name>.upstream = http://api:8080   (required per route)
//   archetype.route.<name>.pathprefix = /v1      (optional)
//   archetype.route.<name>.strict = true         (optional, per-route override)
//
// A container may declare multiple routes via distinct <name> segments. If a
// container is enabled but declares no `archetype.route.*` keys, a single
// implicit route named after the container is created IF a top-level
// `archetype.upstream` is present.

use std::collections::BTreeMap;

use crate::config::{Route, Source, parse_bool_token};

const NS: &str = "archetype.";
const ENABLE_KEY: &str = "archetype.enable";
const GLOBAL_STRICT_KEY: &str = "archetype.attestation.strict";
const IMPLICIT_UPSTREAM_KEY: &str = "archetype.upstream";
const ROUTE_PREFIX: &str = "archetype.route.";

/// Parse one container's label map into zero or more Routes.
///
/// `container_id` disambiguates auto-generated route names across containers.
/// Returns an empty Vec if the container is not enabled or declares no usable
/// upstream. Routes missing an `upstream` are skipped (logged by the caller via
/// the returned `warnings`).
pub fn routes_from_labels(
    container_id: &str,
    labels: &BTreeMap<String, String>,
) -> (Vec<Route>, Vec<String>) {
    let mut warnings = Vec::new();

    if labels
        .get(ENABLE_KEY)
        .and_then(|v| parse_bool_token(v))
        != Some(true)
    {
        return (Vec::new(), warnings);
    }

    let global_strict = labels
        .get(GLOBAL_STRICT_KEY)
        .and_then(|v| parse_bool_token(v));

    // Group keys by route name: archetype.route.<name>.<field>.
    let mut grouped: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for (k, v) in labels {
        let Some(rest) = k.strip_prefix(ROUTE_PREFIX) else {
            continue;
        };
        // rest = "<name>.<field>"; split on the LAST dot so names may not
        // contain dots but fields are simple identifiers.
        let Some((name, field)) = rest.rsplit_once('.') else {
            warnings.push(format!("ignoring malformed route label `{k}`"));
            continue;
        };
        grouped
            .entry(name.to_owned())
            .or_default()
            .insert(field.to_ascii_lowercase(), v.clone());
    }

    let mut routes = Vec::new();

    for (name, fields) in &grouped {
        let Some(upstream) = fields.get("upstream") else {
            warnings.push(format!("route `{name}` missing `upstream`; skipped"));
            continue;
        };
        let strict = fields
            .get("strict")
            .and_then(|v| parse_bool_token(v))
            .or(global_strict);
        routes.push(Route {
            name: format!("docker/{}/{name}", short(container_id)),
            host: fields.get("host").cloned().unwrap_or_default(),
            path_prefix: fields.get("pathprefix").cloned().unwrap_or_default(),
            upstream: upstream.clone(),
            strict_attestation: strict,
            source: Source::Discovered,
        });
    }

    // Implicit single route when no explicit routes but a top-level upstream.
    if routes.is_empty() {
        if let Some(upstream) = labels.get(IMPLICIT_UPSTREAM_KEY) {
            routes.push(Route {
                name: format!("docker/{}", short(container_id)),
                host: labels
                    .get("archetype.host")
                    .cloned()
                    .unwrap_or_default(),
                path_prefix: labels
                    .get("archetype.pathprefix")
                    .cloned()
                    .unwrap_or_default(),
                upstream: upstream.clone(),
                strict_attestation: global_strict,
                source: Source::Discovered,
            });
        } else {
            warnings.push(format!(
                "container {} enabled but declares no routes",
                short(container_id)
            ));
        }
    }

    let _ = NS; // namespace constant kept for documentation/grep.
    (routes, warnings)
}

fn short(id: &str) -> String {
    id.chars().take(12).collect()
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
    fn disabled_container_yields_nothing() {
        let (routes, _) = routes_from_labels("abc", &map(&[("archetype.enable", "false")]));
        assert!(routes.is_empty());
        let (routes, _) = routes_from_labels("abc", &map(&[("other.label", "x")]));
        assert!(routes.is_empty());
    }

    #[test]
    fn single_named_route() {
        let labels = map(&[
            ("archetype.enable", "true"),
            ("archetype.route.api.host", "api.internal"),
            ("archetype.route.api.upstream", "http://api:8080"),
            ("archetype.route.api.pathprefix", "/v1"),
        ]);
        let (routes, warnings) = routes_from_labels("deadbeefcafe0000", &labels);
        assert_eq!(routes.len(), 1);
        let r = &routes[0];
        assert_eq!(r.host, "api.internal");
        assert_eq!(r.upstream, "http://api:8080");
        assert_eq!(r.path_prefix, "/v1");
        assert_eq!(r.name, "docker/deadbeefcafe/api");
        assert_eq!(r.source, Source::Discovered);
        assert!(warnings.is_empty());
    }

    #[test]
    fn multiple_routes_per_container() {
        let labels = map(&[
            ("archetype.enable", "true"),
            ("archetype.route.a.upstream", "http://a:1"),
            ("archetype.route.b.upstream", "http://b:2"),
            ("archetype.route.b.host", "b.internal"),
        ]);
        let (mut routes, _) = routes_from_labels("c1", &labels);
        routes.sort_by(|x, y| x.upstream.cmp(&y.upstream));
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].upstream, "http://a:1");
        assert_eq!(routes[1].host, "b.internal");
    }

    #[test]
    fn per_route_strict_overrides_global() {
        let labels = map(&[
            ("archetype.enable", "true"),
            ("archetype.attestation.strict", "true"),
            ("archetype.route.a.upstream", "http://a:1"),
            ("archetype.route.a.strict", "false"),
            ("archetype.route.b.upstream", "http://b:2"),
        ]);
        let (routes, _) = routes_from_labels("c1", &labels);
        let a = routes.iter().find(|r| r.upstream == "http://a:1").unwrap();
        let b = routes.iter().find(|r| r.upstream == "http://b:2").unwrap();
        assert_eq!(a.strict_attestation, Some(false));
        assert_eq!(b.strict_attestation, Some(true));
    }

    #[test]
    fn missing_upstream_warns_and_skips() {
        let labels = map(&[
            ("archetype.enable", "true"),
            ("archetype.route.a.host", "a.internal"),
        ]);
        let (routes, warnings) = routes_from_labels("c1", &labels);
        assert!(routes.is_empty());
        assert!(warnings.iter().any(|w| w.contains("missing `upstream`")));
    }

    #[test]
    fn implicit_route_from_top_level_upstream() {
        let labels = map(&[
            ("archetype.enable", "true"),
            ("archetype.upstream", "http://solo:9000"),
            ("archetype.host", "solo.internal"),
        ]);
        let (routes, _) = routes_from_labels("abcdef123456", &labels);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].upstream, "http://solo:9000");
        assert_eq!(routes[0].host, "solo.internal");
        assert_eq!(routes[0].name, "docker/abcdef123456");
    }

    #[test]
    fn enabled_but_no_routes_warns() {
        let (routes, warnings) = routes_from_labels("c1", &map(&[("archetype.enable", "true")]));
        assert!(routes.is_empty());
        assert!(warnings.iter().any(|w| w.contains("no routes")));
    }
}
