//! Process metrics exposed in Prometheus text format at `/metrics`. Uses
//! plain atomics rather than the `metrics`/`metrics-exporter-prometheus`
//! crates to keep the dependency surface small; the counters are incremented
//! at the proxy hot-path edges.
//!
//! Exposed series:
//!   * `archetype_proxy_handshakes_total`        (counter)
//!   * `archetype_proxy_active_sessions`         (gauge, sampled from registry)
//!   * `archetype_proxy_decrypt_failures_total`  (counter)
//!   * `archetype_proxy_upstream_requests_total` (counter)
//!   * `archetype_proxy_upstream_errors_total`   (counter)
//!   * `archetype_proxy_upstream_latency_seconds`(histogram)

use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Upstream-latency histogram bucket upper bounds (seconds). The implicit
/// `+Inf` bucket is added on render.
const LATENCY_BUCKETS_SECS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Shared metrics handle. Cheap to clone (Arc).
#[derive(Clone)]
pub struct Metrics(Arc<Inner>);

struct Inner {
    handshakes_total: AtomicU64,
    decrypt_failures_total: AtomicU64,
    upstream_requests_total: AtomicU64,
    upstream_errors_total: AtomicU64,
    /// Cumulative bucket counts (one per `LATENCY_BUCKETS_SECS` entry).
    latency_buckets: Vec<AtomicU64>,
    /// `+Inf` bucket / total observation count.
    latency_count: AtomicU64,
    /// Sum of all observed latencies, in microseconds (integer to stay atomic).
    latency_sum_micros: AtomicU64,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    #[must_use]
    pub fn new() -> Self {
        let latency_buckets = LATENCY_BUCKETS_SECS.iter().map(|_| AtomicU64::new(0)).collect();
        Self(Arc::new(Inner {
            handshakes_total: AtomicU64::new(0),
            decrypt_failures_total: AtomicU64::new(0),
            upstream_requests_total: AtomicU64::new(0),
            upstream_errors_total: AtomicU64::new(0),
            latency_buckets,
            latency_count: AtomicU64::new(0),
            latency_sum_micros: AtomicU64::new(0),
        }))
    }

    pub fn inc_handshakes(&self) {
        self.0.handshakes_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_decrypt_failures(&self) {
        self.0.decrypt_failures_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_upstream_requests(&self) {
        self.0.upstream_requests_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_upstream_errors(&self) {
        self.0.upstream_errors_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record one upstream round-trip latency observation.
    pub fn observe_upstream_latency(&self, secs: f64) {
        for (i, ub) in LATENCY_BUCKETS_SECS.iter().enumerate() {
            if secs <= *ub {
                self.0.latency_buckets[i].fetch_add(1, Ordering::Relaxed);
            }
        }
        self.0.latency_count.fetch_add(1, Ordering::Relaxed);
        let micros = (secs * 1_000_000.0).round() as u64;
        self.0.latency_sum_micros.fetch_add(micros, Ordering::Relaxed);
    }

    /// Render the full Prometheus text exposition. `active_sessions` is sampled
    /// by the caller from the AtB registry at scrape time.
    #[must_use]
    pub fn render_prometheus(&self, active_sessions: usize) -> String {
        let i = &self.0;
        let mut out = String::with_capacity(1024);

        let counter = |out: &mut String, name: &str, help: &str, v: u64| {
            let _ = writeln!(out, "# HELP {name} {help}");
            let _ = writeln!(out, "# TYPE {name} counter");
            let _ = writeln!(out, "{name} {v}");
        };

        counter(
            &mut out,
            "archetype_proxy_handshakes_total",
            "Total attestation handshakes served on /attest.",
            i.handshakes_total.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "archetype_proxy_decrypt_failures_total",
            "Total trusted-request decrypt/MAC verification failures.",
            i.decrypt_failures_total.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "archetype_proxy_upstream_requests_total",
            "Total upstream requests attempted.",
            i.upstream_requests_total.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "archetype_proxy_upstream_errors_total",
            "Total upstream requests that failed at the transport level.",
            i.upstream_errors_total.load(Ordering::Relaxed),
        );

        let _ = writeln!(
            out,
            "# HELP archetype_proxy_active_sessions Live AtB sessions in the registry."
        );
        let _ = writeln!(out, "# TYPE archetype_proxy_active_sessions gauge");
        let _ = writeln!(out, "archetype_proxy_active_sessions {active_sessions}");

        // Histogram.
        let _ = writeln!(
            out,
            "# HELP archetype_proxy_upstream_latency_seconds Upstream round-trip latency."
        );
        let _ = writeln!(out, "# TYPE archetype_proxy_upstream_latency_seconds histogram");
        for (idx, ub) in LATENCY_BUCKETS_SECS.iter().enumerate() {
            let c = i.latency_buckets[idx].load(Ordering::Relaxed);
            let _ = writeln!(
                out,
                "archetype_proxy_upstream_latency_seconds_bucket{{le=\"{ub}\"}} {c}"
            );
        }
        let total = i.latency_count.load(Ordering::Relaxed);
        let _ = writeln!(
            out,
            "archetype_proxy_upstream_latency_seconds_bucket{{le=\"+Inf\"}} {total}"
        );
        let sum_secs = i.latency_sum_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0;
        let _ = writeln!(out, "archetype_proxy_upstream_latency_seconds_sum {sum_secs}");
        let _ = writeln!(out, "archetype_proxy_upstream_latency_seconds_count {total}");

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_and_render() {
        let m = Metrics::new();
        m.inc_handshakes();
        m.inc_handshakes();
        m.inc_decrypt_failures();
        m.inc_upstream_requests();
        m.inc_upstream_errors();
        m.observe_upstream_latency(0.03);
        m.observe_upstream_latency(2.0);
        let text = m.render_prometheus(7);
        assert!(text.contains("archetype_proxy_handshakes_total 2"));
        assert!(text.contains("archetype_proxy_decrypt_failures_total 1"));
        assert!(text.contains("archetype_proxy_upstream_requests_total 1"));
        assert!(text.contains("archetype_proxy_upstream_errors_total 1"));
        assert!(text.contains("archetype_proxy_active_sessions 7"));
        // 0.03 falls in le=0.05 bucket (and all larger); 2.0 in le=2.5.
        assert!(text.contains("le=\"0.05\"} 1"));
        assert!(text.contains("le=\"2.5\"} 2"));
        assert!(text.contains("le=\"+Inf\"} 2"));
        assert!(text.contains("archetype_proxy_upstream_latency_seconds_count 2"));
    }

    #[test]
    fn histogram_is_cumulative() {
        let m = Metrics::new();
        m.observe_upstream_latency(0.001);
        let text = m.render_prometheus(0);
        // 0.001 <= every bucket bound, so every bucket counts it.
        assert!(text.contains("le=\"0.005\"} 1"));
        assert!(text.contains("le=\"10\"} 1"));
    }
}
