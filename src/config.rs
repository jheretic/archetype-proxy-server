// Layered, Traefik-style configuration (task #6).
//
// Two tiers:
//   * STATIC  -- file/env/CLI only, read once at boot: how the proxy boots and
//                which discovery providers are enabled (server, attestation,
//                discovery). Does NOT hot-reload.
//   * DYNAMIC -- the set of attested routes (match rule -> upstream). Sourced
//                from the file AND/OR discovery providers; hot-reloadable.
//
// Precedence for a resolved field (highest wins):
//   CLI flag > env (ARCHETYPE_PROXY_*) > discovered > TOML file > built-in default.
// Each resolved static field records which layer set it (`Provenance`).

use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::path::Path;

use serde::Deserialize;

const DEFAULT_MAX_BODY_BYTES: usize = 4 * 1024 * 1024;
const DEFAULT_LISTEN: &str = "127.0.0.1:8443";
const DEFAULT_DOCKER_SOCKET: &str = "unix:///var/run/docker.sock";
const DEFAULT_DOCKER_POLL_SECS: u64 = 10;
const DEFAULT_ATB_TTL_SECS: u64 = 300;
const DEFAULT_ATB_EVICTION_INTERVAL_SECS: u64 = 60;
const DEFAULT_ATB_MAX_SESSIONS: usize = 10_000;
const DEFAULT_TEE_PROVIDER: TeeProviderKind = TeeProviderKind::Mock;
const DEFAULT_VERIFIER: VerifierKind = VerifierKind::Mock;
// Per-IP sliding-window rate limit defaults (applied to attested routes).
const DEFAULT_RATE_LIMIT_MAX_REQUESTS: usize = 0; // 0 = disabled
const DEFAULT_RATE_LIMIT_WINDOW_SECS: u64 = 60;
const ENV_CONFIG_PATH: &str = "ARCHETYPE_PROXY_CONFIG";
const DEFAULT_CONFIG_PATH: &str = "./archetype-proxy.toml";

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

/// Which layer supplied a field's resolved value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Default,
    File,
    Discovered,
    Env,
    Cli,
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Source::Default => "default",
            Source::File => "file",
            Source::Discovered => "discovered",
            Source::Env => "env",
            Source::Cli => "cli",
        };
        f.write_str(s)
    }
}

impl Source {
    /// Tie-breaker rank when two routes have equal specificity: a discovered
    /// route outranks (and therefore overrides) a file route with the same
    /// match rule. See `RouteTable::new`.
    fn route_rank(self) -> u8 {
        match self {
            Source::Discovered | Source::Env | Source::Cli => 1,
            Source::File | Source::Default => 0,
        }
    }
}

/// Parse a boolean token from config/labels/annotations. Trimmed and
/// case-insensitive: `1/true/yes/on` => true, `0/false/no/off` => false,
/// anything else => None. Shared by env, Docker labels, and K8s annotations.
pub fn parse_bool_token(s: &str) -> Option<bool> {
    match s.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// TEE provider / verifier selection (task #7)
// ---------------------------------------------------------------------------

/// Which TEE attestation PROVIDER the server generates quotes with. Real
/// variants only build under the matching cargo feature on this crate (see
/// `Cargo.toml`); selecting one at runtime without its feature compiled in is
/// a fatal startup error (see `attestation::build_tee_provider`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeeProviderKind {
    Mock,
    Tdx,
    SevSnp,
    Sgx,
    TrustZone,
    AwsNitro,
}

/// Which quote VERIFIER the server validates client/peer quotes with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifierKind {
    Mock,
    /// Azure Microsoft Azure Attestation (REST). Needs `verifier_endpoint`.
    Maa,
    /// Intel Trust Authority (REST). Needs `verifier_endpoint` + `verifier_api_key`.
    Ita,
    /// AMD SEV-SNP VCEK chain.
    AmdSnp,
    /// TPM 2.0 PCR quote (upstream stub — see README).
    Tpm,
    /// NVIDIA Hopper GPU.
    Nvidia,
    /// Intel DCAP (no verifier type exists in the pinned openhttpa revision).
    Dcap,
}

impl TeeProviderKind {
    #[must_use]
    pub const fn is_mock(self) -> bool {
        matches!(self, Self::Mock)
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mock => "mock",
            Self::Tdx => "tdx",
            Self::SevSnp => "sev_snp",
            Self::Sgx => "sgx",
            Self::TrustZone => "trustzone",
            Self::AwsNitro => "aws_nitro",
        }
    }
}

impl VerifierKind {
    #[must_use]
    pub const fn is_mock(self) -> bool {
        matches!(self, Self::Mock)
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mock => "mock",
            Self::Maa => "maa",
            Self::Ita => "ita",
            Self::AmdSnp => "amd_snp",
            Self::Tpm => "tpm",
            Self::Nvidia => "nvidia",
            Self::Dcap => "dcap",
        }
    }
}

impl std::str::FromStr for TeeProviderKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "mock" => Ok(Self::Mock),
            "tdx" => Ok(Self::Tdx),
            "sev_snp" | "sevsnp" | "snp" => Ok(Self::SevSnp),
            "sgx" => Ok(Self::Sgx),
            "trustzone" | "trust_zone" => Ok(Self::TrustZone),
            "aws_nitro" | "nitro" => Ok(Self::AwsNitro),
            other => Err(format!(
                "unknown tee_provider {other:?} (expected mock|tdx|sev_snp|sgx|trustzone|aws_nitro)"
            )),
        }
    }
}

impl std::str::FromStr for VerifierKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "mock" => Ok(Self::Mock),
            "maa" => Ok(Self::Maa),
            "ita" => Ok(Self::Ita),
            "amd_snp" | "amdsnp" | "sev_snp" | "snp" => Ok(Self::AmdSnp),
            "tpm" => Ok(Self::Tpm),
            "nvidia" | "nvidia_gpu" => Ok(Self::Nvidia),
            "dcap" => Ok(Self::Dcap),
            other => Err(format!(
                "unknown verifier {other:?} (expected mock|maa|ita|amd_snp|tpm|nvidia|dcap)"
            )),
        }
    }
}

impl fmt::Display for TeeProviderKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Display for VerifierKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for TeeProviderKind {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl<'de> Deserialize<'de> for VerifierKind {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Public-facing TLS termination config (task #7 hook). Optional; see README
/// for the supported posture. Reused as the file representation.
///
/// Two MUTUALLY EXCLUSIVE cert sources: static PEM files (`cert_path` +
/// `key_path`) OR ACME auto-provisioning (`[server.tls.acme] enabled=true`).
/// `validate()` enforces exactly-one and is called at startup (fail-fast).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    #[serde(default)]
    pub acme: Option<AcmeConfig>,
}

/// Which ACME challenge type to use. DNS-01 is the only type that can issue
/// WILDCARD certs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AcmeChallenge {
    /// Validation cert served on the existing :443 TLS listener (no extra port).
    #[default]
    TlsAlpn01,
    /// Key-authorization served at GET /.well-known/acme-challenge/<token> on :80.
    Http01,
    /// `_acme-challenge` TXT record published via a `DnsProvider`.
    Dns01,
}

impl AcmeChallenge {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TlsAlpn01 => "tls-alpn-01",
            Self::Http01 => "http-01",
            Self::Dns01 => "dns-01",
        }
    }
}

impl std::str::FromStr for AcmeChallenge {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "tls-alpn-01" | "tls_alpn_01" | "tlsalpn01" | "tls-alpn" => Ok(Self::TlsAlpn01),
            "http-01" | "http_01" | "http01" | "http" => Ok(Self::Http01),
            "dns-01" | "dns_01" | "dns01" | "dns" => Ok(Self::Dns01),
            other => Err(format!(
                "unknown acme challenge {other:?} (expected tls-alpn-01|http-01|dns-01)"
            )),
        }
    }
}

impl fmt::Display for AcmeChallenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AcmeChallenge {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Which DNS provider publishes the `_acme-challenge` TXT record for DNS-01.
/// Only `Manual` (hook command / poll-until-present) is implemented; specific
/// APIs (Cloudflare/Route53/etc.) are pluggable follow-ups via the
/// `acme::DnsProvider` trait.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DnsProviderKind {
    #[default]
    Manual,
}

impl DnsProviderKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
        }
    }
}

impl std::str::FromStr for DnsProviderKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "manual" | "hook" => Ok(Self::Manual),
            other => Err(format!(
                "unknown dns provider {other:?} (expected manual; \
                 cloudflare/route53/etc. are follow-ups)"
            )),
        }
    }
}

impl fmt::Display for DnsProviderKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for DnsProviderKind {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// DNS-01 settings (used only when `challenge = "dns-01"`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeDnsConfig {
    #[serde(default)]
    pub provider: DnsProviderKind,
    /// External command run to PUBLISH the TXT record. Receives the record
    /// name + value via env (`ACME_DNS_NAME`, `ACME_DNS_VALUE`, `ACME_DNS_DOMAIN`).
    /// If unset, the record is logged and the manager polls DNS until present.
    pub hook_command: Option<String>,
    /// External command run to CLEAN UP the TXT record after validation.
    pub cleanup_command: Option<String>,
    /// Seconds to wait for DNS propagation before telling the CA to validate.
    #[serde(default = "default_dns_propagation_secs")]
    pub propagation_secs: u64,
}

impl Default for AcmeDnsConfig {
    fn default() -> Self {
        Self {
            provider: DnsProviderKind::Manual,
            hook_command: None,
            cleanup_command: None,
            propagation_secs: default_dns_propagation_secs(),
        }
    }
}

const fn default_dns_propagation_secs() -> u64 {
    60
}

/// ACME automatic-TLS config (task #12). Off by default.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub domains: Vec<String>,
    /// Contact email (stored as a `mailto:` URI on the ACME account).
    pub contact: Option<String>,
    #[serde(default)]
    pub challenge: AcmeChallenge,
    /// Explicit ACME directory URL. Overrides `staging`. Defaults to Let's
    /// Encrypt production.
    pub directory_url: Option<String>,
    /// Use Let's Encrypt STAGING (relaxed rate limits, untrusted certs).
    /// Ignored if `directory_url` is set.
    #[serde(default)]
    pub staging: bool,
    /// Directory to persist the ACME account key + issued cert across restarts.
    pub cache_dir: Option<String>,
    /// Listen addr for the plaintext :80 HTTP-01 responder (challenge=http-01).
    pub http01_listen: Option<SocketAddr>,
    #[serde(default)]
    pub dns: AcmeDnsConfig,
}

/// The validated, resolved TLS cert source: exactly one of static / ACME.
#[derive(Debug, Clone)]
pub enum TlsMode {
    Static {
        cert_path: String,
        key_path: String,
    },
    Acme(AcmeConfig),
}

impl TlsConfig {
    /// Classify + validate the `[server.tls]` block into exactly one cert
    /// source. FAIL-FAST: returns a clear error string (no silent fallback) if
    /// the static pair and ACME are both/neither configured, if the static
    /// pair is half-specified, or if ACME is enabled with no domains.
    pub fn validate(&self) -> Result<TlsMode, String> {
        let acme_enabled = self.acme.as_ref().is_some_and(|a| a.enabled);
        let has_static = self.cert_path.is_some() || self.key_path.is_some();

        match (acme_enabled, has_static) {
            (true, true) => Err(
                "[server.tls]: static cert_path/key_path and [server.tls.acme] enabled=true are \
                 mutually exclusive — configure exactly one cert source"
                    .to_owned(),
            ),
            (false, false) => Err(
                "[server.tls] is present but configures no cert source: set cert_path+key_path \
                 OR [server.tls.acme] enabled=true"
                    .to_owned(),
            ),
            (false, true) => match (&self.cert_path, &self.key_path) {
                (Some(cert_path), Some(key_path)) => Ok(TlsMode::Static {
                    cert_path: cert_path.clone(),
                    key_path: key_path.clone(),
                }),
                (Some(_), None) => {
                    Err("[server.tls]: cert_path is set but key_path is missing".to_owned())
                }
                (None, Some(_)) => {
                    Err("[server.tls]: key_path is set but cert_path is missing".to_owned())
                }
                (None, None) => unreachable!("has_static implies at least one is Some"),
            },
            (true, false) => {
                let acme = self.acme.as_ref().expect("acme_enabled implies Some");
                if acme.domains.is_empty() {
                    return Err(
                        "[server.tls.acme]: enabled=true but `domains` is empty".to_owned()
                    );
                }
                if acme.challenge != AcmeChallenge::Dns01
                    && acme.domains.iter().any(|d| d.starts_with("*."))
                {
                    return Err(format!(
                        "[server.tls.acme]: wildcard domain requires challenge=\"dns-01\" \
                         (got challenge=\"{}\")",
                        acme.challenge
                    ));
                }
                Ok(TlsMode::Acme(acme.clone()))
            }
        }
    }
}

/// field-path -> winning layer, for debuggability.
#[derive(Debug, Clone, Default)]
pub struct Provenance(BTreeMap<String, Source>);

impl Provenance {
    fn record(&mut self, field: &str, source: Source) {
        self.0.insert(field.to_owned(), source);
    }

    pub fn get(&self, field: &str) -> Option<Source> {
        self.0.get(field).copied()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &Source)> {
        self.0.iter()
    }
}

// ---------------------------------------------------------------------------
// Resolved static config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct StaticConfig {
    pub server: ServerConfig,
    pub attestation: AttestationConfig,
    pub discovery: DiscoveryConfig,
    pub rate_limit: RateLimitConfig,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub max_body_bytes: usize,
    /// Optional public-TLS termination. `None` => plaintext listener (the
    /// server is expected to sit behind a TLS-terminating ingress). See README.
    pub tls: Option<TlsConfig>,
}

#[derive(Debug, Clone)]
pub struct AttestationConfig {
    pub allow_mock: bool,
    /// Global default for per-route strict attestation. Enforcement is task #7;
    /// this is parsed and threaded through but not yet acted upon.
    pub strict_attestation: bool,
    pub atb_ttl_secs: u64,
    /// Background eviction interval for the AtB registry (BLOCKER B). Expired
    /// single-use sessions are reaped on this cadence so a long-running bridge
    /// doing >>capacity requests does not exhaust the registry.
    pub atb_eviction_interval_secs: u64,
    /// Max live AtB sessions held by the registry (capacity).
    pub atb_max_sessions: usize,
    /// TEE provider used to generate quotes (task #7). Real variants require
    /// the matching cargo feature on this crate.
    pub tee_provider: TeeProviderKind,
    /// Quote verifier used to validate quotes (task #7).
    pub verifier: VerifierKind,
    /// REST endpoint for remote verifiers (MAA / ITA).
    pub verifier_endpoint: Option<String>,
    /// API key for verifiers that need one (ITA).
    pub verifier_api_key: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Max requests per IP per window. `0` disables rate limiting.
    pub max_requests: usize,
    pub window_secs: u64,
}

#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    pub docker: DockerDiscoveryConfig,
    pub kubernetes: KubernetesDiscoveryConfig,
}

#[derive(Debug, Clone)]
pub struct DockerDiscoveryConfig {
    pub enabled: bool,
    pub socket: String,
    pub poll_secs: u64,
}

#[derive(Debug, Clone)]
pub struct KubernetesDiscoveryConfig {
    pub enabled: bool,
    /// Optional namespace filter (None = all namespaces).
    pub namespace: Option<String>,
}

// ---------------------------------------------------------------------------
// Dynamic config: routes
// ---------------------------------------------------------------------------

/// A dynamic route: a match rule (host and/or path prefix) -> upstream target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub name: String,
    /// Exact host match (authority). Empty = match any host.
    pub host: String,
    /// Path prefix match. Empty = match any path.
    pub path_prefix: String,
    /// Upstream base URL, e.g. `http://api:8080`.
    pub upstream: String,
    /// Per-route strict attestation override. Enforcement is task #7.
    pub strict_attestation: Option<bool>,
    /// Which layer produced this route.
    pub source: Source,
}

impl Route {
    /// Ordering key (most-specific first). Host match and longer prefix are
    /// preferred; on an exact tie, source rank breaks it so a discovered route
    /// outranks a file route with the same match rule (dynamic precedence:
    /// file < discovered).
    fn specificity(&self) -> (u8, usize, u8) {
        let host_bonus = u8::from(!self.host.is_empty());
        (host_bonus, self.path_prefix.len(), self.source.route_rank())
    }

    fn matches(&self, host: &str, path: &str) -> bool {
        if !self.host.is_empty() && !host.eq_ignore_ascii_case(&self.host) {
            return false;
        }
        if !path_prefix_matches(&self.path_prefix, path) {
            return false;
        }
        true
    }
}

/// Path-prefix match on segment boundaries. Empty/"/" prefix is a catch-all.
/// Otherwise `path` matches iff it equals the prefix (trailing slash ignored)
/// or begins with the prefix followed by `/` — so `/v1` matches `/v1` and
/// `/v1/foo` but NOT `/v123` or `/v1evil`.
fn path_prefix_matches(prefix: &str, path: &str) -> bool {
    let p = prefix.trim_end_matches('/');
    if p.is_empty() {
        return true;
    }
    if let Some(rest) = path.strip_prefix(p) {
        rest.is_empty() || rest.starts_with('/')
    } else {
        false
    }
}

/// An immutable, pre-sorted set of routes. Cheap to clone (Arc-wrapped in the
/// proxy) and swapped wholesale on discovery events.
#[derive(Debug, Clone, Default)]
pub struct RouteTable {
    routes: Vec<Route>,
}

impl RouteTable {
    pub fn new(mut routes: Vec<Route>) -> Self {
        // Most-specific first: host-match beats host-any, then longer prefix;
        // on an exact (host, prefix) tie, a discovered route outranks a file
        // route so it wins selection (file < discovered).
        routes.sort_by_key(|r| std::cmp::Reverse(r.specificity()));
        Self { routes }
    }

    /// Select the upstream base URL for a request by (host, path). Returns the
    /// most-specific matching route.
    pub fn select(&self, host: &str, path: &str) -> Option<&Route> {
        self.routes.iter().find(|r| r.matches(host, path))
    }

    pub fn routes(&self) -> &[Route] {
        &self.routes
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Resolved top-level config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Config {
    pub r#static: StaticConfig,
    /// Routes sourced from the file (the static baseline of the dynamic table).
    /// Discovery adds/replaces routes on top of these at runtime.
    pub file_routes: Vec<Route>,
    pub provenance: Provenance,
}

impl Config {
    /// Initial route table = file routes only (discovery merges in later).
    pub fn initial_routes(&self) -> RouteTable {
        RouteTable::new(self.file_routes.clone())
    }

    /// Human-readable provenance dump for `config dump` / startup debug.
    pub fn dump(&self) -> String {
        let s = &self.r#static;
        let p = &self.provenance;
        let mut out = String::new();
        let line = |out: &mut String, field: &str, val: String| {
            let src = p.get(field).map_or(Source::Default, |s| s);
            out.push_str(&format!("  {field:<28} = {val:<30} [{src}]\n"));
        };
        out.push_str("static config (boot-time only):\n");
        line(&mut out, "server.listen", s.server.listen.to_string());
        line(
            &mut out,
            "server.max_body_bytes",
            s.server.max_body_bytes.to_string(),
        );
        line(
            &mut out,
            "attestation.allow_mock",
            s.attestation.allow_mock.to_string(),
        );
        line(
            &mut out,
            "attestation.strict_attestation",
            s.attestation.strict_attestation.to_string(),
        );
        line(
            &mut out,
            "attestation.atb_ttl_secs",
            s.attestation.atb_ttl_secs.to_string(),
        );
        line(
            &mut out,
            "attestation.atb_eviction_interval_secs",
            s.attestation.atb_eviction_interval_secs.to_string(),
        );
        line(
            &mut out,
            "attestation.atb_max_sessions",
            s.attestation.atb_max_sessions.to_string(),
        );
        line(
            &mut out,
            "attestation.tee_provider",
            s.attestation.tee_provider.to_string(),
        );
        line(
            &mut out,
            "attestation.verifier",
            s.attestation.verifier.to_string(),
        );
        line(
            &mut out,
            "attestation.verifier_endpoint",
            s.attestation
                .verifier_endpoint
                .clone()
                .unwrap_or_else(|| "<none>".to_owned()),
        );
        line(
            &mut out,
            "server.tls",
            s.server.tls.as_ref().map_or_else(
                || "<none>".to_owned(),
                |t| match t.validate() {
                    Ok(TlsMode::Static {
                        cert_path,
                        key_path,
                    }) => format!("static cert={cert_path} key={key_path}"),
                    Ok(TlsMode::Acme(a)) => format!(
                        "acme challenge={} domains={:?} staging={}",
                        a.challenge, a.domains, a.staging
                    ),
                    Err(e) => format!("<invalid: {e}>"),
                },
            ),
        );
        line(
            &mut out,
            "rate_limit.max_requests",
            s.rate_limit.max_requests.to_string(),
        );
        line(
            &mut out,
            "rate_limit.window_secs",
            s.rate_limit.window_secs.to_string(),
        );
        line(
            &mut out,
            "discovery.docker",
            s.discovery.docker.enabled.to_string(),
        );
        line(
            &mut out,
            "discovery.docker.socket",
            s.discovery.docker.socket.clone(),
        );
        line(
            &mut out,
            "discovery.docker.poll_secs",
            s.discovery.docker.poll_secs.to_string(),
        );
        line(
            &mut out,
            "discovery.kubernetes",
            s.discovery.kubernetes.enabled.to_string(),
        );
        line(
            &mut out,
            "discovery.kubernetes.namespace",
            s.discovery
                .kubernetes
                .namespace
                .clone()
                .unwrap_or_else(|| "<all>".to_owned()),
        );
        out.push_str(&format!("dynamic routes (file): {}\n", self.file_routes.len()));
        for r in &self.file_routes {
            out.push_str(&format!(
                "  - {} host={:?} prefix={:?} -> {} [{}]\n",
                r.name, r.host, r.path_prefix, r.upstream, r.source
            ));
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Layer inputs (partials)
// ---------------------------------------------------------------------------

/// A partial set of overrides from one layer. `None` = layer is silent on that
/// field. Shared shape for env, CLI, and (scalar) discovery layers.
#[derive(Debug, Clone, Default)]
pub struct PartialStatic {
    pub listen: Option<SocketAddr>,
    pub max_body_bytes: Option<usize>,
    pub tls: Option<TlsConfig>,
    pub allow_mock: Option<bool>,
    pub strict_attestation: Option<bool>,
    pub atb_ttl_secs: Option<u64>,
    pub atb_eviction_interval_secs: Option<u64>,
    pub atb_max_sessions: Option<usize>,
    pub tee_provider: Option<TeeProviderKind>,
    pub verifier: Option<VerifierKind>,
    pub verifier_endpoint: Option<String>,
    pub verifier_api_key: Option<String>,
    pub rate_limit_max_requests: Option<usize>,
    pub rate_limit_window_secs: Option<u64>,
    pub docker_enabled: Option<bool>,
    pub docker_socket: Option<String>,
    pub docker_poll_secs: Option<u64>,
    pub kubernetes_enabled: Option<bool>,
    /// Three-state so a higher layer can explicitly CLEAR an optional value:
    ///   None        = layer is silent
    ///   Some(None)  = layer clears the namespace (all namespaces)
    ///   Some(Some)  = layer sets a specific namespace
    /// An empty string in file/env/CLI means Clear (all namespaces).
    pub kubernetes_namespace: Option<Option<String>>,
}

/// Map a raw optional string from one layer into a namespace `LayerValue`:
/// absent => silent, empty string => Clear (all namespaces), else => Set.
fn namespace_layer(v: Option<String>) -> Option<Option<String>> {
    v.map(|s| if s.is_empty() { None } else { Some(s) })
}

// ---------------------------------------------------------------------------
// TOML file representation
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    #[serde(default)]
    server: FileServer,
    #[serde(default)]
    attestation: FileAttestation,
    #[serde(default)]
    rate_limit: FileRateLimit,
    #[serde(default)]
    discovery: FileDiscovery,
    // Backwards-compat: the MVP `[upstream] target` single static upstream.
    #[serde(default)]
    upstream: Option<FileUpstream>,
    #[serde(default, rename = "route")]
    routes: Vec<FileRoute>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileServer {
    listen: Option<SocketAddr>,
    max_body_bytes: Option<usize>,
    #[serde(default)]
    tls: Option<TlsConfig>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileAttestation {
    allow_mock: Option<bool>,
    strict_attestation: Option<bool>,
    atb_ttl_secs: Option<u64>,
    atb_eviction_interval_secs: Option<u64>,
    atb_max_sessions: Option<usize>,
    tee_provider: Option<TeeProviderKind>,
    verifier: Option<VerifierKind>,
    verifier_endpoint: Option<String>,
    verifier_api_key: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileRateLimit {
    max_requests: Option<usize>,
    window_secs: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileDiscovery {
    docker: Option<bool>,
    docker_socket: Option<String>,
    docker_poll_secs: Option<u64>,
    kubernetes: Option<bool>,
    kubernetes_namespace: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileUpstream {
    target: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileRoute {
    name: Option<String>,
    #[serde(default)]
    host: String,
    #[serde(default)]
    path_prefix: String,
    upstream: String,
    strict_attestation: Option<bool>,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("failed to parse config file {path}: {source}")]
    Parse {
        path: String,
        source: toml::de::Error,
    },
    #[error("invalid value for {var}: {value} ({reason})")]
    Env {
        var: String,
        value: String,
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

/// Pick the highest-precedence `Some` value across the layers, recording its
/// source. `layers` is ordered LOWEST -> HIGHEST precedence.
fn resolve<T: Clone>(
    field: &str,
    default: T,
    layers: &[(Source, Option<T>)],
    prov: &mut Provenance,
) -> T {
    let mut value = default;
    prov.record(field, Source::Default);
    for (source, candidate) in layers {
        if let Some(v) = candidate {
            value = v.clone();
            prov.record(field, *source);
        }
    }
    value
}

impl Config {
    /// Resolve config path: explicit arg, else `ARCHETYPE_PROXY_CONFIG`, else
    /// the default path.
    pub fn config_path(explicit: Option<&str>) -> String {
        explicit
            .map(ToOwned::to_owned)
            .or_else(|| std::env::var(ENV_CONFIG_PATH).ok())
            .unwrap_or_else(|| DEFAULT_CONFIG_PATH.to_owned())
    }

    /// Load and resolve config from defaults < file < env < CLI. (Discovered
    /// scalar overrides are reserved; discovery primarily contributes routes.)
    pub fn load(cli: PartialStatic, config_path: Option<&str>) -> Result<Self, ConfigError> {
        let path = Self::config_path(config_path);
        let file = Self::read_file(&path)?;
        let env = Self::read_env()?;
        Ok(Self::resolve_layers(file, env, cli))
    }

    fn read_file(path: &str) -> Result<(PartialStatic, Vec<Route>), ConfigError> {
        if !Path::new(path).exists() {
            return Ok((PartialStatic::default(), Vec::new()));
        }
        let raw = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_owned(),
            source,
        })?;
        let fc: FileConfig = toml::from_str(&raw).map_err(|source| ConfigError::Parse {
            path: path.to_owned(),
            source,
        })?;

        let partial = PartialStatic {
            listen: fc.server.listen,
            max_body_bytes: fc.server.max_body_bytes,
            tls: fc.server.tls,
            allow_mock: fc.attestation.allow_mock,
            strict_attestation: fc.attestation.strict_attestation,
            atb_ttl_secs: fc.attestation.atb_ttl_secs,
            atb_eviction_interval_secs: fc.attestation.atb_eviction_interval_secs,
            atb_max_sessions: fc.attestation.atb_max_sessions,
            tee_provider: fc.attestation.tee_provider,
            verifier: fc.attestation.verifier,
            verifier_endpoint: fc.attestation.verifier_endpoint,
            verifier_api_key: fc.attestation.verifier_api_key,
            rate_limit_max_requests: fc.rate_limit.max_requests,
            rate_limit_window_secs: fc.rate_limit.window_secs,
            docker_enabled: fc.discovery.docker,
            docker_socket: fc.discovery.docker_socket,
            docker_poll_secs: fc.discovery.docker_poll_secs,
            kubernetes_enabled: fc.discovery.kubernetes,
            kubernetes_namespace: namespace_layer(fc.discovery.kubernetes_namespace),
        };

        let mut routes: Vec<Route> = fc
            .routes
            .into_iter()
            .enumerate()
            .map(|(i, r)| Route {
                name: r.name.unwrap_or_else(|| format!("route-{i}")),
                host: r.host,
                path_prefix: r.path_prefix,
                upstream: r.upstream,
                strict_attestation: r.strict_attestation,
                source: Source::File,
            })
            .collect();

        // Backwards-compat: `[upstream] target` becomes a catch-all route.
        if let Some(up) = fc.upstream {
            routes.push(Route {
                name: "upstream-default".to_owned(),
                host: String::new(),
                path_prefix: String::new(),
                upstream: up.target,
                strict_attestation: None,
                source: Source::File,
            });
        }

        Ok((partial, routes))
    }

    fn read_env() -> Result<PartialStatic, ConfigError> {
        fn var(name: &str) -> Option<String> {
            std::env::var(name).ok().filter(|s| !s.is_empty())
        }
        fn parse<T: std::str::FromStr>(name: &str) -> Result<Option<T>, ConfigError>
        where
            T::Err: fmt::Display,
        {
            match var(name) {
                None => Ok(None),
                Some(v) => v.parse::<T>().map(Some).map_err(|e| ConfigError::Env {
                    var: name.to_owned(),
                    value: v,
                    reason: e.to_string(),
                }),
            }
        }
        fn parse_bool(name: &str) -> Result<Option<bool>, ConfigError> {
            match var(name) {
                None => Ok(None),
                Some(v) => match parse_bool_token(&v) {
                    Some(b) => Ok(Some(b)),
                    None => Err(ConfigError::Env {
                        var: name.to_owned(),
                        value: v,
                        reason: "expected a boolean".to_owned(),
                    }),
                },
            }
        }

        Ok(PartialStatic {
            listen: parse("ARCHETYPE_PROXY_LISTEN")?,
            max_body_bytes: parse("ARCHETYPE_PROXY_MAX_BODY_BYTES")?,
            // TLS is only set via the file (a cert/key pair); no env shorthand.
            tls: None,
            allow_mock: parse_bool("ARCHETYPE_PROXY_ALLOW_MOCK")?,
            strict_attestation: parse_bool("ARCHETYPE_PROXY_STRICT_ATTESTATION")?,
            atb_ttl_secs: parse("ARCHETYPE_PROXY_ATB_TTL_SECS")?,
            atb_eviction_interval_secs: parse("ARCHETYPE_PROXY_ATB_EVICTION_INTERVAL_SECS")?,
            atb_max_sessions: parse("ARCHETYPE_PROXY_ATB_MAX_SESSIONS")?,
            tee_provider: parse("ARCHETYPE_PROXY_TEE_PROVIDER")?,
            verifier: parse("ARCHETYPE_PROXY_VERIFIER")?,
            verifier_endpoint: var("ARCHETYPE_PROXY_VERIFIER_ENDPOINT"),
            verifier_api_key: var("ARCHETYPE_PROXY_VERIFIER_API_KEY"),
            rate_limit_max_requests: parse("ARCHETYPE_PROXY_RATE_LIMIT_MAX_REQUESTS")?,
            rate_limit_window_secs: parse("ARCHETYPE_PROXY_RATE_LIMIT_WINDOW_SECS")?,
            docker_enabled: parse_bool("ARCHETYPE_PROXY_DOCKER")?,
            docker_socket: var("ARCHETYPE_PROXY_DOCKER_SOCKET"),
            docker_poll_secs: parse("ARCHETYPE_PROXY_DOCKER_POLL_SECS")?,
            kubernetes_enabled: parse_bool("ARCHETYPE_PROXY_KUBERNETES")?,
            // Read raw (not via `var`) so an explicit empty value means Clear
            // (all namespaces) rather than being filtered out as silent.
            kubernetes_namespace: namespace_layer(
                std::env::var("ARCHETYPE_PROXY_KUBERNETES_NAMESPACE").ok(),
            ),
        })
    }

    /// Pure merge: visible for testing.
    pub fn resolve_layers(
        file: (PartialStatic, Vec<Route>),
        env: PartialStatic,
        cli: PartialStatic,
    ) -> Self {
        let (file_partial, file_routes) = file;
        let mut prov = Provenance::default();

        macro_rules! field {
            ($name:literal, $default:expr, $accessor:ident) => {
                resolve(
                    $name,
                    $default,
                    &[
                        (Source::File, file_partial.$accessor.clone()),
                        (Source::Env, env.$accessor.clone()),
                        (Source::Cli, cli.$accessor.clone()),
                    ],
                    &mut prov,
                )
            };
        }

        let listen = field!(
            "server.listen",
            DEFAULT_LISTEN.parse().expect("valid default listen"),
            listen
        );
        let max_body_bytes = field!("server.max_body_bytes", DEFAULT_MAX_BODY_BYTES, max_body_bytes);
        let allow_mock = field!("attestation.allow_mock", true, allow_mock);
        let strict_attestation =
            field!("attestation.strict_attestation", false, strict_attestation);
        let atb_ttl_secs = field!("attestation.atb_ttl_secs", DEFAULT_ATB_TTL_SECS, atb_ttl_secs);
        let atb_eviction_interval_secs = field!(
            "attestation.atb_eviction_interval_secs",
            DEFAULT_ATB_EVICTION_INTERVAL_SECS,
            atb_eviction_interval_secs
        );
        let atb_max_sessions = field!(
            "attestation.atb_max_sessions",
            DEFAULT_ATB_MAX_SESSIONS,
            atb_max_sessions
        );
        let tee_provider = field!("attestation.tee_provider", DEFAULT_TEE_PROVIDER, tee_provider);
        let verifier = field!("attestation.verifier", DEFAULT_VERIFIER, verifier);
        // Optional fields: resolve manually (None default).
        let verifier_endpoint = resolve(
            "attestation.verifier_endpoint",
            None,
            &[
                (Source::File, file_partial.verifier_endpoint.clone().map(Some)),
                (Source::Env, env.verifier_endpoint.clone().map(Some)),
                (Source::Cli, cli.verifier_endpoint.clone().map(Some)),
            ],
            &mut prov,
        );
        let verifier_api_key = resolve(
            "attestation.verifier_api_key",
            None,
            &[
                (Source::File, file_partial.verifier_api_key.clone().map(Some)),
                (Source::Env, env.verifier_api_key.clone().map(Some)),
                (Source::Cli, cli.verifier_api_key.clone().map(Some)),
            ],
            &mut prov,
        );
        let tls = resolve(
            "server.tls",
            None,
            &[
                (Source::File, file_partial.tls.clone().map(Some)),
                (Source::Env, env.tls.clone().map(Some)),
                (Source::Cli, cli.tls.clone().map(Some)),
            ],
            &mut prov,
        );
        let rate_limit_max_requests = field!(
            "rate_limit.max_requests",
            DEFAULT_RATE_LIMIT_MAX_REQUESTS,
            rate_limit_max_requests
        );
        let rate_limit_window_secs = field!(
            "rate_limit.window_secs",
            DEFAULT_RATE_LIMIT_WINDOW_SECS,
            rate_limit_window_secs
        );
        let docker_enabled = field!("discovery.docker", false, docker_enabled);
        let docker_socket = field!(
            "discovery.docker.socket",
            DEFAULT_DOCKER_SOCKET.to_owned(),
            docker_socket
        );
        let docker_poll_secs = field!(
            "discovery.docker.poll_secs",
            DEFAULT_DOCKER_POLL_SECS,
            docker_poll_secs
        );
        let kubernetes_enabled = field!("discovery.kubernetes", false, kubernetes_enabled);

        // Namespace: Option field; resolve manually (None default).
        let kubernetes_namespace = resolve(
            "discovery.kubernetes.namespace",
            None,
            &[
                (Source::File, file_partial.kubernetes_namespace.clone()),
                (Source::Env, env.kubernetes_namespace.clone()),
                (Source::Cli, cli.kubernetes_namespace.clone()),
            ],
            &mut prov,
        );

        Config {
            r#static: StaticConfig {
                server: ServerConfig {
                    listen,
                    max_body_bytes,
                    tls,
                },
                attestation: AttestationConfig {
                    allow_mock,
                    strict_attestation,
                    atb_ttl_secs,
                    atb_eviction_interval_secs,
                    atb_max_sessions,
                    tee_provider,
                    verifier,
                    verifier_endpoint,
                    verifier_api_key,
                },
                rate_limit: RateLimitConfig {
                    max_requests: rate_limit_max_requests,
                    window_secs: rate_limit_window_secs,
                },
                discovery: DiscoveryConfig {
                    docker: DockerDiscoveryConfig {
                        enabled: docker_enabled,
                        socket: docker_socket,
                        poll_secs: docker_poll_secs,
                    },
                    kubernetes: KubernetesDiscoveryConfig {
                        enabled: kubernetes_enabled,
                        namespace: kubernetes_namespace,
                    },
                },
            },
            file_routes,
            provenance: prov,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_file() -> (PartialStatic, Vec<Route>) {
        (PartialStatic::default(), Vec::new())
    }

    #[test]
    fn defaults_when_all_layers_silent() {
        let cfg = Config::resolve_layers(empty_file(), PartialStatic::default(), PartialStatic::default());
        assert_eq!(cfg.r#static.server.max_body_bytes, DEFAULT_MAX_BODY_BYTES);
        assert!(cfg.r#static.attestation.allow_mock);
        assert!(!cfg.r#static.discovery.docker.enabled);
        // BLOCKER B + rate-limit defaults.
        assert_eq!(
            cfg.r#static.attestation.atb_eviction_interval_secs,
            DEFAULT_ATB_EVICTION_INTERVAL_SECS
        );
        assert_eq!(
            cfg.r#static.attestation.atb_max_sessions,
            DEFAULT_ATB_MAX_SESSIONS
        );
        assert_eq!(cfg.r#static.rate_limit.max_requests, 0, "rate limit off by default");
        assert_eq!(
            cfg.provenance.get("server.max_body_bytes"),
            Some(Source::Default)
        );
    }

    #[test]
    fn file_overrides_default() {
        let file = (
            PartialStatic {
                max_body_bytes: Some(999),
                docker_enabled: Some(true),
                ..Default::default()
            },
            Vec::new(),
        );
        let cfg = Config::resolve_layers(file, PartialStatic::default(), PartialStatic::default());
        assert_eq!(cfg.r#static.server.max_body_bytes, 999);
        assert!(cfg.r#static.discovery.docker.enabled);
        assert_eq!(cfg.provenance.get("server.max_body_bytes"), Some(Source::File));
        assert_eq!(cfg.provenance.get("discovery.docker"), Some(Source::File));
    }

    #[test]
    fn env_overrides_file() {
        let file = (
            PartialStatic {
                max_body_bytes: Some(999),
                allow_mock: Some(true),
                ..Default::default()
            },
            Vec::new(),
        );
        let env = PartialStatic {
            max_body_bytes: Some(111),
            ..Default::default()
        };
        let cfg = Config::resolve_layers(file, env, PartialStatic::default());
        assert_eq!(cfg.r#static.server.max_body_bytes, 111);
        assert_eq!(cfg.provenance.get("server.max_body_bytes"), Some(Source::Env));
        // allow_mock untouched by env -> still file.
        assert_eq!(cfg.provenance.get("attestation.allow_mock"), Some(Source::File));
    }

    #[test]
    fn cli_overrides_env_and_file() {
        let file = (
            PartialStatic {
                max_body_bytes: Some(999),
                ..Default::default()
            },
            Vec::new(),
        );
        let env = PartialStatic {
            max_body_bytes: Some(111),
            ..Default::default()
        };
        let cli = PartialStatic {
            max_body_bytes: Some(7),
            ..Default::default()
        };
        let cfg = Config::resolve_layers(file, env, cli);
        assert_eq!(cfg.r#static.server.max_body_bytes, 7);
        assert_eq!(cfg.provenance.get("server.max_body_bytes"), Some(Source::Cli));
    }

    #[test]
    fn partial_override_leaves_other_fields() {
        let file = (
            PartialStatic {
                max_body_bytes: Some(999),
                docker_enabled: Some(true),
                docker_socket: Some("unix:///custom.sock".to_owned()),
                ..Default::default()
            },
            Vec::new(),
        );
        let env = PartialStatic {
            docker_enabled: Some(false),
            ..Default::default()
        };
        let cfg = Config::resolve_layers(file, env, PartialStatic::default());
        // env flips docker enabled...
        assert!(!cfg.r#static.discovery.docker.enabled);
        assert_eq!(cfg.provenance.get("discovery.docker"), Some(Source::Env));
        // ...but socket stays from file.
        assert_eq!(cfg.r#static.discovery.docker.socket, "unix:///custom.sock");
        assert_eq!(cfg.provenance.get("discovery.docker.socket"), Some(Source::File));
        // ...and max_body_bytes stays from file.
        assert_eq!(cfg.r#static.server.max_body_bytes, 999);
    }

    #[test]
    fn namespace_option_provenance() {
        let file = (
            PartialStatic {
                kubernetes_namespace: namespace_layer(Some("prod".to_owned())),
                ..Default::default()
            },
            Vec::new(),
        );
        let cfg = Config::resolve_layers(file, PartialStatic::default(), PartialStatic::default());
        assert_eq!(cfg.r#static.discovery.kubernetes.namespace.as_deref(), Some("prod"));
        assert_eq!(
            cfg.provenance.get("discovery.kubernetes.namespace"),
            Some(Source::File)
        );
        let none = Config::resolve_layers(empty_file(), PartialStatic::default(), PartialStatic::default());
        assert_eq!(none.r#static.discovery.kubernetes.namespace, None);
        assert_eq!(
            none.provenance.get("discovery.kubernetes.namespace"),
            Some(Source::Default)
        );
    }

    // -- route matching -----------------------------------------------------

    fn route(name: &str, host: &str, prefix: &str, upstream: &str) -> Route {
        Route {
            name: name.to_owned(),
            host: host.to_owned(),
            path_prefix: prefix.to_owned(),
            upstream: upstream.to_owned(),
            strict_attestation: None,
            source: Source::File,
        }
    }

    fn route_src(name: &str, prefix: &str, upstream: &str, source: Source) -> Route {
        Route {
            name: name.to_owned(),
            host: String::new(),
            path_prefix: prefix.to_owned(),
            upstream: upstream.to_owned(),
            strict_attestation: None,
            source,
        }
    }

    #[test]
    fn route_selects_by_path_prefix() {
        let t = RouteTable::new(vec![
            route("v1", "", "/v1", "http://v1:80"),
            route("catch", "", "", "http://default:80"),
        ]);
        assert_eq!(t.select("any", "/v1/foo").unwrap().upstream, "http://v1:80");
        assert_eq!(t.select("any", "/other").unwrap().upstream, "http://default:80");
    }

    #[test]
    fn route_host_match_beats_catchall() {
        let t = RouteTable::new(vec![
            route("catch", "", "", "http://default:80"),
            route("api", "api.internal", "", "http://api:80"),
        ]);
        let sel = t.select("api.internal", "/x").unwrap();
        assert_eq!(sel.upstream, "http://api:80");
        // host mismatch falls back to catch-all
        assert_eq!(t.select("other", "/x").unwrap().upstream, "http://default:80");
    }

    #[test]
    fn route_longer_prefix_wins() {
        let t = RouteTable::new(vec![
            route("short", "", "/api", "http://short:80"),
            route("long", "", "/api/v2", "http://long:80"),
        ]);
        assert_eq!(t.select("h", "/api/v2/x").unwrap().upstream, "http://long:80");
        assert_eq!(t.select("h", "/api/v1/x").unwrap().upstream, "http://short:80");
    }

    #[test]
    fn route_host_is_case_insensitive() {
        let t = RouteTable::new(vec![route("api", "API.Internal", "", "http://api:80")]);
        assert!(t.select("api.internal", "/x").is_some());
    }

    #[test]
    fn discovered_overrides_file_on_identical_rule() {
        // BLOCKER 1: same (host, path_prefix); discovered must win.
        let file_first = RouteTable::new(vec![
            route_src("file", "/v1", "http://file:80", Source::File),
            route_src("disc", "/v1", "http://disc:80", Source::Discovered),
        ]);
        assert_eq!(
            file_first.select("h", "/v1/x").unwrap().upstream,
            "http://disc:80"
        );
        // Order of construction must not matter.
        let disc_first = RouteTable::new(vec![
            route_src("disc", "/v1", "http://disc:80", Source::Discovered),
            route_src("file", "/v1", "http://file:80", Source::File),
        ]);
        assert_eq!(
            disc_first.select("h", "/v1/x").unwrap().upstream,
            "http://disc:80"
        );
    }

    #[test]
    fn more_specific_file_route_still_beats_less_specific_discovered() {
        // Specificity wins across DIFFERENT rules regardless of source.
        let t = RouteTable::new(vec![
            route_src("disc-short", "/api", "http://disc:80", Source::Discovered),
            route_src("file-long", "/api/v2", "http://file:80", Source::File),
        ]);
        assert_eq!(t.select("h", "/api/v2/x").unwrap().upstream, "http://file:80");
    }

    #[test]
    fn path_prefix_matches_on_segment_boundary() {
        // BLOCKER 2: "/v1" must not match "/v123".
        assert!(path_prefix_matches("/v1", "/v1"));
        assert!(path_prefix_matches("/v1", "/v1/ok"));
        assert!(path_prefix_matches("/v1/", "/v1/ok"));
        assert!(!path_prefix_matches("/v1", "/v123"));
        assert!(!path_prefix_matches("/v1", "/v1evil"));
        assert!(!path_prefix_matches("/v1", "/v"));
        // Catch-all forms match everything.
        assert!(path_prefix_matches("", "/anything"));
        assert!(path_prefix_matches("/", "/anything"));
    }

    #[test]
    fn route_v1_does_not_match_v123() {
        let t = RouteTable::new(vec![
            route("v1", "", "/v1", "http://v1:80"),
            route("catch", "", "", "http://default:80"),
        ]);
        assert_eq!(t.select("h", "/v1").unwrap().upstream, "http://v1:80");
        assert_eq!(t.select("h", "/v1/ok").unwrap().upstream, "http://v1:80");
        assert_eq!(t.select("h", "/v123").unwrap().upstream, "http://default:80");
        assert_eq!(t.select("h", "/v1evil").unwrap().upstream, "http://default:80");
    }

    #[test]
    fn namespace_cleared_by_higher_layer() {
        // SHOULD-FIX 4: file sets namespace, env clears it (empty => all).
        let file = (
            PartialStatic {
                kubernetes_namespace: namespace_layer(Some("prod".to_owned())),
                ..Default::default()
            },
            Vec::new(),
        );
        let env = PartialStatic {
            kubernetes_namespace: namespace_layer(Some(String::new())),
            ..Default::default()
        };
        let cfg = Config::resolve_layers(file, env, PartialStatic::default());
        assert_eq!(cfg.r#static.discovery.kubernetes.namespace, None);
        assert_eq!(
            cfg.provenance.get("discovery.kubernetes.namespace"),
            Some(Source::Env)
        );
    }

    #[test]
    fn namespace_set_by_higher_layer() {
        let file = (
            PartialStatic {
                kubernetes_namespace: namespace_layer(Some("prod".to_owned())),
                ..Default::default()
            },
            Vec::new(),
        );
        let env = PartialStatic {
            kubernetes_namespace: namespace_layer(Some("staging".to_owned())),
            ..Default::default()
        };
        let cfg = Config::resolve_layers(file, env, PartialStatic::default());
        assert_eq!(
            cfg.r#static.discovery.kubernetes.namespace.as_deref(),
            Some("staging")
        );
        assert_eq!(
            cfg.provenance.get("discovery.kubernetes.namespace"),
            Some(Source::Env)
        );
    }

    #[test]
    fn parse_bool_token_trims_and_normalizes() {
        assert_eq!(parse_bool_token(" TRUE "), Some(true));
        assert_eq!(parse_bool_token("On"), Some(true));
        assert_eq!(parse_bool_token("0"), Some(false));
        assert_eq!(parse_bool_token("  no"), Some(false));
        assert_eq!(parse_bool_token("maybe"), None);
    }

    #[test]
    fn route_no_match_returns_none() {
        let t = RouteTable::new(vec![route("api", "api.internal", "", "http://api:80")]);
        assert!(t.select("nope", "/x").is_none());
    }

    #[test]
    fn file_upstream_backcompat_becomes_catchall() {
        let toml = "[server]\nlisten = \"127.0.0.1:9000\"\n\n[upstream]\ntarget = \"http://back:8080\"\n";
        let dir = std::env::temp_dir().join(format!("aproxy-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("c.toml");
        std::fs::write(&path, toml).unwrap();
        let (partial, routes) = Config::read_file(path.to_str().unwrap()).unwrap();
        assert_eq!(partial.listen.unwrap().to_string(), "127.0.0.1:9000");
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].upstream, "http://back:8080");
        assert!(routes[0].host.is_empty() && routes[0].path_prefix.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_routes_parsed() {
        let toml = r#"
[[route]]
name = "api"
host = "api.internal"
path_prefix = "/v1"
upstream = "http://api:8080"
strict_attestation = true

[[route]]
upstream = "http://default:80"
"#;
        let dir = std::env::temp_dir().join(format!("aproxy-cfg2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("c.toml");
        std::fs::write(&path, toml).unwrap();
        let (_partial, routes) = Config::read_file(path.to_str().unwrap()).unwrap();
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].name, "api");
        assert_eq!(routes[0].strict_attestation, Some(true));
        assert_eq!(routes[1].name, "route-1");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn acme_cfg(challenge: AcmeChallenge, domains: &[&str]) -> AcmeConfig {
        AcmeConfig {
            enabled: true,
            domains: domains.iter().map(|d| (*d).to_owned()).collect(),
            contact: Some("admin@example.com".to_owned()),
            challenge,
            directory_url: None,
            staging: true,
            cache_dir: None,
            http01_listen: None,
            dns: AcmeDnsConfig::default(),
        }
    }

    #[test]
    fn tls_validate_static_pair_ok() {
        let tls = TlsConfig {
            cert_path: Some("/c.pem".to_owned()),
            key_path: Some("/k.pem".to_owned()),
            acme: None,
        };
        assert!(matches!(tls.validate(), Ok(TlsMode::Static { .. })));
    }

    #[test]
    fn tls_validate_static_and_acme_mutually_exclusive() {
        let tls = TlsConfig {
            cert_path: Some("/c.pem".to_owned()),
            key_path: Some("/k.pem".to_owned()),
            acme: Some(acme_cfg(AcmeChallenge::TlsAlpn01, &["example.com"])),
        };
        let err = tls.validate().unwrap_err();
        assert!(err.contains("mutually exclusive"), "got {err}");
    }

    #[test]
    fn tls_validate_no_source_is_error() {
        let tls = TlsConfig {
            cert_path: None,
            key_path: None,
            acme: None,
        };
        let err = tls.validate().unwrap_err();
        assert!(err.contains("no cert source"), "got {err}");
    }

    #[test]
    fn tls_validate_half_static_pair_is_error() {
        let tls = TlsConfig {
            cert_path: Some("/c.pem".to_owned()),
            key_path: None,
            acme: None,
        };
        let err = tls.validate().unwrap_err();
        assert!(err.contains("key_path is missing"), "got {err}");
    }

    #[test]
    fn tls_validate_acme_requires_domains() {
        let tls = TlsConfig {
            cert_path: None,
            key_path: None,
            acme: Some(acme_cfg(AcmeChallenge::TlsAlpn01, &[])),
        };
        let err = tls.validate().unwrap_err();
        assert!(err.contains("`domains` is empty"), "got {err}");
    }

    #[test]
    fn tls_validate_acme_disabled_is_no_source() {
        // enabled=false means ACME is not a cert source; with no static pair
        // either, validate must report "no cert source".
        let mut acme = acme_cfg(AcmeChallenge::TlsAlpn01, &["example.com"]);
        acme.enabled = false;
        let tls = TlsConfig {
            cert_path: None,
            key_path: None,
            acme: Some(acme),
        };
        let err = tls.validate().unwrap_err();
        assert!(err.contains("no cert source"), "got {err}");
    }

    #[test]
    fn tls_validate_wildcard_requires_dns01() {
        for ch in [AcmeChallenge::TlsAlpn01, AcmeChallenge::Http01] {
            let tls = TlsConfig {
                cert_path: None,
                key_path: None,
                acme: Some(acme_cfg(ch, &["*.example.com"])),
            };
            let err = tls.validate().unwrap_err();
            assert!(
                err.contains("wildcard domain requires challenge=\"dns-01\""),
                "challenge {ch}: got {err}"
            );
        }
    }

    #[test]
    fn tls_validate_wildcard_ok_with_dns01() {
        let tls = TlsConfig {
            cert_path: None,
            key_path: None,
            acme: Some(acme_cfg(AcmeChallenge::Dns01, &["*.example.com"])),
        };
        assert!(matches!(tls.validate(), Ok(TlsMode::Acme(_))));
    }
}
