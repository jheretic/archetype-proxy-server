// ACME automatic TLS certificate provisioning.
//
// The issued/renewed cert is fed into an `AcmeResolver` (a swappable
// `ResolvesServerCert`, `tls.rs`) wrapped as `CertSource::Dynamic`, so
// renewals take effect on the live :443 listener without a restart and without
// touching the listener wiring.
//
// Three config-selectable challenge types (RFC 8555 / RFC 8737):
//   * tls-alpn-01 (default): a validation cert is installed into the
//     `AcmeResolver`; the CA connects to :443 negotiating `acme-tls/1` and the
//     resolver serves it (no extra listener).
//   * http-01: a key-authorization is served at
//     GET /.well-known/acme-challenge/<token> by a small plaintext :80 listener.
//   * dns-01: a `_acme-challenge` TXT record is published via a `DnsProvider`
//     (manual/hook). DNS-01 is the only type that can issue wildcard certs.
//
// Any ACME error aborts issuance with a clear log; the server does not
// silently serve plaintext or an expired cert. Account + issued cert are
// persisted under `cache_dir` and a still-valid cached cert is reused on boot.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, KeyAuthorization,
    LetsEncrypt, NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use rustls::crypto::aws_lc_rs;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;
use tokio::sync::Mutex;

use crate::config::{AcmeChallenge, AcmeConfig, DnsProviderKind};
use crate::tls::AcmeResolver;

/// Renew when the certificate has this much (or less) of its lifetime left.
/// Let's Encrypt certs live 90 days; 30 days is the conventional renewal lead.
const RENEW_BEFORE: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// How often the background task checks whether renewal is due.
const RENEW_CHECK_INTERVAL: Duration = Duration::from_secs(12 * 60 * 60);

const ACCOUNT_FILE: &str = "account.json";
const CERT_FILE: &str = "cert.pem";
const KEY_FILE: &str = "key.pem";

#[derive(Debug, thiserror::Error)]
pub enum AcmeError {
    #[error("ACME protocol error: {0}")]
    Acme(#[from] instant_acme::Error),
    #[error("cache I/O error for {path}: {source}")]
    Cache {
        path: String,
        source: std::io::Error,
    },
    #[error("certificate generation error: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("invalid issued certificate: {0}")]
    Cert(String),
    #[error("ACME authorization for {domain} failed with status {status:?}")]
    Authorization {
        domain: String,
        status: AuthorizationStatus,
    },
    #[error("ACME order did not become valid (status {0:?})")]
    Order(OrderStatus),
    #[error("DNS-01 hook command failed: {0}")]
    DnsHook(String),
    #[error("DNS-01 provider error: {0}")]
    Dns(String),
    #[error("rustls key error: {0}")]
    Rustls(#[from] rustls::Error),
}

/// A pending challenge response the manager must publish before telling the CA
/// to validate. Produced by [`challenge_response`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChallengeResponse {
    /// Serve `key_authorization` at `/.well-known/acme-challenge/{token}`.
    Http01 {
        token: String,
        key_authorization: String,
    },
    /// Install a self-signed validation cert (with the ACME identifier
    /// extension over `digest`) for `domain` into the `AcmeResolver`.
    TlsAlpn01 { domain: String, digest: Vec<u8> },
    /// Publish a `_acme-challenge.<domain>` TXT record with `value`.
    Dns01 {
        domain: String,
        record_name: String,
        value: String,
    },
}

/// Compute the challenge response payload from a challenge type and the
/// already-extracted key-authorization values. Takes no `KeyAuthorization` so
/// the per-type dispatch can be tested without a live CA. `key_auth` is the
/// raw authorization string (HTTP-01 body), `digest` its SHA-256
/// (TLS-ALPN-01), `dns_value` its base64url digest (DNS-01 TXT value).
#[must_use]
pub fn build_challenge_response(
    challenge: AcmeChallenge,
    domain: &str,
    token: &str,
    key_auth: &str,
    digest: &[u8],
    dns_value: &str,
) -> ChallengeResponse {
    match challenge {
        AcmeChallenge::Http01 => ChallengeResponse::Http01 {
            token: token.to_owned(),
            key_authorization: key_auth.to_owned(),
        },
        AcmeChallenge::TlsAlpn01 => ChallengeResponse::TlsAlpn01 {
            domain: domain.to_owned(),
            digest: digest.to_vec(),
        },
        AcmeChallenge::Dns01 => ChallengeResponse::Dns01 {
            domain: domain.to_owned(),
            record_name: dns_record_name(domain),
            value: dns_value.to_owned(),
        },
    }
}

/// Adapter from instant-acme's [`KeyAuthorization`] to the dispatch above.
#[must_use]
pub fn challenge_response(
    challenge: AcmeChallenge,
    domain: &str,
    token: &str,
    key_auth: &KeyAuthorization,
) -> ChallengeResponse {
    build_challenge_response(
        challenge,
        domain,
        token,
        key_auth.as_str(),
        key_auth.digest().as_ref(),
        &key_auth.dns_value(),
    )
}

/// The `_acme-challenge` TXT record name for a (possibly wildcard) domain. For
/// `*.example.com` the record is `_acme-challenge.example.com`.
#[must_use]
pub fn dns_record_name(domain: &str) -> String {
    let base = domain.strip_prefix("*.").unwrap_or(domain);
    format!("_acme-challenge.{base}")
}

/// HTTP-01 token store shared with the :80 responder. Maps token ->
/// key-authorization body. Empty except while a challenge is in flight.
#[derive(Debug, Clone, Default)]
pub struct Http01Tokens {
    inner: Arc<arc_swap::ArcSwap<HashMap<String, String>>>,
}

impl Http01Tokens {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(arc_swap::ArcSwap::from_pointee(HashMap::new())),
        }
    }

    pub fn insert(&self, token: String, key_authorization: String) {
        let mut map = self.inner.load().as_ref().clone();
        map.insert(token, key_authorization);
        self.inner.store(Arc::new(map));
    }

    pub fn remove(&self, token: &str) {
        let mut map = self.inner.load().as_ref().clone();
        map.remove(token);
        self.inner.store(Arc::new(map));
    }

    /// The key-authorization body for `token`, if a challenge is in flight.
    #[must_use]
    pub fn get(&self, token: &str) -> Option<String> {
        self.inner.load().get(token).cloned()
    }
}

/// A pluggable DNS-01 provider: publishes / removes the `_acme-challenge` TXT
/// record. Only the manual/hook provider is implemented; specific APIs
/// (Cloudflare/Route53/etc.) can be added behind this trait.
#[async_trait::async_trait]
pub trait DnsProvider: Send + Sync {
    /// Publish a TXT record `record_name` => `value`. Implementations should
    /// return only once the record is (believed) live.
    async fn publish(&self, domain: &str, record_name: &str, value: &str)
    -> Result<(), AcmeError>;

    /// Remove the TXT record after validation (best-effort cleanup).
    async fn cleanup(&self, domain: &str, record_name: &str, value: &str);
}

/// Manual / hook DNS provider. If a `hook_command` is configured it is invoked
/// with the record details in the environment; otherwise the required record
/// is logged and the operator is expected to publish it out of band. Either
/// way it then waits `propagation_secs` for propagation.
pub struct ManualDnsProvider {
    hook_command: Option<String>,
    cleanup_command: Option<String>,
    propagation: Duration,
}

impl ManualDnsProvider {
    #[must_use]
    pub fn new(
        hook_command: Option<String>,
        cleanup_command: Option<String>,
        propagation_secs: u64,
    ) -> Self {
        Self {
            hook_command,
            cleanup_command,
            propagation: Duration::from_secs(propagation_secs),
        }
    }

    async fn run_hook(
        command: &str,
        domain: &str,
        record_name: &str,
        value: &str,
    ) -> Result<(), AcmeError> {
        let status = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(command)
            .env("ACME_DNS_DOMAIN", domain)
            .env("ACME_DNS_NAME", record_name)
            .env("ACME_DNS_VALUE", value)
            .status()
            .await
            .map_err(|e| AcmeError::DnsHook(format!("failed to spawn {command:?}: {e}")))?;
        if !status.success() {
            return Err(AcmeError::DnsHook(format!(
                "command {command:?} exited with {status}"
            )));
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl DnsProvider for ManualDnsProvider {
    async fn publish(
        &self,
        domain: &str,
        record_name: &str,
        value: &str,
    ) -> Result<(), AcmeError> {
        match &self.hook_command {
            Some(cmd) => {
                tracing::info!(%record_name, "running DNS-01 publish hook");
                Self::run_hook(cmd, domain, record_name, value).await?;
            }
            None => {
                tracing::warn!(
                    %record_name,
                    %value,
                    "DNS-01 manual mode: create this TXT record now \
                     (no hook_command configured)"
                );
            }
        }
        tracing::info!(
            secs = self.propagation.as_secs(),
            "waiting for DNS propagation"
        );
        tokio::time::sleep(self.propagation).await;
        Ok(())
    }

    async fn cleanup(&self, domain: &str, record_name: &str, value: &str) {
        if let Some(cmd) = &self.cleanup_command
            && let Err(e) = Self::run_hook(cmd, domain, record_name, value).await
        {
            tracing::warn!(error = %e, "DNS-01 cleanup hook failed");
        }
    }
}

/// Default Cloudflare API base. Overridable so tests can point at a local stub.
const CLOUDFLARE_API_BASE: &str = "https://api.cloudflare.com";

/// Cloudflare API v4 DNS-01 provider. Publishes/removes the `_acme-challenge`
/// TXT record over the shared reqwest stack (no `cloudflare` crate, so nothing
/// pulls `ring`). The zone id is either configured or auto-discovered by
/// walking the record's domain labels; discovered ids are cached.
pub struct CloudflareDnsProvider {
    client: reqwest::Client,
    token: String,
    zone_id: Option<String>,
    base_url: String,
    propagation: Duration,
    // (record_name, value) -> created DNS record id, for cleanup.
    records: Mutex<HashMap<(String, String), String>>,
    // Cache of discovered zone ids keyed by the registrable domain candidate.
    zone_cache: Mutex<HashMap<String, String>>,
}

#[derive(serde::Deserialize)]
struct CfError {
    code: i64,
    message: String,
}

#[derive(serde::Deserialize)]
struct CfEnvelope<T> {
    success: bool,
    #[serde(default)]
    errors: Vec<CfError>,
    result: Option<T>,
}

#[derive(serde::Deserialize)]
struct CfRecord {
    id: String,
}

#[derive(serde::Deserialize)]
struct CfZone {
    id: String,
}

fn cf_errors_to_string(errors: &[CfError]) -> String {
    if errors.is_empty() {
        return "no error detail".to_owned();
    }
    errors
        .iter()
        .map(|e| format!("{} ({})", e.message, e.code))
        .collect::<Vec<_>>()
        .join("; ")
}

impl CloudflareDnsProvider {
    #[must_use]
    pub fn new(
        client: reqwest::Client,
        token: String,
        zone_id: Option<String>,
        propagation_secs: u64,
    ) -> Self {
        Self::with_base_url(
            client,
            token,
            zone_id,
            propagation_secs,
            CLOUDFLARE_API_BASE.to_owned(),
        )
    }

    #[must_use]
    pub fn with_base_url(
        client: reqwest::Client,
        token: String,
        zone_id: Option<String>,
        propagation_secs: u64,
        base_url: String,
    ) -> Self {
        Self {
            client,
            token,
            zone_id,
            base_url: base_url.trim_end_matches('/').to_owned(),
            propagation: Duration::from_secs(propagation_secs),
            records: Mutex::new(HashMap::new()),
            zone_cache: Mutex::new(HashMap::new()),
        }
    }

    /// Registrable-domain candidates for zone lookup, from most specific up,
    /// derived from the TXT record name with the leading `_acme-challenge.`
    /// stripped. `_acme-challenge.foo.example.com` yields
    /// `foo.example.com`, `example.com`, `com`.
    fn zone_candidates(record_name: &str) -> Vec<String> {
        let base = record_name
            .strip_prefix("_acme-challenge.")
            .unwrap_or(record_name);
        let labels: Vec<&str> = base.split('.').filter(|l| !l.is_empty()).collect();
        (0..labels.len())
            .map(|i| labels[i..].join("."))
            .collect()
    }

    async fn resolve_zone_id(&self, record_name: &str) -> Result<String, AcmeError> {
        if let Some(id) = &self.zone_id {
            return Ok(id.clone());
        }
        for candidate in Self::zone_candidates(record_name) {
            if let Some(id) = self.zone_cache.lock().await.get(&candidate) {
                return Ok(id.clone());
            }
            let url = format!("{}/client/v4/zones", self.base_url);
            let resp = self
                .client
                .get(&url)
                .bearer_auth(&self.token)
                .query(&[("name", candidate.as_str())])
                .send()
                .await
                .map_err(|e| AcmeError::Dns(format!("zone lookup request failed: {e}")))?;
            let env: CfEnvelope<Vec<CfZone>> = resp
                .json()
                .await
                .map_err(|e| AcmeError::Dns(format!("zone lookup decode failed: {e}")))?;
            if !env.success {
                return Err(AcmeError::Dns(format!(
                    "zone lookup for {candidate:?} failed: {}",
                    cf_errors_to_string(&env.errors)
                )));
            }
            if let Some(zone) = env.result.and_then(|z| z.into_iter().next()) {
                self.zone_cache
                    .lock()
                    .await
                    .insert(candidate, zone.id.clone());
                return Ok(zone.id);
            }
        }
        Err(AcmeError::Dns(format!(
            "no Cloudflare zone found for {record_name:?} (check the token has Zone:Read \
             or set zone_id explicitly)"
        )))
    }
}

#[async_trait::async_trait]
impl DnsProvider for CloudflareDnsProvider {
    async fn publish(
        &self,
        _domain: &str,
        record_name: &str,
        value: &str,
    ) -> Result<(), AcmeError> {
        let zone_id = self.resolve_zone_id(record_name).await?;
        let url = format!("{}/client/v4/zones/{zone_id}/dns_records", self.base_url);
        let body = serde_json::json!({
            "type": "TXT",
            "name": record_name,
            "content": value,
            "ttl": 60,
        });
        let resp = self
            .client
            .post(&url)
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .map_err(|e| AcmeError::Dns(format!("create TXT request failed: {e}")))?;
        let env: CfEnvelope<CfRecord> = resp
            .json()
            .await
            .map_err(|e| AcmeError::Dns(format!("create TXT decode failed: {e}")))?;
        if !env.success {
            return Err(AcmeError::Dns(format!(
                "create TXT {record_name:?} failed: {}",
                cf_errors_to_string(&env.errors)
            )));
        }
        let record = env
            .result
            .ok_or_else(|| AcmeError::Dns("create TXT returned no record".to_owned()))?;
        self.records
            .lock()
            .await
            .insert((record_name.to_owned(), value.to_owned()), record.id);

        tracing::info!(
            secs = self.propagation.as_secs(),
            "waiting for DNS propagation"
        );
        tokio::time::sleep(self.propagation).await;
        Ok(())
    }

    async fn cleanup(&self, _domain: &str, record_name: &str, value: &str) {
        let key = (record_name.to_owned(), value.to_owned());
        let Some(record_id) = self.records.lock().await.remove(&key) else {
            tracing::warn!(%record_name, "no tracked Cloudflare record id to clean up");
            return;
        };
        let zone_id = match self.resolve_zone_id(record_name).await {
            Ok(id) => id,
            Err(e) => {
                tracing::warn!(error = %e, "DNS-01 cleanup: zone resolve failed");
                return;
            }
        };
        let url = format!(
            "{}/client/v4/zones/{zone_id}/dns_records/{record_id}",
            self.base_url
        );
        match self.client.delete(&url).bearer_auth(&self.token).send().await {
            Ok(resp) if resp.status().is_success() => {}
            Ok(resp) => {
                tracing::warn!(status = %resp.status(), "DNS-01 cleanup DELETE returned error");
            }
            Err(e) => tracing::warn!(error = %e, "DNS-01 cleanup DELETE failed"),
        }
    }
}

/// An issued certificate: PEM chain + PEM private key.
#[derive(Debug, Clone)]
pub struct IssuedCert {
    pub cert_pem: String,
    pub key_pem: String,
}

impl IssuedCert {
    /// Parse into a rustls `CertifiedKey` (aws-lc-rs provider). Verifies the
    /// key matches the cert, the same check as for static certs.
    pub fn into_certified_key(&self) -> Result<CertifiedKey, AcmeError> {
        let certs = CertificateDer::pem_slice_iter(self.cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| AcmeError::Cert(format!("certificate PEM: {e}")))?;
        if certs.is_empty() {
            return Err(AcmeError::Cert("no certificates in issued PEM".to_owned()));
        }
        let key = PrivateKeyDer::from_pem_slice(self.key_pem.as_bytes())
            .map_err(|e| AcmeError::Cert(format!("private key PEM: {e}")))?;
        let provider = aws_lc_rs::default_provider();
        let certified = CertifiedKey::from_der(certs, key, &provider)?;
        Ok(certified)
    }

    /// Seconds of validity remaining on the end-entity cert, or `None` if the
    /// cert is unparseable or already expired/not-yet-valid.
    #[must_use]
    pub fn time_to_expiry(&self) -> Option<Duration> {
        let der = CertificateDer::pem_slice_iter(self.cert_pem.as_bytes())
            .next()?
            .ok()?;
        let (_, parsed) = x509_parser::parse_x509_certificate(der.as_ref()).ok()?;
        let secs = parsed.validity().time_to_expiration()?.whole_seconds();
        u64::try_from(secs).ok().map(Duration::from_secs)
    }

    /// Whether this cert needs renewal (expires within `RENEW_BEFORE`, or is
    /// already invalid/unparseable).
    #[must_use]
    pub fn needs_renewal(&self) -> bool {
        match self.time_to_expiry() {
            Some(remaining) => remaining <= RENEW_BEFORE,
            None => true,
        }
    }
}

/// Persisted ACME state under `cache_dir`.
struct Cache {
    dir: PathBuf,
}

impl Cache {
    fn new(dir: &str) -> Self {
        Self {
            dir: PathBuf::from(dir),
        }
    }

    fn ensure_dir(&self) -> Result<(), AcmeError> {
        std::fs::create_dir_all(&self.dir).map_err(|source| AcmeError::Cache {
            path: self.dir.display().to_string(),
            source,
        })
    }

    fn read(&self, name: &str) -> Option<String> {
        std::fs::read_to_string(self.dir.join(name)).ok()
    }

    fn write(&self, name: &str, contents: &str) -> Result<(), AcmeError> {
        let path = self.dir.join(name);
        std::fs::write(&path, contents).map_err(|source| AcmeError::Cache {
            path: path.display().to_string(),
            source,
        })
    }

    fn load_cert(&self) -> Option<IssuedCert> {
        Some(IssuedCert {
            cert_pem: self.read(CERT_FILE)?,
            key_pem: self.read(KEY_FILE)?,
        })
    }

    fn store_cert(&self, cert: &IssuedCert) -> Result<(), AcmeError> {
        self.write(CERT_FILE, &cert.cert_pem)?;
        self.write(KEY_FILE, &cert.key_pem)?;
        Ok(())
    }
}

/// Resolve the ACME directory URL from config (explicit URL > staging flag >
/// Let's Encrypt production).
#[must_use]
pub fn directory_url(cfg: &AcmeConfig) -> String {
    if let Some(url) = &cfg.directory_url {
        return url.clone();
    }
    if cfg.staging {
        LetsEncrypt::Staging.url().to_owned()
    } else {
        LetsEncrypt::Production.url().to_owned()
    }
}

/// Drives ACME issuance + renewal and owns the shared challenge-response state.
pub struct AcmeManager {
    cfg: AcmeConfig,
    resolver: Arc<AcmeResolver>,
    http_tokens: Http01Tokens,
    dns: Arc<dyn DnsProvider>,
    cache: Option<Cache>,
    // Serialize issuance so renewal and startup can't race the order machinery.
    lock: Mutex<()>,
}

impl AcmeManager {
    /// Fails fast if the Cloudflare provider is selected but no API token
    /// resolves; token resolution at construction avoids surfacing a
    /// misconfiguration only mid-issuance.
    pub fn new(
        cfg: AcmeConfig,
        resolver: Arc<AcmeResolver>,
        http_tokens: Http01Tokens,
    ) -> Result<Self, AcmeError> {
        let dns: Arc<dyn DnsProvider> = match cfg.dns.provider {
            DnsProviderKind::Manual => Arc::new(ManualDnsProvider::new(
                cfg.dns.hook_command.clone(),
                cfg.dns.cleanup_command.clone(),
                cfg.dns.propagation_secs,
            )),
            DnsProviderKind::Cloudflare => {
                let token = cfg.dns.resolve_cf_token().ok_or_else(|| {
                    AcmeError::Dns(
                        "dns provider=cloudflare requires a token via api_token or \
                         api_token_env (env var unset or empty)"
                            .to_owned(),
                    )
                })?;
                Arc::new(CloudflareDnsProvider::new(
                    reqwest::Client::new(),
                    token,
                    cfg.dns.zone_id.clone(),
                    cfg.dns.propagation_secs,
                ))
            }
        };
        let cache = cfg.cache_dir.as_deref().map(Cache::new);
        Ok(Self {
            cfg,
            resolver,
            http_tokens,
            dns,
            cache,
            lock: Mutex::new(()),
        })
    }

    /// Load a cached, still-valid cert into the resolver. Returns true if a
    /// usable cert was installed (issuance can be skipped at startup).
    pub fn load_cached(&self) -> bool {
        let Some(cache) = &self.cache else {
            return false;
        };
        let Some(cert) = cache.load_cert() else {
            return false;
        };
        if cert.needs_renewal() {
            tracing::info!("cached ACME cert is missing/expired/near-expiry; will re-issue");
            return false;
        }
        match cert.into_certified_key() {
            Ok(ck) => {
                self.resolver.store(Arc::new(ck));
                tracing::info!("reused cached ACME certificate");
                true
            }
            Err(e) => {
                tracing::warn!(error = %e, "cached ACME cert unusable; will re-issue");
                false
            }
        }
    }

    /// Obtain or restore the ACME account, persisting credentials to the cache.
    async fn account(&self) -> Result<Account, AcmeError> {
        if let Some(cache) = &self.cache
            && let Some(raw) = cache.read(ACCOUNT_FILE)
        {
            if let Ok(creds) = serde_json::from_str::<AccountCredentials>(&raw) {
                tracing::debug!("restoring ACME account from cache");
                return Ok(Account::builder()?.from_credentials(creds).await?);
            }
            tracing::warn!("cached ACME account unreadable; creating a new account");
        }

        let contact: Vec<String> = self
            .cfg
            .contact
            .as_ref()
            .map(|c| {
                vec![if c.starts_with("mailto:") {
                    c.clone()
                } else {
                    format!("mailto:{c}")
                }]
            })
            .unwrap_or_default();
        let contact_refs: Vec<&str> = contact.iter().map(String::as_str).collect();

        let (account, creds) = Account::builder()?
            .create(
                &NewAccount {
                    contact: &contact_refs,
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                directory_url(&self.cfg),
                None,
            )
            .await?;

        if let Some(cache) = &self.cache {
            cache.ensure_dir()?;
            cache.write(ACCOUNT_FILE, &serde_json::to_string(&creds).map_err(|e| {
                AcmeError::Cert(format!("serialize account credentials: {e}"))
            })?)?;
        }
        Ok(account)
    }

    /// Run a full ACME order for all configured domains, install the issued
    /// cert into the resolver, and persist it. Aborts on any error.
    pub async fn issue(&self) -> Result<IssuedCert, AcmeError> {
        let _guard = self.lock.lock().await;
        let account = self.account().await?;

        let identifiers: Vec<Identifier> = self
            .cfg
            .domains
            .iter()
            .map(|d| Identifier::Dns(d.clone()))
            .collect();
        let mut order = account.new_order(&NewOrder::new(&identifiers)).await?;

        // Set up a response for each authorization's selected challenge.
        let challenge_type = self.challenge_type();
        let mut authorizations = order.authorizations();
        let mut active_dns: Vec<(String, String, String)> = Vec::new();
        let mut active_alpn: Vec<String> = Vec::new();
        let mut active_http: Vec<String> = Vec::new();

        while let Some(authz) = authorizations.next().await {
            let mut authz = authz?;
            match authz.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                status => {
                    return Err(AcmeError::Authorization {
                        domain: identifier_domain(&authz),
                        status,
                    });
                }
            }

            let domain = identifier_domain(&authz);
            let mut challenge = authz
                .challenge(challenge_type.clone())
                .ok_or_else(|| AcmeError::Cert(format!(
                    "ACME server offered no {} challenge for {domain}",
                    self.cfg.challenge
                )))?;
            let token = challenge.token.clone();
            let key_auth = challenge.key_authorization();
            let response = challenge_response(self.cfg.challenge, &domain, &token, &key_auth);

            match response {
                ChallengeResponse::Http01 {
                    token,
                    key_authorization,
                } => {
                    self.http_tokens.insert(token.clone(), key_authorization);
                    active_http.push(token);
                }
                ChallengeResponse::TlsAlpn01 { domain, digest } => {
                    let ck = tls_alpn_cert(&domain, &digest)?;
                    self.resolver.set_challenge(domain.clone(), Arc::new(ck));
                    active_alpn.push(domain);
                }
                ChallengeResponse::Dns01 {
                    domain,
                    record_name,
                    value,
                } => {
                    self.dns.publish(&domain, &record_name, &value).await?;
                    active_dns.push((domain, record_name, value));
                }
            }

            challenge.set_ready().await?;
        }

        // Tell the CA to validate and wait for the order to become ready.
        let result = self.finalize_and_fetch(&mut order).await;

        // Tear down challenge responses regardless of outcome.
        for token in &active_http {
            self.http_tokens.remove(token);
        }
        for domain in &active_alpn {
            self.resolver.clear_challenge(domain);
        }
        for (domain, record_name, value) in &active_dns {
            self.dns.cleanup(domain, record_name, value).await;
        }

        let issued = result?;
        if let Some(cache) = &self.cache {
            cache.ensure_dir()?;
            cache.store_cert(&issued)?;
        }
        let ck = issued.into_certified_key()?;
        self.resolver.store(Arc::new(ck));
        tracing::info!(
            domains = ?self.cfg.domains,
            challenge = %self.cfg.challenge,
            "ACME certificate issued and installed"
        );
        Ok(issued)
    }

    async fn finalize_and_fetch(
        &self,
        order: &mut instant_acme::Order,
    ) -> Result<IssuedCert, AcmeError> {
        let status = order.poll_ready(&RetryPolicy::default()).await?;
        if status != OrderStatus::Ready {
            return Err(AcmeError::Order(status));
        }
        // `finalize()` generates the keypair + CSR and returns the private key
        // PEM; `poll_certificate()` returns the issued chain PEM.
        let key_pem = order.finalize().await?;
        let cert_pem = order.poll_certificate(&RetryPolicy::default()).await?;
        Ok(IssuedCert { cert_pem, key_pem })
    }

    const fn challenge_type(&self) -> ChallengeType {
        match self.cfg.challenge {
            AcmeChallenge::TlsAlpn01 => ChallengeType::TlsAlpn01,
            AcmeChallenge::Http01 => ChallengeType::Http01,
            AcmeChallenge::Dns01 => ChallengeType::Dns01,
        }
    }

    /// Background loop: periodically re-issue before expiry. Runs forever.
    pub async fn renewal_loop(self: Arc<Self>) {
        loop {
            tokio::time::sleep(RENEW_CHECK_INTERVAL).await;
            let due = self
                .resolver
                .current()
                .is_none_or(|_| self.cert_needs_renewal());
            if !due {
                continue;
            }
            tracing::info!("ACME certificate renewal due; re-issuing");
            if let Err(e) = self.issue().await {
                tracing::error!(error = %e, "ACME renewal failed; will retry next cycle");
            }
        }
    }

    fn cert_needs_renewal(&self) -> bool {
        match self.cache.as_ref().and_then(Cache::load_cert) {
            Some(cert) => cert.needs_renewal(),
            None => true,
        }
    }
}

/// Build a self-signed TLS-ALPN-01 validation cert for `domain` carrying the
/// ACME identifier extension over `digest` (the SHA-256 of the key
/// authorization), per RFC 8737.
fn tls_alpn_cert(domain: &str, digest: &[u8]) -> Result<CertifiedKey, AcmeError> {
    let key_pair = rcgen::KeyPair::generate()?;
    let mut params = rcgen::CertificateParams::new(vec![domain.to_owned()])?;
    params
        .custom_extensions
        .push(rcgen::CustomExtension::new_acme_identifier(digest));
    let cert = params.self_signed(&key_pair)?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(key_pair.serialize_der())
        .map_err(|e| AcmeError::Cert(format!("rcgen key: {e}")))?;
    let provider = aws_lc_rs::default_provider();
    let signing_key = provider.key_provider.load_private_key(key_der)?;
    Ok(CertifiedKey::new(vec![cert_der], signing_key))
}

fn identifier_domain(authz: &instant_acme::AuthorizationHandle<'_>) -> String {
    authz.identifier().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AcmeChallenge, AcmeConfig, AcmeDnsConfig, DnsProviderKind};

    fn base_cfg() -> AcmeConfig {
        AcmeConfig {
            enabled: true,
            domains: vec!["example.com".to_owned()],
            contact: Some("admin@example.com".to_owned()),
            challenge: AcmeChallenge::TlsAlpn01,
            directory_url: None,
            staging: false,
            cache_dir: None,
            http01_listen: None,
            dns: AcmeDnsConfig::default(),
        }
    }

    #[test]
    fn directory_url_prefers_explicit_then_staging_then_prod() {
        let mut cfg = base_cfg();
        assert_eq!(directory_url(&cfg), LetsEncrypt::Production.url());
        cfg.staging = true;
        assert_eq!(directory_url(&cfg), LetsEncrypt::Staging.url());
        cfg.directory_url = Some("https://acme.example/dir".to_owned());
        assert_eq!(directory_url(&cfg), "https://acme.example/dir");
    }

    #[test]
    fn dns_record_name_strips_wildcard() {
        assert_eq!(dns_record_name("example.com"), "_acme-challenge.example.com");
        assert_eq!(
            dns_record_name("*.example.com"),
            "_acme-challenge.example.com"
        );
    }

    #[test]
    fn dispatch_http01_returns_keyauth_body_for_token() {
        let r = build_challenge_response(
            AcmeChallenge::Http01,
            "example.com",
            "tok123",
            "tok123.thumbprint",
            &[0u8; 32],
            "ignored",
        );
        assert_eq!(
            r,
            ChallengeResponse::Http01 {
                token: "tok123".to_owned(),
                key_authorization: "tok123.thumbprint".to_owned(),
            }
        );
    }

    #[test]
    fn dispatch_tls_alpn01_carries_digest_and_domain() {
        let digest = [0x42u8; 32];
        let r = build_challenge_response(
            AcmeChallenge::TlsAlpn01,
            "host.example.com",
            "tok",
            "tok.thumb",
            &digest,
            "ignored",
        );
        assert_eq!(
            r,
            ChallengeResponse::TlsAlpn01 {
                domain: "host.example.com".to_owned(),
                digest: digest.to_vec(),
            }
        );
    }

    #[test]
    fn dispatch_dns01_uses_record_name_and_txt_value() {
        let r = build_challenge_response(
            AcmeChallenge::Dns01,
            "*.example.com",
            "tok",
            "tok.thumb",
            &[0u8; 32],
            "base64url-digest",
        );
        assert_eq!(
            r,
            ChallengeResponse::Dns01 {
                domain: "*.example.com".to_owned(),
                record_name: "_acme-challenge.example.com".to_owned(),
                value: "base64url-digest".to_owned(),
            }
        );
    }

    #[test]
    fn http01_token_store_round_trip() {
        let tokens = Http01Tokens::new();
        assert_eq!(tokens.get("tok"), None);
        tokens.insert("tok".to_owned(), "tok.keyauth".to_owned());
        assert_eq!(tokens.get("tok").as_deref(), Some("tok.keyauth"));
        tokens.remove("tok");
        assert_eq!(tokens.get("tok"), None);
    }

    #[test]
    fn tls_alpn_validation_cert_builds() {
        let digest = [0x11u8; 32];
        let ck = tls_alpn_cert("example.com", &digest).unwrap();
        assert_eq!(ck.cert.len(), 1);
    }

    #[test]
    fn manual_provider_default_kind() {
        let cfg = AcmeDnsConfig::default();
        assert_eq!(cfg.provider, DnsProviderKind::Manual);
    }

    #[tokio::test]
    async fn manual_dns_provider_logs_without_hook() {
        // No hook command => publish just waits (0s propagation here).
        let p = ManualDnsProvider::new(None, None, 0);
        p.publish("example.com", "_acme-challenge.example.com", "val")
            .await
            .unwrap();
        // cleanup with no command is a no-op.
        p.cleanup("example.com", "_acme-challenge.example.com", "val")
            .await;
    }

    #[tokio::test]
    async fn manual_dns_provider_runs_hook_with_env() {
        let dir = std::env::temp_dir().join(format!("aproxy-acme-dns-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("hook.out");
        let cmd = format!(
            "printf '%s %s %s' \"$ACME_DNS_DOMAIN\" \"$ACME_DNS_NAME\" \"$ACME_DNS_VALUE\" > {}",
            out.display()
        );
        let p = ManualDnsProvider::new(Some(cmd), None, 0);
        p.publish("example.com", "_acme-challenge.example.com", "theval")
            .await
            .unwrap();
        let written = std::fs::read_to_string(&out).unwrap();
        assert_eq!(written, "example.com _acme-challenge.example.com theval");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn manual_dns_provider_hook_failure_is_error() {
        let p = ManualDnsProvider::new(Some("exit 3".to_owned()), None, 0);
        let err = p
            .publish("example.com", "_acme-challenge.example.com", "v")
            .await
            .unwrap_err();
        assert!(matches!(err, AcmeError::DnsHook(_)), "got {err:?}");
    }

    #[test]
    fn cf_zone_candidates_walk_labels() {
        assert_eq!(
            CloudflareDnsProvider::zone_candidates("_acme-challenge.foo.bar.example.com"),
            vec!["foo.bar.example.com", "bar.example.com", "example.com", "com"]
        );
        // Wildcard TXT records share the base name; no _acme-challenge prefix
        // is still handled.
        assert_eq!(
            CloudflareDnsProvider::zone_candidates("example.com"),
            vec!["example.com", "com"]
        );
    }

    // --- Cloudflare provider unit tests against a local axum stub ---
    //
    // These exercise the request/response wiring (JSON shape, Bearer auth,
    // zone auto-discovery, record-id capture + DELETE, error mapping) without
    // touching Cloudflare. Live DNS-01 issuance against a real token/zone plus
    // public DNS propagation cannot run in CI and is exercised manually.

    use std::sync::Arc as StdArc;
    use std::sync::Mutex as StdMutex;

    // reqwest uses rustls' `*-no-provider` feature, so a default crypto
    // provider must be installed before building a client (main() does this at
    // startup). Idempotent across tests.
    fn install_crypto_provider() {
        use std::sync::Once;
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = aws_lc_rs::default_provider().install_default();
        });
    }

    // (label, name-or-path, body, auth-header) captured per stub request.
    type StubReq = (String, String, Option<String>, Option<String>);

    #[derive(Default)]
    struct StubState {
        requests: StdMutex<Vec<StubReq>>,
    }

    async fn spawn_cf_stub(
        state: StdArc<StubState>,
        zone_name_match: Option<String>,
        create_success: bool,
    ) -> String {
        use axum::extract::{Query, State};
        use axum::routing::{delete, get, post};
        use axum::{Json, Router};
        use std::collections::HashMap as Map;

        async fn list_zones(
            State((state, zn)): State<(StdArc<StubState>, Option<String>)>,
            Query(q): Query<Map<String, String>>,
            headers: axum::http::HeaderMap,
        ) -> Json<serde_json::Value> {
            let auth = headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let name = q.get("name").cloned();
            state.requests.lock().unwrap().push((
                "GET zones".to_owned(),
                q.get("name").cloned().unwrap_or_default(),
                None,
                auth,
            ));
            let matches = zn.as_deref() == name.as_deref();
            let result = if matches {
                serde_json::json!([{"id": "zone-123"}])
            } else {
                serde_json::json!([])
            };
            Json(serde_json::json!({"success": true, "errors": [], "result": result}))
        }

        async fn create_record(
            State((state, ok)): State<(StdArc<StubState>, bool)>,
            headers: axum::http::HeaderMap,
            body: String,
        ) -> Json<serde_json::Value> {
            let auth = headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            state.requests.lock().unwrap().push((
                "POST record".to_owned(),
                String::new(),
                Some(body),
                auth,
            ));
            if ok {
                Json(serde_json::json!({
                    "success": true, "errors": [], "result": {"id": "rec-999"}
                }))
            } else {
                Json(serde_json::json!({
                    "success": false,
                    "errors": [{"code": 1004, "message": "DNS record invalid"}],
                    "result": null
                }))
            }
        }

        async fn delete_record(
            State(state): State<StdArc<StubState>>,
            axum::extract::Path((zone, id)): axum::extract::Path<(String, String)>,
        ) -> Json<serde_json::Value> {
            state.requests.lock().unwrap().push((
                "DELETE record".to_owned(),
                format!("{zone}/{id}"),
                None,
                None,
            ));
            Json(serde_json::json!({"success": true, "errors": [], "result": {"id": id}}))
        }

        let app = Router::new()
            .route(
                "/client/v4/zones",
                get(list_zones).with_state((state.clone(), zone_name_match)),
            )
            .route(
                "/client/v4/zones/{zone}/dns_records",
                post(create_record).with_state((state.clone(), create_success)),
            )
            .route(
                "/client/v4/zones/{zone}/dns_records/{id}",
                delete(delete_record).with_state(state.clone()),
            );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn cloudflare_publish_posts_txt_and_cleanup_deletes() {
        install_crypto_provider();
        let state = StdArc::new(StubState::default());
        let base = spawn_cf_stub(state.clone(), Some("example.com".to_owned()), true).await;
        let p = CloudflareDnsProvider::with_base_url(
            reqwest::Client::new(),
            "tok-abc".to_owned(),
            None,
            0,
            base,
        );

        p.publish("example.com", "_acme-challenge.example.com", "txtval")
            .await
            .unwrap();
        p.cleanup("example.com", "_acme-challenge.example.com", "txtval")
            .await;

        let reqs = state.requests.lock().unwrap();
        // zone auto-discovery hit the list endpoint and matched example.com.
        let zone_lookup = reqs.iter().find(|r| r.0 == "GET zones").unwrap();
        assert_eq!(zone_lookup.1, "example.com");
        assert_eq!(zone_lookup.3.as_deref(), Some("Bearer tok-abc"));

        // create carried the right JSON + auth.
        let create = reqs.iter().find(|r| r.0 == "POST record").unwrap();
        assert_eq!(create.3.as_deref(), Some("Bearer tok-abc"));
        let body: serde_json::Value = serde_json::from_str(create.2.as_deref().unwrap()).unwrap();
        assert_eq!(body["type"], "TXT");
        assert_eq!(body["name"], "_acme-challenge.example.com");
        assert_eq!(body["content"], "txtval");

        // cleanup deleted the captured record id in the discovered zone.
        let del = reqs.iter().find(|r| r.0 == "DELETE record").unwrap();
        assert_eq!(del.1, "zone-123/rec-999");
    }

    #[tokio::test]
    async fn cloudflare_zone_discovery_walks_to_registrable_domain() {
        install_crypto_provider();
        let state = StdArc::new(StubState::default());
        // Only the registrable domain matches; the more specific label must be
        // tried and skipped first.
        let base = spawn_cf_stub(state.clone(), Some("example.com".to_owned()), true).await;
        let p = CloudflareDnsProvider::with_base_url(
            reqwest::Client::new(),
            "tok".to_owned(),
            None,
            0,
            base,
        );
        p.publish("sub.example.com", "_acme-challenge.sub.example.com", "v")
            .await
            .unwrap();
        let reqs = state.requests.lock().unwrap();
        let names: Vec<&str> = reqs
            .iter()
            .filter(|r| r.0 == "GET zones")
            .map(|r| r.1.as_str())
            .collect();
        assert_eq!(names.first(), Some(&"sub.example.com"));
        assert!(names.contains(&"example.com"));
    }

    #[tokio::test]
    async fn cloudflare_publish_maps_cf_failure_to_error() {
        install_crypto_provider();
        let state = StdArc::new(StubState::default());
        let base = spawn_cf_stub(state, Some("example.com".to_owned()), false).await;
        let p = CloudflareDnsProvider::with_base_url(
            reqwest::Client::new(),
            "tok".to_owned(),
            Some("zone-123".to_owned()),
            0,
            base,
        );
        let err = p
            .publish("example.com", "_acme-challenge.example.com", "v")
            .await
            .unwrap_err();
        match err {
            AcmeError::Dns(m) => assert!(m.contains("DNS record invalid"), "got {m}"),
            other => panic!("expected AcmeError::Dns, got {other:?}"),
        }
    }

    #[test]
    fn construction_fails_fast_when_cloudflare_without_token() {
        let mut cfg = base_cfg();
        cfg.challenge = AcmeChallenge::Dns01;
        cfg.dns = AcmeDnsConfig {
            provider: DnsProviderKind::Cloudflare,
            ..AcmeDnsConfig::default()
        };
        let resolver = Arc::new(AcmeResolver::empty());
        match AcmeManager::new(cfg, resolver, Http01Tokens::new()) {
            Ok(_) => panic!("expected construction to fail without a token"),
            Err(AcmeError::Dns(_)) => {}
            Err(other) => panic!("expected AcmeError::Dns, got {other:?}"),
        }
    }
}
