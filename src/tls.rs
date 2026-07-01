// Public-facing transport TLS termination (task #11). This is the OUTER
// listener TLS, distinct from the attested OpenHTTPA session (the inner,
// end-to-end encrypted channel), which is unaffected.
//
// CRYPTO BACKEND: rustls is driven with the aws-lc-rs provider, installed
// EXPLICITLY here. The dependency tree enables both rustls crypto features
// (`aws_lc_rs` from the openhttpa crates' crypto stack and `ring` pulled in
// transitively by rustls-webpki for cert-path verification), so rustls has no
// unambiguous process-default provider — `ServerConfig::builder()` would panic.
// `builder_with_provider(aws_lc_rs)` removes that ambiguity.
//
// CERT-SOURCE SEAM (for task #12 ACME): `CertSource` abstracts where the
// server certificate comes from. Both variants resolve to a single
// `Arc<dyn ResolvesServerCert>`, and the listener wiring only ever sees that
// resolver — so an ACME-backed, auto-renewing resolver (whose `CertifiedKey`
// is swapped at runtime) plugs in via `CertSource::Dynamic` WITHOUT touching
// `server_config` or the listener wiring in main.rs. Only `StaticFiles` is
// implemented now.

use std::sync::Arc;

use arc_swap::ArcSwap;
use rustls::ServerConfig;
use rustls::crypto::aws_lc_rs;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

/// ALPN protocol identifier for the TLS-ALPN-01 challenge (RFC 8737).
pub const ACME_TLS_ALPN_NAME: &[u8] = b"acme-tls/1";

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("failed to read TLS {kind} file {path}: {source}")]
    Read {
        kind: &'static str,
        path: String,
        source: std::io::Error,
    },
    #[error("no certificates found in PEM file {path}")]
    NoCerts { path: String },
    #[error("no private key found in PEM file {path}")]
    NoKey { path: String },
    #[error("invalid PEM in {kind} file {path}: {source}")]
    Pem {
        kind: &'static str,
        path: String,
        source: std::io::Error,
    },
    #[error("invalid private key in {path}: {source}")]
    Key {
        path: String,
        source: rustls::Error,
    },
    #[error(
        "TLS certificate {cert_path} and private key {key_path} do not match \
         (key does not correspond to the certificate's public key): {source}"
    )]
    KeyMismatch {
        cert_path: String,
        key_path: String,
        source: rustls::Error,
    },
    #[error("failed to build rustls ServerConfig: {0}")]
    Config(#[from] rustls::Error),
}

/// Where the server's TLS certificate comes from. The listener only consumes
/// the `ResolvesServerCert` this produces, so new variants (e.g. an ACME-backed
/// resolver in task #12) require no change to `server_config` or main.rs.
pub enum CertSource {
    /// Static PEM cert chain + private key loaded from disk at startup.
    StaticFiles { cert_path: String, key_path: String },
    /// SEAM (task #12 ACME): a runtime-swappable cert resolver. Not used yet.
    #[allow(dead_code)]
    Dynamic(Arc<dyn ResolvesServerCert>),
}

impl CertSource {
    /// Resolve this source into the rustls cert resolver the listener uses.
    /// FAIL-FAST: static files are read + parsed here; any missing/unreadable/
    /// invalid PEM is a hard error (no plaintext fallback).
    fn into_resolver(self) -> Result<Arc<dyn ResolvesServerCert>, TlsError> {
        match self {
            Self::StaticFiles {
                cert_path,
                key_path,
            } => {
                let certified = load_certified_key(&cert_path, &key_path)?;
                Ok(Arc::new(StaticCertResolver(Arc::new(certified))))
            }
            Self::Dynamic(resolver) => Ok(resolver),
        }
    }
}

/// A `ResolvesServerCert` that always returns one fixed certificate. Used for
/// `CertSource::StaticFiles`. Task #12's ACME resolver replaces this with one
/// that hot-swaps the inner `CertifiedKey` on renewal.
#[derive(Debug)]
struct StaticCertResolver(Arc<CertifiedKey>);

impl ResolvesServerCert for StaticCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// Build a rustls `ServerConfig` for the given cert source, pinning the
/// aws-lc-rs crypto provider explicitly (see module docs). Negotiates HTTP/2
/// and HTTP/1.1 over ALPN.
pub fn server_config(source: CertSource) -> Result<ServerConfig, TlsError> {
    let resolver = source.into_resolver()?;
    Ok(config_with_resolver(resolver, false))
}

/// Build a `ServerConfig` directly from an already-constructed resolver.
/// `acme_tls_alpn` adds the `acme-tls/1` protocol so TLS-ALPN-01 validation
/// connections negotiate it alongside the normal `h2`/`http/1.1` protocols.
pub fn config_with_resolver(
    resolver: Arc<dyn ResolvesServerCert>,
    acme_tls_alpn: bool,
) -> ServerConfig {
    let provider = Arc::new(aws_lc_rs::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("aws-lc-rs supports the default protocol versions")
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    if acme_tls_alpn {
        config.alpn_protocols.push(ACME_TLS_ALPN_NAME.to_vec());
    }
    config
}

/// Load a PEM cert chain + private key from disk into a rustls `CertifiedKey`,
/// signing with the aws-lc-rs provider.
fn load_certified_key(cert_path: &str, key_path: &str) -> Result<CertifiedKey, TlsError> {
    let cert_pem = std::fs::read(cert_path).map_err(|source| TlsError::Read {
        kind: "certificate",
        path: cert_path.to_owned(),
        source,
    })?;
    let key_pem = std::fs::read(key_path).map_err(|source| TlsError::Read {
        kind: "private key",
        path: key_path.to_owned(),
        source,
    })?;

    let certs = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| TlsError::Pem {
            kind: "certificate",
            path: cert_path.to_owned(),
            source,
        })?;
    if certs.is_empty() {
        return Err(TlsError::NoCerts {
            path: cert_path.to_owned(),
        });
    }

    let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .map_err(|source| TlsError::Pem {
            kind: "private key",
            path: key_path.to_owned(),
            source,
        })?
        .ok_or_else(|| TlsError::NoKey {
            path: key_path.to_owned(),
        })?;

    let signing_key = aws_lc_rs::sign::any_supported_type(&key).map_err(|source| TlsError::Key {
        path: key_path.to_owned(),
        source,
    })?;

    // FAIL-FAST on a cert/key MISMATCH: `CertifiedKey::new` does NOT check that
    // the private key corresponds to the certificate's public key, so a
    // mismatched pair would build a ServerConfig and only fail at handshake
    // time. `keys_match()` compares SubjectPublicKeyInfo bytes up front. An
    // `InconsistentKeys::Unknown` (provider can't introspect the key) is NOT
    // treated as an error — only a definite mismatch. ACME-issued certs flow
    // through the same `CertifiedKey` path (see `acme.rs`).
    let certified = CertifiedKey::new(certs, signing_key);
    match certified.keys_match() {
        Ok(()) | Err(rustls::Error::InconsistentKeys(rustls::InconsistentKeys::Unknown)) => {}
        Err(source) => {
            return Err(TlsError::KeyMismatch {
                cert_path: cert_path.to_owned(),
                key_path: key_path.to_owned(),
                source,
            });
        }
    }
    Ok(certified)
}

/// A runtime-swappable cert resolver for ACME (task #12). Holds the live
/// production certificate (hot-swapped on renewal via [`AcmeResolver::store`]
/// so the listener picks up the new cert without a restart) AND, for the
/// duration of a TLS-ALPN-01 challenge, a map of short-lived validation certs
/// keyed by SNI. When a ClientHello negotiates the `acme-tls/1` ALPN protocol
/// (the validation handshake), the matching validation cert is served instead
/// of the production cert. This is the concrete type fed into
/// [`CertSource::Dynamic`].
#[derive(Debug)]
pub struct AcmeResolver {
    /// The live production cert. `None` until first issuance/load.
    current: ArcSwap<Option<Arc<CertifiedKey>>>,
    /// SNI domain -> TLS-ALPN-01 validation cert, present only during a
    /// challenge.
    challenges: ArcSwap<std::collections::HashMap<String, Arc<CertifiedKey>>>,
}

impl AcmeResolver {
    /// Create an empty resolver (no cert yet). `resolve` returns `None` until
    /// a cert is stored, which makes the TLS handshake fail rather than serve
    /// a bogus cert — never a plaintext fallback.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            current: ArcSwap::from_pointee(None),
            challenges: ArcSwap::from_pointee(std::collections::HashMap::new()),
        }
    }

    /// Install / replace the live certificate (called after issuance + renewal).
    pub fn store(&self, certified: Arc<CertifiedKey>) {
        self.current.store(Arc::new(Some(certified)));
    }

    /// The currently installed production cert, if any.
    #[must_use]
    pub fn current(&self) -> Option<Arc<CertifiedKey>> {
        self.current.load().as_ref().clone()
    }

    /// Install a TLS-ALPN-01 validation cert for `domain`.
    pub fn set_challenge(&self, domain: String, certified: Arc<CertifiedKey>) {
        let mut map = self.challenges.load().as_ref().clone();
        map.insert(domain, certified);
        self.challenges.store(Arc::new(map));
    }

    /// Remove the TLS-ALPN-01 validation cert for `domain` after validation.
    pub fn clear_challenge(&self, domain: &str) {
        let mut map = self.challenges.load().as_ref().clone();
        map.remove(domain);
        self.challenges.store(Arc::new(map));
    }
}

impl ResolvesServerCert for AcmeResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // A TLS-ALPN-01 validation connection negotiates ONLY `acme-tls/1`.
        let is_acme_alpn = client_hello
            .alpn()
            .is_some_and(|mut p| p.any(|proto| proto == ACME_TLS_ALPN_NAME));
        if is_acme_alpn {
            if let Some(name) = client_hello.server_name() {
                return self.challenges.load().get(name).cloned();
            }
            return None;
        }
        self.current.load().as_ref().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_temp(dir: &std::path::Path, name: &str, bytes: &[u8]) -> String {
        let p = dir.join(name);
        std::fs::write(&p, bytes).unwrap();
        p.to_str().unwrap().to_owned()
    }

    #[test]
    fn static_files_round_trip_builds_config() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let dir = std::env::temp_dir().join(format!("aproxy-tls-ok-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = write_temp(&dir, "cert.pem", cert.cert.pem().as_bytes());
        let key_path = write_temp(&dir, "key.pem", cert.signing_key.serialize_pem().as_bytes());

        let cfg = server_config(CertSource::StaticFiles {
            cert_path,
            key_path,
        });
        assert!(cfg.is_ok(), "valid PEM should build a ServerConfig: {cfg:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_cert_file_fails_fast() {
        let err = server_config(CertSource::StaticFiles {
            cert_path: "/nonexistent/cert.pem".to_owned(),
            key_path: "/nonexistent/key.pem".to_owned(),
        })
        .unwrap_err();
        assert!(matches!(err, TlsError::Read { .. }), "got {err:?}");
    }

    #[test]
    fn invalid_pem_fails_fast() {
        let dir = std::env::temp_dir().join(format!("aproxy-tls-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = write_temp(&dir, "cert.pem", b"not a pem at all");
        let key_path = write_temp(&dir, "key.pem", b"also not a pem");
        let err = server_config(CertSource::StaticFiles {
            cert_path,
            key_path,
        })
        .unwrap_err();
        // No certs parse out of garbage -> NoCerts.
        assert!(matches!(err, TlsError::NoCerts { .. }), "got {err:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
