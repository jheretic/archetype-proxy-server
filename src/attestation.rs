//! TEE provider + quote verifier selection from config, and the
//! no-mock-in-release startup guard (task #7).
//!
//! # Cargo feature mapping
//!
//! Real TEE providers/verifiers in the upstream openhttpa crates are gated
//! behind cargo features that pull in hardware SDKs / system libraries. We
//! mirror them as features ON THIS CRATE so the DEFAULT build stays mock-only
//! and CI-buildable on a box with no TEE hardware:
//!
//! | this crate feature | enables                       | provider / verifier            |
//! |--------------------|-------------------------------|--------------------------------|
//! | `tdx`              | `openhttpa-tee/tdx`           | `TdxTeeProvider`               |
//! | `sev_snp`          | `openhttpa-tee/sev_snp`       | `SevSnpTeeProvider`            |
//! | `sgx`              | `openhttpa-tee/sgx`           | `SgxTeeProvider`               |
//! | `trustzone`        | `openhttpa-tee/trustzone`     | `TrustZoneTeeProvider`         |
//! | `aws_nitro`        | `openhttpa-tee/aws_nitro`     | `AwsNitroTeeProvider`          |
//! | `maa`              | `openhttpa-attestation/maa`   | `MaaVerifier`                  |
//! | `ita`              | `openhttpa-attestation/ita`   | `ItaVerifier`                  |
//! | `amd_snp`          | `openhttpa-attestation/amd_snp` | `SevSnpVerifier` (full chain)|
//!
//! A variant selected at runtime whose feature was NOT compiled in fails fast
//! with a clear "requires building with --features X" error.

use std::sync::Arc;

use openhttpa_attestation::QuoteVerifier;
use openhttpa_tee::TeeProvider;

use crate::config::{AttestationConfig, TeeProviderKind, VerifierKind};

/// Resolved attestation mode, returned by the startup guard so `main` can log
/// the right banner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationMode {
    /// Real hardware attestation for both provider and verifier.
    Secure,
    /// At least one of provider/verifier/allow_mock is mock. Carries whether
    /// we are in a release build (so the caller logs the LOUD banner).
    Insecure { release: bool },
}

/// Fatal startup decision error. Stringly-typed message is the user-facing
/// reason printed before a non-zero exit.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct FatalError(pub String);

/// Env var that opts a RELEASE build into running with mock attestation.
pub const INSECURE_DEV_ENV: &str = "ARCHETYPE_PROXY_INSECURE_DEV";

/// `true` if the resolved config would use mock attestation in ANY of the
/// three independent ways it can creep in.
#[must_use]
pub fn uses_mock(cfg: &AttestationConfig) -> bool {
    cfg.allow_mock || cfg.tee_provider.is_mock() || cfg.verifier.is_mock()
}

/// PURE, fully unit-testable startup policy. Decides whether the server may
/// boot given the build profile, the resolved attestation config, and whether
/// the operator set the insecure-dev escape hatch.
///
/// Policy:
///   * real provider + real verifier + `allow_mock=false` => `Secure`, boot.
///   * mock in effect, debug build                        => `Insecure`, boot (warn).
///   * mock in effect, release build, escape hatch set    => `Insecure`, boot (LOUD warn).
///   * mock in effect, release build, no escape hatch     => `Err(FatalError)`.
///
/// # Errors
/// Returns [`FatalError`] when a release build would run mock attestation
/// without the explicit `ARCHETYPE_PROXY_INSECURE_DEV=1` escape hatch.
pub fn startup_attestation_decision(
    is_release: bool,
    cfg: &AttestationConfig,
    insecure_dev_env: bool,
) -> Result<AttestationMode, FatalError> {
    if !uses_mock(cfg) {
        return Ok(AttestationMode::Secure);
    }
    if !is_release {
        // Dev default: mock allowed, caller still warns.
        return Ok(AttestationMode::Insecure { release: false });
    }
    // Release build with mock in effect.
    if insecure_dev_env {
        Ok(AttestationMode::Insecure { release: true })
    } else {
        Err(FatalError(format!(
            "refusing to start: RELEASE build resolved to MOCK attestation \
             (allow_mock={}, tee_provider={}, verifier={}), which provides ZERO security. \
             Configure a real hardware tee_provider + verifier (and build with the matching \
             --features), or set {INSECURE_DEV_ENV}=1 to explicitly run an INSECURE dev server.",
            cfg.allow_mock, cfg.tee_provider, cfg.verifier
        )))
    }
}

/// Read the build profile via `debug_assertions`. Release = assertions off.
#[must_use]
pub const fn is_release_build() -> bool {
    !cfg!(debug_assertions)
}

/// Read the escape-hatch env var (`=1`).
#[must_use]
pub fn insecure_dev_env_set() -> bool {
    std::env::var(INSECURE_DEV_ENV).is_ok_and(|v| v == "1")
}

/// Construct the configured [`TeeProvider`]. Real variants only exist under the
/// matching cargo feature; selecting one without the feature is a fatal error.
///
/// # Errors
/// Returns [`FatalError`] if the selected provider's cargo feature is not
/// compiled into this build.
pub fn build_tee_provider(
    cfg: &AttestationConfig,
) -> Result<Arc<dyn TeeProvider>, FatalError> {
    match cfg.tee_provider {
        TeeProviderKind::Mock => Ok(Arc::new(openhttpa_tee::mock::MockTeeProvider::default())),
        TeeProviderKind::Tdx => {
            #[cfg(feature = "tdx")]
            {
                Ok(Arc::new(openhttpa_tee::tdx::TdxTeeProvider))
            }
            #[cfg(not(feature = "tdx"))]
            {
                Err(feature_error("tee_provider", "tdx", "tdx"))
            }
        }
        TeeProviderKind::SevSnp => {
            #[cfg(feature = "sev_snp")]
            {
                Ok(Arc::new(openhttpa_tee::sev_snp::SevSnpTeeProvider))
            }
            #[cfg(not(feature = "sev_snp"))]
            {
                Err(feature_error("tee_provider", "sev_snp", "sev_snp"))
            }
        }
        TeeProviderKind::Sgx => {
            #[cfg(feature = "sgx")]
            {
                Ok(Arc::new(openhttpa_tee::sgx::SgxTeeProvider))
            }
            #[cfg(not(feature = "sgx"))]
            {
                Err(feature_error("tee_provider", "sgx", "sgx"))
            }
        }
        TeeProviderKind::TrustZone => {
            #[cfg(feature = "trustzone")]
            {
                Ok(Arc::new(openhttpa_tee::trustzone::TrustZoneTeeProvider))
            }
            #[cfg(not(feature = "trustzone"))]
            {
                Err(feature_error("tee_provider", "trustzone", "trustzone"))
            }
        }
        TeeProviderKind::AwsNitro => {
            #[cfg(feature = "aws_nitro")]
            {
                Ok(Arc::new(openhttpa_tee::aws_nitro::AwsNitroTeeProvider))
            }
            #[cfg(not(feature = "aws_nitro"))]
            {
                Err(feature_error("tee_provider", "aws_nitro", "aws_nitro"))
            }
        }
    }
}

/// Construct the configured [`QuoteVerifier`].
///
/// # Errors
/// Returns [`FatalError`] if the selected verifier's cargo feature is not
/// compiled in, if a required endpoint/key is missing, or if the variant has
/// no implementation in the pinned openhttpa revision (e.g. `dcap`).
pub fn build_verifier(
    cfg: &AttestationConfig,
) -> Result<Arc<dyn QuoteVerifier>, FatalError> {
    match cfg.verifier {
        VerifierKind::Mock => Ok(Arc::new(openhttpa_attestation::MockVerifier::default())),
        VerifierKind::Maa => {
            #[cfg(feature = "maa")]
            {
                let endpoint = cfg.verifier_endpoint.as_deref().ok_or_else(|| {
                    FatalError(
                        "verifier=maa requires attestation.verifier_endpoint (e.g. \
                         https://sharedeus2.eus2.attest.azure.net)"
                            .to_owned(),
                    )
                })?;
                Ok(Arc::new(openhttpa_attestation::maa_verifier::MaaVerifier::new(
                    endpoint,
                )))
            }
            #[cfg(not(feature = "maa"))]
            {
                Err(feature_error("verifier", "maa", "maa"))
            }
        }
        VerifierKind::Ita => {
            #[cfg(feature = "ita")]
            {
                let endpoint = cfg.verifier_endpoint.as_deref().ok_or_else(|| {
                    FatalError("verifier=ita requires attestation.verifier_endpoint".to_owned())
                })?;
                let api_key = cfg.verifier_api_key.as_deref().ok_or_else(|| {
                    FatalError("verifier=ita requires attestation.verifier_api_key".to_owned())
                })?;
                Ok(Arc::new(openhttpa_attestation::ItaVerifier::new(
                    api_key, endpoint,
                )))
            }
            #[cfg(not(feature = "ita"))]
            {
                Err(feature_error("verifier", "ita", "ita"))
            }
        }
        VerifierKind::AmdSnp => {
            // `SevSnpVerifier` is exported on all feature sets, but full VCEK
            // chain verification only happens under `amd_snp`. Refuse to wire
            // it without the feature so we never ship a no-op verifier.
            #[cfg(feature = "amd_snp")]
            {
                Ok(Arc::new(openhttpa_attestation::SevSnpVerifier::new()))
            }
            #[cfg(not(feature = "amd_snp"))]
            {
                Err(feature_error("verifier", "amd_snp", "amd_snp"))
            }
        }
        VerifierKind::Tpm | VerifierKind::Nvidia | VerifierKind::Dcap => Err(FatalError(format!(
            "verifier={} is not supported by archetype-proxy in the pinned openhttpa revision \
             (no production-ready verifier type is available); choose mock|maa|ita|amd_snp",
            cfg.verifier
        ))),
    }
}

#[cfg_attr(
    all(
        feature = "tdx",
        feature = "sev_snp",
        feature = "sgx",
        feature = "trustzone",
        feature = "aws_nitro",
        feature = "maa",
        feature = "ita",
        feature = "amd_snp"
    ),
    allow(dead_code)
)]
fn feature_error(kind: &str, value: &str, feature: &str) -> FatalError {
    FatalError(format!(
        "{kind}={value} requires building with --features {feature}; this binary was compiled \
         without it (default build is mock-only)"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AttestationConfig;

    fn cfg(allow_mock: bool, tee: TeeProviderKind, ver: VerifierKind) -> AttestationConfig {
        AttestationConfig {
            allow_mock,
            strict_attestation: false,
            atb_ttl_secs: 300,
            atb_eviction_interval_secs: 60,
            atb_max_sessions: 100,
            tee_provider: tee,
            verifier: ver,
            verifier_endpoint: None,
            verifier_api_key: None,
        }
    }

    // ---- the headline guard, all combos ----

    #[test]
    fn release_mock_no_escape_is_fatal() {
        let c = cfg(true, TeeProviderKind::Mock, VerifierKind::Mock);
        let err = startup_attestation_decision(true, &c, false).unwrap_err();
        assert!(err.0.contains("refusing to start"));
        assert!(err.0.contains("ZERO security"));
    }

    #[test]
    fn release_mock_with_escape_boots_insecure() {
        let c = cfg(true, TeeProviderKind::Mock, VerifierKind::Mock);
        assert_eq!(
            startup_attestation_decision(true, &c, true).unwrap(),
            AttestationMode::Insecure { release: true }
        );
    }

    #[test]
    fn release_real_boots_secure() {
        let c = cfg(false, TeeProviderKind::Tdx, VerifierKind::Maa);
        assert_eq!(
            startup_attestation_decision(true, &c, false).unwrap(),
            AttestationMode::Secure
        );
    }

    #[test]
    fn debug_mock_boots_insecure_without_escape() {
        let c = cfg(true, TeeProviderKind::Mock, VerifierKind::Mock);
        assert_eq!(
            startup_attestation_decision(false, &c, false).unwrap(),
            AttestationMode::Insecure { release: false }
        );
    }

    #[test]
    fn allow_mock_alone_taints_real_provider_verifier() {
        // Real provider + verifier but allow_mock=true still counts as mock.
        let c = cfg(true, TeeProviderKind::Tdx, VerifierKind::Maa);
        assert!(uses_mock(&c));
        let err = startup_attestation_decision(true, &c, false).unwrap_err();
        assert!(err.0.contains("allow_mock=true"));
    }

    #[test]
    fn mock_provider_alone_taints() {
        let c = cfg(false, TeeProviderKind::Mock, VerifierKind::Maa);
        assert!(uses_mock(&c));
        assert!(startup_attestation_decision(true, &c, false).is_err());
    }

    #[test]
    fn mock_verifier_alone_taints() {
        let c = cfg(false, TeeProviderKind::Tdx, VerifierKind::Mock);
        assert!(uses_mock(&c));
        assert!(startup_attestation_decision(true, &c, false).is_err());
    }

    #[test]
    fn debug_real_is_secure() {
        let c = cfg(false, TeeProviderKind::SevSnp, VerifierKind::AmdSnp);
        assert_eq!(
            startup_attestation_decision(false, &c, false).unwrap(),
            AttestationMode::Secure
        );
    }

    // ---- provider/verifier construction (default = mock-only build) ----

    #[test]
    fn mock_provider_and_verifier_build() {
        let c = cfg(true, TeeProviderKind::Mock, VerifierKind::Mock);
        assert!(build_tee_provider(&c).is_ok());
        assert!(build_verifier(&c).is_ok());
    }

    #[cfg(not(feature = "tdx"))]
    #[test]
    fn tdx_without_feature_is_fatal() {
        let c = cfg(false, TeeProviderKind::Tdx, VerifierKind::Mock);
        // `Arc<dyn TeeProvider>` is not Debug, so avoid unwrap_err().
        let Err(err) = build_tee_provider(&c) else {
            panic!("expected fatal error")
        };
        assert!(err.0.contains("--features tdx"));
    }

    #[cfg(not(feature = "maa"))]
    #[test]
    fn maa_without_feature_is_fatal() {
        let c = cfg(false, TeeProviderKind::Mock, VerifierKind::Maa);
        let Err(err) = build_verifier(&c) else {
            panic!("expected fatal error")
        };
        assert!(err.0.contains("--features maa"));
    }

    #[test]
    fn dcap_is_unsupported() {
        let c = cfg(false, TeeProviderKind::Mock, VerifierKind::Dcap);
        let Err(err) = build_verifier(&c) else {
            panic!("expected fatal error")
        };
        assert!(err.0.contains("not supported"));
    }
}
