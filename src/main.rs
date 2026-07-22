use std::sync::Arc;
use std::time::Duration;

use openhttpa_server::atb_registry::AtbRegistry;
use openhttpa_server::rate_limit::RateLimitLayer;
use openhttpa_server::OpenHttpaServerBuilder;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use clap::Parser;

use archetype_proxy_server::attestation::{
    self, AttestationMode, INSECURE_DEV_ENV,
};
use archetype_proxy_server::cli::Args;
use archetype_proxy_server::config::Config;
use archetype_proxy_server::discovery::{RouteManager, build_providers};
use archetype_proxy_server::metrics::Metrics;
use archetype_proxy_server::proxy::{ProxyState, build_router};

#[tokio::main]
async fn main() {
    // Pin the rustls crypto provider before any TLS client or server is built;
    // the dependency tree enables more than one, leaving no unambiguous default.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("install aws-lc-rs as the process-default rustls CryptoProvider");

    // Parsed before tracing init so --log-level/-v can set the default filter.
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| args.log_directive().into()),
        )
        .init();

    let config = match Config::load(args.overrides(), args.config_path()) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "failed to load config");
            std::process::exit(1);
        }
    };

    if args.dump() {
        print!("{}", config.dump());
        return;
    }

    tracing::debug!("resolved config:\n{}", config.dump());
    tracing::info!(
        listen = %config.r#static.server.listen,
        max_body_bytes = config.r#static.server.max_body_bytes,
        allow_mock = config.r#static.attestation.allow_mock,
        docker = config.r#static.discovery.docker.enabled,
        kubernetes = config.r#static.discovery.kubernetes.enabled,
        file_routes = config.file_routes.len(),
        "archetype-proxy-server starting"
    );

    let atb_cfg = &config.r#static.attestation;
    let is_release = attestation::is_release_build();
    let insecure_dev = attestation::insecure_dev_env_set();
    match attestation::startup_attestation_decision(is_release, atb_cfg, insecure_dev) {
        Ok(AttestationMode::Secure) => {
            tracing::info!(
                tee_provider = %atb_cfg.tee_provider,
                verifier = %atb_cfg.verifier,
                "real hardware attestation selected"
            );
        }
        Ok(AttestationMode::Insecure { release }) => {
            warn_insecure_mode(atb_cfg, release);
        }
        Err(e) => {
            tracing::error!(error = %e, "attestation startup guard refused to boot");
            eprintln!("\nerror: {e}\n");
            std::process::exit(1);
        }
    }

    warn_tpm_unpinned_ak(atb_cfg);

    // Surface openhttpa-tee's own mock-fallback signal at our level.
    openhttpa_tee::telemetry::register_fallback_hook(|reason| {
        tracing::error!(
            security = true,
            %reason,
            "insecure: openhttpa-tee fell back to a mock provider"
        );
    });

    let tee_provider = match attestation::build_tee_provider(atb_cfg) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = %e, "FATAL: failed to construct TEE provider");
            eprintln!("\nerror: {e}\n");
            std::process::exit(1);
        }
    };
    let verifier = match attestation::build_verifier(atb_cfg) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "FATAL: failed to construct quote verifier");
            eprintln!("\nerror: {e}\n");
            std::process::exit(1);
        }
    };

    let executor = Arc::new(openhttpa_core::handshake::AtHsExecutor::with_config(
        vec![],
        vec![
            openhttpa_proto::ProtocolVersion::V2,
            openhttpa_proto::ProtocolVersion::V1,
        ],
        false,
        true,
    ));

    let atb = &config.r#static.attestation;
    let metrics = Metrics::new();
    let registry = AtbRegistry::with_capacity(atb.atb_max_sessions);
    let builder = OpenHttpaServerBuilder::new()
        .with_executor(executor)
        .with_tee_provider(tee_provider)
        .with_verifier(verifier)
        .with_registry(registry.clone())
        .with_atb_ttl(Duration::from_secs(atb.atb_ttl_secs));
    let base_router = builder.build();

    // Hold the handle so the eviction task is not cancelled.
    let _eviction_handle =
        registry.start_eviction_task(Duration::from_secs(atb.atb_eviction_interval_secs));
    tracing::info!(
        capacity = atb.atb_max_sessions,
        ttl_secs = atb.atb_ttl_secs,
        eviction_interval_secs = atb.atb_eviction_interval_secs,
        "AtB registry eviction task started"
    );

    // Route manager owns the live route table; discovery providers feed it.
    let manager = RouteManager::new(config.file_routes.clone());
    let routes_handle = manager.handle();

    let providers = build_providers(&config.r#static.discovery);
    if !providers.is_empty() {
        let (tx, rx) = mpsc::channel(16);
        for provider in providers {
            let tx = tx.clone();
            tracing::info!(provider = provider.name(), "starting discovery provider");
            tokio::spawn(provider.run(tx));
        }
        drop(tx); // manager exits cleanly once all providers stop
        tokio::spawn(manager.run(rx));
    }

    let state = ProxyState {
        registry,
        http: reqwest::Client::new(),
        routes: routes_handle,
        max_body_bytes: config.r#static.server.max_body_bytes,
        metrics,
    };

    let mut app = build_router(base_router, state);

    // Optional per-IP sliding-window rate limit on all routes (0 = disabled).
    let rl = &config.r#static.rate_limit;
    if rl.max_requests > 0 {
        tracing::info!(
            max_requests = rl.max_requests,
            window_secs = rl.window_secs,
            "per-IP rate limiting enabled"
        );
        app = app.layer(RateLimitLayer::new(
            rl.max_requests,
            Duration::from_secs(rl.window_secs),
        ));
    }

    // With [server.tls], terminate public TLS here from one cert source (static
    // files or ACME); otherwise bind plaintext and expect TLS at an ingress. A
    // cert/key or ACME failure aborts rather than falling back to plaintext.
    let addr = config.r#static.server.listen;
    if let Some(tls) = &config.r#static.server.tls {
        use archetype_proxy_server::config::TlsMode;
        let mode = match tls.validate() {
            Ok(m) => m,
            Err(e) => {
                tracing::error!(error = %e, "FATAL: invalid [server.tls] configuration");
                eprintln!("\nerror: {e}\n");
                std::process::exit(1);
            }
        };

        let server_config = match mode {
            TlsMode::Static {
                cert_path,
                key_path,
            } => {
                let source = archetype_proxy_server::tls::CertSource::StaticFiles {
                    cert_path: cert_path.clone(),
                    key_path: key_path.clone(),
                };
                match archetype_proxy_server::tls::server_config(source) {
                    Ok(c) => {
                        tracing::info!(%addr, %cert_path, "listening (TLS; static; aws-lc-rs)");
                        c
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e, %cert_path, %key_path,
                            "failed to load [server.tls] certificate/key; refusing to start"
                        );
                        eprintln!("\nerror: {e}\n");
                        std::process::exit(1);
                    }
                }
            }
            TlsMode::Acme(acme_cfg) => {
                setup_acme(*acme_cfg, addr).await
            }
        };

        let rustls_config =
            axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(server_config));
        axum_server::bind_rustls(addr, rustls_config)
            .serve(app.into_make_service())
            .await
            .expect("TLS server error");
    } else {
        let listener = TcpListener::bind(addr).await.expect("bind listen addr");
        tracing::info!(
            addr = %listener.local_addr().unwrap(),
            "listening (plaintext; terminate public TLS at an ingress)"
        );
        axum::serve(listener, app).await.expect("server error");
    }
}

/// Provision the ACME certificate and return the listener's rustls config (same
/// type as the static branch, so the bind code is shared). The cert lives in an
/// `AcmeResolver` that is swapped on renewal without a restart. Aborts startup
/// if there is no cached cert and issuance fails.
async fn setup_acme(
    acme_cfg: archetype_proxy_server::config::AcmeConfig,
    addr: std::net::SocketAddr,
) -> rustls::ServerConfig {
    use archetype_proxy_server::acme::{AcmeManager, Http01Tokens};
    use archetype_proxy_server::config::AcmeChallenge;
    use archetype_proxy_server::tls::{self, AcmeResolver};

    let resolver = Arc::new(AcmeResolver::empty());
    let http_tokens = Http01Tokens::new();
    let manager = match AcmeManager::new(
        acme_cfg.clone(),
        resolver.clone(),
        http_tokens.clone(),
    ) {
        Ok(m) => Arc::new(m),
        Err(e) => {
            tracing::error!(error = %e, "ACME manager setup failed; refusing to start");
            eprintln!("\nerror: ACME setup failed: {e}\n");
            std::process::exit(1);
        }
    };

    // The CA fetches the HTTP-01 key-authorization during issuance, so the
    // responder must be listening before issue() runs.
    if acme_cfg.challenge == AcmeChallenge::Http01 {
        let listen = acme_cfg
            .http01_listen
            .unwrap_or_else(|| std::net::SocketAddr::new(addr.ip(), 80));
        spawn_http01_responder(listen, http_tokens.clone());
    }

    if manager.load_cached() {
        tracing::info!(%addr, domains = ?acme_cfg.domains, "listening (TLS; ACME cached cert)");
    } else if let Err(e) = manager.issue().await {
        tracing::error!(
            error = %e,
            domains = ?acme_cfg.domains,
            challenge = %acme_cfg.challenge,
            "ACME certificate issuance failed; refusing to start"
        );
        eprintln!("\nerror: ACME issuance failed: {e}\n");
        std::process::exit(1);
    } else {
        tracing::info!(
            %addr,
            domains = ?acme_cfg.domains,
            challenge = %acme_cfg.challenge,
            "listening (TLS; ACME issued cert; aws-lc-rs)"
        );
    }

    tokio::spawn(manager.renewal_loop());

    let acme_tls_alpn = matches!(acme_cfg.challenge, AcmeChallenge::TlsAlpn01);
    tls::config_with_resolver(resolver, acme_tls_alpn)
}

/// Serve the HTTP-01 key-authorization at `/.well-known/acme-challenge/{token}`.
fn spawn_http01_responder(
    listen: std::net::SocketAddr,
    tokens: archetype_proxy_server::acme::Http01Tokens,
) {
    use axum::extract::{Path, State};
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::Router;

    async fn serve_token(
        State(tokens): State<archetype_proxy_server::acme::Http01Tokens>,
        Path(token): Path<String>,
    ) -> impl IntoResponse {
        match tokens.get(&token) {
            Some(key_authorization) => (StatusCode::OK, key_authorization).into_response(),
            None => (StatusCode::NOT_FOUND, "unknown ACME challenge token\n").into_response(),
        }
    }

    let app = Router::new()
        .route("/.well-known/acme-challenge/{token}", get(serve_token))
        .with_state(tokens);

    tokio::spawn(async move {
        match TcpListener::bind(listen).await {
            Ok(listener) => {
                tracing::info!(%listen, "ACME HTTP-01 responder listening (plaintext)");
                if let Err(e) = axum::serve(listener, app).await {
                    tracing::error!(error = %e, "ACME HTTP-01 responder stopped");
                }
            }
            Err(e) => {
                tracing::error!(
                    error = %e, %listen,
                    "failed to bind ACME HTTP-01 responder; refusing to start"
                );
                std::process::exit(1);
            }
        }
    });
}

/// Warn that mock attestation is active.
fn warn_insecure_mode(cfg: &archetype_proxy_server::config::AttestationConfig, release: bool) {
    let profile = if release { "RELEASE" } else { "debug" };
    tracing::error!(
        security = true,
        profile,
        allow_mock = cfg.allow_mock,
        tee_provider = %cfg.tee_provider,
        verifier = %cfg.verifier,
        "\n\
        ============================================================\n\
        ==  INSECURE / MOCK ATTESTATION MODE  ======================\n\
        ==  Mock attestation provides ZERO security: quotes are   ==\n\
        ==  not bound to any real TEE and MUST NOT be trusted.     ==\n\
        ==  This is for DEV/CI ONLY. Do not expose to production.  ==\n\
        ============================================================"
    );
    if release {
        tracing::error!(
            security = true,
            "running a {profile} build with mock attestation because {INSECURE_DEV_ENV}=1 was set"
        );
    }
}

/// Warn loudly when a TPM verifier is configured to accept an unpinned,
/// unchained AK. In that mode the AK's authenticity is not verified.
fn warn_tpm_unpinned_ak(cfg: &archetype_proxy_server::config::AttestationConfig) {
    use archetype_proxy_server::config::VerifierKind;
    let unpinned = matches!(cfg.verifier, VerifierKind::Tpm)
        && cfg.tpm.as_ref().is_some_and(|t| t.allow_unpinned_ak);
    if !unpinned {
        return;
    }
    tracing::error!(
        security = true,
        verifier = %cfg.verifier,
        "\n\
        ============================================================\n\
        ==  TPM allow_unpinned_ak = true  ==========================\n\
        ==  The TPM attestation key (AK) is NOT authenticated: it  ==\n\
        ==  is neither pinned nor chained to a trusted EK root, so ==\n\
        ==  any AK is accepted. Boot-state (PCR) checks still run, ==\n\
        ==  but a rogue TPM/AK cannot be detected. DEV/TEST ONLY.  ==\n\
        ============================================================"
    );
}
