// Task #11: the public TLS listener actually terminates TLS and serves the
// real router. Generate an ephemeral self-signed cert (rcgen), start the
// server with [server.tls] pointing at it, then hit /healthz over HTTPS with a
// rustls client (reqwest) that trusts the fixture — assert 200.

use std::sync::Arc;

use archetype_proxy_server::proxy::{ProxyState, build_router};
use archetype_proxy_server::tls::{CertSource, server_config};

use openhttpa_attestation::MockVerifier;
use openhttpa_server::OpenHttpaServerBuilder;
use openhttpa_tee::mock::MockTeeProvider;

use axum::Router;

fn build_app() -> Router {
    let tee_provider = Arc::new(MockTeeProvider::default());
    let verifier = Arc::new(MockVerifier::default());
    let executor = Arc::new(openhttpa_core::handshake::AtHsExecutor::with_config(
        vec![],
        vec![
            openhttpa_proto::ProtocolVersion::V2,
            openhttpa_proto::ProtocolVersion::V1,
        ],
        false,
        true,
    ));
    let builder = OpenHttpaServerBuilder::new()
        .with_executor(executor)
        .with_tee_provider(tee_provider)
        .with_verifier(verifier);
    let registry = builder.registry.clone();
    let base_router = builder.build();

    let routes = Arc::new(arc_swap::ArcSwap::from_pointee(
        archetype_proxy_server::config::RouteTable::default(),
    ));
    let state = ProxyState {
        registry,
        http: reqwest::Client::new(),
        routes,
        max_body_bytes: 4 * 1024 * 1024,
        metrics: archetype_proxy_server::metrics::Metrics::new(),
    };
    build_router(base_router, state)
}

#[tokio::test]
async fn healthz_served_over_tls() {
    // reqwest uses rustls' `*-no-provider` feature (no `ring`), so the process
    // needs a default rustls CryptoProvider installed before the first TLS
    // client/config is built (main() does this at startup).
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    // Ephemeral self-signed cert for "localhost".
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.signing_key.serialize_pem();

    let dir = std::env::temp_dir().join(format!("aproxy-tls-listener-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, cert_pem.as_bytes()).unwrap();
    std::fs::write(&key_path, key_pem.as_bytes()).unwrap();

    // Build the rustls server config exactly as main.rs does.
    let tls_config = server_config(CertSource::StaticFiles {
        cert_path: cert_path.to_str().unwrap().to_owned(),
        key_path: key_path.to_str().unwrap().to_owned(),
    })
    .expect("server_config from valid PEM");
    let rustls_config = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls_config));

    // Bind an ephemeral port, then serve.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener); // free it; axum_server::bind_rustls rebinds.

    let app = build_app();
    tokio::spawn(async move {
        axum_server::bind_rustls(addr, rustls_config)
            .serve(app.into_make_service())
            .await
            .unwrap();
    });

    // Give the listener a moment to come up.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // rustls client that trusts the fixture cert. Connect to "localhost" so
    // the SAN matches; resolve it to the bound 127.0.0.1 port.
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(cert_pem.as_bytes()).unwrap())
        .resolve("localhost", std::net::SocketAddr::new(addr.ip(), addr.port()))
        .build()
        .unwrap();

    let resp = client
        .get(format!("https://localhost:{}/healthz", addr.port()))
        .send()
        .await
        .expect("HTTPS request to /healthz");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    assert_eq!(resp.text().await.unwrap(), "ok");

    let _ = std::fs::remove_dir_all(&dir);
}
