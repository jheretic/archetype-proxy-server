// End-to-end: OpenHttpaClient handshake -> attested proxy -> local upstream.
// Asserts (a) 2xx body round-trips and (b) non-2xx status is faithfully
// carried via the sealed RESPONSE stream (`StreamFrame::Head` + `Body`).
//
// The proxy now seals the RESPONSE as a sequence of OpenHTTPA `seal_stream`
// frames (`[len][counter][ciphertext]`), NOT the old monolithic
// `{"ciphertext": hex}` JSON envelope. The stock `OpenHttpaClient::trusted_request`
// JSON-decodes the response and so cannot read frames. We therefore drive the
// trusted request at the transport level here -- monolithic request seal
// (mirroring the real client's `seal_request_body` / our session.rs) + framed
// response decode (the inverse of `seal_stream`) -- exactly as the real
// archetype-proxy-client does in session.rs. The handshake still uses the
// stock client (that path is unchanged).

use std::sync::Arc;

use openhttpa_attestation::MockVerifier;
use openhttpa_client::builder::OpenHttpaClientBuilder;
use openhttpa_server::OpenHttpaServerBuilder;
use openhttpa_tee::mock::MockTeeProvider;
use openhttpa_transport::reqwest_adapter::ReqwestTransport;

use axum::Router;
use axum::http::StatusCode;
use axum::routing::any;
use tokio::net::TcpListener;

mod frame_helper;
use frame_helper::{FramedResponse, framed_trusted_request};

// reqwest is built with rustls' `*-no-provider` feature (the task #11/#12
// aws-lc-rs-only goal, so no `ring`), so the PROCESS needs a default rustls
// CryptoProvider installed before the first TLS client/config is built. main()
// does this at startup; the test binary must too. Idempotent across tests.
fn install_crypto_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

// Tiny upstream: /ok -> 200 "upstream-ok-body"; /method -> 200 echoing the
// HTTP method the upstream actually received; anything else -> 404 "nope".
async fn upstream_handler(
    method: axum::http::Method,
    uri: axum::http::Uri,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    match uri.path() {
        "/ok" => (StatusCode::OK, "upstream-ok-body").into_response(),
        // Echo the method so the test can assert the REAL method (not the wire
        // POST) was forwarded. HEAD bodies are dropped by HTTP, so callers of
        // /method must use a method whose response body survives.
        "/method" => (StatusCode::OK, format!("method={method}")).into_response(),
        _ => (StatusCode::NOT_FOUND, "nope").into_response(),
    }
}

async fn spawn_upstream() -> String {
    let app = Router::new().fallback(any(upstream_handler));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn proxy_round_trips_status_and_body() {
    install_crypto_provider();
    let _ = tracing_subscriber::fmt()
        .with_env_filter("archetype_proxy_server=debug")
        .try_init();
    let upstream = spawn_upstream().await;

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
        .with_tee_provider(tee_provider.clone())
        .with_verifier(verifier.clone());
    let registry = builder.registry.clone();
    let base_router = builder.build();

    // Mirror src/main.rs wiring: load a small TOML (single catch-all route
    // reproducing the old single-upstream behavior), build ProxyState + router.
    let config_toml = format!(
        "[server]\nlisten = \"127.0.0.1:0\"\nmax_body_bytes = 4194304\n\n[attestation]\nallow_mock = true\n\n[[route]]\nname = \"default\"\nupstream = \"{upstream}\"\n"
    );
    let cfg_dir = std::env::temp_dir().join(format!("aproxy-test-{}", std::process::id()));
    std::fs::create_dir_all(&cfg_dir).unwrap();
    let cfg_path = cfg_dir.join("archetype-proxy.toml");
    std::fs::write(&cfg_path, config_toml).unwrap();

    let config = archetype_proxy_server::config::Config::load(
        archetype_proxy_server::config::PartialStatic::default(),
        Some(cfg_path.to_str().unwrap()),
    )
    .unwrap();
    let routes = std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(config.initial_routes()));
    let state = archetype_proxy_server::proxy::ProxyState {
        registry,
        http: reqwest::Client::new(),
        routes,
        max_body_bytes: config.r#static.server.max_body_bytes,
        metrics: archetype_proxy_server::metrics::Metrics::new(),
    };
    let app = archetype_proxy_server::proxy::build_router(base_router, state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Health check (no attestation).
    let health = reqwest::get(format!("http://{addr}/healthz"))
        .await
        .unwrap();
    assert_eq!(health.status(), reqwest::StatusCode::OK);

    // Client handshake.
    let server_uri = format!("http://{addr}").parse().unwrap();
    let transport = Arc::new(ReqwestTransport::new());
    let client = OpenHttpaClientBuilder::default()
        .server_uri(server_uri)
        .tee_provider(tee_provider.clone())
        .verifier(verifier.clone())
        .transport(transport)
        .require_preflight(true)
        .build();

    // NOTE: the OpenHTTPA client picks a random 64-bit nonce per request and
    // checks it against its own session's SlidingWindow(4096) replay guard, so
    // multiple sequential requests on ONE session are flaky. We use a fresh
    // handshake per request (deterministic) — each still exercises the full
    // decrypt -> forward -> reseal proxy path.

    let server_base: http::Uri = format!("http://{addr}").parse().unwrap();

    // (a) 2xx upstream body round-trips. Drive a monolithic request + framed
    // response decode (the stock client cannot read frames).
    let session = client.attest_handshake().await.expect("handshake failed");
    let ok: FramedResponse =
        framed_trusted_request(&session, &server_base, "POST", "/ok", b"ping")
            .await
            .expect("trusted request /ok failed");
    assert_eq!(ok.status, 200, "expected upstream 200");
    assert_eq!(ok.body, b"upstream-ok-body");

    // (b) non-2xx upstream status faithfully carried via the sealed stream Head.
    let session2 = client.attest_handshake().await.expect("handshake 2 failed");
    let nf: FramedResponse =
        framed_trusted_request(&session2, &server_base, "POST", "/missing", b"ping")
            .await
            .expect("trusted request /missing failed");
    assert_eq!(nf.status, 404, "non-2xx status must survive the transport");
    assert_eq!(nf.body, b"nope");

    let _ = std::fs::remove_dir_all(&cfg_dir);
}

// Spawn an attested proxy from a config TOML; return (addr, tee_provider,
// verifier) so a client can handshake against it.
async fn spawn_proxy(
    config_toml: &str,
    tag: &str,
) -> (String, Arc<MockTeeProvider>, Arc<MockVerifier>) {
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
        .with_tee_provider(tee_provider.clone())
        .with_verifier(verifier.clone());
    let registry = builder.registry.clone();
    let base_router = builder.build();

    let cfg_dir = std::env::temp_dir().join(format!("aproxy-test-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&cfg_dir).unwrap();
    let cfg_path = cfg_dir.join("archetype-proxy.toml");
    std::fs::write(&cfg_path, config_toml).unwrap();
    let config = archetype_proxy_server::config::Config::load(
        archetype_proxy_server::config::PartialStatic::default(),
        Some(cfg_path.to_str().unwrap()),
    )
    .unwrap();
    let routes = std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(config.initial_routes()));
    let state = archetype_proxy_server::proxy::ProxyState {
        registry,
        http: reqwest::Client::new(),
        routes,
        max_body_bytes: config.r#static.server.max_body_bytes,
        metrics: archetype_proxy_server::metrics::Metrics::new(),
    };
    let app = archetype_proxy_server::proxy::build_router(base_router, state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let _ = std::fs::remove_dir_all(&cfg_dir);
    (format!("http://{addr}"), tee_provider, verifier)
}

fn client_for(
    server: &str,
    tee_provider: Arc<MockTeeProvider>,
    verifier: Arc<MockVerifier>,
) -> openhttpa_client::OpenHttpaClient {
    let server_uri = server.parse().unwrap();
    let transport = Arc::new(ReqwestTransport::new());
    OpenHttpaClientBuilder::default()
        .server_uri(server_uri)
        .tee_provider(tee_provider)
        .verifier(verifier)
        .transport(transport)
        .require_preflight(true)
        .build()
}

// BLOCKER A: a request with NO matching route must come back as a SEALED
// envelope carrying status 404 — NOT a bare transport error.
#[tokio::test]
async fn no_route_returns_sealed_404() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("archetype_proxy_server=debug")
        .try_init();
    install_crypto_provider();
    // No [[route]] entries at all: nothing matches.
    let toml = "[server]\nlisten = \"127.0.0.1:0\"\n\n[attestation]\nallow_mock = true\n";
    let (proxy, tee, ver) = spawn_proxy(toml, "noroute").await;
    let client = client_for(&proxy, tee, ver);
    let server_base: http::Uri = proxy.parse().unwrap();

    let session = client.attest_handshake().await.expect("handshake failed");
    let sealed: FramedResponse =
        framed_trusted_request(&session, &server_base, "POST", "/anything", b"x")
            .await
            .expect("trusted request must succeed at transport level (sealed error)");
    assert_eq!(sealed.status, 404, "no-route must be a SEALED 404");
}

// BLOCKER A: an unreachable upstream must come back as a SEALED 502/504
// envelope, not a transport error.
#[tokio::test]
async fn unreachable_upstream_returns_sealed_502() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("archetype_proxy_server=debug")
        .try_init();
    install_crypto_provider();
    // Route to a port nothing listens on (connection refused).
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        drop(l); // free the port so connects are refused
        format!("http://{a}")
    };
    let toml = format!(
        "[server]\nlisten = \"127.0.0.1:0\"\n\n[attestation]\nallow_mock = true\n\n[[route]]\nname = \"default\"\nupstream = \"{dead}\"\n"
    );
    let (proxy, tee, ver) = spawn_proxy(&toml, "deadup").await;
    let client = client_for(&proxy, tee, ver);
    let server_base: http::Uri = proxy.parse().unwrap();

    let session = client.attest_handshake().await.expect("handshake failed");
    let sealed: FramedResponse =
        framed_trusted_request(&session, &server_base, "POST", "/x", b"x")
            .await
            .expect("trusted request must succeed at transport level (sealed error)");
    assert!(
        sealed.status == 502 || sealed.status == 504,
        "unreachable upstream must be a SEALED 502/504, got {}",
        sealed.status
    );
}

// GET-WITH-BODY FIX: a trusted request whose REAL method is GET (wire method
// POST + AHL-bound `attest-real-method: GET`) must be forwarded to the upstream
// AS GET and round-trip. Before the fix the wire GET dropped the encrypted
// envelope body -> server serde EOF -> 400. The upstream echoes the method it
// received, proving the REAL (semantic) method reached it, not the wire POST.
#[tokio::test]
async fn get_real_method_forwarded_to_upstream() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("archetype_proxy_server=debug")
        .try_init();
    install_crypto_provider();
    let upstream = spawn_upstream().await;
    let toml = format!(
        "[server]\nlisten = \"127.0.0.1:0\"\n\n[attestation]\nallow_mock = true\n\n[[route]]\nname = \"default\"\nupstream = \"{upstream}\"\n"
    );
    let (proxy, tee, ver) = spawn_proxy(&toml, "realmethod").await;
    let client = client_for(&proxy, tee, ver);
    let server_base: http::Uri = proxy.parse().unwrap();

    // GET: a bodyless method that broke before the fix.
    let session = client.attest_handshake().await.expect("handshake failed");
    let resp: FramedResponse =
        framed_trusted_request(&session, &server_base, "GET", "/method", b"")
            .await
            .expect("GET trusted request must not 400");
    assert_eq!(resp.status, 200, "GET must round-trip (no 400)");
    assert_eq!(
        resp.body, b"method=GET",
        "upstream must receive the REAL method GET, not the wire POST"
    );

    // DELETE: another method whose forwarding must be preserved end-to-end.
    let session = client.attest_handshake().await.expect("handshake 2 failed");
    let resp: FramedResponse =
        framed_trusted_request(&session, &server_base, "DELETE", "/method", b"")
            .await
            .expect("DELETE trusted request must not 400");
    assert_eq!(resp.status, 200, "DELETE must round-trip");
    assert_eq!(
        resp.body, b"method=DELETE",
        "upstream must receive the REAL method DELETE"
    );
}
