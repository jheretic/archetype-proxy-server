// Full CLIENT-TO-SERVER attested handshake with REAL TPM quotes over the wire,
// swtpm-backed (proxy `tpm` feature).
//
// This closes the gap left by tests/tpm_swtpm.rs, which exercised only the
// server-side build_tee_provider -> build_verifier round trip and never drove a
// wire handshake. Here the stock `openhttpa-client` SDK performs a genuine
// `attest_handshake` against a running attested proxy:
//
//   * The CLIENT is configured with the real TPM `TeeProvider` (TpmTeeAdapter),
//     so `generate_client_quote` produces a genuine `TPM2_Quote` whose 64-byte
//     qualifying data is the SIGMA-I handshake binding hash. That quote rides
//     the wire in the `Attest-Quotes` header (mHTTPA / mutual attestation).
//   * The SERVER is built exactly as src/main.rs wires it -- AtHsExecutor +
//     TpmTeeAdapter provider + TpmVerifier (from build_verifier) -- and its
//     `AtHsExecutor::verify_client_quotes` recomputes the identical binding and
//     verifies the client's quote with the configured TpmVerifier.
//   * The SERVER also emits its OWN TPM quote, which the client's TpmVerifier
//     checks (`verify_server_quotes`). So this is genuinely MUTUAL TPM
//     attestation over the wire.
//
// Assertions:
//   (a) valid client TPM quote + server policy matching the (freshly-cleared)
//       swtpm PCRs -> handshake SUCCEEDS and a subsequent trusted_request
//       round-trips through the proxy to a local upstream.
//   (b) a server whose PCR reference policy does NOT match the client's boot
//       state -> handshake is REJECTED (fails closed).
//   (c) a server that pins a WRONG AK public key -> handshake is REJECTED
//       (fails closed).
//
// HONEST SCOPE NOTES
// ------------------
// * This IS a real wire handshake with real swtpm-generated TPM quotes verified
//   by the real fail-closed TpmVerifier -- not a mock and not a server-only
//   round trip.
// * The client and server providers share ONE swtpm instance. `TpmTeeAdapter`
//   resolves its TCTI from the process-global `TCTI` env var, so two providers
//   in one process cannot target two different software TPMs without a fork
//   change to thread a per-instance TCTI through the provider. A single swtpm
//   serving both roles is sufficient to prove the wire handshake: client and
//   server each generate independent quotes (with independent, TPM-derived AKs)
//   against the same measured-boot state. See the report for the exact fork
//   hook that a two-TPM separation would need.
// * The byte-level tamper / wrong-nonce fail-closed cases are covered directly
//   against the verifier in tests/tpm_swtpm.rs (cases b/c) and the fork's
//   openhttpa-tee swtpm_integration.rs; over the wire the client SDK only emits
//   well-formed genuine quotes, so the wire-level fail-closed proofs here are
//   the two policy mismatches (b) and (c) that the SERVER controls.
//
// Skips (does not fail) if the `swtpm` binary is absent.

#![cfg(feature = "tpm")]

use std::collections::BTreeMap;
use std::net::TcpListener as StdTcpListener;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::Duration;

use archetype_proxy_server::attestation::{build_tee_provider, build_verifier};
use archetype_proxy_server::config::{
    AttestationConfig, TeeProviderKind, TpmConfig, VerifierKind,
};

use openhttpa_client::builder::OpenHttpaClientBuilder;
use openhttpa_server::OpenHttpaServerBuilder;
use openhttpa_transport::reqwest_adapter::ReqwestTransport;

use axum::Router;
use axum::http::StatusCode;
use axum::routing::any;
use tokio::net::TcpListener;

mod frame_helper;
use frame_helper::{FramedResponse, framed_trusted_request};

// reqwest/rustls need a process-default CryptoProvider (aws-lc-rs; no `ring`)
// installed before the first TLS config is built. Idempotent.
fn install_crypto_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

/// A running swtpm instance; kills the process and removes its state dir on drop.
struct Swtpm {
    child: Child,
    state_dir: PathBuf,
    port: u16,
}

impl Swtpm {
    fn start() -> Option<Self> {
        let port = free_port()?;
        let _ctrl = port.checked_add(1)?;
        let state_dir =
            std::env::temp_dir().join(format!("aproxy-hs-swtpm-{}", std::process::id()));
        std::fs::create_dir_all(&state_dir).ok()?;
        let child = Command::new("swtpm")
            .arg("socket")
            .arg("--tpmstate")
            .arg(format!("dir={}", state_dir.display()))
            .arg("--server")
            .arg(format!("type=tcp,port={port}"))
            .arg("--ctrl")
            .arg(format!("type=tcp,port={}", port + 1))
            .arg("--tpm2")
            .arg("--flags")
            .arg("not-need-init,startup-clear")
            .spawn()
            .ok()?;
        let sw = Self {
            child,
            state_dir,
            port,
        };
        std::thread::sleep(Duration::from_millis(750));
        Some(sw)
    }

    fn tcti(&self) -> String {
        format!("swtpm:host=127.0.0.1,port={}", self.port)
    }
}

impl Drop for Swtpm {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.state_dir);
    }
}

fn free_port() -> Option<u16> {
    let l = StdTcpListener::bind("127.0.0.1:0").ok()?;
    let p = l.local_addr().ok()?.port();
    drop(l);
    if p >= u16::MAX - 1 { None } else { Some(p) }
}

fn swtpm_available() -> bool {
    Command::new("swtpm")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// A freshly-cleared swtpm reports all-zero SHA-256 PCRs 0-7 (the default slots
/// quoted by `TpmTeeAdapter`). The verifier RECOMPUTES the composite from these
/// and compares it to the SIGNED pcrDigest, so a matching policy is a genuine
/// check, not a tautology. This mirrors tests/tpm_swtpm.rs.
fn cleared_pcrs() -> BTreeMap<u32, Vec<u8>> {
    let mut m = BTreeMap::new();
    for i in 0..8u32 {
        m.insert(i, vec![0u8; 32]);
    }
    m
}

fn att_cfg(tpm: TpmConfig) -> AttestationConfig {
    AttestationConfig {
        allow_mock: false,
        strict_attestation: true,
        atb_ttl_secs: 300,
        atb_eviction_interval_secs: 60,
        atb_max_sessions: 100,
        tee_provider: TeeProviderKind::Tpm,
        verifier: VerifierKind::Tpm,
        verifier_endpoint: None,
        verifier_api_key: None,
        tpm: Some(tpm),
    }
}

// Tiny upstream: /ok -> 200 "upstream-ok-body"; anything else -> 404 "nope".
async fn upstream_handler(uri: axum::http::Uri) -> axum::response::Response {
    use axum::response::IntoResponse;
    match uri.path() {
        "/ok" => (StatusCode::OK, "upstream-ok-body").into_response(),
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

/// Build + serve an attested proxy whose provider/verifier come from `server_cfg`
/// (built via the SAME build_tee_provider / build_verifier path as src/main.rs).
/// Returns the loopback base URI.
async fn spawn_tpm_proxy(server_cfg: &AttestationConfig, upstream: &str, tag: &str) -> String {
    let tee_provider = build_tee_provider(server_cfg).expect("build server TPM provider");
    let verifier = build_verifier(server_cfg).expect("build server TpmVerifier");

    // Mirror src/main.rs executor wiring.
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

    // A routes-only config (its own attestation block is unused: the provider
    // and verifier above come from the builder, exactly like proxy_e2e.rs).
    let config_toml = format!(
        "[server]\nlisten = \"127.0.0.1:0\"\nmax_body_bytes = 4194304\n\n[attestation]\nallow_mock = true\n\n[[route]]\nname = \"default\"\nupstream = \"{upstream}\"\n"
    );
    let cfg_dir =
        std::env::temp_dir().join(format!("aproxy-hs-test-{tag}-{}", std::process::id()));
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
    format!("http://{addr}")
}

/// Build a client that generates its OWN quote with the real TPM provider and
/// verifies the server's quote with a TpmVerifier -- both from `client_cfg`.
fn tpm_client(server: &str, client_cfg: &AttestationConfig) -> openhttpa_client::OpenHttpaClient {
    let tee_provider = build_tee_provider(client_cfg).expect("build client TPM provider");
    let verifier = build_verifier(client_cfg).expect("build client TpmVerifier");
    let server_uri = server.parse().unwrap();
    let transport = Arc::new(ReqwestTransport::new());
    OpenHttpaClientBuilder::default()
        .server_uri(server_uri)
        .tee_provider(tee_provider)
        .verifier(verifier)
        .transport(transport)
        .require_preflight(true)
        // Force mutual attestation: the client MUST produce a real TPM quote and
        // MUST verify the server's, else the handshake errors (fail closed).
        .strict_attestation(true)
        .build()
}

// A single serial async test: the TPM provider reads its TCTI from the
// process-global `TCTI` env var, so parallel handshakes would race on swtpm.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_to_server_tpm_wire_handshake_succeeds_and_fails_closed() {
    if !swtpm_available() {
        eprintln!(
            "SKIP client_to_server_tpm_wire_handshake_succeeds_and_fails_closed: `swtpm` binary \
             not found. Install with `dnf install -y swtpm swtpm-tools tpm2-tss tpm2-tss-devel` \
             and rerun `cargo test --features tpm --test tpm_handshake_e2e`."
        );
        return;
    }

    install_crypto_provider();
    let _ = tracing_subscriber::fmt()
        .with_env_filter("archetype_proxy_server=debug")
        .try_init();

    let swtpm = match Swtpm::start() {
        Some(s) => s,
        None => {
            eprintln!("SKIP: swtpm present but failed to launch");
            return;
        }
    };
    // SAFETY: single-threaded test entry before any handshake task spawns; no
    // other thread reads env concurrently at this point.
    unsafe {
        std::env::set_var("TCTI", swtpm.tcti());
    }

    let upstream = spawn_upstream().await;

    // ---- (a) SUCCESS: matching PCR policy on both sides. ----
    // Client generates a genuine TPM quote; server verifies it against the
    // freshly-cleared PCRs; server emits its own quote; client verifies it.
    let good_cfg = att_cfg(TpmConfig {
        expected_pcrs: cleared_pcrs(),
        pinned_ak_sec1: None,
        pcr_selection: None,
        trusted_ek_root_paths: Vec::new(),
        allow_unpinned_ak: true,
    });
    let server = spawn_tpm_proxy(&good_cfg, &upstream, "ok").await;

    // Health check (no attestation).
    let health = reqwest::get(format!("{server}/healthz")).await.unwrap();
    assert_eq!(health.status(), reqwest::StatusCode::OK);

    let client = tpm_client(&server, &good_cfg);
    let session = client
        .attest_handshake()
        .await
        .expect("(a) mutual TPM handshake must succeed");

    let server_base: http::Uri = server.parse().unwrap();
    let ok: FramedResponse =
        framed_trusted_request(&session, &server_base, "POST", "/ok", b"ping")
            .await
            .expect("(a) trusted_request over the TPM-attested session must round-trip");
    assert_eq!(ok.status, 200, "(a) upstream 200 must survive the attested transport");
    assert_eq!(ok.body, b"upstream-ok-body", "(a) upstream body must round-trip");

    // ---- (b) FAIL CLOSED: server PCR policy does NOT match client boot state.
    let bad_pcr_cfg = att_cfg(TpmConfig {
        expected_pcrs: {
            let mut m = cleared_pcrs();
            m.insert(0u32, vec![0xaa; 32]); // wrong PCR0 reference
            m
        },
        pinned_ak_sec1: None,
        pcr_selection: None,
        trusted_ek_root_paths: Vec::new(),
        allow_unpinned_ak: true,
    });
    let bad_server = spawn_tpm_proxy(&bad_pcr_cfg, &upstream, "badpcr").await;
    // Client itself is fine (good verifier for the server's own quote).
    let client_b = tpm_client(&bad_server, &good_cfg);
    let res_b = client_b.attest_handshake().await;
    assert!(
        res_b.is_err(),
        "(b) mismatched server PCR policy must REJECT the handshake (fail closed), got Ok"
    );

    // ---- (c) FAIL CLOSED: server pins a WRONG AK public key.
    let wrong_ak_cfg = att_cfg(TpmConfig {
        expected_pcrs: cleared_pcrs(),
        // A bogus but well-formed uncompressed SEC1 point (0x04 || 32*0x01 || 32*0x02).
        pinned_ak_sec1: Some({
            let mut v = vec![0x04u8];
            v.extend(std::iter::repeat_n(0x01u8, 32));
            v.extend(std::iter::repeat_n(0x02u8, 32));
            v
        }),
        pcr_selection: None,
        trusted_ek_root_paths: Vec::new(),
        allow_unpinned_ak: false,
    });
    let ak_server = spawn_tpm_proxy(&wrong_ak_cfg, &upstream, "wrongak").await;
    let client_c = tpm_client(&ak_server, &good_cfg);
    let res_c = client_c.attest_handshake().await;
    assert!(
        res_c.is_err(),
        "(c) wrong pinned AK on the server must REJECT the handshake (fail closed), got Ok"
    );

    drop(swtpm);
}
