// swtpm-backed integration test for the SERVER's TPM attestation wiring
// (proxy `tpm` feature). Proves the config -> build_tee_provider ->
// build_verifier path yields a real tss-esapi quote provider and a fail-closed
// TpmVerifier that verifies a genuine swtpm quote and rejects tampering.
//
// This exercises the SERVER-SIDE construction path end to end against a
// software TPM. It does NOT drive a full client-side attested handshake with
// TPM quotes over the wire: the proxy's build_tee_provider / build_verifier are
// the units under test, and they are wired exactly as src/main.rs wires them
// into the OpenHttpaServerBuilder. The always-on unit coverage for the
// verifier's crypto (signature / nonce / PCR checks) lives in the fork's
// openhttpa-attestation::tpm_verifier tests; this test adds the LIVE swtpm ->
// real provider -> real verifier round trip that a pure unit test cannot.
//
// Skips (does not fail) if the `swtpm` binary is absent so CI without a
// software TPM stays green.

#![cfg(feature = "tpm")]

use std::collections::BTreeMap;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::Duration;

use archetype_proxy_server::attestation::{build_tee_provider, build_verifier};
use archetype_proxy_server::config::{
    AttestationConfig, TeeProviderKind, TpmConfig, VerifierKind,
};

use openhttpa_tee::provider::QuoteRequest;
use openhttpa_tee::tpm_format::TpmQuoteBlob;

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
            std::env::temp_dir().join(format!("aproxy-swtpm-{}", std::process::id()));
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
    let l = TcpListener::bind("127.0.0.1:0").ok()?;
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

// A single serial test: the provider reads its TCTI from the process-global
// `TCTI` env var, so parallel tests would race on it.
#[test]
fn server_tpm_wiring_verifies_swtpm_quote_and_fails_closed() {
    if !swtpm_available() {
        eprintln!(
            "SKIP server_tpm_wiring_verifies_swtpm_quote_and_fails_closed: `swtpm` binary not \
             found. Install with `dnf install -y swtpm swtpm-tools tpm2-tss tpm2-tss-devel` and \
             rerun `cargo test --features tpm --test tpm_swtpm`."
        );
        return;
    }

    let swtpm = match Swtpm::start() {
        Some(s) => s,
        None => {
            eprintln!("SKIP: swtpm present but failed to launch");
            return;
        }
    };

    // SAFETY: single-threaded test entry; no other thread reads env concurrently.
    unsafe {
        std::env::set_var("TCTI", swtpm.tcti());
    }

    // The server builds its TEE provider from [attestation]. To generate a
    // quote we need the report_data (the handshake binds the transcript hash
    // here; for this construction test we use a fixed, non-trivial nonce).
    let report_data: [u8; 64] = {
        let mut r = [0u8; 64];
        for (i, b) in r.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        r
    };

    // Bootstrap: build the provider with a placeholder (non-empty) policy just
    // to read the live PCRs off swtpm; the real verifier policy is built from
    // those PCRs below.
    let mut placeholder = BTreeMap::new();
    placeholder.insert(0u32, vec![0u8; 32]);
    let boot_cfg = att_cfg(TpmConfig {
        expected_pcrs: placeholder,
        pinned_ak_sec1: None,
        pcr_selection: None,
        trusted_ek_root_paths: Vec::new(),
        allow_unpinned_ak: true,
    });
    let provider = build_tee_provider(&boot_cfg).expect("build TPM provider");
    let quote = provider
        .generate_quote(&QuoteRequest { report_data })
        .expect("real swtpm quote generation must succeed");

    // Extract the PCR composite the provider actually quoted by parsing the
    // blob; build the verifier policy from the freshly-cleared swtpm's PCRs.
    let blob = TpmQuoteBlob::from_bytes(&quote.raw).expect("decode quote blob");
    let ak_sec1 = blob.ak_pub_sec1();

    // A freshly-cleared swtpm reports all-zero SHA-256 PCRs 0-7. The verifier
    // recomputes the composite and compares to the SIGNED pcrDigest, so this is
    // a genuine match, not a tautology.
    let mut expected_pcrs = BTreeMap::new();
    for i in 0..8u32 {
        expected_pcrs.insert(i, vec![0u8; 32]);
    }

    // (a) Valid quote + matching policy + pinned AK -> verifier VERIFIES.
    let good_cfg = att_cfg(TpmConfig {
        expected_pcrs: expected_pcrs.clone(),
        pinned_ak_sec1: Some(ak_sec1.clone()),
        pcr_selection: None,
        trusted_ek_root_paths: Vec::new(),
        allow_unpinned_ak: false,
    });
    let verifier = build_verifier(&good_cfg).expect("build TpmVerifier");
    let fut = verifier.verify(&quote, &report_data);
    futures_executor_block_on(fut).expect("(a) valid swtpm quote must verify Ok");

    // (b) Tampered signature -> Err (fail closed).
    {
        let mut b = TpmQuoteBlob::from_bytes(&quote.raw).unwrap();
        b.sig_r[0] ^= 0xff;
        let mut tampered = quote.clone();
        tampered.raw = bytes::Bytes::from(b.to_bytes().unwrap());
        let res = futures_executor_block_on(verifier.verify(&tampered, &report_data));
        assert!(res.is_err(), "(b) tampered signature must fail closed: {res:?}");
    }

    // (c) Wrong nonce / report_data -> Err (session-binding freshness).
    {
        let mut wrong = report_data;
        wrong[0] ^= 0xff;
        let res = futures_executor_block_on(verifier.verify(&quote, &wrong));
        assert!(res.is_err(), "(c) wrong report_data must fail closed: {res:?}");
    }

    // (d) Mismatched PCR policy -> Err (boot-state policy).
    {
        let mut bad = expected_pcrs.clone();
        bad.insert(0u32, vec![0xaa; 32]);
        let bad_cfg = att_cfg(TpmConfig {
            expected_pcrs: bad,
            pinned_ak_sec1: Some(ak_sec1.clone()),
            pcr_selection: None,
            trusted_ek_root_paths: Vec::new(),
            allow_unpinned_ak: false,
        });
        let bad_verifier = build_verifier(&bad_cfg).expect("build mismatched TpmVerifier");
        let res = futures_executor_block_on(bad_verifier.verify(&quote, &report_data));
        assert!(res.is_err(), "(d) mismatched PCR policy must fail closed: {res:?}");
    }

    // (e) Wrong pinned AK -> Err (AK pinning).
    {
        let mut wrong_ak = ak_sec1.clone();
        wrong_ak[1] ^= 0xff;
        let bad_cfg = att_cfg(TpmConfig {
            expected_pcrs: expected_pcrs.clone(),
            pinned_ak_sec1: Some(wrong_ak),
            pcr_selection: None,
            trusted_ek_root_paths: Vec::new(),
            allow_unpinned_ak: false,
        });
        let bad_verifier = build_verifier(&bad_cfg).expect("build wrong-AK TpmVerifier");
        let res = futures_executor_block_on(bad_verifier.verify(&quote, &report_data));
        assert!(res.is_err(), "(e) wrong pinned AK must fail closed: {res:?}");
    }

    drop(swtpm);
}

// Minimal executor to block on the verifier's boxed future without pulling a
// full tokio runtime into this test's dependency surface.
fn futures_executor_block_on<F: std::future::Future>(fut: F) -> F::Output {
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    fn noop_raw() -> RawWaker {
        fn no(_: *const ()) {}
        fn clone(_: *const ()) -> RawWaker {
            noop_raw()
        }
        RawWaker::new(
            std::ptr::null(),
            &RawWakerVTable::new(clone, no, no, no),
        )
    }
    // The TpmVerifier future is synchronous (verify_blob is pure); it is Ready
    // on the first poll, so a no-op waker is sufficient.
    let waker = unsafe { Waker::from_raw(noop_raw()) };
    let mut cx = Context::from_waker(&waker);
    let mut fut = Box::pin(fut);
    loop {
        if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return v;
        }
    }
}
