// BLOCKER B: the AtB registry must actively reap expired single-use sessions
// so a long-running bridge doing >>capacity requests does not brick the server.
// We verify the exact eviction API wired in main.rs: a tiny-TTL session is
// reaped by the background `start_eviction_task` without ever being looked up
// (so lazy expiry on `get` is NOT what evicts it).

use std::time::{Duration, Instant};

use openhttpa_core::session::{AttestSession, ReplayStrategy};
use openhttpa_crypto::hkdf::SessionKeys;
use openhttpa_proto::{AtbId, CipherSuite, ProtocolVersion};
use openhttpa_server::atb_registry::AtbRegistry;

fn make_session(ttl: Duration) -> AttestSession {
    let keys = SessionKeys::derive(&[0u8; 64], &[0u8; 48]).unwrap();
    AttestSession::new(
        AtbId::new(),
        CipherSuite::X25519MlKem768Aes256GcmSha384,
        ProtocolVersion::V2,
        keys,
        Instant::now() + ttl,
        ReplayStrategy::default(),
        None,
    )
}

#[tokio::test]
async fn expired_sessions_are_actively_evicted() {
    // Small capacity to mirror the exhaustion scenario.
    let reg = AtbRegistry::with_capacity(4);
    for _ in 0..4 {
        reg.insert(make_session(Duration::from_millis(10))).unwrap();
    }
    assert_eq!(reg.len(), 4, "registry should be full");

    // Wire eviction exactly as main.rs does.
    let _handle = reg.start_eviction_task(Duration::from_millis(10));

    // Wait for TTL to elapse + at least one eviction tick.
    tokio::time::sleep(Duration::from_millis(120)).await;

    assert_eq!(
        reg.len(),
        0,
        "expired sessions must be reaped by the background eviction task"
    );

    // And new sessions can be established again (registry not bricked).
    reg.insert(make_session(Duration::from_secs(60)))
        .expect("registry must accept new sessions after eviction");
}
