// Attested WebSocket passthrough (task #14).
//
// A local app opens `ws://127.0.0.1:<port>/...` against the CLIENT bridge; the
// client establishes an attested WS to THIS server (hand-rolled, see the client
// session.rs), and we proxy that to an upstream `ws://` backend selected from
// the live route table, pumping frames BOTH directions for the connection
// lifetime.
//
// ROUTING (why we don't use the SDK's `attested_ws_upgrade` directly)
// ===================================================================
// The SDK ships `openhttpa_server::ws::attested_ws_upgrade::<H>` -- a fixed
// axum GET handler that derives the per-WS AEAD keys and calls a static
// `AttestWsHandler`. But that handler NEVER sees the request path/host, so it
// cannot select an upstream from our route table. We therefore REUSE the SDK's
// public primitives (`AttestWsSession::new` key derivation logic, replicated
// here via `peek_keys` + `cipher_suite_to_aead`) but drive the upgrade
// ourselves so route selection happens per-connection. The on-the-wire frame
// format is byte-identical to `ws.rs` (12-byte nonce || AEAD(type||payload),
// AAD = "openhttpa:" + atb-id) so the hand-rolled client interops with EITHER
// this handler or the stock SDK one.
//
// DISPATCH (how a WS upgrade avoids the proxy catch-all)
// ======================================================
// An attested WS is an HTTP GET carrying `Upgrade: websocket` + the
// `Attest-Base-ID` header. The normal proxy routes (`/` and `/{*path}`,
// method `any`) would otherwise swallow it and try to decrypt a non-existent
// trusted-request body. `build_router` (in proxy.rs) installs a
// `from_fn_with_state` guard OUTSIDE the `TrRequestLayer`: it inspects every
// request and, when it is a WS upgrade, dispatches to `ws_upgrade_handler`
// here; otherwise it passes through untouched to the existing proxy/observ-
// ability routes. We do session lookup + key derivation ourselves (the
// `TrRequestLayer` injects the session only for the proxy path, and its
// model is single-request, not a long-lived socket).
//
// SESSION LIFECYCLE (long-lived WS vs single-use HTTP pool)
// =========================================================
// A trusted HTTP request is single-use per session (random per-request nonce +
// SlidingWindow guard -- see the client session.rs headline docs). A WS is
// DIFFERENT: it uses ORDERED COUNTER nonces (TLS-1.3 XOR construction, counter
// 1,2,3,...) in EACH direction, exactly like the SDK's `AttestWsSession`. A
// single attested session therefore carries an entire WS conversation: the
// inbound (client->server) direction enforces a STRICT-MONOTONIC counter
// (replay/reorder protection, mirroring `AttestWsSession::decode_frame`), and
// the outbound (server->client) direction seals with a monotonic
// `BoundAeadKey` counter. This coexists with the HTTP pool because a WS upgrade
// consumes a DEDICATED session for its whole lifetime -- it is never returned
// to / drawn from the single-use request pool.

use axum::extract::ws::{Message as AxumMessage, WebSocket, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use futures_util::{SinkExt, StreamExt};
use openhttpa_core::session::AttestSession;
use openhttpa_crypto::aead::{AeadAlgorithm, AeadKey, AeadNonce, BoundAeadKey};
use openhttpa_server::ws::cipher_suite_to_aead;
use tokio_tungstenite::tungstenite::Message as UpMessage;
use tracing::{debug, warn};

use crate::proxy::ProxyState;

/// Message-type prefix bytes inside the AEAD plaintext (must match the SDK's
/// `ws.rs`: 0x00 = text, 0x01 = binary).
const MSG_TEXT: u8 = 0x00;
const MSG_BINARY: u8 = 0x01;

/// Minimum encrypted frame length: 12-byte nonce + 1-byte type + 16-byte GCM tag.
const MIN_FRAME: usize = 12 + 1 + 16;

/// Per-frame size sanity cap. An attested WS frame larger than this (encrypted
/// or decrypted) is rejected and tears the connection down, so a peer cannot
/// force unbounded buffering. Independent of the HTTP body cap (which bounds a
/// whole request); this bounds a single WS message.
const MAX_WS_FRAME: usize = 16 * 1024 * 1024;

/// Detect an attested WebSocket upgrade: an HTTP GET carrying the WebSocket
/// `Upgrade` token AND the `Attest-Base-ID` header. Used by the dispatch guard
/// in `build_router` to route the request here instead of the proxy catch-all.
#[must_use]
pub fn is_attested_ws_upgrade(req: &axum::extract::Request) -> bool {
    use openhttpa_headers::HDR_ATTEST_BASE_ID;
    if req.method() != http::Method::GET {
        return false;
    }
    let has_upgrade = req
        .headers()
        .get(http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
    has_upgrade && req.headers().contains_key(&*HDR_ATTEST_BASE_ID)
}

/// Derived per-WS key material cloned out of the session under `peek_keys`.
struct WsKeys {
    /// Server -> client write key bytes (outbound seal).
    server_write_key: Vec<u8>,
    server_write_iv: [u8; 12],
    /// Client -> server write key bytes (inbound open).
    client_write_key: Vec<u8>,
    client_write_iv: [u8; 12],
    algorithm: AeadAlgorithm,
}

impl WsKeys {
    /// Replicate the SDK `attested_ws_upgrade` key extraction: clone the raw
    /// session keys (so the pump tasks are `'static`) and pick the AEAD algo
    /// from the negotiated cipher suite.
    fn from_session(session: &AttestSession) -> Option<Self> {
        let algorithm = cipher_suite_to_aead(session.state().cipher_suite);
        session
            .peek_keys(|keys| {
                let mut swiv = [0u8; 12];
                let mut cwiv = [0u8; 12];
                swiv.copy_from_slice(&keys.server_write_iv[..12]);
                cwiv.copy_from_slice(&keys.client_write_iv[..12]);
                Self {
                    server_write_key: keys.server_write_key.clone(),
                    server_write_iv: swiv,
                    client_write_key: keys.client_write_key.clone(),
                    client_write_iv: cwiv,
                    algorithm,
                }
            })
            .ok()
    }
}

/// Build the AAD that binds every frame to the session: `"openhttpa:" || <atb
/// id string>`. Byte-identical to `AttestWsSession::new` so frames sealed here
/// open against the hand-rolled client and vice versa.
fn session_aad(session: &AttestSession) -> Vec<u8> {
    let mut aad = b"openhttpa:".to_vec();
    aad.extend_from_slice(session.id().to_string().as_bytes());
    aad
}

/// Extract the TLS-1.3 counter embedded in a received nonce (inverse of the
/// XOR construction) for strict-monotonic replay detection. Mirrors the SDK's
/// private `extract_counter_from_nonce`.
fn extract_counter(nonce: &[u8], iv: &[u8; 12]) -> u64 {
    let mut counter = [0u8; 8];
    for (i, (n, v)) in nonce[4..12].iter().zip(iv[4..12].iter()).enumerate() {
        counter[i] = n ^ v;
    }
    u64::from_be_bytes(counter)
}

/// Decoded inbound application payload (client -> server).
enum InPayload {
    Text(String),
    Binary(Vec<u8>),
}

/// The axum handler invoked by the dispatch guard for an attested WS upgrade.
/// Looks up the session, derives keys, selects the upstream from the live route
/// table, and on upgrade dials the upstream and pumps frames bidirectionally.
pub async fn ws_upgrade_handler(
    ws: WebSocketUpgrade,
    state: ProxyState,
    req_parts: WsRequestMeta,
) -> Response {
    use openhttpa_headers::HDR_ATTEST_BASE_ID;
    use openhttpa_proto::AtbId;

    // 1. Session lookup from the Attest-Base-ID header (the WS path is not
    //    behind TrRequestLayer, so we authenticate the upgrade ourselves).
    let atb_id: Option<AtbId> = req_parts
        .base_id
        .as_deref()
        .and_then(|s| s.parse().ok());
    let Some(atb_id) = atb_id else {
        return (
            StatusCode::UNAUTHORIZED,
            format!("{} header missing or invalid", HDR_ATTEST_BASE_ID.as_str()),
        )
            .into_response();
    };
    let Some(session) = state.registry.get(&atb_id) else {
        return (StatusCode::UNAUTHORIZED, "AtB session not found or expired").into_response();
    };
    if !session.is_alive() {
        return (StatusCode::UNAUTHORIZED, "AtB session not in attested state").into_response();
    }

    // 2. Select the upstream from the live route table (same host/path rule the
    //    proxy uses), then translate http(s):// -> ws(s)://.
    let table = state.routes.load();
    let Some(route) = table.select(&req_parts.host, &req_parts.path) else {
        warn!(host = %req_parts.host, path = %req_parts.path, "no route matched for WS upgrade");
        return (StatusCode::NOT_FOUND, "no route matched").into_response();
    };
    let upstream_url = match build_upstream_ws_url(&route.upstream, &req_parts.path, req_parts.query.as_deref()) {
        Ok(u) => u,
        Err(e) => {
            warn!(upstream = %route.upstream, error = %e, "invalid upstream WS URL");
            return (StatusCode::BAD_GATEWAY, "invalid upstream WS target").into_response();
        }
    };

    // 3. Derive per-WS keys from the session BEFORE the upgrade (so a failure
    //    surfaces as a clean HTTP error, not a half-open socket).
    let Some(keys) = WsKeys::from_session(&session) else {
        return (StatusCode::UNAUTHORIZED, "session keys unavailable").into_response();
    };
    let aad = session_aad(&session);

    debug!(%atb_id, upstream = %upstream_url, "upgrading to attested WebSocket passthrough");

    // 4. Perform the HTTP -> WS upgrade and run the bridge.
    ws.on_upgrade(move |socket| async move {
        if let Err(e) = run_bridge(socket, &upstream_url, keys, aad).await {
            debug!(error = %e, "attested WS bridge ended");
        }
    })
}

/// Request metadata needed for WS routing, captured by the dispatch guard
/// before the body is touched.
pub struct WsRequestMeta {
    pub host: String,
    pub path: String,
    pub query: Option<String>,
    pub base_id: Option<String>,
}

/// Translate a route's `http(s)://host[:port]` upstream + the request path/query
/// into a `ws(s)://` URL for `connect_async`.
fn build_upstream_ws_url(
    upstream: &str,
    path: &str,
    query: Option<&str>,
) -> Result<String, String> {
    let base = upstream.trim_end_matches('/');
    let ws_base = if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{rest}")
    } else if base.starts_with("ws://") || base.starts_with("wss://") {
        base.to_owned()
    } else {
        return Err(format!("unsupported upstream scheme: {upstream}"));
    };
    let mut url = format!("{ws_base}{path}");
    if let Some(q) = query {
        url.push('?');
        url.push_str(q);
    }
    Ok(url)
}

/// Dial the upstream WS and pump frames in both directions until either side
/// closes or errors. Clean teardown: `select!` drops the losing direction.
async fn run_bridge(
    client_ws: WebSocket,
    upstream_url: &str,
    keys: WsKeys,
    aad: Vec<u8>,
) -> Result<(), String> {
    let (upstream_ws, _resp) = tokio_tungstenite::connect_async(upstream_url)
        .await
        .map_err(|e| format!("upstream WS dial failed: {e}"))?;

    let (mut client_tx, mut client_rx) = client_ws.split();
    let (mut up_tx, mut up_rx) = upstream_ws.split();

    // Outbound (server -> client) seal key: monotonic counter via BoundAeadKey.
    let out_key = BoundAeadKey::new(keys.algorithm, &keys.server_write_key, keys.server_write_iv)
        .map_err(|e| format!("outbound key setup failed: {e}"))?;
    // Inbound (client -> server) open key + IV for counter extraction.
    let in_key = AeadKey::new(keys.algorithm, &keys.client_write_key)
        .map_err(|e| format!("inbound key setup failed: {e}"))?;
    let in_iv = keys.client_write_iv;
    let aad_in = aad.clone();

    // client -> upstream: decrypt each client frame, forward to the upstream.
    let c2u = async move {
        let mut last_counter: u64 = 0;
        while let Some(msg) = client_rx.next().await {
            let msg = match msg {
                Ok(m) => m,
                Err(e) => return Err(format!("client WS recv error: {e}")),
            };
            match msg {
                AxumMessage::Binary(data) => {
                    if data.len() > MAX_WS_FRAME {
                        return Err("inbound WS frame exceeds cap".to_owned());
                    }
                    match decode_inbound(&data, &in_key, &in_iv, &aad_in, &mut last_counter)? {
                        InPayload::Text(t) => up_tx
                            .send(UpMessage::Text(t.into()))
                            .await
                            .map_err(|e| format!("upstream send failed: {e}"))?,
                        InPayload::Binary(b) => up_tx
                            .send(UpMessage::Binary(b.into()))
                            .await
                            .map_err(|e| format!("upstream send failed: {e}"))?,
                    }
                }
                AxumMessage::Ping(p) => up_tx
                    .send(UpMessage::Ping(p))
                    .await
                    .map_err(|e| format!("upstream ping failed: {e}"))?,
                AxumMessage::Pong(p) => up_tx
                    .send(UpMessage::Pong(p))
                    .await
                    .map_err(|e| format!("upstream pong failed: {e}"))?,
                AxumMessage::Close(_) => {
                    let _ = up_tx.send(UpMessage::Close(None)).await;
                    return Ok(());
                }
                // Plaintext text frames are not part of the attested wire
                // format; ignore for robustness (mirrors SDK leniency).
                AxumMessage::Text(_) => {}
            }
        }
        Ok(())
    };

    // upstream -> client: encrypt each upstream message, forward to the client.
    let u2c = async move {
        while let Some(msg) = up_rx.next().await {
            let msg = match msg {
                Ok(m) => m,
                Err(e) => return Err(format!("upstream WS recv error: {e}")),
            };
            match msg {
                UpMessage::Text(t) => {
                    if t.len() > MAX_WS_FRAME {
                        return Err("upstream text frame exceeds cap".to_owned());
                    }
                    let frame = encode_outbound(MSG_TEXT, t.as_bytes(), &out_key, &aad)?;
                    client_tx
                        .send(AxumMessage::Binary(frame.into()))
                        .await
                        .map_err(|e| format!("client send failed: {e}"))?;
                }
                UpMessage::Binary(b) => {
                    if b.len() > MAX_WS_FRAME {
                        return Err("upstream binary frame exceeds cap".to_owned());
                    }
                    let frame = encode_outbound(MSG_BINARY, &b, &out_key, &aad)?;
                    client_tx
                        .send(AxumMessage::Binary(frame.into()))
                        .await
                        .map_err(|e| format!("client send failed: {e}"))?;
                }
                UpMessage::Ping(p) => client_tx
                    .send(AxumMessage::Ping(p))
                    .await
                    .map_err(|e| format!("client ping failed: {e}"))?,
                UpMessage::Pong(p) => client_tx
                    .send(AxumMessage::Pong(p))
                    .await
                    .map_err(|e| format!("client pong failed: {e}"))?,
                UpMessage::Close(_) => {
                    let _ = client_tx.send(AxumMessage::Close(None)).await;
                    return Ok(());
                }
                // Raw frames are not produced by tokio-tungstenite in read mode.
                UpMessage::Frame(_) => {}
            }
        }
        Ok(())
    };

    // Whichever direction ends first tears the bridge down; the other future is
    // dropped (closing its sink) for a clean bidirectional teardown.
    tokio::select! {
        r = c2u => r,
        r = u2c => r,
    }
}

/// Seal an outbound application payload into the attested WS wire frame:
/// `[12-byte nonce] || AEAD( type_byte || payload )`. Mirrors
/// `AttestWsSession::encode_frame`.
fn encode_outbound(
    type_byte: u8,
    payload: &[u8],
    key: &BoundAeadKey,
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let mut plaintext = Vec::with_capacity(1 + payload.len());
    plaintext.push(type_byte);
    plaintext.extend_from_slice(payload);
    let nonce = key
        .seal(aad, &mut plaintext)
        .map_err(|e| format!("WS seal failed: {e}"))?;
    let mut frame = Vec::with_capacity(12 + plaintext.len());
    frame.extend_from_slice(&nonce.0);
    frame.extend_from_slice(&plaintext);
    Ok(frame)
}

/// Open an inbound attested WS frame, enforcing strict-monotonic counters.
/// Mirrors `AttestWsSession::decode_frame`.
fn decode_inbound(
    frame: &[u8],
    key: &AeadKey,
    iv: &[u8; 12],
    aad: &[u8],
    last_counter: &mut u64,
) -> Result<InPayload, String> {
    if frame.len() < MIN_FRAME {
        return Err(format!("frame too short: {} bytes", frame.len()));
    }
    let nonce = AeadNonce::from_slice(&frame[..12]).map_err(|e| format!("bad nonce: {e}"))?;
    let counter = extract_counter(&frame[..12], iv);
    if counter <= *last_counter {
        return Err("nonce replay detected".to_owned());
    }
    *last_counter = counter;

    let mut ciphertext = frame[12..].to_vec();
    let plaintext = key
        .open_in_place(&nonce, aad, &mut ciphertext)
        .map_err(|e| format!("WS open failed: {e}"))?;

    match plaintext.first().copied() {
        Some(MSG_TEXT) => {
            let text = String::from_utf8(plaintext[1..].to_vec())
                .map_err(|e| format!("invalid UTF-8 in text frame: {e}"))?;
            Ok(InPayload::Text(text))
        }
        Some(MSG_BINARY) => Ok(InPayload::Binary(plaintext[1..].to_vec())),
        Some(b) => Err(format!("unknown message type byte: {b:#04x}")),
        None => Err("empty plaintext".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_url_http_to_ws() {
        assert_eq!(
            build_upstream_ws_url("http://api:8080", "/chat", None).unwrap(),
            "ws://api:8080/chat"
        );
        assert_eq!(
            build_upstream_ws_url("https://api:8443/", "/chat", Some("x=1")).unwrap(),
            "wss://api:8443/chat?x=1"
        );
        assert_eq!(
            build_upstream_ws_url("ws://api:9000", "/s", None).unwrap(),
            "ws://api:9000/s"
        );
        assert!(build_upstream_ws_url("ftp://api", "/s", None).is_err());
    }

    #[test]
    fn outbound_roundtrips_through_inbound_decode() {
        // Seal with the server-write key, open with a fresh key of the same
        // bytes (the client mirror), proving wire-format symmetry + monotonic
        // counter acceptance.
        let key_bytes = [7u8; 32];
        let iv = [3u8; 12];
        let aad = b"openhttpa:test".to_vec();

        let out = BoundAeadKey::new(AeadAlgorithm::Aes256Gcm, &key_bytes, iv).unwrap();
        let in_key = AeadKey::new(AeadAlgorithm::Aes256Gcm, &key_bytes).unwrap();

        let mut last = 0u64;
        let frame = encode_outbound(MSG_TEXT, b"hello", &out, &aad).unwrap();
        match decode_inbound(&frame, &in_key, &iv, &aad, &mut last).unwrap() {
            InPayload::Text(t) => assert_eq!(t, "hello"),
            InPayload::Binary(_) => panic!("expected text"),
        }
        assert_eq!(last, 1, "first frame carries counter 1");

        let frame2 = encode_outbound(MSG_BINARY, &[1, 2, 3], &out, &aad).unwrap();
        match decode_inbound(&frame2, &in_key, &iv, &aad, &mut last).unwrap() {
            InPayload::Binary(b) => assert_eq!(b, vec![1, 2, 3]),
            InPayload::Text(_) => panic!("expected binary"),
        }
        assert_eq!(last, 2);
    }

    #[test]
    fn replayed_counter_rejected() {
        let key_bytes = [9u8; 32];
        let iv = [1u8; 12];
        let aad = b"openhttpa:x".to_vec();
        let out = BoundAeadKey::new(AeadAlgorithm::Aes256Gcm, &key_bytes, iv).unwrap();
        let in_key = AeadKey::new(AeadAlgorithm::Aes256Gcm, &key_bytes).unwrap();

        let f1 = encode_outbound(MSG_TEXT, b"a", &out, &aad).unwrap();
        let f2 = encode_outbound(MSG_TEXT, b"b", &out, &aad).unwrap();

        let mut last = 0u64;
        decode_inbound(&f2, &in_key, &iv, &aad, &mut last).unwrap(); // counter 2 accepted
        // f1 carries counter 1 (<= last) -> replay.
        assert!(decode_inbound(&f1, &in_key, &iv, &aad, &mut last).is_err());
    }

    #[test]
    fn short_frame_rejected() {
        let key = AeadKey::new(AeadAlgorithm::Aes256Gcm, &[0u8; 32]).unwrap();
        let iv = [0u8; 12];
        let mut last = 0u64;
        assert!(decode_inbound(&[0u8; 10], &key, &iv, b"aad", &mut last).is_err());
    }
}
