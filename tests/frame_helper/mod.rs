// Shared test helper: drive a MONOLITHIC trusted request + decode the FRAMED
// `seal_stream` RESPONSE, exactly as the real archetype-proxy-client does in
// `src-tauri/src/session.rs`. The stock `OpenHttpaClient::trusted_request`
// JSON-decodes the response and so cannot read the proxy's frame stream; this
// helper replicates the request seal (mirroring the client's private
// `seal_request_body`) and the response-frame decode (the inverse of the
// server's `seal_stream`) so the e2e tests can assert against the true
// upstream/proxy status + body.
//
// This is the "shared frame-decode test helper" the task asked for: it lives in
// a `tests/` SUBDIRECTORY (`frame_helper/mod.rs`) so Cargo does NOT compile it
// as its own test binary; it is `mod frame_helper`'d into proxy_e2e.rs.

use hmac::{Hmac, KeyInit, Mac};
use http_body_util::BodyExt;
use openhttpa_core::session::AttestSession;
use openhttpa_crypto::aead::{AeadAlgorithm, AeadKey, AeadNonce, BoundAeadKey};
use openhttpa_headers::{HDR_ATTEST_BASE_ID, HDR_ATTEST_TICKET, encode_attest_ticket, update_ahl};
use openhttpa_transport::connection::{AttestTransport, TransportRequest, full_body};
use openhttpa_transport::reqwest_adapter::ReqwestTransport;
use sha2::{Digest, Sha384};

/// Mirror of the client/server `HDR_ATTEST_REAL_METHOD` const: carries the
/// browser's real method while the wire method is always POST. KEEP IN SYNC.
const HDR_ATTEST_REAL_METHOD: &str = "attest-real-method";
const WIRE_METHOD: &str = "POST";

// Mirror of `archetype_proxy_server::envelope::StreamFrame` (kept private to the
// crate). Byte-identical serde shape: the wire is JSON(StreamFrame).
#[derive(serde::Deserialize)]
enum StreamFrame {
    Head {
        status: u16,
        headers: Vec<(String, String)>,
    },
    Body {
        #[serde(with = "serde_bytes_hex")]
        data: Vec<u8>,
    },
}

mod serde_bytes_hex {
    use serde::{Deserialize, Deserializer};
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

type HmacSha384 = Hmac<Sha384>;

/// Reassembled framed response: the `Head` status + headers and the
/// concatenated `Body` frames.
pub struct FramedResponse {
    pub status: u16,
    #[allow(dead_code)]
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// AHL authority for a URI, dropping the default port (mirrors the client's
/// private `ahl_authority`). MUST stay byte-compatible with the pinned client.
fn ahl_authority(uri: &http::Uri) -> &str {
    let Some(auth) = uri.authority().map(http::uri::Authority::as_str) else {
        return "";
    };
    let default_port = match uri.scheme_str() {
        Some("https") => "443",
        Some("http") => "80",
        _ => return auth,
    };
    if let Some((host, port)) = auth.rsplit_once(':')
        && port == default_port
    {
        return host;
    }
    auth
}

/// Send a MONOLITHIC trusted request on `session` against `server_base` and
/// decode the FRAMED response into a [`FramedResponse`]. Mirrors session.rs.
pub async fn framed_trusted_request(
    session: &AttestSession,
    server_base: &http::Uri,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<FramedResponse, String> {
    let transport = ReqwestTransport::new();

    let base_id = session.state().id;
    let mut aad = b"openhttpa:".to_vec();
    aad.extend_from_slice(base_id.to_string().as_bytes());

    // Build the full URI (server base + path) exactly as the client does.
    let mut base_uri_str = server_base.to_string();
    if base_uri_str.ends_with('/') && path.starts_with('/') {
        base_uri_str.pop();
    }
    let full_uri_str = format!("{base_uri_str}{path}");
    let full_uri: http::Uri = full_uri_str
        .parse()
        .map_err(|e| format!("invalid uri {full_uri_str}: {e}"))?;
    let final_path = full_uri.path().to_owned();
    let query = full_uri.query().map(ToOwned::to_owned);
    let authority = ahl_authority(&full_uri).to_owned();

    // MONOLITHIC request seal (mirror seal_request_body): random nonce, counter
    // from the session, AEAD over the body, HMAC-SHA-384 over counter + AHL.
    let (headers, encrypted_body) = seal_request(
        session,
        method,
        &final_path,
        query.as_deref(),
        &authority,
        body,
        &aad,
        base_id,
    )?;

    let mut headers = headers;
    headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/json"),
    );

    // TRANSPORT vs SEMANTIC method (mirrors session.rs): always send wire POST
    // so the encrypted envelope body survives; the real method rode in the
    // AHL-bound header sealed in `seal_request`.
    let req = TransportRequest {
        method: http::Method::from_bytes(WIRE_METHOD.as_bytes()).unwrap(),
        uri: full_uri,
        headers,
        body: full_body(
            serde_json::to_vec(&serde_json::json!({
                "ciphertext": hex::encode(encrypted_body)
            }))
            .map_err(|e| e.to_string())?,
        ),
        trailers: None,
    };

    let resp = transport
        .send(req)
        .await
        .map_err(|e| format!("transport send failed: {e}"))?;

    if !resp.status.is_success() {
        return Err(format!("server returned error: {}", resp.status));
    }

    // Collect the full framed body (test-only: buffering is fine here).
    let raw = resp
        .body
        .collect()
        .await
        .map_err(|e| format!("body collect failed: {e}"))?
        .to_bytes();

    decode_frames(session, &aad, &raw)
}

/// Decode the `[len: u32 BE][counter: u64 BE][ciphertext]` frame stream into a
/// reassembled response. Inverse of the server's `seal_stream`: nonce =
/// server_write_iv XOR counter, AAD = aad || cumulative_SHA384(prev ct),
/// plaintext = JSON(StreamFrame). FIRST frame is `Head`, rest are `Body`.
fn decode_frames(
    session: &AttestSession,
    aad: &[u8],
    raw: &[u8],
) -> Result<FramedResponse, String> {
    let mut offset = 0usize;
    let mut prev_hash = [0u8; 48];
    let mut status: Option<u16> = None;
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut body: Vec<u8> = Vec::new();

    while offset < raw.len() {
        if offset + 12 > raw.len() {
            return Err("truncated frame header".to_owned());
        }
        let len = u32::from_be_bytes(raw[offset..offset + 4].try_into().unwrap()) as usize;
        let counter = u64::from_be_bytes(raw[offset + 4..offset + 12].try_into().unwrap());
        offset += 12;
        if offset + len > raw.len() {
            return Err("truncated frame body".to_owned());
        }
        let mut ciphertext = raw[offset..offset + len].to_vec();
        offset += len;

        let parsed = session
            .with_keys_for_trs(|keys, _counter| {
                let mut nonce_bytes = [0u8; 12];
                nonce_bytes.copy_from_slice(&keys.server_write_iv);
                let count_bytes = counter.to_be_bytes();
                for (i, b) in count_bytes.iter().enumerate() {
                    nonce_bytes[4 + i] ^= b;
                }
                let aead_nonce = AeadNonce::from_slice(&nonce_bytes)
                    .map_err(|_| "nonce length invariant violated".to_owned())?;
                let key = AeadKey::new(AeadAlgorithm::Aes256Gcm, &keys.server_write_key)
                    .map_err(|e| e.to_string())?;

                let mut chunk_aad = aad.to_vec();
                chunk_aad.extend_from_slice(&prev_hash);

                // Advance cumulative hash over the CIPHERTEXT before decrypt.
                let mut hasher = Sha384::new();
                hasher.update(prev_hash);
                hasher.update(&ciphertext);
                let next_hash: [u8; 48] = hasher.finalize().into();

                let plaintext = key
                    .open_in_place(&aead_nonce, &chunk_aad, &mut ciphertext)
                    .map_err(|e| format!("stream decrypt failed: {e:?}"))?;
                let frame: StreamFrame = serde_json::from_slice(plaintext)
                    .map_err(|e| format!("malformed stream frame: {e}"))?;
                Ok::<(StreamFrame, [u8; 48]), String>((frame, next_hash))
            })
            .map_err(|e| e.to_string())??;

        let (frame, next_hash) = parsed;
        prev_hash = next_hash;
        match frame {
            StreamFrame::Head { status: s, headers: h } => {
                if status.is_some() {
                    return Err("unexpected second Head frame".to_owned());
                }
                status = Some(s);
                headers = h;
            }
            StreamFrame::Body { data } => {
                if status.is_none() {
                    return Err("Body frame before Head".to_owned());
                }
                body.extend_from_slice(&data);
            }
        }
    }

    let status = status.ok_or_else(|| "empty stream: no Head frame".to_owned())?;
    Ok(FramedResponse {
        status,
        headers,
        body,
    })
}

/// Replicate the client's private `seal_request_body`: AEAD-seal the body with
/// the session's `client_write_key` (random nonce, counter from the session),
/// and MAC the counter + AHL into the Attest-Ticket header.
#[allow(clippy::too_many_arguments)]
fn seal_request(
    session: &AttestSession,
    method: &str,
    path: &str,
    query: Option<&str>,
    authority: &str,
    body: &[u8],
    aad: &[u8],
    base_id: openhttpa_proto::AtbId,
) -> Result<(http::HeaderMap, Vec<u8>), String> {
    let mut nonce_bytes = [0u8; 8];
    let rng = openhttpa_crypto::rand::SystemRandom::new();
    openhttpa_crypto::rand::SecureRandom::fill(&rng, &mut nonce_bytes)
        .map_err(|_| "RNG failure".to_owned())?;
    let nonce = u64::from_be_bytes(nonce_bytes);

    session
        .with_keys_for_trr(nonce, |keys, counter| {
            let mut iv = [0u8; 12];
            iv.copy_from_slice(&keys.client_write_iv);
            let bound_key = BoundAeadKey::new(AeadAlgorithm::Aes256Gcm, &keys.client_write_key, iv)
                .map_err(|e| format!("key setup failed: {e}"))?;

            let mut data = body.to_vec();
            bound_key
                .seal(aad, &mut data)
                .map_err(|e| format!("encryption failed: {e:?}"))?;

            let mut hdrs = http::HeaderMap::new();
            hdrs.insert(
                &*HDR_ATTEST_BASE_ID,
                http::HeaderValue::from_str(&base_id.to_string())
                    .map_err(|e| format!("invalid base-id header: {e}"))?,
            );

            // Bind the browser's real method into the AHL header set (mirrors
            // session.rs): `update_ahl` folds all `attest-*` headers into the
            // MAC, authenticating it end-to-end.
            hdrs.insert(
                http::HeaderName::from_static(HDR_ATTEST_REAL_METHOD),
                http::HeaderValue::from_str(&method.to_ascii_uppercase())
                    .map_err(|e| format!("invalid real-method header: {e}"))?,
            );

            let mut hmac = HmacSha384::new_from_slice(&keys.client_mac_key)
                .map_err(|e| format!("HMAC key setup failed: {e}"))?;
            hmac.update(&counter.to_be_bytes());
            // Seal AHL over the WIRE method (POST), not the browser's method.
            update_ahl(WIRE_METHOD, path, query, authority, &hdrs, |chunk| {
                hmac.update(chunk);
            })
            .map_err(|e| format!("AHL error: {e}"))?;
            let mac = hmac.finalize().into_bytes().to_vec();

            hdrs.insert(&*HDR_ATTEST_TICKET, encode_attest_ticket(counter, &mac, None));

            Ok::<_, String>((hdrs, data))
        })
        .map_err(|e| e.to_string())?
}
