// Terminates attested sessions and reverse-proxies decrypted traffic: decrypt
// the trusted request, select an upstream from the live route table by
// host/path, forward via reqwest, and stream a sealed response back.

use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::Router;
use axum::extract::{FromRef, FromRequest, FromRequestParts, OriginalUri, Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};

use openhttpa_crypto::aead::{AeadAlgorithm, AeadNonce, BoundAeadKey};
use openhttpa_server::LlmError;
use openhttpa_server::atb_registry::AtbRegistry;
use openhttpa_server::extractors::OpenHttpaSession;
use openhttpa_server::middleware::TrRequestLayer;

use crate::config::RouteTable;
use crate::envelope::StreamFrame;
use crate::metrics::Metrics;

/// Carries the client's real HTTP method. The wire request is always POST so
/// the encrypted body survives transports that drop it on GET/HEAD/DELETE; the
/// real method travels here. The `attest-` prefix is required: `update_ahl`
/// folds every `attest-*` header into the AHL MAC, so a verified Attest-Ticket
/// authenticates this value and it can be trusted for upstream forwarding.
/// Kept in sync with the same const in the client's session.rs.
const HDR_ATTEST_REAL_METHOD: &str = "attest-real-method";

#[derive(Clone)]
pub struct ProxyState {
    pub registry: AtbRegistry,
    pub http: reqwest::Client,
    /// Live, hot-swappable route table (file routes + discovery).
    pub routes: Arc<ArcSwap<RouteTable>>,
    pub max_body_bytes: usize,
    /// Process metrics (counters/histogram) exposed at `/metrics`.
    pub metrics: Metrics,
}

impl FromRef<ProxyState> for AtbRegistry {
    fn from_ref(state: &ProxyState) -> Self {
        state.registry.clone()
    }
}

impl FromRef<ProxyState> for Metrics {
    fn from_ref(state: &ProxyState) -> Self {
        state.metrics.clone()
    }
}

/// Lets the `DecryptedRequest` extractor read the body cap from state.
#[derive(Clone, Copy)]
pub struct MaxBodyBytes(pub usize);

impl FromRef<ProxyState> for MaxBodyBytes {
    fn from_ref(state: &ProxyState) -> Self {
        Self(state.max_body_bytes)
    }
}

/// A decrypted trusted request: plaintext body plus the metadata needed to
/// reconstruct the outbound call. Follows the `EncryptedJson` decrypt+MAC path
/// but yields raw bytes so arbitrary (non-JSON) bodies round-trip.
pub struct DecryptedRequest {
    pub session: OpenHttpaSession,
    pub method: http::Method,
    pub path: String,
    pub query: Option<String>,
    /// Request authority (host) as seen by the client; used for route matching.
    pub host: String,
    pub body: Vec<u8>,
}

#[derive(serde::Deserialize)]
struct CiphertextBody {
    ciphertext: String,
}

impl<S> FromRequest<S> for DecryptedRequest
where
    AtbRegistry: FromRef<S>,
    MaxBodyBytes: FromRef<S>,
    Metrics: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let max_body_bytes = MaxBodyBytes::from_ref(state).0;
        let metrics = Metrics::from_ref(state);
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::Sha384;
        type HmacSha384 = Hmac<Sha384>;

        let (mut parts, body) = req.into_parts();
        let session =
            <OpenHttpaSession as FromRequestParts<S>>::from_request_parts(&mut parts, state)
                .await?;

        let decoded = openhttpa_headers::decode_attest_ticket(&parts.headers).map_err(|e| {
            let status = if matches!(e, openhttpa_headers::TrailerError::Missing { .. }) {
                StatusCode::UNAUTHORIZED
            } else {
                StatusCode::BAD_REQUEST
            };
            (status, "Invalid Attest-Ticket format").into_response()
        })?;
        let (nonce_val, mac_val) = (decoded.nonce, decoded.mac);

        // Cap the encrypted envelope before buffering. The body is
        // {"ciphertext":"<hex>"}: hex doubles the ciphertext, which is at most
        // plaintext + 16 (GCM tag), plus a little JSON overhead.
        const JSON_OVERHEAD: usize = 64;
        let pre_decrypt_cap = max_body_bytes
            .saturating_add(16)
            .saturating_mul(2)
            .saturating_add(JSON_OVERHEAD);
        let body_bytes = axum::body::to_bytes(body, pre_decrypt_cap).await.map_err(|_| {
            (
                StatusCode::PAYLOAD_TOO_LARGE,
                "Encrypted request envelope too large",
            )
                .into_response()
        })?;
        let parsed: CiphertextBody = serde_json::from_slice(&body_bytes).map_err(|e| {
            tracing::error!(error = %e, "invalid request envelope");
            (StatusCode::BAD_REQUEST, "Invalid request envelope").into_response()
        })?;

        let mut ciphertext = hex::decode(&parsed.ciphertext).map_err(|e| {
            tracing::error!(error = %e, "invalid ciphertext hex");
            (StatusCode::BAD_REQUEST, "Invalid ciphertext hex").into_response()
        })?;

        // Path/query as seen by the client (OriginalUri preserves nesting).
        let original_uri = parts.extensions.get::<OriginalUri>().cloned();
        let path = original_uri
            .as_ref()
            .map_or_else(|| parts.uri.path(), |u| u.0.path())
            .to_owned();
        let query = original_uri
            .as_ref()
            .map_or_else(|| parts.uri.query(), |u| u.0.query())
            .map(ToOwned::to_owned);

        // Authority for AHL: URI authority (HTTP/2) or Host header (HTTP/1.1).
        let host_hdr;
        let authority = if let Some(a) = parts.uri.authority() {
            a.as_str().to_owned()
        } else {
            host_hdr = parts
                .headers
                .get(http::header::HOST)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned();
            host_hdr.clone()
        };
        if authority.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                "Missing Host / authority header — required for AHL integrity",
            )
                .into_response());
        }

        let plaintext_res = session.session.with_keys_for_trr(
            nonce_val,
            |keys, _counter: u64| -> Result<Vec<u8>, Box<Response>> {
                // 1. Verify Attest-Ticket MAC (HMAC-SHA-384 over nonce + AHL).
                let mut hmac = HmacSha384::new_from_slice(&keys.client_mac_key).map_err(|_| {
                    Box::new(
                        (StatusCode::INTERNAL_SERVER_ERROR, "HMAC init failed").into_response(),
                    )
                })?;
                hmac.update(&nonce_val.to_be_bytes());
                openhttpa_headers::update_ahl(
                    parts.method.as_str(),
                    &path,
                    query.as_deref(),
                    &authority,
                    &parts.headers,
                    |chunk| hmac.update(chunk),
                )
                .map_err(|e| {
                    tracing::error!(error = %e, "AHL error");
                    Box::new((StatusCode::BAD_REQUEST, format!("AHL error: {e}")).into_response())
                })?;
                if hmac.verify_slice(&mac_val).is_err() {
                    return Err(Box::new(
                        (StatusCode::UNAUTHORIZED, "Invalid header MAC").into_response(),
                    ));
                }

                // 2. Decrypt body.
                let mut nonce_bytes = [0u8; 12];
                nonce_bytes.copy_from_slice(&keys.client_write_iv);
                let count_bytes = nonce_val.to_be_bytes();
                for (i, b) in count_bytes.iter().enumerate() {
                    nonce_bytes[4 + i] ^= b;
                }
                let aead_nonce = AeadNonce::from_slice(&nonce_bytes).unwrap();

                let bound_key = BoundAeadKey::new(
                    AeadAlgorithm::Aes256Gcm,
                    &keys.client_write_key,
                    keys.client_write_iv.clone().try_into().expect(
                        "client_write_iv must be exactly 12 bytes (HKDF-SHA384 invariant)",
                    ),
                )
                .map_err(|_| {
                    Box::new(
                        (StatusCode::INTERNAL_SERVER_ERROR, "Key setup failed").into_response(),
                    )
                })?;

                let p = bound_key
                    .open(&aead_nonce, &session.aad, &mut ciphertext)
                    .map_err(|e| {
                        tracing::error!(error = ?e, "decryption failed");
                        Box::new((StatusCode::BAD_REQUEST, "Decryption failed").into_response())
                    })?;
                Ok(p.to_vec())
            },
        );

        let plaintext = match plaintext_res {
            Ok(Ok(p)) => p,
            Ok(Err(resp)) => {
                metrics.inc_decrypt_failures();
                return Err(*resp);
            }
            Err(e) => {
                metrics.inc_decrypt_failures();
                return Err((StatusCode::UNAUTHORIZED, format!("{e}")).into_response());
            }
        };

        // The wire method is always POST; the real method is in the (MAC-bound)
        // attest-real-method header. Fall back to the wire method if absent.
        let method = parts
            .headers
            .get(HDR_ATTEST_REAL_METHOD)
            .and_then(|v| v.to_str().ok())
            .and_then(|m| http::Method::from_bytes(m.as_bytes()).ok())
            .unwrap_or_else(|| parts.method.clone());

        Ok(Self {
            method,
            session,
            path,
            query,
            host: authority,
            body: plaintext,
        })
    }
}

/// Build the router: the OpenHTTPA base router (handshake), the attested
/// catch-all reverse proxy, and the unauthenticated `/healthz`, `/readyz`, and
/// `/metrics` endpoints.
pub fn build_router(base_router: Router, state: ProxyState) -> Router {
    let tr_layer = TrRequestLayer::new(state.registry.clone());

    // Count successful handshakes by observing /attest responses.
    let metrics_for_hs = state.metrics.clone();
    let base_router = base_router.layer(axum::middleware::from_fn(
        move |req: Request, next: axum::middleware::Next| {
            let metrics = metrics_for_hs.clone();
            async move {
                let is_attest = req.method() == http::Method::POST && req.uri().path() == "/attest";
                let resp = next.run(req).await;
                if is_attest && resp.status().is_success() {
                    metrics.inc_handshakes();
                }
                resp
            }
        },
    ));

    // Observability endpoints share state but sit outside the attestation gate.
    let observability = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics_handler))
        .with_state(state.clone());

    let proxy_routes = Router::new()
        .route("/", any(proxy_handler))
        .route("/{*path}", any(proxy_handler))
        .route_layer(tr_layer)
        .with_state(state.clone());

    let merged = base_router.merge(observability).merge(proxy_routes);

    // An attested WebSocket is a GET upgrade that shares paths with the proxy
    // catch-all. This guard, outside TrRequestLayer, routes those upgrades to
    // the WS handler and passes everything else through.
    merged.layer(axum::middleware::from_fn_with_state(
        state,
        ws_dispatch_middleware,
    ))
}

/// Middleware that diverts attested WS upgrades to the WS handler and passes
/// everything else through to the normal proxy/observability routes.
async fn ws_dispatch_middleware(
    State(state): State<ProxyState>,
    req: Request,
    next: axum::middleware::Next,
) -> Response {
    use axum::extract::FromRequestParts;
    use axum::extract::ws::WebSocketUpgrade;

    if !crate::ws::is_attested_ws_upgrade(&req) {
        return next.run(req).await;
    }

    // Capture routing metadata (path/host/query + base-id) before consuming the
    // request to build the WebSocketUpgrade extractor.
    let (mut parts, body) = req.into_parts();
    let path = parts.uri.path().to_owned();
    let query = parts.uri.query().map(ToOwned::to_owned);
    let host = parts
        .uri
        .authority()
        .map(|a| a.as_str().to_owned())
        .or_else(|| {
            parts
                .headers
                .get(http::header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(ToOwned::to_owned)
        })
        .unwrap_or_default();
    let base_id = parts
        .headers
        .get(&*openhttpa_headers::HDR_ATTEST_BASE_ID)
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);

    let meta = crate::ws::WsRequestMeta { host, path, query, base_id };

    let ws = match WebSocketUpgrade::from_request_parts(&mut parts, &state).await {
        Ok(ws) => ws,
        Err(rej) => {
            // Not a valid WS upgrade after all -- restore and pass through.
            let req = Request::from_parts(parts, body);
            let _ = rej;
            return next.run(req).await;
        }
    };

    crate::ws::ws_upgrade_handler(ws, state, meta).await
}

/// Liveness: the process is up.
async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

/// Readiness: the router is built and serving.
async fn readyz() -> impl IntoResponse {
    (StatusCode::OK, "ready")
}

async fn metrics_handler(State(state): State<ProxyState>) -> impl IntoResponse {
    let active = state.registry.len();
    let body = state.metrics.render_prometheus(active);
    (
        StatusCode::OK,
        [(
            http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
}

/// Seal a proxy-generated error into the same framed response as a normal reply,
/// so the client recovers the real status instead of a bare non-2xx it would
/// misread as a transport failure. Emits a `Head` frame then one `Body` frame.
fn seal_error(session: OpenHttpaSession, status: StatusCode, message: &str) -> Response {
    let frames: Vec<Result<StreamFrame, LlmError>> = vec![
        Ok(StreamFrame::Head {
            status: status.as_u16(),
            headers: vec![("content-type".to_owned(), "text/plain".to_owned())],
        }),
        Ok(StreamFrame::Body {
            data: message.as_bytes().to_vec(),
        }),
    ];
    session.seal_stream(futures_util::stream::iter(frames))
}

async fn proxy_handler(State(state): State<ProxyState>, req: DecryptedRequest) -> Response {
    let max = state.max_body_bytes;

    if req.body.len() > max {
        return seal_error(req.session, StatusCode::PAYLOAD_TOO_LARGE, "request body too large");
    }

    let table = state.routes.load();
    let Some(route) = table.select(&req.host, &req.path) else {
        tracing::warn!(host = %req.host, path = %req.path, "no route matched");
        return seal_error(req.session, StatusCode::NOT_FOUND, "no route matched");
    };

    let mut url = route.upstream.trim_end_matches('/').to_owned();
    url.push_str(&req.path);
    if let Some(q) = req.query.as_deref() {
        url.push('?');
        url.push_str(q);
    }

    let method = match reqwest::Method::from_bytes(req.method.as_str().as_bytes()) {
        Ok(m) => m,
        Err(_) => return seal_error(req.session, StatusCode::BAD_REQUEST, "invalid method"),
    };

    state.metrics.inc_upstream_requests();
    let started = std::time::Instant::now();
    let upstream_resp = state
        .http
        .request(method, &url)
        .body(req.body)
        .send()
        .await;
    state
        .metrics
        .observe_upstream_latency(started.elapsed().as_secs_f64());

    let upstream_resp = match upstream_resp {
        Ok(r) => r,
        Err(e) => {
            state.metrics.inc_upstream_errors();
            let status = if e.is_timeout() {
                StatusCode::GATEWAY_TIMEOUT
            } else {
                StatusCode::BAD_GATEWAY
            };
            tracing::error!(error = %e, url = %url, "upstream request failed");
            return seal_error(req.session, status, "upstream request failed");
        }
    };

    let status = upstream_resp.status().as_u16();

    // Strip the static hop-by-hop headers plus any names the upstream lists in
    // its Connection header, so a Connection-nominated secret cannot leak.
    let mut strip: std::collections::HashSet<String> = upstream_resp
        .headers()
        .get(http::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .into_iter()
        .flat_map(|v| v.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .collect();
    strip.extend(STATIC_HOP_BY_HOP.iter().map(|s| (*s).to_owned()));

    let headers: Vec<(String, String)> = upstream_resp
        .headers()
        .iter()
        .filter(|(name, _)| !strip.contains(name.as_str()))
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.as_str().to_owned(), v.to_owned()))
        })
        .collect();

    // Reject up front on an over-cap Content-Length, before buffering anything.
    if let Some(len) = upstream_resp.content_length()
        && len > max as u64
    {
        tracing::warn!(content_length = len, max, "upstream Content-Length over cap");
        return seal_error(req.session, StatusCode::PAYLOAD_TOO_LARGE, "upstream body too large");
    }

    // Stream the response as a Head frame (status + headers) followed by one
    // Body frame per upstream chunk, sealed as they arrive so the body is never
    // held whole. The size cap is enforced against a running total; once frames
    // are in flight the Head is already sent, so an over-cap body ends the
    // stream with a transport error and the client enforces the same cap.
    use futures_util::StreamExt;
    let head = StreamFrame::Head { status, headers };
    let upstream_stream = upstream_resp.bytes_stream();

    let body_frames = upstream_stream.scan(0usize, move |acc, chunk| {
        let out = match chunk {
            Ok(c) => {
                *acc = acc.saturating_add(c.len());
                if *acc > max {
                    tracing::warn!(max, "upstream body exceeded cap while streaming");
                    Err(LlmError::Transport("upstream body too large".to_owned()))
                } else {
                    Ok(StreamFrame::Body { data: c.to_vec() })
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "reading upstream body failed");
                Err(LlmError::Transport("upstream body read failed".to_owned()))
            }
        };
        futures_util::future::ready(Some(out))
    });

    let frame_stream =
        futures_util::stream::once(async move { Ok::<_, LlmError>(head) }).chain(body_frames);

    req.session.seal_stream(frame_stream)
}

// Stripped before sealing; the body is re-framed, so the upstream's framing
// headers no longer apply. Connection-nominated names are added at runtime.
const STATIC_HOP_BY_HOP: &[&str] = &[
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "upgrade",
];