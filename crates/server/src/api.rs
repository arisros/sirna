//! The HTTP surface.
//!
//! Four endpoints and three probes. The server's whole job is to move opaque
//! bytes and to guarantee that a blob is handed out at most once.

use std::sync::Arc;

use axum::{
    extract::{ConnectInfo, DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tracing::{info, warn};

use crate::db::{Claim, Db};
use crate::limit::RateLimiter;
use crate::store::BlobStore;

pub struct AppState<S: BlobStore> {
    pub db: tokio::sync::Mutex<Db>,
    pub store: S,
    pub limiter: RateLimiter,
    /// In-memory only, and untrusted by design — see `rendezvous`.
    pub relay: std::sync::Arc<crate::rendezvous::Relay>,
    pub max_blob_bytes: usize,
    pub default_ttl: u64,
    pub max_ttl: u64,
}

pub type Shared<S> = Arc<AppState<S>>;

pub fn router<S: BlobStore>(state: Shared<S>) -> Router {
    let max = state.max_blob_bytes;
    Router::new()
        .route("/api/v1/blobs", post(create))
        .route("/api/v1/blobs/{id}", get(fetch).delete(destroy))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz::<S>))
        .route("/metrics", get(metrics::<S>))
        // Custody mode: introduces a reader to the owner who holds the key.
        // Colocated on purpose — it is stateless, holds no secrets and needs no
        // storage, so it costs one deployment, one Caddy block and one
        // certificate rather than three of each.
        .route(
            "/api/v1/rendezvous/{id}",
            get(crate::rendezvous::handler::<S>),
        )
        // Everything else is the browser client, including the client-side
        // /m/<id> route.
        .fallback(crate::web::serve)
        // Without an explicit cap, a single large POST can drive the pod into
        // its memory limit and take the service down. There is no such cap
        // anywhere in OTM, which is exactly why one is here.
        .layer(DefaultBodyLimit::max(max))
        .with_state(state)
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The real client address.
///
/// Behind Cloudflare and two Caddy hops, the socket peer is a proxy. Caddy is
/// configured to put the visitor's address first in `X-Forwarded-For`; if that
/// chain is ever misconfigured every visitor collapses into a single bucket and
/// the rate limiter silently becomes global. That failure has already happened
/// once on this infrastructure, so it is worth stating plainly here.
fn client_ip(headers: &HeaderMap, peer: SocketAddr) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| peer.ip().to_string())
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

#[derive(Debug, Serialize)]
pub struct CreateResponse {
    pub id: String,
    /// Lets the owner withdraw the blob before it is read. Held only by the
    /// uploader; the server stores a hash of it.
    pub delete_token: String,
    pub expires_at: u64,
}

#[derive(Debug, Deserialize, Default)]
pub struct CreateQuery {
    pub ttl: Option<u64>,
}

pub struct ApiError(StatusCode, &'static str);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({ "error": self.1 }))).into_response()
    }
}

async fn create<S: BlobStore>(
    State(st): State<Shared<S>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<CreateQuery>,
    body: axum::body::Bytes,
) -> Result<Json<CreateResponse>, ApiError> {
    let ip = client_ip(&headers, peer);
    if !st.limiter.allow(&ip) {
        return Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "too many requests"));
    }

    if body.len() > st.max_blob_bytes {
        return Err(ApiError(
            StatusCode::PAYLOAD_TOO_LARGE,
            "envelope too large",
        ));
    }

    // Validate the header before storing. This is the only thing the server
    // understands about the payload, and it is enough to keep the bucket free
    // of junk. It cannot and must not go any further: `sirna_core::Header` is
    // the only part of the format this crate links.
    if sirna_core::Header::parse(&body).is_err() {
        return Err(ApiError(StatusCode::BAD_REQUEST, "not a Sirna envelope"));
    }

    let ttl = q.ttl.unwrap_or(st.default_ttl).min(st.max_ttl);
    let now = now();
    let expires_at = if ttl == 0 { 0 } else { now + ttl };

    let id = random_hex(16);
    let delete_token = random_hex(16);
    let token_hash = blake3::hash(delete_token.as_bytes()).to_hex().to_string();

    st.store.put(&id, body.to_vec()).await.map_err(|e| {
        warn!(%id, error = %e, "store put failed");
        ApiError(StatusCode::BAD_GATEWAY, "storage unavailable")
    })?;

    let db = st.db.lock().await;
    if let Err(e) = db.insert(&id, body.len() as u64, now, expires_at, &token_hash) {
        drop(db);
        // The object is already in the store but has no metadata row, so it
        // would never be reachable or reaped. Remove it rather than leak it.
        let _ = st.store.delete(&id).await;
        warn!(%id, error = %e, "metadata insert failed");
        return Err(ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not record blob",
        ));
    }

    info!(%id, size = body.len(), "stored");
    Ok(Json(CreateResponse {
        id,
        delete_token,
        expires_at,
    }))
}

async fn fetch<S: BlobStore>(
    State(st): State<Shared<S>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let ip = client_ip(&headers, peer);
    if !st.limiter.allow(&ip) {
        return Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "too many requests"));
    }
    if !is_valid_id(&id) {
        return Err(ApiError(StatusCode::NOT_FOUND, "not available"));
    }

    let claim = {
        let db = st.db.lock().await;
        db.try_claim(&id, now())
            .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "storage error"))?
    };

    match claim {
        // Never confirm which of the three it was. "Already read", "expired"
        // and "never existed" all look identical from outside, so the endpoint
        // cannot be used to probe whether a message ever existed.
        Claim::Unknown | Claim::Taken => return Err(ApiError(StatusCode::GONE, "not available")),
        Claim::Won => {}
    }

    // The blob was already marked consumed by the claim itself. Whatever
    // happens from here — a successful stream, a storage error, a dropped
    // connection — it will never be served again.
    match st.store.get(&id).await {
        Ok(bytes) => {
            info!(%id, "delivered");

            Ok((
                StatusCode::OK,
                [
                    ("content-type", "application/octet-stream"),
                    ("cache-control", "no-store"),
                ],
                bytes,
            )
                .into_response())
        }
        Err(e) => {
            // No retry. The claim stands, so this message is now gone for
            // everyone — that is what one-time means, and softening it here
            // would quietly turn "once" into "usually once".
            warn!(%id, error = %e, "store get failed after the blob was claimed; it is now unrecoverable");
            Err(ApiError(StatusCode::BAD_GATEWAY, "storage unavailable"))
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct DestroyBody {
    pub delete_token: String,
}

async fn destroy<S: BlobStore>(
    State(st): State<Shared<S>>,
    Path(id): Path<String>,
    Json(body): Json<DestroyBody>,
) -> Result<StatusCode, ApiError> {
    if !is_valid_id(&id) {
        return Err(ApiError(StatusCode::NOT_FOUND, "not available"));
    }

    let stored = {
        let db = st.db.lock().await;
        db.delete_token_hash(&id)
            .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "storage error"))?
    };

    let Some(stored) = stored else {
        return Err(ApiError(StatusCode::NOT_FOUND, "not available"));
    };

    let offered = blake3::hash(body.delete_token.as_bytes())
        .to_hex()
        .to_string();
    if offered != stored {
        return Err(ApiError(StatusCode::FORBIDDEN, "not available"));
    }

    let _ = st.store.delete(&id).await;
    let db = st.db.lock().await;
    let _ = db.forget(&id);
    info!(%id, "withdrawn by owner");

    Ok(StatusCode::NO_CONTENT)
}

/// Ids are server-generated hex. Rejecting anything else keeps path traversal
/// and odd object keys out of the store entirely.
fn is_valid_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

async fn healthz() -> &'static str {
    "ok"
}

async fn readyz<S: BlobStore>(State(st): State<Shared<S>>) -> Response {
    let db_ok = {
        let db = st.db.lock().await;
        db.ping().is_ok()
    };
    let store_ok = st.store.health().await.is_ok();

    if db_ok && store_ok {
        (StatusCode::OK, "ready").into_response()
    } else {
        // Readiness must fail loudly when a dependency is down, otherwise the
        // pod keeps taking traffic it cannot serve.
        (
            StatusCode::SERVICE_UNAVAILABLE,
            format!("db={db_ok} store={store_ok}"),
        )
            .into_response()
    }
}

async fn metrics<S: BlobStore>(State(st): State<Shared<S>>) -> String {
    let db = st.db.lock().await;
    let (live, consumed, bytes) = db.counts().unwrap_or((0, 0, 0));

    // Counts only. Nothing here can leak content, and nothing is labelled by
    // blob id — a metric with an id in it would turn Prometheus into a log of
    // who received what.
    format!(
        "# HELP sirna_blobs_live Blobs awaiting a reader.\n\
         # TYPE sirna_blobs_live gauge\n\
         sirna_blobs_live {live}\n\
         # HELP sirna_blobs_consumed Blobs read, pending reaping.\n\
         # TYPE sirna_blobs_consumed gauge\n\
         sirna_blobs_consumed {consumed}\n\
         # HELP sirna_bytes_stored Bytes held for unread blobs.\n\
         # TYPE sirna_bytes_stored gauge\n\
         sirna_bytes_stored {bytes}\n"
    )
}
