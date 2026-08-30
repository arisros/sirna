//! Server integration tests, run entirely against `FsStore`.
//!
//! No S3, no Garage, no network. The store abstraction exists mostly so this
//! file can be honest without infrastructure.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sirna_core::{seal, SealOptions};
use sirna_server::{
    api::{router, AppState},
    db::Db,
    limit::RateLimiter,
    store::FsStore,
};
use tower::ServiceExt;

struct Harness {
    app: axum::Router,
    _tmp: tempfile::TempDir,
}

fn harness() -> Harness {
    let tmp = tempfile::tempdir().unwrap();
    let db = Db::open(tmp.path().join("meta.db").to_str().unwrap()).unwrap();
    let store = FsStore::new(tmp.path().join("blobs")).unwrap();

    let state = Arc::new(AppState {
        db: tokio::sync::Mutex::new(db),
        store,
        // Generous, so the limiter does not interfere with tests that are not
        // about the limiter.
        limiter: RateLimiter::new(10_000, 10_000.0),
        relay: sirna_server::rendezvous::Relay::new(),
        max_blob_bytes: 1024 * 1024,
        default_ttl: 3600,
        max_ttl: 86_400,
    });

    Harness {
        app: router(state),
        _tmp: tmp,
    }
}

fn envelope(text: &[u8]) -> Vec<u8> {
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let (env, _key) = seal(text, &SealOptions::default(), &mut rng, 1_800_000_000).unwrap();
    env
}

/// `oneshot` bypasses the layer that normally injects `ConnectInfo`, so tests
/// add it by hand rather than weakening the handler signature.
fn with_peer(mut req: Request<Body>) -> Request<Body> {
    req.extensions_mut().insert(axum::extract::ConnectInfo(
        "203.0.113.10:40000"
            .parse::<std::net::SocketAddr>()
            .unwrap(),
    ));
    req
}

async fn send(app: &axum::Router, req: Request<Body>) -> (StatusCode, Vec<u8>) {
    let res = app.clone().oneshot(with_peer(req)).await.unwrap();
    let status = res.status();
    let body = res.into_body().collect().await.unwrap().to_bytes().to_vec();
    (status, body)
}

fn post(body: Vec<u8>) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/v1/blobs")
        .header("x-forwarded-for", "203.0.113.10")
        .body(Body::from(body))
        .unwrap()
}

fn get(id: &str) -> Request<Body> {
    Request::builder()
        .uri(format!("/api/v1/blobs/{id}"))
        .header("x-forwarded-for", "203.0.113.10")
        .body(Body::empty())
        .unwrap()
}

async fn upload(app: &axum::Router, body: Vec<u8>) -> (String, String) {
    let (status, out) = send(app, post(body)).await;
    assert_eq!(status, StatusCode::OK, "upload failed");
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    (
        v["id"].as_str().unwrap().to_string(),
        v["delete_token"].as_str().unwrap().to_string(),
    )
}

#[tokio::test]
async fn upload_then_read_once() {
    let h = harness();
    let env = envelope(b"hello");
    let (id, _) = upload(&h.app, env.clone()).await;

    let (status, body) = send(&h.app, get(&id)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, env, "the server must return the bytes it was given");

    let (status, _) = send(&h.app, get(&id)).await;
    assert_eq!(status, StatusCode::GONE, "a second read must be refused");
}

#[tokio::test]
async fn stored_bytes_are_opaque_to_the_server() {
    // The whole premise: what the server holds must not contain the plaintext.
    let h = harness();
    let secret = b"the treasure is buried under the third oak";
    let env = envelope(secret);
    let (id, _) = upload(&h.app, env).await;

    let (_, delivered) = send(&h.app, get(&id)).await;
    assert!(
        !delivered.windows(secret.len()).any(|w| w == secret),
        "plaintext appears in what the server stored and returned"
    );
}

#[tokio::test]
async fn unknown_and_consumed_ids_are_indistinguishable() {
    // The endpoint must not confirm whether a given id ever existed.
    let h = harness();
    let (id, _) = upload(&h.app, envelope(b"x")).await;
    let (_, _) = send(&h.app, get(&id)).await;

    let (consumed, _) = send(&h.app, get(&id)).await;
    let (never, _) = send(&h.app, get(&"a".repeat(32))).await;
    assert_eq!(consumed, never);
}

#[tokio::test]
async fn only_one_of_many_concurrent_readers_wins() {
    let h = harness();
    let env = envelope(b"contended");
    let (id, _) = upload(&h.app, env).await;

    let mut tasks = Vec::new();
    for _ in 0..50 {
        let app = h.app.clone();
        let id = id.clone();
        tasks.push(tokio::spawn(async move {
            app.oneshot(with_peer(get(&id))).await.unwrap().status()
        }));
    }

    let mut ok = 0;
    let mut gone = 0;
    for t in tasks {
        match t.await.unwrap() {
            StatusCode::OK => ok += 1,
            StatusCode::GONE => gone += 1,
            other => panic!("unexpected status {other}"),
        }
    }

    assert_eq!(ok, 1, "exactly one reader may win");
    assert_eq!(gone, 49);
}

#[tokio::test]
async fn junk_is_rejected_before_it_reaches_the_store() {
    let h = harness();
    let (status, _) = send(&h.app, post(b"this is not an envelope".to_vec())).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn oversized_uploads_are_refused() {
    // OTM has no body limit anywhere, so a single large POST can drive the pod
    // into its memory limit. This asserts that Sirna does.
    let h = harness();
    let huge = vec![0u8; 2 * 1024 * 1024];
    let (status, _) = send(&h.app, post(huge)).await;
    assert!(
        status == StatusCode::PAYLOAD_TOO_LARGE || status == StatusCode::BAD_REQUEST,
        "oversized upload was accepted with {status}"
    );
}

#[tokio::test]
async fn malformed_ids_are_refused() {
    let h = harness();
    for bad in ["../../etc/passwd", "short", &"z".repeat(32)] {
        let (status, _) = send(&h.app, get(bad)).await;
        assert!(
            status == StatusCode::GONE || status == StatusCode::NOT_FOUND,
            "id {bad:?} produced {status}"
        );
    }
}

#[tokio::test]
async fn owner_can_withdraw_before_it_is_read() {
    let h = harness();
    let (id, token) = upload(&h.app, envelope(b"recall me")).await;

    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/blobs/{id}"))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "delete_token": token }).to_string(),
        ))
        .unwrap();
    let (status, _) = send(&h.app, req).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = send(&h.app, get(&id)).await;
    assert_eq!(status, StatusCode::GONE);
}

#[tokio::test]
async fn a_wrong_delete_token_does_nothing() {
    let h = harness();
    let (id, _) = upload(&h.app, envelope(b"safe")).await;

    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/blobs/{id}"))
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"delete_token":"00000000000000000000000000000000"}"#,
        ))
        .unwrap();
    let (status, _) = send(&h.app, req).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = send(&h.app, get(&id)).await;
    assert_eq!(status, StatusCode::OK, "the blob must survive a bad token");
}

#[tokio::test]
async fn probes_and_metrics_report_without_leaking() {
    let h = harness();
    let secret = b"metrics must not contain this";
    let (id, _) = upload(&h.app, envelope(secret)).await;

    let (status, _) = send(
        &h.app,
        Request::builder()
            .uri("/healthz")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = send(
        &h.app,
        Request::builder()
            .uri("/readyz")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = send(
        &h.app,
        Request::builder()
            .uri("/metrics")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let text = String::from_utf8(body).unwrap();

    assert!(text.contains("sirna_blobs_live 1"));
    // A metric labelled by blob id would turn Prometheus into a record of who
    // received what.
    assert!(!text.contains(&id), "metrics must not carry blob ids");
    assert!(!text.contains("treasure"));
}

#[tokio::test]
async fn the_browser_client_is_served_and_locked_down() {
    let h = harness();

    let (status, body) = send(
        &h.app,
        Request::builder().uri("/").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(String::from_utf8_lossy(&body).contains("<html"));

    // /m/<id> is a client-side route and must return the app, not a 404.
    let res = h
        .app
        .clone()
        .oneshot(with_peer(
            Request::builder()
                .uri(format!("/m/{}", "a".repeat(32)))
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let csp = res
        .headers()
        .get("content-security-policy")
        .expect("every page must carry a CSP")
        .to_str()
        .unwrap()
        .to_string();

    // In a page that handles keys, any external origin is an exfiltration
    // channel. There must be none, and the policy must not permit inline
    // script either.
    assert!(csp.contains("default-src 'none'"));
    assert!(csp.contains("connect-src 'self'"));
    assert!(!csp.contains("unsafe-inline"));
    assert!(
        !csp.contains("http://") && !csp.contains("https://"),
        "CSP names an external origin: {csp}"
    );
}

#[tokio::test]
async fn a_malformed_api_path_does_not_return_the_web_app() {
    // Answering a bad API call with HTML and a 200 hides typos and confuses
    // clients.
    let h = harness();
    let (status, _) = send(
        &h.app,
        Request::builder()
            .uri("/api/v1/nonsense")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_failed_delivery_still_burns_the_message() {
    // The strictest reading of one-time: a blob is spent the moment it is
    // claimed, whatever happens to the transfer afterwards. An earlier version
    // handed the claim back on a storage error so a reader with a dropped
    // connection was not left with nothing — kinder, but it meant a blob could
    // be served twice, and "once" is the whole promise.
    let tmp = tempfile::tempdir().unwrap();
    let blobs = tmp.path().join("blobs");
    let db = Db::open(tmp.path().join("meta.db").to_str().unwrap()).unwrap();
    let store = FsStore::new(&blobs).unwrap();

    let state = Arc::new(AppState {
        db: tokio::sync::Mutex::new(db),
        store,
        limiter: RateLimiter::new(10_000, 10_000.0),
        relay: sirna_server::rendezvous::Relay::new(),
        max_blob_bytes: 1024 * 1024,
        default_ttl: 3600,
        max_ttl: 86_400,
    });
    let app = router(state);

    let (status, out) = send(&app, post(envelope(b"only once"))).await;
    assert_eq!(status, StatusCode::OK);
    let id = serde_json::from_slice::<serde_json::Value>(&out).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Simulate the object going missing between the claim and the read.
    std::fs::remove_file(blobs.join(&id)).unwrap();

    let (status, _) = send(&app, get(&id)).await;
    assert_eq!(
        status,
        StatusCode::BAD_GATEWAY,
        "delivery should have failed"
    );

    // Even though nobody ever received it, it is spent.
    let (status, _) = send(&app, get(&id)).await;
    assert_eq!(
        status,
        StatusCode::GONE,
        "a failed delivery must not hand the message back"
    );
}

#[tokio::test]
async fn assets_are_reachable_from_the_deep_route_too() {
    // This is the test that was missing when a relative `./app.js` shipped.
    // The app is served from two URL shapes, / and /m/<id>, and a reference
    // that resolves under one and not the other produces a page that looks
    // present but is inert. Asserting the page loads is not enough — the
    // assets it names have to load from where the browser will ask for them.
    let h = harness();

    for path in ["/style.css", "/app.js", "/sirna_wasm.js"] {
        let res = h
            .app
            .clone()
            .oneshot(with_peer(
                Request::builder().uri(path).body(Body::empty()).unwrap(),
            ))
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK, "{path} is not served");
        let ct = res
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(
            !ct.starts_with("text/html"),
            "{path} came back as HTML — the fallback is masking a missing asset"
        );
    }
}

#[tokio::test]
async fn a_missing_asset_is_a_404_not_the_app() {
    // A fallback that answers every unknown path with index.html turns a broken
    // asset reference into a 200, and the browser only notices when the HTML
    // fails to parse as JavaScript. Anything that looks like a file must 404.
    let h = harness();

    for path in [
        "/m/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/app.js",
        "/m/style.css",
        "/nope.js",
    ] {
        let (status, _) = send(
            &h.app,
            Request::builder().uri(path).body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path} should be a 404");
    }
}

#[tokio::test]
async fn the_html_references_only_root_absolute_assets() {
    // Relative asset paths are correct at / and wrong at /m/<id>. Catch them in
    // the markup rather than waiting to notice a blank page on a phone.
    let h = harness();
    let (_, body) = send(
        &h.app,
        Request::builder().uri("/").body(Body::empty()).unwrap(),
    )
    .await;
    let html = String::from_utf8_lossy(&body);

    assert!(
        !html.contains("=\"./"),
        "index.html contains a relative asset path, which breaks under /m/<id>"
    );
}
