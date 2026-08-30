//! Serving the browser client.
//!
//! The assets are embedded in the binary, so there is one container and no
//! sidecar, and the security headers are set in one place in code instead of
//! being spread across a web server configuration nobody reads.

use axum::{
    http::{header, StatusCode, Uri},
    response::{IntoResponse, Response},
};

#[derive(rust_embed::Embed)]
#[folder = "../../web/"]
struct Assets;

/// No third-party origin appears anywhere. In a page that handles keys, every
/// external origin is an exfiltration channel — so there are no font CDNs, no
/// analytics, and no error reporters, and the policy says so rather than
/// relying on nobody adding one later.
const CSP: &str = "default-src 'none'; \
     script-src 'self' 'wasm-unsafe-eval'; \
     connect-src 'self'; \
     img-src 'self' data:; \
     style-src 'self'; \
     font-src 'self'; \
     form-action 'none'; \
     frame-ancestors 'none'; \
     base-uri 'none'";

pub async fn serve(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');

    // Anything under /api that reached the fallback is a malformed API call,
    // not a page. Serving the single-page app there would answer a bad request
    // with HTML and a 200, which is a confusing thing to hand a client — and it
    // would quietly hide typos in the API surface.
    if path.starts_with("api/") {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }

    let known = Assets::iter().any(|f| f == path);

    // /m/<id> is a client-side route and must return the app. But a path that
    // looks like a file must NOT: answering a missing asset with index.html and
    // a 200 turns a broken reference into something that looks like it worked,
    // and the browser only discovers it when the HTML fails to parse as
    // JavaScript. That is exactly how a relative `./app.js` under /m/<id>
    // shipped unnoticed.
    let looks_like_a_file = path
        .rsplit('/')
        .next()
        .is_some_and(|last| last.contains('.'));

    if !known && looks_like_a_file {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }

    let file = if known { path } else { "index.html" };

    let Some(asset) = Assets::get(file) else {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    };

    let mime = mime_guess::from_path(file).first_or_octet_stream();

    // The wasm and its glue are content-addressed only by build, so they are
    // not cached hard; the app is small and correctness beats a round trip.
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, mime.as_ref()),
            (header::CONTENT_SECURITY_POLICY, CSP),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::REFERRER_POLICY, "no-referrer"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        asset.data,
    )
        .into_response()
}
