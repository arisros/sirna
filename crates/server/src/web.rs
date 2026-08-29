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

    // /m/<id> is a client-side route, so it has to return the app rather than
    // a 404. Anything else unknown falls through to the app too — there is no
    // meaningful 404 page for a single-view client.
    let file = if path.is_empty() || !Assets::iter().any(|f| f == path) {
        "index.html"
    } else {
        path
    };

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
