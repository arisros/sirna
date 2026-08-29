//! Browser bindings.
//!
//! A thin translation layer and nothing more. Every cryptographic decision
//! lives in `sirna-core`, so the browser runs exactly the same code as the CLI
//! and the phone — which is the entire reason for a shared Rust core rather
//! than a JavaScript reimplementation that would drift within a month.
//!
//! Worth stating plainly, because it is widely misunderstood: **WASM is not a
//! security boundary in a browser.** JavaScript on the same page can read this
//! module's linear memory. Keys are not hidden here and this file does not
//! pretend otherwise. What WASM buys is a single implementation across targets,
//! XChaCha20-Poly1305 which WebCrypto does not provide, and explicit zeroing.
//! See `docs/THREAT-MODEL.md` §3.

use wasm_bindgen::prelude::*;

use sirna_core::{open, open_with_passphrase, seal, seal_with_passphrase, SealOptions, SecretKey};

/// Map a core error onto a JS error carrying the canonical numeric code.
///
/// The code is the cross-target contract, so it travels with the message
/// rather than being flattened into prose that only reads well in English.
fn js_err(e: sirna_core::ErrorCode) -> JsValue {
    let obj = js_sys::Object::new();
    let _ = js_sys::Reflect::set(&obj, &"code".into(), &JsValue::from(e.code()));
    let _ = js_sys::Reflect::set(&obj, &"message".into(), &JsValue::from(e.to_string()));
    obj.into()
}

/// What `sealText`/`sealFile` hand back: the envelope, and the key in both
/// encodings so the UI can show words and a QR without deriving either itself.
#[wasm_bindgen(getter_with_clone)]
pub struct Sealed {
    pub envelope: Vec<u8>,
    pub mnemonic: String,
    pub uri: String,
}

#[wasm_bindgen(getter_with_clone)]
pub struct Opened {
    pub plaintext: Vec<u8>,
    pub filename: Option<String>,
    pub mime: Option<String>,
    pub note: Option<String>,
    pub is_file: bool,
    pub expires_at: u64,
}

fn to_opened(o: sirna_core::Opened) -> Opened {
    Opened {
        is_file: matches!(o.meta.content_kind, sirna_core::ContentKind::File),
        filename: o.meta.filename,
        mime: o.meta.mime,
        note: o.meta.note,
        expires_at: o.meta.expires_at,
        plaintext: o.plaintext,
    }
}

/// The clock is a parameter, not a call to `Date.now()` inside the core.
/// wasm32 has no `SystemTime`, and keeping time at the edge is what lets the
/// same code be tested deterministically.
fn opts(filename: Option<String>, mime: Option<String>, expires_at: u64) -> SealOptions {
    SealOptions {
        filename,
        mime,
        expires_at,
        ..Default::default()
    }
}

#[wasm_bindgen(js_name = sealBytes)]
pub fn seal_bytes(
    plaintext: &[u8],
    filename: Option<String>,
    mime: Option<String>,
    expires_at: u64,
    now_unix: u64,
) -> Result<Sealed, JsValue> {
    let mut rng = rand::rngs::OsRng;
    let (envelope, key) = seal(
        plaintext,
        &opts(filename, mime, expires_at),
        &mut rng,
        now_unix,
    )
    .map_err(js_err)?;

    Ok(Sealed {
        envelope,
        mnemonic: key.to_mnemonic(),
        uri: key.to_uri(),
    })
}

#[wasm_bindgen(js_name = sealBytesWithPassphrase)]
pub fn seal_bytes_with_passphrase(
    plaintext: &[u8],
    passphrase: &str,
    filename: Option<String>,
    mime: Option<String>,
    expires_at: u64,
    now_unix: u64,
) -> Result<Vec<u8>, JsValue> {
    let mut rng = rand::rngs::OsRng;
    seal_with_passphrase(
        plaintext,
        passphrase,
        &opts(filename, mime, expires_at),
        &mut rng,
        now_unix,
    )
    .map_err(js_err)
}

/// Accepts 24 words or a `sirna1:` URI, so one input box handles a pasted
/// phrase and a scanned QR without asking the user which they have.
#[wasm_bindgen(js_name = openEnvelope)]
pub fn open_envelope(envelope: &[u8], key: &str, now_unix: u64) -> Result<Opened, JsValue> {
    let key = SecretKey::parse(key).map_err(js_err)?;
    open(envelope, &key, now_unix)
        .map(to_opened)
        .map_err(js_err)
}

#[wasm_bindgen(js_name = openEnvelopeWithPassphrase)]
pub fn open_envelope_with_passphrase(
    envelope: &[u8],
    passphrase: &str,
    now_unix: u64,
) -> Result<Opened, JsValue> {
    open_with_passphrase(envelope, passphrase, now_unix)
        .map(to_opened)
        .map_err(js_err)
}

/// Reject junk before uploading it, and before asking the user for a key they
/// would only waste on a file that is not ours.
#[wasm_bindgen(js_name = inspect)]
pub fn inspect(envelope: &[u8]) -> Result<JsValue, JsValue> {
    let h = sirna_core::Header::parse(envelope).map_err(js_err)?;
    let obj = js_sys::Object::new();
    let _ = js_sys::Reflect::set(
        &obj,
        &"chunkSize".into(),
        &JsValue::from(h.chunk_size() as u32),
    );
    let _ = js_sys::Reflect::set(&obj, &"isFile".into(), &JsValue::from(h.is_file()));
    let _ = js_sys::Reflect::set(
        &obj,
        &"isPassphrase".into(),
        &JsValue::from(h.flags & sirna_core::header::FLAG_PASSPHRASE != 0),
    );
    Ok(obj.into())
}

#[wasm_bindgen(js_name = formatVersion)]
pub fn format_version() -> u8 {
    sirna_core::FORMAT_VERSION
}
