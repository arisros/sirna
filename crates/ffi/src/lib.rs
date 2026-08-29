//! Kotlin bindings.
//!
//! The Android app is the client with real integrity — you install it once and
//! can check what you installed — so it matters that it runs the same envelope
//! code as everything else rather than a reimplementation. This crate exposes
//! `sirna-core` and adds nothing of its own.
//!
//! Key custody deliberately lives on the Kotlin side, not here. A key held in
//! Android Keystore is never exportable into process memory as raw bytes, so
//! there is nothing for Rust to hold; Kotlin unwraps it and hands the 32 bytes
//! in only for the moment of a seal or an open.

uniffi::setup_scaffolding!();

use sirna_core::{open, open_with_passphrase, seal, seal_with_passphrase, SealOptions, SecretKey};

/// Errors cross the boundary carrying the canonical numeric code, which is the
/// cross-target contract. The message is UI copy and may be translated; the
/// code is what tests assert.
///
/// The field is `detail`, not `message`: uniffi maps this onto a Kotlin
/// exception, and a field called `message` collides with `Throwable.message`,
/// producing bindings that will not compile. The JVM conformance suite caught
/// that before any app code existed, which is what it is for.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum SirnaError {
    #[error("{detail} (code {code})")]
    Failed { code: u8, detail: String },
}

impl From<sirna_core::ErrorCode> for SirnaError {
    fn from(e: sirna_core::ErrorCode) -> Self {
        SirnaError::Failed {
            code: e.code(),
            detail: e.to_string(),
        }
    }
}

// Likewise no `Debug` — `key` is raw key material.
#[derive(uniffi::Record)]
pub struct Sealed {
    pub envelope: Vec<u8>,
    pub mnemonic: String,
    pub uri: String,
    /// The raw key, for the caller to wrap in Keystore immediately and then
    /// forget. It is returned rather than kept here because Rust has nowhere
    /// safe to keep it — the secure element is on the Kotlin side.
    pub key: Vec<u8>,
}

// No `Debug`: this holds decrypted plaintext, and the easiest way to leak a
// secret is an idle `{:?}` in a handler.
#[derive(uniffi::Record)]
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

fn opts(filename: Option<String>, mime: Option<String>, expires_at: u64) -> SealOptions {
    SealOptions {
        filename,
        mime,
        expires_at,
        ..Default::default()
    }
}

/// Seal with a freshly generated key, which is handed back for the caller to
/// place in Keystore.
#[uniffi::export]
pub fn seal_bytes(
    plaintext: Vec<u8>,
    filename: Option<String>,
    mime: Option<String>,
    expires_at: u64,
    now_unix: u64,
) -> Result<Sealed, SirnaError> {
    let mut rng = rand::rngs::OsRng;
    let (envelope, key) = seal(
        &plaintext,
        &opts(filename, mime, expires_at),
        &mut rng,
        now_unix,
    )?;

    Ok(Sealed {
        envelope,
        mnemonic: key.to_mnemonic(),
        uri: key.to_uri(),
        key: key.as_bytes().to_vec(),
    })
}

/// Seal under a key the caller already holds — the custody path, where the key
/// came back out of Keystore for exactly this call.
#[uniffi::export]
pub fn seal_bytes_with_key(
    plaintext: Vec<u8>,
    key: Vec<u8>,
    filename: Option<String>,
    mime: Option<String>,
    expires_at: u64,
    now_unix: u64,
) -> Result<Vec<u8>, SirnaError> {
    let key = key_from_vec(key)?;
    let mut rng = rand::rngs::OsRng;
    Ok(sirna_core::seal_with_key(
        &plaintext,
        &key,
        &opts(filename, mime, expires_at),
        &mut rng,
        now_unix,
    )?)
}

#[uniffi::export]
pub fn seal_bytes_with_passphrase(
    plaintext: Vec<u8>,
    passphrase: String,
    filename: Option<String>,
    mime: Option<String>,
    expires_at: u64,
    now_unix: u64,
) -> Result<Vec<u8>, SirnaError> {
    let mut rng = rand::rngs::OsRng;
    Ok(seal_with_passphrase(
        &plaintext,
        &passphrase,
        &opts(filename, mime, expires_at),
        &mut rng,
        now_unix,
    )?)
}

/// Accepts 24 words or a `sirna1:` URI, so one input handles a pasted phrase
/// and a scanned QR without asking which it is.
#[uniffi::export]
pub fn open_envelope(envelope: Vec<u8>, key: String, now_unix: u64) -> Result<Opened, SirnaError> {
    let key = SecretKey::parse(&key)?;
    Ok(to_opened(open(&envelope, &key, now_unix)?))
}

#[uniffi::export]
pub fn open_envelope_with_key_bytes(
    envelope: Vec<u8>,
    key: Vec<u8>,
    now_unix: u64,
) -> Result<Opened, SirnaError> {
    let key = key_from_vec(key)?;
    Ok(to_opened(open(&envelope, &key, now_unix)?))
}

#[uniffi::export]
pub fn open_envelope_with_passphrase(
    envelope: Vec<u8>,
    passphrase: String,
    now_unix: u64,
) -> Result<Opened, SirnaError> {
    Ok(to_opened(open_with_passphrase(
        &envelope,
        &passphrase,
        now_unix,
    )?))
}

#[uniffi::export]
pub fn key_to_mnemonic(key: Vec<u8>) -> Result<String, SirnaError> {
    Ok(key_from_vec(key)?.to_mnemonic())
}

#[uniffi::export]
pub fn key_to_uri(key: Vec<u8>) -> Result<String, SirnaError> {
    Ok(key_from_vec(key)?.to_uri())
}

#[uniffi::export]
pub fn key_from_text(text: String) -> Result<Vec<u8>, SirnaError> {
    Ok(SecretKey::parse(&text)?.as_bytes().to_vec())
}

#[uniffi::export]
pub fn format_version() -> u8 {
    sirna_core::FORMAT_VERSION
}

fn key_from_vec(v: Vec<u8>) -> Result<SecretKey, SirnaError> {
    let bytes: [u8; 32] = v.try_into().map_err(|_| SirnaError::Failed {
        code: sirna_core::ErrorCode::KeyDecodeFailed.code(),
        detail: "a key must be exactly 32 bytes".into(),
    })?;
    Ok(SecretKey::from_bytes(bytes))
}
