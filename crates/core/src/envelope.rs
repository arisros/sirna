//! Sealing and opening — see `spec/ENVELOPE.md` §5.
//!
//! The nonce and AAD construction is written out by hand rather than inherited
//! from a streaming helper in a dependency. The wire format has to be a property
//! of the spec, not of whichever version of a crate happened to compile.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::error::{ErrorCode, Result};
use crate::header::*;
use crate::key::SecretKey;
use crate::meta::{ContentKind, Meta};

pub const TAG_LEN: usize = 16;
/// Unreachable as a data-chunk index: the maximum chunk count is bounded well
/// below this, so it can safely mark the metadata chunk.
const META_INDEX: u32 = 0xFFFF_FFFF;

/// What the caller wants sealed. Kept separate from `Meta` so the caller never
/// has to think about wire-level fields like `plaintext_len`.
#[derive(Debug, Clone, Default)]
pub struct SealOptions {
    pub filename: Option<String>,
    pub mime: Option<String>,
    pub note: Option<String>,
    /// Unix seconds. `0` means no expiry.
    pub expires_at: u64,
    pub chunk_log2: Option<u8>,
    pub custody: bool,
}

#[derive(Debug, Clone)]
pub struct Opened {
    pub meta: Meta,
    pub plaintext: Vec<u8>,
}

fn nonce_for(stream_nonce: &[u8; 19], index: u32, last: u8) -> [u8; 24] {
    let mut n = [0u8; 24];
    n[0..19].copy_from_slice(stream_nonce);
    n[19..23].copy_from_slice(&index.to_be_bytes());
    n[23] = last;
    n
}

fn aad_for(header_hash: &[u8; 32], index: u32, last: u8) -> [u8; 37] {
    let mut a = [0u8; 37];
    a[0..32].copy_from_slice(header_hash);
    a[32..36].copy_from_slice(&index.to_be_bytes());
    a[36] = last;
    a
}

fn subkeys(key: &SecretKey) -> ([u8; 32], [u8; 32]) {
    // Domain separation costs two lines and leaves room to grant a
    // metadata-only preview later without exposing the payload.
    (
        blake3::derive_key("sirna v1 data key", key.as_bytes()),
        blake3::derive_key("sirna v1 meta key", key.as_bytes()),
    )
}

fn cipher(k: &[u8; 32]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(k.into())
}

/// Seal with a freshly generated key. Returns the envelope and the key — the
/// caller is responsible for getting the key to the reader over a *separate*
/// channel, and for destroying its own copy.
pub fn seal(
    plaintext: &[u8],
    opts: &SealOptions,
    rng: &mut (impl RngCore + CryptoRng),
    now_unix: u64,
) -> Result<(Vec<u8>, SecretKey)> {
    let key = SecretKey::generate(rng);
    let env = seal_inner(plaintext, &key, opts, rng, now_unix, None)?;
    Ok((env, key))
}

/// Seal under a passphrase instead of a random key.
///
/// A fresh salt is generated and stored in the header, so two people who pick
/// the same passphrase still produce different keys. There is no key to hand
/// back — the reader needs the passphrase and nothing else.
///
/// This mode is weaker than the random-key one and the caller should say so in
/// its interface: a passphrase a human invented carries far less entropy than
/// 256 random bits, and Argon2id makes guessing expensive rather than
/// impossible.
pub fn seal_with_passphrase(
    plaintext: &[u8],
    passphrase: &str,
    opts: &SealOptions,
    rng: &mut (impl RngCore + CryptoRng),
    now_unix: u64,
) -> Result<Vec<u8>> {
    let mut salt = [0u8; 16];
    rng.fill_bytes(&mut salt);
    let key = SecretKey::from_passphrase(passphrase, &salt)?;
    seal_inner(plaintext, &key, opts, rng, now_unix, Some(salt))
}

/// Open an envelope that was sealed under a passphrase. The salt comes from the
/// header, which is authenticated, so it cannot be swapped without failing.
pub fn open_with_passphrase(envelope: &[u8], passphrase: &str, now_unix: u64) -> Result<Opened> {
    let header = Header::parse(envelope)?;
    if header.flags & FLAG_PASSPHRASE == 0 {
        // Refusing here is friendlier than letting the derivation run and
        // reporting a generic authentication failure a second later.
        return Err(ErrorCode::KeyDecodeFailed);
    }
    let key = SecretKey::from_passphrase(passphrase, &header.kdf_salt)?;
    open(envelope, &key, now_unix)
}

pub fn seal_with_key(
    plaintext: &[u8],
    key: &SecretKey,
    opts: &SealOptions,
    rng: &mut (impl RngCore + CryptoRng),
    now_unix: u64,
) -> Result<Vec<u8>> {
    seal_inner(plaintext, key, opts, rng, now_unix, None)
}

fn seal_inner(
    plaintext: &[u8],
    key: &SecretKey,
    opts: &SealOptions,
    rng: &mut (impl RngCore + CryptoRng),
    now_unix: u64,
    passphrase_salt: Option<[u8; 16]>,
) -> Result<Vec<u8>> {
    let chunk_log2 = opts.chunk_log2.unwrap_or(CHUNK_LOG2_DEFAULT);
    if !(CHUNK_LOG2_MIN..=CHUNK_LOG2_MAX).contains(&chunk_log2) {
        return Err(ErrorCode::ChunkTooLarge);
    }

    let mut flags = 0u8;
    if opts.filename.is_some() {
        flags |= FLAG_FILE;
    }
    if opts.custody {
        flags |= FLAG_CUSTODY;
    }
    if passphrase_salt.is_some() {
        flags |= FLAG_PASSPHRASE;
    }

    let mut stream_nonce = [0u8; 19];
    rng.fill_bytes(&mut stream_nonce);

    let header = Header {
        flags,
        stream_nonce,
        kdf_salt: passphrase_salt.unwrap_or([0u8; 16]),
        chunk_log2,
    };
    let header_bytes = header.to_bytes();
    let header_hash = header.hash();

    let (k_data, k_meta) = subkeys(key);
    let data_cipher = cipher(&k_data);
    let meta_cipher = cipher(&k_meta);

    let meta = Meta {
        content_kind: if header.is_file() {
            ContentKind::File
        } else {
            ContentKind::Text
        },
        filename: opts.filename.clone(),
        mime: opts.mime.clone(),
        plaintext_len: plaintext.len() as u64,
        created_at: now_unix,
        expires_at: opts.expires_at,
        note: opts.note.clone(),
        owner_pubkey: None,
    };

    let meta_plain = meta.to_cbor()?;
    let meta_ct = meta_cipher
        .encrypt(
            XNonce::from_slice(&nonce_for(&stream_nonce, META_INDEX, 0)),
            Payload {
                msg: &meta_plain,
                aad: &aad_for(&header_hash, META_INDEX, 0),
            },
        )
        .map_err(|_| ErrorCode::AuthFailed)?;

    let chunk_size = header.chunk_size();
    let mut out = Vec::with_capacity(HEADER_LEN + 4 + meta_ct.len() + plaintext.len() + TAG_LEN);
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&(meta_ct.len() as u32).to_le_bytes());
    out.extend_from_slice(&meta_ct);

    // An empty payload is a real case, not an error: it becomes exactly one
    // final chunk carrying zero bytes. Without this branch the loop below would
    // emit nothing and the envelope would decode as `Truncated`.
    if plaintext.is_empty() {
        let ct = data_cipher
            .encrypt(
                XNonce::from_slice(&nonce_for(&stream_nonce, 0, 1)),
                Payload {
                    msg: &[][..],
                    aad: &aad_for(&header_hash, 0, 1),
                },
            )
            .map_err(|_| ErrorCode::AuthFailed)?;
        out.extend_from_slice(&ct);
    } else {
        let total = plaintext.len().div_ceil(chunk_size);
        for (i, chunk) in plaintext.chunks(chunk_size).enumerate() {
            let last = u8::from(i + 1 == total);
            let idx = i as u32;
            let ct = data_cipher
                .encrypt(
                    XNonce::from_slice(&nonce_for(&stream_nonce, idx, last)),
                    Payload {
                        msg: chunk,
                        aad: &aad_for(&header_hash, idx, last),
                    },
                )
                .map_err(|_| ErrorCode::AuthFailed)?;
            out.extend_from_slice(&ct);
        }
    }

    let mut k_data = k_data;
    let mut k_meta = k_meta;
    k_data.zeroize();
    k_meta.zeroize();

    Ok(out)
}

pub fn open(envelope: &[u8], key: &SecretKey, now_unix: u64) -> Result<Opened> {
    let header = Header::parse(envelope)?;
    let header_hash = header.hash();
    let (k_data, k_meta) = subkeys(key);
    let data_cipher = cipher(&k_data);
    let meta_cipher = cipher(&k_meta);

    let mut pos = HEADER_LEN;

    // Metadata length is attacker-controlled, so it is bounds-checked against
    // both the cap and the real buffer before anything is allocated.
    if envelope.len() < pos + 4 {
        return Err(ErrorCode::MalformedHeader);
    }
    let meta_len = u32::from_le_bytes(envelope[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;
    if !(TAG_LEN..=crate::meta::MAX_META_LEN).contains(&meta_len) {
        return Err(ErrorCode::MalformedHeader);
    }
    if envelope.len() < pos + meta_len {
        return Err(ErrorCode::MalformedHeader);
    }

    let meta_plain = meta_cipher
        .decrypt(
            XNonce::from_slice(&nonce_for(&header.stream_nonce, META_INDEX, 0)),
            Payload {
                msg: &envelope[pos..pos + meta_len],
                aad: &aad_for(&header_hash, META_INDEX, 0),
            },
        )
        .map_err(|_| ErrorCode::AuthFailed)?;
    pos += meta_len;

    let meta = Meta::from_cbor(&meta_plain)?;
    meta.check_not_expired(now_unix)?;

    let chunk_size = header.chunk_size();

    // `plaintext_len` comes out of the metadata block, which is encrypted and
    // authenticated — an attacker cannot lie about it without failing the meta
    // tag first. That makes the exact ciphertext length computable rather than
    // guessable, which is what lets truncation and trailing bytes be told apart
    // from corruption. A decoder that guesses chunk boundaries by length cannot
    // distinguish "bytes appended to the final chunk" from "final chunk
    // damaged", because the final chunk is short by nature.
    let plaintext_len = usize::try_from(meta.plaintext_len).map_err(|_| ErrorCode::Truncated)?;
    let chunk_count = if plaintext_len == 0 {
        1 // an empty payload is one final chunk carrying zero bytes
    } else {
        plaintext_len.div_ceil(chunk_size)
    };
    let expected_data = plaintext_len
        .checked_add(
            chunk_count
                .checked_mul(TAG_LEN)
                .ok_or(ErrorCode::Truncated)?,
        )
        .ok_or(ErrorCode::Truncated)?;
    let expected_total = pos.checked_add(expected_data).ok_or(ErrorCode::Truncated)?;

    match envelope.len().cmp(&expected_total) {
        core::cmp::Ordering::Less => return Err(ErrorCode::Truncated),
        core::cmp::Ordering::Greater => return Err(ErrorCode::TrailingData),
        core::cmp::Ordering::Equal => {}
    }

    let mut plaintext = Vec::with_capacity(plaintext_len);
    let mut remaining = plaintext_len;

    for index in 0..chunk_count {
        let this_pt = if index + 1 == chunk_count {
            remaining
        } else {
            chunk_size
        };
        let take = this_pt + TAG_LEN;
        let last = u8::from(index + 1 == chunk_count);
        let idx = u32::try_from(index).map_err(|_| ErrorCode::MalformedHeader)?;

        let pt = data_cipher
            .decrypt(
                XNonce::from_slice(&nonce_for(&header.stream_nonce, idx, last)),
                Payload {
                    msg: &envelope[pos..pos + take],
                    aad: &aad_for(&header_hash, idx, last),
                },
            )
            .map_err(|_| ErrorCode::AuthFailed)?;

        plaintext.extend_from_slice(&pt);
        pos += take;
        remaining -= this_pt;
    }

    let mut k_data = k_data;
    let mut k_meta = k_meta;
    k_data.zeroize();
    k_meta.zeroize();

    Ok(Opened { meta, plaintext })
}
