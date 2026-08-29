//! The message key, plus its two human-facing encodings.
//!
//! The most common real-world key leak is not a broken cipher, it is an
//! accidental log line. `SecretKey` therefore has no derived `Debug`, no
//! `Display`, and no `Serialize` — printing one has to be a deliberate act.

use base64::Engine as _;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{ErrorCode, Result};

pub const KEY_LEN: usize = 32;

/// Argon2id parameters, fixed by the format — see `spec/ENVELOPE.md` §2.
///
/// 64 MiB is the largest memory cost that reliably survives mobile Safari and
/// low-end Android without being OOM-killed. Raising it would lock out the
/// devices this is meant to run on.
pub const ARGON2_M_COST: u32 = 65_536; // KiB
pub const ARGON2_T_COST: u32 = 3;
pub const ARGON2_P_COST: u32 = 1;

const URI_PREFIX: &str = "sirna1:";
const URI_VERSION: u8 = 1;

/// A 256-bit message key. Zeroized on drop.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; KEY_LEN]);

// Deliberately opaque: a stray `{:?}` in a handler must not print key material.
impl core::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

impl SecretKey {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn generate(rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng)) -> Self {
        let mut k = [0u8; KEY_LEN];
        rng.fill_bytes(&mut k);
        Self(k)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Derive a key from a passphrase and the envelope's salt.
    ///
    /// The salt lives in the header in the clear, which is fine — a salt is not
    /// a secret, it exists so that two people who choose the same passphrase do
    /// not produce the same key.
    ///
    /// Worth being blunt about: a passphrase a human invented has far less
    /// entropy than the 256 random bits used elsewhere. Argon2id makes guessing
    /// expensive, not impossible. This mode exists for cases where handing over
    /// 24 words is impractical, and it is weaker.
    pub fn from_passphrase(passphrase: &str, salt: &[u8; 16]) -> Result<Self> {
        let params =
            argon2::Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(KEY_LEN))
                .map_err(|_| ErrorCode::KeyDecodeFailed)?;

        let argon =
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        let mut out = [0u8; KEY_LEN];
        argon
            .hash_password_into(passphrase.as_bytes(), salt, &mut out)
            .map_err(|_| ErrorCode::KeyDecodeFailed)?;
        Ok(Self(out))
    }

    /// BIP-39, 24 words, English. The wordlist checksum catches transcription
    /// errors before any decrypt is attempted, so a mistyped word reports
    /// `ChecksumFailed` instead of `AuthFailed` — a very different thing to
    /// show a human.
    pub fn to_mnemonic(&self) -> String {
        bip39::Mnemonic::from_entropy(&self.0)
            .expect("32 bytes of entropy is always a valid 24-word mnemonic")
            .to_string()
    }

    pub fn from_mnemonic(phrase: &str) -> Result<Self> {
        let m = bip39::Mnemonic::parse_normalized(phrase.trim()).map_err(|e| match e {
            bip39::Error::InvalidChecksum => ErrorCode::ChecksumFailed,
            _ => ErrorCode::KeyDecodeFailed,
        })?;
        let (entropy, len) = m.to_entropy_array();
        if len != KEY_LEN {
            return Err(ErrorCode::KeyDecodeFailed);
        }
        let mut k = [0u8; KEY_LEN];
        k.copy_from_slice(&entropy[..KEY_LEN]);
        Ok(Self(k))
    }

    /// Compact URI for QR codes: `sirna1:<base64url(version ‖ key ‖ crc16)>`.
    /// Roughly 50 characters, which keeps QR density low enough to scan from
    /// across a room.
    pub fn to_uri(&self) -> String {
        let mut payload = Vec::with_capacity(1 + KEY_LEN + 2);
        payload.push(URI_VERSION);
        payload.extend_from_slice(&self.0);
        let crc = crc16_ccitt(&payload);
        payload.extend_from_slice(&crc.to_be_bytes());

        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&payload);
        payload.zeroize();
        format!("{URI_PREFIX}{encoded}")
    }

    pub fn from_uri(uri: &str) -> Result<Self> {
        let body = uri
            .trim()
            .strip_prefix(URI_PREFIX)
            .ok_or(ErrorCode::KeyDecodeFailed)?;

        let mut raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| ErrorCode::KeyDecodeFailed)?;

        if raw.len() != 1 + KEY_LEN + 2 {
            raw.zeroize();
            return Err(ErrorCode::KeyDecodeFailed);
        }
        if raw[0] != URI_VERSION {
            raw.zeroize();
            return Err(ErrorCode::KeyDecodeFailed);
        }

        let expected = u16::from_be_bytes([raw[1 + KEY_LEN], raw[2 + KEY_LEN]]);
        let actual = crc16_ccitt(&raw[..1 + KEY_LEN]);
        // A CRC guards against a misread QR, not against an attacker, so a
        // constant-time compare would be theatre here.
        if expected != actual {
            raw.zeroize();
            return Err(ErrorCode::ChecksumFailed);
        }

        let mut k = [0u8; KEY_LEN];
        k.copy_from_slice(&raw[1..1 + KEY_LEN]);
        raw.zeroize();
        Ok(Self(k))
    }

    /// Accepts either encoding, so a single input box can take a pasted
    /// mnemonic or a scanned QR without asking the user which is which.
    pub fn parse(input: &str) -> Result<Self> {
        let t = input.trim();
        if t.starts_with(URI_PREFIX) {
            Self::from_uri(t)
        } else {
            Self::from_mnemonic(t)
        }
    }
}

/// CRC-16/CCITT-FALSE. Small enough that pulling in a dependency would cost
/// more than it saves.
fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}
