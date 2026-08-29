//! The encrypted metadata block — see `spec/ENVELOPE.md` §6.
//!
//! Everything a storage layer might find interesting lives here, behind the
//! same AEAD as the payload: filename, MIME type, true length, expiry. The
//! server sees none of it.

use serde::{Deserialize, Serialize};

use crate::error::{ErrorCode, Result};

/// Metadata is capped so the parser's appetite stays bounded on
/// attacker-controlled input. Metadata is small by nature.
pub const MAX_META_LEN: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ContentKind {
    Text = 0,
    File = 1,
}

/// CBOR map with integer keys. Integer keys keep the block small; CBOR keeps it
/// self-describing, so optional fields can be added later without a version
/// bump.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meta {
    #[serde(rename = "1")]
    pub content_kind: ContentKind,
    #[serde(rename = "2", skip_serializing_if = "Option::is_none", default)]
    pub filename: Option<String>,
    #[serde(rename = "3", skip_serializing_if = "Option::is_none", default)]
    pub mime: Option<String>,
    #[serde(rename = "4")]
    pub plaintext_len: u64,
    #[serde(rename = "5")]
    pub created_at: u64,
    #[serde(rename = "6")]
    pub expires_at: u64,
    #[serde(rename = "7", skip_serializing_if = "Option::is_none", default)]
    pub note: Option<String>,
    #[serde(rename = "8", skip_serializing_if = "Option::is_none", default)]
    pub owner_pubkey: Option<[u8; 32]>,
}

impl Meta {
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|_| ErrorCode::MetaDecodeFailed)?;
        if buf.len() > MAX_META_LEN {
            return Err(ErrorCode::MetaDecodeFailed);
        }
        Ok(buf)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        ciborium::from_reader(bytes).map_err(|_| ErrorCode::MetaDecodeFailed)
    }

    /// Expiry is enforced from *this* copy, which lives inside the authenticated
    /// envelope — not from the server's database. A client must refuse an
    /// expired message even when the server hands it over. Server-side expiry
    /// is a courtesy; this one can be reasoned about.
    ///
    /// `now_unix` is a parameter rather than a call to the system clock so that
    /// this is testable and so that `core` stays usable under wasm32, which has
    /// no `SystemTime`.
    pub fn check_not_expired(&self, now_unix: u64) -> Result<()> {
        if self.expires_at != 0 && now_unix > self.expires_at {
            return Err(ErrorCode::Expired);
        }
        Ok(())
    }
}
