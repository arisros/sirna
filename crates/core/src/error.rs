//! Canonical error codes, shared by every binding.
//!
//! Test vectors assert the numeric code, never the message. Without that, "wrong
//! key" and "corrupt file" end up telling three different stories on three
//! platforms, and a user who mistyped one word gets told their file is damaged.

use core::fmt;

/// Every way an envelope can be rejected. The discriminants are part of the
/// format contract — see `spec/ENVELOPE.md` §9 — so they must never be
/// reordered or reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ErrorCode {
    BadMagic = 1,
    UnsupportedVersion = 2,
    UnsupportedSuite = 3,
    MalformedHeader = 4,
    AuthFailed = 5,
    Truncated = 6,
    TrailingData = 7,
    MetaDecodeFailed = 8,
    Expired = 9,
    ChunkTooLarge = 10,
    KeyDecodeFailed = 11,
    ChecksumFailed = 12,
}

impl ErrorCode {
    pub fn code(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Wording aimed at a human, not a log parser. The numeric code is the
        // machine-readable half.
        let s = match self {
            Self::BadMagic => "not a Sirna envelope",
            Self::UnsupportedVersion => "envelope version is not supported",
            Self::UnsupportedSuite => "cipher suite is not supported",
            Self::MalformedHeader => "envelope header is malformed",
            Self::AuthFailed => "wrong key, or the envelope has been altered",
            Self::Truncated => "envelope is incomplete — data is missing from the end",
            Self::TrailingData => "unexpected data after the end of the envelope",
            Self::MetaDecodeFailed => "metadata could not be decoded",
            Self::Expired => "this message has expired",
            Self::ChunkTooLarge => "chunk size is out of range",
            Self::KeyDecodeFailed => "key is not well-formed",
            Self::ChecksumFailed => "key checksum does not match — likely a typo",
        };
        f.write_str(s)
    }
}

impl std::error::Error for ErrorCode {}

pub type Result<T> = core::result::Result<T, ErrorCode>;
