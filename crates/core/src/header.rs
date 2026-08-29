//! The 44-byte envelope header — see `spec/ENVELOPE.md` §3.1.
//!
//! The header is the entire remote attack surface: it is the only part a server
//! or a reader parses before any key is involved, and it consumes
//! attacker-controlled bytes. Everything here validates before it allocates.

use crate::error::{ErrorCode, Result};

pub const MAGIC: [u8; 4] = *b"SRNA";
pub const VERSION: u8 = 1;
pub const SUITE_XCHACHA_STREAM_BLAKE3: u8 = 1;
pub const HEADER_LEN: usize = 44;

pub const FLAG_FILE: u8 = 1 << 0;
pub const FLAG_PASSPHRASE: u8 = 1 << 1;
pub const FLAG_CUSTODY: u8 = 1 << 2;
pub const FLAG_PADDED: u8 = 1 << 3;
const FLAG_KNOWN_MASK: u8 = 0b0000_1111;

/// Bounds from spec §10. Below 1 KiB the 16-byte tag per chunk starts to
/// dominate; above 16 MiB a single chunk stops fitting comfortably in a mobile
/// heap.
pub const CHUNK_LOG2_MIN: u8 = 10;
pub const CHUNK_LOG2_MAX: u8 = 24;
pub const CHUNK_LOG2_DEFAULT: u8 = 16; // 64 KiB

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub flags: u8,
    pub stream_nonce: [u8; 19],
    pub kdf_salt: [u8; 16],
    pub chunk_log2: u8,
}

impl Header {
    pub fn chunk_size(&self) -> usize {
        1usize << self.chunk_log2
    }

    pub fn is_file(&self) -> bool {
        self.flags & FLAG_FILE != 0
    }

    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..4].copy_from_slice(&MAGIC);
        out[4] = VERSION;
        out[5] = SUITE_XCHACHA_STREAM_BLAKE3;
        out[6] = self.flags;
        out[7] = 0; // reserved
        out[8..27].copy_from_slice(&self.stream_nonce);
        out[27..43].copy_from_slice(&self.kdf_salt);
        out[43] = self.chunk_log2;
        out
    }

    /// Parse and fully validate. Ordering matters: the most specific rejection
    /// wins, so a caller can tell "this is not our file" apart from "this is
    /// our file but from a newer version".
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < HEADER_LEN {
            return Err(ErrorCode::MalformedHeader);
        }
        if buf[0..4] != MAGIC {
            return Err(ErrorCode::BadMagic);
        }
        if buf[4] != VERSION {
            return Err(ErrorCode::UnsupportedVersion);
        }
        if buf[5] != SUITE_XCHACHA_STREAM_BLAKE3 {
            return Err(ErrorCode::UnsupportedSuite);
        }

        let flags = buf[6];
        // Unknown flag bits mean the writer used a feature we do not implement.
        // Ignoring them would risk decoding the payload incorrectly and calling
        // it success, which is worse than refusing.
        if flags & !FLAG_KNOWN_MASK != 0 {
            return Err(ErrorCode::MalformedHeader);
        }
        if buf[7] != 0 {
            return Err(ErrorCode::MalformedHeader);
        }

        let chunk_log2 = buf[43];
        if !(CHUNK_LOG2_MIN..=CHUNK_LOG2_MAX).contains(&chunk_log2) {
            return Err(ErrorCode::ChunkTooLarge);
        }

        let mut stream_nonce = [0u8; 19];
        stream_nonce.copy_from_slice(&buf[8..27]);
        let mut kdf_salt = [0u8; 16];
        kdf_salt.copy_from_slice(&buf[27..43]);

        Ok(Self {
            flags,
            stream_nonce,
            kdf_salt,
            chunk_log2,
        })
    }

    /// BLAKE3 of the serialized header. Folded into every chunk's AAD, which is
    /// what authenticates the header without needing a separate MAC over it.
    pub fn hash(&self) -> [u8; 32] {
        *blake3::hash(&self.to_bytes()).as_bytes()
    }
}
