//! Sirna envelope format.
//!
//! This crate is deliberately inert: no I/O, no network, and no clock. Current
//! time arrives as a `now_unix: u64` parameter and randomness arrives as an
//! injected `RngCore + CryptoRng`.
//!
//! That is not purity for its own sake. Two concrete things depend on it:
//! wasm32 has no `SystemTime`, and byte-exact cross-target test vectors are
//! impossible without a seedable RNG — and those vectors are the only thing
//! stopping the CLI, the web client and the Android app from silently drifting
//! apart.
//!
//! The format itself is specified in `spec/ENVELOPE.md`, which is normative.
//! Where this code and that document disagree, this code is wrong.

#![forbid(unsafe_code)]

pub mod envelope;
pub mod error;
pub mod header;
pub mod key;
pub mod meta;

pub use envelope::{open, seal, seal_with_key, Opened, SealOptions};
pub use error::{ErrorCode, Result};
pub use header::{Header, CHUNK_LOG2_DEFAULT, CHUNK_LOG2_MAX, CHUNK_LOG2_MIN};
pub use key::SecretKey;
pub use meta::{ContentKind, Meta};

/// The envelope version this build produces and accepts.
pub const FORMAT_VERSION: u8 = header::VERSION;
