//! A blob store that cannot read what it stores.
//!
//! This crate links `sirna_core` for one thing only: the envelope header
//! parser, so junk can be rejected at upload time. It never links the
//! decryption path, and it holds no key material of any kind. "The server
//! cannot decrypt" is therefore a property of the build rather than a promise
//! in a document.

pub mod api;
pub mod db;
pub mod limit;
pub mod store;
pub mod web;
