//! The committed vector corpus, checked on every `cargo test`.
//!
//! This is the Rust side of a three-way agreement: the WASM build and the
//! Android build run the same corpus from their own test suites. A vector that
//! one target accepts and another rejects means one of them has drifted, and
//! the corpus is what makes that visible instead of silent.

use std::path::Path;

#[test]
fn committed_vectors_match_this_build() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors");
    let (passed, failed) = sirna_cli::vectors::verify(&dir).expect("reading the corpus");

    assert_eq!(failed, 0, "{failed} vector(s) disagree with this build");
    assert!(passed > 0, "corpus is empty — did generation run?");
}
