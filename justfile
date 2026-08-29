# Sirna repository tasks.
# `mise` supplies RUSTUP_TOOLCHAIN and CARGO_TARGET_DIR — see mise.toml.

default:
    @just --list

# Check the build environment before blaming the code.
doctor:
    cargo run -q -p xtask -- doctor

test:
    cargo test --workspace

lint:
    cargo fmt --all --check
    cargo clippy --workspace --all-targets -- -D warnings

# The full gate. Run this before pushing.
check: doctor lint test spec-lint

# Vector bytes may not change while the format version stays put.
spec-lint:
    cargo run -q -p xtask -- spec-lint

# Regenerate the cross-target corpus. Output is deterministic; a diff here
# means the wire format moved.
vectors:
    cargo run -q -p sirna-cli -- vectors generate --out spec/vectors
    cargo run -q -p xtask -- spec-lint
