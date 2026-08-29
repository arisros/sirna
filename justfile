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
check: doctor lint test spec-lint wasm-test

# Build the browser bindings and copy them next to the web client.
wasm:
    CARGO_TARGET_DIR=/home/workspace/.cargo-target/sirna-wasm \
      wasm-pack build crates/wasm --target web --out-dir pkg --release
    cp crates/wasm/pkg/sirna_wasm.js crates/wasm/pkg/sirna_wasm_bg.wasm web/

# The same corpus, through the real wasm-bindgen glue — which is where the
# bugs a pure-Rust wasm test cannot see actually live. Plus interop in both
# directions between the CLI and the browser build.
wasm-test: wasm
    node crates/wasm/tests-node/vectors.mjs
    SIRNA_CLI=$CARGO_TARGET_DIR/debug/sirna node crates/wasm/tests-node/cross-client.mjs

# Vector bytes may not change while the format version stays put.
spec-lint:
    cargo run -q -p xtask -- spec-lint

# Regenerate the cross-target corpus. Output is deterministic; a diff here
# means the wire format moved.
vectors:
    cargo run -q -p sirna-cli -- vectors generate --out spec/vectors
    cargo run -q -p xtask -- spec-lint
