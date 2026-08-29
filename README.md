# Sirna

*sirna* — Indonesian: to vanish without leaving a trace.

Encrypted messages and files whose **key** can be destroyed on demand. Destroy
the key and every copy of the ciphertext — anywhere in the world, including
copies you do not control — becomes permanently unreadable at the same instant.

## The idea in one paragraph

You cannot delete data off someone else's device. Nobody can, and products that
claim to are relying on the recipient's goodwill and calling it security. But
you *can* delete a key out of a hardware secure element, and that deletion is
enforced by silicon rather than by politeness. So Sirna inverts the usual
design: ciphertext is treated as worthless public litter that may exist forever,
and the key becomes the only scarce, destructible object.

The promise is **"destroy the key", not "destroy the copy"** — see
[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md), which is required reading before
trusting this with anything that matters.

## What makes it different from a paste-bin with encryption

The server is **structurally incapable** of reading anything. Not by policy, not
by promise — the key never reaches it, and the server binary does not even link
a decryption path. There is no master key in an environment variable anywhere in
the deployment.

The key also never travels in the URL. Sirna deliberately rejects the
`example.com/#key` pattern: link and key go over separate channels, so leaking
one of them is not enough.

## Status

Early. `core` and the envelope spec are done and tested; everything else is on
the way.

| Component | State |
|---|---|
| `spec/ENVELOPE.md` — normative wire format v1 | done |
| `crates/core` — chunked AEAD, key schedule, key encodings | done |
| `crates/cli` — seal / open / vector generation | in progress |
| `crates/server` — blob store in front of Garage | planned |
| `crates/wasm` + `web/` — browser client | planned |
| `crates/ffi` + `android/` — owner app, Keystore-backed | planned |

## Design

```
crates/core     pure Rust — no I/O, no clock, no network
  ├── cli       test tool and vector generator
  ├── wasm      wasm-bindgen  → browser
  ├── ffi       uniffi        → Android
  └── server    dumb blob store + rendezvous relay
spec/           the format, and the vectors every target is tested against
```

`core` takes the current time as a `now_unix: u64` parameter and its randomness
as an injected RNG. That is not fastidiousness: wasm32 has no `SystemTime`, and
byte-exact cross-target test vectors are impossible without a seedable RNG —
and those vectors are the only thing that stops the CLI, the browser and the
Android app from silently drifting apart.

The envelope uses XChaCha20-Poly1305 in a STREAM construction with an explicit
last-chunk flag, BLAKE3 for key derivation, and CBOR for encrypted metadata.
Chunk boundaries are computed from the authenticated plaintext length rather
than guessed from the remaining byte count, which is what lets a truncated
download be reported as *truncated* instead of as a wrong key.

## Building

```bash
cargo test --workspace     # 36 tests, including negative and property tests
cargo clippy --all-targets -- -D warnings
```

`core` is `#![forbid(unsafe_code)]`.

On this homelab host, `mise` exports `RUSTUP_TOOLCHAIN`, which silently
overrides `rust-toolchain.toml`. `mise.toml` in the project root is the file
that actually wins locally; `rust-toolchain.toml` is there for CI and other
machines. It also pins `CARGO_TARGET_DIR` onto `/home`, because `/` has very
little free space and a multi-target build tree does not fit.

## Relationship to OTM

Sirna is the successor to [otm](https://github.com/arisros/otm), but not a fork
of it. OTM keeps a master `SECRET_KEY` on the server, which means the server can
decrypt every message it holds. That is a reasonable trade for a teaching demo
of applied cryptography, which is what OTM is and remains. It is not a
reasonable trade for a tool that sells the word "secret", and it cannot be
patched out — it is the shape of the whole design.

## License

MIT
