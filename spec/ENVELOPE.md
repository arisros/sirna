# Sirna envelope format — version 1

**Status: normative.** Every client — Rust, CLI, WASM, Android — is tested against
this document via the committed vectors in `spec/vectors/`. If an implementation
disagrees with this file, the implementation is wrong.

Changing any committed `spec/vectors/*.bin` requires bumping `version`. This is
enforced by `cargo xtask spec-lint`.

---

## 1. Design constraints

An envelope is a self-contained, opaque byte string. It carries everything needed
to decrypt **except the key**, and it reveals nothing useful without one.

Three rules drove every choice below:

1. **The server must be structurally unable to read it.** No field is plaintext
   beyond what a storage layer needs to move bytes around: magic, version, suite,
   nonce, salt and chunk size. Filename, MIME type, true length and expiry all
   live inside the encrypted metadata block.
2. **Truncation and reordering must fail loudly.** Plain per-chunk AEAD does not
   give this. Cutting a stream short would otherwise yield a shorter but valid
   plaintext, which for a secret-sharing tool is a correctness bug with security
   consequences.
3. **All four targets must produce identical bytes.** Anything that depends on a
   dependency's internal defaults is a divergence waiting to happen, so the
   nonce and AAD construction is specified here explicitly and implemented by
   hand rather than inherited from a library.

## 2. Primitives

| Purpose | Algorithm | Why this one |
|---|---|---|
| Payload AEAD | XChaCha20-Poly1305 | The 192-bit nonce makes a random per-message nonce safe without any counter bookkeeping. WebCrypto does not implement it, so every target runs the same Rust code path instead of splitting between a native and a polyfilled implementation. |
| Streaming | STREAM with an explicit last-chunk flag | Binds chunk index and finality into the AEAD, which is what makes truncation and reordering detectable. |
| KDF / hash | BLAKE3 | One dependency covers key derivation, hashing and keyed hashing, and it is fast in WASM where SHA-2 is not. |
| Passphrase KDF | Argon2id, m=64 MiB, t=3, p=1 | 64 MiB is the largest parameter that reliably survives mobile Safari and low-end Android without being OOM-killed. |
| Metadata encoding | CBOR | Self-describing, so optional fields can be added later without a version bump. |
| Key as text | BIP-39, 24 words | A battle-tested wordlist with a built-in checksum. Inventing one has no upside. |
| Key as QR | `sirna1:` URI, see §7 | Roughly 50 characters keeps QR density low enough to scan across a room. |
| Constant-time comparison | `subtle` | Tag and checksum comparisons must not short-circuit. |

## 3. Byte layout

```
Envelope := Header ‖ MetaChunk ‖ DataChunk[0 .. n-1]
```

### 3.1 Header — 44 bytes, fixed, little-endian

| Offset | Size | Field | Notes |
|---:|---:|---|---|
| 0 | 4 | `magic` | `0x53 0x52 0x4E 0x41` — ASCII `SRNA` |
| 4 | 1 | `version` | `1` |
| 5 | 1 | `suite` | `1` = XChaCha20-Poly1305 / STREAM / BLAKE3 |
| 6 | 1 | `flags` | bit0 `0`=text `1`=file · bit1 passphrase-derived key · bit2 custody mode · bit3 payload padded · bits 4-7 reserved, must be `0` |
| 7 | 1 | `reserved` | must be `0` |
| 8 | 19 | `stream_nonce` | random, per envelope |
| 27 | 16 | `kdf_salt` | Argon2id salt; all-zero when bit1 is clear |
| 43 | 1 | `chunk_log2` | plaintext chunk size is `1 << chunk_log2`; default `16` (64 KiB); valid range `10..=24` |

The header is **not** encrypted — a storage layer has to be able to reject
garbage without a key. It is authenticated: see §5.

### 3.2 Chunks

```
MetaChunk := u32le meta_len ‖ AEAD(K_meta, nonce_meta, aad_meta, CBOR(Meta))
DataChunk := AEAD(K_data, nonce_i, aad_i, plaintext_chunk_i)
```

`meta_len` counts the ciphertext bytes that follow, including the 16-byte tag.

Every data chunk except the last carries exactly `1 << chunk_log2` plaintext
bytes. The last chunk carries `1..=1<<chunk_log2` bytes — except for an empty
payload, which is a single last chunk of zero bytes.

A ciphertext chunk is always plaintext length plus the 16-byte Poly1305 tag.

## 4. Key schedule

```
K_msg = 32 random bytes from a CSPRNG                                (flags bit1 clear)
      | Argon2id(passphrase, kdf_salt, m=65536, t=3, p=1) -> 32 B    (flags bit1 set)

K_data = BLAKE3::derive_key("sirna v1 data key", K_msg)
K_meta = BLAKE3::derive_key("sirna v1 meta key", K_msg)
```

`K_msg` itself is never used to encrypt anything directly. Domain-separated
subkeys cost two lines and leave the door open to granting a metadata-only
preview later without exposing the payload.

The context strings are part of the format. Changing them breaks every existing
envelope, so they are fixed here rather than derived from the crate name.

## 5. Nonce and AAD construction

Implement this explicitly. Do not delegate it to a streaming helper in a
dependency — the wire format must be a property of this spec, not of whichever
version of a crate happened to compile.

```
header_hash = BLAKE3(Header[0..44])            // 32 bytes

nonce_i     = stream_nonce ‖ u32be(i) ‖ u8(last_flag)          // 19 + 4 + 1 = 24
aad_i       = header_hash  ‖ u32be(i) ‖ u8(last_flag)          // 32 + 4 + 1 = 37

nonce_meta  = stream_nonce ‖ u32be(0xFFFFFFFF) ‖ u8(0x00)
aad_meta    = header_hash  ‖ u32be(0xFFFFFFFF) ‖ u8(0x00)

last_flag   = 0x01 on the final data chunk, 0x00 otherwise
i           = 0-based data chunk index
```

The metadata chunk uses index `0xFFFFFFFF`, which is unreachable for data chunks
because the maximum chunk count is bounded well below that.

### 5.1 Chunk boundaries are computed, never guessed

A decoder **must not** infer chunk boundaries from the remaining byte count.
`plaintext_len` (metadata key 4) is decrypted and authenticated *before* any
data chunk is read, so the exact layout is known:

```
chunk_count   = max(1, ceil(plaintext_len / chunk_size))
expected_data = plaintext_len + chunk_count * 16
expected_size = 44 + 4 + meta_len + expected_data
```

An envelope shorter than `expected_size` is `Truncated`; longer is
`TrailingData`. Only then are chunks decrypted, each with a known length.

This is not a micro-optimisation, it is what makes the error codes honest. A
decoder that guesses boundaries by length cannot tell "bytes appended to the
final chunk" apart from "final chunk damaged", because the final chunk is short
by nature — both surface as `AuthFailed`, and the user is told their key is
wrong when in fact their download was corrupted. An attacker cannot exploit the
dependency on `plaintext_len` either: lying about it means forging the metadata
tag first.

### 5.2 What the construction buys

Because index and finality are inside both the nonce and the AAD, and because
the header is hashed into every AAD:

| Tamper | Detected as |
|---|---|
| Stream cut, anywhere | length mismatch → `Truncated` |
| Bytes appended anywhere | length mismatch → `TrailingData` |
| Two chunks swapped, or one duplicated | wrong `i` in nonce and AAD → `AuthFailed` |
| `last_flag` inconsistent with position | wrong AAD → `AuthFailed` |
| Any header byte flipped | `header_hash` changes → `AuthFailed` on the first chunk |
| Metadata altered to lie about length | metadata tag fails → `AuthFailed` |

No prefix of a valid envelope may ever decode successfully. That property is
what stops a partial download from being displayed as a complete, shorter
message, and it is asserted directly by the test suite.

There is deliberately **no separate MAC over the header**. Folding
`header_hash` into every chunk's AAD removes an entire primitive while still
making header tampering fail on the very first chunk.

## 6. Metadata block

CBOR map with integer keys, encrypted under `K_meta`. The server never sees any
of this.

| Key | Type | Meaning |
|---:|---|---|
| 1 | u8 | content kind: `0` text, `1` file |
| 2 | text, optional | filename |
| 3 | text, optional | MIME type |
| 4 | u64 | true plaintext length, so padding can be stripped |
| 5 | u64 | created at, Unix seconds |
| 6 | u64 | expires at, Unix seconds |
| 7 | text, optional | note |
| 8 | bytes(32), optional | owner public key, custody mode only |

**Expiry lives here as well as in the server database, and the client enforces
this copy.** A client must refuse to render an expired message even if the
server hands it over. Server-side expiry is a courtesy; the copy inside the
authenticated envelope is the one that can be reasoned about.

## 7. Key encodings

### 7.1 Mnemonic

Standard BIP-39 over the 256-bit `K_msg`: 24 words, English wordlist. The
built-in checksum catches transcription errors before a decrypt is attempted,
so a mistyped word reports `ChecksumFailed` rather than `AuthFailed`. Those are
very different messages to show a human.

### 7.2 Compact URI

```
sirna1:<base64url_nopad( u8(version) ‖ K_msg(32) ‖ u16be(crc16_ccitt) )>
```

CRC-16/CCITT-FALSE over `version ‖ K_msg`. This is an integrity check against a
misread QR, not a security control.

## 8. Padding — reserved in v1, implemented in M6

When `flags` bit3 is set, the plaintext is padded to the next size bucket before
chunking, and key 4 of the metadata carries the true length so a reader can trim
it back.

Buckets: 1 KiB, 4 KiB, 16 KiB, 64 KiB, 256 KiB, 1 MiB, 4 MiB, 16 MiB, 32 MiB.

The reason is that the server necessarily learns blob length, and "this blob is
41 bytes" is a strong fingerprint of a short message. The flag bit and the
length field are reserved now so that turning padding on later needs no version
bump.

## 9. Error codes

Canonical and shared across every binding. Vectors assert the **code**, never
the message — otherwise "wrong key" and "corrupt file" end up telling three
different stories on three platforms.

| Code | Name | Meaning |
|---:|---|---|
| 1 | `BadMagic` | first four bytes are not `SRNA` |
| 2 | `UnsupportedVersion` | version byte is not recognised |
| 3 | `UnsupportedSuite` | suite byte is not recognised |
| 4 | `MalformedHeader` | truncated header, reserved bits set, or a length field points outside the buffer |
| 5 | `AuthFailed` | AEAD tag mismatch: wrong key, tampering, or reordering |
| 6 | `Truncated` | stream ended without a chunk marked final |
| 7 | `TrailingData` | bytes present after the final chunk |
| 8 | `MetaDecodeFailed` | metadata decrypted but is not valid CBOR |
| 9 | `Expired` | `expires_at` is in the past |
| 10 | `ChunkTooLarge` | `chunk_log2` outside `10..=24` |
| 11 | `KeyDecodeFailed` | mnemonic or URI is not well-formed |
| 12 | `ChecksumFailed` | mnemonic or URI checksum does not match |

## 10. Limits

| Bound | Value | Reason |
|---|---|---|
| `chunk_log2` | `10..=24` | Below 1 KiB the tag overhead dominates; above 16 MiB a single chunk stops fitting comfortably in a mobile heap |
| Max chunk count | 2³² − 2 | Bounded by the 32-bit index; `0xFFFFFFFF` is reserved for metadata |
| Max metadata | 64 KiB | Metadata is small by nature; a cap keeps the parser's appetite bounded |
| Max envelope, as deployed | 32 MiB | A deployment policy, not a format limit. See `docs/OPERATIONS.md` |

## 11. Reading order for implementers

1. Parse and validate the 44-byte header. Reject on magic, version, suite,
   reserved bits and `chunk_log2` range **before** allocating anything.
2. Compute `header_hash`.
3. Derive `K_data` and `K_meta`.
4. Decrypt the metadata chunk; check expiry against the caller-supplied clock.
5. Compute `expected_size` from the authenticated `plaintext_len` (§5.1) and
   compare it against the real buffer length. Reject before decrypting any data.
6. Decrypt each chunk at its known offset and length.

Step 1 is the entire remote attack surface and it consumes attacker-controlled
input, so it is also the target of the fuzzing harness.
