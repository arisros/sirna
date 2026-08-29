//! Cross-target test vectors.
//!
//! These are the load-bearing part of the whole project. The CLI, the browser
//! and the Android app each carry their own copy of the format's behaviour, and
//! nothing except a shared, byte-exact corpus stops them from drifting apart
//! until the day a file written on a phone will not open on a laptop.
//!
//! Generation is deterministic: a seeded RNG and a fixed clock, so re-running
//! the generator on an unchanged codebase produces byte-identical output. If it
//! does not, something in the format moved and the spec version must move too.

use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use sirna_core::{
    header::HEADER_LEN, open, open_with_passphrase, seal_with_key, seal_with_passphrase,
    SealOptions, SecretKey,
};

/// Fixed clock for every vector. A real timestamp would make the corpus
/// non-reproducible and would start failing on its own once expiry passed.
const VECTOR_NOW: u64 = 1_800_000_000;

#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
    /// Envelope format version this corpus was generated for. `spec-lint`
    /// refuses to let the bytes change while this stays put.
    pub format_version: u8,
    pub vectors: Vec<Vector>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Vector {
    pub id: String,
    pub description: String,
    pub key_hex: String,
    pub mnemonic: String,
    pub chunk_log2: u8,
    pub plaintext_len: u64,
    pub plaintext_b3: String,
    pub envelope_file: String,
    pub envelope_b3: String,
    /// `"ok"`, or the numeric error code from `spec/ENVELOPE.md` §9 as a string.
    pub expect: String,
    /// Present only for passphrase-mode vectors. The salt lives in the header,
    /// so a client can reproduce the key from this string alone — which is
    /// exactly the property that has to match across targets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<String>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn b3(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// Deterministic filler. Not random — a vector whose contents depend on the
/// host's RNG is not a vector.
fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i.wrapping_mul(31) % 251) as u8).collect()
}

fn key_for(seed: u8) -> SecretKey {
    SecretKey::from_bytes([seed; 32])
}

struct Case {
    id: &'static str,
    description: &'static str,
    len: usize,
    chunk_log2: u8,
    key_seed: u8,
    /// Applied to a freshly sealed envelope to produce the corrupt variant.
    /// `None` means the vector is expected to open cleanly.
    tamper: Option<fn(&mut Vec<u8>)>,
    expect: &'static str,
    /// When set, the vector is sealed under this passphrase instead of
    /// `key_seed`. Cross-target conformance for Argon2id matters as much as for
    /// the AEAD: if one client derives differently, files silently stop opening.
    passphrase: Option<&'static str>,
}

fn meta_len(env: &[u8]) -> usize {
    u32::from_le_bytes(env[HEADER_LEN..HEADER_LEN + 4].try_into().unwrap()) as usize
}

/// The corpus. Positive cases first, then one case per rejection path in §9.
fn cases() -> Vec<Case> {
    vec![
        Case {
            id: "v001-empty",
            description: "empty payload is valid, not an error",
            len: 0,
            chunk_log2: 10,
            key_seed: 1,
            tamper: None,
            expect: "ok",
            passphrase: None,
        },
        Case {
            id: "v002-tiny-text",
            description: "single short chunk",
            len: 11,
            chunk_log2: 10,
            key_seed: 2,
            tamper: None,
            expect: "ok",
            passphrase: None,
        },
        Case {
            id: "v003-exact-chunk",
            description: "payload exactly one chunk long",
            len: 1024,
            chunk_log2: 10,
            key_seed: 3,
            tamper: None,
            expect: "ok",
            passphrase: None,
        },
        Case {
            id: "v004-chunk-plus-one",
            description: "one byte past a chunk boundary",
            len: 1025,
            chunk_log2: 10,
            key_seed: 4,
            tamper: None,
            expect: "ok",
            passphrase: None,
        },
        Case {
            id: "v005-multi-chunk",
            description: "several chunks with a short tail",
            len: 5000,
            chunk_log2: 10,
            key_seed: 5,
            tamper: None,
            expect: "ok",
            passphrase: None,
        },
        Case {
            id: "v006-large-chunk-size",
            description: "non-default chunk_log2",
            len: 70000,
            chunk_log2: 16,
            key_seed: 6,
            tamper: None,
            expect: "ok",
            passphrase: None,
        },
        Case {
            id: "v007-passphrase",
            description: "sealed under a passphrase; salt is in the header",
            len: 64,
            chunk_log2: 10,
            key_seed: 0,
            tamper: None,
            expect: "ok",
            passphrase: Some("correct horse battery staple"),
        },
        Case {
            id: "n001-bad-magic",
            description: "first byte of the magic altered",
            len: 32,
            chunk_log2: 10,
            key_seed: 7,
            tamper: Some(|e| e[0] = b'X'),
            expect: "1",
            passphrase: None,
        },
        Case {
            id: "n002-bad-version",
            description: "version byte bumped",
            len: 32,
            chunk_log2: 10,
            key_seed: 7,
            tamper: Some(|e| e[4] = 2),
            expect: "2",
            passphrase: None,
        },
        Case {
            id: "n003-bad-suite",
            description: "unknown cipher suite",
            len: 32,
            chunk_log2: 10,
            key_seed: 7,
            tamper: Some(|e| e[5] = 99),
            expect: "3",
            passphrase: None,
        },
        Case {
            id: "n004-reserved-set",
            description: "reserved header byte non-zero",
            len: 32,
            chunk_log2: 10,
            key_seed: 7,
            tamper: Some(|e| e[7] = 1),
            expect: "4",
            passphrase: None,
        },
        Case {
            id: "n005-unknown-flag",
            description: "undefined flag bit set",
            len: 32,
            chunk_log2: 10,
            key_seed: 7,
            tamper: Some(|e| e[6] |= 0b1000_0000),
            expect: "4",
            passphrase: None,
        },
        Case {
            id: "n006-chunk-log2-low",
            description: "chunk_log2 below the floor",
            len: 32,
            chunk_log2: 10,
            key_seed: 7,
            tamper: Some(|e| e[43] = 4),
            expect: "10",
            passphrase: None,
        },
        Case {
            id: "n007-chunk-log2-high",
            description: "chunk_log2 above the ceiling",
            len: 32,
            chunk_log2: 10,
            key_seed: 7,
            tamper: Some(|e| e[43] = 40),
            expect: "10",
            passphrase: None,
        },
        Case {
            id: "n008-nonce-tamper",
            description: "stream nonce altered — header is authenticated via AAD",
            len: 32,
            chunk_log2: 10,
            key_seed: 7,
            tamper: Some(|e| e[8] ^= 0x01),
            expect: "5",
            passphrase: None,
        },
        Case {
            id: "n009-tag-tamper",
            description: "final tag byte flipped",
            len: 32,
            chunk_log2: 10,
            key_seed: 7,
            tamper: Some(|e| {
                let l = e.len() - 1;
                e[l] ^= 0x01;
            }),
            expect: "5",
            passphrase: None,
        },
        Case {
            id: "n010-truncated-boundary",
            description: "last chunk dropped at a chunk boundary",
            len: 1124,
            chunk_log2: 10,
            key_seed: 7,
            tamper: Some(|e| {
                let cut = HEADER_LEN + 4 + meta_len(e) + (1024 + 16);
                e.truncate(cut);
            }),
            expect: "6",
            passphrase: None,
        },
        Case {
            id: "n011-truncated-mid",
            description: "cut inside the final chunk",
            len: 300,
            chunk_log2: 10,
            key_seed: 7,
            tamper: Some(|e| {
                let l = e.len() - 5;
                e.truncate(l);
            }),
            expect: "6",
            passphrase: None,
        },
        Case {
            id: "n012-trailing",
            description: "bytes appended after the envelope",
            len: 32,
            chunk_log2: 10,
            key_seed: 7,
            tamper: Some(|e| e.extend_from_slice(b"extra")),
            expect: "7",
            passphrase: None,
        },
        Case {
            id: "n013-swapped-chunks",
            description: "two chunks exchanged",
            len: 3072,
            chunk_log2: 10,
            key_seed: 7,
            tamper: Some(|e| {
                let start = HEADER_LEN + 4 + meta_len(e);
                let full = 1024 + 16;
                let a: Vec<u8> = e[start..start + full].to_vec();
                let b: Vec<u8> = e[start + full..start + 2 * full].to_vec();
                e[start..start + full].copy_from_slice(&b);
                e[start + full..start + 2 * full].copy_from_slice(&a);
            }),
            expect: "5",
            passphrase: None,
        },
        Case {
            id: "n014-meta-len-overflow",
            description: "metadata length points past the buffer",
            len: 32,
            chunk_log2: 10,
            key_seed: 7,
            tamper: Some(|e| {
                e[HEADER_LEN..HEADER_LEN + 4].copy_from_slice(&u32::MAX.to_le_bytes())
            }),
            expect: "4",
            passphrase: None,
        },
        Case {
            id: "n015-short-buffer",
            description: "shorter than a header",
            len: 32,
            chunk_log2: 10,
            key_seed: 7,
            tamper: Some(|e| e.truncate(20)),
            expect: "4",
            passphrase: None,
        },
    ]
}

pub fn generate(out_dir: &Path) -> Result<usize> {
    fs::create_dir_all(out_dir).with_context(|| format!("creating {}", out_dir.display()))?;

    let mut entries = Vec::new();
    for case in cases() {
        let key = key_for(case.key_seed);
        let plaintext = payload(case.len);
        let opts = SealOptions {
            chunk_log2: Some(case.chunk_log2),
            ..Default::default()
        };

        // Seed derived from the id so each vector is independent yet stable.
        let seed = case.id.bytes().map(u64::from).sum::<u64>();
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let mut envelope = match case.passphrase {
            Some(p) => seal_with_passphrase(&plaintext, p, &opts, &mut rng, VECTOR_NOW),
            None => seal_with_key(&plaintext, &key, &opts, &mut rng, VECTOR_NOW),
        }
        .map_err(|e| anyhow::anyhow!("sealing {}: {e}", case.id))?;

        if let Some(t) = case.tamper {
            t(&mut envelope);
        }

        let file = format!("{}.bin", case.id);
        fs::write(out_dir.join(&file), &envelope)?;

        entries.push(Vector {
            passphrase: case.passphrase.map(str::to_string),
            id: case.id.to_string(),
            description: case.description.to_string(),
            key_hex: if case.passphrase.is_some() {
                String::new()
            } else {
                hex(key.as_bytes())
            },
            mnemonic: if case.passphrase.is_some() {
                String::new()
            } else {
                key.to_mnemonic()
            },
            chunk_log2: case.chunk_log2,
            plaintext_len: case.len as u64,
            plaintext_b3: b3(&plaintext),
            envelope_file: file,
            envelope_b3: b3(&envelope),
            expect: case.expect.to_string(),
        });
    }

    let manifest = Manifest {
        format_version: sirna_core::FORMAT_VERSION,
        vectors: entries,
    };
    let json = serde_json::to_string_pretty(&manifest)? + "\n";
    fs::write(out_dir.join("vectors.json"), json)?;

    Ok(manifest.vectors.len())
}

/// The reference verifier. Every other target reimplements this against the
/// same corpus; if any of them disagrees, one of the implementations is wrong
/// and the vectors say which.
pub fn verify(dir: &Path) -> Result<(usize, usize)> {
    let manifest_path = dir.join("vectors.json");
    let raw = fs::read_to_string(&manifest_path)
        .with_context(|| format!("reading {}", manifest_path.display()))?;
    let manifest: Manifest = serde_json::from_str(&raw)?;

    if manifest.format_version != sirna_core::FORMAT_VERSION {
        bail!(
            "corpus targets format version {} but this build produces {}",
            manifest.format_version,
            sirna_core::FORMAT_VERSION
        );
    }

    let mut passed = 0usize;
    let mut failed = 0usize;

    for v in &manifest.vectors {
        let envelope = fs::read(dir.join(&v.envelope_file))?;

        // A silent edit to a .bin would otherwise let the corpus drift away
        // from what the manifest claims it contains.
        if b3(&envelope) != v.envelope_b3 {
            eprintln!("FAIL {}: envelope hash does not match the manifest", v.id);
            failed += 1;
            continue;
        }

        let outcome = if let Some(p) = &v.passphrase {
            open_with_passphrase(&envelope, p, VECTOR_NOW)
        } else {
            let key = SecretKey::from_mnemonic(&v.mnemonic)
                .map_err(|e| anyhow::anyhow!("{}: bad mnemonic in manifest: {e}", v.id))?;
            if hex(key.as_bytes()) != v.key_hex {
                eprintln!("FAIL {}: mnemonic and key_hex disagree", v.id);
                failed += 1;
                continue;
            }
            open(&envelope, &key, VECTOR_NOW)
        };
        let ok = match (&v.expect[..], outcome) {
            ("ok", Ok(got)) => {
                let len_ok = got.plaintext.len() as u64 == v.plaintext_len;
                let hash_ok = b3(&got.plaintext) == v.plaintext_b3;
                if !len_ok || !hash_ok {
                    eprintln!("FAIL {}: decrypted plaintext does not match", v.id);
                }
                len_ok && hash_ok
            }
            ("ok", Err(e)) => {
                eprintln!(
                    "FAIL {}: expected success, got error {} ({e})",
                    v.id,
                    e.code()
                );
                false
            }
            (want, Ok(_)) => {
                eprintln!(
                    "FAIL {}: expected error {want}, but it opened successfully",
                    v.id
                );
                false
            }
            (want, Err(e)) => {
                let got = e.code().to_string();
                if got != want {
                    eprintln!("FAIL {}: expected error {want}, got {got} ({e})", v.id);
                }
                got == want
            }
        };

        if ok {
            passed += 1;
        } else {
            failed += 1;
        }
    }

    Ok((passed, failed))
}
