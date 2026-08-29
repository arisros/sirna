//! Round-trip and boundary tests.
//!
//! The boundary cases here are the ones this class of code always gets wrong:
//! an empty payload, a payload exactly one chunk long, and a payload one byte
//! past a chunk boundary.

use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sirna_core::{header::CHUNK_LOG2_MIN, open, seal, ErrorCode, SealOptions, SecretKey};

const NOW: u64 = 1_800_000_000;

fn rng() -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(42)
}

fn opts() -> SealOptions {
    SealOptions {
        expires_at: 0,
        chunk_log2: Some(CHUNK_LOG2_MIN), // 1 KiB, so boundary tests stay cheap
        ..Default::default()
    }
}

fn roundtrip(plaintext: &[u8]) {
    let mut r = rng();
    let (env, key) = seal(plaintext, &opts(), &mut r, NOW).unwrap();
    let got = open(&env, &key, NOW).unwrap();
    assert_eq!(got.plaintext, plaintext, "len {}", plaintext.len());
    assert_eq!(got.meta.plaintext_len, plaintext.len() as u64);
}

#[test]
fn empty_payload_is_valid_not_an_error() {
    roundtrip(b"");
}

#[test]
fn single_byte() {
    roundtrip(b"x");
}

#[test]
fn chunk_boundaries() {
    let chunk = 1usize << CHUNK_LOG2_MIN;
    for len in [chunk - 1, chunk, chunk + 1, 2 * chunk, 2 * chunk + 1] {
        let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        roundtrip(&data);
    }
}

#[test]
fn text_and_metadata_survive() {
    let mut r = rng();
    let o = SealOptions {
        filename: Some("notes.txt".into()),
        mime: Some("text/plain".into()),
        note: Some("for review".into()),
        expires_at: NOW + 3600,
        ..opts()
    };
    let (env, key) = seal(b"hello", &o, &mut r, NOW).unwrap();
    let got = open(&env, &key, NOW).unwrap();

    assert_eq!(got.plaintext, b"hello");
    assert_eq!(got.meta.filename.as_deref(), Some("notes.txt"));
    assert_eq!(got.meta.mime.as_deref(), Some("text/plain"));
    assert_eq!(got.meta.created_at, NOW);
    assert_eq!(got.meta.expires_at, NOW + 3600);
}

#[test]
fn expiry_is_enforced_by_the_client_not_the_server() {
    let mut r = rng();
    let o = SealOptions {
        expires_at: NOW + 10,
        ..opts()
    };
    let (env, key) = seal(b"secret", &o, &mut r, NOW).unwrap();

    assert!(open(&env, &key, NOW + 9).is_ok());
    // The envelope is byte-identical here; only the clock moved. Nothing on the
    // server side is consulted.
    assert_eq!(open(&env, &key, NOW + 11).unwrap_err(), ErrorCode::Expired);
}

#[test]
fn wrong_key_fails() {
    let mut r = rng();
    let (env, _key) = seal(b"secret", &opts(), &mut r, NOW).unwrap();
    let other = SecretKey::from_bytes([7u8; 32]);
    assert_eq!(open(&env, &other, NOW).unwrap_err(), ErrorCode::AuthFailed);
}

#[test]
fn same_plaintext_seals_differently_each_time() {
    // Different stream nonces must produce different envelopes, otherwise
    // identical messages would be linkable by anyone holding the ciphertext.
    let (a, _) = seal(b"same", &opts(), &mut ChaCha20Rng::seed_from_u64(1), NOW).unwrap();
    let (b, _) = seal(b"same", &opts(), &mut ChaCha20Rng::seed_from_u64(2), NOW).unwrap();
    assert_ne!(a, b);
}

#[test]
fn seal_is_deterministic_for_a_fixed_seed() {
    // This property is what makes byte-exact cross-target vectors possible.
    let (a, ka) = seal(b"fixed", &opts(), &mut rng(), NOW).unwrap();
    let (b, kb) = seal(b"fixed", &opts(), &mut rng(), NOW).unwrap();
    assert_eq!(a, b);
    assert_eq!(ka.as_bytes(), kb.as_bytes());
}

#[test]
fn key_encodings_round_trip() {
    let mut r = rng();
    let key = SecretKey::generate(&mut r);

    let phrase = key.to_mnemonic();
    assert_eq!(phrase.split_whitespace().count(), 24);
    assert_eq!(SecretKey::from_mnemonic(&phrase).unwrap(), key);

    let uri = key.to_uri();
    assert!(uri.starts_with("sirna1:"));
    assert_eq!(SecretKey::from_uri(&uri).unwrap(), key);

    // One input box should accept either form without asking the user which.
    assert_eq!(SecretKey::parse(&phrase).unwrap(), key);
    assert_eq!(SecretKey::parse(&uri).unwrap(), key);
}

#[test]
fn secret_key_never_prints_material() {
    let key = SecretKey::from_bytes([0xAB; 32]);
    let shown = format!("{key:?}");
    assert_eq!(shown, "SecretKey(<redacted>)");
    assert!(!shown.contains("ab"), "key bytes must not reach a log line");
}
