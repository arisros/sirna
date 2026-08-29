//! Negative tests — the table in `spec/ENVELOPE.md` §5.1 and §9.
//!
//! Each case asserts the numeric error code, not the message. Codes are the
//! cross-target contract; messages are UI copy and may be translated.

use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sirna_core::{
    envelope::TAG_LEN,
    header::{CHUNK_LOG2_MIN, HEADER_LEN},
    open, seal, ErrorCode, SealOptions, SecretKey,
};

const NOW: u64 = 1_800_000_000;
const CHUNK: usize = 1 << CHUNK_LOG2_MIN;

fn sealed(len: usize) -> (Vec<u8>, SecretKey) {
    let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
    let o = SealOptions {
        chunk_log2: Some(CHUNK_LOG2_MIN),
        ..Default::default()
    };
    seal(&data, &o, &mut ChaCha20Rng::seed_from_u64(9), NOW).unwrap()
}

fn err(env: &[u8], key: &SecretKey) -> ErrorCode {
    open(env, key, NOW).unwrap_err()
}

#[test]
fn bad_magic() {
    let (mut env, key) = sealed(10);
    env[0] = b'X';
    assert_eq!(err(&env, &key), ErrorCode::BadMagic);
}

#[test]
fn unsupported_version() {
    let (mut env, key) = sealed(10);
    env[4] = 2;
    assert_eq!(err(&env, &key), ErrorCode::UnsupportedVersion);
}

#[test]
fn unsupported_suite() {
    let (mut env, key) = sealed(10);
    env[5] = 99;
    assert_eq!(err(&env, &key), ErrorCode::UnsupportedSuite);
}

#[test]
fn reserved_byte_must_be_zero() {
    let (mut env, key) = sealed(10);
    env[7] = 1;
    assert_eq!(err(&env, &key), ErrorCode::MalformedHeader);
}

#[test]
fn unknown_flag_bits_are_refused() {
    // Ignoring an unknown flag risks decoding the payload wrongly and calling
    // it success, which is worse than refusing outright.
    let (mut env, key) = sealed(10);
    env[6] |= 0b1000_0000;
    assert_eq!(err(&env, &key), ErrorCode::MalformedHeader);
}

#[test]
fn chunk_log2_out_of_range() {
    for bad in [0u8, 9, 25, 40] {
        let (mut env, key) = sealed(10);
        env[43] = bad;
        assert_eq!(
            err(&env, &key),
            ErrorCode::ChunkTooLarge,
            "chunk_log2={bad}"
        );
    }
}

#[test]
fn header_tamper_fails_authentication() {
    // Every header byte is folded into every chunk's AAD via header_hash, so
    // flipping any of them must fail even though there is no separate MAC.
    for offset in [8usize, 20, 26, 30, 42] {
        let (mut env, key) = sealed(10);
        env[offset] ^= 0x01;
        assert_eq!(err(&env, &key), ErrorCode::AuthFailed, "offset={offset}");
    }
}

#[test]
fn flipped_tag_byte() {
    let (mut env, key) = sealed(10);
    let last = env.len() - 1;
    env[last] ^= 0x01;
    assert_eq!(err(&env, &key), ErrorCode::AuthFailed);
}

#[test]
fn truncated_at_a_chunk_boundary_reports_truncated_not_auth_failure() {
    // Two chunks; drop the second entirely. The surviving chunk authenticates
    // as non-final, which is how we know data is missing rather than corrupt.
    let (env, key) = sealed(CHUNK + 100);
    let cut = HEADER_LEN + 4 + meta_len(&env) + (CHUNK + TAG_LEN);
    assert_eq!(err(&env[..cut], &key), ErrorCode::Truncated);
}

#[test]
fn truncated_mid_chunk() {
    // Because the expected length is derived from the authenticated metadata,
    // a cut anywhere — not just on a chunk boundary — is reported as missing
    // data rather than as a bad key.
    let (env, key) = sealed(CHUNK + 100);
    assert_eq!(err(&env[..env.len() - 5], &key), ErrorCode::Truncated);
}

#[test]
fn truncated_single_chunk_message() {
    let (env, key) = sealed(10);
    assert_eq!(err(&env[..env.len() - 1], &key), ErrorCode::Truncated);
}

#[test]
fn every_prefix_of_a_valid_envelope_is_rejected() {
    // No prefix of a valid envelope may ever decode successfully. This is the
    // property that stops a partial download from being shown as a complete,
    // shorter message.
    let (env, key) = sealed(2 * CHUNK + 7);
    for cut in (HEADER_LEN..env.len()).step_by(97) {
        assert!(
            open(&env[..cut], &key, NOW).is_err(),
            "prefix of length {cut} decoded successfully"
        );
    }
}

#[test]
fn trailing_data_after_final_chunk() {
    let (mut env, key) = sealed(10);
    env.extend_from_slice(b"extra");
    assert_eq!(err(&env, &key), ErrorCode::TrailingData);
}

#[test]
fn swapped_chunks() {
    let (env, key) = sealed(3 * CHUNK);
    let start = HEADER_LEN + 4 + meta_len(&env);
    let full = CHUNK + TAG_LEN;

    let mut tampered = env.clone();
    let (a, b) = (start, start + full);
    let chunk_a = env[a..a + full].to_vec();
    let chunk_b = env[b..b + full].to_vec();
    tampered[a..a + full].copy_from_slice(&chunk_b);
    tampered[b..b + full].copy_from_slice(&chunk_a);

    assert_eq!(err(&tampered, &key), ErrorCode::AuthFailed);
}

#[test]
fn duplicated_chunk() {
    let (env, key) = sealed(3 * CHUNK);
    let start = HEADER_LEN + 4 + meta_len(&env);
    let full = CHUNK + TAG_LEN;

    let mut tampered = env.clone();
    let first = env[start..start + full].to_vec();
    tampered[start + full..start + 2 * full].copy_from_slice(&first);

    assert_eq!(err(&tampered, &key), ErrorCode::AuthFailed);
}

#[test]
fn meta_length_pointing_outside_the_buffer() {
    let (mut env, key) = sealed(10);
    env[HEADER_LEN..HEADER_LEN + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(err(&env, &key), ErrorCode::MalformedHeader);
}

#[test]
fn envelope_shorter_than_a_header() {
    let (env, key) = sealed(10);
    assert_eq!(err(&env[..20], &key), ErrorCode::MalformedHeader);
}

#[test]
fn mnemonic_with_a_bad_checksum() {
    let key = SecretKey::from_bytes([1u8; 32]);
    let phrase = key.to_mnemonic();
    let mut words: Vec<&str> = phrase.split_whitespace().collect();
    // Swap two words: still all-valid words, but the checksum no longer holds.
    words.swap(0, 1);
    let broken = words.join(" ");
    assert_eq!(
        SecretKey::from_mnemonic(&broken).unwrap_err(),
        ErrorCode::ChecksumFailed
    );
}

#[test]
fn mnemonic_with_a_word_outside_the_list() {
    assert_eq!(
        SecretKey::from_mnemonic("notaword ".repeat(24).trim()).unwrap_err(),
        ErrorCode::KeyDecodeFailed
    );
}

#[test]
fn uri_with_a_bad_crc() {
    let key = SecretKey::from_bytes([2u8; 32]);
    let uri = key.to_uri();
    let mut bytes = uri.into_bytes();
    let last = bytes.len() - 1;
    bytes[last] = if bytes[last] == b'A' { b'B' } else { b'A' };
    let broken = String::from_utf8(bytes).unwrap();

    let e = SecretKey::from_uri(&broken).unwrap_err();
    assert!(
        e == ErrorCode::ChecksumFailed || e == ErrorCode::KeyDecodeFailed,
        "got {e:?}"
    );
}

#[test]
fn uri_without_the_scheme() {
    assert_eq!(
        SecretKey::from_uri("AAAA").unwrap_err(),
        ErrorCode::KeyDecodeFailed
    );
}

/// Read the metadata ciphertext length out of an envelope so tests can locate
/// where the data chunks begin.
fn meta_len(env: &[u8]) -> usize {
    u32::from_le_bytes(env[HEADER_LEN..HEADER_LEN + 4].try_into().unwrap()) as usize
}
