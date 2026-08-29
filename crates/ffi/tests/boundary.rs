//! The FFI boundary itself. The deep behaviour is covered by the core suite and
//! the shared vector corpus; what matters here is that types survive the
//! crossing and that errors arrive carrying the canonical code.

use sirna_ffi::*;

const NOW: u64 = 1_800_000_000;

fn code_of(e: SirnaError) -> u8 {
    let SirnaError::Failed { code, .. } = e;
    code
}

#[test]
fn seal_and_open_across_the_boundary() {
    let sealed = seal_bytes(
        b"across the boundary".to_vec(),
        Some("note.txt".into()),
        Some("text/plain".into()),
        0,
        NOW,
    )
    .unwrap();

    // Both key encodings must work, since one input box accepts either.
    let by_words = open_envelope(sealed.envelope.clone(), sealed.mnemonic.clone(), NOW).unwrap();
    let by_uri = open_envelope(sealed.envelope.clone(), sealed.uri.clone(), NOW).unwrap();

    assert_eq!(by_words.plaintext, b"across the boundary");
    assert_eq!(by_uri.plaintext, by_words.plaintext);
    assert_eq!(by_words.filename.as_deref(), Some("note.txt"));
    assert!(by_words.is_file);
}

#[test]
fn raw_key_bytes_round_trip() {
    // The custody path: Kotlin holds the key in Keystore and hands the bytes
    // in only for the moment of a call.
    let sealed = seal_bytes(b"custody".to_vec(), None, None, 0, NOW).unwrap();
    assert_eq!(sealed.key.len(), 32);

    let again =
        open_envelope_with_key_bytes(sealed.envelope.clone(), sealed.key.clone(), NOW).unwrap();
    assert_eq!(again.plaintext, b"custody");

    // And the bytes must agree with the words shown on screen.
    assert_eq!(
        key_to_mnemonic(sealed.key.clone()).unwrap(),
        sealed.mnemonic
    );
    assert_eq!(key_from_text(sealed.mnemonic).unwrap(), sealed.key);
}

#[test]
fn errors_carry_the_canonical_code() {
    let a = seal_bytes(b"one".to_vec(), None, None, 0, NOW).unwrap();
    let b = seal_bytes(b"two".to_vec(), None, None, 0, NOW).unwrap();

    // `Opened` has no Debug on purpose — it holds plaintext — so unwrap_err()
    // is not available and the result is matched instead.
    let e = match open_envelope(a.envelope, b.mnemonic, NOW) {
        Err(e) => e,
        Ok(_) => panic!("a wrong key must not open the envelope"),
    };
    assert_eq!(code_of(e), 5, "wrong key must be code 5 on every target");

    let e = match open_envelope_with_key_bytes(vec![0u8; 100], vec![0u8; 31], NOW) {
        Err(e) => e,
        Ok(_) => panic!("a 31-byte key must be refused"),
    };
    assert_eq!(code_of(e), 11, "a malformed key must be code 11");
}

#[test]
fn passphrase_mode_crosses_too() {
    let env =
        seal_bytes_with_passphrase(b"x".to_vec(), "phrase".into(), None, None, 0, NOW).unwrap();
    let got = open_envelope_with_passphrase(env, "phrase".into(), NOW).unwrap();
    assert_eq!(got.plaintext, b"x");
}

#[test]
fn the_binding_reports_the_same_format_version() {
    assert_eq!(format_version(), sirna_core::FORMAT_VERSION);
}
