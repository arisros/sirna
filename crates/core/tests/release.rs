//! Custody-mode key release.
//!
//! The relay carrying these bytes is untrusted by design, so the tests are
//! written from its point of view: what can a relay that sees everything and
//! can substitute anything actually achieve?

use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sirna_core::{
    open, seal, seal_release, short_auth_string, verify_receipt, ErrorCode, OwnerIdentity,
    ReaderSession, SealOptions, SecretKey,
};

const NOW: u64 = 1_800_000_000;
const BLOB: &[u8] = b"4d116cb02cf3edcc20651005bfcd2af8";

fn rng(seed: u64) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(seed)
}

#[test]
fn the_reader_recovers_the_key_and_opens_the_message() {
    let mut r = rng(1);
    let (envelope, key) = seal(
        b"released to one reader",
        &SealOptions::default(),
        &mut r,
        NOW,
    )
    .unwrap();

    let reader = ReaderSession::generate(&mut rng(2));
    let sealed = seal_release(&key, &reader.public_key(), BLOB, &mut rng(3)).unwrap();

    let recovered = reader.open_release(&sealed, BLOB).unwrap();
    assert_eq!(recovered.as_bytes(), key.as_bytes());

    let opened = open(&envelope, &recovered, NOW).unwrap();
    assert_eq!(opened.plaintext, b"released to one reader");
}

#[test]
fn the_release_reveals_nothing_to_the_relay() {
    let mut r = rng(4);
    let key = SecretKey::generate(&mut r);
    let reader = ReaderSession::generate(&mut rng(5));
    let sealed = seal_release(&key, &reader.public_key(), BLOB, &mut rng(6)).unwrap();

    // Everything the relay sees, and the key is not in it.
    assert!(
        !sealed.windows(32).any(|w| w == key.as_bytes()),
        "the message key appears in plaintext inside the release"
    );
}

#[test]
fn a_relay_that_substitutes_the_reader_gets_nothing() {
    // The relay's best attack: hand the owner its own public key instead of the
    // reader's, take the release, and try to open it. It works — but only for a
    // key it substituted, which is exactly what the SAS is there to reveal.
    let mut r = rng(7);
    let key = SecretKey::generate(&mut r);

    let real_reader = ReaderSession::generate(&mut rng(8));
    let impostor = ReaderSession::generate(&mut rng(9));

    let sealed = seal_release(&key, &impostor.public_key(), BLOB, &mut rng(10)).unwrap();

    // The real reader cannot open a release addressed to someone else.
    assert_eq!(
        real_reader.open_release(&sealed, BLOB).unwrap_err(),
        ErrorCode::AuthFailed
    );

    // And the substitution changes the SAS, which is how a human notices.
    let owner_pub = [9u8; 32];
    assert_ne!(
        short_auth_string(&real_reader.public_key(), &owner_pub, BLOB),
        short_auth_string(&impostor.public_key(), &owner_pub, BLOB),
        "a substituted reader must change the digits shown on both screens"
    );
}

#[test]
fn a_release_is_bound_to_its_message() {
    // Replaying a release under a different blob id must fail, or a relay could
    // reuse one grant to unlock a different message.
    let mut r = rng(11);
    let key = SecretKey::generate(&mut r);
    let reader = ReaderSession::generate(&mut rng(12));
    let sealed = seal_release(&key, &reader.public_key(), BLOB, &mut rng(13)).unwrap();

    assert_eq!(
        reader
            .open_release(&sealed, b"a different blob id here")
            .unwrap_err(),
        ErrorCode::AuthFailed
    );
}

#[test]
fn tampering_with_any_byte_of_a_release_is_detected() {
    let mut r = rng(14);
    let key = SecretKey::generate(&mut r);
    let reader = ReaderSession::generate(&mut rng(15));
    let sealed = seal_release(&key, &reader.public_key(), BLOB, &mut rng(16)).unwrap();

    for i in [0usize, 31, 32, 55, 56, sealed.len() - 1] {
        let mut bad = sealed.clone();
        bad[i] ^= 0x01;
        assert!(
            reader.open_release(&bad, BLOB).is_err(),
            "a flipped bit at offset {i} was not detected"
        );
    }
}

#[test]
fn a_truncated_release_is_refused_before_any_crypto() {
    let reader = ReaderSession::generate(&mut rng(17));
    assert!(reader.open_release(&[0u8; 10], BLOB).is_err());
    assert!(reader.open_release(&[], BLOB).is_err());
}

#[test]
fn the_sas_is_five_digits_and_stable() {
    let a = [1u8; 32];
    let b = [2u8; 32];

    let sas = short_auth_string(&a, &b, BLOB);
    assert_eq!(sas.len(), 5);
    assert!(sas.chars().all(|c| c.is_ascii_digit()));
    // Both screens must derive the same string from the same inputs, every time.
    assert_eq!(sas, short_auth_string(&a, &b, BLOB));

    // Order matters: reader and owner are not interchangeable.
    assert_ne!(sas, short_auth_string(&b, &a, BLOB));
}

#[test]
fn a_shred_receipt_cannot_be_forged_by_the_relay() {
    // "It has been destroyed" is the one claim this product exists to make. A
    // relay that could fabricate it could tell a reader their copy is dead
    // while quietly keeping the key alive.
    let owner = OwnerIdentity::generate(&mut rng(18));
    let at = NOW + 60;
    let sig = owner.sign_receipt(BLOB, at);

    assert!(verify_receipt(&owner.public_key(), BLOB, at, &sig));

    // Someone else's identity does not verify.
    let other = OwnerIdentity::generate(&mut rng(19));
    assert!(!verify_receipt(&other.public_key(), BLOB, at, &sig));

    // Nor does the same signature moved onto another message or another time.
    assert!(!verify_receipt(
        &owner.public_key(),
        b"another blob id here!!!!!!!!!!!!!",
        at,
        &sig
    ));
    assert!(!verify_receipt(&owner.public_key(), BLOB, at + 1, &sig));
}

#[test]
fn an_identity_survives_being_reloaded_from_its_seed() {
    let seed = [7u8; 32];
    let a = OwnerIdentity::from_seed(&seed);
    let b = OwnerIdentity::from_seed(&seed);
    assert_eq!(a.public_key(), b.public_key());
    assert_eq!(a.sign_receipt(BLOB, NOW), b.sign_receipt(BLOB, NOW));
}
