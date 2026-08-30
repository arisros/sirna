//! Custody mode: releasing a message key to one reader, once.
//!
//! In handoff mode the key travels as words and the sender cannot take it back.
//! Custody mode keeps the key on the owner's device — in a secure element on a
//! phone — and releases it to a specific reader at read time, after which the
//! owner destroys it. That is what makes revocation real, and it is why this
//! module exists.
//!
//! Everything here is carried by a relay that is **explicitly untrusted**. The
//! relay is a pair of sockets and a lookup table; it can drop messages, replay
//! them, or try to stand in for the reader. What it must not be able to do is
//! learn the key or convince the owner it is someone it is not, and that is
//! what the construction below is for.
//!
//! Both halves must agree byte for byte across every client, so this lives in
//! `core` alongside the envelope and is covered by the same vector corpus. A
//! SAS that differs between a phone and a browser is not a cosmetic bug: it
//! trains people to ignore the one check that stops an impersonating relay.

use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::error::{ErrorCode, Result};
use crate::key::SecretKey;

/// A reader's one-time X25519 keypair. Generated per read attempt and dropped
/// afterwards, so a key released for one attempt cannot open a later one.
pub struct ReaderSession {
    secret: x25519_dalek::StaticSecret,
    public: x25519_dalek::PublicKey,
}

impl ReaderSession {
    pub fn generate(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let secret = x25519_dalek::StaticSecret::from(bytes);
        bytes.zeroize();
        let public = x25519_dalek::PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// Recover the message key from what the owner sent.
    pub fn open_release(&self, sealed: &[u8], blob_id: &[u8]) -> Result<SecretKey> {
        if sealed.len() != SEALED_LEN {
            return Err(ErrorCode::MalformedHeader);
        }

        let mut eph = [0u8; 32];
        eph.copy_from_slice(&sealed[0..32]);
        let eph_pub = x25519_dalek::PublicKey::from(eph);

        let mut shared = self.secret.diffie_hellman(&eph_pub).to_bytes();
        let mut wrapping = derive_wrapping_key(&shared, &eph, &self.public_key(), blob_id);
        shared.zeroize();

        let plain = crate::envelope::aead_open(
            &wrapping,
            &sealed[32..56],
            &sealed[56..],
            &release_aad(&eph, &self.public_key(), blob_id),
        )?;
        wrapping.zeroize();

        let bytes: [u8; 32] = plain
            .as_slice()
            .try_into()
            .map_err(|_| ErrorCode::KeyDecodeFailed)?;
        Ok(SecretKey::from_bytes(bytes))
    }
}

/// 32-byte ephemeral public key, 24-byte nonce, 32-byte key plus a 16-byte tag.
pub const SEALED_LEN: usize = 32 + 24 + 32 + 16;

/// Seal the message key to one reader's public key.
///
/// A fresh ephemeral keypair per release means the same message released twice
/// — which should never happen, but might during development — does not reuse a
/// shared secret.
pub fn seal_release(
    key: &SecretKey,
    reader_pub: &[u8; 32],
    blob_id: &[u8],
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Vec<u8>> {
    let mut eph_bytes = [0u8; 32];
    rng.fill_bytes(&mut eph_bytes);
    let eph_secret = x25519_dalek::StaticSecret::from(eph_bytes);
    eph_bytes.zeroize();

    let eph_pub = x25519_dalek::PublicKey::from(&eph_secret).to_bytes();
    let mut shared = eph_secret
        .diffie_hellman(&x25519_dalek::PublicKey::from(*reader_pub))
        .to_bytes();
    let mut wrapping = derive_wrapping_key(&shared, &eph_pub, reader_pub, blob_id);
    shared.zeroize();

    let mut nonce = [0u8; 24];
    rng.fill_bytes(&mut nonce);

    let ct = crate::envelope::aead_seal(
        &wrapping,
        &nonce,
        key.as_bytes(),
        &release_aad(&eph_pub, reader_pub, blob_id),
    )?;
    wrapping.zeroize();

    let mut out = Vec::with_capacity(SEALED_LEN);
    out.extend_from_slice(&eph_pub);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Both public keys and the blob id go into the derivation, so a release is
/// bound to this reader and this message. A relay that swaps either produces a
/// key that does not decrypt rather than one that silently works.
fn derive_wrapping_key(
    shared: &[u8; 32],
    eph_pub: &[u8; 32],
    reader_pub: &[u8; 32],
    blob_id: &[u8],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("sirna v1 key release");
    h.update(shared);
    h.update(eph_pub);
    h.update(reader_pub);
    h.update(blob_id);
    *h.finalize().as_bytes()
}

fn release_aad(eph_pub: &[u8; 32], reader_pub: &[u8; 32], blob_id: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(64 + blob_id.len());
    aad.extend_from_slice(eph_pub);
    aad.extend_from_slice(reader_pub);
    aad.extend_from_slice(blob_id);
    aad
}

/// The short authentication string: five digits shown on both screens.
///
/// This is the only thing standing between the owner and a relay pretending to
/// be the reader, and it works by a human comparing two numbers. Five digits is
/// a deliberate compromise — one in a hundred thousand for an attacker who gets
/// exactly one attempt, and short enough that someone will actually read it
/// aloud. Making it longer would raise the odds on paper and lower them in
/// practice, because people skip what is tedious.
///
/// Derived from both public keys and the blob id, so it changes if the relay
/// substitutes either side.
pub fn short_auth_string(reader_pub: &[u8; 32], owner_pub: &[u8; 32], blob_id: &[u8]) -> String {
    let mut h = blake3::Hasher::new_derive_key("sirna v1 sas");
    h.update(reader_pub);
    h.update(owner_pub);
    h.update(blob_id);

    let digest = h.finalize();
    let n = u32::from_be_bytes(digest.as_bytes()[0..4].try_into().unwrap()) % 100_000;
    format!("{n:05}")
}

/// The owner's long-term identity. Signs shred receipts so the relay cannot
/// fabricate one — a forged "it has been destroyed" would be a lie about the
/// one thing this product promises.
pub struct OwnerIdentity {
    signing: ed25519_dalek::SigningKey,
}

impl OwnerIdentity {
    pub fn generate(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        seed.zeroize();
        Self { signing }
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            signing: ed25519_dalek::SigningKey::from_bytes(seed),
        }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn sign_receipt(&self, blob_id: &[u8], shredded_at: u64) -> [u8; 64] {
        use ed25519_dalek::Signer;
        self.signing
            .sign(&receipt_message(blob_id, shredded_at))
            .to_bytes()
    }
}

pub fn verify_receipt(
    owner_pub: &[u8; 32],
    blob_id: &[u8],
    shredded_at: u64,
    signature: &[u8; 64],
) -> bool {
    use ed25519_dalek::Verifier;
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(owner_pub) else {
        return false;
    };
    vk.verify(
        &receipt_message(blob_id, shredded_at),
        &ed25519_dalek::Signature::from_bytes(signature),
    )
    .is_ok()
}

fn receipt_message(blob_id: &[u8], shredded_at: u64) -> Vec<u8> {
    // Domain-separated so a signature over a receipt can never be replayed as a
    // signature over anything else this identity might sign later.
    let mut m = Vec::with_capacity(24 + blob_id.len());
    m.extend_from_slice(b"sirna v1 shred receipt\n");
    m.extend_from_slice(blob_id);
    m.extend_from_slice(&shredded_at.to_be_bytes());
    m
}
