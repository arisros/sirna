//! Property tests.
//!
//! Hand-written cases cover the boundaries someone thought of. These cover the
//! ones nobody did — in particular the interaction between arbitrary payload
//! lengths and arbitrary chunk sizes, which is where off-by-one errors in
//! chunked formats actually live.

use proptest::prelude::*;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sirna_core::{open, seal, SealOptions, SecretKey};

const NOW: u64 = 1_800_000_000;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn roundtrip_any_length_any_chunk_size(
        data in prop::collection::vec(any::<u8>(), 0..8192),
        chunk_log2 in 10u8..=13,
        seed in any::<u64>(),
    ) {
        let opts = SealOptions { chunk_log2: Some(chunk_log2), ..Default::default() };
        let mut rng = ChaCha20Rng::seed_from_u64(seed);

        let (env, key) = seal(&data, &opts, &mut rng, NOW).unwrap();
        let got = open(&env, &key, NOW).unwrap();

        prop_assert_eq!(got.plaintext, data);
    }

    #[test]
    fn no_prefix_of_a_valid_envelope_ever_opens(
        data in prop::collection::vec(any::<u8>(), 1..4096),
        cut_ratio in 0.0f64..1.0,
    ) {
        let opts = SealOptions { chunk_log2: Some(10), ..Default::default() };
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let (env, key) = seal(&data, &opts, &mut rng, NOW).unwrap();

        let cut = (env.len() as f64 * cut_ratio) as usize;
        prop_assume!(cut < env.len());

        prop_assert!(open(&env[..cut], &key, NOW).is_err());
    }

    #[test]
    fn flipping_any_single_bit_is_always_detected(
        data in prop::collection::vec(any::<u8>(), 1..1024),
        byte_ratio in 0.0f64..1.0,
        bit in 0u8..8,
    ) {
        let opts = SealOptions { chunk_log2: Some(10), ..Default::default() };
        let mut rng = ChaCha20Rng::seed_from_u64(11);
        let (mut env, key) = seal(&data, &opts, &mut rng, NOW).unwrap();

        let idx = ((env.len() - 1) as f64 * byte_ratio) as usize;
        env[idx] ^= 1 << bit;

        // Never a silent wrong answer: either it is rejected, or the bit landed
        // somewhere with no effect on the decoded output.
        match open(&env, &key, NOW) {
            Err(_) => {}
            Ok(got) => prop_assert_eq!(got.plaintext, data),
        }
    }

    #[test]
    fn appending_any_bytes_is_always_detected(
        data in prop::collection::vec(any::<u8>(), 0..2048),
        extra in prop::collection::vec(any::<u8>(), 1..64),
    ) {
        let opts = SealOptions { chunk_log2: Some(10), ..Default::default() };
        let mut rng = ChaCha20Rng::seed_from_u64(13);
        let (mut env, key) = seal(&data, &opts, &mut rng, NOW).unwrap();
        env.extend_from_slice(&extra);

        prop_assert!(open(&env, &key, NOW).is_err());
    }

    #[test]
    fn key_encodings_survive_any_key(seed in any::<u64>()) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let key = SecretKey::generate(&mut rng);

        prop_assert_eq!(SecretKey::from_mnemonic(&key.to_mnemonic()).unwrap(), key.clone());
        prop_assert_eq!(SecretKey::from_uri(&key.to_uri()).unwrap(), key);
    }
}
