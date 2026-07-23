//! Cross-validation of rine's X-Wing against a second, independent
//! implementation (the RustCrypto `x-wing` crate, a development dependency
//! that never ships).
//!
//! The two share no code: rine's runs on libcrux ML-KEM and libcrux SHA-3,
//! RustCrypto's on its own ML-KEM and its own SHA-3. What they must share is
//! every byte on the wire. The load-bearing cases are the crossed ones — one
//! side encapsulates, the other decapsulates — because those are the only ones
//! that can catch a combiner that is self-consistently wrong.
//!
//! If these ever disagree, the working assumption is that rine's side is wrong.

use rine_mls_core::xwing;
use x_wing::{
    Decapsulate, DecapsulationKey, Decapsulator, EncapsulationKey, KeyExport, TryKeyInit,
};

fn reference_key(sk: [u8; xwing::DECAPSULATION_KEY_SIZE]) -> DecapsulationKey {
    DecapsulationKey::from(sk)
}

/// Deterministic, distinct seeds. Nothing here needs unpredictability: the
/// property under test is agreement, and a fixed seed makes a failure
/// reproducible.
fn seeds() -> impl Iterator<Item = [u8; xwing::DECAPSULATION_KEY_SIZE]> {
    (1u8..=8).map(|i| {
        let mut seed = [0u8; xwing::DECAPSULATION_KEY_SIZE];
        seed.iter_mut()
            .enumerate()
            .for_each(|(j, b)| *b = i.wrapping_mul(31).wrapping_add(j as u8));
        seed
    })
}

fn encapsulation_seeds() -> impl Iterator<Item = [u8; xwing::ENCAPSULATION_SEED_SIZE]> {
    (1u8..=8).map(|i| {
        let mut seed = [0u8; xwing::ENCAPSULATION_SEED_SIZE];
        seed.iter_mut()
            .enumerate()
            .for_each(|(j, b)| *b = i.wrapping_mul(17).wrapping_add(j as u8));
        seed
    })
}

#[test]
fn test_encapsulation_key_when_derived_from_the_same_seed_is_byte_identical() {
    for seed in seeds() {
        assert_eq!(
            xwing::encapsulation_key(&seed).as_slice(),
            &*reference_key(seed).encapsulation_key().to_bytes(),
        );
    }
}

#[test]
fn test_encapsulate_when_given_the_same_randomness_produces_identical_bytes() {
    for (seed, eseed) in seeds().zip(encapsulation_seeds()) {
        let public_key = xwing::encapsulation_key(&seed);

        let (ours_ss, ours_ct) = xwing::encapsulate(&public_key, &eseed).expect("encapsulate");
        let (theirs_ct, theirs_ss) = EncapsulationKey::new_from_slice(&public_key)
            .expect("reference key")
            .encapsulate_deterministic(&eseed.into());

        assert_eq!(ours_ct.as_slice(), &*theirs_ct, "ciphertext");
        assert_eq!(ours_ss.as_slice(), &*theirs_ss, "shared secret");
    }
}

#[test]
fn test_decapsulate_when_the_reference_encapsulated_recovers_the_same_secret() {
    for (seed, eseed) in seeds().zip(encapsulation_seeds()) {
        let reference = reference_key(seed);
        let (ciphertext, expected) = reference
            .encapsulation_key()
            .encapsulate_deterministic(&eseed.into());

        let ours = xwing::decapsulate(&ciphertext, &seed).expect("decapsulate");

        assert_eq!(ours.as_slice(), &*expected);
    }
}

#[test]
fn test_reference_decapsulate_when_rine_encapsulated_recovers_the_same_secret() {
    for (seed, eseed) in seeds().zip(encapsulation_seeds()) {
        let reference = reference_key(seed);
        let public_key = xwing::encapsulation_key(&seed);

        let (expected, ciphertext) = xwing::encapsulate(&public_key, &eseed).expect("encapsulate");
        let theirs = reference.decapsulate(&ciphertext.into());

        assert_eq!(expected.as_slice(), &*theirs);
    }
}

#[test]
fn test_derive_key_pair_when_seeded_identically_agrees_with_the_reference() {
    // rine's HPKE key derivation condenses the input with SHAKE-256 before
    // expanding it; the reference crate has no such entry point, so the check
    // is that the derived seed still produces the reference's key pair.
    for ikm in seeds() {
        let (secret, public) = xwing::derive_key_pair(&ikm);

        assert_eq!(
            &*reference_key(*secret).encapsulation_key().to_bytes(),
            public.as_slice(),
        );
    }
}
