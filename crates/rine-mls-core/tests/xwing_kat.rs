//! Known-answer tests for the X-Wing KEM against the draft's own vectors.
//!
//! This is the fixture that turns a silent dependency change into a loud test
//! failure: if a libcrux, x25519-dalek or SHA-3 bump alters a single byte of
//! key generation, encapsulation or decapsulation, these values stop matching.

mod kat;

use rine_mls_core::xwing;

const FIXTURE: &str = include_str!("kat/xwing-draft06.txt");

#[test]
fn test_encapsulation_key_when_expanded_from_the_seed_matches_the_published_vector() {
    for vector in kat::parse(FIXTURE) {
        let sk = vector.array::<{ xwing::DECAPSULATION_KEY_SIZE }>("sk");

        assert_eq!(
            xwing::encapsulation_key(&sk).as_slice(),
            vector.bytes("pk"),
            "vector {}",
            vector.label,
        );
    }
}

#[test]
fn test_encapsulate_when_given_the_published_randomness_reproduces_ciphertext_and_secret() {
    for vector in kat::parse(FIXTURE) {
        let eseed = vector.array::<{ xwing::ENCAPSULATION_SEED_SIZE }>("eseed");

        let (shared_secret, ciphertext) =
            xwing::encapsulate(vector.bytes("pk"), &eseed).expect("encapsulate");

        assert_eq!(ciphertext.as_slice(), vector.bytes("ct"), "ciphertext");
        assert_eq!(
            shared_secret.as_slice(),
            vector.bytes("ss"),
            "shared secret"
        );
    }
}

#[test]
fn test_decapsulate_when_given_the_published_ciphertext_recovers_the_shared_secret() {
    for vector in kat::parse(FIXTURE) {
        let shared_secret =
            xwing::decapsulate(vector.bytes("ct"), vector.bytes("sk")).expect("decapsulate");

        assert_eq!(
            shared_secret.as_slice(),
            vector.bytes("ss"),
            "vector {}",
            vector.label
        );
    }
}

#[test]
fn test_decapsulate_when_the_ciphertext_is_tampered_with_yields_a_different_secret() {
    // ML-KEM answers a bad ciphertext with an implicit-rejection secret rather
    // than an error, so "decapsulation succeeded" is never proof of anything;
    // agreement on the secret is.
    let vector = &kat::parse(FIXTURE)[0];

    let mut ciphertext = vector.bytes("ct").to_vec();
    ciphertext[0] ^= 0x01;

    let shared_secret =
        xwing::decapsulate(&ciphertext, vector.bytes("sk")).expect("implicit rejection");

    assert_ne!(shared_secret.as_slice(), vector.bytes("ss"));
}

#[test]
fn test_validate_encapsulation_key_when_the_key_is_published_accepts_it() {
    for vector in kat::parse(FIXTURE) {
        xwing::validate_encapsulation_key(vector.bytes("pk")).expect("published key is valid");
    }
}

#[test]
fn test_validate_encapsulation_key_when_the_ml_kem_half_is_not_reduced_rejects_it() {
    // ML-KEM encapsulation keys are only valid if their 12-bit coefficients
    // re-encode to the same bytes; 0xFF everywhere does not.
    let mut key = kat::parse(FIXTURE)[0].bytes("pk").to_vec();
    key[..1184].fill(0xFF);

    assert!(xwing::validate_encapsulation_key(&key).is_err());
}
