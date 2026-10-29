//! Seeded ML-KEM-768 and ML-DSA-65 keys, as the org-root tree derives them.
//!
//! The expected digests are SHA3-256 (what `libcrux_sha3::sha256` computes, and
//! the hash FIPS 203 itself uses), taken from `@noble/post-quantum` 0.6.1 run on
//! the same seeds (`ml_kem768.keygen(seed)` and `ml_dsa65.keygen(seed)`), so each
//! assertion is a cross-implementation known answer: libcrux here, noble there,
//! no code in common. The ML-KEM seed is `d‖z` with `d` first, the ACVP layout.

use rine_mls_core::mldsa;
use rine_mls_core::mlkem;

const KEM_SK_SHA3: &str = "1149f17c3c4ac6ab1e3e2d9d8bd0171355ac0fa31bb8855c48ceade874c0864b";
const KEM_PK_SHA3: &str = "a24e16d8f8f9383a95b77050f4d9fd2f5733eec1d63ef3c23ebf9918173669a7";
const DSA_PK_SHA3: &str = "77ebb80eff73ebfcddaf558b84c6bc1fc4b6b0e5cf0d986ee24ed70841329351";

fn sha3_hex(bytes: &[u8]) -> String {
    hex::encode(libcrux_sha3::sha256(bytes))
}

fn kem_seed() -> Vec<u8> {
    (0..64).collect()
}

fn dsa_seed() -> Vec<u8> {
    (0..32).map(|i| 0xa0 + i).collect()
}

#[test]
fn test_ml_kem_key_pair_from_seed_when_given_a_fixed_seed_matches_the_noble_known_answer() {
    let (private_key, public_key) = mlkem::key_pair_from_seed(&kem_seed()).expect("keygen");

    assert_eq!(sha3_hex(&public_key), KEM_PK_SHA3);
    assert_eq!(sha3_hex(private_key.as_slice()), KEM_SK_SHA3);
}

#[test]
fn test_ml_kem_key_pair_from_seed_when_repeated_returns_the_same_key_pair() {
    let first = mlkem::key_pair_from_seed(&kem_seed()).expect("keygen");
    let second = mlkem::key_pair_from_seed(&kem_seed()).expect("keygen");

    assert_eq!(first.0.as_slice(), second.0.as_slice());
    assert_eq!(first.1, second.1);
}

#[test]
fn test_ml_kem_key_pair_from_seed_when_used_to_decapsulate_agrees_with_encapsulation() {
    let (private_key, public_key) = mlkem::key_pair_from_seed(&kem_seed()).expect("keygen");
    let (ciphertext, sent) = mlkem::encapsulate(&public_key).expect("encapsulate");

    let received = mlkem::decapsulate(&ciphertext, private_key.as_slice()).expect("decapsulate");

    assert_eq!(sent.as_slice(), received.as_slice());
    assert_eq!(
        mlkem::public_key(private_key.as_slice()).expect("recover"),
        public_key
    );
}

#[test]
fn test_ml_kem_key_pair_from_seed_when_the_seed_is_not_64_bytes_is_refused() {
    for len in [0, 32, 63, 65] {
        let err = mlkem::key_pair_from_seed(&vec![7u8; len]).expect_err("wrong length");

        assert!(matches!(err, mlkem::MlKemError::SeedLength(got) if got == len));
    }
}

#[test]
fn test_ml_dsa_public_key_from_seed_when_given_a_fixed_seed_matches_the_noble_known_answer() {
    let public_key = mldsa::public_key_from_seed(&dsa_seed()).expect("keygen");

    assert_eq!(public_key.len(), mldsa::PUBLIC_KEY_SIZE);
    assert_eq!(mldsa::PUBLIC_KEY_SIZE, 1952);
    assert_eq!(sha3_hex(&public_key), DSA_PK_SHA3);
}

#[test]
fn test_ml_dsa_public_key_from_seed_when_the_seed_changes_returns_a_different_key() {
    let mut other = dsa_seed();
    other[0] ^= 1;

    assert_ne!(
        mldsa::public_key_from_seed(&dsa_seed()).expect("keygen"),
        mldsa::public_key_from_seed(&other).expect("keygen")
    );
}

#[test]
fn test_ml_dsa_public_key_from_seed_when_the_seed_is_not_32_bytes_is_refused() {
    for len in [0, 31, 33, 64] {
        assert!(mldsa::public_key_from_seed(&vec![7u8; len]).is_err());
    }
}
