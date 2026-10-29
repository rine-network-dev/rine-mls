//! The raw ML-KEM-768 surface the `hpke-hybrid-v2` DM envelope is built from.
//!
//! Cross-stack agreement with `@noble/post-quantum` is proven where it can
//! actually be observed — the Python SDK decrypts committed TypeScript
//! ciphertext in `rine-sdk/tests/test_crypto/test_hybrid.py`. What is pinned
//! here is what only this side can see: the FIPS 203 sizes the SDK's length
//! checks read, the embedded-public-key layout `public_key` relies on, and the
//! refusals a caller is entitled to get instead of a panic.

use rine_mls_core::mlkem;

#[test]
fn test_encapsulate_when_answered_by_decapsulate_agrees_on_the_shared_secret() {
    let (private_key, public_key) = mlkem::generate_key_pair().expect("keygen");
    let (ciphertext, sent) = mlkem::encapsulate(&public_key).expect("encapsulate");

    let received = mlkem::decapsulate(&ciphertext, private_key.as_slice()).expect("decapsulate");

    assert_eq!(sent.as_slice(), received.as_slice());
}

#[test]
fn test_key_pair_when_generated_has_the_fips_203_sizes_the_wire_format_assumes() {
    let (private_key, public_key) = mlkem::generate_key_pair().expect("keygen");
    let (ciphertext, secret) = mlkem::encapsulate(&public_key).expect("encapsulate");

    assert_eq!(private_key.len(), mlkem::PRIVATE_KEY_SIZE);
    assert_eq!(public_key.len(), mlkem::PUBLIC_KEY_SIZE);
    assert_eq!(ciphertext.len(), mlkem::CIPHERTEXT_SIZE);
    assert_eq!(secret.len(), mlkem::SHARED_SECRET_SIZE);
}

#[test]
fn test_public_key_when_read_off_a_private_key_matches_the_one_keygen_returned() {
    let (private_key, public_key) = mlkem::generate_key_pair().expect("keygen");

    assert_eq!(
        mlkem::public_key(private_key.as_slice()).expect("recover"),
        public_key
    );
}

#[test]
fn test_public_key_when_the_private_key_was_corrupted_is_refused_not_published() {
    let (private_key, _) = mlkem::generate_key_pair().expect("keygen");
    let mut corrupt = private_key.to_vec();
    // Flip a bit inside the embedded public key: the private key's own H(ek) no
    // longer matches, which is the only way this layer can notice.
    corrupt[1200] ^= 0x01;

    assert!(matches!(
        mlkem::public_key(&corrupt),
        Err(mlkem::MlKemError::MalformedKey),
    ));
}

#[test]
fn test_decapsulate_when_given_the_wrong_key_yields_a_different_secret_rather_than_failing() {
    // FIPS 203 implicit rejection: there is no "wrong key" error to return, so
    // the SDK's AEAD is what refuses. Pinned so nobody adds a check that the
    // standard says cannot exist.
    let (_, public_key) = mlkem::generate_key_pair().expect("keygen");
    let (other_private, _) = mlkem::generate_key_pair().expect("keygen");
    let (ciphertext, sent) = mlkem::encapsulate(&public_key).expect("encapsulate");

    let received =
        mlkem::decapsulate(&ciphertext, other_private.as_slice()).expect("implicit rejection");

    assert_ne!(sent.as_slice(), received.as_slice());
}

#[test]
fn test_every_input_when_the_wrong_length_is_refused_with_the_length_it_got() {
    let (private_key, public_key) = mlkem::generate_key_pair().expect("keygen");
    let (ciphertext, _) = mlkem::encapsulate(&public_key).expect("encapsulate");

    assert!(matches!(
        mlkem::encapsulate(&public_key[..10]),
        Err(mlkem::MlKemError::PublicKeyLength(10)),
    ));
    assert!(matches!(
        mlkem::public_key(&private_key[..10]),
        Err(mlkem::MlKemError::PrivateKeyLength(10)),
    ));
    assert!(matches!(
        mlkem::decapsulate(&ciphertext[..10], private_key.as_slice()),
        Err(mlkem::MlKemError::CiphertextLength(10)),
    ));
    assert!(matches!(
        mlkem::decapsulate(&ciphertext, &private_key[..10]),
        Err(mlkem::MlKemError::PrivateKeyLength(10)),
    ));
}

#[test]
fn test_encapsulate_when_the_public_key_is_not_a_valid_encoding_is_refused() {
    // Right length, invalid ML-KEM encoding: the modulus check libcrux runs is
    // what catches it.
    assert!(matches!(
        mlkem::encapsulate(&[0xff; mlkem::PUBLIC_KEY_SIZE]),
        Err(mlkem::MlKemError::MalformedKey),
    ));
}
