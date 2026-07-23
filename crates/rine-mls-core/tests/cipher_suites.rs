//! What rine's two ciphersuites are, at the code-point and primitive level.
//!
//! Three things are checked here that no group-flow test can catch: that the
//! post-quantum suite really sits at the private-use code point and not at the
//! withdrawn draft's, that the primitives underneath it are the ones claimed,
//! and that adding it left the classical suite bit-for-bit identical to the one
//! mls-rs ships.

mod common;
mod kat;

use common::{group_id, TestAgent};
use mls_rs::MlsMessage;
use mls_rs_core::crypto::{CipherSuite, CipherSuiteProvider, CryptoProvider};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;
use rine_mls_core::{xwing, RineCipherSuite, RineCryptoProvider, XWING_KEM_ID};

const FIXTURE: &str = include_str!("kat/rine-suite-f057.txt");

/// The code point the withdrawn X-Wing MLS draft used. It is back in the
/// standards-track range and can be assigned to a different suite, so rine must
/// never emit it.
const WITHDRAWN_DRAFT_CODE_POINT: u16 = 0x004D;

fn provider(suite: RineCipherSuite) -> impl CipherSuiteProvider {
    RineCryptoProvider
        .cipher_suite_provider(CipherSuite::new(suite.id()))
        .expect("rine supports its own suites")
}

#[test]
fn test_post_quantum_suite_when_identified_is_the_private_use_point_not_the_withdrawn_draft() {
    assert_eq!(RineCipherSuite::XWing.id(), 0xF057);
    assert_ne!(RineCipherSuite::XWing.id(), WITHDRAWN_DRAFT_CODE_POINT);
    assert_eq!(XWING_KEM_ID, 0xF057);

    assert!(RineCipherSuite::XWing.is_post_quantum());
    assert!(!RineCipherSuite::Classical.is_post_quantum());
    assert_eq!(RineCipherSuite::Classical.id(), 0x0001);

    assert_eq!(
        RineCipherSuite::try_from(WITHDRAWN_DRAFT_CODE_POINT),
        Err(WITHDRAWN_DRAFT_CODE_POINT),
        "the withdrawn code point must not resolve to a rine suite",
    );

    for suite in RineCipherSuite::ALL {
        assert_eq!(RineCipherSuite::try_from(suite.id()), Ok(suite));
    }
}

#[test]
fn test_key_package_when_minted_carries_the_suite_id_on_the_wire() {
    for suite in RineCipherSuite::ALL {
        let key_package = TestAgent::new(1, suite)
            .client
            .generate_key_package()
            .expect("key package");

        assert_eq!(
            MlsMessage::from_bytes(&key_package)
                .expect("decode")
                .cipher_suite(),
            Some(CipherSuite::new(suite.id())),
        );

        // The same value, read straight off the encoded message: protocol
        // version, wire format and the KeyPackage's own version come first, so
        // the ciphersuite is the fourth 16-bit field. Reading it as bytes is
        // the check that nothing is remapping the id on its way out.
        assert_eq!(
            u16::from_be_bytes([key_package[6], key_package[7]]),
            suite.id(),
        );
        assert_ne!(
            u16::from_be_bytes([key_package[6], key_package[7]]),
            WITHDRAWN_DRAFT_CODE_POINT,
        );
    }
}

#[test]
fn test_group_when_created_on_the_post_quantum_suite_reports_that_suite() {
    let alice = TestAgent::new(1, RineCipherSuite::XWing);

    alice
        .client
        .create_group(&group_id(0xF0))
        .expect("post-quantum group");

    assert_eq!(alice.client.cipher_suite(), RineCipherSuite::XWing);
}

#[test]
fn test_provider_when_asked_for_an_unknown_suite_refuses_it() {
    for unknown in [
        WITHDRAWN_DRAFT_CODE_POINT,
        CipherSuite::CURVE25519_CHACHA.raw_value(),
        CipherSuite::P256_AES128.raw_value(),
    ] {
        assert!(
            RineCryptoProvider
                .cipher_suite_provider(CipherSuite::new(unknown))
                .is_none(),
            "0x{unknown:04X} is not a rine suite",
        );
    }

    assert_eq!(
        RineCryptoProvider.supported_cipher_suites(),
        RineCipherSuite::ALL
            .iter()
            .map(|s| CipherSuite::new(s.id()))
            .collect::<Vec<_>>(),
    );
}

#[test]
fn test_post_quantum_suite_when_exercised_matches_the_independently_derived_vectors() {
    let vector = &kat::parse(FIXTURE)[0];
    let suite = provider(RineCipherSuite::XWing);

    assert_eq!(
        suite.hash(vector.bytes("hash_input")).expect("hash"),
        vector.bytes("hash"),
        "hash is not SHA-256",
    );
    assert_eq!(
        suite
            .mac(vector.bytes("mac_key"), vector.bytes("hash_input"))
            .expect("mac"),
        vector.bytes("mac"),
        "MAC is not HMAC-SHA-256",
    );

    let prk = suite
        .kdf_extract(vector.bytes("kdf_salt"), vector.bytes("kdf_ikm"))
        .expect("extract");
    assert_eq!(&*prk, vector.bytes("kdf_prk"), "KDF is not HKDF-SHA-256");
    assert_eq!(
        &*suite
            .kdf_expand(&prk, vector.bytes("kdf_info"), 64)
            .expect("expand"),
        vector.bytes("kdf_expand_64"),
    );

    assert_eq!(
        suite
            .aead_seal(
                vector.bytes("aead_key"),
                vector.bytes("aead_plaintext"),
                Some(vector.bytes("aead_aad")),
                vector.bytes("aead_nonce"),
            )
            .expect("seal"),
        vector.bytes("aead_ciphertext"),
        "AEAD is not ChaCha20-Poly1305",
    );
    assert_eq!(suite.aead_key_size(), 32);
    assert_eq!(suite.aead_nonce_size(), 12);
    assert_eq!(suite.kdf_extract_size(), 32);
}

#[test]
fn test_kem_derive_when_seeded_matches_the_independently_derived_key() {
    let vector = &kat::parse(FIXTURE)[0];

    let (secret, public) = provider(RineCipherSuite::XWing)
        .kem_derive(vector.bytes("kem_derive_ikm"))
        .expect("derive");

    assert_eq!(
        &*secret,
        vector.bytes("kem_derive_sk"),
        "the KEM id or the derivation changed",
    );
    assert_eq!(secret.len(), xwing::DECAPSULATION_KEY_SIZE);
    assert_eq!(public.len(), xwing::ENCAPSULATION_KEY_SIZE);

    let seed: [u8; xwing::DECAPSULATION_KEY_SIZE] =
        vector.array::<{ xwing::DECAPSULATION_KEY_SIZE }>("kem_derive_sk");
    assert_eq!(&*public, xwing::encapsulation_key(&seed).as_slice());
}

#[test]
fn test_classical_suite_when_compared_to_the_upstream_provider_is_unchanged() {
    // Adding a suite must not have moved the one that was already there.
    let ours = provider(RineCipherSuite::Classical);
    let upstream = RustCryptoProvider::new()
        .cipher_suite_provider(CipherSuite::CURVE25519_AES128)
        .expect("upstream classical suite");

    let ikm = [7u8; 32];

    assert_eq!(ours.cipher_suite(), upstream.cipher_suite());
    assert_eq!(ours.aead_key_size(), upstream.aead_key_size());
    assert_eq!(ours.aead_nonce_size(), upstream.aead_nonce_size());
    assert_eq!(ours.kdf_extract_size(), upstream.kdf_extract_size());
    assert_eq!(
        ours.hash(&ikm).expect("ours"),
        upstream.hash(&ikm).expect("upstream"),
    );
    assert_eq!(
        ours.kdf_extract(b"salt", &ikm).expect("ours"),
        upstream.kdf_extract(b"salt", &ikm).expect("upstream"),
    );
    assert_eq!(
        ours.kem_derive(&ikm).expect("ours").1,
        upstream.kem_derive(&ikm).expect("upstream").1,
        "the classical KEM must derive the same key it always did",
    );

    // Ciphertexts made by one open under the other, so the AEAD and the HPKE
    // composition are the same on both sides, not merely the same size.
    let (secret, public) = ours.kem_derive(&ikm).expect("key pair");
    let sealed = upstream
        .hpke_seal(&public, b"info", None, b"classical stays classical")
        .expect("upstream seal");

    assert_eq!(
        &*ours
            .hpke_open(&sealed, &secret, &public, b"info", None)
            .expect("ours open"),
        b"classical stays classical",
    );
}

#[test]
fn test_post_quantum_hpke_when_sealed_and_opened_round_trips_a_kilobyte_ciphertext() {
    let suite = provider(RineCipherSuite::XWing);
    let (secret, public) = suite.kem_generate().expect("key pair");

    let sealed = suite
        .hpke_seal(&public, b"info", Some(b"aad"), b"welcome secret")
        .expect("seal");

    // The encapsulated key is a full X-Wing ciphertext, which is what makes a
    // post-quantum Welcome two orders of magnitude larger than a classical one.
    assert_eq!(sealed.kem_output.len(), xwing::CIPHERTEXT_SIZE);

    assert_eq!(
        &*suite
            .hpke_open(&sealed, &secret, &public, b"info", Some(b"aad"))
            .expect("open"),
        b"welcome secret",
    );

    let wrong_key = suite.kem_generate().expect("key pair");
    assert!(
        suite
            .hpke_open(&sealed, &wrong_key.0, &wrong_key.1, b"info", Some(b"aad"))
            .is_err(),
        "another key must not open it",
    );
}

#[test]
fn test_post_quantum_key_when_malformed_is_rejected_before_use() {
    let suite = provider(RineCipherSuite::XWing);
    let (_, public) = suite.kem_generate().expect("key pair");

    suite.kem_public_key_validate(&public).expect("valid");

    // Wrong length, and a right-length key whose ML-KEM half does not re-encode
    // to itself. Validation is an encoding check: it says the bytes decode to a
    // key, never that the key is one anybody should trust. Nothing downstream
    // may treat it as authentication.
    let mut unreduced = public.to_vec();
    unreduced[..1184].fill(0xFF);

    for bad in [vec![0u8; 32], unreduced] {
        assert!(suite.kem_public_key_validate(&bad.into()).is_err());
    }
}

#[test]
fn test_add_member_when_the_key_package_is_from_the_other_suite_is_refused() {
    // rine's own suite negotiation lives above MLS, but MLS is the backstop:
    // a classical key package must never be admitted into a post-quantum group
    // by mistake, in either direction.
    for (group_suite, joiner_suite) in [
        (RineCipherSuite::XWing, RineCipherSuite::Classical),
        (RineCipherSuite::Classical, RineCipherSuite::XWing),
    ] {
        let founder = TestAgent::new(1, group_suite);
        let joiner = TestAgent::new(2, joiner_suite);

        let (mut group, _) = founder
            .client
            .create_group(&group_id(0xC1))
            .expect("create");
        let key_package = joiner.client.generate_key_package().expect("key package");

        assert!(
            group.add_member(&key_package).is_err(),
            "{joiner_suite:?} key package must not join a {group_suite:?} group",
        );
    }
}

#[test]
fn test_saved_group_when_reloaded_keeps_its_own_suite_whatever_the_client_was_built_for() {
    // A client's suite decides what it *mints* — key packages and new groups.
    // An existing group carries its own suite in its state and keeps it, so one
    // agent can sit in a classical group and a post-quantum group at once
    // without needing a client for each.
    let alice = TestAgent::new(1, RineCipherSuite::XWing);
    let bob = TestAgent::new(2, RineCipherSuite::XWing);
    let id = group_id(0xC2);

    let (mut group, _) = alice.client.create_group(&id).expect("create");
    let add = group
        .add_member(&bob.client.generate_key_package().expect("key package"))
        .expect("add");
    let mut bob_group = bob
        .client
        .join_from_welcome(&add.welcomes[0])
        .expect("join");
    bob_group.save().expect("persist");

    let ciphertext = group
        .encrypt_application_message(b"still post-quantum")
        .expect("encrypt");

    let mut reloaded = bob
        .reopen_as(RineCipherSuite::Classical)
        .load_group(&id)
        .expect("the group's own suite is what counts");

    assert_eq!(
        reloaded
            .decrypt_application_message(&ciphertext)
            .expect("decrypt")
            .envelope,
        b"still post-quantum",
    );
}
