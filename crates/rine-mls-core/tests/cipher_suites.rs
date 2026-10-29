//! What rine's ciphersuite is, at the code-point and primitive level.
//!
//! Three things are checked here that no group-flow test can catch: that the
//! post-quantum suite really sits at the private-use code point and not at the
//! withdrawn draft's, that the primitives underneath it are the ones claimed,
//! and that it is the only suite rine speaks, RFC 9420's classical `0x0001`
//! included.

mod common;
mod kat;

use common::{group_id, TestAgent};
use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
use mls_rs::identity::SigningIdentity;
use mls_rs::{Client, ExtensionList, MlsMessage};
use mls_rs_core::crypto::{CipherSuite, CipherSuiteProvider, CryptoProvider};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;
use rine_mls_core::{xwing, RineCipherSuite, RineCryptoProvider, RineMlsError, XWING_KEM_ID};

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

    assert_eq!(RineCipherSuite::ALL, [RineCipherSuite::XWing]);
    assert_eq!(RineCipherSuite::DEFAULT, RineCipherSuite::XWing);

    assert_eq!(
        RineCipherSuite::try_from(WITHDRAWN_DRAFT_CODE_POINT),
        Err(WITHDRAWN_DRAFT_CODE_POINT),
        "the withdrawn code point must not resolve to a rine suite",
    );
    assert_eq!(
        RineCipherSuite::try_from(CipherSuite::CURVE25519_AES128.raw_value()),
        Err(0x0001),
        "the classical suite must not resolve to a rine suite, so no client opens for it",
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
        CipherSuite::CURVE25519_AES128.raw_value(),
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
fn test_add_member_when_the_key_package_is_a_stock_classical_one_is_refused_by_name() {
    // rine's own client can no longer mint a classical KeyPackage, but the
    // server's upload check is not the only guard: a stock mls-rs client can
    // still produce one, and MLS must not seat it in a post-quantum group.
    let provider = RustCryptoProvider::new();
    let suite = CipherSuite::CURVE25519_AES128;
    let (secret, public) = provider
        .cipher_suite_provider(suite)
        .expect("stock classical suite")
        .signature_key_generate()
        .expect("signature key");
    let stock = Client::builder()
        .crypto_provider(provider)
        .identity_provider(BasicIdentityProvider::new())
        .signing_identity(
            SigningIdentity::new(
                BasicCredential::new(b"stock".to_vec()).into_credential(),
                public,
            ),
            secret,
            suite,
        )
        .build();
    let classical = stock
        .generate_key_package_message(ExtensionList::new(), ExtensionList::new(), None)
        .expect("classical key package")
        .to_bytes()
        .expect("encode");

    let founder = TestAgent::new(1, RineCipherSuite::XWing);
    let (mut group, _) = founder
        .client
        .create_group(&group_id(0xC1))
        .expect("create");

    assert!(matches!(
        group.add_member(&classical),
        Err(RineMlsError::CipherSuiteMismatch {
            expected: 0xF057,
            got: 0x0001,
        })
    ));
}

/// Pins the claim `rine-mls/deny.toml` makes to ignore RUSTSEC-2026-0387
/// (crypto-bigint, reached only through mls-rs-crypto-rustcrypto's P-256/P-384
/// code): the one suite rine builds is 0xF057 with Ed25519 signatures and the
/// X-Wing KEM, and no P-256/P-384 suite is offered or accepted.
#[test]
fn test_provider_when_built_offers_only_xwing_with_ed25519_and_never_a_p256_or_p384_suite() {
    assert_eq!(
        RineCryptoProvider.supported_cipher_suites(),
        vec![CipherSuite::new(0xF057)],
    );

    // Every RFC 9420 suite plus the mls-rs experimental ones, P-256 (2), P-521
    // (5) and P-384 (7) among them: none may resolve to a provider.
    for id in (0..=0x0010u16).chain([65001, 65002, 65003, 65100]) {
        assert_eq!(
            RineCryptoProvider
                .cipher_suite_provider(CipherSuite::new(id))
                .is_some(),
            id == 0xF057,
            "0x{id:04X} must be accepted only if it is rine's suite",
        );
    }

    let suite = provider(RineCipherSuite::XWing);
    assert_eq!(suite.cipher_suite(), CipherSuite::new(0xF057));

    // Ed25519: a 32-byte public key, and a signature that the independent
    // ed25519-dalek verifier accepts. A P-256 or P-384 signer cannot satisfy both.
    let (secret, public) = suite.signature_key_generate().expect("signature key");
    assert_eq!(public.len(), 32);
    let signature = suite.sign(&secret, b"pin").expect("sign");
    assert_eq!(signature.len(), 64);
    let key: [u8; 32] = public.as_ref().try_into().expect("32-byte key");
    ed25519_dalek::VerifyingKey::from_bytes(&key)
        .expect("Ed25519 point")
        .verify_strict(
            b"pin",
            &ed25519_dalek::Signature::from_slice(&signature).expect("64-byte signature"),
        )
        .expect("dalek verifies the provider's signature");

    // X-Wing KEM: its id, and the key sizes only X-Wing has.
    let (kem_secret, kem_public) = suite.kem_generate().expect("kem key");
    assert_eq!(XWING_KEM_ID, 0xF057);
    assert_eq!(kem_secret.len(), xwing::DECAPSULATION_KEY_SIZE);
    assert_eq!(kem_public.len(), xwing::ENCAPSULATION_KEY_SIZE);
}
