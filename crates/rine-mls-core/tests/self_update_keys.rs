//! The allowed set records one generation per pair, and a KeyPackage reads
//! back its leaf key.

mod common;

use common::seat::{allowing, Seat};
use rine_mls_core::{AllowedIdentities, RineMlsErrorCode};

#[test]
fn allowed_insert_conflicting_generation_refused() {
    let allowed = AllowedIdentities::new();
    let key = [7u8; 32];
    allowed
        .insert(b"agent-a", &key, 0)
        .expect("the first generation");

    let error = allowed
        .insert(b"agent-a", &key, 1)
        .expect_err("the pair is already recorded at another generation");
    assert_eq!(
        error.code(),
        RineMlsErrorCode::AllowedGenerationConflict,
        "got {error:?}"
    );
    assert!(allowed.contains(b"agent-a", &key), "the set is unchanged");

    allowed
        .insert(b"agent-a", &key, 0)
        .expect("the same pair at the same generation");
    allowed
        .insert(b"agent-a", &[8u8; 32], 1)
        .expect("a different key is a different pair");
}

#[test]
fn key_package_signature_key_reads_leaf_key() {
    let a = Seat::new("agent-a", 16);
    let set = allowing(&[(&a, 0)]);
    let client = a.open(&set, 0);
    let key_package = client.generate_key_package().expect("key package");

    assert_eq!(
        rine_mls_core::key_package_signature_key(&key_package).expect("signature key"),
        client.leaf_public_key().to_vec(),
    );
    assert!(
        rine_mls_core::key_package_signature_key(&[0xFF; 8]).is_err(),
        "garbage is not a KeyPackage",
    );
}
