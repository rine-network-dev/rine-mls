//! ML-DSA-65 public keys from a seed, for the org-root tree.
//!
//! The tree derives an agent's ML-DSA-65 key from a 32-byte seed `xi` and
//! publishes only the public half in the org-signed agent certificate. The
//! Python SDK has no ML-DSA of its own, so this is the one place it gets the
//! FIPS 204 `ML-DSA.KeyGen_internal(xi)` expansion, from the same libcrux the
//! ML-KEM surface in [`crate::mlkem`] runs on. The private key is computed as a
//! by-product and wiped; nothing here signs.
//!
//! The encoding is FIPS 204's, which is also what `@noble/post-quantum`'s
//! `ml_dsa65` produces from the same seed, so each stack's key verifies against
//! the other's (`tests/seeded_keys.rs`).

use libcrux_ml_dsa::ml_dsa_65;
use zeroize::{Zeroize, Zeroizing};

pub const SEED_SIZE: usize = libcrux_ml_dsa::KEY_GENERATION_RANDOMNESS_SIZE;
pub const PUBLIC_KEY_SIZE: usize = ml_dsa_65::MLDSA65VerificationKey::len();

#[derive(Debug, thiserror::Error)]
#[error("ML-DSA-65 key-generation seed must be {SEED_SIZE} bytes, got {0}")]
pub struct SeedLengthError(usize);

/// The 1952-byte ML-DSA-65 public key the 32-byte seed `xi` generates.
pub fn public_key_from_seed(seed: &[u8]) -> Result<[u8; PUBLIC_KEY_SIZE], SeedLengthError> {
    let seed: Zeroizing<[u8; SEED_SIZE]> =
        Zeroizing::new(seed.try_into().map_err(|_| SeedLengthError(seed.len()))?);

    let mut pair = ml_dsa_65::generate_key_pair(*seed);
    pair.signing_key.as_mut_slice().zeroize();

    Ok(*pair.verification_key.as_ref())
}
