//! X-Wing: the X25519 + ML-KEM-768 hybrid KEM rine's post-quantum ciphersuite
//! is built on, implemented per `draft-connolly-cfrg-xwing-kem-06`.
//!
//! Hybrid means a passive attacker has to break *both* halves: X25519 today, or
//! ML-KEM-768 once a quantum computer exists. Harvest-now-decrypt-later on a
//! rine group therefore has to wait for a machine that can also break X25519 in
//! the same session.
//!
//! Everything here is derandomized on purpose — randomness enters one function,
//! [`crate::crypto`]'s KEM, and never this module. That keeps the primitive
//! testable against fixed vectors and keeps the RNG on one seam.
//!
//! Sizes, all fixed: a decapsulation key is the 32-byte seed and nothing else,
//! an encapsulation key is `pk_M || pk_X`, and a ciphertext is `ct_M || ct_X`.
//!
//! This module owns the key material — what a seed expands into and how keys
//! are encoded; [`exchange`] owns the combiner and the encapsulate/decapsulate
//! pair.

mod exchange;

use libcrux_ml_kem::mlkem768;
use zeroize::{Zeroize, Zeroizing};

pub use exchange::{decapsulate, encapsulate};

/// The seed a decapsulation key *is*: every other private value is expanded
/// from it on demand, so this is the only thing that has to be stored.
pub const DECAPSULATION_KEY_SIZE: usize = 32;
/// `pk_M || pk_X`.
pub const ENCAPSULATION_KEY_SIZE: usize = 1216;
/// `ct_M || ct_X`.
pub const CIPHERTEXT_SIZE: usize = 1120;
pub const SHARED_SECRET_SIZE: usize = 32;
/// Encapsulation consumes 64 bytes: 32 for ML-KEM, then 32 for the X25519
/// ephemeral, in that order.
pub const ENCAPSULATION_SEED_SIZE: usize = 64;

const ML_KEM_PUBLIC_KEY_SIZE: usize = 1184;
const ML_KEM_CIPHERTEXT_SIZE: usize = 1088;
const X25519_SIZE: usize = 32;
const EXPANDED_SEED_SIZE: usize = 96;

/// `concat("\./", "/^\")`, i.e. the six bytes `5c 2e 2f 2f 5e 5c`. It is hashed
/// *last*, after the four secrets — the ordering is part of the construction,
/// not a stylistic choice, so it is pinned by a test.
const LABEL: &[u8; 6] = br"\.//^\";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum XWingError {
    #[error("X-Wing encapsulation key must be {ENCAPSULATION_KEY_SIZE} bytes, got {0}")]
    EncapsulationKeyLength(usize),

    #[error("X-Wing decapsulation key must be {DECAPSULATION_KEY_SIZE} bytes, got {0}")]
    DecapsulationKeyLength(usize),

    #[error("X-Wing ciphertext must be {CIPHERTEXT_SIZE} bytes, got {0}")]
    CiphertextLength(usize),

    #[error("ML-KEM-768 encapsulation key is not a valid encoding")]
    MalformedMlKemKey,
}

type Result<T> = core::result::Result<T, XWingError>;

/// The four keys a decapsulation seed unfolds into.
struct Expanded {
    sk_m: mlkem768::MlKem768PrivateKey,
    sk_x: Zeroizing<[u8; X25519_SIZE]>,
    pk_m: [u8; ML_KEM_PUBLIC_KEY_SIZE],
    pk_x: [u8; X25519_SIZE],
}

/// libcrux's key types do not wipe themselves, so the ~2.4 kB ML-KEM private
/// key would otherwise be left in memory by every decapsulation. `sk_x` clears
/// itself, being a [`Zeroizing`]; `sk_m` is cleared through the byte-range
/// accessor libcrux exposes, since it offers no wipe of its own.
///
/// This covers the copy rine holds. Bytes libcrux itself moved through on the
/// way out of key generation are beyond reach from here and would need an
/// upstream change.
impl Drop for Expanded {
    fn drop(&mut self) {
        self.sk_m[..mlkem768::MlKem768PrivateKey::len()].zeroize();
    }
}

/// SHAKE-256 the seed to 96 bytes, then hand the first 64 to ML-KEM key
/// generation and keep the last 32 as the X25519 private key.
///
/// ML-KEM's own key generation is *not* re-randomized here: it is driven
/// entirely by those 64 bytes, which is what makes the whole key pair a pure
/// function of the seed and lets a 32-byte secret stand in for 2.4 kB of
/// ML-KEM private key.
fn expand(sk: &[u8; DECAPSULATION_KEY_SIZE]) -> Expanded {
    let expanded = Zeroizing::new(libcrux_sha3::shake256::<EXPANDED_SEED_SIZE>(sk));

    let mut ml_kem_seed = Zeroizing::new([0u8; 64]);
    ml_kem_seed.copy_from_slice(&expanded[..64]);
    let key_pair = mlkem768::generate_key_pair(*ml_kem_seed);

    let mut sk_x = Zeroizing::new([0u8; X25519_SIZE]);
    sk_x.copy_from_slice(&expanded[64..]);
    let pk_x = x25519_dalek::x25519(*sk_x, x25519_dalek::X25519_BASEPOINT_BYTES);

    let (sk_m, pk_m) = key_pair.into_parts();

    Expanded {
        sk_m,
        sk_x,
        pk_m: *pk_m.as_slice(),
        pk_x,
    }
}

/// The encapsulation key belonging to a decapsulation seed.
pub fn encapsulation_key(sk: &[u8; DECAPSULATION_KEY_SIZE]) -> [u8; ENCAPSULATION_KEY_SIZE] {
    let expanded = expand(sk);

    let mut pk = [0u8; ENCAPSULATION_KEY_SIZE];
    pk[..ML_KEM_PUBLIC_KEY_SIZE].copy_from_slice(&expanded.pk_m);
    pk[ML_KEM_PUBLIC_KEY_SIZE..].copy_from_slice(&expanded.pk_x);
    pk
}

/// Derive a key pair from key material that is already uniformly random,
/// as the HPKE mapping of X-Wing specifies: condense the input to a 32-byte
/// seed with SHAKE-256, then expand that seed normally.
pub fn derive_key_pair(
    ikm: &[u8],
) -> (
    Zeroizing<[u8; DECAPSULATION_KEY_SIZE]>,
    [u8; ENCAPSULATION_KEY_SIZE],
) {
    let sk = Zeroizing::new(libcrux_sha3::shake256::<DECAPSULATION_KEY_SIZE>(ikm));
    let pk = encapsulation_key(&sk);

    (sk, pk)
}

/// Reject an encapsulation key whose ML-KEM half is not a valid encoding.
/// The X25519 half has no invalid encodings.
pub fn validate_encapsulation_key(pk: &[u8]) -> Result<()> {
    let (pk_m, _) = split_encapsulation_key(pk)?;

    if mlkem768::validate_public_key(&mlkem768::MlKem768PublicKey::from(&pk_m)) {
        Ok(())
    } else {
        Err(XWingError::MalformedMlKemKey)
    }
}

fn split_encapsulation_key(pk: &[u8]) -> Result<([u8; ML_KEM_PUBLIC_KEY_SIZE], [u8; X25519_SIZE])> {
    if pk.len() != ENCAPSULATION_KEY_SIZE {
        return Err(XWingError::EncapsulationKeyLength(pk.len()));
    }

    let mut pk_m = [0u8; ML_KEM_PUBLIC_KEY_SIZE];
    pk_m.copy_from_slice(&pk[..ML_KEM_PUBLIC_KEY_SIZE]);
    let mut pk_x = [0u8; X25519_SIZE];
    pk_x.copy_from_slice(&pk[ML_KEM_PUBLIC_KEY_SIZE..]);

    Ok((pk_m, pk_x))
}
