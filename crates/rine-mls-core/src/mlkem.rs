//! Raw ML-KEM-768, for rine's 1:1 `hpke-hybrid-v2` DM envelope.
//!
//! This is *not* the group KEM. Groups run X-Wing ([`crate::xwing`]), whose
//! combiner and wire format are fixed by the X-Wing draft; the DM envelope
//! predates it, combines its two halves with HKDF, and is already deployed. The
//! two therefore stay separate constructions — but they are the same ML-KEM,
//! from the same libcrux, audited and updated once. That is the whole reason
//! this module exists rather than a second post-quantum implementation living
//! in the Python SDK.
//!
//! Key encodings are FIPS 203's, which is also what `@noble/post-quantum`'s
//! `ml_kem768` produces, so a key minted by the TypeScript stack loads here and
//! vice versa.
//!
//! Randomness enters at two points — key generation and encapsulation — and
//! both take it from the OS, except [`key_pair_from_seed`]: the org-root tree
//! derives an agent's ML-KEM key from a 64-byte `d‖z` seed, and a Python SDK
//! with no other seeded ML-KEM needs the same expansion `@noble/post-quantum`
//! performs. Encapsulation is never derandomized.

use libcrux_ml_kem::mlkem768;
use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

pub const PUBLIC_KEY_SIZE: usize = 1184;
pub const PRIVATE_KEY_SIZE: usize = 2400;
pub const CIPHERTEXT_SIZE: usize = 1088;
pub const SHARED_SECRET_SIZE: usize = 32;

/// The FIPS 203 key-generation seed `d‖z`, `d` first (the ACVP layout).
pub const KEYGEN_SEED_SIZE: usize = 64;
const ENCAPS_SEED_SIZE: usize = 32;
/// FIPS 203 §7.1 lays a private key out as `dk_PKE || ek || H(ek) || z`, so the
/// public key and its hash sit at fixed offsets inside it.
const EK_OFFSET: usize = 1152;
const EK_HASH_OFFSET: usize = EK_OFFSET + PUBLIC_KEY_SIZE;
const EK_HASH_SIZE: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum MlKemError {
    #[error("ML-KEM-768 public key must be {PUBLIC_KEY_SIZE} bytes, got {0}")]
    PublicKeyLength(usize),

    #[error("ML-KEM-768 private key must be {PRIVATE_KEY_SIZE} bytes, got {0}")]
    PrivateKeyLength(usize),

    #[error("ML-KEM-768 ciphertext must be {CIPHERTEXT_SIZE} bytes, got {0}")]
    CiphertextLength(usize),

    #[error("ML-KEM-768 key-generation seed must be {KEYGEN_SEED_SIZE} bytes, got {0}")]
    SeedLength(usize),

    #[error("ML-KEM-768 key is not a valid encoding")]
    MalformedKey,

    #[error("the operating system random number generator failed: {0}")]
    Rand(rand_core::Error),
}

type Result<T> = core::result::Result<T, MlKemError>;

fn as_public(bytes: &[u8]) -> Result<[u8; PUBLIC_KEY_SIZE]> {
    bytes
        .try_into()
        .map_err(|_| MlKemError::PublicKeyLength(bytes.len()))
}

fn as_private(bytes: &[u8]) -> Result<Zeroizing<[u8; PRIVATE_KEY_SIZE]>> {
    let key: [u8; PRIVATE_KEY_SIZE] = bytes
        .try_into()
        .map_err(|_| MlKemError::PrivateKeyLength(bytes.len()))?;

    Ok(Zeroizing::new(key))
}

fn os_seed<const N: usize>() -> Result<Zeroizing<[u8; N]>> {
    let mut seed = Zeroizing::new([0u8; N]);
    OsRng
        .try_fill_bytes(seed.as_mut_slice())
        .map_err(MlKemError::Rand)?;

    Ok(seed)
}

/// libcrux's ML-KEM private key does not wipe itself, so the ~2.4 kB of secret
/// it holds would otherwise be left on the stack by every keygen and every
/// decapsulation. `wiped` takes the copy rine owns out of it and clears the
/// original through the byte-range accessor libcrux exposes.
///
/// This covers rine's copy. Bytes libcrux itself moved through internally are
/// beyond reach from here and would need an upstream change — the same bound
/// [`crate::xwing`] documents.
fn wiped(mut key: mlkem768::MlKem768PrivateKey) -> Zeroizing<[u8; PRIVATE_KEY_SIZE]> {
    let owned = Zeroizing::new(*key.as_slice());
    key[..mlkem768::MlKem768PrivateKey::len()].zeroize();

    owned
}

/// Mint a key pair, as `(private_key, public_key)`.
pub fn generate_key_pair() -> Result<(Zeroizing<[u8; PRIVATE_KEY_SIZE]>, [u8; PUBLIC_KEY_SIZE])> {
    Ok(key_pair(&*os_seed::<KEYGEN_SEED_SIZE>()?))
}

/// The key pair FIPS 203 `ML-KEM.KeyGen_internal(d, z)` yields for the 64-byte
/// seed `d‖z`, as `(private_key, public_key)`. The same seed always yields the
/// same pair, and the private key is the 2400-byte expanded form the rest of
/// this module takes.
pub fn key_pair_from_seed(
    seed: &[u8],
) -> Result<(Zeroizing<[u8; PRIVATE_KEY_SIZE]>, [u8; PUBLIC_KEY_SIZE])> {
    let seed: Zeroizing<[u8; KEYGEN_SEED_SIZE]> = Zeroizing::new(
        seed.try_into()
            .map_err(|_| MlKemError::SeedLength(seed.len()))?,
    );

    Ok(key_pair(&seed))
}

fn key_pair(
    seed: &[u8; KEYGEN_SEED_SIZE],
) -> (Zeroizing<[u8; PRIVATE_KEY_SIZE]>, [u8; PUBLIC_KEY_SIZE]) {
    let (sk, pk) = mlkem768::generate_key_pair(*seed).into_parts();

    (wiped(sk), *pk.as_slice())
}

/// The public key a private key carries, checked against the `H(ek)` the
/// private key also carries — so a corrupted key is refused here rather than
/// published as an agent's post-quantum key and silently stranding every
/// message sealed to it.
pub fn public_key(private_key: &[u8]) -> Result<[u8; PUBLIC_KEY_SIZE]> {
    let sk = as_private(private_key)?;
    let ek = as_public(&sk[EK_OFFSET..EK_HASH_OFFSET])?;

    if libcrux_sha3::sha256(&ek) != sk[EK_HASH_OFFSET..EK_HASH_OFFSET + EK_HASH_SIZE] {
        return Err(MlKemError::MalformedKey);
    }

    Ok(ek)
}

/// Encapsulate to a public key, as `(ciphertext, shared_secret)`.
pub fn encapsulate(
    public_key: &[u8],
) -> Result<([u8; CIPHERTEXT_SIZE], Zeroizing<[u8; SHARED_SECRET_SIZE]>)> {
    let pk = mlkem768::MlKem768PublicKey::from(&as_public(public_key)?);
    if !mlkem768::validate_public_key(&pk) {
        return Err(MlKemError::MalformedKey);
    }

    let seed = os_seed::<ENCAPS_SEED_SIZE>()?;
    let (ct, ss) = mlkem768::encapsulate(&pk, *seed);

    Ok((*ct.as_slice(), Zeroizing::new(ss)))
}

/// Recover the shared secret from a ciphertext.
///
/// A wrong-but-well-formed private key does not fail: FIPS 203's implicit
/// rejection returns a pseudorandom secret instead, and the AEAD that consumes
/// it is what refuses. Only a malformed length is an error here.
pub fn decapsulate(
    ciphertext: &[u8],
    private_key: &[u8],
) -> Result<Zeroizing<[u8; SHARED_SECRET_SIZE]>> {
    let ct: [u8; CIPHERTEXT_SIZE] = ciphertext
        .try_into()
        .map_err(|_| MlKemError::CiphertextLength(ciphertext.len()))?;
    let sk = as_private(private_key)?;

    let mut key = mlkem768::MlKem768PrivateKey::from(&*sk);
    let ss = mlkem768::decapsulate(&key, &mlkem768::MlKem768Ciphertext::from(&ct));
    key[..mlkem768::MlKem768PrivateKey::len()].zeroize();

    Ok(Zeroizing::new(ss))
}
