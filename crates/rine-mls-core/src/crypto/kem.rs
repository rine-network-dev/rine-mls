use mls_rs_core::crypto::{HpkePublicKey, HpkeSecretKey};
use mls_rs_crypto_hpke::dhkem::DhKem;
use mls_rs_crypto_rustcrypto::{ecdh::Ecdh, kdf::Kdf};
use mls_rs_crypto_traits::{KemResult, KemType};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::crypto::error::RineKemError;
use crate::xwing;

/// The HPKE KEM id rine's X-Wing KEM is labelled with.
///
/// It never travels as a negotiated identifier — it appears only inside the
/// fixed HPKE and KEM suite-id labels, which both peers derive from the
/// ciphersuite they already agreed on. It is set to the same number as the
/// ciphersuite so there is one value to remember, and deliberately not to the
/// value the X-Wing draft asks IANA for: that one is unassigned, and borrowing
/// it would make rine-private key schedules look standard without being it.
pub const XWING_KEM_ID: u16 = 0xF057;

/// The two KEMs rine's ciphersuites are built on. Everything else in a suite —
/// AEAD, KDF, hash, signatures — is shared, so this enum is the entire
/// difference between the classical suite and the post-quantum one.
#[derive(Clone)]
pub(crate) enum RineKem {
    /// RFC 9180 DHKEM(X25519, HKDF-SHA256), as used by RFC 9420's classical
    /// ciphersuites.
    X25519HkdfSha256(DhKem<Ecdh, Kdf>),

    /// X25519 + ML-KEM-768, per `draft-connolly-cfrg-xwing-kem-06`.
    XWing,
}

impl KemType for RineKem {
    type Error = RineKemError;

    fn kem_id(&self) -> u16 {
        match self {
            Self::X25519HkdfSha256(kem) => kem.kem_id(),
            Self::XWing => XWING_KEM_ID,
        }
    }

    fn generate_deterministic(
        &self,
        seed: &[u8],
    ) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        match self {
            Self::X25519HkdfSha256(kem) => Ok(kem.generate_deterministic(seed)?),
            Self::XWing => {
                let (sk, pk) = xwing::derive_key_pair(seed);

                Ok((sk.to_vec().into(), pk.to_vec().into()))
            }
        }
    }

    fn generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        match self {
            Self::X25519HkdfSha256(kem) => Ok(kem.generate()?),
            Self::XWing => {
                let mut sk = Zeroizing::new([0u8; xwing::DECAPSULATION_KEY_SIZE]);
                OsRng
                    .try_fill_bytes(&mut sk[..])
                    .map_err(RineKemError::Rand)?;
                let pk = xwing::encapsulation_key(&sk);

                Ok((sk.to_vec().into(), pk.to_vec().into()))
            }
        }
    }

    fn public_key_validate(&self, key: &HpkePublicKey) -> Result<(), Self::Error> {
        match self {
            Self::X25519HkdfSha256(kem) => Ok(kem.public_key_validate(key)?),
            Self::XWing => Ok(xwing::validate_encapsulation_key(key)?),
        }
    }

    fn encap(&self, remote_key: &HpkePublicKey) -> Result<KemResult, Self::Error> {
        match self {
            Self::X25519HkdfSha256(kem) => Ok(kem.encap(remote_key)?),
            Self::XWing => {
                let mut eseed = Zeroizing::new([0u8; xwing::ENCAPSULATION_SEED_SIZE]);
                OsRng
                    .try_fill_bytes(&mut eseed[..])
                    .map_err(RineKemError::Rand)?;

                let (shared_secret, enc) = xwing::encapsulate(remote_key, &eseed)?;

                Ok(KemResult::new(shared_secret.to_vec(), enc.to_vec()))
            }
        }
    }

    fn decap(
        &self,
        enc: &[u8],
        secret_key: &HpkeSecretKey,
        local_public: &HpkePublicKey,
    ) -> Result<Vec<u8>, Self::Error> {
        match self {
            Self::X25519HkdfSha256(kem) => Ok(kem.decap(enc, secret_key, local_public)?),
            Self::XWing => Ok(xwing::decapsulate(enc, secret_key)?.to_vec()),
        }
    }

    fn seed_length_for_derive(&self) -> usize {
        match self {
            Self::X25519HkdfSha256(kem) => kem.seed_length_for_derive(),
            Self::XWing => xwing::DECAPSULATION_KEY_SIZE,
        }
    }
}
