use mls_rs_core::crypto::{HpkePublicKey, HpkeSecretKey};
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

/// The KEM rine's ciphersuite is built on: X25519 + ML-KEM-768, per
/// `draft-connolly-cfrg-xwing-kem-06`. Everything else in the suite — AEAD,
/// KDF, hash, signatures — comes unmodified from RFC 9420 suite `0x0003`.
#[derive(Clone, Copy)]
pub(crate) struct RineKem;

impl KemType for RineKem {
    type Error = RineKemError;

    fn kem_id(&self) -> u16 {
        XWING_KEM_ID
    }

    fn generate_deterministic(
        &self,
        seed: &[u8],
    ) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        let (sk, pk) = xwing::derive_key_pair(seed);

        Ok((sk.to_vec().into(), pk.to_vec().into()))
    }

    fn generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        let mut sk = Zeroizing::new([0u8; xwing::DECAPSULATION_KEY_SIZE]);
        OsRng
            .try_fill_bytes(&mut sk[..])
            .map_err(RineKemError::Rand)?;
        let pk = xwing::encapsulation_key(&sk);

        Ok((sk.to_vec().into(), pk.to_vec().into()))
    }

    fn public_key_validate(&self, key: &HpkePublicKey) -> Result<(), Self::Error> {
        Ok(xwing::validate_encapsulation_key(key)?)
    }

    fn encap(&self, remote_key: &HpkePublicKey) -> Result<KemResult, Self::Error> {
        let mut eseed = Zeroizing::new([0u8; xwing::ENCAPSULATION_SEED_SIZE]);
        OsRng
            .try_fill_bytes(&mut eseed[..])
            .map_err(RineKemError::Rand)?;

        let (shared_secret, enc) = xwing::encapsulate(remote_key, &eseed)?;

        Ok(KemResult::new(shared_secret.to_vec(), enc.to_vec()))
    }

    fn decap(
        &self,
        enc: &[u8],
        secret_key: &HpkeSecretKey,
        _local_public: &HpkePublicKey,
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(xwing::decapsulate(enc, secret_key)?.to_vec())
    }

    fn seed_length_for_derive(&self) -> usize {
        xwing::DECAPSULATION_KEY_SIZE
    }
}
