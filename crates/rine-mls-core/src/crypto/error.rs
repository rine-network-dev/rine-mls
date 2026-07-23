use mls_rs_core::error::{AnyError, IntoAnyError};
use mls_rs_crypto_hpke::dhkem::DhKemError;
use mls_rs_crypto_hpke::hpke::HpkeError;
use mls_rs_crypto_rustcrypto::ec_signer::EcSignerError;
use mls_rs_crypto_rustcrypto::mac::HashError;

use crate::xwing::XWingError;

/// Failures from the KEM half of a rine ciphersuite.
#[derive(Debug, thiserror::Error)]
pub enum RineKemError {
    #[error(transparent)]
    DiffieHellman(#[from] DhKemError),

    #[error(transparent)]
    XWing(#[from] XWingError),

    #[error("the operating system random number generator failed: {0}")]
    Rand(rand_core::Error),
}

impl IntoAnyError for RineKemError {
    fn into_dyn_error(
        self,
    ) -> core::result::Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}

/// Failures from a rine ciphersuite provider. The AEAD and KDF arms carry an
/// erased error because the traits they come from erase it too.
#[derive(Debug, thiserror::Error)]
pub enum RineCryptoError {
    #[error(transparent)]
    Aead(AnyError),

    #[error(transparent)]
    Kdf(AnyError),

    #[error(transparent)]
    Hash(#[from] HashError),

    #[error(transparent)]
    Signature(#[from] EcSignerError),

    #[error(transparent)]
    Hpke(#[from] HpkeError),

    #[error("the operating system random number generator failed: {0}")]
    Rand(rand_core::Error),
}

impl IntoAnyError for RineCryptoError {
    fn into_dyn_error(
        self,
    ) -> core::result::Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}
