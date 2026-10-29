//! rine's MLS crypto provider: rine's post-quantum ciphersuite from a single set
//! of primitives.
//!
//! The AEAD, KDF, hash and signature scheme are taken unmodified from the
//! providers mls-rs ships, so nothing here re-implements a primitive; the
//! suite's only new cryptography is the X-Wing KEM in [`crate::xwing`].
//!
//! The suite lives at a private-use ciphersuite code point, which
//! is what RFC 9420 reserves that range for. It is not the code point the
//! withdrawn X-Wing MLS draft used: that one is back in the standards range and
//! can be assigned to something else, and a group that silently disagreed with
//! a future occupant about what its own ciphersuite means is not a failure mode
//! worth inheriting.

mod cipher_suite;
mod error;
mod kem;

use mls_rs_core::crypto::{CipherSuite, CryptoProvider};
use mls_rs_crypto_hpke::hpke::Hpke;
use mls_rs_crypto_rustcrypto::{aead::Aead, ec_signer::EcSigner, kdf::Kdf, mac::Hash};

use crate::error::RineMlsError;
use crate::suite::RineCipherSuite;
use kem::RineKem;

pub use error::{RineCryptoError, RineKemError};
pub use kem::XWING_KEM_ID;

/// The crypto provider rine's MLS clients are built on.
#[derive(Debug, Clone, Copy, Default)]
pub struct RineCryptoProvider;

impl CryptoProvider for RineCryptoProvider {
    type CipherSuiteProvider = RineCipherSuiteProvider;

    fn supported_cipher_suites(&self) -> Vec<CipherSuite> {
        RineCipherSuite::ALL.iter().map(|s| s.mls_rs()).collect()
    }

    fn cipher_suite_provider(
        &self,
        cipher_suite: CipherSuite,
    ) -> Option<Self::CipherSuiteProvider> {
        RineCipherSuiteProvider::new(RineCipherSuite::try_from(cipher_suite.raw_value()).ok()?)
    }
}

/// One rine ciphersuite, assembled.
#[derive(Clone)]
pub struct RineCipherSuiteProvider {
    cipher_suite: CipherSuite,
    aead: Aead,
    kdf: Kdf,
    hash: Hash,
    signer: EcSigner,
    hpke: Hpke<RineKem, Kdf, Aead>,
}

impl RineCipherSuiteProvider {
    /// The provider of a suite rine speaks. Every [`RineCipherSuite`] has one;
    /// the error exists so no caller has to assert that.
    pub(crate) fn for_suite(suite: RineCipherSuite) -> Result<Self, RineMlsError> {
        Self::new(suite).ok_or(RineMlsError::UnsupportedCipherSuite { id: suite.id() })
    }

    fn new(suite: RineCipherSuite) -> Option<Self> {
        // The suite borrows its non-KEM primitives from an RFC 9420 suite that
        // already defines them, so `Kdf`/`Aead`/`Hash`/`EcSigner` are
        // constructed exactly as mls-rs' own provider constructs them.
        let primitives = suite.primitives();

        let kdf = Kdf::new(primitives)?;
        let aead = Aead::new(primitives)?;
        let hash = Hash::new(primitives).ok()?;
        let signer = EcSigner::new(primitives)?;

        Some(Self {
            cipher_suite: suite.mls_rs(),
            aead,
            kdf,
            hash,
            signer,
            hpke: Hpke::new(RineKem, kdf, Some(aead)),
        })
    }
}
