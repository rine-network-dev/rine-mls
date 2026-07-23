//! rine's MLS crypto provider: the classical ciphersuite plus rine's own
//! post-quantum one, from a single set of primitives.
//!
//! The two suites differ in exactly one component, the KEM. The AEAD, KDF,
//! hash and signature scheme are taken unmodified from the providers mls-rs
//! ships, so nothing here re-implements a primitive; the post-quantum suite's
//! only new cryptography is the X-Wing KEM in [`crate::xwing`].
//!
//! The post-quantum suite lives at a private-use ciphersuite code point, which
//! is what RFC 9420 reserves that range for. It is not the code point the
//! withdrawn X-Wing MLS draft used: that one is back in the standards range and
//! can be assigned to something else, and a group that silently disagreed with
//! a future occupant about what its own ciphersuite means is not a failure mode
//! worth inheriting.

mod cipher_suite;
mod error;
mod kem;

use mls_rs_core::crypto::{CipherSuite, CryptoProvider};
use mls_rs_crypto_hpke::dhkem::DhKem;
use mls_rs_crypto_hpke::hpke::Hpke;
use mls_rs_crypto_rustcrypto::{aead::Aead, ec_signer::EcSigner, ecdh::Ecdh, kdf::Kdf, mac::Hash};
use mls_rs_crypto_traits::KemId;

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
    fn new(suite: RineCipherSuite) -> Option<Self> {
        // Both suites borrow their non-KEM primitives from an RFC 9420 suite
        // that already defines them, so `Kdf`/`Aead`/`Hash`/`EcSigner` are
        // constructed exactly as mls-rs' own provider constructs them and the
        // classical suite stays bit-for-bit what it was.
        let primitives = suite.primitives();

        let kdf = Kdf::new(primitives)?;
        let aead = Aead::new(primitives)?;
        let hash = Hash::new(primitives).ok()?;
        let signer = EcSigner::new(primitives)?;

        let kem = match suite {
            RineCipherSuite::Classical => {
                let kem_id = KemId::new(primitives)?;

                RineKem::X25519HkdfSha256(DhKem::new(
                    Ecdh::new(primitives)?,
                    kdf,
                    kem_id as u16,
                    kem_id.n_secret(),
                ))
            }
            RineCipherSuite::XWing => RineKem::XWing,
        };

        Some(Self {
            cipher_suite: suite.mls_rs(),
            aead,
            kdf,
            hash,
            signer,
            hpke: Hpke::new(kem, kdf, Some(aead)),
        })
    }
}
