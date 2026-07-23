use ed25519_dalek::SigningKey;
use mls_rs::identity::basic::BasicCredential;
use mls_rs::identity::SigningIdentity;
use mls_rs_core::crypto::{SignaturePublicKey, SignatureSecretKey};

use crate::error::{Result, RineMlsError};

/// A rine agent's Ed25519 identity signing key, in the 32-byte seed form every
/// other rine surface stores it in (`keys/<agent>/signing.key`).
///
/// The MLS credential is `basic` with the raw Ed25519 public key as its
/// identity, and the KeyPackage leaf signature key is this same key — MLS adds
/// no second identity. Credential validation stays accept-all at the MLS layer
/// (`BasicIdentityProvider`); what is actually verified per message is the
/// inner rine envelope signature made with this key.
#[derive(Clone)]
pub struct AgentSigningKey {
    inner: SigningKey,
}

impl AgentSigningKey {
    /// `seed` is the 32-byte Ed25519 private key as stored by rine.
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        let seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| RineMlsError::InvalidSigningSeed { len: seed.len() })?;

        Ok(Self {
            inner: SigningKey::from_bytes(&seed),
        })
    }

    /// The raw 32-byte Ed25519 public key — also the basic-credential identity.
    pub fn public_key(&self) -> [u8; 32] {
        self.inner.verifying_key().to_bytes()
    }

    /// Provider seam: `mls-rs-crypto-rustcrypto` round-trips Ed25519 secrets
    /// through `ed25519_dalek::SigningKey::from_keypair_bytes`, i.e. it expects
    /// `seed || public_key` (64 bytes), not the bare 32-byte seed. Handing it
    /// rine's stored seed directly fails to parse, so expand it here — this is
    /// the only place the two representations meet.
    pub(crate) fn signer(&self) -> SignatureSecretKey {
        self.inner.to_keypair_bytes().to_vec().into()
    }

    pub(crate) fn signing_identity(&self) -> SigningIdentity {
        let public = self.public_key().to_vec();
        SigningIdentity::new(
            BasicCredential::new(public.clone()).into_credential(),
            SignaturePublicKey::from(public),
        )
    }
}
