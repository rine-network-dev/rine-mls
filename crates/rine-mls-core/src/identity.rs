use ed25519_dalek::SigningKey;
use mls_rs::identity::basic::BasicCredential;
use mls_rs::identity::SigningIdentity;
use mls_rs_core::crypto::{SignaturePublicKey, SignatureSecretKey};
use zeroize::Zeroizing;

use crate::error::{Result, RineMlsError};

/// The MLS identity one rine agent opens a client with: the agent id, and the
/// leaf signature key derived for it (`mls.key`, 32 bytes, an RFC 8032 seed).
///
/// The MLS credential is `basic` with the agent id as its identity, and the
/// KeyPackage leaf signature key is the public half of the derived key. That
/// key is separate from the agent's message-signing key, and the org-signed
/// agent certificate binds the two together (its `mls` field), so a member's
/// leaf can be checked against the certificate chain by anyone who holds the
/// chain. The check is [`crate::AllowedIdentities`].
#[derive(Clone)]
pub struct LeafIdentity {
    agent_id: Vec<u8>,
    key: SigningKey,
}

impl LeafIdentity {
    /// `agent_id` is the identity bytes the credential carries and
    /// [`RineMlsGroup::member_index`](crate::RineMlsGroup::member_index) looks
    /// members up by; it must not be empty. `leaf_seed` is the 32-byte
    /// derived leaf signature seed.
    pub fn new(agent_id: &[u8], leaf_seed: &[u8]) -> Result<Self> {
        if agent_id.is_empty() {
            return Err(RineMlsError::EmptyAgentId);
        }

        let seed: Zeroizing<[u8; 32]> =
            Zeroizing::new(
                leaf_seed
                    .try_into()
                    .map_err(|_| RineMlsError::InvalidSigningSeed {
                        len: leaf_seed.len(),
                    })?,
            );

        Ok(Self {
            agent_id: agent_id.to_vec(),
            key: SigningKey::from_bytes(&seed),
        })
    }

    pub fn agent_id(&self) -> &[u8] {
        &self.agent_id
    }

    /// The raw 32-byte Ed25519 leaf signature public key: the `mls` field of
    /// the agent's certificate.
    pub fn leaf_public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// Provider seam: `mls-rs-crypto-rustcrypto` round-trips Ed25519 secrets
    /// through `ed25519_dalek::SigningKey::from_keypair_bytes`, i.e. it expects
    /// `seed || public_key` (64 bytes), not the bare 32-byte seed. Handing it
    /// rine's stored seed directly fails to parse, so expand it here — this is
    /// the only place the two representations meet.
    pub(crate) fn signer(&self) -> SignatureSecretKey {
        self.key.to_keypair_bytes().to_vec().into()
    }

    pub(crate) fn signing_identity(&self) -> SigningIdentity {
        SigningIdentity::new(
            BasicCredential::new(self.agent_id.clone()).into_credential(),
            SignaturePublicKey::from(self.leaf_public_key().to_vec()),
        )
    }
}
