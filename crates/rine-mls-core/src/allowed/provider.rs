//! The MLS identity provider that holds every leaf to the allowed set.

use mls_rs::identity::basic::BasicCredential;
use mls_rs::identity::{CredentialType, SigningIdentity};
use mls_rs::time::MlsTime;
use mls_rs_core::error::IntoAnyError;
use mls_rs_core::extension::ExtensionList;
use mls_rs_core::identity::{IdentityProvider, MemberValidationContext};

use super::AllowedIdentities;
use crate::error::AgentLabel;

/// Why the identity provider refused a leaf.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("unsupported credential type {0:?}: rine members carry basic credentials")]
    UnsupportedCredential(CredentialType),

    #[error(
        "agent {} is not in the allowed set with the leaf key it carries",
        AgentLabel(agent_id)
    )]
    NotAllowed { agent_id: Vec<u8> },
}

impl IntoAnyError for IdentityError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}

/// The MLS identity provider: a leaf is valid only if its basic credential and
/// signature key, taken together, are in the [`AllowedIdentities`].
///
/// A successor leaf must carry the same agent id as the leaf it replaces, and
/// either the same signature key or a key of a strictly newer chain-verified
/// generation: that is how a self-update moves a seat to a rotated key. An
/// external commit is held to the same key by the client's MLS rules, so a
/// resync never changes it.
#[derive(Clone)]
pub struct AllowedSetIdentityProvider {
    allowed: AllowedIdentities,
}

impl AllowedSetIdentityProvider {
    pub fn new(allowed: AllowedIdentities) -> Self {
        Self { allowed }
    }
}

fn basic(identity: &SigningIdentity) -> Result<&BasicCredential, IdentityError> {
    identity
        .credential
        .as_basic()
        .ok_or_else(|| IdentityError::UnsupportedCredential(identity.credential.credential_type()))
}

fn check(allowed: &AllowedIdentities, identity: &SigningIdentity) -> Result<(), IdentityError> {
    let credential = basic(identity)?;

    allowed
        .allows(identity)
        .then_some(())
        .ok_or_else(|| IdentityError::NotAllowed {
            agent_id: credential.identifier.clone(),
        })
}

impl IdentityProvider for AllowedSetIdentityProvider {
    type Error = IdentityError;

    fn validate_member(
        &self,
        signing_identity: &SigningIdentity,
        _timestamp: Option<MlsTime>,
        _context: MemberValidationContext<'_>,
    ) -> Result<(), Self::Error> {
        check(&self.allowed, signing_identity)
    }

    fn validate_external_sender(
        &self,
        signing_identity: &SigningIdentity,
        _timestamp: Option<MlsTime>,
        _extensions: Option<&ExtensionList>,
    ) -> Result<(), Self::Error> {
        check(&self.allowed, signing_identity)
    }

    fn identity(
        &self,
        signing_identity: &SigningIdentity,
        _extensions: &ExtensionList,
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(basic(signing_identity)?.identifier.clone())
    }

    fn valid_successor(
        &self,
        predecessor: &SigningIdentity,
        successor: &SigningIdentity,
        _extensions: &ExtensionList,
    ) -> Result<bool, Self::Error> {
        let (from, to) = (basic(predecessor)?, basic(successor)?);

        if predecessor == successor {
            return Ok(true);
        }
        if from.identifier != to.identifier {
            return Ok(false);
        }

        let generation = |identity| {
            self.allowed
                .generation(identity)
                .ok_or_else(|| IdentityError::NotAllowed {
                    agent_id: to.identifier.clone(),
                })
        };

        Ok(generation(successor)? > generation(predecessor)?)
    }

    fn supported_types(&self) -> Vec<CredentialType> {
        vec![BasicCredential::credential_type()]
    }
}
