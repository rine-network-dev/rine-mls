//! Who an MLS group may seat: the `(agent id, leaf key)` pairs a client has
//! chain-verified, and the identity provider that holds every leaf to them.

mod provider;

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock};

use mls_rs::identity::basic::BasicCredential;
use mls_rs::identity::SigningIdentity;
use mls_rs_core::crypto::SignaturePublicKey;

pub use provider::{AllowedSetIdentityProvider, IdentityError};

use crate::error::{LeafUpdateFault, RineMlsError};

/// The `(agent id, leaf signature key)` pairs a client accepts as group
/// members, shared by every handle cloned from it.
///
/// The caller fills it with the pairs it has chain-verified against org-signed
/// agent certificates — every verified generation of an agent, not only the
/// current one, because MLS validates every leaf already in a tree it joins —
/// and keeps adding to it as it verifies more. A client holds the set it was
/// opened with, so an addition is seen by a client already open. The client's
/// own pair belongs in it too: nothing is implicitly trusted.
#[derive(Clone, Default)]
pub struct AllowedIdentities {
    pairs: Arc<RwLock<HashMap<SigningIdentity, u32>>>,
}

impl AllowedIdentities {
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit one pair at `generation`, the generation the agent's certificate
    /// chain signs for that key. Admitting a pair again at the same generation
    /// changes nothing; at another one is refused and the set keeps the first,
    /// because a pair has one generation and two answers mean a caller bug.
    pub fn insert(
        &self,
        agent_id: &[u8],
        leaf_public_key: &[u8],
        generation: u32,
    ) -> Result<(), RineMlsError> {
        let mut pairs = self.pairs.write().unwrap_or_else(PoisonError::into_inner);

        match pairs.entry(pair(agent_id, leaf_public_key)) {
            Entry::Vacant(slot) => {
                slot.insert(generation);
            }
            Entry::Occupied(held) if *held.get() != generation => {
                return Err(LeafUpdateFault::AllowedGenerationConflict {
                    agent_id: agent_id.to_vec(),
                }
                .into());
            }
            Entry::Occupied(_) => {}
        }

        Ok(())
    }

    pub fn contains(&self, agent_id: &[u8], leaf_public_key: &[u8]) -> bool {
        self.pairs
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .contains_key(&pair(agent_id, leaf_public_key))
    }

    pub(super) fn generation(&self, identity: &SigningIdentity) -> Option<u32> {
        self.pairs
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(identity)
            .copied()
    }

    pub(super) fn allows(&self, identity: &SigningIdentity) -> bool {
        self.generation(identity).is_some()
    }
}

fn pair(agent_id: &[u8], leaf_public_key: &[u8]) -> SigningIdentity {
    SigningIdentity::new(
        BasicCredential::new(agent_id.to_vec()).into_credential(),
        SignaturePublicKey::new_slice(leaf_public_key),
    )
}
