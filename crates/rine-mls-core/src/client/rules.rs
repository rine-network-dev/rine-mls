//! The MLS rules every rine client runs, and the one rule beyond mls-rs's
//! defaults: an external commit may rejoin a seat, never change its key.

use mls_rs::group::{GroupContext, Roster};
use mls_rs::mls_rules::{
    CommitDirection, CommitOptions, CommitSource, EncryptionOptions, ProposalBundle,
};
use mls_rs::MlsRules;
use mls_rs_core::error::IntoAnyError;
use mls_rs_core::identity::SigningIdentity;

use crate::error::AgentLabel;

/// Why the rules refused a commit.
#[derive(Debug, thiserror::Error)]
pub enum RineRulesError {
    #[error(
        "an external commit by agent {} replaces its leaf with a different key",
        AgentLabel(agent_id)
    )]
    ExternalCommitChangesKey { agent_id: Vec<u8> },
}

impl IntoAnyError for RineRulesError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}

#[derive(Clone)]
pub struct RineMlsRules {
    commit_options: CommitOptions,
}

impl RineMlsRules {
    pub fn new() -> Self {
        // Four commit options rine's control plane depends on:
        //
        // - the ratchet tree rides in every commit and GroupInfo, because rine
        //   has no out-of-band tree-sync channel, so a joiner's only source of
        //   the tree is the extension inside what it is handed;
        // - one Welcome per added member, never one shared Welcome, because
        //   rine delivers Welcomes per agent (`welcomes: [{agent_id, welcome}]`)
        //   and a shared one has no single recipient to address it to. MLS
        //   defaults the other way, so this is set rather than assumed;
        // - every commit carries an UpdatePath, always. MLS lets a commit that
        //   only adds members skip the path, and then the committer's own leaf
        //   keys and the path above it are unchanged across the epoch: the new
        //   epoch's secrets are derived from key material a member who was
        //   compromised before it already holds, so that epoch inherits the
        //   compromise instead of healing it. Post-compromise security is a
        //   property rine states about its groups, and it is only true if the
        //   path is there on every commit, so this is not a knob;
        // - every commit also yields the GroupInfo of the epoch it creates, so
        //   a commit that is built but not yet applied (the self-update) can
        //   still hand its caller the GroupInfo an external joiner will need.
        Self {
            commit_options: CommitOptions::new()
                .with_ratchet_tree_extension(true)
                .with_single_welcome_message(false)
                .with_path_required(true)
                .with_allow_external_commit(true),
        }
    }
}

impl MlsRules for RineMlsRules {
    type Error = RineRulesError;

    fn filter_proposals(
        &self,
        _direction: CommitDirection,
        source: CommitSource,
        current_roster: &Roster,
        _current_context: &GroupContext,
        proposals: ProposalBundle,
    ) -> Result<ProposalBundle, Self::Error> {
        if let CommitSource::NewMember(joiner) = &source {
            for removal in proposals.remove_proposals() {
                let replaced = current_roster.member_with_index(removal.proposal.to_remove());
                if replaced.is_ok_and(|member| member.signing_identity != *joiner) {
                    return Err(RineRulesError::ExternalCommitChangesKey {
                        agent_id: joiner_agent_id(joiner),
                    });
                }
            }
        }

        Ok(proposals)
    }

    fn commit_options(
        &self,
        _new_roster: &Roster,
        _new_context: &GroupContext,
        _proposals: &ProposalBundle,
    ) -> Result<CommitOptions, Self::Error> {
        Ok(self.commit_options)
    }

    fn encryption_options(
        &self,
        _current_roster: &Roster,
        _current_context: &GroupContext,
    ) -> Result<EncryptionOptions, Self::Error> {
        Ok(EncryptionOptions::default())
    }
}

/// The agent id a joiner's basic credential carries, empty for any other kind.
fn joiner_agent_id(joiner: &SigningIdentity) -> Vec<u8> {
    joiner
        .credential
        .as_basic()
        .map(|basic| basic.identifier.clone())
        .unwrap_or_default()
}
