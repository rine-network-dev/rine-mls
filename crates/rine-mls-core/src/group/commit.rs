//! Building the commits rine posts to `POST /groups/{id}/mls/commit`.
//!
//! Every commit rine sends carries its proposals inline — the standalone
//! proposal endpoint exists on the server but is off the add and remove paths —
//! and republishes a GroupInfo, because a GroupInfo is spent by the epoch it
//! names.

use mls_rs::group::CommitOutput;
use mls_rs::{KeyPackageRef, MlsMessage};
use mls_rs_core::crypto::CryptoProvider;

use crate::crypto::RineCryptoProvider;
use crate::error::{LeafUpdateFault, Result, RineMlsError};
use crate::wire;

use super::RineMlsGroup;

#[cfg(test)]
mod path_tests;

/// Everything one rine commit produces: the commit to broadcast, one Welcome
/// per member the commit added, a fresh current-epoch GroupInfo for the next
/// external joiner, and the epoch the group is now at (what
/// `POST /groups/{id}/mls/commit` CASes on).
///
/// `welcomes[i]` is the Welcome for the member added by `key_packages[i]`, so a
/// caller that claimed those KeyPackages per agent can build the server's
/// `welcomes: [{agent_id, welcome}]` mapping straight off the index. That
/// alignment is established by matching each Welcome to its KeyPackage
/// reference, not by trusting the order MLS emitted them in.
#[derive(Debug, Clone)]
pub struct CommitBundle {
    pub commit: Vec<u8>,
    pub welcomes: Vec<Vec<u8>>,
    pub group_info: Vec<u8>,
    pub epoch: u64,
}

impl RineMlsGroup {
    /// Commit inline Add proposals for every claimed KeyPackage, in one commit.
    ///
    /// One commit for N members rather than N chained commits: the intermediate
    /// commits of a chain are never posted anywhere (rine's control plane takes
    /// a single commit blob), so each one is an epoch spent on a message no peer
    /// ever sees.
    ///
    /// An empty slice is a valid, member-less commit — the group-creation case,
    /// where rine still owes the server a commit blob.
    pub fn add_members(&mut self, key_packages: &[Vec<u8>]) -> Result<CommitBundle> {
        let (output, references) = self.build_add_commit(key_packages)?;

        self.finish_commit(output, &references)
    }

    /// Build the Add commit without applying it, alongside the KeyPackage
    /// reference of each member it admits. Split out from [`Self::add_members`]
    /// so the commit MLS produced can be inspected before it is consumed.
    fn build_add_commit(
        &mut self,
        key_packages: &[Vec<u8>],
    ) -> Result<(CommitOutput, Vec<KeyPackageRef>)> {
        self.active()?;

        let suite = self.cipher_suite()?;
        let added = key_packages
            .iter()
            .enumerate()
            .map(|(index, blob)| wire::decode_key_package(blob, index, suite))
            .collect::<Result<Vec<_>>>()?;

        let references = self.key_package_references(&added)?;

        let mut builder = self.inner.commit_builder();
        for key_package in added {
            builder = builder.add_member(key_package)?;
        }

        Ok((builder.build()?, references))
    }

    /// Commit one inline Add — rine's steady-state "member joins an existing
    /// group" path, where KeyPackages are claimed one agent at a time.
    pub fn add_member(&mut self, key_package: &[u8]) -> Result<CommitBundle> {
        self.add_members(&[key_package.to_vec()])
    }

    /// Commit an inline Remove. The evicted member reads no later message: the
    /// commit rekeys the group without it.
    pub fn remove_member(&mut self, leaf_index: u32) -> Result<CommitBundle> {
        self.active()?;

        let output = self
            .inner
            .commit_builder()
            .remove_member(leaf_index)?
            .build()?;

        self.finish_commit(output, &[])
    }

    /// The bundle an external-commit self-join produces. It carries no Welcome
    /// — an external commit adds nobody — and a GroupInfo minted at the joined
    /// epoch, because RFC 9420 spends a GroupInfo on every external join and the
    /// next joiner needs one.
    pub(crate) fn external_join_bundle(&self, commit: MlsMessage) -> Result<CommitBundle> {
        Ok(CommitBundle {
            commit: commit.to_bytes()?,
            welcomes: Vec::new(),
            group_info: self.group_info()?,
            epoch: self.epoch(),
        })
    }

    fn finish_commit(
        &mut self,
        output: CommitOutput,
        added: &[KeyPackageRef],
    ) -> Result<CommitBundle> {
        let commit = output.commit_message.to_bytes()?;
        let welcomes = welcomes_in_add_order(added, &output.welcome_messages)?;

        let group_info = next_group_info(&output)?;

        self.inner.apply_pending_commit()?;

        Ok(CommitBundle {
            commit,
            welcomes,
            group_info,
            epoch: self.epoch(),
        })
    }

    fn key_package_references(&self, added: &[MlsMessage]) -> Result<Vec<KeyPackageRef>> {
        let suite = self.inner.cipher_suite();
        let provider = RineCryptoProvider.cipher_suite_provider(suite).ok_or(
            RineMlsError::UnsupportedCipherSuite {
                id: suite.raw_value(),
            },
        )?;

        added
            .iter()
            .enumerate()
            .map(|(index, key_package)| {
                key_package
                    .key_package_reference(&provider)?
                    .ok_or(RineMlsError::UnreadableKeyPackage { index })
            })
            .collect()
    }
}

/// The GroupInfo of the epoch a built commit creates, which the commit's own
/// output carries because the rules ask for it. Read from the output, not from
/// the group, so it exists before the commit is applied.
pub(super) fn next_group_info(output: &CommitOutput) -> Result<Vec<u8>> {
    let group_info = output
        .external_commit_group_info
        .as_ref()
        .ok_or(LeafUpdateFault::MissingGroupInfo)?;

    Ok(group_info.to_bytes()?)
}

/// Pair each added member with its own Welcome.
///
/// MLS may put every joiner's group secrets in a single Welcome; rine's control
/// plane cannot use that, because it delivers a Welcome per agent. This client
/// therefore always asks for one Welcome per added member — and then proves the
/// mapping rather than assuming it, by matching each Welcome against the
/// KeyPackage reference it was encrypted to. A one-member commit gets the same
/// treatment as a ten-member one, so the batching case is not a second path
/// that only runs when someone remembers to test it.
fn welcomes_in_add_order(added: &[KeyPackageRef], produced: &[MlsMessage]) -> Result<Vec<Vec<u8>>> {
    added
        .iter()
        .enumerate()
        .map(|(index, reference)| {
            let welcome = produced
                .iter()
                .find(|welcome| {
                    welcome
                        .welcome_key_package_references()
                        .contains(&reference)
                })
                .ok_or(RineMlsError::MissingWelcome { index })?;

            Ok(welcome.to_bytes()?)
        })
        .collect()
}
