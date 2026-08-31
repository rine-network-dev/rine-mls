use napi::bindgen_prelude::Uint8Array;
use napi_derive::napi;
use rine_mls_core::{wire_epoch, PanicGuard, RineMlsError, RineMlsGroup};

use crate::error::{from_core, guard, MlsError};
use crate::types::{
    convert_bundle, into_members, to_vecs, AppMessage, CommitBundle, MemberIdentity,
};

/// One MLS group as seen by one agent.
///
/// Ownership: the handle owns its Rust state and the JS garbage collector owns
/// the handle. Every byte string crossing the boundary is copied — a JS
/// `Uint8Array` argument is read during the call and never retained, and a
/// returned `Uint8Array` owns a `Vec<u8>` moved out of Rust. No pointer into
/// either heap outlives a call.
///
/// Nothing is written to disk until [`MlsGroup::save`], mirroring the core: post
/// the commit, let the server's epoch CAS rule on it, and only then persist, so
/// a rejected commit leaves no forked state behind.
#[napi]
pub struct MlsGroup {
    inner: RineMlsGroup,
    last_commit: Option<rine_mls_core::CommitBundle>,
    /// `pub(crate)` only so the `panic-probe` module can trip it deliberately.
    pub(crate) poison: PanicGuard,
}

#[napi]
impl MlsGroup {
    pub(crate) fn new(
        inner: RineMlsGroup,
        last_commit: Option<rine_mls_core::CommitBundle>,
    ) -> Self {
        Self {
            inner,
            last_commit,
            poison: PanicGuard::default(),
        }
    }

    /// The rine group UUID's raw bytes — MLS state is keyed by it, never by the
    /// server's opaque `mls_group_id` latch.
    #[napi]
    pub fn group_id(&mut self) -> Result<Uint8Array, MlsError> {
        let inner = &self.inner;
        guard(&mut self.poison, || Ok(inner.group_id())).map(Uint8Array::new)
    }

    #[napi]
    pub fn epoch(&mut self) -> Result<i64, MlsError> {
        let inner = &self.inner;
        guard(&mut self.poison, || wire_epoch(inner.epoch()))
    }

    /// The group's own suite, read from its group context — what a Welcome
    /// joiner records as `mls_cipher_suite`, rather than whatever suite the
    /// client that opened it mints with.
    #[napi]
    pub fn cipher_suite(&mut self) -> Result<u16, MlsError> {
        let inner = &self.inner;
        guard(&mut self.poison, || Ok(inner.cipher_suite()?.id()))
    }

    /// False once a Remove commit evicted this member. **A sync loop must check
    /// this after `applyCommit`**: eviction is not an error there, it is the
    /// correct outcome of a valid commit. Every operation that would change or
    /// use the group then fails `RINE_MLS_GROUP_INACTIVE`; decryption stays open
    /// for the backlog this member already held secrets for.
    #[napi]
    pub fn is_active(&mut self) -> Result<bool, MlsError> {
        let inner = &self.inner;
        guard(&mut self.poison, || Ok(inner.is_active()))
    }

    /// Leaf index of the member whose basic-credential identity (its raw
    /// Ed25519 public key) is `identity` — the input to [`Self::remove_member`].
    #[napi]
    pub fn member_index(&mut self, identity: Uint8Array) -> Result<u32, MlsError> {
        let inner = &self.inner;
        guard(&mut self.poison, || inner.member_index(&identity))
    }

    /// Every occupied leaf in the ratchet tree, as `{ index, identity }` — the
    /// inverse of `memberIndex`, and the only way to learn that a leaf exists
    /// without already knowing whose it is. That is what an *orphan* leaf
    /// needs: one whose agent the server reports in neither
    /// `GET /groups/{id}/members` nor
    /// `GET /groups/{id}/requests?outstanding=live`, so no caller can produce
    /// its identity to ask about it.
    ///
    /// A leaf carrying a credential this core cannot read fails the whole call
    /// with `RINE_MLS_UNREADABLE_CREDENTIAL` rather than being skipped. Order
    /// follows the tree, so it is stable for a given tree but carries no
    /// meaning — never index into the result to identify a member.
    #[napi]
    pub fn member_identities(&mut self) -> Result<Vec<MemberIdentity>, MlsError> {
        let inner = &self.inner;
        guard(&mut self.poison, || inner.member_identities()).map(into_members)
    }

    /// This handle's own leaf index — the `staleLeaf` argument to
    /// `MlsClient.resyncByExternalCommit`, and the only place it may come from.
    /// The server does not know MLS leaf indices.
    #[napi]
    pub fn current_member_index(&mut self) -> Result<u32, MlsError> {
        let inner = &self.inner;
        guard(&mut self.poison, || inner.current_member_index())
    }

    /// A fresh GroupInfo for the current epoch, carrying `external_pub` and the
    /// ratchet tree. Single-use per epoch, so every commit republishes one.
    #[napi]
    pub fn group_info(&mut self) -> Result<Uint8Array, MlsError> {
        let inner = &self.inner;
        guard(&mut self.poison, || inner.group_info()).map(Uint8Array::new)
    }

    /// The commit produced by whatever created this handle: the init commit
    /// after `createGroup`/`createGroupWithMembers`, the external commit after
    /// `joinByExternalCommit`, the last add/remove otherwise. `null` for a
    /// Welcome join, which mints no commit.
    #[napi]
    pub fn last_commit(&mut self) -> Result<Option<CommitBundle>, MlsError> {
        let last = &self.last_commit;
        let bundle = guard(&mut self.poison, || Ok(last.clone()))?;

        bundle.map(convert_bundle).transpose().map_err(from_core)
    }

    /// Commit an inline Add — rine's steady-state one-agent-at-a-time add.
    #[napi]
    pub fn add_member(&mut self, key_package: Uint8Array) -> Result<CommitBundle, MlsError> {
        self.commit(|inner| inner.add_member(&key_package))
    }

    /// Commit inline Adds for every claimed KeyPackage, in one commit.
    /// `welcomes[i]` is the Welcome for `keyPackages[i]`.
    #[napi]
    pub fn add_members(&mut self, key_packages: Vec<Uint8Array>) -> Result<CommitBundle, MlsError> {
        let owned = to_vecs(&key_packages);
        self.commit(move |inner| inner.add_members(&owned))
    }

    /// Commit an inline Remove. The evicted member reads no later message.
    #[napi]
    pub fn remove_member(&mut self, leaf_index: u32) -> Result<CommitBundle, MlsError> {
        self.commit(|inner| inner.remove_member(leaf_index))
    }

    /// Apply a commit from `GET /groups/{id}/mls/handshakes`. Refuses anything
    /// but the group's own `current + 1`, the same CAS the server enforces.
    #[napi]
    pub fn apply_commit(&mut self, commit: Uint8Array) -> Result<i64, MlsError> {
        let inner = &mut self.inner;
        guard(&mut self.poison, || {
            wire_epoch(inner.apply_commit(&commit)?)
        })
    }

    /// Encrypt a signed rine envelope into an `mls-v1` payload — version tag
    /// included, base64url left to the transport.
    #[napi]
    pub fn encrypt_application_message(
        &mut self,
        envelope: Uint8Array,
    ) -> Result<Uint8Array, MlsError> {
        let inner = &mut self.inner;
        guard(&mut self.poison, || {
            inner.encrypt_application_message(&envelope)
        })
        .map(Uint8Array::new)
    }

    /// Decrypt a base64url-decoded `encrypted_payload`. A message this member
    /// sent comes back from the self-read cache, or as
    /// `RINE_MLS_SELF_MESSAGE_NOT_CACHED` once it has aged out.
    #[napi]
    pub fn decrypt_application_message(
        &mut self,
        payload: Uint8Array,
    ) -> Result<AppMessage, MlsError> {
        let inner = &mut self.inner;
        let message = guard(&mut self.poison, || {
            inner.decrypt_application_message(&payload)
        })?;

        Ok(AppMessage {
            envelope: Uint8Array::new(message.envelope),
            sender_index: message.sender_index,
        })
    }

    /// Persist to the local store. Never sent to the server.
    #[napi]
    pub fn save(&mut self) -> Result<(), MlsError> {
        let inner = &mut self.inner;
        guard(&mut self.poison, || inner.save())
    }

    fn commit(
        &mut self,
        build: impl FnOnce(&mut RineMlsGroup) -> Result<rine_mls_core::CommitBundle, RineMlsError>,
    ) -> Result<CommitBundle, MlsError> {
        let inner = &mut self.inner;
        let bundle = guard(&mut self.poison, || build(inner))?;

        self.last_commit = Some(bundle.clone());
        convert_bundle(bundle).map_err(from_core)
    }
}
