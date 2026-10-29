//! An agent's KeyPackage pool: minting, inventory, low-water replenishment and
//! the release-time drain.
//!
//! Ordering is the whole of the correctness story here, and it runs one way:
//! **the private half is on disk before the public blob is published.** mls-rs
//! writes the private half during minting, so every blob these calls return is
//! already backed locally. The reverse order would let the server hand a peer a
//! KeyPackage whose private half this agent never stored, and the Welcome that
//! peer sends back would be permanently unprocessable. The cost of this
//! ordering is a private half whose upload failed — a wasted file, and a local
//! inventory that over-counts and so tops up later than it might have.
//!
//! Reading the inventory runs the same way round. `GET
//! /agents/{id}/mls/key-packages` is a *claim*: it consumes what it returns, so
//! it can never be used to ask how many are left. The local mirror is the only
//! non-destructive count rine has.

use mls_rs::ExtensionList;

use crate::error::{MlsBlobKind, Result, RineMlsError};
use crate::policy::{key_package_shortfall, KEY_PACKAGE_MAX_BATCH, KEY_PACKAGE_TARGET};
use crate::suite::RineCipherSuite;
use crate::wire;

use super::RineMlsClient;

impl RineMlsClient {
    /// Mint one KeyPackage for `POST /agents/{id}/mls/key-packages`. The
    /// private half lands in this agent's local key-package store; only the
    /// returned public blob leaves the machine.
    pub fn generate_key_package(&self) -> Result<Vec<u8>> {
        let message = self.inner.generate_key_package_message(
            ExtensionList::new(),
            ExtensionList::new(),
            None,
        )?;

        Ok(message.to_bytes()?)
    }

    /// Mint `count` KeyPackages for one publish request.
    ///
    /// Capped at [`KEY_PACKAGE_MAX_BATCH`] rather than at the server's
    /// hundred-package array limit: a hundred post-quantum KeyPackages is a
    /// ~357 kB request body, and rine's proxy and app tier configure no
    /// request-body ceiling at all, so the only place this can be bounded is
    /// here. Over the cap is a typed refusal, not a truncated batch — silently
    /// publishing fewer than asked would leave the caller believing an
    /// inventory it does not have.
    pub fn generate_key_packages(&self, count: usize) -> Result<Vec<Vec<u8>>> {
        if count > KEY_PACKAGE_MAX_BATCH {
            return Err(RineMlsError::KeyPackageBatchTooLarge {
                requested: count,
                max: KEY_PACKAGE_MAX_BATCH,
            });
        }

        (0..count).map(|_| self.generate_key_package()).collect()
    }

    /// How many published KeyPackages this agent still holds the private half
    /// of — its inventory, read locally because the server offers no
    /// non-destructive count.
    pub fn key_package_count(&self) -> Result<usize> {
        Ok(self.key_packages.count()?)
    }

    /// Mint the batch a low-water top-up needs, or nothing when the inventory is
    /// healthy.
    ///
    /// The caller publishes whatever comes back and does nothing when it is
    /// empty. The thresholds are [`crate::KEY_PACKAGE_LOW_WATER`] and
    /// [`KEY_PACKAGE_TARGET`], which is also what the TypeScript stack
    /// replenishes against: an agent must not be addable from one surface and
    /// not from another.
    ///
    /// Replenishment exists because every add by a peer consumes one KeyPackage
    /// globally, so an agent that never tops up eventually becomes un-addable —
    /// and the agent that hits that wall is the *adder*, which cannot fix it.
    /// Only the pool's owner can, which is why this runs on the owner's own MLS
    /// operations rather than on demand.
    pub fn replenish_key_packages(&self) -> Result<Vec<Vec<u8>>> {
        self.generate_key_packages(key_package_shortfall(self.key_package_count()?))
    }

    /// Drain this agent's KeyPackage pool and mint a fresh one.
    ///
    /// rine's MLS cutover leaves every pre-cutover KeyPackage unreadable by
    /// this core, and unreadable in its entirety — a peer that meets one gets
    /// [`RineMlsError::UnreadableKeyPackage`] for every entry in that pool, so
    /// there is no retry that helps and no partial pool worth keeping. The pool
    /// is replaced wholesale, on both sides: the caller drains the server's
    /// copy and publishes what this returns.
    ///
    /// The new batch is minted **before** the old private halves are deleted,
    /// so a crash in the middle leaves both pools on disk — harmless, since a
    /// stale private half only costs a file — rather than a published pool with
    /// no private halves at all, which would make every incoming Welcome
    /// unprocessable.
    pub fn drain_and_republish_key_packages(&self) -> Result<Vec<Vec<u8>>> {
        let stale = self.key_packages.stored_refs()?;
        let fresh = self.generate_key_packages(KEY_PACKAGE_TARGET)?;

        for id in stale {
            self.key_packages.remove(&id)?;
        }

        Ok(fresh)
    }

    /// Give back the private half of the KeyPackage a Welcome was sealed to,
    /// for a Welcome that left the caller's spool without being opened. The
    /// local inventory then falls, and the ordinary top-up republishes.
    ///
    /// Returns `true` when exactly one of the Welcome's KeyPackageRefs names a
    /// private half in this client's store, and deletes that half. Returns
    /// `false`, deleting nothing, when none does or when more than one does: a
    /// real Welcome names this agent once, so a forged one that names several
    /// of its refs is refused. Idempotent: a second call finds nothing.
    ///
    /// Never call it for a Welcome that was installed — installing consumes the
    /// half itself.
    pub fn discard_welcome_key_package(&self, welcome: &[u8]) -> Result<bool> {
        let message = wire::decode(welcome, MlsBlobKind::Welcome, self.suite)?;

        let mut held = Vec::new();
        for reference in message.welcome_key_package_references() {
            if self.key_packages.holds(reference)? {
                held.push(reference);
            }
        }

        match held.as_slice() {
            [only] => {
                self.key_packages.remove(only)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

/// The leaf signature key a KeyPackage carries, for the claim check. The
/// KeyPackage's own signature is checked when an Add is built from it, not here.
pub fn key_package_signature_key(key_package: &[u8]) -> Result<Vec<u8>> {
    let message = wire::decode_key_package(key_package, 0, RineCipherSuite::DEFAULT)?;
    let key_package = message
        .into_key_package()
        .ok_or(RineMlsError::UnreadableKeyPackage { index: 0 })?;

    Ok(key_package.signing_identity().signature_key.to_vec())
}
