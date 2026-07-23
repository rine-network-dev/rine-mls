//! One owner for rine's MLS lifecycle policy: how far back a group keeps epoch
//! secrets, and how many KeyPackages an agent keeps published.
//!
//! These numbers decide what a returning agent can still read and whether a
//! peer can still add it to a group. Stating each of them once, here, is what
//! keeps the TypeScript and Python stacks from drifting into two policies for
//! one protocol — both bindings read these values rather than restating them.

use core::num::NonZeroUsize;

use crate::error::{Result, RineMlsError};

/// How far back a group keeps epoch secrets on disk.
///
/// MLS forward secrecy is a property of what a client still holds: an epoch
/// secret that has been deleted cannot decrypt a message from that epoch, ever
/// again. rine's server holds an undelivered message until it is delivered —
/// the undelivered queue drops *delivered* rows after 90 days and never drops
/// undelivered ones — so an agent returning from a long absence is handed
/// messages from however many epochs ago the group has churned through since.
/// Retaining less than that turns those rows into permanently unreadable inbox
/// entries, which is a message loss, not a degraded experience.
///
/// Hence the default, [`EpochRetention::FullBacklog`]: retention reaches
/// whatever the undelivered queue can still be holding. The cost is bounded by
/// the shape of MLS rather than by traffic — an epoch advances on a *commit*, a
/// membership change, never on a message — so a real rine group's full backlog
/// is tens of small files, not a per-message cost.
///
/// The trade-off is real, and is exactly why the knob exists: retained epoch
/// secrets sit on disk for as long as they are retained, so a wider backlog is
/// a wider forward-secrecy window. A deployment that would rather lose backlog
/// than keep old secrets around sets [`EpochRetention::Recent`] and accepts
/// that a member absent for more commits than that cannot read what it missed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochRetention {
    /// Keep every prior epoch the group has had. rine's default.
    FullBacklog,

    /// Keep only the newest `n` prior epochs, deleting the rest on every state
    /// write.
    Recent(NonZeroUsize),
}

impl EpochRetention {
    /// rine's shipped policy: reach the whole undelivered backlog.
    pub const DEFAULT: Self = Self::FullBacklog;

    /// Build the policy from the integer form a host configuration carries:
    /// an absent setting (`None`) is the full backlog, `Some(n)` keeps the
    /// newest `n` prior epochs.
    ///
    /// Zero is refused rather than silently accepted. Keeping no prior epoch at
    /// all would make every message that arrives after the next commit
    /// undecryptable — not a tighter forward-secrecy window, a broken group.
    pub fn from_limit(limit: Option<usize>) -> Result<Self> {
        match limit {
            None => Ok(Self::FullBacklog),
            Some(n) => NonZeroUsize::new(n)
                .map(Self::Recent)
                .ok_or(RineMlsError::InvalidEpochRetention),
        }
    }

    /// The number of prior epochs kept, or `None` when every one is kept.
    pub const fn limit(self) -> Option<usize> {
        match self {
            Self::FullBacklog => None,
            Self::Recent(n) => Some(n.get()),
        }
    }
}

impl Default for EpochRetention {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Inventory an agent's published KeyPackage pool is topped back up to.
///
/// The same value the TypeScript stack replenishes to, deliberately: an
/// inventory policy that differs by language is an agent that is addable from
/// one surface and not from another.
pub const KEY_PACKAGE_TARGET: usize = 10;

/// Inventory at or above which replenishment is a no-op.
pub const KEY_PACKAGE_LOW_WATER: usize = 3;

/// The largest batch of KeyPackages one publish call may mint.
///
/// A KeyPackage on the post-quantum suite is roughly 3.5 kB once base64'd, and
/// the server accepts up to 100 of them in a single `packages` array — a
/// ~357 kB request body, with no request-body ceiling configured anywhere in
/// rine's proxy or app tier to catch it. The cap therefore has to be applied by
/// the client, and it is applied here: 32 packages is about 114 kB, three times
/// [`KEY_PACKAGE_TARGET`] so a full drain-and-republish is still one request,
/// and far below the server's own 200-package inventory cap.
pub const KEY_PACKAGE_MAX_BATCH: usize = 32;

/// How many KeyPackages to mint given the inventory an agent still holds.
///
/// Low-water, not top-of-every-call: an agent at or above
/// [`KEY_PACKAGE_LOW_WATER`] mints nothing, and one below it goes back to
/// [`KEY_PACKAGE_TARGET`] in a single batch.
pub const fn key_package_shortfall(available: usize) -> usize {
    if available >= KEY_PACKAGE_LOW_WATER {
        return 0;
    }

    KEY_PACKAGE_TARGET.saturating_sub(available)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epoch_retention_when_unset_reaches_the_full_backlog() {
        assert_eq!(EpochRetention::default(), EpochRetention::FullBacklog);
        assert_eq!(EpochRetention::from_limit(None).unwrap().limit(), None);
    }

    #[test]
    fn test_epoch_retention_when_tightened_keeps_that_many_epochs() {
        assert_eq!(
            EpochRetention::from_limit(Some(3)).unwrap().limit(),
            Some(3)
        );
    }

    #[test]
    fn test_epoch_retention_when_set_to_zero_is_refused() {
        assert!(matches!(
            EpochRetention::from_limit(Some(0)).unwrap_err(),
            RineMlsError::InvalidEpochRetention
        ));
    }

    #[test]
    fn test_key_package_shortfall_when_inventory_is_healthy_mints_nothing() {
        assert_eq!(key_package_shortfall(KEY_PACKAGE_LOW_WATER), 0);
        assert_eq!(key_package_shortfall(KEY_PACKAGE_TARGET), 0);
    }

    #[test]
    fn test_key_package_shortfall_when_inventory_is_low_refills_to_target() {
        assert_eq!(key_package_shortfall(KEY_PACKAGE_LOW_WATER - 1), 8);
        assert_eq!(key_package_shortfall(0), KEY_PACKAGE_TARGET);
    }

    #[test]
    fn test_key_package_shortfall_never_exceeds_the_publish_batch_cap() {
        assert!(key_package_shortfall(0) <= KEY_PACKAGE_MAX_BATCH);
    }
}
