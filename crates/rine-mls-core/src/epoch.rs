use crate::error::{Result, RineMlsError};

/// An MLS epoch as the rine wire carries it.
///
/// RFC 9420 epochs are uint64, but the rine control plane moves them as JSON
/// numbers and the server stores them in a column bounded by int64 max
/// (`MLS_EPOCH_MAX`). Converting here means every binding refuses an epoch the
/// server could not have accepted, instead of each one truncating differently.
pub fn wire_epoch(epoch: u64) -> Result<i64> {
    i64::try_from(epoch).map_err(|_| RineMlsError::EpochOverflow { current: epoch })
}

/// Strict `current + 1` commit ordering.
///
/// The rine server CASes a group's epoch on every commit: a commit is accepted
/// only when it moves the group from `current` to `current + 1`, otherwise the
/// server raises `EpochConflictError`. Clients must apply the same rule locally
/// or they silently fork: a replayed or skipped commit would either be applied
/// twice or leave a hole no later commit can fill.
///
/// `commit_epoch` is the epoch the commit was *built at* (RFC 9420 puts the
/// sender's current epoch in the framing), so the epoch it produces is
/// `commit_epoch + 1`.
pub(crate) fn epoch_after_commit(current: u64, commit_epoch: u64) -> Result<u64> {
    if commit_epoch != current {
        return Err(RineMlsError::EpochConflict {
            current,
            commit: commit_epoch,
        });
    }

    current
        .checked_add(1)
        .ok_or(RineMlsError::EpochOverflow { current })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epoch_after_commit_when_commit_is_current_returns_next() {
        assert_eq!(epoch_after_commit(7, 7).unwrap(), 8);
    }

    #[test]
    fn test_epoch_after_commit_when_commit_is_stale_rejects() {
        let err = epoch_after_commit(7, 6).unwrap_err();
        assert!(matches!(
            err,
            RineMlsError::EpochConflict {
                current: 7,
                commit: 6
            }
        ));
    }

    #[test]
    fn test_epoch_after_commit_when_commit_skips_ahead_rejects() {
        let err = epoch_after_commit(7, 8).unwrap_err();
        assert!(matches!(err, RineMlsError::EpochConflict { .. }));
    }

    #[test]
    fn test_wire_epoch_when_within_the_server_bound_is_carried_unchanged() {
        assert_eq!(wire_epoch(9_223_372_036_854_775_807).unwrap(), i64::MAX);
    }

    #[test]
    fn test_wire_epoch_when_past_the_server_bound_reports_overflow() {
        let err = wire_epoch(u64::MAX).unwrap_err();
        assert!(matches!(err, RineMlsError::EpochOverflow { .. }));
    }

    #[test]
    fn test_epoch_after_commit_when_counter_saturated_reports_overflow() {
        let err = epoch_after_commit(u64::MAX, u64::MAX).unwrap_err();
        assert!(matches!(err, RineMlsError::EpochOverflow { .. }));
    }
}
