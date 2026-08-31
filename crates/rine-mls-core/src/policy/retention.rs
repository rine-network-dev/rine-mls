//! How far back a group keeps epoch secrets, and where that number comes from.

use core::num::NonZeroUsize;

use crate::error::{Result, RineMlsError};

/// Days a message the server has already handed over can still be asked for.
///
/// rine's retention policy: delivered rows are dropped after ninety days,
/// undelivered ones are never dropped. This is the server-side number
/// [`EPOCH_RETENTION_DEFAULT`] is derived from, restated here because Rust
/// cannot import the server's Python and a client that retained less than the
/// server serves would turn served messages into unreadable inbox entries.
pub const MESSAGE_RETENTION_DAYS: usize = 90;

/// The largest group rine serves. Restated from `MAX_GROUP_MEMBERS` in
/// `src/rine/core/group_limits.py`, for the same reason as above. Used only to
/// derive the window below, and only as a *ceiling*: a copy that lagged behind
/// a lowered server ceiling would over-retain, never under-retain.
const CEILING_MEMBERS: usize = 500;

/// Peak modelled daily membership churn, as a percentage of a group's members.
///
/// The worst cell of the daily-usage model (`tests/scale_daily.rs`
/// `CHURN_RATES`): a tenth of the group changes every day — a complete
/// turnover every ten days. rine has no production churn distribution yet, so
/// the window is sized on the worst rate the model carries rather than on its
/// 2 % headline. Sizing on the headline would make the window ninety days only
/// for the groups that churn at the headline.
const PEAK_DAILY_CHURN_PERCENT: usize = 10;

/// Membership changes a day in the largest group rine serves, at the peak
/// modelled churn — and therefore epochs a day, because **one membership change
/// is exactly one epoch**.
///
/// That last step is the one that could have been wrong, so it is MEASURED
/// rather than reasoned: `tests/epoch_window.rs` drives a real group through a
/// modelled day and counts the epoch records that reach disk. One per commit,
/// zero per message — an epoch advances on a commit, never on traffic.
const PEAK_EPOCHS_PER_DAY: usize = CEILING_MEMBERS * PEAK_DAILY_CHURN_PERCENT / 100;

/// Prior epochs a group keeps secrets for under rine's shipped policy.
///
/// **Derived, not chosen.** [`MESSAGE_RETENTION_DAYS`] days of backlog, at
/// [`PEAK_EPOCHS_PER_DAY`] epochs a day:
///
/// ```text
/// 90 days  ×  ⌈500 members × 10 %/day⌉ epochs/day  =  4,500 epochs
///  policy      size ceiling   peak modelled churn
/// ```
///
/// A count was the only mechanism available — the store keys epochs by id, not
/// by date, and an age-based window would put message readability at the mercy
/// of the system clock, where a forward jump silently deletes secrets the
/// server is still serving. So the count is sized for the fastest group rine
/// serves, and every slower group gets *more* than ninety days rather than
/// less. A fixed count picked for the headline was rejected for the mirror
/// image of that reason: at high churn it would be days rather than months,
/// and a member offline through one busy week would lose backlog for reasons
/// unrelated to what the server still holds.
///
/// **What it costs and what it bounds.** MEASURED at the ceiling on both
/// suites (`tests/epoch_window.rs`): one membership change is one epoch and a
/// message is none; a retained epoch record is **17,239 B** at 500 members; so
/// a full window is **77.6 MB** for one group. That is a bound, not a new cost
/// — a group of 500 churning at the peak rate spends **861,950 B/day**, so it
/// reaches the same 77.6 MB today by day ninety and then keeps going, at
/// **+0.86 MB/day and +25.9 MB/month** for the life of the group. Every figure
/// in this paragraph is one group at 10 %/day and comes from the one test
/// named above; a portfolio figure for an agent in twenty-eight groups is a
/// different model and lives in `tests/scale_daily.rs`.
///
/// The same measurement priced the window in days at each modelled churn rate:
/// **90 days at 10 %, 450 at 2 %, 1,500 at 0.5 %** — every group at or below
/// the rate this is sized for gets more than the server's retention, never
/// less.
///
/// **The break-even, stated as the quantity it really is.** A percentage of
/// membership is how the window was derived and it is a misleading way to read
/// it, because what is retained is a COUNT. `4,500 ÷ 90` is **50 membership
/// changes a day, at any group size**: a group over that rate covers less than
/// ninety days however few members it has, and a group under it covers more
/// however many it has. Being small is not by itself protection — a six-member
/// group with one bot rejoining every ten minutes spends 288 epochs a day,
/// 5.8× the break-even, and covers about a fortnight.
///
/// **What is given up, in plain words.** Undelivered backlog older than the
/// window becomes permanently undecryptable on that device. Nothing the server
/// still serves is lost at the modelled rates; a message left undelivered for
/// longer than the window is, and no rotation brings it back — the epoch secret
/// is the only copy. Retained epochs serve undelivered backlog and nothing
/// else: a group message is opened once per reader, never re-read from MLS.
pub const EPOCH_RETENTION_DEFAULT: usize = MESSAGE_RETENTION_DAYS * PEAK_EPOCHS_PER_DAY;

/// How far back a group keeps epoch secrets on disk.
///
/// MLS forward secrecy is a property of what a client still holds: an epoch
/// secret that has been deleted cannot decrypt a message from that epoch, ever
/// again. So this number is not a cache size — it is the exact set of past
/// messages a returning agent can still open.
///
/// Every window is finite, and [`EpochRetention::DEFAULT`] is the one rine
/// ships. There is deliberately no "keep everything" setting: the unbounded
/// default this replaced grew for the life of the group and never fell, and a
/// policy that cannot be reached by leaving a knob unset is a policy no
/// deployment is on by accident.
///
/// A deployment that wants a narrower forward-secrecy window sets a smaller
/// number and accepts that a member absent for more commits than that cannot
/// read what it missed. That is a trade someone has to type a number to make —
/// the window cannot shorten on its own.
///
/// The setting takes any non-zero count, wider as well as narrower: a
/// deployment whose groups churn faster than fifty membership changes a day
/// needs a *larger* number to reach ninety days, and nothing here stops it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochRetention(NonZeroUsize);

impl EpochRetention {
    /// rine's shipped policy: [`EPOCH_RETENTION_DEFAULT`] prior epochs.
    pub const DEFAULT: Self = Self(match NonZeroUsize::new(EPOCH_RETENTION_DEFAULT) {
        Some(limit) => limit,
        None => panic!("the derived epoch-retention window must keep at least one epoch"),
    });

    /// Build the policy from the integer form a host configuration carries: an
    /// absent setting (`None`) is [`Self::DEFAULT`], `Some(n)` keeps the newest
    /// `n` prior epochs.
    ///
    /// **`None` is the shipped window, not an unbounded one.** Both bindings
    /// reach the policy through here, so this is the single seam that decides
    /// what an unconfigured client retains.
    ///
    /// Zero is refused rather than silently accepted. Keeping no prior epoch at
    /// all would make every message that arrives after the next commit
    /// undecryptable — not a tighter forward-secrecy window, a broken group.
    pub fn from_limit(limit: Option<usize>) -> Result<Self> {
        match limit {
            None => Ok(Self::DEFAULT),
            Some(n) => NonZeroUsize::new(n)
                .map(Self)
                .ok_or(RineMlsError::InvalidEpochRetention),
        }
    }

    /// The number of prior epochs kept.
    pub const fn limit(self) -> usize {
        self.0.get()
    }
}

impl Default for EpochRetention {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The model this window is sized against, restated as literals so the
    /// assertions below are a check and not a tautology: the group-size
    /// ceiling, the churn rates `tests/scale_daily.rs` sweeps, and the
    /// retention policy's ninety days.
    const CEILING: usize = 500;
    const MODELLED_CHURN_PER_MILLE: [usize; 3] = [5, 20, 100];
    const RETAINED_DAYS: usize = 90;

    #[test]
    fn test_epoch_retention_when_unset_is_the_shipped_window() {
        assert_eq!(EpochRetention::default(), EpochRetention::DEFAULT);
        assert_eq!(
            EpochRetention::from_limit(None).unwrap().limit(),
            EPOCH_RETENTION_DEFAULT,
        );
    }

    #[test]
    fn test_epoch_retention_when_shipped_covers_the_server_retention_at_every_modelled_churn() {
        for per_mille in MODELLED_CHURN_PER_MILLE {
            let epochs_a_day = (CEILING * per_mille).div_ceil(1000);
            let needed = RETAINED_DAYS * epochs_a_day;

            assert!(
                EPOCH_RETENTION_DEFAULT >= needed,
                "a group of {CEILING} churning {per_mille}/1000 a day spends {needed} epochs \
                 across the server's {RETAINED_DAYS}-day retention, and the shipped window \
                 keeps only {EPOCH_RETENTION_DEFAULT}",
            );
        }
    }

    #[test]
    fn test_epoch_retention_when_tightened_keeps_that_many_epochs() {
        assert_eq!(EpochRetention::from_limit(Some(3)).unwrap().limit(), 3);
    }

    /// The other side of the same seam, and the reason it is worth a test of its
    /// own: [`EpochRetention::from_limit`] rejects nothing but zero, so a
    /// configured window may be *wider* than the shipped one as well as
    /// narrower. Only the tightening case was pinned, which is how several
    /// surfaces came to describe the setting as "any smaller number".
    #[test]
    fn test_epoch_retention_when_widened_keeps_that_many_epochs() {
        let wider = EPOCH_RETENTION_DEFAULT * 2;

        assert_eq!(
            EpochRetention::from_limit(Some(wider)).unwrap().limit(),
            wider
        );
        assert_eq!(
            EpochRetention::from_limit(Some(usize::MAX))
                .unwrap()
                .limit(),
            usize::MAX,
        );
    }

    /// The window is an absolute COUNT, while every surface that describes it
    /// frames the budget as a percentage of membership. Those are the same
    /// thing only at the size it was derived for, so the break-even is pinned
    /// here as the size-independent quantity it actually is.
    #[test]
    fn test_epoch_retention_when_expressed_as_a_rate_is_independent_of_group_size() {
        assert_eq!(EPOCH_RETENTION_DEFAULT / MESSAGE_RETENTION_DAYS, 50);
        assert_eq!(PEAK_EPOCHS_PER_DAY, 50);
    }

    #[test]
    fn test_epoch_retention_when_set_to_zero_is_refused() {
        assert!(matches!(
            EpochRetention::from_limit(Some(0)).unwrap_err(),
            RineMlsError::InvalidEpochRetention
        ));
    }
}
