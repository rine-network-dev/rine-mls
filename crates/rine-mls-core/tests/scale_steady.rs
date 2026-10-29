//! Measurement B — what an ordinary day in a large group costs, per operation.
//!
//! Founding a group is a one-off. What decides whether rine can carry
//! thousand-member groups is the steady state: one Add, one Remove, one
//! application message, and what each of them leaves on disk. The
//! application-message overhead in particular was measured nowhere in this repo
//! before this file — and whether it is constant in the group size or grows
//! with it is the difference between a large group being cheap to talk in and
//! being unusable.
//!
//! `#[ignore]`d because the thousand-member row founds a real thousand-member
//! group, which is not work `ci.sh` stage 8 should do.
//!
//! ```text
//! cargo test --release -p rine-mls-core --test scale_steady -- --ignored --nocapture
//! ```

mod common;

use common::for_each_suite;
use common::scale::{millis, secs};
use common::unit_costs::UnitCosts;

/// Group sizes to take the steady-state deltas at. The spread is the point: a
/// cost that is O(log N) and one that is O(N) are indistinguishable at a single
/// size.
///
/// 500 is here for a second reason and is not interchangeable with the others:
/// it is `MAX_GROUP_MEMBERS`, and its `churn_commit` is the unit the ceiling
/// decision's own per-member daily cost is composed from
/// (`src/rine/core/group_limits.py`). That row was quoted for a year without
/// ever being measured — the sizes bracketing it were, and the figure between
/// them was interpolated by hand and came out ~25 % high.
const SIZES: [usize; 5] = [16, 100, 250, 500, 1000];

/// Commit size against group size, as an exponent: `size ∝ N^e`. The design
/// note this measurement was written to check assumed `e ≈ 0` (an UpdatePath
/// over the committer's direct path, so logarithmic in N). Superlinear growth
/// is something else again and would be a regression in the commit shape, not
/// a scaling property — that is what this bound guards.
const SUPERLINEAR_EXPONENT: f64 = 1.1;

/// The steady-state table: one Add, one Remove, one application message and the
/// on-disk residue, at four group sizes on every suite.
///
/// ```text
/// cargo test --release -p rine-mls-core --test scale_steady -- --ignored --nocapture \
///     test_steady_state_deltas_when_the_group_is_large
/// ```
#[test]
#[ignore = "founds a real 1000-member group per suite"]
fn test_steady_state_deltas_when_the_group_is_large() {
    for_each_suite(|suite| {
        let measured: Vec<UnitCosts> = SIZES
            .iter()
            .map(|&size| {
                let costs = UnitCosts::measure(size, suite, 0xC0, 0);
                report(&costs);
                costs
            })
            .collect();

        let small = &measured[0];
        let large = measured.last().expect("one row per size");
        let span = large.size as f64 / small.size as f64;

        let commit_exponent = exponent(small.churn_commit, large.churn_commit, span);
        eprintln!(
            "B* suite 0x{:04X}  N {} -> {} (x{span:.1})  commit N^{commit_exponent:.2}  \
             state N^{:.2}  app_overhead {} -> {} B  decrypt x{:.2}  encrypt x{:.2}  \
             (exponent 1.0 = linear in N, 0.0 = flat)",
            suite.id(),
            small.size,
            large.size,
            exponent(small.state_bytes as usize, large.state_bytes as usize, span),
            small.app_overhead,
            large.app_overhead,
            large.decrypt.as_secs_f64() / small.decrypt.as_secs_f64(),
            large.encrypt.as_secs_f64() / small.encrypt.as_secs_f64(),
        );

        assert_eq!(
            small.app_overhead,
            large.app_overhead,
            "an application message's MLS overhead must not depend on the group size — \
             it did at 0x{:04X}, which would make large groups expensive to talk in",
            suite.id(),
        );
        assert_eq!(large.remove_welcomes, 0, "a Remove admits nobody");
        assert!(
            commit_exponent < SUPERLINEAR_EXPONENT,
            "commit size grows as N^{commit_exponent:.2} on suite 0x{:04X} — superlinear, \
             which is a change in the commit's shape rather than a scaling property",
            suite.id(),
        );
    });
}

/// The exponent `e` in `cost ∝ N^e`, taken between two measured sizes. Stating
/// growth this way rather than as a ratio makes "logarithmic" and "linear"
/// directly comparable across suites whose absolute sizes differ by an order of
/// magnitude.
fn exponent(small: usize, large: usize, span: f64) -> f64 {
    (large as f64 / small as f64).ln() / span.ln()
}

fn report(costs: &UnitCosts) {
    eprintln!(
        "B1 suite 0x{:04X}  N {:4}  app_payload {:5} B (MLS overhead +{:3} B)  \
         add_commit {:7} B  add_welcome {:9} B  add_group_info {:9} B  \
         remove_commit {:7} B (welcomes {})  churn_commit {:7} B",
        costs.suite.id(),
        costs.size,
        costs.app_payload,
        costs.app_overhead,
        costs.add_commit,
        costs.add_welcome,
        costs.add_group_info,
        costs.remove_commit,
        costs.remove_welcomes,
        costs.churn_commit,
    );
    eprintln!(
        "B2 suite 0x{:04X}  N {:4}  state.bin {:9} B  group dir {:10} B  \
         epoch {:9} B x{:2}  self_read {:7} B  founding POST {:10} B",
        costs.suite.id(),
        costs.size,
        costs.state_bytes,
        costs.group_dir_bytes,
        costs.epoch_bytes,
        costs.epochs_kept,
        costs.self_read_bytes,
        costs.founding_total,
    );
    eprintln!(
        "B3 suite 0x{:04X}  N {:4}  found {:6.2} s  welcome-join {:7.3} s  \
         encrypt {:7.3} ms  decrypt {:7.3} ms  apply_add {:7.3} ms  \
         apply_remove {:7.3} ms  apply_churn {:7.3} ms  save {:7.3} ms",
        costs.suite.id(),
        costs.size,
        secs(costs.found_in),
        secs(costs.join_in),
        millis(costs.encrypt),
        millis(costs.decrypt),
        millis(costs.apply_add),
        millis(costs.apply_remove),
        millis(costs.apply_churn),
        millis(costs.save),
    );
}
