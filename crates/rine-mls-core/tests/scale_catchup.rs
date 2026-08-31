//! Open item 2 — what an agent pays for having been offline.
//!
//! MLS commits apply in order and cannot be skipped, so an agent that missed a
//! day of churn has to process every commit it missed, in sequence. There is
//! therefore a group size and an absence length past which throwing the local
//! state away and re-joining by external commit is simply cheaper than catching
//! up, and where that crossover sits is a product number: it is the point at
//! which rine should stop syncing and start rejoining.
//!
//! The crossover is not free to cross. An external join is a new leaf with no
//! history, so the backlog the missed epochs would have decrypted is gone —
//! this measurement says when rejoining becomes cheap, not when it becomes
//! correct.
//!
//! ```text
//! cargo test --release -p rine-mls-core --test scale_catchup -- --ignored --nocapture
//! ```

mod common;

use std::time::{Duration, Instant};

use common::scale::{found, millis, secs};
use common::{base64_len, for_each_suite, TestAgent};
use rine_mls_core::RineCipherSuite;

/// The group the crossover is measured on. The question only bites at scale: at
/// sixteen members a commit is small enough that no absence is worth rejoining
/// over.
const SIZE: usize = 1000;

/// Commits to mint and then catch up on. A 1000-member group at the plan's 2 %
/// daily churn turns over twenty members a day, so two thousand commits is
/// about three months of absence.
const COMMITS: usize = 2000;

/// Absences to report the running cost at. Twenty is one day at 2 % churn of a
/// thousand-member group — the headline cell of the daily simulation.
const CHECKPOINTS: [usize; 7] = [1, 10, 20, 100, 500, 1000, 2000];

/// ```text
/// cargo test --release -p rine-mls-core --test scale_catchup -- --ignored --nocapture \
///     test_offline_catchup_against_a_fresh_external_join
/// ```
#[test]
#[ignore = "founds a 1000-member group and applies 2000 commits, per suite"]
fn test_offline_catchup_against_a_fresh_external_join() {
    for_each_suite(catchup_curve);
}

fn catchup_curve(suite: RineCipherSuite) {
    let mut cohort = found(SIZE, 2, suite, 0xD0, 0);
    eprintln!(
        "E0 suite 0x{:04X}  N {SIZE}  founded in {:.2} s  Welcome-join {:.3} s  \
         one Welcome {} B",
        suite.id(),
        secs(cohort.found_in),
        secs(cohort.join_in),
        cohort.welcome,
    );
    let (committer, receivers) = cohort.split();

    let mut bytes = 0usize;
    let mut apply = Duration::ZERO;
    let mut save_each = Duration::ZERO;

    for k in 1..=COMMITS {
        // A path-only commit: the cheapest churn commit MLS has, and what a
        // Remove reduces to once its proposal is subtracted. It keeps the sweep
        // about the UpdatePath, which is the part that scales with the group.
        let commit = committer
            .add_members(&[])
            .expect("path-only churn commit")
            .commit;
        bytes += base64_len(commit.len());

        let started = Instant::now();
        receivers[0].apply_commit(&commit).expect("catch up");
        apply += started.elapsed();

        // What one commit costs to persist, taken on the first one: a client
        // that catches up without saving as it goes restarts from the
        // beginning after any interruption, so this is part of the real
        // per-commit cost and not an afterthought.
        if k == 1 {
            let started = Instant::now();
            receivers[0].save().expect("persist one commit");
            save_each = started.elapsed();
        }

        if CHECKPOINTS.contains(&k) {
            eprintln!(
                "E1 suite 0x{:04X}  missed {k:5} commits  download {bytes:11} B  \
                 apply {:8.2} s  ({:6.2} ms per commit)",
                suite.id(),
                secs(apply),
                millis(apply) / k as f64,
            );
        }
    }

    // The other persistence strategy: save once at the end. It is not the
    // cheap option it looks like — mls-rs hands the store every epoch record it
    // deferred, so this one call writes a file per missed commit.
    let started = Instant::now();
    receivers[0].save().expect("persist caught-up state");
    let deferred = started.elapsed();
    let group_info = committer.group_info().expect("group info");

    eprintln!(
        "E2 suite 0x{:04X}  persisting the catch-up: {:.2} ms per commit as it lands, \
         or {:.2} s in one deferred save of all {COMMITS} epochs",
        suite.id(),
        millis(save_each),
        secs(deferred),
    );

    external_join(suite, &group_info, bytes, apply, save_each);
}

/// The other side of the crossover: what a fresh agent pays to self-join the
/// same group by external commit, and how many missed commits that is worth.
fn external_join(
    suite: RineCipherSuite,
    group_info: &[u8],
    catchup_bytes: usize,
    catchup_apply: Duration,
    save_each: Duration,
) {
    let outsider = TestAgent::indexed(900_000, suite);

    let started = Instant::now();
    let (_group, bundle) = outsider
        .client
        .join_by_external_commit(group_info)
        .expect("external join");
    let joined = started.elapsed();

    let download = base64_len(group_info.len());
    let upload = base64_len(bundle.commit.len()) + base64_len(bundle.group_info.len());
    let per_commit_bytes = catchup_bytes as f64 / COMMITS as f64;
    let per_commit_time = catchup_apply.as_secs_f64() / COMMITS as f64 + save_each.as_secs_f64();

    eprintln!(
        "E3 suite 0x{:04X}  external join: download {download} B  upload {upload} B  \
         in {:.3} s   |   catch-up per commit: {per_commit_bytes:.0} B  \
         {:.2} ms apply + {:.2} ms save",
        suite.id(),
        secs(joined),
        millis(catchup_apply) / COMMITS as f64,
        millis(save_each),
    );
    eprintln!(
        "E4 suite 0x{:04X}  crossover: rejoining is cheaper than catching up past \
         {:.1} missed commits by bytes, {:.1} by wall clock",
        suite.id(),
        download as f64 / per_commit_bytes,
        joined.as_secs_f64() / per_commit_time,
    );
}
