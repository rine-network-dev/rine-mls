//! Measurement A — what founding a large group actually weighs.
//!
//! `founding_budget.rs` weighs the founding of a *small* group, which is the
//! group rine's batch constant was calibrated on. This file weighs the sizes
//! nobody had measured: every number about groups above 17 members in this
//! repo was a fit to three points, and a Welcome carries the ratchet tree of
//! the group being joined, so the interesting quantity grows with the tree and
//! not with the batch.
//!
//! Three measurements live here. The single-batch curve (`A1`) is what a
//! founding costs in aggregate. The batched curve (`A2`) is the number rine's
//! control plane has to survive: founding happens in batches, and the *last*
//! batch joins a tree that is already nearly the full group — so the largest
//! founding POST a big group ever sends is a batch of Welcomes of a
//! nearly-complete tree, not of an empty one. That is the shape that curve is
//! about, and it is why the size-aware batch that replaced the fixed one
//! shrinks as the tree grows.
//!
//! ⚠️ `A2`'s batch is the RETIRED fixed `MLS_FOUNDING_MEMBERS_PER_COMMIT`, kept
//! because it is the size that curve was taken at and because it is the
//! evidence the fixed batch had to go. It prices a client nobody ships: `grep`
//! finds no `MLS_FOUNDING_MEMBERS_PER_COMMIT` in any client package. Do not
//! quote it about today's client.
//!
//! `A3` is today's client. It walks the LIVE schedule —
//! `mlsFoundingBatchSizes` in `rine-core/src/mls-founding.ts`, clamped by
//! `MLS_COMMIT_WELCOMES_MAX` and sized against `MLS_FOUNDING_POST_BUDGET_B64`
//! — commit by commit against the real MLS core, at the group-size ceiling.
//! Before it existed, the claim that a 500-member group is reachable at all
//! rested on a re-implementation of that formula in a script, never on the
//! crate: the schedule is chosen from an ESTIMATE of what a Welcome weighs, and
//! nothing had ever checked the estimate against the bytes at the ceiling.
//!
//! All three are `#[ignore]`d: a thousand-member founding is minutes of client
//! CPU and gigabytes of Welcomes, which is not something `ci.sh` stage 8 should
//! ever wait for.
//!
//! ```text
//! cargo test --release -p rine-mls-core --test scale_founding -- --ignored --nocapture
//! ```

mod common;

use std::time::Instant;

use common::scale::{key_packages, secs};
use common::{base64_len, for_each_suite, group_id, TestAgent};
use rine_mls_core::RineCipherSuite;

/// Group sizes to weigh, counting the founder.
const SIZES: [usize; 7] = [16, 32, 64, 100, 250, 500, 1000];

/// Founding members admitted per commit when the `A2` curve was measured — the
/// retired fixed batch, not what the client sends today.
const FOUNDING_MEMBERS_PER_COMMIT: usize = 13;

/// The largest group rine serves: `MAX_GROUP_MEMBERS`
/// (`src/rine/core/group_limits.py`). `A3` walks the live schedule at exactly
/// this size, because it is the size the ceiling claims is reachable.
const CEILING_MEMBERS: usize = 500;

/// The live schedule's three inputs, restated from
/// `rine-core/src/mls-founding.ts` in a language that cannot import them.
///
/// `MLS_FOUNDING_POST_BUDGET_B64` is the base64 weight one founding POST is
/// allowed; `MLS_COMMIT_WELCOMES_MAX` is the server's `MlsCommitRequest`
/// `welcomes` cap and the upper clamp on any batch; the two Welcome
/// coefficients are the client's ESTIMATE of a Welcome's size, which is what
/// picks each batch. That last one is the reason this measurement exists — the
/// schedule is chosen from the estimate and paid in real bytes, and only a run
/// can say whether the estimate is still an upper bound at the ceiling.
const FOUNDING_POST_BUDGET_B64: usize = 8 * 1024 * 1024;
const COMMIT_WELCOMES_MAX: usize = 32;
const WELCOME_B64_PER_MEMBER: usize = 1_868;
const WELCOME_B64_BASE: usize = 13_100;
const COMMIT_AND_GROUP_INFO_IN_WELCOMES: usize = 2;

/// The model this measurement replaces: a two-point fit taken at N=8 and N=16
/// on the post-quantum suite, `Welcome ≈ 2058·N + 5272` bytes, hence a
/// single-batch founding of `2058·N² + 9042·N`. Printed alongside the truth at
/// every size so the error is on the record rather than assumed small.
const MODEL_WELCOME_SLOPE: f64 = 2058.0;
const MODEL_WELCOME_INTERCEPT: f64 = 5272.0;
const MODEL_FOUNDING_LINEAR: f64 = 9042.0;

/// The whole founding, in one commit: what the init POST would weigh if rine
/// did not batch. Also the aggregate cost of founding however it is split, since
/// every member needs exactly one Welcome either way.
///
/// ```text
/// cargo test --release -p rine-mls-core --test scale_founding -- --ignored --nocapture \
///     test_founding_curve_when_the_whole_group_joins_in_one_commit
/// ```
#[test]
#[ignore = "founds groups up to 1000 members; minutes of CPU and GBs of Welcomes"]
fn test_founding_curve_when_the_whole_group_joins_in_one_commit() {
    for_each_suite(|suite| {
        for size in SIZES {
            weigh_single_batch(suite, size);
        }
    });
}

/// The POST body rine's control plane really sends for a large group: the last
/// batch of thirteen, joining a tree that already holds everyone else.
///
/// ```text
/// cargo test --release -p rine-mls-core --test scale_founding -- --ignored --nocapture \
///     test_founding_post_body_when_the_last_batch_of_thirteen_joins_a_large_group
/// ```
#[test]
#[ignore = "founds groups up to 1000 members; minutes of CPU and GBs of Welcomes"]
fn test_founding_post_body_when_the_last_batch_of_thirteen_joins_a_large_group() {
    for_each_suite(|suite| {
        for size in SIZES {
            weigh_last_batch(suite, size);
        }
    });
}

/// Founding a group at the ceiling the way today's client founds one: every
/// batch sized by `mlsFoundingBatchSizes`, every POST weighed as the bytes the
/// real core produced rather than as the estimate that chose the batch.
///
/// What it settles, and nothing else had: that the schedule's estimate is an
/// upper bound at 500 members, so no POST the live client sends exceeds
/// `MLS_FOUNDING_POST_BUDGET_B64` — and what founding a full-size group costs
/// in aggregate, produced by the crate.
///
/// ```text
/// cargo test --release -p rine-mls-core --test scale_founding -- --ignored --nocapture \
///     test_founding_at_the_ceiling_when_the_live_batch_schedule_is_walked
/// ```
#[test]
#[ignore = "founds a 500-member group one live-schedule batch at a time, per suite"]
fn test_founding_at_the_ceiling_when_the_live_batch_schedule_is_walked() {
    for_each_suite(|suite| walk_live_schedule(suite, CEILING_MEMBERS));
}

/// Estimated base64 weight of a founding POST admitting `batch` members into a
/// tree that will hold `seated` once they are in — `foundingPostB64` in
/// `rine-core/src/mls-founding.ts`.
fn estimate_post_b64(seated: usize, batch: usize) -> usize {
    (WELCOME_B64_PER_MEMBER * seated + WELCOME_B64_BASE)
        * (batch + COMMIT_AND_GROUP_INFO_IN_WELCOMES)
}

/// `batchSizeAt` — the largest batch a tree of `seated` can admit under the
/// budget, clamped at `MLS_COMMIT_WELCOMES_MAX` and never below 1.
fn batch_size_at(seated: usize) -> usize {
    let mut batch = COMMIT_WELCOMES_MAX;
    while batch > 1 && estimate_post_b64(seated + batch, batch) > FOUNDING_POST_BUDGET_B64 {
        batch -= 1;
    }
    batch
}

/// `mlsFoundingBatchSizes(joiner_count, seated)` — how many members each
/// successive commit admits.
fn founding_batch_sizes(joiner_count: usize, seated: usize) -> Vec<usize> {
    let mut sizes = Vec::new();
    let mut tree = seated;
    while tree - seated < joiner_count {
        let batch = (joiner_count - (tree - seated)).min(batch_size_at(tree));
        sizes.push(batch);
        tree += batch;
    }
    sizes
}

/// Found a group of `size` by walking the live schedule, weighing every POST.
fn walk_live_schedule(suite: RineCipherSuite, size: usize) {
    let schedule = founding_batch_sizes(size - 1, 1);
    let founder = TestAgent::indexed(0, suite);
    let mut packages = key_packages(1, size - 1, suite).into_iter();

    let started = Instant::now();
    let mut group = None;
    let mut seated = 1;
    let mut total = 0;
    // The largest POST, with the estimate that chose it: that commit is the one
    // the budget binds on, so its own margin decides whether b(N) has any room
    // left. And separately the tightest margin anywhere in the walk, which is
    // what says whether the estimate is an upper bound at all.
    let mut largest = (0usize, 0usize, 0usize);
    let mut tightest = (f64::INFINITY, 0usize, 0usize);

    for (nth, &batch) in schedule.iter().enumerate() {
        let admitted: Vec<Vec<u8>> = packages.by_ref().take(batch).collect();
        assert_eq!(
            admitted.len(),
            batch,
            "the schedule asked for more members than exist"
        );

        let bundle = match group.as_mut() {
            None => {
                let (handle, bundle) = founder
                    .client
                    .create_group_with_members(&group_id(0xB3), &admitted)
                    .expect("founding commit");
                group = Some(handle);
                bundle
            }
            Some(handle) => handle.add_members(&admitted).expect("batch commit"),
        };

        seated += batch;
        let welcomes: usize = bundle.welcomes.iter().map(|w| base64_len(w.len())).sum();
        let body = base64_len(bundle.commit.len()) + welcomes + base64_len(bundle.group_info.len());
        drop(bundle);

        let estimate = estimate_post_b64(seated, batch);
        // The margin the schedule is actually running on: >1 means the estimate
        // that chose this batch was an upper bound on the bytes it produced.
        let margin = estimate as f64 / body as f64;
        if margin < tightest.0 {
            tightest = (margin, nth + 1, body);
        }
        if body > largest.0 {
            largest = (body, estimate, nth + 1);
        }
        total += body;

        assert!(
            body <= FOUNDING_POST_BUDGET_B64,
            "commit {} of {} on suite 0x{:04X} admitted {batch} into a tree of {seated} and \
             weighed {body} B, over MLS_FOUNDING_POST_BUDGET_B64 ({FOUNDING_POST_BUDGET_B64} B): \
             the estimate in mls-founding.ts predicted {estimate} B, so the Welcome coefficients \
             there are under the truth and b(N) is choosing batches the wire cannot carry",
            nth + 1,
            schedule.len(),
            suite.id(),
        );
    }

    assert_eq!(
        seated, size,
        "the schedule must seat exactly the group it was asked for"
    );

    eprintln!(
        "A3 suite 0x{:04X}  N {size:4}  live schedule {} commits {:?}..{:?}  \
         aggregate {total:10} B  largest POST {} B at commit {} ({:5.2} % of the \
         {FOUNDING_POST_BUDGET_B64} B budget, estimate/measured {:.4}x)  tightest \
         estimate/measured anywhere {:.4}x at commit {} ({} B)  founded in {:7.2} s",
        suite.id(),
        schedule.len(),
        &schedule[..schedule.len().min(3)],
        &schedule[schedule.len().saturating_sub(2)..],
        largest.0,
        largest.2,
        largest.0 as f64 / FOUNDING_POST_BUDGET_B64 as f64 * 100.0,
        largest.1 as f64 / largest.0 as f64,
        tightest.0,
        tightest.1,
        tightest.2,
        secs(started.elapsed()),
    );
}

fn weigh_single_batch(suite: RineCipherSuite, size: usize) {
    let founder = TestAgent::indexed(0, suite);
    let packages = key_packages(1, size - 1, suite);

    let started = Instant::now();
    let (_group, bundle) = founder
        .client
        .create_group_with_members(&group_id(0xB1), &packages)
        .expect("founding commit");
    let elapsed = started.elapsed();

    let commit = base64_len(bundle.commit.len());
    let group_info = base64_len(bundle.group_info.len());
    let welcome = base64_len(bundle.welcomes[0].len());
    let welcomes: usize = bundle.welcomes.iter().map(|w| base64_len(w.len())).sum();
    let body = commit + welcomes + group_info;
    drop(bundle);

    let n = size as f64;
    let model_welcome = MODEL_WELCOME_SLOPE * n + MODEL_WELCOME_INTERCEPT;
    let model_body = MODEL_WELCOME_SLOPE * n * n + MODEL_FOUNDING_LINEAR * n;

    eprintln!(
        "A1 suite 0x{:04X}  N {size:4}  aggregate {body:10} B  commit {commit:8} B  \
         welcome {welcome:8} B  group_info {group_info:8} B  \
         model_welcome {:+7.1}%  model_aggregate {:+7.1}%  built in {:7.2} s",
        suite.id(),
        error(model_welcome, welcome),
        error(model_body, body),
        secs(elapsed),
    );
}

fn weigh_last_batch(suite: RineCipherSuite, size: usize) {
    let joining = FOUNDING_MEMBERS_PER_COMMIT.min(size - 1);
    let seated = size - joining;

    let founder = TestAgent::indexed(0, suite);
    let seats = key_packages(1, seated - 1, suite);
    let (mut group, founding) = founder
        .client
        .create_group_with_members(&group_id(0xB2), &seats)
        .expect("founding commit");
    drop(founding);

    let batch = key_packages(1 + size as u32, joining, suite);
    let started = Instant::now();
    let bundle = group.add_members(&batch).expect("batch commit");
    let elapsed = started.elapsed();

    let commit = base64_len(bundle.commit.len());
    let group_info = base64_len(bundle.group_info.len());
    let welcomes: usize = bundle.welcomes.iter().map(|w| base64_len(w.len())).sum();
    let body = commit + welcomes + group_info;
    drop(bundle);

    eprintln!(
        "A2 suite 0x{:04X}  N {size:4}  batch of {joining:2} onto {seated:4} seated  \
         POST body {body:10} B  = commit {commit:8} B + welcomes {welcomes:9} B \
         + group_info {group_info:8} B  ({:5.1}x MLS_FOUNDING_POST_BUDGET_B64)  \
         built in {:6.2} s   [RETIRED batch — see A3 for today's client]",
        suite.id(),
        body as f64 / FOUNDING_POST_BUDGET_B64 as f64,
        secs(elapsed),
    );
}

/// Signed relative error of a prediction against the measurement, in percent:
/// positive means the model was over, negative means it was under. Both
/// directions matter — a model that overstated the cost would have had rine
/// batching more conservatively than it needed to.
fn error(predicted: f64, measured: usize) -> f64 {
    (predicted - measured as f64) / measured as f64 * 100.0
}
