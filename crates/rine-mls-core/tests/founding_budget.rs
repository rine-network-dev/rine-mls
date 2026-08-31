//! What one founding `POST /groups/{id}/mls/commit` weighs.
//!
//! A founding POST is the commit, one Welcome per member admitted and the
//! GroupInfo, each base64. This test weighs the real bundle, so a change that
//! inflates a commit (a ciphersuite, a commit option, a new extension) is caught
//! here rather than by a request the server drops.
//!
//! **The constant this file was written against no longer exists.**
//! `MLS_FOUNDING_MEMBERS_PER_COMMIT` — a fixed batch of 13 under a ~600 kB
//! self-imposed budget — was replaced during the groups rebuild by the
//! size-aware batch `mlsFoundingBatchSizes` (`rine-core/src/mls-founding.ts`),
//! which is clamped by `MLS_COMMIT_WELCOMES_MAX` and sized against
//! `MLS_FOUNDING_POST_BUDGET_B64`. `grep` finds no
//! `MLS_FOUNDING_MEMBERS_PER_COMMIT` anywhere in `rine-core/src`, so the old
//! failure message named a constant nobody could lower.
//!
//! rine has exactly ONE founding budget today, and it is
//! `MLS_FOUNDING_POST_BUDGET_B64`, asserted below at a full
//! `MLS_COMMIT_WELCOMES_MAX` batch — the largest founding POST rine sends. The
//! second assertion is not a budget at all: 600 kB is the size a small founding
//! has always come in under, kept as a tripwire on the shape of the commit
//! bundle itself. A 14-member founding crossing it means a ciphersuite, a
//! commit option or an extension inflated the bundle, which is worth knowing
//! long before it threatens the live budget. It is named for what it is so
//! nobody quotes it as a limit rine enforces.
//!
//! The sizes are printed, so `cargo test -p rine-mls-core --test founding_budget
//! -- --nocapture` is also the measurement harness for both.

mod common;

use common::{base64_len, for_each_suite, group_id, TestAgent};
use rine_mls_core::RineCipherSuite;

/// The retired fixed batch. Retained only as the size the tripwire below was
/// calibrated at, which is what makes 600 kB a meaningful number to trip on.
const LEGACY_MEMBERS_PER_COMMIT: usize = 13;

/// Not a budget rine enforces anywhere — the size a small founding has always
/// come in under, kept as a tripwire on the commit bundle's shape. See the
/// module docs.
const SMALL_FOUNDING_TRIPWIRE_BYTES: usize = 600_000;

/// `MLS_COMMIT_WELCOMES_MAX` (`rine-core/src/mls-founding.ts`), which is also
/// the server's `MLS_WELCOMES_PER_COMMIT_MAX`. The upper clamp on the
/// size-aware batch, so a founding at `seated = 1` sends exactly this many
/// Welcomes — the largest single founding POST rine ever produces.
const COMMIT_WELCOMES_MAX: usize = 32;

/// `MLS_FOUNDING_POST_BUDGET_B64` (`rine-core/src/mls-founding.ts`): the budget
/// `b(N)` shrinks the batch to stay under as the tree grows.
const FOUNDING_POST_BUDGET_B64: usize = 8 * 1024 * 1024;

/// Group sizes to weigh, counting the founder. The last is a full legacy batch.
const GROUP_SIZES: [usize; 3] = [2, 8, LEGACY_MEMBERS_PER_COMMIT + 1];

#[test]
fn test_founding_commit_when_a_small_batch_joins_stays_under_the_historical_size() {
    for_each_suite(|suite| {
        for size in GROUP_SIZES {
            let body = weigh_founding_post(suite, size);

            assert!(
                body <= SMALL_FOUNDING_TRIPWIRE_BYTES,
                "a {size}-member founding POST on suite 0x{:04X} is {body} B, over the \
                 {SMALL_FOUNDING_TRIPWIRE_BYTES} B a small founding has always come in under: \
                 something inflated the commit bundle itself, because the batch size did not \
                 change",
                suite.id(),
            );
        }
    });
}

#[test]
fn test_founding_commit_when_the_batch_is_at_its_clamp_stays_within_the_live_budget() {
    for_each_suite(|suite| {
        let body = weigh_founding_post(suite, COMMIT_WELCOMES_MAX + 1);

        assert!(
            body <= FOUNDING_POST_BUDGET_B64,
            "a full {COMMIT_WELCOMES_MAX}-Welcome founding POST on suite 0x{:04X} is {body} B, \
             over MLS_FOUNDING_POST_BUDGET_B64 ({FOUNDING_POST_BUDGET_B64} B): b(N) clamps at \
             MLS_COMMIT_WELCOMES_MAX and therefore cannot shrink this batch any further, so \
             the clamp in rine-core/src/mls-founding.ts is the thing that has to come down",
            suite.id(),
        );
    });
}

/// Found a group of `size` members in one commit and return the size, in bytes,
/// of the JSON body `postMlsCommit` (`rine-core/src/mls-commit.ts`) sends for
/// it: base64 commit, base64 Welcome per member, base64 GroupInfo.
fn weigh_founding_post(suite: RineCipherSuite, size: usize) -> usize {
    let founder = TestAgent::new(1, suite);
    let joiners: Vec<TestAgent> = (1..size)
        .map(|n| TestAgent::new(0x40 + n as u8, suite))
        .collect();
    let key_packages: Vec<Vec<u8>> = joiners
        .iter()
        .map(|joiner| joiner.client.generate_key_package().expect("key package"))
        .collect();

    let (_, bundle) = founder
        .client
        .create_group_with_members(&group_id(0xB0), &key_packages)
        .expect("founding commit");

    let commit = base64_len(bundle.commit.len());
    let welcomes: usize = bundle.welcomes.iter().map(|w| base64_len(w.len())).sum();
    let group_info = base64_len(bundle.group_info.len());
    let body = commit + welcomes + group_info;

    eprintln!(
        "suite 0x{:04X}  group {size:2}  POST body {body:7} B  = commit {commit:6} B \
         + {} welcomes {welcomes:7} B + group_info {group_info:6} B",
        suite.id(),
        bundle.welcomes.len(),
    );

    body
}
