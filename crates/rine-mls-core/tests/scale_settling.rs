//! Why a commit in a large rine group is not O(log N), and what would make it
//! one.
//!
//! The steady-state table says a commit grows almost linearly with the group,
//! which contradicts the usual reading of RFC 9420: an UpdatePath covers the
//! committer's direct path, which is `log2(N)` nodes deep. Both are true. A
//! path secret is encrypted to the *resolution* of each copath node, and a
//! founding commit leaves every interior node above the leaves blank — so the
//! resolution of the copath node at depth `d` is every leaf under it, and the
//! commit carries O(N) ciphertexts. The tree only stops being blank as members
//! commit through their own paths.
//!
//! This file measures how fast that happens, by having every live member commit
//! once in turn. It is the difference between "a churn commit in a
//! 1000-member group is 110 kB" and "it is 2 kB", so it decides which number
//! the daily simulation is entitled to use.
//!
//! ```text
//! cargo test --release -p rine-mls-core --test scale_settling -- --ignored --nocapture
//! ```

mod common;

use common::scale::{found, secs};
use common::{base64_len, for_each_suite};
use rine_mls_core::RineCipherSuite;
use std::time::Instant;

/// Each row is a group size and the number of its members that ever commit.
/// The first four fully populate their tree, which is `live²` commit
/// applications — the reason the sweep stops at 512. The last row is the shape
/// rine actually has at scale, a thousand-member group where a handful of
/// admins do the adding and removing, and it is deliberately *not* fully
/// populated: settling a 1000-member tree is a million commit applications,
/// which is hours of CPU and outside what this harness will spend. What that
/// row shows instead is what partial population is worth.
const CASES: [(usize, usize); 5] = [(16, 16), (64, 64), (128, 128), (512, 512), (1000, 32)];

/// ```text
/// cargo test --release -p rine-mls-core --test scale_settling -- --ignored --nocapture \
///     test_commit_size_when_members_commit_through_their_own_paths
/// ```
#[test]
#[ignore = "every live member commits and every other one applies it: O(live^2) work"]
fn test_commit_size_when_members_commit_through_their_own_paths() {
    for_each_suite(|suite| {
        for (size, live) in CASES {
            settle(suite, size, live);
        }
    });
}

fn settle(suite: RineCipherSuite, size: usize, live: usize) {
    let mut cohort = found(size, live, suite, 0xE0, 0);
    let started = Instant::now();
    let mut sizes = Vec::with_capacity(live);

    for round in 0..live {
        let commit = cohort.groups[round]
            .add_members(&[])
            .expect("path-only commit")
            .commit;

        for (index, group) in cohort.groups.iter_mut().enumerate() {
            if index != round {
                group.apply_commit(&commit).expect("apply");
            }
        }

        sizes.push(base64_len(commit.len()));
    }

    let first = sizes[0];
    let last = *sizes.last().expect("one commit per live member");
    let shown: Vec<String> = sizes
        .iter()
        .take(6)
        .map(|bytes| format!("{bytes}"))
        .collect();

    eprintln!(
        "D1 suite 0x{:04X}  N {size:4}  {live:4} of them commit  \
         first six commits {} B ...  last {last} B  \
         (first/last x{:.1})  {:.1} s",
        suite.id(),
        shown.join(", "),
        first as f64 / last as f64,
        secs(started.elapsed()),
    );
}
