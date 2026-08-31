//! Does mls-rs put a new member in a blanked leaf, or always at the end?
//!
//! This one cannot be closed by argument, and a whole decision rests on the
//! answer. rine gives an unaccepted invitation a 7-day life so that a no-show
//! stops taxing the group, and the premise here is that expiry therefore
//! **bounds** the ratchet tree. That premise only holds if the leaf a departure
//! blanks can be occupied again. If it cannot, expiry slows the tree's growth
//! and never reverses it, and a long-lived group that churns members inflates
//! every later Welcome and commit without bound — which is a smaller promise
//! than the expiry rule assumes, and one the docs must not overstate.
//!
//! Nothing about this is rine's to choose: it is mls-rs's ratchet-tree
//! management, so the only way to learn it is to build both trees and weigh
//! them. Two groups reach the same membership by different routes — one churned
//! (add N, remove k, add k), one pristine (add N directly) — and are compared on
//! the two things that matter downstream: where a new member's leaf lands, and
//! what a Welcome for the next joiner costs.
//!
//! Sizes are printed, so
//! `cargo test -p rine-mls-core --test leaf_reuse -- --nocapture` is the
//! measurement harness as well as the assertion.

mod common;

use common::{base64_len, for_each_suite, group_id, TestAgent};
use rine_mls_core::{RineCipherSuite, RineMlsGroup};

/// Members the founder seats before anyone leaves, founder excluded.
const COHORT: usize = 15;

/// Members removed, and then re-added as different agents. Five is enough to
/// tell reuse from append without making the test slow: an appending tree ends
/// five leaves wider than a reusing one.
const CHURN: usize = 5;

#[test]
fn test_add_member_when_a_leaf_was_blanked_by_a_remove_then_reports_where_it_landed() {
    for_each_suite(|suite| {
        let churned = build_churned(suite);
        let pristine = build_pristine(suite);

        assert_eq!(
            churned.live_members, pristine.live_members,
            "the two groups must be compared at the same membership",
        );

        let reused = churned
            .replacement_leaves
            .iter()
            .filter(|leaf| churned.blanked_leaves.contains(leaf))
            .count();

        eprintln!(
            "suite 0x{:04X}  members {}  churned: widest leaf {} , next Welcome {} B  |  \
             pristine: widest leaf {} , next Welcome {} B  |  replacements landing in a \
             blanked leaf: {}/{}",
            suite.id(),
            churned.live_members,
            churned.widest_leaf,
            churned.next_welcome_b64,
            pristine.widest_leaf,
            pristine.next_welcome_b64,
            reused,
            CHURN,
        );

        // The first assertion is deliberately the WEAK one — a consistency
        // check, not the answer to whether a blanked leaf is re-occupied, which
        // the equality below pins: whatever mls-rs does here, it must do
        // consistently, so the two measurements agree with each other. A tree
        // that reuses leaves is the same width and the same Welcome cost as one
        // that never lost any; a tree that appends is wider AND dearer. The one
        // outcome that would mean something is broken is disagreement — a tree
        // that grew wider without its Welcome growing, or the reverse — because
        // then the cost model rine sizes MLS_BLOB_MAX_B64 from is not tracking
        // the tree at all.
        let wider = churned.widest_leaf > pristine.widest_leaf;
        let dearer = churned.next_welcome_b64 > pristine.next_welcome_b64;
        assert_eq!(
            wider,
            dearer,
            "on suite 0x{:04X} a churned tree is {} than a pristine one but its Welcome is {}: \
             the per-member Welcome rate no longer tracks the ratchet tree, and every budget \
             derived from it (MLS_BLOB_MAX_B64, b(N)) is sized against the wrong thing",
            suite.id(),
            if wider { "wider" } else { "no wider" },
            if dearer { "dearer" } else { "no dearer" },
        );

        // Reuse and append are mutually exclusive, and which one holds is the
        // answer this file exists to get. Pinned as an EQUALITY on the reuse world, not
        // as a branch: a branch that accepts either answer records the behaviour
        // and asserts nothing about it, so an mls-rs bump to append-only would
        // land `reused == 0` and stay green while reclamation's premise quietly
        // went false. Reuse is the world rine ships against and the only one this
        // suite may pass in.
        assert_eq!(
            reused, CHURN,
            "mls-rs seated {reused} of {CHURN} replacements in a blanked leaf. A reclaimed leaf \
             is no longer re-occupiable, so reclamation only SLOWS the tree's growth and never \
             reverses it: the \"reclamation bounds the tree\" claim is false, and every surface \
             that states the bound must be corrected — rine-core/src/mls-orphans.ts, \
             rine-sdk/src/rine/_mls/orphans.py, PROTOCOL.md §10.5.7, \
             docs/docs/concepts/encryption.md, docs/docs/api/reference.md",
        );
        assert!(
            !wider,
            "every replacement landed in a blanked leaf, so the tree cannot be wider",
        );
    });
}

/// What one group looks like after it is built, measured the two ways that
/// matter to rine's budgets.
struct Measured {
    live_members: usize,
    /// Highest leaf index any live member occupies, +1 — the tree's occupied
    /// width, which is what a Welcome has to describe.
    widest_leaf: u32,
    /// Base64 bytes of the Welcome the NEXT joiner would receive. This is the
    /// quantity `MLS_WELCOME_B64_PER_MEMBER` models and `b(N)` batches against.
    next_welcome_b64: usize,
    blanked_leaves: Vec<u32>,
    replacement_leaves: Vec<u32>,
}

/// Add `COHORT`, remove `CHURN` of them, then admit `CHURN` different agents.
fn build_churned(suite: RineCipherSuite) -> Measured {
    let founder = TestAgent::new(1, suite);
    let (mut group, _) = founder
        .client
        .create_group(&group_id(0xC1))
        .expect("create group");

    let cohort: Vec<TestAgent> = (0..COHORT)
        .map(|n| TestAgent::indexed(0x1000 + n as u32, suite))
        .collect();
    seat(&mut group, &cohort);

    let blanked_leaves: Vec<u32> = cohort
        .iter()
        .take(CHURN)
        .map(|agent| group.member_index(&agent.identity).expect("seated"))
        .collect();
    for leaf in &blanked_leaves {
        group.remove_member(*leaf).expect("remove commit");
    }

    let replacements: Vec<TestAgent> = (0..CHURN)
        .map(|n| TestAgent::indexed(0x2000 + n as u32, suite))
        .collect();
    seat(&mut group, &replacements);

    let replacement_leaves: Vec<u32> = replacements
        .iter()
        .map(|agent| group.member_index(&agent.identity).expect("seated"))
        .collect();
    let live: Vec<&TestAgent> = cohort
        .iter()
        .skip(CHURN)
        .chain(replacements.iter())
        .collect();

    Measured {
        live_members: live.len() + 1,
        widest_leaf: widest(&group, &founder, &live),
        next_welcome_b64: next_welcome_b64(&mut group, suite, 0x3000),
        blanked_leaves,
        replacement_leaves,
    }
}

/// The same final membership, reached without anyone ever leaving.
fn build_pristine(suite: RineCipherSuite) -> Measured {
    let founder = TestAgent::new(2, suite);
    let (mut group, _) = founder
        .client
        .create_group(&group_id(0xC2))
        .expect("create group");

    let members: Vec<TestAgent> = (0..COHORT)
        .map(|n| TestAgent::indexed(0x4000 + n as u32, suite))
        .collect();
    seat(&mut group, &members);
    let live: Vec<&TestAgent> = members.iter().collect();

    Measured {
        live_members: live.len() + 1,
        widest_leaf: widest(&group, &founder, &live),
        next_welcome_b64: next_welcome_b64(&mut group, suite, 0x5000),
        blanked_leaves: Vec::new(),
        replacement_leaves: Vec::new(),
    }
}

/// Admit every agent in one Add commit, exactly as a batched admission does.
fn seat(group: &mut RineMlsGroup, agents: &[TestAgent]) {
    let key_packages: Vec<Vec<u8>> = agents
        .iter()
        .map(|agent| agent.client.generate_key_package().expect("key package"))
        .collect();
    group.add_members(&key_packages).expect("add commit");
}

fn widest(group: &RineMlsGroup, founder: &TestAgent, live: &[&TestAgent]) -> u32 {
    let mut widest = group
        .member_index(&founder.identity)
        .expect("founder seated");
    for agent in live {
        widest = widest.max(group.member_index(&agent.identity).expect("seated"));
    }
    widest + 1
}

/// Admit one more agent and weigh the Welcome it produces. Mutating: the
/// measurement is taken last, after every other number this group reports.
fn next_welcome_b64(group: &mut RineMlsGroup, suite: RineCipherSuite, seed: u32) -> usize {
    let joiner = TestAgent::indexed(seed, suite);
    let bundle = group
        .add_member(&joiner.client.generate_key_package().expect("key package"))
        .expect("add commit");

    base64_len(bundle.welcomes[0].len())
}
