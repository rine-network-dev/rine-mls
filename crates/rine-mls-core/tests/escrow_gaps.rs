//! An epoch that cannot be escrowed is reported as a gap and never fails the
//! take for the others: a tree over the leaf limit, and a queue over its cap.

mod common;

use std::collections::HashMap;

use common::scale::key_packages;
use common::{group_id, TestAgent};
use rine_mls_core::{
    EscrowFault, EscrowGapReason, RineCipherSuite, RineMlsGroup, MAX_CONTEXT_LEN,
    MAX_DROPPED_EPOCH_READ_EPOCHS, MAX_LEAVES, MAX_QUEUED_EPOCH_READ_EXPORTS,
};

const SUITE: RineCipherSuite = RineCipherSuite::DEFAULT;

/// Members admitted per commit while the tree grows: the server's cap on
/// Welcomes in one commit.
const BATCH: usize = 32;

/// Past the leaf limit by this many occupied leaves.
const OVER: usize = 20;

/// Grow `group` by `batch` members in one commit, returning the epoch it made.
fn admit(group: &mut RineMlsGroup, first: u32, batch: usize) -> u64 {
    group
        .add_members(&key_packages(first, batch, SUITE))
        .expect("add members")
        .epoch
}

#[test]
fn test_gap_take_when_the_tree_holds_over_the_leaf_limit_of_occupied_leaves_reports_the_epoch_and_keeps_the_rest(
) {
    let alice = TestAgent::new(1, SUITE);
    let id = group_id(0xC1);
    let (mut group, _) = alice.client.create_group(&id).expect("create");

    // (epoch, occupied leaves) of every epoch the group installs. Creation
    // installs epoch 0 and then its own first commit.
    let mut epochs = vec![(0u64, 1usize), (group.epoch(), 1)];
    // The fork fingerprint each epoch carried while it was the live one.
    let mut forks = HashMap::new();
    // The queue holds 32 epochs, so a take after every commit keeps them all.
    let mut taken = group.take_escrow_exports().expect("first take");
    let mut leaves = 1usize;
    while leaves < MAX_LEAVES + OVER {
        let batch = BATCH.min(MAX_LEAVES + OVER - leaves);
        let epoch = admit(&mut group, 1000 + leaves as u32, batch);
        leaves += batch;
        epochs.push((epoch, leaves));
        forks.insert(epoch, group.epoch_fingerprint().expect("live fingerprint"));
        let take = group
            .take_escrow_exports()
            .expect("a take never fails on a big tree");
        taken.exports.extend(take.exports);
        taken.gaps.extend(take.gaps);
    }
    assert!(
        leaves > MAX_LEAVES,
        "the tree outgrew the escrow leaf limit"
    );

    let take = taken;

    let over: Vec<u64> = epochs
        .iter()
        .filter(|(_, n)| *n > MAX_LEAVES)
        .map(|(e, _)| *e)
        .collect();
    let within: Vec<u64> = epochs
        .iter()
        .filter(|(_, n)| *n <= MAX_LEAVES)
        .map(|(e, _)| *e)
        .collect();
    assert!(!over.is_empty() && !within.is_empty());

    let mut gap_epochs: Vec<u64> = take.gaps.iter().map(|g| g.epoch).collect();
    gap_epochs.sort_unstable();
    assert_eq!(gap_epochs, over, "exactly the oversize epochs are gaps");
    assert!(take
        .gaps
        .iter()
        .all(|g| g.reason == EscrowGapReason::TooManyLeaves && g.group_id == id));
    assert!(
        take.gaps.iter().all(|g| g.fp == Some(forks[&g.epoch])),
        "each gap names the fork of the epoch it could not escrow"
    );

    let exported: Vec<u64> = take.exports.iter().map(|e| e.epoch).collect();
    assert_eq!(exported, within, "every other epoch still has its export");

    assert!(
        group
            .take_escrow_exports()
            .expect("second take")
            .gaps
            .is_empty(),
        "a gap is reported once"
    );
}

#[test]
fn test_gap_queue_when_more_than_the_cap_wait_discards_the_oldest_and_reports_them() {
    let alice = TestAgent::new(1, SUITE);
    let id = group_id(0xC2);
    let (mut group, _) = alice.client.create_group(&id).expect("create");

    let extra = 3;
    let installed = MAX_QUEUED_EPOCH_READ_EXPORTS + extra;
    for n in 0..installed {
        admit(&mut group, 2000 + n as u32, 1);
    }
    group.save().expect("persist");

    // Creation installs two epochs and each commit one more; only the cap is kept.
    let backlog = group.escrow_backlog();
    assert_eq!(backlog.queued, MAX_QUEUED_EPOCH_READ_EXPORTS);
    assert_eq!(backlog.dropped, extra + 2);

    // A reload sees the same backlog: the discard is part of the saved snapshot.
    drop(group);
    let mut group = alice.client.load_group(&id).expect("load");
    assert_eq!(group.escrow_backlog(), backlog);

    let take = group.take_escrow_exports().expect("take");
    let mut dropped: Vec<u64> = take.gaps.iter().map(|g| g.epoch).collect();
    dropped.sort_unstable();
    assert_eq!(dropped, (0..extra as u64 + 2).collect::<Vec<_>>());
    assert!(take
        .gaps
        .iter()
        .all(|g| g.reason == EscrowGapReason::QueueOverflow));
    assert!(
        take.gaps.iter().all(|g| g.fp.is_none()),
        "a discarded export keeps only its epoch number, so it names no fork"
    );
    assert_eq!(take.exports.len(), MAX_QUEUED_EPOCH_READ_EXPORTS);
    assert_eq!(
        take.exports.first().map(|e| e.epoch),
        Some(extra as u64 + 2),
        "the newest epochs are the ones kept"
    );

    let after = group.escrow_backlog();
    assert_eq!((after.queued, after.dropped), (0, 0), "a take empties both");
}

#[test]
fn test_gap_queue_when_the_deferral_never_ends_remembers_only_the_newest_dropped_epochs() {
    let alice = TestAgent::new(1, SUITE);
    let bob = TestAgent::new(2, SUITE);
    let id = group_id(0xC3);
    let (mut group, _) = alice.client.create_group(&id).expect("create");

    // Each round adds and removes bob: two installed epochs and no tree growth.
    let past_the_cap = 10;
    let installed = MAX_QUEUED_EPOCH_READ_EXPORTS + MAX_DROPPED_EPOCH_READ_EPOCHS + past_the_cap;
    while group.epoch() + 1 < installed as u64 {
        let key_package = bob.client.generate_key_package().expect("key package");
        group.add_member(&key_package).expect("add bob");
        let leaf = group.member_index(&bob.identity).expect("bob seated");
        group.remove_member(leaf).expect("remove bob");
    }
    group.save().expect("persist");

    let backlog = group.escrow_backlog();
    assert_eq!(backlog.queued, MAX_QUEUED_EPOCH_READ_EXPORTS);
    assert_eq!(
        backlog.dropped, MAX_DROPPED_EPOCH_READ_EPOCHS,
        "the record of discarded epochs is bounded"
    );

    let take = group.take_escrow_exports().expect("take");
    let oldest_kept = take.gaps.iter().map(|g| g.epoch).min().expect("gaps");
    assert_eq!(
        oldest_kept, past_the_cap as u64,
        "the oldest records are the ones forgotten"
    );
}

#[test]
fn test_gap_take_when_the_group_context_is_over_the_limit_reports_context_too_large() {
    let alice = TestAgent::new(1, SUITE);
    // The group id rides in every epoch's group context.
    let id = vec![0xC4; MAX_CONTEXT_LEN];
    let (mut group, _) = alice.client.create_group(&id).expect("create");

    let live = group.epoch_fingerprint().expect("live fingerprint");

    let take = group.take_escrow_exports().expect("take");

    assert!(take.exports.is_empty());
    assert_eq!(take.gaps.len(), 2, "creation installs two epochs");
    assert!(take
        .gaps
        .iter()
        .all(|g| g.reason == EscrowGapReason::ContextTooLarge));
    assert!(
        take.gaps.iter().all(|g| g.fp.is_some()),
        "an epoch that failed to encode still knows its fork"
    );
    assert_eq!(take.gaps.last().and_then(|g| g.fp), Some(live));
}

#[test]
fn test_gap_reason_when_the_fault_is_not_a_size_limit_is_malformed() {
    for fault in [
        EscrowFault::BadFieldLength {
            len: 31,
            expected: 32,
        },
        EscrowFault::UndecodableContext,
    ] {
        assert_eq!(EscrowGapReason::from(fault), EscrowGapReason::Malformed);
    }
}
