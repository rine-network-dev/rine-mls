//! The fork fingerprint of a group's current epoch, read without taking exports.

mod common;

use common::escrow::take;
use common::{group_id, TestAgent};
use rine_mls_core::{RineCipherSuite, RineMlsGroup};

const SUITE: RineCipherSuite = RineCipherSuite::DEFAULT;

/// Alice founds a group with Bob in one commit: both hold epoch 1.
fn pair(id: &[u8]) -> (RineMlsGroup, RineMlsGroup) {
    let alice = TestAgent::new(1, SUITE);
    let bob = TestAgent::new(2, SUITE);
    let (alice_group, bundle) = alice
        .client
        .create_group_with_members(id, &[bob.client.generate_key_package().expect("kp")])
        .expect("create with bob");
    let bob_group = bob
        .client
        .join_from_welcome(&bundle.welcomes[0])
        .expect("join");
    (alice_group, bob_group)
}

#[test]
fn test_epoch_fingerprint_when_the_epoch_is_exported_then_it_is_the_exports_fp() {
    let (mut alice_group, _bob_group) = pair(&group_id(0xF1));
    let live = alice_group.epoch_fingerprint().expect("fingerprint");
    let epoch = alice_group.epoch();
    let export = take(&mut alice_group)
        .into_iter()
        .find(|e| e.epoch == epoch)
        .expect("export of the current epoch");

    assert_eq!(live, export.fp);
}

#[test]
fn test_epoch_fingerprint_when_two_members_share_the_epoch_then_they_agree() {
    let (alice_group, bob_group) = pair(&group_id(0xF2));

    assert_eq!(
        alice_group.epoch_fingerprint().expect("alice"),
        bob_group.epoch_fingerprint().expect("bob")
    );
}

#[test]
fn test_epoch_fingerprint_when_two_forks_hold_the_same_epoch_then_they_differ() {
    let (alice_group, _bob) = pair(&group_id(0xF3));
    let (other_group, _other_bob) = pair(&group_id(0xF3));

    assert_eq!(alice_group.epoch(), other_group.epoch());
    assert_ne!(
        alice_group.epoch_fingerprint().expect("first fork"),
        other_group.epoch_fingerprint().expect("second fork")
    );
}

#[test]
fn test_epoch_fingerprint_when_the_epoch_advances_then_the_fingerprint_changes() {
    let (mut alice_group, _bob_group) = pair(&group_id(0xF4));
    let before = alice_group.epoch_fingerprint().expect("before");
    let carol = TestAgent::new(3, SUITE);
    alice_group
        .add_member(&carol.client.generate_key_package().expect("kp"))
        .expect("add carol");

    assert_ne!(before, alice_group.epoch_fingerprint().expect("after"));
}

#[test]
fn test_epoch_fingerprint_when_read_then_the_backlog_is_untouched() {
    let (alice_group, _bob_group) = pair(&group_id(0xF5));
    let backlog = alice_group.escrow_backlog();

    alice_group.epoch_fingerprint().expect("fingerprint");

    assert_eq!(alice_group.escrow_backlog(), backlog);
}

#[test]
fn test_queued_escrow_fingerprints_when_exports_wait_then_each_equals_the_fp_a_take_returns() {
    let (mut alice_group, _bob_group) = pair(&group_id(0xF6));
    let carol = TestAgent::new(3, SUITE);
    alice_group
        .add_member(&carol.client.generate_key_package().expect("kp"))
        .expect("add carol");

    let queued = alice_group.queued_escrow_fingerprints().expect("queued");
    let taken: Vec<_> = take(&mut alice_group)
        .into_iter()
        .map(|export| (export.epoch, export.fp))
        .collect();

    assert!(
        queued.len() > 1,
        "creation, the add and the commit all wait"
    );
    assert_eq!(
        queued.iter().map(|q| (q.epoch, q.fp)).collect::<Vec<_>>(),
        taken
    );
}

#[test]
fn test_queued_escrow_fingerprints_when_read_then_the_backlog_is_untouched() {
    let (alice_group, _bob_group) = pair(&group_id(0xF7));
    let backlog = alice_group.escrow_backlog();
    assert!(backlog.queued > 0);

    alice_group.queued_escrow_fingerprints().expect("queued");

    assert_eq!(alice_group.escrow_backlog(), backlog);
}
