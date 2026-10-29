//! A private message sent in an earlier epoch, read after the group moved on.
//!
//! The vendored mls-rs opens such a message only when the sender's leaf still
//! belongs to the same agent: the same key, or a valid successor of it under the
//! reader's allowed-set identity provider. A member who was removed, and an index
//! another agent now holds, stay refused, so nothing is attributed to whoever
//! reuses the leaf.

mod common;

use common::rotation::rotating_pair;
use common::{for_each_suite, group_id, TestAgent};
use mls_rs::error::MlsError;
use rine_mls_core::{AllowedIdentities, RineMlsError};

/// Assert the read was refused because the sender's leaf is not the one that
/// sent the message, and for no other reason.
fn assert_sender_not_found<T: std::fmt::Debug>(read: Result<T, RineMlsError>) {
    assert!(
        matches!(read, Err(RineMlsError::Mls(MlsError::MemberNotFound))),
        "expected a refusal for a sender no longer found, got {read:?}",
    );
}

#[test]
fn test_decrypt_when_sender_self_updated_after_sending_then_opens() {
    let (a, _r, _a_set, _r_set, mut a_group, mut r_group, _id) = rotating_pair(0xC8);

    let before = a_group
        .encrypt_application_message(b"sent under the old leaf key")
        .expect("encrypt");

    let bundle = a_group.commit_update(&a.seed(1)).expect("commit update");
    a_group.apply_pending_commit().expect("apply pending");
    r_group.apply_commit(&bundle.commit).expect("apply");

    let received = r_group
        .decrypt_application_message(&before)
        .expect("a message from before the sender's update still opens");

    assert_eq!(received.envelope, b"sent under the old leaf key");
    assert!(
        r_group.decrypt_application_message(&before).is_err(),
        "the consumed generation does not open a second time",
    );
}

#[test]
fn test_decrypt_when_sender_removed_after_sending_then_refuses() {
    for_each_suite(|suite| {
        let alice = TestAgent::new(1, suite);
        let bob = TestAgent::new(2, suite);
        let carol = TestAgent::new(3, suite);

        let key_packages = vec![
            bob.client.generate_key_package().expect("bob's package"),
            carol
                .client
                .generate_key_package()
                .expect("carol's package"),
        ];
        let (mut alice_group, bundle) = alice
            .client
            .create_group_with_members(&group_id(0xC9), &key_packages)
            .expect("create with members");
        let mut bob_group = bob
            .client
            .join_from_welcome(&bundle.welcomes[0])
            .expect("bob joins");
        let mut carol_group = carol
            .client
            .join_from_welcome(&bundle.welcomes[1])
            .expect("carol joins");

        let before = carol_group
            .encrypt_application_message(b"sent by the member who then leaves")
            .expect("encrypt");

        let carol_leaf = alice_group
            .member_index(&carol.identity)
            .expect("carol's leaf");
        let removal = alice_group.remove_member(carol_leaf).expect("remove carol");
        bob_group
            .apply_commit(&removal.commit)
            .expect("bob applies the removal");

        assert_sender_not_found(bob_group.decrypt_application_message(&before));
    });
}

#[test]
fn test_decrypt_when_sender_leaf_reused_by_another_agent_then_refuses() {
    for_each_suite(|suite| {
        let alice = TestAgent::new(1, suite);
        let bob = TestAgent::new(2, suite);
        let carol = TestAgent::new(3, suite);
        let dave = TestAgent::new(4, suite);

        let key_packages = vec![
            bob.client.generate_key_package().expect("bob's package"),
            carol
                .client
                .generate_key_package()
                .expect("carol's package"),
        ];
        let (mut alice_group, bundle) = alice
            .client
            .create_group_with_members(&group_id(0xCA), &key_packages)
            .expect("create with members");
        let mut bob_group = bob
            .client
            .join_from_welcome(&bundle.welcomes[0])
            .expect("bob joins");
        let mut carol_group = carol
            .client
            .join_from_welcome(&bundle.welcomes[1])
            .expect("carol joins");

        let before = carol_group
            .encrypt_application_message(b"sent by the member whose leaf is reused")
            .expect("encrypt");

        let carol_leaf = alice_group
            .member_index(&carol.identity)
            .expect("carol's leaf");
        let removal = alice_group.remove_member(carol_leaf).expect("remove carol");
        bob_group
            .apply_commit(&removal.commit)
            .expect("bob applies the removal");
        let add = alice_group
            .add_member(&dave.client.generate_key_package().expect("dave's package"))
            .expect("add dave");
        bob_group
            .apply_commit(&add.commit)
            .expect("bob applies the add");
        assert_eq!(
            alice_group
                .member_index(&dave.identity)
                .expect("dave's leaf"),
            carol_leaf,
            "dave takes the leaf carol held",
        );

        assert_sender_not_found(bob_group.decrypt_application_message(&before));
    });
}

/// R's handle reopened over an allowed set that records A's epoch-1 key as
/// `epoch_key_agent` at `epoch_key_generation` and A's updated key as
/// generation 1, then reads A's message from before the update.
fn read_with_epoch_key_admitted_as(
    tag: u8,
    epoch_key_agent: &[u8],
    epoch_key_generation: u32,
) -> Result<(), RineMlsError> {
    let (a, r, _a_set, _r_set, mut a_group, mut r_group, id) = rotating_pair(tag);
    let before = a_group
        .encrypt_application_message(b"sent under the old leaf key")
        .expect("encrypt");
    let bundle = a_group.commit_update(&a.seed(1)).expect("commit update");
    a_group.apply_pending_commit().expect("apply pending");
    r_group.apply_commit(&bundle.commit).expect("apply");
    r_group.save().expect("save");

    let set = AllowedIdentities::new();
    r.allow(&set, 0);
    a.allow(&set, 1);
    set.insert(epoch_key_agent, &a.public_key(0), epoch_key_generation)
        .expect("one generation per pair");
    let mut reopened = r.open(&set, 0).load_group(&id).expect("reload the reader");

    reopened.decrypt_application_message(&before).map(|_| ())
}

#[test]
fn test_decrypt_when_epoch_key_is_older_than_the_current_leaf_then_opens() {
    read_with_epoch_key_admitted_as(0xCB, b"agent-a", 0).expect("a strictly older key opens");
}

#[test]
fn test_decrypt_when_epoch_key_generation_equals_the_current_leaf_then_refuses() {
    assert_sender_not_found(read_with_epoch_key_admitted_as(0xCC, b"agent-a", 1));
}

#[test]
fn test_decrypt_when_epoch_key_generation_exceeds_the_current_leaf_then_refuses() {
    assert_sender_not_found(read_with_epoch_key_admitted_as(0xCD, b"agent-a", 2));
}

#[test]
fn test_decrypt_when_epoch_key_pair_is_unknown_to_the_provider_then_refuses() {
    assert_sender_not_found(read_with_epoch_key_admitted_as(0xCE, b"agent-x", 0));
}
