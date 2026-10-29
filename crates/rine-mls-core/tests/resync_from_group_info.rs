//! Resync from a GroupInfo alone: an agent that lost its local state finds its
//! own seat in the tree and replaces it, without ever holding a stale handle.
//!
//! `resync_by_external_commit` needs the leaf index out of the old handle;
//! `resync_from_group_info` finds the seat by credential instead, which is the
//! only path left to an agent whose state is gone. These tests drive that path
//! end to end: the seat is restored, the epoch it lands on is escrowed, a
//! stranger and a different credential are refused, and a rotated leaf key is
//! refused too — an external commit keeps the key it replaces, and a rotated
//! agent moves with a self-update instead. A Welcome, by contrast,
//! validates every leaf already in the tree, so it still joins when the joiner
//! has verified the rotated agent's old leaf.

mod common;

use common::{group_id, TestAgent};
use rine_mls_core::{
    AllowedIdentities, LeafIdentity, MlsStoreRoot, RineCipherSuite, RineMlsClient, RineMlsError,
    RineMlsErrorCode, RineMlsGroup,
};
use tempfile::TempDir;

const SUITE: RineCipherSuite = RineCipherSuite::DEFAULT;

/// Alice founds a group with Bob in one commit; both hold epoch 1.
fn pair(id: &[u8]) -> (TestAgent, RineMlsGroup, TestAgent, RineMlsGroup) {
    let alice = TestAgent::new(1, SUITE);
    let bob = TestAgent::new(2, SUITE);

    let (alice_group, bundle) = alice
        .client
        .create_group_with_members(
            id,
            &[bob.client.generate_key_package().expect("key package")],
        )
        .expect("create with bob");
    let bob_group = bob
        .client
        .join_from_welcome(&bundle.welcomes[0])
        .expect("welcome join");

    (alice, alice_group, bob, bob_group)
}

#[test]
fn test_resync_from_group_info_when_local_state_is_gone_then_the_seat_is_restored() {
    let id = group_id(0xB1);
    let (_alice, mut alice_group, bob, bob_group) = pair(&id);
    drop(bob_group);

    bob.client
        .delete_group_state(&id)
        .expect("wipe bob's state");
    assert!(
        bob.client.load_group(&id).is_err(),
        "the resync must start from no local state at all",
    );

    let (mut resynced, bundle) = bob
        .client
        .resync_from_group_info(&alice_group.group_info().expect("group info"))
        .expect("bob finds his own seat in the tree");

    alice_group
        .apply_commit(&bundle.commit)
        .expect("alice applies the resync commit");

    assert_eq!(
        resynced.epoch(),
        alice_group.epoch(),
        "the recovered handle and the group must agree on the epoch",
    );

    let roster = alice_group.member_identities().expect("enumerate tree");
    assert_eq!(
        roster.len(),
        2,
        "a resync replaces a seat, it does not add one"
    );
    assert!(
        roster.iter().any(|leaf| leaf.identity == bob.identity),
        "bob's agent id must still be seated after the resync",
    );

    let from_bob = resynced
        .encrypt_application_message(b"back from the dead")
        .expect("resynced handle sends");
    assert_eq!(
        alice_group
            .decrypt_application_message(&from_bob)
            .expect("alice reads the resynced handle")
            .envelope,
        b"back from the dead",
    );

    let from_alice = alice_group
        .encrypt_application_message(b"welcome back")
        .expect("alice sends");
    assert_eq!(
        resynced
            .decrypt_application_message(&from_alice)
            .expect("the resynced handle reads alice")
            .envelope,
        b"welcome back",
    );
}

#[test]
fn test_resync_from_group_info_when_it_lands_then_the_new_epoch_is_escrowed() {
    let id = group_id(0xB2);
    let (_alice, alice_group, bob, bob_group) = pair(&id);
    drop(bob_group);

    bob.client
        .delete_group_state(&id)
        .expect("wipe bob's state");
    let (mut resynced, bundle) = bob
        .client
        .resync_from_group_info(&alice_group.group_info().expect("group info"))
        .expect("resync");

    let exports = resynced.take_escrow_exports().expect("exports").exports;
    assert_eq!(
        exports.len(),
        1,
        "a resync installs exactly one epoch, and it must be escrowed",
    );
    assert_eq!(
        exports[0].epoch, bundle.epoch,
        "the escrowed epoch must be the one the resync commit created",
    );
}

#[test]
fn test_resync_from_group_info_when_the_agent_was_never_a_member_then_it_is_refused() {
    let id = group_id(0xB3);
    let (alice, alice_group, _bob, bob_group) = pair(&id);
    drop(bob_group);

    let carol = TestAgent::new(3, SUITE);
    let error = carol
        .client
        .resync_from_group_info(&alice_group.group_info().expect("group info"))
        .map(|_| ())
        .expect_err("carol holds no seat");

    assert!(
        matches!(error, RineMlsError::NoSeatToReplace),
        "got {error:?}",
    );
    assert_eq!(error.code(), RineMlsErrorCode::NoSeatToReplace);
    drop(alice);
}

#[test]
fn test_resync_from_group_info_when_another_agent_holds_bobs_leaf_key_then_it_is_refused() {
    let id = group_id(0xB4);
    let (alice, alice_group, bob, bob_group) = pair(&id);
    drop(bob_group);

    // The impostor carries bob's leaf signing seed under a different agent id:
    // the leaf key is bob's, the credential is not.
    let impostor_leaf = LeafIdentity::new(b"impostor", &[2u8; 32]).expect("32-byte seed");
    let allowed = AllowedIdentities::new();
    allowed
        .insert(&alice.identity, &alice.client.leaf_public_key(), 0)
        .expect("record the pair");
    allowed
        .insert(&bob.identity, &bob.client.leaf_public_key(), 0)
        .expect("record the pair");
    allowed
        .insert(
            impostor_leaf.agent_id(),
            &impostor_leaf.leaf_public_key(),
            0,
        )
        .expect("record the pair");

    let dir = TempDir::new().expect("temp dir");
    let impostor = RineMlsClient::open(
        MlsStoreRoot::new(dir.path().join("mls2")),
        &impostor_leaf,
        allowed,
        SUITE,
    );

    let error = impostor
        .resync_from_group_info(&alice_group.group_info().expect("group info"))
        .map(|_| ())
        .expect_err("the seat is found by credential, not by leaf key");

    assert!(
        matches!(error, RineMlsError::NoSeatToReplace),
        "got {error:?}",
    );
}

#[test]
fn test_resync_from_group_info_when_the_leaf_key_rotated_then_it_is_refused() {
    let id = group_id(0xB5);
    let (_alice, alice_group, bob, bob_group) = pair(&id);
    drop(bob_group);

    // Bob rotates: same agent id, a new leaf signing seed, both keys allowed.
    // The seat is found by credential, but an external commit may not replace
    // a leaf with one that carries a different key.
    let rotated = bob.rotated(3);
    let error = rotated
        .client
        .resync_from_group_info(&alice_group.group_info().expect("group info"))
        .map(|_| ())
        .expect_err("a rotated leaf key cannot take over the seat it no longer matches");

    assert_eq!(
        error.code(),
        RineMlsErrorCode::ResyncChangesKey,
        "got {error:?}"
    );
}

#[test]
fn test_join_from_welcome_when_the_tree_holds_a_rotated_agents_old_leaf_then_only_a_joiner_that_verified_it_joins(
) {
    let id = group_id(0xB6);
    let (alice, mut alice_group, bob, bob_group) = pair(&id);
    drop(bob_group);

    // Bob rotates but does not resync: his old leaf stays in the tree, and his
    // new key is registered alongside it.
    let _rotated = bob.rotated(3);

    // Carol shares the global allowed set, which holds bob's old leaf, so the
    // Welcome validates the tree it is handed.
    let carol = TestAgent::new(4, SUITE);
    let add = alice_group
        .add_member(&carol.client.generate_key_package().expect("key package"))
        .expect("alice adds carol");

    let mut carol_group = carol
        .client
        .join_from_welcome(&add.welcomes[0])
        .expect("carol's allowed set holds bob's old leaf");

    let sealed = alice_group
        .encrypt_application_message(b"hello carol")
        .expect("alice sends");
    assert_eq!(
        carol_group
            .decrypt_application_message(&sealed)
            .expect("carol reads alice")
            .envelope,
        b"hello carol",
    );

    // A fourth agent whose allowed set holds only its own pair and alice's:
    // the tree still holds bob's old leaf, which it has not verified.
    let dave = TestAgent::new(5, SUITE);
    let dave_leaf = LeafIdentity::new(&dave.identity, &[5u8; 32]).expect("32-byte seed");
    let daves_view = AllowedIdentities::new();
    daves_view
        .insert(&dave.identity, &dave_leaf.leaf_public_key(), 0)
        .expect("record the pair");
    daves_view
        .insert(&alice.identity, &alice.client.leaf_public_key(), 0)
        .expect("record the pair");

    let dir = TempDir::new().expect("temp dir");
    let dave_client = RineMlsClient::open(
        MlsStoreRoot::new(dir.path().join("mls2")),
        &dave_leaf,
        daves_view,
        SUITE,
    );

    let add = alice_group
        .add_member(&dave_client.generate_key_package().expect("key package"))
        .expect("alice adds dave");

    let error = dave_client
        .join_from_welcome(&add.welcomes[0])
        .map(|_| ())
        .expect_err("dave has not verified bob's old leaf");
    assert_eq!(
        error.code(),
        RineMlsErrorCode::PeerNotAdmitted,
        "got {error:?}"
    );
    assert_eq!(error.refused_peer(), Some(bob.identity.as_slice()));
}
