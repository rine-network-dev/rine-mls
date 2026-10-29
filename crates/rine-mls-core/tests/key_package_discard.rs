//! Discarding the key package a Welcome was built against: the one place a
//! client learns its key package was spent without joining.

mod common;

use common::member::{allowing, group_id, stock_client, Member, StockWire};
use mls_rs::{ExtensionList, MlsMessage};
use rine_mls_core::{MlsBlobKind, MlsStoreRoot, RineMlsClient, RineMlsError};

/// Alice founds a group and adds `joiner`, returning the Welcome built for it.
fn welcome_for(joiner: &Member, allowed: &rine_mls_core::AllowedIdentities) -> Vec<u8> {
    let alice = Member::new("alice", 1);
    allowed
        .insert(alice.leaf.agent_id(), &alice.leaf.leaf_public_key(), 0)
        .expect("record the pair");
    let (mut group, _) = alice
        .open(allowed)
        .create_group(&group_id(0x30))
        .expect("create");
    let key_package = joiner
        .open(allowed)
        .generate_key_package()
        .expect("key package");

    group
        .add_member(&key_package)
        .expect("add")
        .welcomes
        .remove(0)
}

#[test]
fn test_discard_welcome_key_package_when_the_welcome_is_ours_then_the_key_package_is_gone() {
    let bob = Member::new("bob", 2);
    let everyone = allowing(&[&bob]);
    let welcome = welcome_for(&bob, &everyone);
    let client = bob.open(&everyone);
    assert_eq!(client.key_package_count().expect("count"), 1);

    assert!(client
        .discard_welcome_key_package(&welcome)
        .expect("discard"));
    assert_eq!(client.key_package_count().expect("count"), 0);
    assert!(
        client.join_from_welcome(&welcome).is_err(),
        "the secret the Welcome needs is gone",
    );
    assert!(!client.discard_welcome_key_package(&welcome).expect("again"));
}

#[test]
fn test_discard_welcome_key_package_when_the_stored_half_is_damaged_then_it_is_still_removed() {
    let bob = Member::new("bob", 2);
    let everyone = allowing(&[&bob]);
    let welcome = welcome_for(&bob, &everyone);
    let client = bob.open(&everyone);
    let damaged = std::fs::read_dir(bob.dir.path().join("mls2").join("key_packages"))
        .expect("key package dir")
        .next()
        .expect("one stored half")
        .expect("entry")
        .path();
    std::fs::write(&damaged, [0u8; 3]).expect("truncate");

    assert!(client
        .discard_welcome_key_package(&welcome)
        .expect("a damaged half does not wedge the release"));
    assert_eq!(client.key_package_count().expect("count"), 0);
}

#[test]
fn test_discard_welcome_key_package_when_the_welcome_is_for_someone_else_then_nothing_is_removed() {
    let (bob, carol) = (Member::new("bob", 2), Member::new("carol", 3));
    let everyone = allowing(&[&bob, &carol]);
    let welcome = welcome_for(&carol, &everyone);
    let client = bob.open(&everyone);
    client.generate_key_package().expect("a second key package");
    let held = client.key_package_count().expect("count");

    assert!(!client
        .discard_welcome_key_package(&welcome)
        .expect("discard"));
    assert_eq!(client.key_package_count().expect("count"), held);
}

#[test]
fn test_discard_welcome_key_package_when_the_blob_is_a_commit_then_it_is_refused() {
    let bob = Member::new("bob", 2);
    let everyone = allowing(&[&bob]);
    let alice = Member::new("alice", 1);
    alice.allow(&everyone);
    let (_, bundle) = alice
        .open(&everyone)
        .create_group(&group_id(0x31))
        .expect("create");

    let error = bob
        .open(&everyone)
        .discard_welcome_key_package(&bundle.commit)
        .expect_err("a commit is not a Welcome");
    assert!(
        matches!(
            error,
            RineMlsError::UnexpectedBlob {
                expected: MlsBlobKind::Welcome,
                ..
            }
        ),
        "got {error:?}",
    );
}

#[test]
fn test_discard_welcome_key_package_when_a_forged_welcome_names_several_held_ones_then_nothing_is_removed(
) {
    let (alice, dave, eve) = (
        Member::new("alice", 1),
        Member::new("dave", 4),
        Member::new("eve", 5),
    );
    let everyone = allowing(&[&alice, &dave, &eve]);
    // Both clients keep their key packages in one directory, so a single
    // client holds the references of both.
    let shared = dave.dir.path().join("mls2");
    let eves_client = RineMlsClient::open(
        MlsStoreRoot::new(shared.clone()),
        &eve.leaf,
        everyone.clone(),
        common::member::SUITE,
    );
    let daves_client = dave.open(&everyone);
    let daves = daves_client.generate_key_package().expect("dave");
    let eves = eves_client.generate_key_package().expect("eve");

    let founder = stock_client(&alice, everyone.clone(), StockWire::SharedWelcome);
    let mut group = founder
        .create_group_with_id(
            group_id(0x32).to_vec(),
            ExtensionList::new(),
            ExtensionList::new(),
            None,
        )
        .expect("create");
    let output = group
        .commit_builder()
        .add_member(MlsMessage::from_bytes(&daves).expect("framed"))
        .expect("add dave")
        .add_member(MlsMessage::from_bytes(&eves).expect("framed"))
        .expect("add eve")
        .build()
        .expect("commit");
    assert_eq!(output.welcome_messages.len(), 1, "one Welcome names both");
    let welcome = output.welcome_messages[0].to_bytes().expect("welcome");
    let held = daves_client.key_package_count().expect("count");

    assert!(!daves_client
        .discard_welcome_key_package(&welcome)
        .expect("discard"));
    assert_eq!(daves_client.key_package_count().expect("count"), held);
}
