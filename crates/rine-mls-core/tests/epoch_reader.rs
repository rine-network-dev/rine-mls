//! The org reader's path: an `EpochReader` built from an escrow export opens the
//! application messages of that epoch.

mod common;

use common::escrow::{self, assert_malformed_refused, export, reader, send, take};
use common::rfc9420::provider;
use common::rfc9420_seal::seal_application;
use common::{group_id, TestAgent};
use rine_mls_core::{RineCipherSuite, RineMlsError, RineMlsGroup};

const SUITE: RineCipherSuite = RineCipherSuite::DEFAULT;

/// Alice founds a group with Bob in one commit: both hold epoch 1.
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

/// Alice admits Carol by her own Add commit, Carol joins by Welcome and Bob
/// applies the commit: all three hold epoch 2, with Alice at leaf 0.
fn trio(id: &[u8]) -> (RineMlsGroup, RineMlsGroup, RineMlsGroup) {
    let (_alice, mut alice_group, _bob, mut bob_group) = pair(id);
    let carol = TestAgent::new(3, SUITE);

    let add = alice_group
        .add_member(&carol.client.generate_key_package().expect("key package"))
        .expect("add carol");
    let carol_group = carol
        .client
        .join_from_welcome(&add.welcomes[0])
        .expect("carol joins");
    bob_group.apply_commit(&add.commit).expect("bob syncs");

    (alice_group, bob_group, carol_group)
}

#[test]
fn test_epoch_reader_when_built_from_an_export_opens_a_members_message() {
    let id = group_id(0xE1);
    let (_alice, mut alice_group, _bob, mut bob_group) = pair(&id);

    let exports = alice_group.take_escrow_exports().expect("exports").exports;
    let epoch_one = exports
        .iter()
        .find(|e| e.epoch == 1)
        .expect("epoch 1 export");

    let payload = bob_group
        .encrypt_application_message(b"what bob said")
        .expect("encrypt");
    let mut reader = reader(&id, 1, &epoch_one.plaintext);

    let opened = reader.open(&payload[1..]).expect("open");

    assert_eq!(opened.envelope, b"what bob said");
    assert_eq!(
        opened.sender_index,
        bob_group.current_member_index().expect("index")
    );
    assert_eq!(
        opened.signer_public_key,
        escrow::leaf_key(&epoch_one.plaintext, opened.sender_index),
        "the signer key is the one the escrow records for the sender's leaf",
    );
}

#[test]
fn test_epoch_reader_when_every_sender_is_out_of_order_opens_all_nine() {
    let id = group_id(0xE2);
    let (mut alice_group, mut bob_group, mut carol_group) = trio(&id);
    let exports = take(&mut alice_group);
    let mut reader = reader(&id, 2, &export(&exports, 2).plaintext);

    let senders = vec![
        ("alice", &mut alice_group),
        ("bob", &mut bob_group),
        ("carol", &mut carol_group),
    ];

    for message in escrow::out_of_order(senders) {
        let opened = reader.open(&message.payload[1..]).expect("open");
        let label = format!("{} generation {}", message.sender, message.generation);
        assert_eq!(opened.envelope, message.envelope, "{label}");
        assert_eq!(opened.sender_index, message.leaf, "{label}");
        assert_eq!(opened.generation, message.generation, "{label}");
        assert_eq!(
            opened.signer_public_key,
            escrow::leaf_key(&export(&exports, 2).plaintext, message.leaf),
            "{label}"
        );
    }
}

#[test]
fn test_epoch_reader_when_the_message_is_from_another_epoch_refuses_it() {
    let id = group_id(0xE3);
    let (mut alice_group, mut bob_group, _carol_group) = trio(&id);
    let exports = take(&mut alice_group);
    let (payload, _) = send(&mut bob_group, "epoch two");

    let mut stale = reader(&id, 1, &export(&exports, 1).plaintext);
    assert!(matches!(
        stale.open(&payload[1..]),
        Err(RineMlsError::Mls(_))
    ));

    let mut current = reader(&id, 2, &export(&exports, 2).plaintext);
    assert_eq!(
        current.open(&payload[1..]).expect("open").envelope,
        b"epoch two"
    );
}

#[test]
fn test_epoch_reader_when_the_epoch_forked_refuses_the_other_forks_message() {
    let id = group_id(0xE4);
    let (_alice, mut alice_group, _bob, mut bob_group) = pair(&id);
    let carol = TestAgent::new(3, SUITE);
    let dave = TestAgent::new(4, SUITE);

    alice_group
        .add_member(&carol.client.generate_key_package().expect("key package"))
        .expect("alice adds carol");
    bob_group
        .add_member(&dave.client.generate_key_package().expect("key package"))
        .expect("bob adds dave");

    let fork_a = take(&mut alice_group);
    let fork_b = take(&mut bob_group);
    let (payload, _) = send(&mut bob_group, "fork B");

    let mut reader_a = reader(&id, 2, &export(&fork_a, 2).plaintext);
    assert!(matches!(
        reader_a.open(&payload[1..]),
        Err(RineMlsError::Mls(_))
    ));

    let mut reader_b = reader(&id, 2, &export(&fork_b, 2).plaintext);
    assert_eq!(
        reader_b.open(&payload[1..]).expect("open").envelope,
        b"fork B"
    );
}

#[test]
fn test_epoch_reader_when_the_export_is_taken_after_processing_still_opens_earlier_messages() {
    let id = group_id(0xE5);
    let (_alice, mut alice_group, _bob, mut bob_group) = pair(&id);

    let (first, _) = send(&mut bob_group, "bob one");
    let (second, _) = send(&mut bob_group, "bob two");
    alice_group
        .decrypt_application_message(&first)
        .expect("read one");
    alice_group
        .decrypt_application_message(&second)
        .expect("read two");
    send(&mut alice_group, "alice one");

    let exports = take(&mut alice_group);
    let mut reader = reader(&id, 1, &export(&exports, 1).plaintext);

    assert_eq!(
        reader.open(&first[1..]).expect("open one").envelope,
        b"bob one"
    );
    assert_eq!(
        reader.open(&second[1..]).expect("open two").envelope,
        b"bob two"
    );
}

#[test]
fn test_epoch_reader_when_the_generation_is_past_the_window_opens_the_last_message() {
    let id = group_id(0xE6);
    let (_alice, mut alice_group, _bob, mut bob_group) = pair(&id);
    let exports = take(&mut alice_group);

    let mut last = (Vec::new(), Vec::new());
    for generation in 0..1030u32 {
        last = send(&mut bob_group, &format!("bob {generation}"));
    }

    let mut reader = reader(&id, 1, &export(&exports, 1).plaintext);
    let opened = reader.open(&last.0[1..]).expect("open the last");

    assert_eq!(opened.generation, 1029);
    assert_eq!(opened.envelope, last.1);
}

#[test]
fn test_epoch_reader_when_the_generation_is_three_thousand_opens_it_directly() {
    let id = group_id(0xEA);
    let (_alice, mut alice_group, _bob, mut bob_group) = pair(&id);
    let exports = take(&mut alice_group);

    let mut messages = Vec::new();
    for generation in 0..=3000u32 {
        messages.push(send(&mut bob_group, &format!("bob {generation}")));
    }

    let mut reader = reader(&id, 1, &export(&exports, 1).plaintext);
    let (payload, envelope) = &messages[3000];
    let opened = reader.open(&payload[1..]).expect("open generation 3000");

    assert_eq!(opened.generation, 3000);
    assert_eq!(&opened.envelope, envelope);
}

#[test]
fn test_epoch_reader_when_the_generation_is_beyond_the_reach_refuses_it_by_name() {
    let id = group_id(0xEB);
    let (_alice, mut alice_group, _bob, bob_group) = pair(&id);
    let exports = take(&mut alice_group);
    let plaintext = &export(&exports, 1).plaintext;

    let generation = 70_000;
    let sealed = seal_application(
        &provider(),
        &id,
        1,
        &escrow::sender_data_secret(plaintext),
        bob_group.current_member_index().expect("index"),
        generation,
        &[0; 32],
        &[0; 12],
    );

    assert!(matches!(
        reader(&id, 1, plaintext).open(&sealed),
        Err(RineMlsError::GenerationTooFar { generation: g }) if g == generation
    ));
}

#[test]
fn test_epoch_reader_when_a_leaf_key_is_rewritten_rejects_the_sender() {
    let id = group_id(0xE7);
    let (mut alice_group, mut bob_group, _carol_group) = trio(&id);
    let exports = take(&mut alice_group);

    let mut doctored = export(&exports, 2).plaintext.to_vec();
    let carol_key = escrow::leaf_key(&doctored, 2);
    escrow::set_leaf_key(&mut doctored, 1, &carol_key);

    let (payload, _) = send(&mut bob_group, "bob");
    let mut reader = reader(&id, 2, &doctored);

    assert!(matches!(
        reader.open(&payload[1..]),
        Err(RineMlsError::MemberRejected { sender: 1, .. })
    ));
}

#[test]
fn test_epoch_reader_when_two_leaf_keys_are_swapped_rejects_both_senders() {
    let id = group_id(0xE8);
    let (mut alice_group, mut bob_group, _carol_group) = trio(&id);
    let exports = take(&mut alice_group);

    let mut doctored = export(&exports, 2).plaintext.to_vec();
    escrow::swap_leaf_keys(&mut doctored, 0, 1);

    let (bob_payload, _) = send(&mut bob_group, "bob");
    let (alice_payload, _) = send(&mut alice_group, "alice");

    let mut reader = reader(&id, 2, &doctored);
    assert!(matches!(
        reader.open(&bob_payload[1..]),
        Err(RineMlsError::MemberRejected { sender: 1, .. })
    ));
    assert!(matches!(
        reader.open(&alice_payload[1..]),
        Err(RineMlsError::MemberRejected { sender: 0, .. })
    ));
}

#[test]
fn test_epoch_reader_when_the_escrow_is_malformed_refuses_it_by_name() {
    let id = group_id(0xE9);
    let (mut alice_group, ..) = trio(&id);
    let exports = take(&mut alice_group);

    assert_malformed_refused(&id, 2, &export(&exports, 2).plaintext);
}
