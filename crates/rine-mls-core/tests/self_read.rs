//! Reading back a message this member sent, and retiring local state.
//!
//! MLS forward secrecy consumes the sender's ratchet step at encryption time,
//! so the sender's own message is the one message MLS will not decrypt. Every
//! rine surface shows a sender its own thread, so this is not an edge case: it
//! is the ordinary case, answered from the plaintext the encrypt call kept.

mod common;

use std::fs;
use std::path::PathBuf;

use common::{for_each_suite, group_id, TestAgent};
use rine_mls_core::{RineCipherSuite, RineMlsErrorCode, RineMlsGroup};

fn cache_path(agent: &TestAgent, id: &[u8]) -> PathBuf {
    agent
        .store_path()
        .join("groups")
        .join(hex::encode(id))
        .join("self_read.bin")
}

/// A two-member group, returned as (alice, alice's group handle, bob, bob's
/// group handle) at the epoch Bob joined at.
fn pair(suite: RineCipherSuite, id: &[u8]) -> (TestAgent, RineMlsGroup, TestAgent, RineMlsGroup) {
    let alice = TestAgent::new(1, suite);
    let bob = TestAgent::new(2, suite);

    let (mut alice_group, _) = alice.client.create_group(id).expect("create");
    let add = alice_group
        .add_member(&bob.client.generate_key_package().expect("key package"))
        .expect("add commit");
    let mut bob_group = bob
        .client
        .join_from_welcome(&add.welcomes[0])
        .expect("welcome join");

    alice_group.save().expect("persist");
    bob_group.save().expect("persist");

    (alice, alice_group, bob, bob_group)
}

#[test]
fn test_own_message_when_read_back_returns_the_plaintext_the_sender_sent() {
    for_each_suite(|suite| {
        let id = group_id(0xC1);
        let (alice, mut alice_group, _bob, mut bob_group) = pair(suite, &id);

        let payload = alice_group
            .encrypt_application_message(b"what alice said")
            .expect("encrypt");

        let read_back = alice_group
            .decrypt_application_message(&payload)
            .expect("a sender must be able to read its own message");

        assert_eq!(read_back.envelope, b"what alice said");
        assert_eq!(
            read_back.sender_index,
            bob_group
                .member_index(&alice.identity)
                .expect("alice's leaf"),
            "the self-read must report alice's own leaf, not a placeholder",
        );

        // And the ordinary path is untouched: Bob still decrypts it as MLS.
        assert_eq!(
            bob_group
                .decrypt_application_message(&payload)
                .expect("peer decrypt")
                .envelope,
            b"what alice said",
        );
    });
}

#[test]
fn test_own_message_when_the_process_restarted_is_still_readable() {
    let id = group_id(0xC2);
    let (alice, mut alice_group, ..) = pair(RineCipherSuite::DEFAULT, &id);

    let payload = alice_group
        .encrypt_application_message(b"sent before the restart")
        .expect("encrypt");
    alice_group.save().expect("persist");
    drop(alice_group);

    let mut reopened = alice.reopen().load_group(&id).expect("load from disk");

    assert_eq!(
        reopened
            .decrypt_application_message(&payload)
            .expect("self-read survives a restart")
            .envelope,
        b"sent before the restart",
    );
}

#[test]
fn test_own_message_when_several_were_sent_reads_each_one_back() {
    let id = group_id(0xC3);
    let (_alice, mut alice_group, ..) = pair(RineCipherSuite::DEFAULT, &id);

    let sent: Vec<(Vec<u8>, Vec<u8>)> = (0..8u8)
        .map(|i| {
            let envelope = format!("message {i}").into_bytes();
            let payload = alice_group
                .encrypt_application_message(&envelope)
                .expect("encrypt");
            (payload, envelope)
        })
        .collect();

    for (payload, envelope) in &sent {
        assert_eq!(
            alice_group
                .decrypt_application_message(payload)
                .expect("self-read")
                .envelope,
            *envelope,
        );
    }
}

#[test]
fn test_own_message_when_the_cache_no_longer_holds_it_says_so_by_name() {
    let id = group_id(0xC4);
    let (alice, mut alice_group, ..) = pair(RineCipherSuite::DEFAULT, &id);

    let payload = alice_group
        .encrypt_application_message(b"aged out")
        .expect("encrypt");
    alice_group.save().expect("persist");
    drop(alice_group);

    fs::remove_file(cache_path(&alice, &id)).expect("evict the cache the hard way");

    let err = alice
        .reopen()
        .load_group(&id)
        .expect("load from disk")
        .decrypt_application_message(&payload)
        .expect_err("nothing can decrypt this now");

    assert_eq!(err.code(), RineMlsErrorCode::SelfMessageNotCached);
}

#[cfg(unix)]
#[test]
fn test_self_read_cache_when_written_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let id = group_id(0xC5);
    let (alice, mut alice_group, ..) = pair(RineCipherSuite::DEFAULT, &id);

    alice_group
        .encrypt_application_message(b"plaintext on disk")
        .expect("encrypt");

    let mode = fs::metadata(cache_path(&alice, &id))
        .expect("cache file")
        .permissions()
        .mode()
        & 0o777;

    assert_eq!(
        mode, 0o600,
        "the cache holds plaintext; it is the most sensitive file in the store",
    );
}

#[test]
fn test_delete_group_state_when_a_group_is_retired_takes_the_plaintext_with_it() {
    let id = group_id(0xC6);
    let (alice, mut alice_group, ..) = pair(RineCipherSuite::DEFAULT, &id);

    alice_group
        .encrypt_application_message(b"to be retired")
        .expect("encrypt");
    alice_group.save().expect("persist");
    drop(alice_group);

    assert!(cache_path(&alice, &id).exists());

    let reopened = alice.reopen();
    reopened.delete_group_state(&id).expect("retire");

    assert!(
        !cache_path(&alice, &id).exists(),
        "the last thing left after a group is retired must not be the only \
         unencrypted copy of its messages",
    );
    assert!(
        reopened.load_group(&id).is_err(),
        "retired state is gone, not merely emptied",
    );
}

#[test]
fn test_delete_group_state_when_there_is_no_such_group_is_not_an_error() {
    let agent = TestAgent::new(1, RineCipherSuite::DEFAULT);

    agent
        .client
        .delete_group_state(&group_id(0xC7))
        .expect("retiring what was never there is the outcome the caller wanted");
}
