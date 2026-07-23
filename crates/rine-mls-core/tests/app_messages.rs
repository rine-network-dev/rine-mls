//! Application messages: the data plane, over both join paths.
//!
//! The plaintext here stands in for the signed rine envelope that MLS wraps;
//! the transport adds the 0x04 version tag and base64url on top of these bytes.

mod common;

use common::{for_each_suite, group_id, TestAgent};

#[test]
fn test_application_message_when_sent_to_a_welcome_joiner_round_trips() {
    for_each_suite(|suite| {
        let alice = TestAgent::new(1, suite);
        let bob = TestAgent::new(2, suite);

        let (mut alice_group, _) = alice.client.create_group(&group_id(0xA4)).expect("create");
        let add = alice_group
            .add_member(&bob.client.generate_key_package().expect("key package"))
            .expect("add commit");
        let mut bob_group = bob
            .client
            .join_from_welcome(&add.welcomes[0])
            .expect("welcome join");

        let envelope = b"rine envelope: kid || sig || plaintext";
        let ciphertext = alice_group
            .encrypt_application_message(envelope)
            .expect("encrypt");

        assert_ne!(
            &ciphertext[..],
            &envelope[..],
            "envelope is not in the clear"
        );

        let received = bob_group
            .decrypt_application_message(&ciphertext)
            .expect("decrypt");

        assert_eq!(received.envelope, envelope);
        assert_eq!(
            received.sender_index,
            alice_group
                .member_index(&alice.identity)
                .expect("alice leaf"),
        );
    });
}

#[test]
fn test_application_message_when_sent_by_an_external_joiner_reaches_every_member() {
    for_each_suite(|suite| {
        let alice = TestAgent::new(1, suite);
        let bob = TestAgent::new(2, suite);
        let carol = TestAgent::new(3, suite);

        let (mut alice_group, _) = alice.client.create_group(&group_id(0xA5)).expect("create");
        let add = alice_group
            .add_member(&bob.client.generate_key_package().expect("key package"))
            .expect("add commit");
        let mut bob_group = bob
            .client
            .join_from_welcome(&add.welcomes[0])
            .expect("welcome join");

        let (mut carol_group, carol_commit) = carol
            .client
            .join_by_external_commit(&add.group_info)
            .expect("external join");
        alice_group
            .apply_commit(&carol_commit.commit)
            .expect("alice");
        bob_group.apply_commit(&carol_commit.commit).expect("bob");

        let envelope = b"posted by the external joiner";
        let ciphertext = carol_group
            .encrypt_application_message(envelope)
            .expect("encrypt");

        assert_eq!(
            alice_group
                .decrypt_application_message(&ciphertext)
                .expect("alice decrypt")
                .envelope,
            envelope,
        );
        assert_eq!(
            bob_group
                .decrypt_application_message(&ciphertext)
                .expect("bob decrypt")
                .envelope,
            envelope,
        );
    });
}
