//! Group lifecycle: create, both join paths, removal — run once per rine
//! ciphersuite, so the post-quantum suite has to carry the whole flow and not
//! merely exchange a key.
//!
//! Every blob crossing between agents here is exactly what rine puts on the
//! wire: KeyPackage, commit, Welcome and GroupInfo bytes, moved by value the
//! way the server relays them. No agent ever sees another's state.

mod common;

use common::{for_each_suite, group_id, TestAgent};

#[test]
fn test_create_group_when_founder_self_commits_publishes_a_joinable_group_info() {
    for_each_suite(|suite| {
        let alice = TestAgent::new(1, suite);
        let id = group_id(0xA1);

        let (group, bundle) = alice.client.create_group(&id).expect("create group");

        assert_eq!(group.group_id(), id.to_vec());
        assert_eq!(group.epoch(), 1, "creation self-commit advances 0 -> 1");
        assert_eq!(bundle.epoch, 1);
        assert!(bundle.welcomes.is_empty(), "no members added yet");
        assert!(!bundle.commit.is_empty());
        assert!(!bundle.group_info.is_empty());
        assert_eq!(alice.client.cipher_suite(), suite);
    });
}

#[test]
fn test_welcome_join_when_member_is_added_lands_on_the_committed_epoch() {
    for_each_suite(|suite| {
        let alice = TestAgent::new(1, suite);
        let bob = TestAgent::new(2, suite);

        let (mut group, _) = alice.client.create_group(&group_id(0xA2)).expect("create");
        let key_package = bob.client.generate_key_package().expect("key package");

        let bundle = group.add_member(&key_package).expect("add commit");

        assert_eq!(bundle.epoch, 2, "the Add commit advances 1 -> 2");
        assert_eq!(bundle.welcomes.len(), 1);

        let bob_group = bob
            .client
            .join_from_welcome(&bundle.welcomes[0])
            .expect("welcome join");

        assert_eq!(bob_group.group_id(), group.group_id());
        assert_eq!(bob_group.epoch(), group.epoch());
        assert_eq!(
            group.member_index(&bob.identity).expect("bob in roster"),
            bob_group
                .member_index(&bob.identity)
                .expect("bob sees self"),
        );
    });
}

#[test]
fn test_external_commit_join_when_group_info_is_published_admits_the_joiner() {
    for_each_suite(|suite| {
        let alice = TestAgent::new(1, suite);
        let bob = TestAgent::new(2, suite);
        let carol = TestAgent::new(3, suite);

        let (mut alice_group, _) = alice.client.create_group(&group_id(0xA3)).expect("create");
        let add = alice_group
            .add_member(&bob.client.generate_key_package().expect("key package"))
            .expect("add commit");
        let mut bob_group = bob
            .client
            .join_from_welcome(&add.welcomes[0])
            .expect("welcome join");

        // Carol self-joins from the published GroupInfo alone: no Welcome, no
        // action by any existing member.
        let (carol_group, carol_commit) = carol
            .client
            .join_by_external_commit(&add.group_info)
            .expect("external join");

        assert_eq!(
            carol_group.epoch(),
            3,
            "the external commit advances 2 -> 3"
        );

        assert_eq!(
            alice_group
                .apply_commit(&carol_commit.commit)
                .expect("alice"),
            3
        );
        assert_eq!(
            bob_group.apply_commit(&carol_commit.commit).expect("bob"),
            3
        );

        for group in [&alice_group, &bob_group, &carol_group] {
            assert!(group.member_index(&carol.identity).is_ok(), "carol joined");
        }
    });
}

#[test]
fn test_remove_member_when_committed_evicts_the_leaf_and_cuts_off_decryption() {
    for_each_suite(|suite| {
        let alice = TestAgent::new(1, suite);
        let bob = TestAgent::new(2, suite);
        let carol = TestAgent::new(3, suite);

        let (mut alice_group, _) = alice.client.create_group(&group_id(0xA6)).expect("create");
        let add_bob = alice_group
            .add_member(&bob.client.generate_key_package().expect("key package"))
            .expect("add bob");
        let mut bob_group = bob
            .client
            .join_from_welcome(&add_bob.welcomes[0])
            .expect("bob joins");

        let add_carol = alice_group
            .add_member(&carol.client.generate_key_package().expect("key package"))
            .expect("add carol");
        let mut carol_group = carol
            .client
            .join_from_welcome(&add_carol.welcomes[0])
            .expect("carol joins");
        bob_group
            .apply_commit(&add_carol.commit)
            .expect("bob syncs");

        let bob_leaf = alice_group.member_index(&bob.identity).expect("bob leaf");
        let removal = alice_group.remove_member(bob_leaf).expect("remove commit");

        assert_eq!(removal.epoch, 4);
        assert!(removal.welcomes.is_empty(), "a Remove produces no Welcome");
        carol_group
            .apply_commit(&removal.commit)
            .expect("carol syncs");

        assert!(alice_group.member_index(&bob.identity).is_err());
        assert!(carol_group.member_index(&bob.identity).is_err());

        // Bob is still sitting on his stale epoch-3 state; post-removal traffic is
        // out of his reach.
        let ciphertext = alice_group
            .encrypt_application_message(b"after the eviction")
            .expect("encrypt");
        assert!(bob_group.decrypt_application_message(&ciphertext).is_err());
    });
}
