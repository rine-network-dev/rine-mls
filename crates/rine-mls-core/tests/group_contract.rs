//! The parts of rine's group contract that are decisions rather than plumbing:
//! how a group is founded, how a Welcome finds its member, what happens when a
//! peer's KeyPackages predate the MLS cutover, and what a removed member sees.

mod common;

use common::{for_each_suite, group_id, TestAgent};
use rine_mls_core::{RineCipherSuite, RineMlsError, APP_MESSAGE_TAG};

/// A KeyPackage as rine's pre-cutover TypeScript stack published it: the bare
/// RFC 9420 object, without the MLSMessage framing this core puts around it.
/// Stripping the 4-byte MLSMessage header (protocol version, wire format)
/// leaves exactly those bytes.
fn unframed(key_package: &[u8]) -> Vec<u8> {
    key_package[4..].to_vec()
}

/// What a blob costs in the JSON body rine puts it in. The server bounds every
/// MLS blob it accepts by its base64 length (`MLS_BLOB_MAX_B64`), not by its
/// raw size.
fn base64_len(blob: &[u8]) -> usize {
    blob.len().div_ceil(3) * 4
}

/// `src/rine/api/mls_schemas.py`: every MLS blob field is capped at this many
/// base64 characters, server side, and a commit that exceeds it is a 422 rather
/// than a group.
const MLS_BLOB_MAX_B64: usize = 256 * 1024;

#[test]
fn test_default_cipher_suite_is_the_post_quantum_one() {
    assert_eq!(RineCipherSuite::DEFAULT, RineCipherSuite::XWing);
    assert_eq!(RineCipherSuite::DEFAULT.id(), 0xF057);
}

#[test]
fn test_create_group_with_members_when_founding_a_group_admits_everyone_in_one_commit() {
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

        let (group, bundle) = alice
            .client
            .create_group_with_members(&group_id(0xB1), &key_packages)
            .expect("create with members");

        assert_eq!(bundle.epoch, 1, "one commit, one epoch, whatever the size");
        assert_eq!(group.epoch(), 1);
        assert_eq!(bundle.welcomes.len(), 2, "one Welcome per member added");
        assert!(group.member_index(&bob.identity).is_ok());
        assert!(group.member_index(&carol.identity).is_ok());
    });
}

#[test]
fn test_create_group_with_members_when_welcomes_are_delivered_pairs_each_with_its_own_member() {
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
            .create_group_with_members(&group_id(0xB2), &key_packages)
            .expect("create with members");

        // The server is handed `welcomes[i]` as the Welcome for the agent whose
        // KeyPackage was `key_packages[i]`. Each member must be able to join
        // with its own, and only with its own.
        let mut bob_group = bob
            .client
            .join_from_welcome(&bundle.welcomes[0])
            .expect("bob joins with the first Welcome");
        let mut carol_group = carol
            .client
            .join_from_welcome(&bundle.welcomes[1])
            .expect("carol joins with the second Welcome");

        assert!(bob.client.join_from_welcome(&bundle.welcomes[1]).is_err());
        assert!(carol.client.join_from_welcome(&bundle.welcomes[0]).is_err());

        let envelope = b"rine envelope: kid || sig || plaintext";
        let payload = alice_group
            .encrypt_application_message(envelope)
            .expect("encrypt");

        for group in [&mut bob_group, &mut carol_group] {
            assert_eq!(
                group
                    .decrypt_application_message(&payload)
                    .expect("founding member decrypts")
                    .envelope,
                envelope,
            );
        }
    });
}

/// Founding a group in one commit puts every member's KeyPackage inline in that
/// commit, so the commit grows with the group where a chain of single-Add
/// commits would not have. The server bounds each blob, so the growth is
/// measured rather than assumed — and it is measured on the post-quantum suite,
/// whose keys are the large ones.
#[test]
fn test_create_group_with_members_when_founding_a_group_stays_inside_the_servers_blob_cap() {
    let suite = RineCipherSuite::DEFAULT;
    let alice = TestAgent::new(1, suite);
    let members: Vec<TestAgent> = (0..16).map(|i| TestAgent::new(20 + i, suite)).collect();

    let key_packages = members
        .iter()
        .map(|member| member.client.generate_key_package().expect("package"))
        .collect::<Vec<_>>();

    let (_, bundle) = alice
        .client
        .create_group_with_members(&group_id(0xB9), &key_packages)
        .expect("create with members");

    let welcome = base64_len(&bundle.welcomes[0]);
    eprintln!(
        "16-member post-quantum init: key package {}, commit {}, welcome {}, group info {} (base64)",
        base64_len(&key_packages[0]),
        base64_len(&bundle.commit),
        welcome,
        base64_len(&bundle.group_info),
    );

    assert!(base64_len(&bundle.commit) <= MLS_BLOB_MAX_B64);
    assert!(welcome <= MLS_BLOB_MAX_B64);
    assert!(base64_len(&bundle.group_info) <= MLS_BLOB_MAX_B64);
}

#[test]
fn test_encrypt_application_message_when_framed_carries_the_mls_v1_version_tag() {
    for_each_suite(|suite| {
        let alice = TestAgent::new(1, suite);
        let (mut group, _) = alice.client.create_group(&group_id(0xB3)).expect("create");

        let payload = group
            .encrypt_application_message(b"tagged in the core")
            .expect("encrypt");

        assert_eq!(payload[0], APP_MESSAGE_TAG, "0x04 belongs to the core");
    });
}

#[test]
fn test_add_members_when_a_key_package_predates_the_cutover_names_the_member_to_republish() {
    for_each_suite(|suite| {
        let alice = TestAgent::new(1, suite);
        let bob = TestAgent::new(2, suite);
        let carol = TestAgent::new(3, suite);

        let key_packages = vec![
            bob.client.generate_key_package().expect("bob's package"),
            unframed(
                &carol
                    .client
                    .generate_key_package()
                    .expect("carol's package"),
            ),
        ];

        let error = alice
            .client
            .create_group_with_members(&group_id(0xB4), &key_packages)
            .map(|_| ())
            .expect_err("a pre-cutover KeyPackage is not readable");

        assert!(
            matches!(error, RineMlsError::UnreadableKeyPackage { index: 1 }),
            "the second member is the one who has to republish, got {error:?}",
        );
    });
}

#[test]
fn test_group_cipher_suite_when_joined_by_welcome_reports_the_groups_own_suite() {
    for_each_suite(|suite| {
        let alice = TestAgent::new(1, suite);
        let bob = TestAgent::new(2, suite);

        let (mut alice_group, _) = alice.client.create_group(&group_id(0xB7)).expect("create");
        let bundle = alice_group
            .add_member(&bob.client.generate_key_package().expect("package"))
            .expect("add bob");
        let bob_group = bob
            .client
            .join_from_welcome(&bundle.welcomes[0])
            .expect("welcome join");

        assert_eq!(alice_group.cipher_suite().expect("founder suite"), suite);
        assert_eq!(bob_group.cipher_suite().expect("joiner suite"), suite);
    });
}

#[test]
fn test_apply_commit_when_it_removes_this_member_retires_the_group_handle() {
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
            .create_group_with_members(&group_id(0xB8), &key_packages)
            .expect("create with members");
        let mut bob_group = bob
            .client
            .join_from_welcome(&bundle.welcomes[0])
            .expect("bob joins");
        let mut carol_group = carol
            .client
            .join_from_welcome(&bundle.welcomes[1])
            .expect("carol joins");

        let before = alice_group
            .encrypt_application_message(b"sent while bob was still a member")
            .expect("encrypt");

        let bob_leaf = alice_group.member_index(&bob.identity).expect("bob's leaf");
        let removal = alice_group.remove_member(bob_leaf).expect("remove bob");

        assert!(
            bob_group.is_active(),
            "still a member until the commit lands"
        );
        bob_group
            .apply_commit(&removal.commit)
            .expect("bob applies the commit that evicts him");
        assert!(!bob_group.is_active(), "the eviction retires the handle");

        // Everything that would carry the group forward is refused by name.
        for error in [
            bob_group
                .encrypt_application_message(b"after the eviction")
                .err(),
            bob_group.add_members(&[]).err(),
            bob_group.apply_commit(&removal.commit).err(),
        ] {
            assert!(
                matches!(error, Some(RineMlsError::GroupInactive { epoch: 2 })),
                "got {error:?}",
            );
        }

        // Being removed ends participation; it does not unread the inbox.
        assert_eq!(
            bob_group
                .decrypt_application_message(&before)
                .expect("a message bob already held the secrets for")
                .envelope,
            b"sent while bob was still a member",
        );

        carol_group
            .apply_commit(&removal.commit)
            .expect("carol applies the same commit");
        assert!(carol_group.is_active(), "carol was not the one removed");
        assert_eq!(carol_group.epoch(), 2);
    });
}
