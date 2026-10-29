//! The escrow export install sites: every place an epoch is installed must
//! leave exactly one export behind, and nowhere else may.
//!
//! Each test is the proof for one site, named `test_install_site_<site>_...` so
//! a mutation that drops a capture turns exactly one test red. The plaintext is
//! decoded here by hand, from the layout in the interface note, never through
//! the crate's own parser.

mod common;

use std::collections::BTreeMap;

use common::escrow::take;
use common::{group_id, TestAgent};
use rine_mls_core::{EscrowExport, RineCipherSuite, RineMlsGroup};

const SUITE: RineCipherSuite = RineCipherSuite::DEFAULT;

/// Alice founds a group with Bob in one commit: both hold epoch 1.
fn pair(id: &[u8]) -> (TestAgent, RineMlsGroup, TestAgent, RineMlsGroup) {
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
    (alice, alice_group, bob, bob_group)
}

/// The three-member variant: Alice admits Carol by her own Add commit, Carol
/// joins by Welcome and Bob applies the commit, so all three hold epoch 2.
fn trio(id: &[u8]) -> (RineMlsGroup, RineMlsGroup, u64) {
    let (_alice, mut alice_group, _bob, mut bob_group) = pair(id);
    let carol = TestAgent::new(3, SUITE);
    let add = alice_group
        .add_member(&carol.client.generate_key_package().expect("kp"))
        .expect("add carol");
    let _carol = carol
        .client
        .join_from_welcome(&add.welcomes[0])
        .expect("join");
    bob_group.apply_commit(&add.commit).expect("bob syncs");
    (alice_group, bob_group, add.epoch)
}

fn epoch_export(group: &mut RineMlsGroup, epoch: u64) -> EscrowExport {
    take(group)
        .into_iter()
        .find(|e| e.epoch == epoch)
        .expect("export")
}

#[test]
fn test_install_site_create_when_a_group_is_founded_exports_epoch_zero() {
    let alice = TestAgent::new(1, SUITE);
    let (mut group, _) = alice.client.create_group(&group_id(0xB1)).expect("create");
    assert!(
        take(&mut group).iter().any(|e| e.epoch == 0),
        "creation exports epoch 0"
    );
}
#[test]
fn test_install_site_welcome_when_a_member_joins_exports_only_the_joined_epoch() {
    let (_alice, _alice_group, _bob, mut bob_group) = pair(&group_id(0xB2));
    let epochs: Vec<u64> = take(&mut bob_group).iter().map(|e| e.epoch).collect();
    assert_eq!(
        epochs,
        vec![1],
        "a Welcome joiner exports only the epoch it joined at"
    );
}
#[test]
fn test_install_site_own_commit_when_a_member_is_added_exports_the_new_epoch() {
    let (mut alice_group, _bob_group, joined) = trio(&group_id(0xB3));
    assert!(
        take(&mut alice_group).iter().any(|e| e.epoch == joined),
        "the group applying its own Add commit exports the new epoch",
    );
}
#[test]
fn test_install_site_received_commit_when_a_member_applies_it_exports_the_new_epoch() {
    let (_alice_group, mut bob_group, joined) = trio(&group_id(0xB4));
    assert!(
        take(&mut bob_group).iter().any(|e| e.epoch == joined),
        "a received commit that passed its confirmation tag exports the new epoch",
    );
}
#[test]
fn test_install_site_external_commit_when_a_stranger_joins_or_resyncs_exports_only_its_own_epoch() {
    let (_alice, alice_group, bob, mut bob_group) = pair(&group_id(0xB5));
    let carol = TestAgent::new(3, SUITE);
    let group_info = alice_group.group_info().expect("group info");
    let (mut carol_group, join) = carol
        .client
        .join_by_external_commit(&group_info)
        .expect("external join");
    let joined = take(&mut carol_group);
    assert_eq!(joined.len(), 1, "the placeholder epoch is not exported");
    assert_eq!(joined[0].epoch, join.epoch, "its own commit's epoch");
    assert_ne!(joined[0].epoch, 1, "the placeholder epoch is not exported");

    let stale_leaf = bob_group.current_member_index().expect("bob's leaf");
    let _ = take(&mut bob_group);
    let (mut resynced, resync) = bob
        .client
        .resync_by_external_commit(&group_info, stale_leaf)
        .expect("resync");
    let exports = take(&mut resynced);
    assert_eq!(exports.len(), 1, "the placeholder epoch is not exported");
    assert_eq!(exports[0].epoch, resync.epoch, "its own commit's epoch");
}
#[test]
fn test_install_site_take_when_called_twice_empties_the_list() {
    let alice = TestAgent::new(1, SUITE);
    let (mut group, _) = alice.client.create_group(&group_id(0xB6)).expect("create");
    assert!(!take(&mut group).is_empty());
    assert!(take(&mut group).is_empty(), "a second take is empty");
}
#[test]
fn test_install_site_snapshot_when_a_take_is_unsaved_re_yields_and_when_saved_does_not() {
    let id = group_id(0xB7);
    let alice = TestAgent::new(1, SUITE);
    let (mut group, _) = alice.client.create_group(&id).expect("create");
    group.save().expect("persist");
    let first = take(&mut group);
    assert!(!first.is_empty());
    drop(group);

    // The take was never saved, so the stored snapshot still holds the exports.
    let mut reloaded = alice.client.load_group(&id).expect("load");
    let again = take(&mut reloaded);
    let (before, after): (Vec<u64>, Vec<u64>) = (
        first.iter().map(|e| e.epoch).collect(),
        again.iter().map(|e| e.epoch).collect(),
    );
    assert_eq!(after, before, "an unsaved take re-yields the same epochs");
    for (a, b) in first.iter().zip(again.iter()) {
        assert_eq!(a.fp, b.fp, "the fingerprint survives the crash");
        assert_eq!(
            &a.plaintext[..],
            &b.plaintext[..],
            "the plaintext survives the crash"
        );
    }

    // Saving after the take persists the emptied list, so nothing re-yields.
    reloaded.save().expect("persist the take");
    drop(reloaded);
    let mut after_save = alice.client.load_group(&id).expect("load");
    assert!(
        take(&mut after_save).is_empty(),
        "a saved take is not re-yielded"
    );
}
#[test]
fn test_install_site_fork_when_two_members_commit_from_one_epoch_fingerprints_differ() {
    let (_alice, mut alice_group, _bob, mut bob_group) = pair(&group_id(0xB9));
    let alice_one = epoch_export(&mut alice_group, 1);
    let bob_one = epoch_export(&mut bob_group, 1);
    assert_eq!(alice_one.fp, bob_one.fp, "one epoch, one fingerprint");

    let carol = TestAgent::new(3, SUITE);
    let dave = TestAgent::new(4, SUITE);
    alice_group
        .add_member(&carol.client.generate_key_package().expect("kp"))
        .expect("alice adds carol");
    bob_group
        .add_member(&dave.client.generate_key_package().expect("kp"))
        .expect("bob adds dave");

    let alice_two = epoch_export(&mut alice_group, 2);
    let bob_two = epoch_export(&mut bob_group, 2);
    assert_ne!(alice_two.fp, bob_two.fp, "two forks of epoch 2");
    assert_ne!(
        &alice_two.plaintext[..],
        &bob_two.plaintext[..],
        "different secrets"
    );
}
#[test]
fn test_install_site_layout_when_decoded_by_hand_matches_the_epoch() {
    let (alice, mut alice_group, bob, _bob_group) = pair(&group_id(0xBA));
    let export = epoch_export(&mut alice_group, 1);
    let bytes = &export.plaintext[..];
    let u32_at = |o: usize| u32::from_be_bytes(bytes[o..o + 4].try_into().expect("4"));

    assert_eq!(bytes[0], 0x01, "version");
    assert_eq!(
        u16::from_be_bytes(bytes[1..3].try_into().expect("2")),
        0xF057,
        "suite"
    );
    assert_eq!(u32_at(3), 2, "alice and bob occupy two leaves");

    let context_len = u32_at(71) as usize;
    assert!(context_len > 0, "the group context is never empty");
    let n = u32_at(75 + context_len) as usize;
    assert_eq!(n, 2, "two non-empty leaves");
    assert_eq!(
        bytes.len(),
        79 + context_len + 36 * n,
        "the length formula holds"
    );

    let keys: BTreeMap<u32, Vec<u8>> = alice_group
        .member_identities()
        .expect("roster")
        .into_iter()
        .map(|leaf| {
            let (i, id) = (leaf.index, leaf.identity);
            let key = if id == alice.identity {
                alice.client.leaf_public_key()
            } else {
                assert_eq!(id, bob.identity, "the roster holds only alice and bob");
                bob.client.leaf_public_key()
            };
            (i, key.to_vec())
        })
        .collect();
    let mut offset = 79 + context_len;
    for _ in 0..n {
        let index = u32_at(offset);
        assert_eq!(
            keys.get(&index).map(Vec::as_slice),
            Some(&bytes[offset + 4..offset + 36]),
            "leaf {index} carries its member's leaf public key",
        );
        offset += 36;
    }
}
#[test]
fn test_install_site_what_is_not_escrowed_when_two_members_share_an_epoch_is_identical() {
    let (_alice, mut alice_group, _bob, mut bob_group) = pair(&group_id(0xBB));
    let alice_one = epoch_export(&mut alice_group, 1);
    let bob_one = epoch_export(&mut bob_group, 1);
    let (a, b) = (&alice_one.plaintext[..], &bob_one.plaintext[..]);

    assert_eq!(
        &a[7..39],
        &b[7..39],
        "sender_data_secret is the epoch's, not the member's"
    );
    assert_eq!(
        &a[39..71],
        &b[39..71],
        "encryption_secret is the epoch's, not the member's"
    );
    assert_eq!(
        a, b,
        "the whole plaintext is the same for both members of one epoch"
    );
}
#[test]
fn test_install_site_received_commit_when_the_commit_is_refused_exports_nothing() {
    let (_alice, mut alice_group, _bob, mut bob_group) = pair(&group_id(0xBB));
    let carol = TestAgent::new(3, SUITE);
    let add = alice_group
        .add_member(&carol.client.generate_key_package().expect("kp"))
        .expect("add carol");
    let _ = take(&mut bob_group);
    let epoch = bob_group.epoch();

    let mut flipped = add.commit.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 1;
    assert!(
        bob_group.apply_commit(&flipped).is_err(),
        "a corrupted commit"
    );
    assert_eq!(bob_group.epoch(), epoch, "the epoch did not move");
    assert!(
        take(&mut bob_group).is_empty(),
        "a refused commit exports nothing"
    );

    bob_group
        .apply_commit(&add.commit)
        .expect("the real commit");
    assert!(
        take(&mut bob_group).iter().any(|e| e.epoch == add.epoch),
        "the same commit, intact, exports its epoch",
    );
    assert!(
        bob_group.apply_commit(&add.commit).is_err(),
        "a replayed commit is refused"
    );
    assert!(take(&mut bob_group).is_empty(), "a replay exports nothing");
}

#[test]
fn test_install_site_welcome_when_the_welcome_is_unusable_returns_an_error() {
    let id = group_id(0xBC);
    let alice = TestAgent::new(1, SUITE);
    let bob = TestAgent::new(2, SUITE);
    let carol = TestAgent::new(3, SUITE);
    let (_group, bundle) = alice
        .client
        .create_group_with_members(&id, &[bob.client.generate_key_package().expect("kp")])
        .expect("create with bob");

    assert!(
        carol.client.join_from_welcome(b"not a welcome").is_err(),
        "garbage bytes are not a Welcome",
    );
    assert!(
        carol.client.join_from_welcome(&bundle.welcomes[0]).is_err(),
        "a Welcome for another member is not this member's",
    );
}
