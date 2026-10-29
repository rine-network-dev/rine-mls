//! A member that re-enters a group it already holds local state for — re-added
//! by Welcome after a removal, self-joining by external commit after one, or
//! resyncing after its pending commit was lost — starts a new group state over
//! the old group directory. The retained prior epochs of the old state must not
//! stop the new state from advancing.

mod common;

use common::kept_store::{restore, snapshot, KeptStore, SUITE};
use common::{group_id, TestAgent};
use mls_rs::error::MlsError;
use rine_mls_core::{
    AllowedIdentities, LeafIdentity, MlsStoreRoot, RineMlsClient, RineMlsError, RineMlsGroup,
};
use tempfile::TempDir;

/// Removed, then re-added by Welcome over the kept store. The Welcome joins, and
/// the first commit after it must apply rather than fail with `InvalidEpoch`
/// ("plaintext message for incorrect epoch").
#[test]
fn test_readd_by_welcome_over_kept_store_then_the_next_commit_applies() {
    let mut scene = KeptStore::new(0xE1);
    scene.remove_bob();
    assert!(!scene.bob_group.is_active());
    let KeptStore {
        mut alice_group,
        bob,
        bob_group,
        carol,
        ..
    } = scene;
    drop(bob_group);

    let readd = alice_group
        .add_member(&bob.client.generate_key_package().expect("kp"))
        .expect("re-add bob");
    let mut rejoined = bob
        .client
        .join_from_welcome(&readd.welcomes[0])
        .expect("the Welcome itself joins");
    rejoined.save().expect("save");
    assert_eq!(rejoined.epoch(), alice_group.epoch());

    let carol_leaf = alice_group
        .member_index(&carol.identity)
        .expect("carol's leaf");
    let next = alice_group.remove_member(carol_leaf).expect("next commit");
    let applied = rejoined.apply_commit(&next.commit);

    assert_eq!(
        applied.expect("the re-added member applies the next commit"),
        alice_group.epoch(),
    );
}

/// Control for the re-add: the same re-add over a wiped store applies the next commit.
/// The only difference is the old group directory.
#[test]
fn test_readd_by_welcome_over_wiped_store_then_the_next_commit_applies() {
    let mut scene = KeptStore::new(0xE2);
    scene.remove_bob();
    let KeptStore {
        id,
        mut alice_group,
        bob,
        bob_group,
        carol,
        ..
    } = scene;
    drop(bob_group);
    bob.client.delete_group_state(&id).expect("wipe");

    let readd = alice_group
        .add_member(&bob.client.generate_key_package().expect("kp"))
        .expect("re-add bob");
    let mut rejoined = bob
        .client
        .join_from_welcome(&readd.welcomes[0])
        .expect("join");
    rejoined.save().expect("save");

    let carol_leaf = alice_group
        .member_index(&carol.identity)
        .expect("carol's leaf");
    let next = alice_group.remove_member(carol_leaf).expect("next commit");
    assert_eq!(
        rejoined.apply_commit(&next.commit).expect("applies"),
        alice_group.epoch(),
    );
}

/// The same defect on the external-commit path: removed, then self-joining by
/// external commit over the kept store. The build applies its own commit and
/// inserts the GroupInfo's epoch as a prior epoch, which does not follow the
/// highest one stored.
#[test]
fn test_external_join_over_kept_store_after_removal_then_it_builds() {
    let mut scene = KeptStore::new(0xE3);
    scene.remove_bob();
    let KeptStore {
        mut alice_group,
        bob,
        bob_group,
        ..
    } = scene;
    drop(bob_group);

    let (joined, bundle) = bob
        .client
        .join_by_external_commit(&alice_group.group_info().expect("group info"))
        .expect("the external join builds over the kept store");
    alice_group
        .apply_commit(&bundle.commit)
        .expect("alice applies the join");
    assert_eq!(joined.epoch(), alice_group.epoch());
}

/// What the new state keeps readable: a message Bob held the keys for but never
/// read, sent at a retained epoch before the removal, still opens after the
/// re-add. One sent at his last epoch stays unreadable, because that epoch lived
/// only in the state file the re-add overwrites.
#[test]
fn test_readd_over_kept_store_then_an_unread_retained_epoch_message_opens() {
    let id = group_id(0xE6).to_vec();
    let alice = TestAgent::new(0x11, SUITE);
    let bob = TestAgent::new(0x12, SUITE);
    let carol = TestAgent::new(0x13, SUITE);
    let dave = TestAgent::new(0x14, SUITE);

    let (mut alice_group, founding) = alice
        .client
        .create_group_with_members(&id, &[bob.client.generate_key_package().expect("kp")])
        .expect("found with bob");
    let mut bob_group = bob
        .client
        .join_from_welcome(&founding.welcomes[0])
        .expect("bob joins");
    bob_group.save().expect("save");

    let mut unread = Vec::new();
    for joiner in [&carol, &dave] {
        let add = alice_group
            .add_member(&joiner.client.generate_key_package().expect("kp"))
            .expect("add");
        bob_group
            .apply_commit(&add.commit)
            .expect("bob applies the add");
        bob_group.save().expect("save");
        unread.push(
            alice_group
                .encrypt_application_message(b"sent and never read")
                .expect("encrypt"),
        );
    }
    let [at_retained_epoch, at_last_epoch] = [&unread[0], &unread[1]];

    let bob_leaf = alice_group.member_index(&bob.identity).expect("bob's leaf");
    let removal = alice_group.remove_member(bob_leaf).expect("remove bob");
    bob_group
        .apply_commit(&removal.commit)
        .expect("bob applies his removal");
    bob_group.save().expect("save");
    drop(bob_group);

    let readd = alice_group
        .add_member(&bob.client.generate_key_package().expect("kp"))
        .expect("re-add bob");
    let mut rejoined = bob
        .client
        .join_from_welcome(&readd.welcomes[0])
        .expect("the Welcome joins");
    rejoined.save().expect("save");

    let opened = rejoined
        .decrypt_application_message(at_retained_epoch)
        .expect("the unread message at a retained epoch opens");
    assert_eq!(opened.envelope, b"sent and never read");
    assert!(
        matches!(
            rejoined.decrypt_application_message(at_last_epoch),
            Err(RineMlsError::Mls(MlsError::EpochNotFound))
        ),
        "the message at the member's last epoch stays unreadable",
    );
}

/// One agent id with a state directory of its own and a leaf per generation
/// (seed byte `base + generation`), opened against a shared allowed set.
struct Rotor {
    agent: &'static str,
    base: u8,
    dir: TempDir,
}

impl Rotor {
    fn new(agent: &'static str, base: u8) -> Self {
        Self {
            agent,
            base,
            dir: tempfile::tempdir().expect("temp dir"),
        }
    }

    fn seed(&self, generation: u8) -> [u8; 32] {
        [self.base + generation; 32]
    }

    fn leaf(&self, generation: u8) -> LeafIdentity {
        LeafIdentity::new(self.agent.as_bytes(), &self.seed(generation)).expect("seed")
    }

    fn store(&self) -> std::path::PathBuf {
        self.dir.path().join("mls2")
    }

    fn allow(&self, allowed: &AllowedIdentities, generation: u8) {
        allowed
            .insert(
                self.agent.as_bytes(),
                &self.leaf(generation).leaf_public_key(),
                generation.into(),
            )
            .expect("record the pair");
    }

    fn open(&self, allowed: &AllowedIdentities, generation: u8) -> RineMlsClient {
        RineMlsClient::open(
            MlsStoreRoot::new(self.store()),
            &self.leaf(generation),
            allowed.clone(),
            SUITE,
        )
    }
}

/// A founds with R and adds two more members, so R, who applies and saves
/// every commit at generation 0, sits at epoch 3 with prior epochs 1 and 2.
fn rotor_group(
    tag: u8,
) -> (
    Vec<u8>,
    AllowedIdentities,
    RineMlsGroup,
    Rotor,
    RineMlsGroup,
) {
    let id = group_id(tag).to_vec();
    let a = Rotor::new("agent-a", 0x10);
    let r = Rotor::new("agent-r", 0x30);
    let c = Rotor::new("agent-c", 0x50);
    let d = Rotor::new("agent-d", 0x70);
    let allowed = AllowedIdentities::new();
    for (rotor, generation) in [(&a, 0), (&r, 0), (&r, 1), (&c, 0), (&d, 0)] {
        rotor.allow(&allowed, generation);
    }

    let (mut a_group, founding) = a
        .open(&allowed, 0)
        .create_group_with_members(
            &id,
            &[r.open(&allowed, 0).generate_key_package().expect("kp")],
        )
        .expect("found with r");
    let mut r_group = r
        .open(&allowed, 0)
        .join_from_welcome(&founding.welcomes[0])
        .expect("r joins");
    r_group.save().expect("save");
    for joiner in [&c, &d] {
        let add = a_group
            .add_member(&joiner.open(&allowed, 0).generate_key_package().expect("kp"))
            .expect("add");
        r_group
            .apply_commit(&add.commit)
            .expect("r applies the add");
        r_group.save().expect("save");
    }
    assert_eq!(r_group.epoch(), 3);

    (id, allowed, a_group, r, r_group)
}

/// A pending self-update is lost: R's update to generation 1 landed at P = 4 and was
/// acked, then R's store is restored from a copy taken before the update (state
/// at E = 3, prior epochs 1 and 2). The resync at key equality (R's client now
/// signs with generation 1, the key the canonical tree holds) must build, so
/// that something is posted.
#[test]
fn test_resync_after_lost_pending_update_over_restored_store_then_it_builds() {
    let (id, allowed, mut a_group, r, mut r_group) = rotor_group(0xE4);

    let before_update = snapshot(&r.store());

    let update = r_group.commit_update(&r.seed(1)).expect("self-update");
    r_group.apply_pending_commit().expect("apply pending");
    r_group.save().expect("save");
    drop(r_group);
    a_group
        .apply_commit(&update.commit)
        .expect("a applies (the ack confirmed it)");
    assert_eq!(a_group.epoch(), 4);

    // The lost pending commit: the pre-update copy, opened at generation 1.
    restore(&r.store(), &before_update);
    let r1 = r.open(&allowed, 1);
    let stale = r1.load_group(&id).expect("control: the copy loads");
    assert_eq!(
        stale.epoch(),
        3,
        "control: the restored store reads epoch E"
    );
    let stale_leaf = stale.current_member_index().expect("stale leaf");
    drop(stale);

    let (resynced, bundle) = r1
        .resync_by_external_commit(&a_group.group_info().expect("group info"), stale_leaf)
        .expect("the resync builds over the restored store");
    a_group
        .apply_commit(&bundle.commit)
        .expect("a applies the resync");
    assert_eq!(resynced.epoch(), a_group.epoch());
}

/// Control for the resync: the same resync after the restored store is wiped builds.
#[test]
fn test_resync_after_lost_pending_update_over_wiped_store_then_it_builds() {
    let (id, allowed, mut a_group, r, mut r_group) = rotor_group(0xE5);

    let update = r_group.commit_update(&r.seed(1)).expect("self-update");
    drop(r_group);
    a_group.apply_commit(&update.commit).expect("a applies");
    let r1 = r.open(&allowed, 1);
    r1.delete_group_state(&id).expect("wipe");

    let (resynced, bundle) = r1
        .resync_from_group_info(&a_group.group_info().expect("group info"))
        .expect("builds");
    a_group.apply_commit(&bundle.commit).expect("applies");
    assert_eq!(resynced.epoch(), a_group.epoch());
}
