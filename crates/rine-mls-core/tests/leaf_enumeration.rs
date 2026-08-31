//! Two NEEDS-A-RUN items: can a client see the whole tree, and can it
//! retire a leaf that carries its own identity?
//!
//! Both were carried into this crate as unanswerable by argument alone. Each
//! gates a different half of the decision:
//!
//! **1. The leaf-index round trip (gates orphan reclamation).**
//! `member_identities()` is built over mls-rs's `Roster`, whose own doc comment
//! warns that its indices *"do not correlate with indexes of users within
//! `ReceivedMessage` content descriptions"*. Read against the source that
//! warning is about a different quantity — `member_from_leaf_node` is handed
//! the real `LeafIndex` — but mls-rs is a library rine does not own, and the
//! claim is load-bearing for a verb that **removes members**. If the round trip
//! does not hold, orphan reclamation removes the wrong leaf.
//!
//! **2. Removing a leaf whose credential equals the committer's own (gates the
//! duplicate-leaf cleanup).** The duplicate-leaf regression's premise was that
//! a resync by external commit seats a new leaf and abandons the old one, so an
//! agent's presence silently doubles and somebody has to clean up. **That
//! premise is measured FALSE.** mls-rs refuses a plain external commit from an
//! agent the tree already holds — `duplicate signature key, hpke key or
//! identity found at index N` — so the duplicate class that cleanup was scoped
//! for cannot arise.
//!
//! What that changes is bigger than what it answers. The plain external commit
//! is not a resync path at all: an agent recovering from unusable local state
//! gets an error, not a second leaf. The path that works is RFC 9420's own
//! resync form, where the Remove of the agent's own stale leaf rides in the
//! **same** commit as the join — one commit, no window in which two leaves
//! exist, and no orphan to reclaim afterwards. The last test pins the property
//! that makes it safe to expose: MLS refuses at build time to let that Remove
//! name anyone else's leaf.
//!
//! Everything runs on both suites, because a suite that only works classically
//! is not a suite rine can ship.
//!
//! `cargo test -p rine-mls-core --test leaf_enumeration -- --nocapture` prints
//! what each group looked like, so this is the evidence trail as well as the
//! assertion.

mod common;

use common::{for_each_suite, group_id, TestAgent};
use rine_mls_core::{RineCipherSuite, RineMlsGroup};

/// Members seated before anyone leaves, founder excluded.
const COHORT: usize = 8;

/// Members removed, to blank leaves in the middle of the tree. The round trip
/// is only interesting once the occupied indices are non-contiguous — a tree
/// nobody ever left would pass a positional-index bug unnoticed.
const CHURN: usize = 3;

// ---------------------------------------------------------------------------
// NEEDS-A-RUN 1 — the leaf-index round trip (gates orphan reclamation)
// ---------------------------------------------------------------------------

#[test]
fn test_member_identities_when_the_tree_has_blanked_leaves_then_every_index_round_trips() {
    for_each_suite(|suite| {
        let (group, live) = build_churned_group(suite, 0xE1);

        let roster = group.member_identities().expect("enumerate tree");

        // Every leaf the enumeration reports must be findable by the identity
        // it reports, AND come back at the same index. This is the assertion
        // orphan reclamation is gated on: a reclamation verb reads an index out
        // of this list and hands it to `remove_member`, so an index that means
        // something else there removes an innocent member.
        for (index, identity) in &roster {
            let found = group
                .member_index(identity)
                .expect("an enumerated identity must be findable");

            assert_eq!(
                found,
                *index,
                "on suite 0x{:04X} leaf {index} enumerated an identity that member_index \
                 resolves to leaf {found}: the two are not the same index space, so orphan \
                 reclamation would post a Remove for the wrong member",
                suite.id(),
            );
        }

        // The enumeration must also be COMPLETE and EXACT. A short roster makes
        // a live member look like an orphan — the set difference reclamation
        // computes would name it for removal — and a long one keeps a departed
        // member's leaf invisible to reclamation.
        let mut enumerated: Vec<u32> = roster.iter().map(|(index, _)| *index).collect();
        enumerated.sort_unstable();

        let mut expected: Vec<u32> = live
            .iter()
            .map(|agent| group.member_index(&agent.identity).expect("seated"))
            .collect();
        expected.sort_unstable();

        eprintln!(
            "suite 0x{:04X}  live members {}  occupied leaves {:?}  (widest {})",
            suite.id(),
            live.len(),
            enumerated,
            enumerated.last().copied().unwrap_or(0),
        );

        assert_eq!(
            enumerated,
            expected,
            "on suite 0x{:04X} the enumerated tree is not the live membership: a leaf missing \
             here is a leaf reclamation can never name, and a leaf too many is a live member \
             the orphan set would evict",
            suite.id(),
        );

        // A blanked leaf must NOT be reported. This is the half that decides
        // whether reclamation converges: if removed members lingered in the
        // roster, every reclamation pass would re-propose leaves already gone.
        assert!(
            enumerated.len() == COHORT + 1 - CHURN,
            "expected {} occupied leaves after {CHURN} removals, got {}",
            COHORT + 1 - CHURN,
            enumerated.len(),
        );
    });
}

#[test]
fn test_current_member_index_when_the_group_is_open_then_it_names_this_handles_own_leaf() {
    for_each_suite(|suite| {
        let founder = TestAgent::new(0x21, suite);
        let (mut group, _) = founder
            .client
            .create_group(&group_id(0xE2))
            .expect("create group");

        let joiner = TestAgent::new(0x22, suite);
        let bundle = group
            .add_member(&joiner.client.generate_key_package().expect("key package"))
            .expect("add commit");

        let joined = joiner
            .client
            .join_from_welcome(&bundle.welcomes[0])
            .expect("join from welcome");

        // Each handle's own index must agree with what the identity-keyed
        // lookup says about it, from BOTH sides of the group. The duplicate-leaf
        // cleanup leans on this to tell its live leaf from its stale one.
        for (label, handle, agent) in [("founder", &group, &founder), ("joiner", &joined, &joiner)]
        {
            let own = handle.current_member_index().expect("own leaf");
            let by_identity = handle.member_index(&agent.identity).expect("seated");

            eprintln!(
                "suite 0x{:04X}  {label}: current_member_index {own}, member_index {by_identity}",
                suite.id(),
            );
            assert_eq!(
                own,
                by_identity,
                "on suite 0x{:04X} the {label} handle disagrees with itself about which leaf \
                 it occupies",
                suite.id(),
            );
        }
    });
}

// ---------------------------------------------------------------------------
// NEEDS-A-RUN 2 — removing a leaf that carries the committer's own identity
// (gates the duplicate-leaf cleanup)
// ---------------------------------------------------------------------------

/// The duplicate-leaf regression's premise: that a resync seats a new leaf and
/// abandons the old one, so the agent's presence silently doubles.
/// **MEASURED FALSE** — mls-rs
/// refuses the plain external commit outright, on both suites, with `duplicate
/// signature key, hpke key or identity found at index N`.
///
/// That is a stricter and better answer than the decision assumed, and it is
/// pinned here because that whole cleanup was scoped for the duplicate this
/// test proves cannot exist. It also means the plain join is not a resync path
/// at all: an agent recovering from unusable state gets an error, not a second
/// leaf. What replaces it is measured by
/// [`test_resync_by_external_commit_when_the_agent_is_already_seated_then_it_replaces_its_own_leaf`].
#[test]
fn test_join_by_external_commit_when_the_agent_is_already_seated_then_mls_refuses_it() {
    for_each_suite(|suite| {
        let founder = TestAgent::new(0x31, suite);
        let (mut group, _) = founder
            .client
            .create_group(&group_id(0xE3))
            .expect("create group");

        let agent = TestAgent::new(0x32, suite);
        let bundle = group
            .add_member(&agent.client.generate_key_package().expect("key package"))
            .expect("add commit");
        let mut original = agent
            .client
            .join_from_welcome(&bundle.welcomes[0])
            .expect("join from welcome");

        let stale_leaf = original.current_member_index().expect("own leaf");
        original.save().expect("persist the pre-resync handle");

        // A fresh client over the SAME identity — one agent recovering, not a
        // second agent.
        let group_info = group.group_info().expect("group info");
        let error = agent
            .client
            .join_by_external_commit(&group_info)
            .err()
            .unwrap_or_else(|| {
                panic!(
                    "on suite 0x{:04X} a seated agent (leaf {stale_leaf}) was allowed a second \
                     leaf by plain external commit. The duplicate-leaf regression is real \
                     after all, the duplicate-leaf cleanup is needed as originally scoped, and \
                     resync_by_external_commit is no longer the only recovery path",
                    suite.id(),
                )
            });

        eprintln!(
            "suite 0x{:04X}  seated at leaf {stale_leaf}, plain external commit refused: {error}",
            suite.id(),
        );
    });
}

/// What replaces it: RFC 9420's resync form, where the Remove of the agent's
/// own stale leaf rides in the same commit as the join.
///
/// This is the load-bearing measurement for the resync verb. Three things have
/// to hold together, and the third is the one nothing in the tree could answer:
/// the commit must be accepted by MLS, existing members must be able to apply
/// it, and the tree afterwards must carry the agent **exactly once** —
/// otherwise the recovery either fails or leaves the orphan the duplicate-leaf
/// regression describes.
#[test]
fn test_resync_by_external_commit_when_the_agent_is_already_seated_then_it_replaces_its_own_leaf() {
    for_each_suite(|suite| {
        let founder = TestAgent::new(0x41, suite);
        let (mut group, _) = founder
            .client
            .create_group(&group_id(0xE4))
            .expect("create group");

        // A bystander, so the group is not just the two parties to the resync
        // and the commit has somebody else to be delivered to.
        let bystander = TestAgent::new(0x43, suite);
        let agent = TestAgent::new(0x42, suite);
        let bundle = group
            .add_members(&[
                bystander
                    .client
                    .generate_key_package()
                    .expect("key package"),
                agent.client.generate_key_package().expect("key package"),
            ])
            .expect("add commit");
        let mut bystander_group = bystander
            .client
            .join_from_welcome(&bundle.welcomes[0])
            .expect("bystander joins");
        let original = agent
            .client
            .join_from_welcome(&bundle.welcomes[1])
            .expect("agent joins");

        let stale_leaf = original.current_member_index().expect("own leaf");
        let before = group.member_identities().expect("enumerate tree").len();

        let group_info = group.group_info().expect("group info");
        let (resynced, resync) = agent
            .client
            .resync_by_external_commit(&group_info, stale_leaf)
            .unwrap_or_else(|error| {
                panic!(
                    "on suite 0x{:04X} mls-rs refused the RFC resync form: {error}. There is \
                     no recovery path at all then — the plain external commit is refused for a \
                     seated agent, and this was the alternative",
                    suite.id(),
                )
            });

        // Every existing member must be able to apply it, including one with no
        // stake in the resync. A commit only the founder can process is not a
        // commit rine can broadcast.
        group
            .apply_commit(&resync.commit)
            .expect("founder applies the resync commit");
        bystander_group
            .apply_commit(&resync.commit)
            .expect("bystander applies the resync commit");

        let roster = resynced.member_identities().expect("enumerate tree");
        let live_leaf = resynced.current_member_index().expect("own leaf");
        let mine: Vec<u32> = roster
            .iter()
            .filter(|(_, identity)| *identity == agent.identity)
            .map(|(index, _)| *index)
            .collect();

        eprintln!(
            "suite 0x{:04X}  resync: leaf {stale_leaf} -> {live_leaf}, tree {:?}, this identity \
             holds {mine:?}, members {} -> {}",
            suite.id(),
            roster.iter().map(|(index, _)| *index).collect::<Vec<_>>(),
            before,
            roster.len(),
        );

        // The whole point: one leaf, not two. If this is ever more than one,
        // the duplicate-leaf regression is back and a cleanup pass is needed
        // again.
        assert_eq!(
            mine,
            vec![live_leaf],
            "on suite 0x{:04X} the resync left this identity on {mine:?}: the stale leaf was \
             not replaced, so the agent's presence doubled — the duplicate-leaf regression, \
             which must never ship",
            suite.id(),
        );
        assert_eq!(
            roster.len(),
            before,
            "on suite 0x{:04X} the group's membership changed size across a resync",
            suite.id(),
        );

        // The founder's view must agree with the resyncer's, or the two are
        // looking at different trees and every later commit index is suspect.
        assert_eq!(
            group.member_index(&agent.identity).expect("still seated"),
            live_leaf,
            "on suite 0x{:04X} the founder and the resyncer disagree about which leaf the \
             resynced agent occupies",
            suite.id(),
        );
        assert!(
            resynced.is_active(),
            "on suite 0x{:04X} the resync retired the handle it just created — mls-rs read the \
             Remove as a self-eviction",
            suite.id(),
        );

        // And the recovered handle must actually work: a resync that produces a
        // group nobody can send to has recovered nothing.
        let mut resynced = resynced;
        let sealed = resynced
            .encrypt_application_message(b"resynced and speaking")
            .expect("resynced handle must be able to send");
        let read = group
            .decrypt_application_message(&sealed)
            .expect("founder must read what the resynced handle sent");

        assert_eq!(
            read.envelope,
            b"resynced and speaking",
            "on suite 0x{:04X} the resynced handle's message did not survive the round trip",
            suite.id(),
        );

        // The one place the two index spaces actually meet. mls-rs warns that
        // roster indices "do not correlate with indexes of users within
        // ReceivedMessage content descriptions" — `sender_index` IS that
        // quantity, so this is the warning tested head-on rather than reasoned
        // around, on the leaf a resync just moved.
        assert_eq!(
            read.sender_index,
            live_leaf,
            "on suite 0x{:04X} the founder attributes the resynced agent's message to leaf {} \
             while the tree puts it at {live_leaf}: the roster and ReceivedMessage index spaces \
             disagree, and every index reclamation reads out of member_identities is suspect",
            suite.id(),
            read.sender_index,
        );

        eprintln!(
            "suite 0x{:04X}  post-resync send read back by founder, attributed to leaf {}",
            suite.id(),
            read.sender_index,
        );
    });
}

/// The resync form carries a Remove, and a Remove is an eviction primitive. So
/// the question this test exists for is whether it is a *scoped* one: can a
/// party that fetches a GroupInfo — which rine serves to any group member, and
/// which is what an external join needs — name **somebody else's** leaf and
/// evict them by joining?
///
/// If it can, `resync_by_external_commit` is not a recovery path but an
/// unauthenticated kick available to anyone who can reach the GroupInfo, and
/// rine cannot expose it without an authorisation story of its own.
#[test]
fn test_resync_by_external_commit_when_it_names_another_members_leaf_then_the_group_refuses_it() {
    for_each_suite(|suite| {
        let founder = TestAgent::new(0x51, suite);
        let (mut group, _) = founder
            .client
            .create_group(&group_id(0xE5))
            .expect("create group");

        let victim = TestAgent::new(0x52, suite);
        let bundle = group
            .add_member(&victim.client.generate_key_package().expect("key package"))
            .expect("add commit");
        let victim_group = victim
            .client
            .join_from_welcome(&bundle.welcomes[0])
            .expect("victim joins");
        let victim_leaf = victim_group.current_member_index().expect("victim's leaf");

        // A stranger: never a member, holding only the GroupInfo.
        let stranger = TestAgent::new(0x53, suite);
        let group_info = group.group_info().expect("group info");

        let attempt = stranger
            .client
            .resync_by_external_commit(&group_info, victim_leaf);

        // Two acceptable outcomes, and both must be reported by name: MLS
        // refuses to build it, or it builds and the GROUP refuses to apply it.
        // The unacceptable outcome is a commit existing members accept.
        match attempt {
            Err(error) => {
                eprintln!(
                    "suite 0x{:04X}  stranger naming leaf {victim_leaf}: refused at build: \
                     {error}",
                    suite.id(),
                );
            }
            Ok((_, forged)) => {
                let applied = group.apply_commit(&forged.commit);

                match applied {
                    Err(error) => eprintln!(
                        "suite 0x{:04X}  stranger naming leaf {victim_leaf}: built, but the \
                         group refused it: {error}",
                        suite.id(),
                    ),
                    Ok(_) => {
                        let roster = group.member_identities().expect("enumerate tree");
                        let evicted = !roster
                            .iter()
                            .any(|(_, identity)| *identity == victim.identity);

                        panic!(
                            "on suite 0x{:04X} a stranger holding only a GroupInfo joined by \
                             external commit while naming another member's leaf, and the group \
                             ACCEPTED it (victim evicted: {evicted}). \
                             resync_by_external_commit is an unauthenticated eviction \
                             primitive, not a recovery path, and rine must not expose it as \
                             the resync verb was designed",
                            suite.id(),
                        );
                    }
                }
            }
        }
    });
}

/// The wedge the resync verb actually exists to fix, driven end to end.
///
/// `GET /groups/{id}/mls/handshakes` marks each commit delivered on read, so an
/// agent that lost the commits between its epoch and the group's cannot get
/// them again — it is stuck, and the operator sees only `Epoch not found`. The
/// resync is the way out, and it needs the agent's leaf index from **stale**
/// state: state written many epochs ago, by a process that has since restarted.
///
/// So the precondition the whole path rests on is that a leaf index survives
/// staleness — that an agent's leaf does not move under it while it is not
/// looking. Nothing in the tree says so, and if it were false the resync would
/// name whichever member later took that index and the recovery would be an
/// eviction.
#[test]
fn test_resync_by_external_commit_when_the_handle_is_epochs_stale_then_its_leaf_index_still_holds()
{
    for_each_suite(|suite| {
        let founder = TestAgent::new(0x61, suite);
        let (mut group, _) = founder
            .client
            .create_group(&group_id(0xE6))
            .expect("create group");

        let agent = TestAgent::new(0x62, suite);
        let bundle = group
            .add_member(&agent.client.generate_key_package().expect("key package"))
            .expect("add commit");
        let mut stranded = agent
            .client
            .join_from_welcome(&bundle.welcomes[0])
            .expect("agent joins");
        stranded.save().expect("persist state at the joined epoch");

        let stale_epoch = stranded.epoch();
        let stale_leaf = stranded.current_member_index().expect("own leaf");

        // The group moves on without it: members join, and members leave, so
        // leaves are both appended and blanked while the agent is not looking.
        // Blanked leaves are the dangerous part — mls-rs reuses them, so a
        // later joiner can land on an index the stranded agent remembers.
        let others: Vec<TestAgent> = (0..5)
            .map(|n| TestAgent::indexed(0x7000 + n, suite))
            .collect();
        for other in &others {
            group
                .add_member(&other.client.generate_key_package().expect("key package"))
                .expect("add commit");
        }
        for other in others.iter().take(3) {
            let leaf = group.member_index(&other.identity).expect("seated");
            group.remove_member(leaf).expect("remove commit");
        }
        for n in 0..3 {
            let latecomer = TestAgent::indexed(0x8000 + n, suite);
            group
                .add_member(
                    &latecomer
                        .client
                        .generate_key_package()
                        .expect("key package"),
                )
                .expect("add commit");
        }

        // Reopen from disk, as a restarted process does. This handle has never
        // seen any of those commits and cannot get them.
        let reloaded = agent
            .client
            .load_group(&group_id(0xE6))
            .expect("stale state must still load");
        let reloaded_leaf = reloaded.current_member_index().expect("own leaf");

        eprintln!(
            "suite 0x{:04X}  stranded at epoch {stale_epoch} (leaf {stale_leaf}); group now at \
             epoch {}, tree {:?}; reloaded handle reports leaf {reloaded_leaf}",
            suite.id(),
            group.epoch(),
            group
                .member_identities()
                .expect("enumerate")
                .iter()
                .map(|(index, _)| *index)
                .collect::<Vec<_>>(),
        );

        assert_eq!(
            reloaded_leaf,
            stale_leaf,
            "on suite 0x{:04X} a reloaded stale handle reports a different leaf than it saved",
            suite.id(),
        );
        assert_eq!(
            group.member_index(&agent.identity).expect("still a member"),
            stale_leaf,
            "on suite 0x{:04X} the group moved the stranded agent's leaf from {stale_leaf} while \
             it was away: a resync naming the remembered index would evict whoever holds it now",
            suite.id(),
        );

        // And the recovery itself, from nothing but stale state.
        let group_info = group.group_info().expect("group info");
        let (resynced, resync) = agent
            .client
            .resync_by_external_commit(&group_info, reloaded_leaf)
            .expect("a stranded agent must be able to resync");
        group
            .apply_commit(&resync.commit)
            .expect("the group applies the resync");

        let mine: Vec<u32> = resynced
            .member_identities()
            .expect("enumerate tree")
            .into_iter()
            .filter(|(_, identity)| *identity == agent.identity)
            .map(|(index, _)| index)
            .collect();

        assert_eq!(
            mine.len(),
            1,
            "on suite 0x{:04X} the recovered agent holds {mine:?} — a resync out of the wedge \
             must leave it seated exactly once",
            suite.id(),
        );
        assert_eq!(
            resynced.epoch(),
            group.epoch(),
            "on suite 0x{:04X} the resynced handle is not at the group's epoch, so it is still \
             wedged",
            suite.id(),
        );

        eprintln!(
            "suite 0x{:04X}  recovered: epoch {stale_epoch} -> {}, leaf {mine:?}",
            suite.id(),
            resynced.epoch(),
        );
    });
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// A group that has churned, so its occupied leaves are non-contiguous.
/// Returns the group and every agent still in it, founder first.
fn build_churned_group(suite: RineCipherSuite, tag: u8) -> (RineMlsGroup, Vec<TestAgent>) {
    let founder = TestAgent::indexed(0x9000 + tag as u32, suite);
    let (mut group, _) = founder
        .client
        .create_group(&group_id(tag))
        .expect("create group");

    let cohort: Vec<TestAgent> = (0..COHORT)
        .map(|n| TestAgent::indexed(0x6000 + n as u32, suite))
        .collect();

    let key_packages: Vec<Vec<u8>> = cohort
        .iter()
        .map(|agent| agent.client.generate_key_package().expect("key package"))
        .collect();
    group.add_members(&key_packages).expect("add commit");

    for agent in cohort.iter().take(CHURN) {
        let leaf = group.member_index(&agent.identity).expect("seated");
        group.remove_member(leaf).expect("remove commit");
    }

    let mut live = vec![founder];
    live.extend(cohort.into_iter().skip(CHURN));

    (group, live)
}
