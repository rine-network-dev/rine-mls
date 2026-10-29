"""The whole group contract, driven from Python on the post-quantum suite.

This is the surface the Python SDK will call: found a group with its members in
one commit, join by Welcome and by external commit, exchange application
messages, evict a member, persist and reload, retire the state.
"""

from __future__ import annotations

import pytest
import rine_mls
from conftest import DEFAULT_SUITE, SUITES, code_of, group_id


@pytest.mark.parametrize("suite", SUITES)
def test_group_lifecycle_when_driven_from_python_round_trips(make_agent, suite):
    alice, bob, carol, dave = (make_agent(n, suite) for n in ("alice", "bob", "carol", "dave"))
    alice_client, bob_client = alice.open(), bob.open()
    carol_client, dave_client = carol.open(), dave.open()

    # --- founding: one commit, one Welcome per member ------------------------
    gid = group_id()
    alice_group = alice_client.create_group_with_members(
        gid, [bob_client.generate_key_package(), carol_client.generate_key_package()]
    )
    init = alice_group.last_commit()

    assert init.epoch == 1, "founding is one commit whatever the size"
    assert len(init.welcomes) == 2, "one Welcome per founding member"
    assert alice_group.group_id() == gid
    assert alice_group.cipher_suite() == suite
    assert alice_group.is_active() is True

    # welcomes[i] belongs to key_packages[i] — proven by refusing the other's.
    assert code_of(lambda: bob_client.join_from_welcome(init.welcomes[1])) == "RINE_MLS_PROTOCOL", (
        "a member cannot join on another member's Welcome"
    )

    bob_group = bob_client.join_from_welcome(init.welcomes[0])
    carol_group = carol_client.join_from_welcome(init.welcomes[1])

    assert bob_group.epoch() == 1
    assert bob_group.last_commit() is None, "a Welcome joiner mints no commit"
    assert bob_group.cipher_suite() == suite

    # --- data plane, including the sender's own message ----------------------
    hello = alice_group.encrypt_application_message(b"hello group")
    assert hello[0] == rine_mls.APP_MESSAGE_TAG, "mls-v1 payloads carry the 0x04 tag"

    assert bob_group.decrypt_application_message(hello).envelope == b"hello group"
    assert carol_group.decrypt_application_message(hello).envelope == b"hello group"
    assert alice_group.decrypt_application_message(hello).envelope == b"hello group", (
        "a sender reads its own message back through the self-read cache"
    )

    # --- external self-join --------------------------------------------------
    dave_group = dave_client.join_by_external_commit(init.group_info)
    dave_commit = dave_group.last_commit()

    assert dave_commit.epoch == 2
    assert dave_commit.welcomes == [], "an external commit adds nobody"

    for group in (alice_group, bob_group, carol_group):
        assert group.apply_commit(dave_commit.commit) == 2

    from_dave = dave_group.encrypt_application_message(b"dave here")
    assert alice_group.decrypt_application_message(from_dave).envelope == b"dave here"

    # --- eviction ------------------------------------------------------------
    backlog = alice_group.encrypt_application_message(b"last one carol sees")
    removal = alice_group.remove_member(alice_group.member_index(carol_client.agent_id()))

    assert removal.epoch == 3
    assert carol_group.apply_commit(removal.commit) == 2, "an evicted member gets no new epoch"
    assert carol_group.is_active() is False
    assert (
        code_of(lambda: carol_group.encrypt_application_message(b"still here?"))
        == "RINE_MLS_GROUP_INACTIVE"
    )
    assert carol_group.decrypt_application_message(backlog).envelope == b"last one carol sees", (
        "eviction ends participation; it does not unread the backlog"
    )

    for group in (bob_group, dave_group):
        assert group.apply_commit(removal.commit) == 3

    # --- persistence and retirement -----------------------------------------
    alice_group.save()
    assert alice.open().load_group(gid).epoch() == 3

    retiring = alice.open()
    retiring.delete_group_state(gid)
    assert code_of(lambda: retiring.load_group(gid)) == "RINE_MLS_PROTOCOL"
    retiring.delete_group_state(gid)  # deleting what is not there is not an error


def test_add_members_when_batched_pairs_each_welcome_with_its_key_package(make_agent):
    founder = make_agent("founder").open()
    joiners = [make_agent(n).open() for n in ("a", "b", "c")]

    group = founder.create_group(group_id())
    assert group.last_commit().epoch == 1

    bundle = group.add_members([j.generate_key_package() for j in joiners])
    assert len(bundle.welcomes) == 3

    message = group.encrypt_application_message(b"batched")
    for client, welcome in zip(joiners, bundle.welcomes):
        joined = client.join_from_welcome(welcome)
        assert joined.decrypt_application_message(message).envelope == b"batched"


def test_key_package_pool_when_replenished_and_drained_tracks_the_core_policy(make_agent):
    client = make_agent("solo").open()

    assert client.key_package_count() == 0
    assert len(client.replenish_key_packages()) == rine_mls.KEY_PACKAGE_TARGET
    assert client.key_package_count() == rine_mls.KEY_PACKAGE_TARGET
    assert client.replenish_key_packages() == [], "a healthy pool mints nothing"

    fresh = client.drain_and_republish_key_packages()
    assert len(fresh) == rine_mls.KEY_PACKAGE_TARGET
    assert client.key_package_count() == rine_mls.KEY_PACKAGE_TARGET, (
        "the drain replaces the pool rather than adding to it"
    )


def test_constants_when_read_from_the_wheel_match_the_cores_policy():
    assert DEFAULT_SUITE == rine_mls.CIPHER_SUITE_XWING, "new groups are post-quantum"
    assert rine_mls.APP_MESSAGE_TAG == 0x04
    assert rine_mls.KEY_PACKAGE_LOW_WATER < rine_mls.KEY_PACKAGE_TARGET
    assert rine_mls.KEY_PACKAGE_TARGET <= rine_mls.KEY_PACKAGE_MAX_BATCH
    assert rine_mls.SELF_READ_MAX_ENTRIES > 0 and rine_mls.SELF_READ_MAX_BYTES > 0
    assert rine_mls.EPOCH_RETENTION_DEFAULT >= rine_mls.MESSAGE_RETENTION_DAYS, (
        "the epoch window is the server's retention in epochs, so at least a day of it"
    )


# The tree-query and recovery surface the clients are built on: enumerate
# the ratchet tree, learn this handle's own leaf, and rejoin on it.
@pytest.mark.parametrize("suite", SUITES)
def test_tree_enumeration_and_resync_when_driven_from_python_hold(make_agent, suite):
    alice = make_agent("alice", suite).open()
    bob = make_agent("bob", suite).open()
    carol = make_agent("carol", suite).open()

    gid = group_id()
    alice_group = alice.create_group_with_members(
        gid, [bob.generate_key_package(), carol.generate_key_package()]
    )
    init = alice_group.last_commit()
    bob_group = bob.join_from_welcome(init.welcomes[0])
    carol_group = carol.join_from_welcome(init.welcomes[1])

    # --- the tree is enumerable, and every index round-trips -----------------
    tree = alice_group.member_identities()
    assert len(tree) == 3, "every occupied leaf is reported, once"

    for member in tree:
        assert alice_group.member_index(member.identity) == member.index, (
            "an enumerated leaf must be the leaf the identity-keyed lookup names"
        )

    assert sorted(m.identity for m in tree) == sorted(
        c.agent_id() for c in (alice, bob, carol)
    ), "the identities are the members' public keys"

    for group, client in ((alice_group, alice), (bob_group, bob)):
        assert group.current_member_index() == group.member_index(client.agent_id()), (
            "a handle must agree with itself about which leaf it occupies"
        )

    # --- recovery: the plain join is refused, the resync is not --------------
    stale_leaf = bob_group.current_member_index()

    assert code_of(lambda: bob.join_by_external_commit(alice_group.group_info())) == (
        "RINE_MLS_PROTOCOL"
    ), "a seated agent cannot take a second leaf, so the plain join is not a resync"

    resynced = bob.resync_by_external_commit(alice_group.group_info(), stale_leaf)
    commit = resynced.last_commit()

    assert commit.welcomes == [], "a resync admits nobody"
    assert alice_group.apply_commit(commit.commit) == 2
    assert carol_group.apply_commit(commit.commit) == 2, "a bystander applies it too"

    after = resynced.member_identities()
    assert len(after) == len(tree), "a resync does not change the membership count"
    assert [m.index for m in after if m.identity == bob.agent_id()] == [
        resynced.current_member_index()
    ], "the stale leaf is replaced, not doubled"

    hello = alice_group.encrypt_application_message(b"welcome back")
    assert resynced.decrypt_application_message(hello).envelope == b"welcome back"


# Both ends of the one seam every binding passes epoch retention through: an
# unset limit is the shipped window, and zero is refused rather than silently
# accepted.
def test_epoch_retention_when_configured_takes_the_shipped_window_or_refuses(make_agent):
    make_agent("unset").open().create_group(group_id())
    make_agent("tuned", epoch_retention_limit=2).open()

    assert code_of(lambda: make_agent("broken", epoch_retention_limit=0).open()) == (
        "RINE_MLS_INVALID_EPOCH_RETENTION"
    )
