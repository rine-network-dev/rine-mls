"""Moving a member's own leaf to a new key from Python: the pending commit, its
apply and its drop, the keys the tree and a KeyPackage report, and the generation
the allowed set now records."""

from __future__ import annotations

import secrets
from types import SimpleNamespace

import pytest
import rine_mls
from conftest import ALLOWED, DEFAULT_SUITE, SUITES, code_of, group_id


@pytest.fixture
def rotating_pair(make_agent, workspace):
    """Alice founds a group with Bob; her next seed's key is admitted at generation 1."""

    def build(suite):
        alice, bob = make_agent("alice", suite), make_agent("bob", suite)
        alice_client, bob_client = alice.open(), bob.open()

        next_seed = secrets.token_bytes(32)
        next_client = rine_mls.MlsClient(
            str(workspace / "next"), alice.agent_id, next_seed, ALLOWED, suite
        )
        next_key = next_client.leaf_public_key()
        ALLOWED.insert(alice.agent_id, next_key, 1)

        gid = group_id()
        alice_group = alice_client.create_group_with_members(
            gid, [bob_client.generate_key_package()]
        )
        bob_group = bob_client.join_from_welcome(alice_group.last_commit().welcomes[0])
        return SimpleNamespace(
            alice=alice,
            alice_client=alice_client,
            alice_group=alice_group,
            bob_group=bob_group,
            next_seed=next_seed,
            next_key=next_key,
            gid=gid,
        )

    return build


@pytest.mark.parametrize("suite", SUITES)
def test_self_update_when_applied_moves_the_leaf_for_both_members(rotating_pair, suite):
    pair = rotating_pair(suite)
    before = pair.alice_group.own_leaf_signature_key()
    assert before == pair.alice_client.leaf_public_key()
    assert pair.alice_group.pending_commit_epoch() is None

    bundle = pair.alice_group.commit_update(pair.next_seed)

    assert bundle.welcomes == [], "an update admits nobody"
    assert pair.alice_group.pending_commit_epoch() == 2
    assert pair.alice_group.epoch() == 1, "nothing moves until the commit is applied"
    assert pair.alice_group.own_leaf_signature_key() == before

    assert pair.alice_group.apply_pending_commit() == 2
    assert pair.alice_group.pending_commit_epoch() is None
    assert pair.bob_group.apply_commit(bundle.commit) == 2

    for group in (pair.alice_group, pair.bob_group):
        seat = next(
            m for m in group.member_identities() if m.identity == pair.alice.agent_id
        )
        assert seat.signature_key == pair.next_key

    hello = pair.alice_group.encrypt_application_message(b"moved")
    assert pair.bob_group.decrypt_application_message(hello).envelope == b"moved"


@pytest.mark.parametrize("suite", SUITES)
def test_self_update_when_cleared_restores_the_handle(rotating_pair, suite):
    pair = rotating_pair(suite)
    bundle = pair.alice_group.commit_update(pair.next_seed)

    assert code_of(lambda: pair.alice_group.add_member(pair.alice_client.generate_key_package())) == (
        "RINE_MLS_COMMIT_PENDING"
    )
    assert code_of(lambda: pair.alice_group.commit_update(pair.next_seed)) == "RINE_MLS_COMMIT_PENDING"

    pair.alice_group.clear_pending_commit()

    assert pair.alice_group.pending_commit_epoch() is None
    assert code_of(pair.alice_group.apply_pending_commit) == "RINE_MLS_NO_PENDING_COMMIT"
    assert pair.alice_group.own_leaf_signature_key() == pair.alice_client.leaf_public_key()
    assert pair.bob_group.apply_commit(bundle.commit) == 2, "the dropped commit never reached the server"


@pytest.mark.parametrize("suite", SUITES)
def test_self_update_when_saved_while_pending_is_still_pending_after_reload(rotating_pair, suite):
    pair = rotating_pair(suite)
    pair.alice_group.commit_update(pair.next_seed)
    pair.alice_group.save()

    reloaded = pair.alice.open().load_group(pair.gid)

    assert reloaded.pending_commit_epoch() == 2
    assert reloaded.apply_pending_commit() == 2


@pytest.mark.parametrize("suite", SUITES)
def test_self_update_when_the_seed_is_the_current_one_is_refused(rotating_pair, suite):
    pair = rotating_pair(suite)

    assert code_of(lambda: pair.alice_group.commit_update(pair.alice.seed)) == "RINE_MLS_LEAF_ALREADY_CURRENT"


def test_key_package_signature_key_when_read_is_the_clients_leaf_key(make_agent):
    client = make_agent("carol", DEFAULT_SUITE).open()

    assert rine_mls.key_package_signature_key(client.generate_key_package()) == client.leaf_public_key()


def test_allowed_insert_when_a_pair_is_recorded_at_another_generation_is_refused():
    allowed = rine_mls.AllowedIdentities()
    agent_id, key = secrets.token_bytes(16), secrets.token_bytes(32)

    allowed.insert(agent_id, key, 3)
    allowed.insert(agent_id, key, 3)

    assert code_of(lambda: allowed.insert(agent_id, key, 4)) == "RINE_MLS_ALLOWED_GENERATION_CONFLICT"
    assert issubclass(rine_mls.ResyncChangesKeyError, rine_mls.MlsProtocolError)
