"""Concurrency, which rine's Python surfaces can plausibly reach.

Two questions, answered rather than assumed:

1. Can one handle be used from two threads? Yes — every call holds the GIL, so a
   handle is never mutated by two threads at once. Boring, and worth pinning.
2. What happens when two clients share one store root? The KeyPackage store
   survives it (per-file atomic writes, and a count that adds up), across
   threads and across *processes*. Group state does not: the two handles fork,
   and the fork is silent locally until a message fails to decrypt. That is
   pinned here so it cannot change without someone noticing, and it is why
   ``MlsClient`` documents one client per store root.

The napi binding's ``test/concurrency.test.mjs`` asserts the same two things, so
a divergence between the languages shows up as a failing test on one side.
"""

from __future__ import annotations

import secrets
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor

import rine_mls
from conftest import DEFAULT_SUITE, code_of, group_id

PER_WORKER = 4
WORKERS = 4


def _mint(args: tuple[str, bytes, bytes, int, int]) -> int:
    """Mint KeyPackages into a store root several workers are writing to."""
    store_root, agent_id, seed, suite, count = args
    client = rine_mls.MlsClient(store_root, agent_id, seed, rine_mls.AllowedIdentities(), suite)
    return len(client.generate_key_packages(count))


def test_handle_when_used_from_several_threads_stays_consistent(make_agent):
    alice = make_agent("alice").open()
    group = alice.create_group(group_id())

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        payloads = list(
            pool.map(group.encrypt_application_message, [b"threaded %d" % i for i in range(16)])
        )

    assert len({bytes(p) for p in payloads}) == len(payloads), "no ratchet step was reused"
    assert group.epoch() == 1


def test_key_package_store_when_minted_from_several_threads_stays_countable(make_agent):
    shared = make_agent("shared")
    job = (str(shared.store_root), shared.agent_id, shared.seed, shared.cipher_suite, PER_WORKER)

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        minted = list(pool.map(_mint, [job] * WORKERS))

    assert minted == [PER_WORKER] * WORKERS
    assert shared.open().key_package_count() == WORKERS * PER_WORKER


def test_key_package_store_when_minted_from_several_processes_stays_countable(make_agent):
    shared = make_agent("shared")
    job = (str(shared.store_root), shared.agent_id, shared.seed, shared.cipher_suite, PER_WORKER)

    with ProcessPoolExecutor(max_workers=WORKERS) as pool:
        minted = list(pool.map(_mint, [job] * WORKERS))

    assert minted == [PER_WORKER] * WORKERS
    assert shared.open().key_package_count() == WORKERS * PER_WORKER, (
        "every private half landed; nothing was lost to a torn write"
    )


def test_group_state_when_two_clients_share_one_store_root_forks_rather_than_merging(make_agent):
    shared = make_agent("shared")
    bob = make_agent("bob").open()
    carol = make_agent("carol").open()

    gid = group_id()
    first_group = shared.open().create_group_with_members(gid, [bob.generate_key_package()])
    first_group.save()

    # Founding the same group twice is at least refused outright.
    assert code_of(lambda: shared.open().create_group(gid)) == "RINE_MLS_PROTOCOL"

    # Loading it twice is not. Both handles commit, and they commit different
    # things at the same epoch: a fork, with the last save() winning on disk.
    second_group = shared.open().load_group(gid)
    from_first = first_group.add_member(carol.generate_key_package())
    from_second = second_group.add_member(carol.generate_key_package())

    assert from_first.epoch == from_second.epoch
    assert from_first.commit != from_second.commit

    second_group.save()
    survivor = shared.open().load_group(gid)
    stranded = first_group.encrypt_application_message(b"from the losing fork")

    assert code_of(lambda: survivor.decrypt_application_message(stranded)) == "RINE_MLS_PROTOCOL", (
        "the fork surfaces as an undecryptable message, not as a torn state file"
    )


def test_seed_when_copied_into_rust_is_not_the_callers_buffer(make_agent):
    """The client keeps its own zeroizing copy — a caller may clear its own."""
    seed = bytearray(secrets.token_bytes(32))
    client = rine_mls.MlsClient(
        str(make_agent("wipe").store_root),
        b"wipe",
        bytes(seed),
        rine_mls.AllowedIdentities(),
        DEFAULT_SUITE,
    )
    leaf_public_key = client.leaf_public_key()

    seed[:] = bytes(32)
    assert client.leaf_public_key() == leaf_public_key
