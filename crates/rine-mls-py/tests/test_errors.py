"""Every failure a Python caller can provoke raises its own exception class.

The point is not that the extension rejects bad input — it is that a caller can
``except`` the *specific* failure, and that the class carries the same
``RINE_MLS_*`` wire code the JavaScript side sees, so the two bindings name one
failure identically.
"""

from __future__ import annotations

import secrets

import pytest
import rine_mls
from conftest import DEFAULT_SUITE, code_of, group_id


def test_open_when_the_arguments_are_wrong_names_which_argument(workspace):
    seed = secrets.token_bytes(32)

    with pytest.raises(rine_mls.UnsupportedCipherSuiteError):
        rine_mls.MlsClient(str(workspace / "a"), seed, 0x1234)

    with pytest.raises(rine_mls.InvalidSigningSeedError):
        rine_mls.MlsClient(str(workspace / "b"), secrets.token_bytes(16), DEFAULT_SUITE)

    with pytest.raises(rine_mls.InvalidEpochRetentionError):
        rine_mls.MlsClient(str(workspace / "c"), seed, DEFAULT_SUITE, epoch_retention_limit=0)


def test_open_when_epoch_retention_is_a_real_limit_is_accepted(make_agent):
    client = make_agent("tight", epoch_retention_limit=2).open()

    assert client.cipher_suite() == DEFAULT_SUITE


def test_key_package_batch_when_over_the_cap_is_refused_not_truncated(make_agent):
    client = make_agent("greedy").open()

    with pytest.raises(rine_mls.KeyPackageBatchTooLargeError):
        client.generate_key_packages(rine_mls.KEY_PACKAGE_MAX_BATCH + 1)

    assert client.key_package_count() == 0, "a refused batch mints nothing"


def test_blobs_when_of_the_wrong_kind_or_suite_are_refused_by_name(make_agent):
    alice = make_agent("alice").open()
    bob = make_agent("bob").open()
    classical = make_agent("classical", rine_mls.CIPHER_SUITE_CLASSICAL).open()

    group = alice.create_group(group_id())
    key_package = bob.generate_key_package()

    with pytest.raises(rine_mls.UnexpectedBlobError):
        alice.join_from_welcome(key_package)

    with pytest.raises(rine_mls.CipherSuiteMismatchError):
        group.add_member(classical.generate_key_package())

    # A bare RFC 9420 KeyPackage — what a pre-cutover client publishes.
    with pytest.raises(rine_mls.UnreadableKeyPackageError):
        group.add_member(key_package[4:])


def test_application_payloads_when_malformed_name_the_framing_problem(make_agent):
    group = make_agent("alice").open().create_group(group_id())

    with pytest.raises(rine_mls.EmptyFrameError):
        group.decrypt_application_message(b"")

    # An hpke-hybrid-v1 DM mis-routed to the group path.
    with pytest.raises(rine_mls.UnexpectedVersionTagError):
        group.decrypt_application_message(b"\x03\x01\x02")

    with pytest.raises(rine_mls.MlsProtocolError):
        group.decrypt_application_message(bytes([rine_mls.APP_MESSAGE_TAG, 0xFF, 0xFF]))


def test_apply_commit_when_replayed_refuses_on_the_epoch_cas(make_agent):
    alice, bob, carol = (make_agent(n).open() for n in ("alice", "bob", "carol"))

    alice_group = alice.create_group_with_members(group_id(), [bob.generate_key_package()])
    bob_group = bob.join_from_welcome(alice_group.last_commit().welcomes[0])

    commit = alice_group.add_member(carol.generate_key_package()).commit
    assert bob_group.apply_commit(commit) == 2

    with pytest.raises(rine_mls.EpochConflictError):
        bob_group.apply_commit(commit)


def test_self_read_when_the_message_has_aged_out_says_so_by_name(make_agent):
    group = make_agent("alice").open().create_group(group_id())

    first = group.encrypt_application_message(b"the oldest message")
    for i in range(rine_mls.SELF_READ_MAX_ENTRIES + 1):
        group.encrypt_application_message(f"filler {i}".encode())

    # The cache is bounded, and a miss is not dressed up as a key problem.
    with pytest.raises(rine_mls.SelfMessageNotCachedError):
        group.decrypt_application_message(first)


def test_store_failures_when_the_directory_is_unreadable_are_typed_as_store(workspace):
    store_root = workspace / "locked"
    (store_root / "key_packages").mkdir(parents=True)

    client = rine_mls.MlsClient(str(store_root), secrets.token_bytes(32), DEFAULT_SUITE)
    client.generate_key_package()

    (store_root / "key_packages").chmod(0o000)
    try:
        with pytest.raises(rine_mls.MlsStoreError):
            client.key_package_count()
    finally:
        (store_root / "key_packages").chmod(0o700)


def test_exception_classes_when_inspected_share_one_base_and_distinct_codes(workspace):
    classes = [
        rine_mls.UnsupportedCipherSuiteError,
        rine_mls.InvalidSigningSeedError,
        rine_mls.InvalidEpochRetentionError,
        rine_mls.EpochConflictError,
        rine_mls.GroupInactiveError,
        rine_mls.SelfMessageNotCachedError,
        rine_mls.UnreadableKeyPackageError,
        rine_mls.CipherSuiteMismatchError,
        rine_mls.KeyPackageBatchTooLargeError,
    ]

    codes = {cls.code for cls in classes}
    assert len(codes) == len(classes), "one class per failure, not one class for all"
    for cls in classes:
        assert issubclass(cls, rine_mls.RineMlsError)
        assert cls.code.startswith("RINE_MLS_")

    # `except RineMlsError` catches everything, which is what a caller that only
    # wants to know "MLS said no" should be able to write.
    assert (
        code_of(lambda: rine_mls.MlsClient(str(workspace / "x"), b"short", DEFAULT_SUITE))
        == "RINE_MLS_INVALID_SIGNING_SEED"
    )
