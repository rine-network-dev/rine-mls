"""The panic firewall, proven by a real panic rather than by a Rust unit test.

A Rust unwind reaching CPython is undefined behaviour and would take the process
down, so the core wraps every call in a ``PanicGuard``. That guard has always
been unit-tested in Rust; what was never shown is that a genuine panic inside a
genuine extension call comes back to Python as an ordinary exception, and that
the handle is retired afterwards. ``MlsClient.panic_probe`` exists to force
exactly that, and is compiled only under the ``panic-probe`` feature.

Run with ``RINE_MLS_EXPECT_PROBE=1`` (what ``tests/run.sh`` does) to require the
probe build; without it these skip, so the same tests can run against a wheel
that must not carry the probe.
"""

from __future__ import annotations

import pytest
import rine_mls
from conftest import DEFAULT_SUITE, code_of, group_id, probe_expected

pytestmark = pytest.mark.skipif(
    not probe_expected(), reason="wheel built without the panic-probe feature"
)


def test_panic_probe_when_the_build_should_carry_it_is_present(make_agent):
    assert hasattr(make_agent("prober").open(), "panic_probe")


def test_panic_when_it_crosses_the_boundary_arrives_as_a_typed_exception(make_agent):
    prober = make_agent("prober").open()

    with pytest.raises(rine_mls.MlsPanicError) as caught:
        prober.panic_probe()

    assert isinstance(caught.value, rine_mls.RineMlsError)
    assert "panic probe" in str(caught.value), "the message keeps the panic's own detail"


def test_handle_when_a_previous_call_panicked_refuses_every_later_call(make_agent):
    prober = make_agent("prober").open()
    assert prober.cipher_suite() == DEFAULT_SUITE

    assert code_of(prober.panic_probe) == "RINE_MLS_PANIC"

    # State half-mutated by an unwind is not state to keep using.
    with pytest.raises(rine_mls.MlsPoisonedError):
        prober.generate_key_package()
    with pytest.raises(rine_mls.MlsPoisonedError):
        prober.create_group(group_id())


def test_poisoning_when_it_happens_is_scoped_to_the_handle_that_panicked(make_agent):
    alice = make_agent("alice")

    poisoned = alice.open()
    group = poisoned.create_group(group_id())
    assert code_of(poisoned.panic_probe) == "RINE_MLS_PANIC"

    assert group.encrypt_application_message(b"still fine")[0] == rine_mls.APP_MESSAGE_TAG, (
        "a group handle is poisoned by its own panics, not by its client's"
    )

    assert code_of(group.panic_probe) == "RINE_MLS_PANIC"
    assert code_of(group.epoch) == "RINE_MLS_POISONED"
    assert alice.open().cipher_suite() == DEFAULT_SUITE, "a fresh client is unaffected"


def test_process_when_a_panic_was_caught_is_still_healthy(make_agent):
    prober = make_agent("prober").open()
    for i in range(5):
        assert code_of(prober.panic_probe) == ("RINE_MLS_PANIC" if i == 0 else "RINE_MLS_POISONED")

    group = make_agent("fresh").open().create_group(group_id())
    assert group.last_commit().epoch == 1, "MLS still works after the unwind was caught"
