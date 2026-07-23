// The panic firewall, proven by a real panic rather than by a Rust unit test.
//
// A Rust unwind reaching V8 is undefined behaviour and would take the process
// down, so the core wraps every call in a `PanicGuard`. That guard has always
// been unit-tested in Rust; what was never shown is that a genuine panic inside
// a genuine addon call comes back to JavaScript as an ordinary typed error, and
// that the handle is retired afterwards. `MlsClient.panicProbe` exists to force
// exactly that, and is compiled only under the `panic-probe` feature.
//
// Run with RINE_MLS_EXPECT_PROBE=1 (what `test/run.sh` does) to require the
// probe build; without it the suite skips, so the same tests can run against a
// package build that must not carry the probe.

import { test, describe } from "node:test";
import assert from "node:assert/strict";

import { agent, codeOf, envelope, groupId, mls, workspace } from "./helpers.mjs";

const SUITE = mls.CIPHER_SUITE_DEFAULT;
const expected = process.env.RINE_MLS_EXPECT_PROBE === "1";
const client = () => agent(workspace(), "prober", SUITE).open();

test("test_panic_probe_when_the_build_should_carry_it_is_present", () => {
  const present = typeof client().panicProbe === "function";

  if (expected) {
    assert.equal(present, true, "RINE_MLS_EXPECT_PROBE=1 but this build has no probe");
  } else {
    assert.equal(present, false, "a default build must not ship a way to panic on purpose");
  }
});

describe("panic firewall", { skip: expected ? false : "built without panic-probe" }, () => {
  test("test_panic_when_it_crosses_the_boundary_arrives_as_a_typed_error", () => {
    const prober = client();
    let thrown;

    try {
      prober.panicProbe();
    } catch (e) {
      thrown = e;
    }

    assert.ok(thrown instanceof Error, "a panic must arrive as an Error, not as a crash");
    assert.equal(thrown.code, "RINE_MLS_PANIC");
    assert.match(thrown.message, /panic probe/, "the message keeps the panic's own detail");
  });

  test("test_handle_when_a_previous_call_panicked_refuses_every_later_call", () => {
    const prober = client();
    assert.equal(prober.cipherSuite(), SUITE);

    assert.equal(codeOf(() => prober.panicProbe()), "RINE_MLS_PANIC");
    assert.equal(
      codeOf(() => prober.generateKeyPackage()),
      "RINE_MLS_POISONED",
      "state half-mutated by an unwind is not state to keep using",
    );
    assert.equal(codeOf(() => prober.createGroup(groupId())), "RINE_MLS_POISONED");
  });

  test("test_poisoning_when_it_happens_is_scoped_to_the_handle_that_panicked", () => {
    const parent = workspace();
    const alice = agent(parent, "alice", SUITE);

    const poisoned = alice.open();
    const group = poisoned.createGroup(groupId());
    assert.equal(codeOf(() => poisoned.panicProbe()), "RINE_MLS_PANIC");

    assert.equal(
      group.encryptApplicationMessage(envelope("still fine"))[0],
      mls.APP_MESSAGE_TAG,
      "a group handle is poisoned by its own panics, not by its client's",
    );
    assert.equal(codeOf(() => group.panicProbe()), "RINE_MLS_PANIC");
    assert.equal(codeOf(() => group.epoch()), "RINE_MLS_POISONED");

    assert.equal(alice.open().cipherSuite(), SUITE, "a fresh client is unaffected");
  });

  test("test_process_when_a_panic_was_caught_is_still_healthy", () => {
    const prober = client();
    for (let i = 0; i < 5; i += 1) {
      assert.equal(codeOf(() => prober.panicProbe()), i === 0 ? "RINE_MLS_PANIC" : "RINE_MLS_POISONED");
    }

    const fresh = client();
    const group = fresh.createGroup(groupId());
    assert.equal(group.lastCommit().epoch, 1, "MLS still works after the unwind was caught");
  });
});
