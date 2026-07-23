// Concurrency, which rine's CLI and stream paths can plausibly reach.
//
// Two questions, answered rather than assumed:
//
//   1. Can one handle be used from two threads? No — and the runtime says so:
//      a napi class instance is not structured-cloneable, so `postMessage`
//      refuses it. MLS state stays on the thread that owns it.
//   2. What happens when two clients share one store root? The KeyPackage store
//      survives it (per-file atomic writes, and a count that adds up). Group
//      state does not: the two handles fork, and the fork is silent locally
//      until a message fails to decrypt. That is pinned here so it cannot change
//      without someone noticing, and it is why both binding classes document
//      one client per store root.

import { test } from "node:test";
import assert from "node:assert/strict";
import { Worker } from "node:worker_threads";
import { join } from "node:path";
import { randomBytes } from "node:crypto";

import { agent, codeOf, envelope, groupId, mls, workspace } from "./helpers.mjs";

const SUITE = mls.CIPHER_SUITE_DEFAULT;
const WORKER = new URL("./worker.mjs", import.meta.url);

function runWorker(workerData) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(WORKER, { workerData });
    worker.once("message", resolve);
    worker.once("error", reject);
  });
}

test("test_addon_when_loaded_in_several_worker_threads_runs_mls_in_each", async () => {
  const root = workspace();
  const jobs = ["w0", "w1", "w2"].map((name) =>
    runWorker({
      job: "found",
      storeRoot: join(root, name),
      seed: [...randomBytes(32)],
      suite: SUITE,
      groupId: [...groupId()],
    }),
  );

  for (const result of await Promise.all(jobs)) {
    assert.equal(result.ok, true);
    assert.equal(result.epoch, 1);
    assert.equal(result.payload[0], mls.APP_MESSAGE_TAG);
  }
});

test("test_handle_when_sent_across_threads_arrives_without_its_state", async () => {
  const root = workspace();
  const result = await runWorker({
    job: "postHandle",
    storeRoot: join(root, "poster"),
    seed: [...randomBytes(32)],
    suite: SUITE,
  });

  assert.equal(result.ok, true);
  assert.equal(result.hadMethodHere, true, "the handle worked on the thread that owned it");
  assert.equal(
    typeof result.clone.cipherSuite,
    "undefined",
    "structured clone drops the prototype and the native state — the copy is inert",
  );
  assert.equal(result.clone instanceof mls.MlsClient, false);
});

test("test_key_package_store_when_minted_from_several_threads_stays_countable", async () => {
  const root = workspace();
  const shared = agent(root, "shared", SUITE);
  const perThread = 4;
  const threads = 4;

  const results = await Promise.all(
    Array.from({ length: threads }, () =>
      runWorker({
        job: "mintKeyPackages",
        storeRoot: shared.storeRoot,
        seed: [...shared.seed],
        suite: SUITE,
        count: perThread,
      }),
    ),
  );

  assert.deepEqual(
    results.map((r) => r.minted),
    Array.from({ length: threads }, () => perThread),
  );
  assert.equal(
    shared.open().keyPackageCount(),
    threads * perThread,
    "every private half landed; nothing was lost to a torn write",
  );
});

test("test_group_state_when_two_clients_share_one_store_root_forks_rather_than_merging", () => {
  const root = workspace();
  const shared = agent(root, "shared", SUITE);
  const bob = agent(root, "bob", SUITE).open();
  const carol = agent(root, "carol", SUITE).open();

  const gid = groupId();
  const first = shared.open();
  const firstGroup = first.createGroupWithMembers(gid, [bob.generateKeyPackage()]);
  firstGroup.save();

  // Founding the same group twice is at least refused outright.
  assert.equal(codeOf(() => shared.open().createGroup(gid)), "RINE_MLS_PROTOCOL");

  // Loading it twice is not. Both handles commit, and they commit different
  // things at the same epoch: a fork, with the last `save()` winning on disk.
  const secondGroup = shared.open().loadGroup(gid);
  const fromFirst = firstGroup.addMember(carol.generateKeyPackage());
  const fromSecond = secondGroup.addMember(carol.generateKeyPackage());

  assert.equal(fromFirst.epoch, fromSecond.epoch);
  assert.notDeepEqual([...fromFirst.commit], [...fromSecond.commit]);

  secondGroup.save();
  const survivor = shared.open().loadGroup(gid);
  const strandedMessage = firstGroup.encryptApplicationMessage(envelope("from the losing fork"));

  assert.equal(
    codeOf(() => survivor.decryptApplicationMessage(strandedMessage)),
    "RINE_MLS_PROTOCOL",
    "the fork surfaces as an undecryptable message, not as a torn state file",
  );
});
