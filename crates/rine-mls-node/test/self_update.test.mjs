// Moving a member's own leaf to a new key from JavaScript: the pending commit, its
// apply and its drop, the keys the tree and a KeyPackage report, and the generation
// the allowed set now records.

import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { join } from "node:path";

import { SUITES, agent, allowed, codeOf, envelope, groupId, mls, text, workspace } from "./helpers.mjs";

/** Alice founds a group with Bob, and her next seed's key is admitted at generation 1. */
function rotatingPair(suite) {
  const root = workspace();
  const alice = agent(root, "alice", suite);
  const bob = agent(root, "bob", suite);
  const aliceClient = alice.open();
  const bobClient = bob.open();

  const nextSeed = randomBytes(32);
  const nextKey = mls.MlsClient.open(join(root, "next"), alice.agentId, nextSeed, allowed, suite)
    .leafPublicKey();
  allowed.insert(alice.agentId, nextKey, 1);

  const gid = groupId();
  const aliceGroup = aliceClient.createGroupWithMembers(gid, [bobClient.generateKeyPackage()]);
  const bobGroup = bobClient.joinFromWelcome(aliceGroup.lastCommit().welcomes[0]);

  return { alice, aliceClient, aliceGroup, bobGroup, nextSeed, nextKey, gid };
}

for (const [suiteName, suite] of SUITES) {
  test(`test_self_update_when_applied_moves_the_leaf_for_both_members_${suiteName}`, () => {
    const { aliceClient, aliceGroup, bobGroup, nextSeed, nextKey } = rotatingPair(suite);
    const before = aliceGroup.ownLeafSignatureKey();
    assert.deepEqual(Buffer.from(before), Buffer.from(aliceClient.leafPublicKey()));
    assert.equal(aliceGroup.pendingCommitEpoch(), null);

    const bundle = aliceGroup.commitUpdate(nextSeed);

    assert.equal(bundle.welcomes.length, 0, "an update admits nobody");
    assert.equal(aliceGroup.pendingCommitEpoch(), 2);
    assert.equal(aliceGroup.epoch(), 1, "nothing moves until the commit is applied");
    assert.deepEqual(Buffer.from(aliceGroup.ownLeafSignatureKey()), Buffer.from(before));

    assert.equal(aliceGroup.applyPendingCommit(), 2);
    assert.equal(aliceGroup.pendingCommitEpoch(), null);
    assert.equal(bobGroup.applyCommit(bundle.commit), 2);

    for (const group of [aliceGroup, bobGroup]) {
      const seat = group
        .memberIdentities()
        .find((m) => Buffer.compare(Buffer.from(m.identity), Buffer.from(aliceClient.agentId())) === 0);
      assert.deepEqual(Buffer.from(seat.signatureKey), Buffer.from(nextKey));
    }

    const hello = aliceGroup.encryptApplicationMessage(envelope("moved"));
    assert.equal(text(bobGroup.decryptApplicationMessage(hello).envelope), "moved");
  });

  test(`test_self_update_when_cleared_restores_the_handle_${suiteName}`, () => {
    const { aliceClient, aliceGroup, bobGroup, nextSeed } = rotatingPair(suite);
    const bundle = aliceGroup.commitUpdate(nextSeed);

    assert.equal(
      codeOf(() => aliceGroup.addMember(aliceClient.generateKeyPackage())),
      "RINE_MLS_COMMIT_PENDING",
    );
    assert.equal(codeOf(() => aliceGroup.commitUpdate(nextSeed)), "RINE_MLS_COMMIT_PENDING");

    aliceGroup.clearPendingCommit();

    assert.equal(aliceGroup.pendingCommitEpoch(), null);
    assert.equal(codeOf(() => aliceGroup.applyPendingCommit()), "RINE_MLS_NO_PENDING_COMMIT");
    assert.deepEqual(Buffer.from(aliceGroup.ownLeafSignatureKey()), Buffer.from(aliceClient.leafPublicKey()));
    assert.equal(bobGroup.applyCommit(bundle.commit), 2, "the dropped commit never reached the server");
  });

  test(`test_self_update_when_saved_while_pending_is_still_pending_after_reload_${suiteName}`, () => {
    const { alice, aliceGroup, nextSeed, gid } = rotatingPair(suite);
    aliceGroup.commitUpdate(nextSeed);
    aliceGroup.save();

    const reloaded = alice.open().loadGroup(gid);

    assert.equal(reloaded.pendingCommitEpoch(), 2);
    assert.equal(reloaded.applyPendingCommit(), 2);
  });

  test(`test_self_update_when_the_seed_is_the_current_one_is_refused_${suiteName}`, () => {
    const { alice, aliceGroup } = rotatingPair(suite);

    assert.equal(codeOf(() => aliceGroup.commitUpdate(alice.seed)), "RINE_MLS_LEAF_ALREADY_CURRENT");
  });
}

test("test_key_package_signature_key_when_read_is_the_clients_leaf_key", () => {
  const client = agent(workspace(), "carol", SUITES[0][1]).open();

  assert.deepEqual(
    Buffer.from(mls.keyPackageSignatureKey(client.generateKeyPackage())),
    Buffer.from(client.leafPublicKey()),
  );
});

test("test_allowed_insert_when_a_pair_is_recorded_at_another_generation_is_refused", () => {
  const set = new mls.AllowedIdentities();
  const [id, key] = [randomBytes(16), randomBytes(32)];

  set.insert(id, key, 3);
  set.insert(id, key, 3);

  assert.equal(codeOf(() => set.insert(id, key, 4)), "RINE_MLS_ALLOWED_GENERATION_CONFLICT");
});
