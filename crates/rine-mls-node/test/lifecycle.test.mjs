// The whole group contract, driven from JavaScript on both ciphersuites.
//
// This is the surface `rine-core` will call: found a group with its members in
// one commit, join by Welcome and by external commit, exchange application
// messages, evict a member, persist and reload, retire the state.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  SUITES,
  agent,
  codeOf,
  envelope,
  groupId,
  mls,
  text,
  workspace,
} from "./helpers.mjs";

for (const [suiteName, suite] of SUITES) {
  test(`test_group_lifecycle_when_driven_from_javascript_${suiteName}_round_trips`, () => {
    const root = workspace();
    const alice = agent(root, "alice", suite);
    const bob = agent(root, "bob", suite);
    const carol = agent(root, "carol", suite);
    const dave = agent(root, "dave", suite);

    const aliceClient = alice.open();
    const bobClient = bob.open();
    const carolClient = carol.open();
    const daveClient = dave.open();

    // --- founding: one commit, one Welcome per member ---------------------
    const gid = groupId();
    const bobKp = bobClient.generateKeyPackage();
    const carolKp = carolClient.generateKeyPackage();

    const aliceGroup = aliceClient.createGroupWithMembers(gid, [bobKp, carolKp]);
    const init = aliceGroup.lastCommit();

    assert.equal(init.epoch, 1, "founding is one commit whatever the size");
    assert.equal(init.welcomes.length, 2, "one Welcome per founding member");
    assert.deepEqual([...aliceGroup.groupId()], [...gid]);
    assert.equal(aliceGroup.cipherSuite(), suite);
    assert.equal(aliceGroup.isActive(), true);

    // welcomes[i] belongs to keyPackages[i] — proven by refusing the other's.
    assert.equal(
      codeOf(() => bobClient.joinFromWelcome(init.welcomes[1])),
      "RINE_MLS_PROTOCOL",
      "a member cannot join on another member's Welcome",
    );

    const bobGroup = bobClient.joinFromWelcome(init.welcomes[0]);
    const carolGroup = carolClient.joinFromWelcome(init.welcomes[1]);

    assert.equal(bobGroup.epoch(), 1);
    assert.equal(bobGroup.lastCommit(), null, "a Welcome joiner mints no commit");
    assert.equal(bobGroup.cipherSuite(), suite);

    // --- data plane, including the sender's own message --------------------
    const hello = aliceGroup.encryptApplicationMessage(envelope("hello group"));
    assert.equal(hello[0], mls.APP_MESSAGE_TAG, "mls-v1 payloads carry the 0x04 tag");

    assert.equal(text(bobGroup.decryptApplicationMessage(hello).envelope), "hello group");
    assert.equal(text(carolGroup.decryptApplicationMessage(hello).envelope), "hello group");
    assert.equal(
      text(aliceGroup.decryptApplicationMessage(hello).envelope),
      "hello group",
      "a sender reads its own message back through the self-read cache",
    );

    // --- external self-join -----------------------------------------------
    const daveGroup = daveClient.joinByExternalCommit(init.groupInfo);
    const daveCommit = daveGroup.lastCommit();

    assert.equal(daveCommit.epoch, 2);
    assert.equal(daveCommit.welcomes.length, 0, "an external commit adds nobody");

    for (const group of [aliceGroup, bobGroup, carolGroup]) {
      assert.equal(group.applyCommit(daveCommit.commit), 2);
    }

    const fromDave = daveGroup.encryptApplicationMessage(envelope("dave here"));
    assert.equal(text(aliceGroup.decryptApplicationMessage(fromDave).envelope), "dave here");

    // --- eviction ----------------------------------------------------------
    const backlog = aliceGroup.encryptApplicationMessage(envelope("last one carol sees"));
    const removal = aliceGroup.removeMember(aliceGroup.memberIndex(carolClient.publicKey()));

    assert.equal(removal.epoch, 3);
    assert.equal(carolGroup.applyCommit(removal.commit), 2, "an evicted member gets no new epoch");
    assert.equal(carolGroup.isActive(), false);
    assert.equal(
      codeOf(() => carolGroup.encryptApplicationMessage(envelope("still here?"))),
      "RINE_MLS_GROUP_INACTIVE",
    );
    assert.equal(
      text(carolGroup.decryptApplicationMessage(backlog).envelope),
      "last one carol sees",
      "eviction ends participation; it does not unread the backlog",
    );

    for (const group of [bobGroup, daveGroup]) {
      assert.equal(group.applyCommit(removal.commit), 3);
    }

    // --- persistence and retirement ---------------------------------------
    aliceGroup.save();
    const reopened = alice.open().loadGroup(gid);
    assert.equal(reopened.epoch(), 3);

    const retiring = alice.open();
    retiring.deleteGroupState(gid);
    assert.equal(codeOf(() => retiring.loadGroup(gid)), "RINE_MLS_PROTOCOL");
    retiring.deleteGroupState(gid); // deleting what is not there is not an error
  });
}

test("test_add_members_when_batched_pairs_each_welcome_with_its_key_package", () => {
  const root = workspace();
  const suite = mls.CIPHER_SUITE_DEFAULT;
  const founder = agent(root, "founder", suite).open();
  const joiners = ["a", "b", "c"].map((n) => agent(root, n, suite).open());

  const gid = groupId();
  const group = founder.createGroup(gid);
  assert.equal(group.lastCommit().epoch, 1);

  const bundle = group.addMembers(joiners.map((j) => j.generateKeyPackage()));
  assert.equal(bundle.welcomes.length, 3);

  const message = group.encryptApplicationMessage(envelope("batched"));
  joiners.forEach((client, i) => {
    const joined = client.joinFromWelcome(bundle.welcomes[i]);
    assert.equal(text(joined.decryptApplicationMessage(message).envelope), "batched");
  });
});

test("test_key_package_pool_when_replenished_and_drained_tracks_the_core_policy", () => {
  const root = workspace();
  const client = agent(root, "solo", mls.CIPHER_SUITE_DEFAULT).open();

  assert.equal(client.keyPackageCount(), 0);
  assert.equal(
    client.replenishKeyPackages().length,
    mls.KEY_PACKAGE_TARGET,
    "an empty pool refills to the target",
  );
  assert.equal(client.keyPackageCount(), mls.KEY_PACKAGE_TARGET);
  assert.equal(client.replenishKeyPackages().length, 0, "a healthy pool mints nothing");

  const fresh = client.drainAndRepublishKeyPackages();
  assert.equal(fresh.length, mls.KEY_PACKAGE_TARGET);
  assert.equal(
    client.keyPackageCount(),
    mls.KEY_PACKAGE_TARGET,
    "the drain replaces the pool rather than adding to it",
  );
});

test("test_constants_when_read_from_the_addon_match_the_cores_policy", () => {
  assert.equal(mls.CIPHER_SUITE_DEFAULT, mls.CIPHER_SUITE_XWING, "new groups are post-quantum");
  assert.equal(mls.APP_MESSAGE_TAG, 0x04);
  assert.ok(mls.KEY_PACKAGE_LOW_WATER < mls.KEY_PACKAGE_TARGET);
  assert.ok(mls.KEY_PACKAGE_TARGET <= mls.KEY_PACKAGE_MAX_BATCH);
  assert.ok(mls.SELF_READ_MAX_ENTRIES > 0 && mls.SELF_READ_MAX_BYTES > 0);
});
