// Every failure a JavaScript caller can provoke arrives as a real `Error` whose
// `code` is a stable `RINE_MLS_*` string.
//
// The point is not that the addon rejects bad input — it is that a caller can
// *branch* on which rejection it was, without parsing a message. So every case
// here asserts the code, and the suite asserts the codes are distinct.

import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";

import { agent, codeOf, envelope, groupId, mls, workspace } from "./helpers.mjs";

const SUITE = mls.CIPHER_SUITE_DEFAULT;

test("test_open_when_the_arguments_are_wrong_names_which_argument", () => {
  const root = workspace();
  const seed = randomBytes(32);
  const id = Buffer.from("agent");
  const set = new mls.AllowedIdentities();

  assert.equal(
    codeOf(() => mls.MlsClient.open(join(root, "a"), id, seed, set, 0x1234)),
    "RINE_MLS_UNSUPPORTED_CIPHER_SUITE",
  );
  assert.equal(
    codeOf(() => mls.MlsClient.open(join(root, "a"), id, seed, set, 0x0001)),
    "RINE_MLS_UNSUPPORTED_CIPHER_SUITE",
    "the classical suite is refused",
  );
  assert.equal(
    codeOf(() => mls.MlsClient.open(join(root, "b"), id, randomBytes(16), set, SUITE)),
    "RINE_MLS_INVALID_SIGNING_SEED",
  );
  assert.equal(
    codeOf(() => mls.MlsClient.open(join(root, "b"), Buffer.alloc(0), seed, set, SUITE)),
    "RINE_MLS_EMPTY_AGENT_ID",
  );
  assert.equal(
    codeOf(() =>
      mls.MlsClient.open(join(root, "c"), id, seed, set, SUITE, { epochRetentionLimit: 0 }),
    ),
    "RINE_MLS_INVALID_EPOCH_RETENTION",
    "keeping zero prior epochs is a broken group, not a tighter one",
  );
});

test("test_open_when_epoch_retention_is_a_real_limit_is_accepted", () => {
  const root = workspace();
  const client = agent(root, "tight", SUITE, { epochRetentionLimit: 2 }).open();

  assert.equal(client.cipherSuite(), SUITE);
});

test("test_key_package_batch_when_over_the_cap_is_refused_not_truncated", () => {
  const root = workspace();
  const client = agent(root, "greedy", SUITE).open();

  assert.equal(
    codeOf(() => client.generateKeyPackages(mls.KEY_PACKAGE_MAX_BATCH + 1)),
    "RINE_MLS_KEY_PACKAGE_BATCH_TOO_LARGE",
  );
  assert.equal(client.keyPackageCount(), 0, "a refused batch mints nothing");
});

test("test_blobs_when_of_the_wrong_kind_or_suite_are_refused_by_name", () => {
  const root = workspace();
  const alice = agent(root, "alice", SUITE).open();
  const bob = agent(root, "bob", SUITE).open();

  const group = alice.createGroup(groupId());
  const keyPackage = bob.generateKeyPackage();

  assert.equal(
    codeOf(() => alice.joinFromWelcome(keyPackage)),
    "RINE_MLS_UNEXPECTED_BLOB",
    "a KeyPackage offered where a Welcome belongs",
  );
  assert.equal(
    codeOf(() => group.addMember(keyPackage.slice(4))),
    "RINE_MLS_UNREADABLE_KEY_PACKAGE",
    "a bare RFC 9420 KeyPackage — what a pre-cutover client publishes",
  );
});

test("test_application_payloads_when_malformed_name_the_framing_problem", () => {
  const root = workspace();
  const alice = agent(root, "alice", SUITE).open();
  const group = alice.createGroup(groupId());

  assert.equal(codeOf(() => group.decryptApplicationMessage(new Uint8Array(0))), "RINE_MLS_EMPTY_FRAME");
  assert.equal(
    codeOf(() => group.decryptApplicationMessage(Uint8Array.from([0x03, 0x01, 0x02]))),
    "RINE_MLS_UNEXPECTED_VERSION_TAG",
    "an hpke-hybrid-v1 DM mis-routed to the group path",
  );
  assert.equal(
    codeOf(() => group.decryptApplicationMessage(Uint8Array.from([mls.APP_MESSAGE_TAG, 0xff, 0xff]))),
    "RINE_MLS_PROTOCOL",
  );
});

test("test_apply_commit_when_replayed_refuses_on_the_epoch_cas", () => {
  const root = workspace();
  const alice = agent(root, "alice", SUITE).open();
  const bob = agent(root, "bob", SUITE).open();
  const carol = agent(root, "carol", SUITE).open();

  const gid = groupId();
  const aliceGroup = alice.createGroupWithMembers(gid, [bob.generateKeyPackage()]);
  const bobGroup = bob.joinFromWelcome(aliceGroup.lastCommit().welcomes[0]);

  const commit = aliceGroup.addMember(carol.generateKeyPackage()).commit;
  assert.equal(bobGroup.applyCommit(commit), 2);
  assert.equal(codeOf(() => bobGroup.applyCommit(commit)), "RINE_MLS_EPOCH_CONFLICT");
});

test("test_self_read_when_the_message_has_aged_out_says_so_by_name", () => {
  const root = workspace();
  const alice = agent(root, "alice", SUITE).open();
  const group = alice.createGroup(groupId());

  const first = group.encryptApplicationMessage(envelope("the oldest message"));
  for (let i = 0; i <= mls.SELF_READ_MAX_ENTRIES; i += 1) {
    group.encryptApplicationMessage(envelope(`filler ${i}`));
  }

  assert.equal(
    codeOf(() => group.decryptApplicationMessage(first)),
    "RINE_MLS_SELF_MESSAGE_NOT_CACHED",
    "the cache is bounded, and a miss is not dressed up as a key problem",
  );
});

test("test_store_failures_when_the_directory_is_unreadable_are_typed_as_store", () => {
  const root = workspace();
  const storeRoot = join(root, "locked");
  mkdirSync(join(storeRoot, "key_packages"), { recursive: true });

  const client = mls.MlsClient.open(
    storeRoot,
    Buffer.from("locked"),
    randomBytes(32),
    new mls.AllowedIdentities(),
    SUITE,
  );
  client.generateKeyPackage();

  chmodSync(join(storeRoot, "key_packages"), 0o000);
  try {
    assert.equal(codeOf(() => client.keyPackageCount()), "RINE_MLS_STORE");
  } finally {
    chmodSync(join(storeRoot, "key_packages"), 0o700);
  }
});

test("test_error_codes_when_collected_are_distinct_and_prefixed", () => {
  const root = workspace();
  const seed = randomBytes(32);
  const id = Buffer.from("agent");
  const set = new mls.AllowedIdentities();
  const codes = [
    codeOf(() => mls.MlsClient.open(join(root, "x"), id, seed, set, 0x1234)),
    codeOf(() => mls.MlsClient.open(join(root, "y"), id, randomBytes(1), set, SUITE)),
    codeOf(() =>
      mls.MlsClient.open(join(root, "z"), id, seed, set, SUITE, { epochRetentionLimit: 0 }),
    ),
  ];

  assert.equal(new Set(codes).size, codes.length, "one code per failure, not one code for all");
  for (const code of codes) {
    assert.match(code, /^RINE_MLS_[A-Z_]+$/);
  }
});
