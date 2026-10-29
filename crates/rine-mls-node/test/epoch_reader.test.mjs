// The org reader's path: an `EpochReader` built from an escrow export opens the
// application messages of that epoch, as a party that was never a member.
//
// Mirrors the core's `tests/epoch_reader.rs` through the real addon, so the
// binding's byte copies, `i64` epoch and error codes are exercised end to end.
// `RINE_MLS_GENERATION_TOO_FAR` needs a forged ciphertext 65k generations ahead (the
// core test seals one by hand), so it is proved there; this binding only maps the code.

import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

import { agent, codeOf, envelope, groupId, mls, text, workspace } from "./helpers.mjs";

const SUITE = mls.CIPHER_SUITE_DEFAULT;

/** Drop the leading `mls-v1` version tag, as the TS caller does before `open`. */
const untagged = (payload) => payload.subarray(1);

/** Alice founds a group with Bob: both hold epoch 1, and Alice's export is taken. */
function pair() {
  const root = workspace();
  const alice = agent(root, "alice", SUITE).open();
  const bob = agent(root, "bob", SUITE).open();
  const id = groupId();

  const aliceGroup = alice.createGroupWithMembers(id, [bob.generateKeyPackage()]);
  const bobGroup = bob.joinFromWelcome(aliceGroup.lastCommit().welcomes[0]);
  const { exports, gaps } = aliceGroup.takeEscrowExports();

  assert.deepEqual(gaps, []);
  return { id, alice, bob, aliceGroup, bobGroup, escrow: exports.find((e) => e.epoch === 1) };
}

/** Offset of the leaf signature key table: 71 fixed bytes, the context, its two length words. */
function leafTable(plaintext) {
  const contextLen = Buffer.from(plaintext).readUInt32BE(71);
  return 79 + contextLen;
}

/** Swap the signature keys recorded for two leaves, as a forged escrow would. */
function swapLeafKeys(plaintext, a, b) {
  const doctored = Buffer.from(plaintext);
  const entry = (leaf) => leafTable(doctored) + leaf * 36 + 4;
  const keyA = Buffer.from(doctored.subarray(entry(a), entry(a) + 32));
  doctored.copy(doctored, entry(a), entry(b), entry(b) + 32);
  keyA.copy(doctored, entry(b));
  return doctored;
}

test("test_epoch_reader_when_built_from_an_export_opens_a_members_message", () => {
  const { id, bob, bobGroup, escrow } = pair();
  const payload = bobGroup.encryptApplicationMessage(envelope("what bob said"));

  const reader = mls.EpochReader.fromEscrow(id, escrow.epoch, escrow.plaintext);
  const opened = reader.open(untagged(payload));

  assert.equal(text(opened.envelope), "what bob said");
  assert.equal(opened.senderIndex, bobGroup.currentMemberIndex());
  assert.equal(opened.generation, 0);
  assert.deepEqual(
    Buffer.from(opened.signerPublicKey),
    Buffer.from(bob.leafPublicKey()),
    "the signer key is the one the escrow records for the sender's leaf",
  );
});

test("test_epoch_reader_when_messages_arrive_out_of_order_opens_all_of_them", () => {
  const { id, bobGroup, escrow } = pair();
  const sent = [0, 1, 2].map((n) => bobGroup.encryptApplicationMessage(envelope(`bob ${n}`)));
  const reader = mls.EpochReader.fromEscrow(id, escrow.epoch, escrow.plaintext);

  for (const n of [2, 0, 1]) {
    const opened = reader.open(untagged(sent[n]));
    assert.equal(text(opened.envelope), `bob ${n}`);
    assert.equal(opened.generation, n);
  }
});

test("test_epoch_reader_when_the_message_is_from_another_epoch_refuses_it", () => {
  const { id, aliceGroup, bobGroup, escrow } = pair();
  const carol = agent(workspace(), "carol", SUITE).open();
  const add = aliceGroup.addMember(carol.generateKeyPackage());
  bobGroup.applyCommit(add.commit);
  const payload = bobGroup.encryptApplicationMessage(envelope("epoch two"));

  const stale = mls.EpochReader.fromEscrow(id, escrow.epoch, escrow.plaintext);
  assert.throws(() => stale.open(untagged(payload)), (e) => e.code === "RINE_MLS_PROTOCOL");

  const { exports } = aliceGroup.takeEscrowExports();
  const two = exports.find((e) => e.epoch === 2);
  const current = mls.EpochReader.fromEscrow(id, two.epoch, two.plaintext);
  assert.equal(text(current.open(untagged(payload)).envelope), "epoch two");
});

test("test_epoch_reader_when_the_slot_is_not_the_escrows_refuses_it_as_invalid_escrow", () => {
  const { id, escrow } = pair();
  const build = (group, epoch) => () => mls.EpochReader.fromEscrow(group, epoch, escrow.plaintext);

  assert.equal(codeOf(build(id, escrow.epoch + 1)), "RINE_MLS_INVALID_ESCROW", "another epoch");
  assert.equal(codeOf(build(randomBytes(16), escrow.epoch)), "RINE_MLS_INVALID_ESCROW", "another group");
  assert.equal(codeOf(build(id, -1)), "RINE_MLS_INVALID_ESCROW", "a negative epoch");
  assert.equal(codeOf(build(id, escrow.epoch + 0.9)), "RINE_MLS_INVALID_ESCROW", "a fractional epoch");
  assert.equal(codeOf(build(id, Number.NaN)), "RINE_MLS_INVALID_ESCROW", "NaN");
  assert.equal(codeOf(build(id, 2 ** 53)), "RINE_MLS_INVALID_ESCROW", "beyond the safe-integer range");

  const truncated = escrow.plaintext.subarray(0, escrow.plaintext.length - 1);
  assert.equal(
    codeOf(() => mls.EpochReader.fromEscrow(id, escrow.epoch, truncated)),
    "RINE_MLS_INVALID_ESCROW",
    "a cut-short plaintext",
  );
});

test("test_epoch_reader_when_leaf_keys_are_swapped_rejects_the_sender", () => {
  const { id, aliceGroup, bobGroup, escrow } = pair();
  const doctored = swapLeafKeys(escrow.plaintext, 0, 1);
  const bobs = bobGroup.encryptApplicationMessage(envelope("bob"));
  const alices = aliceGroup.encryptApplicationMessage(envelope("alice"));
  const reader = mls.EpochReader.fromEscrow(id, escrow.epoch, doctored);

  assert.equal(codeOf(() => reader.open(untagged(bobs))), "RINE_MLS_MEMBER_REJECTED");
  assert.equal(codeOf(() => reader.open(untagged(alices))), "RINE_MLS_MEMBER_REJECTED");
});

test("test_epoch_reader_when_given_bytes_that_are_not_a_message_throws_a_typed_error", () => {
  const { id, escrow } = pair();
  const reader = mls.EpochReader.fromEscrow(id, escrow.epoch, escrow.plaintext);

  assert.match(codeOf(() => reader.open(randomBytes(40))), /^RINE_MLS_/);
});
