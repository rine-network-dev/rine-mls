// What a consumer of the published package does: import it by name, and use it.
//
// Run inside a clean project by `test/package.sh` — there is no source tree, no
// Rust toolchain and no local `.node` file to fall back on here, so anything
// that works works because the package shipped it.

import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const mls = require("@rine-network/mls");

const store = mkdtempSync(join(tmpdir(), "rine-mls-consumer-"));

try {
  // Types ship, and they describe the real surface.
  const types = readFileSync(require.resolve("@rine-network/mls/index.d.ts"), "utf8");
  for (const symbol of ["MlsClient", "MlsGroup", "createGroupWithMembers", "MlsClientOptions"]) {
    assert.ok(types.includes(symbol), `index.d.ts is missing ${symbol}`);
  }

  const suite = mls.CIPHER_SUITE_DEFAULT;
  const alice = mls.MlsClient.open(join(store, "alice"), randomBytes(32), suite);
  const bob = mls.MlsClient.open(join(store, "bob"), randomBytes(32), suite);

  assert.equal(
    typeof alice.panicProbe,
    "undefined",
    "the published addon must not carry the panic probe",
  );

  const groupId = randomBytes(16);
  const group = alice.createGroupWithMembers(groupId, [bob.generateKeyPackage()]);
  const init = group.lastCommit();

  assert.equal(init.epoch, 1);
  assert.equal(init.welcomes.length, 1);

  const joined = bob.joinFromWelcome(init.welcomes[0]);
  const payload = group.encryptApplicationMessage(Buffer.from("packaged and working"));

  assert.equal(payload[0], mls.APP_MESSAGE_TAG);
  assert.equal(
    Buffer.from(joined.decryptApplicationMessage(payload).envelope).toString("utf8"),
    "packaged and working",
  );

  // Typed errors survive packaging too — a code, not a message.
  try {
    alice.generateKeyPackages(mls.KEY_PACKAGE_MAX_BATCH + 1);
    assert.fail("expected a typed refusal");
  } catch (e) {
    assert.equal(e.code, "RINE_MLS_KEY_PACKAGE_BATCH_TOO_LARGE");
  }

  console.log("consumer: post-quantum group founded, joined, message round-tripped");
} finally {
  rmSync(store, { recursive: true, force: true });
}
