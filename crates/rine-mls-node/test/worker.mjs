// The worker half of `concurrency.test.mjs`: load the addon in a fresh thread
// and run one job on it. Each worker is its own napi module instance, which is
// exactly what the test is there to prove is safe.

import { parentPort, workerData } from "node:worker_threads";

import { mls } from "./helpers.mjs";

const { job, storeRoot, agentId, seed, suite, groupId, count } = workerData;
const allowed = new mls.AllowedIdentities();
const client = mls.MlsClient.open(
  storeRoot,
  Buffer.from(agentId),
  Buffer.from(seed),
  allowed,
  suite,
);
allowed.insert(client.agentId(), client.leafPublicKey(), 0);

const jobs = {
  // Found a group and send one message — a whole MLS flow off the main thread.
  found() {
    const group = client.createGroup(Buffer.from(groupId));
    const payload = group.encryptApplicationMessage(Buffer.from("from a worker"));
    group.save();

    return { epoch: group.lastCommit().epoch, payload: [...payload] };
  },

  // Mint into a KeyPackage store several threads are writing to at once.
  mintKeyPackages() {
    return { minted: client.generateKeyPackages(count).length };
  },

  // Try to send a live handle back. Structured clone keeps neither the
  // prototype nor the native state, so what the parent receives is a hollow
  // object — MLS state cannot leave the thread that owns it.
  postHandle() {
    return { clone: client, hadMethodHere: typeof client.cipherSuite === "function" };
  },
};

try {
  parentPort.postMessage({ ok: true, ...jobs[job]() });
} catch (e) {
  parentPort.postMessage({ ok: false, name: e.constructor.name, code: e.code });
}
