// Shared fixtures for the addon's tests.
//
// Everything here drives the addon exactly as `rine-core` will: real store
// directories on disk, real Ed25519 seeds, real MLS blobs. The one thing left
// out is the transport — base64url and HTTP belong above this layer.

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

export const mls = require("../index.js");

/** Both suites rine speaks, so no test only proves the classical path. */
export const SUITES = [
  ["classical", mls.CIPHER_SUITE_CLASSICAL],
  ["post-quantum", mls.CIPHER_SUITE_XWING],
];

const workspaces = [];

/** A throwaway directory tree, removed when the process exits. */
export function workspace() {
  const root = mkdtempSync(join(tmpdir(), "rine-mls-node-"));
  workspaces.push(root);
  return root;
}

process.on("exit", () => {
  for (const root of workspaces) {
    rmSync(root, { recursive: true, force: true });
  }
});

/**
 * One agent: its own store root under `parent`, its own identity seed.
 * `open` takes the client fresh each time, which is how a restarted process
 * reaches its state.
 */
export function agent(parent, name, cipherSuite, options) {
  const storeRoot = join(parent, name);
  const seed = randomBytes(32);

  return {
    name,
    storeRoot,
    seed,
    open: () => mls.MlsClient.open(storeRoot, seed, cipherSuite, options),
  };
}

export function groupId() {
  return randomBytes(16);
}

export function envelope(text) {
  return Buffer.from(text, "utf8");
}

export function text(bytes) {
  return Buffer.from(bytes).toString("utf8");
}

/** The `code` of a thrown error, or a description of why there wasn't one. */
export function codeOf(fn) {
  try {
    fn();
  } catch (e) {
    return e.code;
  }
  return "<no error thrown>";
}
