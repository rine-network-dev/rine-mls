// Transport for the TypeScript half of the round-trip: the rine HTTP calls, the
// two base64 alphabets the protocol uses, and the signed inner envelope.
//
// This restates the `mls-v1` envelope codec that `rine-core/src/crypto` already
// owns, because the spike must not depend on the stack it exists to validate —
// and because the Python half has to state it too, which is the interop claim
// being tested. The real integration calls rine-core, not this file.

import { readFileSync } from "node:fs";
import { createPrivateKey, createPublicKey, sign, verify } from "node:crypto";

export interface AgentEnv {
  id: string;
  seed: string; // base64url of the 32-byte Ed25519 private key, as rine stores it
}

export interface RoundtripEnv {
  apiUrl: string;
  token: string;
  groupId: string;
  groupHandle: string;
  cipherSuite: number;
  stateRoot: string;
  agents: Record<string, AgentEnv>;
}

export function loadEnv(): RoundtripEnv {
  const path = process.env.RINE_ROUNDTRIP_ENV;
  if (!path) throw new Error("RINE_ROUNDTRIP_ENV is not set");
  return JSON.parse(readFileSync(path, "utf-8")) as RoundtripEnv;
}

export function agent(env: RoundtripEnv, name: string): AgentEnv {
  const found = env.agents[name];
  if (!found) throw new Error(`unknown agent ${name}`);
  return found;
}

// MLS control-plane blobs travel as standard base64; only the application
// message's encrypted_payload is base64url.
export const b64 = (b: Uint8Array): string => Buffer.from(b).toString("base64");
export const unb64 = (s: string): Uint8Array =>
  new Uint8Array(Buffer.from(s, "base64"));
export const b64url = (b: Uint8Array): string =>
  Buffer.from(b).toString("base64url");
export const unb64url = (s: string): Uint8Array =>
  new Uint8Array(Buffer.from(s, "base64url"));

/** The rine group UUID's 16 raw bytes — what the MLS group id is set to. */
export function groupIdBytes(uuid: string): Uint8Array {
  return new Uint8Array(Buffer.from(uuid.replace(/-/g, ""), "hex"));
}

/** An HTTP failure with the status attached, so callers branch on 409 etc. */
export class ApiError extends Error {
	readonly status: number;

	constructor(method: string, path: string, status: number, detail: string) {
		super(`${method} ${path} -> ${status} ${detail}`);
		this.name = "ApiError";
		this.status = status;
	}
}

export async function api(
  env: RoundtripEnv,
  method: string,
  path: string,
  opts: { as?: string; body?: unknown } = {},
): Promise<any> {
  const headers: Record<string, string> = {
    Authorization: `Bearer ${env.token}`,
  };
  if (opts.as) headers["X-Rine-Agent"] = opts.as;
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";

  const res = await fetch(`${env.apiUrl}${path}`, {
    method,
    headers,
    body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
  });
  const text = await res.text();
  if (!res.ok) throw new ApiError(method, path, res.status, text);
  return text ? JSON.parse(text) : null;
}

// --- the signed inner rine envelope: kidLen || kid || sig(64) || plaintext ---

const ED25519_PKCS8_PREFIX = Buffer.from(
  "302e020100300506032b657004220420",
  "hex",
);
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export function signingKid(agentId: string): string {
  return `rine:${agentId}`;
}

export function agentIdFromKid(kid: string): string {
  if (!kid.startsWith("rine:")) throw new Error(`bad kid ${kid}`);
  return kid.slice("rine:".length);
}

export function signWithSeed(seed: Uint8Array, data: Uint8Array): Uint8Array {
  const key = createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(seed)]),
    format: "der",
    type: "pkcs8",
  });
  return new Uint8Array(sign(null, Buffer.from(data), key));
}

export function verifyWithPublicKey(
  publicKey: Uint8Array,
  data: Uint8Array,
  signature: Uint8Array,
): boolean {
  const key = createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(publicKey)]),
    format: "der",
    type: "spki",
  });
  return verify(null, Buffer.from(data), key, Buffer.from(signature));
}

export function encodeEnvelope(
  kid: string,
  signature: Uint8Array,
  payload: Uint8Array,
): Uint8Array {
  const kidBytes = Buffer.from(kid, "utf-8");
  const out = new Uint8Array(1 + kidBytes.length + 64 + payload.length);
  out[0] = kidBytes.length;
  out.set(kidBytes, 1);
  out.set(signature, 1 + kidBytes.length);
  out.set(payload, 1 + kidBytes.length + 64);
  return out;
}

export interface InnerEnvelope {
  kid: string;
  signature: Uint8Array;
  payload: Uint8Array;
}

export function decodeEnvelope(data: Uint8Array): InnerEnvelope {
  const kidLen = data[0] as number;
  return {
    kid: Buffer.from(data.subarray(1, 1 + kidLen)).toString("utf-8"),
    signature: data.slice(1 + kidLen, 1 + kidLen + 64),
    payload: data.slice(1 + kidLen + 64),
  };
}

/** Fetch the sender's PUBLISHED Ed25519 key and check the envelope signature. */
export async function verifyEnvelopeSender(
  env: RoundtripEnv,
  envelope: InnerEnvelope,
  as: string,
): Promise<void> {
  const senderId = agentIdFromKid(envelope.kid);
  const keys = await api(env, "GET", `/agents/${senderId}/keys`, { as });
  const publicKey = unb64url(keys.signing_public_key.x as string);
  if (!verifyWithPublicKey(publicKey, envelope.payload, envelope.signature)) {
    throw new Error(`inner envelope signature failed for ${envelope.kid}`);
  }
}
