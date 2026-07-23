// Data plane, TypeScript side: sending and receiving `mls-v1` group messages,
// plus the typed-error contract observed from JavaScript rather than asserted
// in Rust. py/messaging.py is the same file in the other language.

import {
	agent,
	api,
	b64url,
	decodeEnvelope,
	encodeEnvelope,
	signWithSeed,
	signingKid,
	unb64url,
	verifyEnvelopeSender,
} from "./rine.ts";
import { type Ctx, me, mls, openGroup } from "./joining.ts";

export async function send(ctx: Ctx, text: string): Promise<void> {
  const group = openGroup(ctx);
  const plaintext = new TextEncoder().encode(JSON.stringify({ text }));
  const kid = signingKid(me(ctx));
  const seed = unb64url(agent(ctx.env, ctx.name).seed);
  const envelope = encodeEnvelope(
    kid,
    signWithSeed(seed, plaintext),
    plaintext,
  );
  const payload = group.encryptApplicationMessage(Buffer.from(envelope));
  group.save();

  const message = await api(ctx.env, "POST", "/messages", {
    as: me(ctx),
    body: {
      to_handle: ctx.env.groupHandle,
      type: "rine.v1.dm",
      encrypted_payload: b64url(payload),
      encryption_version: "mls-v1",
      sender_signing_kid: kid,
    },
  });
  console.log(`MESSAGE_ID=${message.id}`);
}

export async function receive(
  ctx: Ctx,
  messageId: string,
  expected: string,
): Promise<void> {
  const inbox = await api(
    ctx.env,
    "GET",
    `/agents/${me(ctx)}/messages?limit=50`,
    {
      as: me(ctx),
    },
  );
  const message = inbox.items.find((m: any) => m.id === messageId);
  if (!message)
    throw new Error(`message ${messageId} is not in ${ctx.name}'s inbox`);
  if (message.encryption_version !== "mls-v1") {
    throw new Error(`expected mls-v1, got ${message.encryption_version}`);
  }

  const group = openGroup(ctx);
  const decrypted = group.decryptApplicationMessage(
    Buffer.from(unb64url(message.encrypted_payload)),
  );
  group.save();

  const envelope = decodeEnvelope(new Uint8Array(decrypted.envelope));
  await verifyEnvelopeSender(ctx.env, envelope, me(ctx));
  if (envelope.kid !== message.sender_signing_kid) {
    throw new Error(
      `envelope kid ${envelope.kid} != header ${message.sender_signing_kid}`,
    );
  }

  const text = JSON.parse(
    new TextDecoder("utf-8", { fatal: true }).decode(envelope.payload),
  ).text;
  if (text !== expected)
    throw new Error(`plaintext mismatch: "${text}" != "${expected}"`);
  console.log(`decrypted exactly: ${text}`);
}

/** The typed-error contract, observed from JavaScript rather than asserted in Rust. */
export async function errorContract(ctx: Ctx): Promise<void> {
  const group = openGroup(ctx);
  const root = ctx.env.stateRoot;
  const suite = ctx.env.cipherSuite;
  const checks: [string, () => unknown][] = [
    [
      "RINE_MLS_UNEXPECTED_VERSION_TAG",
      () => group.decryptApplicationMessage(Buffer.from([0x03, 0x01])),
    ],
    [
      "RINE_MLS_EMPTY_FRAME",
      () => group.decryptApplicationMessage(Buffer.alloc(0)),
    ],
    ["RINE_MLS_UNEXPECTED_BLOB", () => group.applyCommit(group.groupInfo())],
    [
      "RINE_MLS_UNSUPPORTED_CIPHER_SUITE",
      () => mls.MlsClient.open(root, Buffer.alloc(32), 0x004d),
    ],
    [
      "RINE_MLS_INVALID_SIGNING_SEED",
      () => mls.MlsClient.open(root, Buffer.alloc(31), suite),
    ],
  ];

  for (const [code, run] of checks) {
    let thrown: any;
    try {
      run();
    } catch (e) {
      thrown = e;
    }
    if (!thrown) throw new Error(`${code}: expected a throw, got none`);
    if (!(thrown instanceof Error))
      throw new Error(`${code}: threw a non-Error`);
    if (thrown.code !== code)
      throw new Error(`expected code ${code}, got ${thrown.code}`);
  }
  console.log(`${checks.length} typed error codes confirmed from JavaScript`);
}
