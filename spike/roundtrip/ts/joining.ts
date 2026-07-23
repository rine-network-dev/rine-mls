// Control plane, TypeScript side: publishing a KeyPackage, creating the group,
// the two join paths, and applying handshakes. py/joining.py plays the same
// roles, so run.sh can swap which language creates the group and which one
// joins it — the claim is one core behind every surface, not one blessed
// direction.
//
// Everything here also exports the shared handles (Ctx, openClient, openGroup)
// the data-plane module needs.

import { createRequire } from "node:module";
import {
  ApiError,
  agent,
  api,
  b64,
  b64url,
  decodeEnvelope,
  encodeEnvelope,
  groupIdBytes,
  type RoundtripEnv,
  signWithSeed,
  signingKid,
  unb64,
  unb64url,
  verifyEnvelopeSender,
} from "./rine.ts";

const require = createRequire(import.meta.url);
export const mls = require(process.env.RINE_MLS_NODE_ADDON as string);

export interface Ctx {
  env: RoundtripEnv;
  name: string;
}

export const openClient = (ctx: Ctx) =>
  mls.MlsClient.open(
    `${ctx.env.stateRoot}/${ctx.name}`,
    Buffer.from(unb64url(agent(ctx.env, ctx.name).seed)),
    ctx.env.cipherSuite,
  );

export const openGroup = (ctx: Ctx) =>
  openClient(ctx).loadGroup(Buffer.from(groupIdBytes(ctx.env.groupId)));

export const me = (ctx: Ctx) => agent(ctx.env, ctx.name).id;

/** POST a commit bundle exactly as `POST /groups/{id}/mls/commit` wants it. */
async function postCommit(
  ctx: Ctx,
  bundle: any,
  extra: { welcomeFor?: string; isInit?: boolean } = {},
): Promise<void> {
  const body: Record<string, unknown> = {
    commit: b64(bundle.commit),
    group_info: b64(bundle.groupInfo),
    epoch: bundle.epoch,
  };
  if (extra.welcomeFor) {
    body.welcomes = bundle.welcomes.map((w: Uint8Array) => ({
      agent_id: extra.welcomeFor,
      welcome: b64(w),
    }));
  }
  if (extra.isInit) body.cipher_suite = ctx.env.cipherSuite;

  await api(ctx.env, "POST", `/groups/${ctx.env.groupId}/mls/commit`, {
    as: me(ctx),
    body,
  });
}

/**
 * Empty this agent's KeyPackage pool, then publish exactly one of ours.
 *
 * Onboarding already stocked the pool with ts-mls KeyPackages, and the server
 * cannot tell those apart from rine-mls ones — it stores opaque blobs. Claiming
 * blind would hand the adder a KeyPackage from the other stack.
 */
export async function publishKeyPackage(ctx: Ctx): Promise<void> {
  let drained = 0;
  for (;;) {
    try {
      const res = await api(
        ctx.env,
        "GET",
        `/agents/${me(ctx)}/mls/key-packages?count=100`,
        { as: me(ctx) },
      );
      drained += res.packages.length;
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) break;
      throw e;
    }
  }

  const blob = openClient(ctx).generateKeyPackage();
  await api(ctx.env, "POST", `/agents/${me(ctx)}/mls/key-packages`, {
    as: me(ctx),
    body: { packages: [b64(blob)] },
  });
  console.log(`drained ${drained} foreign key package(s), published 1`);
}

/** Create the MLS group, add one member by Welcome, and post the init commit. */
export async function initGroup(ctx: Ctx, peerName: string): Promise<void> {
  const peer = agent(ctx.env, peerName);
  await api(ctx.env, "POST", `/groups/${ctx.env.groupId}/mls/init`, {
    as: me(ctx),
  });

  const claim = await api(
    ctx.env,
    "GET",
    `/agents/${peer.id}/mls/key-packages?count=1`,
    { as: me(ctx) },
  );

  const group = openClient(ctx).createGroup(
    Buffer.from(groupIdBytes(ctx.env.groupId)),
  );
  const add = group.addMember(Buffer.from(unb64(claim.packages[0])));

  await postCommit(ctx, add, { welcomeFor: peer.id, isInit: true });
  group.save();
  console.log(`init commit posted at epoch ${add.epoch}`);
}

/** Consume the one-shot Welcome fetch and persist before it can be lost. */
export async function welcomeJoin(ctx: Ctx): Promise<void> {
  const res = await api(ctx.env, "GET", `/agents/${me(ctx)}/mls/welcomes`, {
    as: me(ctx),
  });
  if (res.welcomes.length !== 1) {
    throw new Error(`expected exactly one welcome, got ${res.welcomes.length}`);
  }

  const group = openClient(ctx).joinFromWelcome(
    Buffer.from(unb64(res.welcomes[0].blob)),
  );
  if (group.lastCommit() !== null)
    throw new Error("a Welcome joiner mints no commit");
  group.save();
  console.log(`joined by Welcome at epoch ${group.epoch()}`);
}

/** RFC 9420 external commit: no Welcome, no action by any existing member. */
export async function externalJoin(ctx: Ctx): Promise<void> {
  const info = await api(
    ctx.env,
    "GET",
    `/groups/${ctx.env.groupId}/mls/group-info`,
    {
      as: me(ctx),
    },
  );
  const group = openClient(ctx).joinByExternalCommit(
    Buffer.from(unb64(info.group_info)),
  );

  const bundle = group.lastCommit();
  if (bundle.welcomes.length !== 0)
    throw new Error("an external commit adds nobody");
  await postCommit(ctx, bundle);
  group.save();
  console.log(`self-joined by external commit at epoch ${group.epoch()}`);
}

export async function sync(ctx: Ctx): Promise<void> {
  const group = openGroup(ctx);
  const res = await api(
    ctx.env,
    "GET",
    `/groups/${ctx.env.groupId}/mls/handshakes?since_epoch=${group.epoch() + 1}`,
    { as: me(ctx) },
  );

  for (const handshake of res.handshakes) {
    group.applyCommit(Buffer.from(unb64(handshake.blob)));
  }
  group.save();
  console.log(
    `applied ${res.handshakes.length} handshake(s), now at epoch ${group.epoch()}`,
  );
}
