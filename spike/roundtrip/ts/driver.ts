// The TypeScript half of the TS<->PY round-trip.
//
// One process, one step, then exit: every step reloads MLS state from disk, so
// nothing is carried between phases in memory and the on-disk state store is
// under test alongside the binding. Usage:
//
//   node driver.ts <step> <agent> [args...]     (env: RINE_ROUNDTRIP_ENV)

import { loadEnv } from "./rine.ts";
import {
	type Ctx,
	externalJoin,
	initGroup,
	publishKeyPackage,
	sync,
	welcomeJoin,
} from "./joining.ts";
import { errorContract, receive, send } from "./messaging.ts";

const [step, agentName, ...rest] = process.argv.slice(2);
if (!step || !agentName) throw new Error("usage: driver.ts <step> <agent> [args]");
const ctx: Ctx = { env: loadEnv(), name: agentName };

const steps: Record<string, (args: string[]) => Promise<void>> = {
	"publish-kp": () => publishKeyPackage(ctx),
	"init-group": (a) => initGroup(ctx, a[0] as string),
	"welcome-join": () => welcomeJoin(ctx),
	"external-join": () => externalJoin(ctx),
	sync: () => sync(ctx),
	send: (a) => send(ctx, a[0] as string),
	recv: (a) => receive(ctx, a[0] as string, a[1] as string),
	"error-contract": () => errorContract(ctx),
};

const run = steps[step];
if (!run) throw new Error(`unknown step ${step}`);
await run(rest);
