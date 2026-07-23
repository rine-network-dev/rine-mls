"""The Python half of the TS<->PY round-trip.

One process, one step, then exit: every step reloads MLS state from disk, so
nothing is carried between phases in memory and the on-disk state store is under
test alongside the binding. Usage::

    python driver.py <step> <agent> [args...]     (env: RINE_ROUNDTRIP_ENV)
"""

from __future__ import annotations

import sys

import joining
import messaging
from rine_transport import Env

step_name, agent_name, *rest = sys.argv[1:]
ctx = joining.Ctx(Env(), agent_name)

STEPS = {
    "publish-kp": lambda args: joining.publish_key_package(ctx),
    "init-group": lambda args: joining.init_group(ctx, args[0]),
    "welcome-join": lambda args: joining.welcome_join(ctx),
    "external-join": lambda args: joining.external_join(ctx),
    "sync": lambda args: joining.sync(ctx),
    "send": lambda args: messaging.send(ctx, args[0]),
    "recv": lambda args: messaging.receive(ctx, args[0], args[1]),
    "error-contract": lambda args: messaging.error_contract(ctx),
}

STEPS[step_name](rest)
