"""Control plane, Python side.

Publishing a KeyPackage, creating the group, the two join paths, and applying
handshakes. ``ts/joining.ts`` plays the same roles, so run.sh can swap which
language creates the group and which one joins it — the claim is one core behind
every surface, not one blessed direction.

This module also owns :class:`Ctx`, the per-agent handle the data plane uses.
"""

from __future__ import annotations

import rine_mls
from rine_transport import (
    ApiError,
    Env,
    b64,
    group_id_bytes,
    unb64,
)


class Ctx:
    """One agent's view of the round-trip: who it is and where its state lives."""

    def __init__(self, env: Env, name: str) -> None:
        self.env = env
        self.name = name
        self.agent = env.agent(name)

    def client(self) -> rine_mls.MlsClient:
        return rine_mls.MlsClient(
            f"{self.env.state_root}/{self.name}", self.agent.seed, self.env.cipher_suite
        )

    def group(self) -> rine_mls.MlsGroup:
        return self.client().load_group(group_id_bytes(self.env.group_id))


def post_commit(
    ctx: Ctx,
    bundle: rine_mls.CommitBundle,
    *,
    welcome_for: str | None = None,
    is_init: bool = False,
) -> None:
    """POST a commit bundle exactly as ``POST /groups/{id}/mls/commit`` wants it."""
    body: dict[str, object] = {
        "commit": b64(bundle.commit),
        "group_info": b64(bundle.group_info),
        "epoch": bundle.epoch,
    }
    if welcome_for:
        body["welcomes"] = [
            {"agent_id": welcome_for, "welcome": b64(w)} for w in bundle.welcomes
        ]
    if is_init:
        body["cipher_suite"] = ctx.env.cipher_suite

    ctx.env.api(
        "POST", f"/groups/{ctx.env.group_id}/mls/commit", acting_as=ctx.agent.id, body=body
    )


def publish_key_package(ctx: Ctx) -> None:
    """Empty this agent's KeyPackage pool, then publish exactly one of ours.

    Onboarding already stocked the pool with ts-mls KeyPackages, and the server
    cannot tell those apart from rine-mls ones — it stores opaque blobs.
    Claiming blind would hand the adder a KeyPackage from the other stack.
    """
    drained = 0
    while True:
        try:
            claim = ctx.env.api(
                "GET",
                f"/agents/{ctx.agent.id}/mls/key-packages?count=100",
                acting_as=ctx.agent.id,
            )
        except ApiError as exc:
            if exc.status == 409:
                break
            raise
        drained += len(claim["packages"])

    blob = ctx.client().generate_key_package()
    ctx.env.api(
        "POST",
        f"/agents/{ctx.agent.id}/mls/key-packages",
        acting_as=ctx.agent.id,
        body={"packages": [b64(blob)]},
    )
    print(f"drained {drained} foreign key package(s), published 1")


def init_group(ctx: Ctx, peer_name: str) -> None:
    """Create the MLS group, add one member by Welcome, and post the init commit."""
    peer = ctx.env.agent(peer_name)
    ctx.env.api("POST", f"/groups/{ctx.env.group_id}/mls/init", acting_as=ctx.agent.id)

    claim = ctx.env.api(
        "GET", f"/agents/{peer.id}/mls/key-packages?count=1", acting_as=ctx.agent.id
    )

    group = ctx.client().create_group(group_id_bytes(ctx.env.group_id))
    add = group.add_member(unb64(claim["packages"][0]))

    post_commit(ctx, add, welcome_for=peer.id, is_init=True)
    group.save()
    print(f"init commit posted at epoch {add.epoch}")


def welcome_join(ctx: Ctx) -> None:
    """Consume the one-shot Welcome fetch and persist before it can be lost."""
    result = ctx.env.api("GET", f"/agents/{ctx.agent.id}/mls/welcomes", acting_as=ctx.agent.id)
    welcomes = result["welcomes"]
    assert len(welcomes) == 1, f"expected exactly one welcome, got {len(welcomes)}"

    group = ctx.client().join_from_welcome(unb64(welcomes[0]["blob"]))
    assert group.last_commit() is None, "a Welcome joiner mints no commit"
    group.save()
    print(f"joined by Welcome at epoch {group.epoch()}")


def external_join(ctx: Ctx) -> None:
    """RFC 9420 external commit: no Welcome, no action by any existing member."""
    info = ctx.env.api(
        "GET", f"/groups/{ctx.env.group_id}/mls/group-info", acting_as=ctx.agent.id
    )
    group = ctx.client().join_by_external_commit(unb64(info["group_info"]))

    bundle = group.last_commit()
    assert bundle.welcomes == [], "an external commit adds nobody"
    post_commit(ctx, bundle)
    group.save()
    print(f"self-joined by external commit at epoch {group.epoch()}")


def sync(ctx: Ctx) -> None:
    group = ctx.group()
    result = ctx.env.api(
        "GET",
        f"/groups/{ctx.env.group_id}/mls/handshakes?since_epoch={group.epoch() + 1}",
        acting_as=ctx.agent.id,
    )

    for handshake in result["handshakes"]:
        group.apply_commit(unb64(handshake["blob"]))
    group.save()
    print(f"applied {len(result['handshakes'])} handshake(s), now at epoch {group.epoch()}")
