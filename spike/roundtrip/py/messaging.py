"""Data plane, Python side.

Sending and receiving ``mls-v1`` group messages, plus the typed-error contract
observed from Python rather than asserted in Rust. ``ts/messaging.ts`` is the
same file in the other language.
"""

from __future__ import annotations

import json

import rine_mls
from joining import Ctx
from rine_transport import (
    b64url,
    decode_envelope,
    encode_envelope,
    sign_with_seed,
    signing_kid,
    unb64url,
    verify_envelope_sender,
)


def send(ctx: Ctx, text: str) -> None:
    group = ctx.group()
    plaintext = json.dumps({"text": text}, separators=(",", ":")).encode("utf-8")
    kid = signing_kid(ctx.agent.id)
    envelope = encode_envelope(kid, sign_with_seed(ctx.agent.seed, plaintext), plaintext)
    payload = group.encrypt_application_message(envelope)
    group.save()

    message = ctx.env.api(
        "POST",
        "/messages",
        acting_as=ctx.agent.id,
        body={
            "to_handle": ctx.env.group_handle,
            "type": "rine.v1.dm",
            "encrypted_payload": b64url(payload),
            "encryption_version": "mls-v1",
            "sender_signing_kid": kid,
        },
    )
    print(f"MESSAGE_ID={message['id']}")


def receive(ctx: Ctx, message_id: str, expected: str) -> None:
    inbox = ctx.env.api(
        "GET", f"/agents/{ctx.agent.id}/messages?limit=50", acting_as=ctx.agent.id
    )
    message = next((m for m in inbox["items"] if m["id"] == message_id), None)
    assert message is not None, f"message {message_id} is not in {ctx.name}'s inbox"
    assert message["encryption_version"] == "mls-v1", message["encryption_version"]

    group = ctx.group()
    decrypted = group.decrypt_application_message(unb64url(message["encrypted_payload"]))
    group.save()

    envelope = decode_envelope(decrypted.envelope)
    verify_envelope_sender(ctx.env, envelope, ctx.agent.id)
    assert envelope.kid == message["sender_signing_kid"], envelope.kid

    text = json.loads(envelope.payload.decode("utf-8"))["text"]
    assert text == expected, f"plaintext mismatch: {text!r} != {expected!r}"
    print(f"decrypted exactly: {text}")


def error_contract(ctx: Ctx) -> None:
    """The typed-error contract, observed from Python rather than asserted in Rust."""
    group = ctx.group()
    root, suite = ctx.env.state_root, ctx.env.cipher_suite
    checks = [
        (rine_mls.UnexpectedVersionTagError, lambda: group.decrypt_application_message(b"\x03\x01")),
        (rine_mls.EmptyFrameError, lambda: group.decrypt_application_message(b"")),
        (rine_mls.UnexpectedBlobError, lambda: group.apply_commit(group.group_info())),
        (rine_mls.UnsupportedCipherSuiteError, lambda: rine_mls.MlsClient(root, bytes(32), 0x004D)),
        (rine_mls.InvalidSigningSeedError, lambda: rine_mls.MlsClient(root, bytes(31), suite)),
    ]

    for expected_type, run in checks:
        try:
            run()
        except rine_mls.RineMlsError as exc:  # every failure shares one base
            assert type(exc) is expected_type, f"expected {expected_type.__name__}, got {type(exc).__name__}"
            assert exc.code == expected_type.code
        else:
            raise AssertionError(f"{expected_type.__name__}: expected a raise, got none")
    print(f"{len(checks)} typed exception classes confirmed from Python")
