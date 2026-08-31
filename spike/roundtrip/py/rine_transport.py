"""Transport for the Python half of the round-trip.

The rine HTTP calls, the two base64 alphabets the protocol uses, and the signed
inner envelope. It restates the ``mls-v1`` envelope codec on purpose: the
TypeScript half states it too, and whether two independent statements of it
produce the same bytes is exactly the interop claim under test. The real
integration puts this inside the Python SDK.
"""

from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

SIGNATURE_SIZE = 64


def b64(data: bytes) -> str:
    """MLS control-plane blobs travel as standard base64."""
    return base64.b64encode(data).decode("ascii")


def unb64(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


def b64url(data: bytes) -> str:
    """Only the application message's encrypted_payload is base64url."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def group_id_bytes(uuid_str: str) -> bytes:
    """The rine group UUID's 16 raw bytes — what the MLS group id is set to."""
    return bytes.fromhex(uuid_str.replace("-", ""))


def signing_kid(agent_id: str) -> str:
    return f"rine:{agent_id}"


def agent_id_from_kid(kid: str) -> str:
    if not kid.startswith("rine:"):
        raise ValueError(f"bad kid {kid}")
    return kid[len("rine:") :]


class ApiError(RuntimeError):
    """An HTTP failure with the status attached, so callers branch on 409 etc."""

    def __init__(self, method: str, path: str, status: int, detail: str) -> None:
        super().__init__(f"{method} {path} -> {status} {detail}")
        self.status = status


@dataclass(frozen=True)
class Agent:
    id: str
    seed: bytes


class Env:
    """The round-trip's shared configuration, written by run.sh."""

    def __init__(self) -> None:
        path = os.environ["RINE_ROUNDTRIP_ENV"]
        with open(path, encoding="utf-8") as handle:
            raw = json.load(handle)

        self.api_url: str = raw["apiUrl"]
        self.token: str = raw["token"]
        self.group_id: str = raw["groupId"]
        self.group_handle: str = raw["groupHandle"]
        self.cipher_suite: int = raw["cipherSuite"]
        self.state_root: str = raw["stateRoot"]
        self._agents: dict[str, Any] = raw["agents"]

    def agent(self, name: str) -> Agent:
        entry = self._agents[name]
        return Agent(id=entry["id"], seed=unb64url(entry["seed"]))

    def api(
        self,
        method: str,
        path: str,
        *,
        acting_as: str | None = None,
        body: Any = None,
    ) -> Any:
        request = urllib.request.Request(f"{self.api_url}{path}", method=method)
        request.add_header("Authorization", f"Bearer {self.token}")
        if acting_as:
            request.add_header("X-Rine-Agent", acting_as)
        payload = None
        if body is not None:
            payload = json.dumps(body).encode("utf-8")
            request.add_header("Content-Type", "application/json")

        try:
            with urllib.request.urlopen(request, payload) as response:
                text = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:  # surface the server's own detail
            raise ApiError(
                method, path, exc.code, exc.read().decode("utf-8", "replace")
            ) from None

        return json.loads(text) if text else None


def sign_with_seed(seed: bytes, data: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).sign(data)


def encode_envelope(kid: str, signature: bytes, payload: bytes) -> bytes:
    kid_bytes = kid.encode("utf-8")
    return bytes([len(kid_bytes)]) + kid_bytes + signature + payload


@dataclass(frozen=True)
class InnerEnvelope:
    kid: str
    signature: bytes
    payload: bytes


def decode_envelope(data: bytes) -> InnerEnvelope:
    kid_len = data[0]
    return InnerEnvelope(
        kid=data[1 : 1 + kid_len].decode("utf-8"),
        signature=data[1 + kid_len : 1 + kid_len + SIGNATURE_SIZE],
        payload=data[1 + kid_len + SIGNATURE_SIZE :],
    )


def verify_envelope_sender(env: Env, envelope: InnerEnvelope, acting_as: str) -> None:
    """Fetch the sender's PUBLISHED Ed25519 key and check the signature."""
    sender_id = agent_id_from_kid(envelope.kid)
    keys = env.api("GET", f"/agents/{sender_id}/keys", acting_as=acting_as)
    public_key = Ed25519PublicKey.from_public_bytes(unb64url(keys["signing_public_key"]["x"]))
    try:
        public_key.verify(envelope.signature, envelope.payload)
    except InvalidSignature:
        raise AssertionError(f"inner envelope signature failed for {envelope.kid}") from None
