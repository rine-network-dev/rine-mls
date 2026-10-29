"""Shared fixtures for the extension's tests.

Everything here drives the wheel exactly as the Python SDK will: real store
directories on disk, real leaf signature seeds, real MLS blobs. The one thing left out
is the transport — base64url and HTTP belong above this layer.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path

import pytest
import rine_mls

# The one suite rine speaks.
SUITES = [pytest.param(rine_mls.CIPHER_SUITE_XWING, id="post-quantum")]

# Every agent a test opens is chain-verified by construction, so each one's
# (agent id, leaf key) pair goes into one process-wide set that all clients share.
ALLOWED = rine_mls.AllowedIdentities()

DEFAULT_SUITE = rine_mls.CIPHER_SUITE_DEFAULT


@dataclass(frozen=True)
class Agent:
    """One agent: its own store root, agent id and leaf signature seed.

    ``open()`` takes a client fresh each time, which is how a restarted process
    reaches its state.
    """

    store_root: Path
    agent_id: bytes
    seed: bytes
    cipher_suite: int
    epoch_retention_limit: int | None = None

    def open(self) -> rine_mls.MlsClient:
        client = rine_mls.MlsClient(
            str(self.store_root),
            self.agent_id,
            self.seed,
            ALLOWED,
            self.cipher_suite,
            epoch_retention_limit=self.epoch_retention_limit,
        )
        ALLOWED.insert(client.agent_id(), client.leaf_public_key(), 0)
        return client


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    return tmp_path


@pytest.fixture
def make_agent(workspace: Path):
    def factory(name: str, cipher_suite: int = DEFAULT_SUITE, **kwargs) -> Agent:
        return Agent(
            workspace / name,
            secrets.token_bytes(16),
            secrets.token_bytes(32),
            cipher_suite,
            **kwargs,
        )

    return factory


def group_id() -> bytes:
    return secrets.token_bytes(16)


def code_of(fn) -> str:
    """The wire code of the exception ``fn`` raises, or why there wasn't one."""
    try:
        fn()
    except rine_mls.RineMlsError as e:
        return type(e).code
    return "<no error raised>"


def probe_expected() -> bool:
    return os.environ.get("RINE_MLS_EXPECT_PROBE") == "1"
