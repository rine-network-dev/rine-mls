"""Shared fixtures for the extension's tests.

Everything here drives the wheel exactly as the Python SDK will: real store
directories on disk, real Ed25519 seeds, real MLS blobs. The one thing left out
is the transport — base64url and HTTP belong above this layer.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path

import pytest
import rine_mls

# Both suites rine speaks, so no test only proves the classical path.
SUITES = [
    pytest.param(rine_mls.CIPHER_SUITE_CLASSICAL, id="classical"),
    pytest.param(rine_mls.CIPHER_SUITE_XWING, id="post-quantum"),
]

DEFAULT_SUITE = rine_mls.CIPHER_SUITE_DEFAULT


@dataclass(frozen=True)
class Agent:
    """One agent: its own store root, its own identity seed.

    ``open()`` takes a client fresh each time, which is how a restarted process
    reaches its state.
    """

    store_root: Path
    seed: bytes
    cipher_suite: int
    epoch_retention_limit: int | None = None

    def open(self) -> rine_mls.MlsClient:
        return rine_mls.MlsClient(
            str(self.store_root),
            self.seed,
            self.cipher_suite,
            epoch_retention_limit=self.epoch_retention_limit,
        )


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    return tmp_path


@pytest.fixture
def make_agent(workspace: Path):
    def factory(name: str, cipher_suite: int = DEFAULT_SUITE, **kwargs) -> Agent:
        return Agent(workspace / name, secrets.token_bytes(32), cipher_suite, **kwargs)

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
