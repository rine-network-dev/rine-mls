"""What a consumer of the published wheel does: import it, and use it.

Run inside a clean virtualenv by ``tests/run.sh`` — there is no source tree and
no Rust toolchain here, so anything that works works because the wheel shipped
it.
"""

from __future__ import annotations

import secrets
import sys
import tempfile
from pathlib import Path

import rine_mls


def main() -> None:
    with tempfile.TemporaryDirectory() as store:
        root = Path(store)
        suite = rine_mls.CIPHER_SUITE_DEFAULT

        allowed = rine_mls.AllowedIdentities()
        alice, bob = (
            rine_mls.MlsClient(
                str(root / name), name.encode(), secrets.token_bytes(32), allowed, suite
            )
            for name in ("alice", "bob")
        )
        for client in (alice, bob):
            allowed.insert(client.agent_id(), client.leaf_public_key(), 0)

        assert not hasattr(alice, "panic_probe"), "the published wheel must not carry the probe"

        group = alice.create_group_with_members(
            secrets.token_bytes(16), [bob.generate_key_package()]
        )
        init = group.last_commit()

        assert init.epoch == 1
        assert len(init.welcomes) == 1

        joined = bob.join_from_welcome(init.welcomes[0])
        payload = group.encrypt_application_message(b"packaged and working")

        assert payload[0] == rine_mls.APP_MESSAGE_TAG
        assert joined.decrypt_application_message(payload).envelope == b"packaged and working"

        # Typed errors survive packaging too — a class, not a message.
        try:
            alice.generate_key_packages(rine_mls.KEY_PACKAGE_MAX_BATCH + 1)
            raise AssertionError("expected a typed refusal")
        except rine_mls.KeyPackageBatchTooLargeError as e:
            assert type(e).code == "RINE_MLS_KEY_PACKAGE_BATCH_TOO_LARGE"

    print(
        f"consumer: post-quantum group founded, joined, message round-tripped "
        f"(python {sys.version_info.major}.{sys.version_info.minor})"
    )


if __name__ == "__main__":
    main()
