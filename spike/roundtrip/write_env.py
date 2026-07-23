"""Write the round-trip's shared env file for one ciphersuite.

The agent signing seeds come from the CLI's own key directory
(``keys/<agent>/signing.key``, base64url of the 32-byte Ed25519 private key) —
the point being that both bindings take the SAME on-disk identity every other
rine surface uses, not a key minted for the test.
"""

from __future__ import annotations

import json
import os
import sys


def seed(config_dir: str, agent_id: str) -> str:
    with open(os.path.join(config_dir, "keys", agent_id, "signing.key"), encoding="utf-8") as f:
        return f.read().strip()


def main() -> None:
    out_path = sys.argv[1]
    config_dir = os.environ["ORG_DIR"]
    agents = {name: os.environ[name.upper()] for name in ("alpha", "bravo", "charlie")}

    env = {
        "apiUrl": os.environ["API_URL"],
        "token": os.environ["TOKEN"],
        "groupId": os.environ["GROUP_ID"],
        "groupHandle": os.environ["GROUP_HANDLE"],
        "cipherSuite": int(os.environ["SUITE_ID"]),
        "stateRoot": os.environ["STATE_ROOT"],
        "agents": {
            name: {"id": agent_id, "seed": seed(config_dir, agent_id)}
            for name, agent_id in agents.items()
        },
    }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(env, f, indent=2)


main()
