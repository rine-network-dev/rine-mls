#!/usr/bin/env bash
# Interop proof: one MLS group, three agents, two languages, a real rine server.
#
# A Node process (napi binding) and a Python process (PyO3 binding) join the
# SAME group through the real HTTP control plane and exchange application
# messages in every direction, with exact plaintext asserted on both sides. The
# whole sequence runs once per ciphersuite: classical 0x0001 and rine's
# post-quantum 0xF057.
#
# Each suite runs in BOTH orientations, so neither language is only ever the
# creator or only ever the joiner:
#
#   TS-led: alpha (Node) creates and adds; bravo + charlie (Python) join
#   PY-led: bravo (Python) creates and adds; alpha + charlie (Node) join
#
# Infrastructure is a throwaway postgres + uvicorn on auto-picked free ports,
# booted by scripts/e2e-lib.sh — never the shared :5499 rig.
#
#   bash rine-mls/spike/roundtrip/run.sh

set -uo pipefail

SPIKE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_NAME="mls-roundtrip"
source "$(cd "$SPIKE_DIR/../../.." && pwd)/scripts/e2e-lib.sh"

SUITES=("1:classical" "61527:xwing")   # 61527 = 0xF057

# "<label> <creator-runtime> <creator> <welcome-runtime> <welcome-joiner>
#          <external-runtime> <external-joiner>"
ORIENTATIONS=(
    "ts-led ts alpha py bravo py charlie"
    "py-led py bravo ts alpha ts charlie"
)

# ---------------------------------------------------------------------------
# Build both bindings (release: ML-KEM in a debug build is painfully slow)
# ---------------------------------------------------------------------------

section "SETUP: bindings"

ADDON_DIR="$WORKDIR/addon"
PYMOD_DIR="$WORKDIR/pymod"
mkdir -p "$ADDON_DIR" "$PYMOD_DIR"

echo "  [rust] cargo build --release -p rine-mls-node -p rine-mls-py"
(cd "$PROJECT_ROOT/rine-mls" && cargo build --release -p rine-mls-node -p rine-mls-py) \
    > "$WORKDIR/cargo.log" 2>&1 \
    || { echo "FATAL: cargo build failed"; tail -30 "$WORKDIR/cargo.log"; exit 1; }

# Both bindings register themselves at module load, so the raw cdylib IS the
# loadable artifact under the name each runtime expects. The npm/maturin
# packaging is the release build's job; the spike only needs the ABI.
cp "$PROJECT_ROOT/rine-mls/target/release/librine_mls_node.so" "$ADDON_DIR/rine_mls.node"
cp "$PROJECT_ROOT/rine-mls/target/release/librine_mls.so" "$PYMOD_DIR/rine_mls.so"
export RINE_MLS_NODE_ADDON="$ADDON_DIR/rine_mls.node"
pass "bindings built and staged"

echo "  [py] isolated venv for the Python driver"
uv venv --python 3.12 "$WORKDIR/pyvenv" > /dev/null 2>&1 \
    && uv pip install --quiet --python "$WORKDIR/pyvenv/bin/python" cryptography \
    || { echo "FATAL: python venv setup failed"; exit 1; }
PY_BIN="$WORKDIR/pyvenv/bin/python"

# ---------------------------------------------------------------------------
# One org, three agents
# ---------------------------------------------------------------------------

section "SETUP: org, agents, keys"

ORG_DIR="$WORKDIR/org"
mkdir -p "$ORG_DIR"
rine() { RINE_CONFIG_DIR="$ORG_DIR" RINE_API_URL="$API_URL" $CLI --json "$@" 2>/dev/null; }

REG=$(RINE_CONFIG_DIR="$ORG_DIR" RINE_API_URL="$API_URL" $CLI --json register \
        --email "mls-roundtrip@gmail.com" --name "MLS Roundtrip" --slug "mlsrt" 2>&1 | extract_json)
[[ -n "$(jf "$REG" '.org_id // empty')" ]] && pass "org registered" || { fail "org register" "$REG"; e2e_summary; }

declare -A AGENT_ID
for name in alpha bravo charlie; do
    AGENT_ID[$name]=$(jf "$(rine agent create --name "$name")" '.id // empty')
    [[ -n "${AGENT_ID[$name]}" ]] || { fail "agent create $name" ""; e2e_summary; }
done
pass "3 agents created (each drives whichever binding its role needs)"

TOKEN=$(get_token "$ORG_DIR")

# ---------------------------------------------------------------------------
# Per-suite run
# ---------------------------------------------------------------------------

# as_agent <METHOD> <agent-id> <path> [json-body]
as_agent() {
    local method="$1" agent="$2" path="$3" body="${4:-}"
    local args=(-s -X "$method" "$API_URL$path"
        -H "Authorization: Bearer $TOKEN" -H "X-Rine-Agent: $agent")
    [[ -n "$body" ]] && args+=(-H "Content-Type: application/json" -d "$body")
    curl "${args[@]}"
}

ts_step()  { RINE_ROUNDTRIP_ENV="$ENV_FILE" node "$SPIKE_DIR/ts/driver.ts" "$@"; }
py_step()  { RINE_ROUNDTRIP_ENV="$ENV_FILE" PYTHONPATH="$PYMOD_DIR:$SPIKE_DIR/py" \
                "$PY_BIN" "$SPIKE_DIR/py/driver.py" "$@"; }

# step "<label>" <ts|py> <args...>
# Full stdout+stderr of every step lands in $STEP_LOG (override to keep it past
# the workdir's cleanup); the summary line only carries the tail.
STEP_LOG="${RINE_ROUNDTRIP_LOG:-$WORKDIR/steps.log}"

step() {
    local label="$1" runtime="$2"; shift 2
    local out status
    out=$("${runtime}_step" "$@" 2>&1)
    status=$?
    printf '\n=== [%s] %s (%s %s) ===\n%s\n' "$runtime" "$label" "$1" "${2:-}" "$out" >> "$STEP_LOG"

    if [[ $status -eq 0 ]]; then
        pass "$label"
        LAST_OUT="$out"
    else
        fail "$label" "$(echo "$out" | tail -3 | tr '\n' ' ')"
        LAST_OUT=""
    fi
}

message_id() { echo "$LAST_OUT" | sed -n 's/^MESSAGE_ID=//p' | tail -1; }

for entry in "${SUITES[@]}"; do
    SUITE_ID="${entry%%:*}"
    SUITE_NAME="${entry##*:}"

  for orientation in "${ORIENTATIONS[@]}"; do
    read -r LABEL CREATOR_RT CREATOR JOIN_RT JOINER EXT_RT EXT <<< "$orientation"
    section "SUITE ${SUITE_NAME} (0x$(printf '%04X' "$SUITE_ID")) — ${LABEL}"

    GROUP=$(as_agent POST "${AGENT_ID[$CREATOR]}" "/groups" \
        "{\"name\":\"mlsrt-${SUITE_NAME}-${LABEL}\",\"visibility\":\"private\",\"enrollment_policy\":\"closed\",\"mls_enabled\":true}")
    GROUP_ID=$(jf "$GROUP" '.id // empty')
    GROUP_HANDLE=$(jf "$GROUP" '.handle // empty')
    [[ -n "$GROUP_ID" ]] && pass "group created (MLS not yet initialized)" \
        || { fail "group create" "$GROUP"; continue; }

    for name in "$JOINER" "$EXT"; do
        # Both endpoints resolve the acting agent from the header: the org owns
        # three agents, so there is no single-agent fallback to fall back to.
        as_agent POST "${AGENT_ID[$CREATOR]}" "/groups/$GROUP_ID/invite" \
            "{\"agent_id\":\"${AGENT_ID[$name]}\"}" > /dev/null
        as_agent POST "${AGENT_ID[$name]}" "/groups/$GROUP_ID/join" '{}' > /dev/null
    done
    MEMBERS=$(jlen "$(as_agent GET "${AGENT_ID[$CREATOR]}" "/groups/$GROUP_ID/members")" '.items')
    [[ "$MEMBERS" == "3" ]] && pass "3 rine members" || fail "membership" "count=$MEMBERS"

    ENV_FILE="$WORKDIR/env-${SUITE_NAME}-${LABEL}.json"
    ORG_DIR="$ORG_DIR" API_URL="$API_URL" TOKEN="$TOKEN" GROUP_ID="$GROUP_ID" \
    GROUP_HANDLE="$GROUP_HANDLE" SUITE_ID="$SUITE_ID" \
    STATE_ROOT="$WORKDIR/state/${SUITE_NAME}-${LABEL}" \
    ALPHA="${AGENT_ID[alpha]}" BRAVO="${AGENT_ID[bravo]}" CHARLIE="${AGENT_ID[charlie]}" \
        python3 "$SPIKE_DIR/write_env.py" "$ENV_FILE" || { fail "env file" ""; continue; }

    step "$JOINER publishes a KeyPackage"                  "$JOIN_RT" publish-kp "$JOINER"
    step "$CREATOR creates the MLS group and adds $JOINER" "$CREATOR_RT" init-group "$CREATOR" "$JOINER"
    step "$JOINER joins by Welcome"                        "$JOIN_RT" welcome-join "$JOINER"
    step "$EXT self-joins by external commit"              "$EXT_RT" external-join "$EXT"
    step "$CREATOR applies the external commit"            "$CREATOR_RT" sync "$CREATOR"
    step "$JOINER applies the external commit"             "$JOIN_RT" sync "$JOINER"

    TEXT_A="hello from the creator on ${SUITE_NAME}/${LABEL}"
    step "$CREATOR sends"                                  "$CREATOR_RT" send "$CREATOR" "$TEXT_A"
    MID=$(message_id)
    step "$JOINER decrypts the creator's plaintext"        "$JOIN_RT" recv "$JOINER" "$MID" "$TEXT_A"
    step "$EXT decrypts the creator's plaintext"           "$EXT_RT" recv "$EXT" "$MID" "$TEXT_A"

    TEXT_B="hello from the Welcome joiner on ${SUITE_NAME}/${LABEL}"
    step "$JOINER sends"                                   "$JOIN_RT" send "$JOINER" "$TEXT_B"
    MID=$(message_id)
    step "$CREATOR decrypts the Welcome joiner's plaintext" "$CREATOR_RT" recv "$CREATOR" "$MID" "$TEXT_B"
    step "$EXT decrypts the Welcome joiner's plaintext"     "$EXT_RT" recv "$EXT" "$MID" "$TEXT_B"

    TEXT_C="hello from the external joiner on ${SUITE_NAME}/${LABEL}"
    step "$EXT sends"                                      "$EXT_RT" send "$EXT" "$TEXT_C"
    MID=$(message_id)
    step "$CREATOR decrypts the external joiner's plaintext" "$CREATOR_RT" recv "$CREATOR" "$MID" "$TEXT_C"
    step "$JOINER decrypts the external joiner's plaintext"  "$JOIN_RT" recv "$JOINER" "$MID" "$TEXT_C"

    step "typed errors reach JavaScript"                   ts error-contract alpha
    step "typed exceptions reach Python"                   py error-contract bravo
  done
done

e2e_summary
