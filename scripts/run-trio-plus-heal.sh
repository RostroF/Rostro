#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# 5-node smoke test of the canonical-files heal mechanism.
#
# Roles:
#   alice    — validator, bootnode (port 30333)
#   bob      — validator (port 30334)
#   charlie  — validator (port 30335)
#   dave     — NON-validator eavesdropper (port 30336)
#   eve      — NON-validator with a TAMPERED gemini-node binary +
#              the canonical bytes available in her
#              --canonical-files-dir (port 30337)
#
# Eve demonstrates the canonical-files heal flow end-to-end:
#
#   1. Eve's `runtime-bin/gemini-node` has been corrupted (one byte
#      flipped). The supervisor's `--child` points to this tampered
#      binary.
#   2. On boot, Eve's verifier hashes `current_exe()` (the tampered
#      file) and compares to the on-chain canonical hash. Mismatch.
#   3. Eve's `--canonical-files-dir` points at her `canonical-cache/`
#      which holds a CLEAN copy of gemini-node (heal source).
#   4. The verifier fetches the canonical bytes by hash from the
#      heal source, stages at `runtime-bin/gemini-node.new`, then
#      `exit(90)`.
#   5. Eve's supervisor sees exit 90, atomically rotates
#      `gemini-node.new` over `gemini-node`, re-spawns.
#   6. Eve's fresh child boots, verifier passes, joins the network.
#
# What you should observe in eve's run.log:
#
#   * FOUNDATION FILESET MISMATCH line on the first boot attempt
#   * "heal staged N bytes at .../gemini-node.new"
#   * "all 1 canonical files staged; exiting code 90 for supervisor swap"
#   * Supervisor: "rotated .../gemini-node.new -> .../gemini-node"
#   * "spawning child (cycle 1)" — fresh respawn
#   * Second-boot verifier: "all 1 canonical files verified"
#   * Eve participates in the chain like dave does (canonical-files
#     attest passes; she's locked out of validator-channel as a
#     non-validator)

set -euo pipefail

LOG_FILTER="${LOG_FILTER:-info}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NODE_BIN="${GEMINI_NODE:-${REPO_ROOT}/target/release/gemini-node}"
SUPERVISOR_BIN="${ROSTRO_SUPERVISOR:-${REPO_ROOT}/target/release/rostro-supervisor}"

for bin in "$NODE_BIN" "$SUPERVISOR_BIN"; do
	if [[ ! -x "$bin" ]]; then
		echo "binary not found at $bin" >&2
		echo "  build first:  \\" >&2
		echo "                  cargo build --release -p gemini-node -p rostro-supervisor" >&2
		exit 1
	fi
done

if ! command -v python3 >/dev/null 2>&1; then
	echo "python3 is required" >&2
	exit 1
fi

GEMINI_NODE_HASH="$(python3 -c "import hashlib,sys;print(hashlib.blake2b(open(sys.argv[1],'rb').read(),digest_size=32).hexdigest())" "$NODE_BIN")"
export ROSTRO_CANONICAL_GEMINI_NODE_HASH="$GEMINI_NODE_HASH"
echo "canonical gemini-node hash: 0x${GEMINI_NODE_HASH}"

ALICE_NODE_KEY="0000000000000000000000000000000000000000000000000000000000000001"
BOB_NODE_KEY="0000000000000000000000000000000000000000000000000000000000000002"
CHARLIE_NODE_KEY="0000000000000000000000000000000000000000000000000000000000000003"
DAVE_NODE_KEY="0000000000000000000000000000000000000000000000000000000000000004"
EVE_NODE_KEY="0000000000000000000000000000000000000000000000000000000000000005"
ALICE_PEER_ID="12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp"

ALICE_BASE="${REPO_ROOT}/.star/alice"
BOB_BASE="${REPO_ROOT}/.star/bob"
CHARLIE_BASE="${REPO_ROOT}/.star/charlie"
DAVE_BASE="${REPO_ROOT}/.star/dave"
EVE_BASE="${REPO_ROOT}/.star/eve"

mkdir -p "$ALICE_BASE" "$BOB_BASE" "$CHARLIE_BASE" "$DAVE_BASE" "$EVE_BASE"

# Standard hard-link cache for the 4 honest nodes.
setup_node_cache() {
	local base="$1"
	mkdir -p "$base/canonical-cache"
	rm -f "$base/canonical-cache/gemini-node"
	ln "$NODE_BIN" "$base/canonical-cache/gemini-node"
}
setup_node_cache "$ALICE_BASE"
setup_node_cache "$BOB_BASE"
setup_node_cache "$CHARLIE_BASE"
setup_node_cache "$DAVE_BASE"

# Eve gets a SEPARATE runtime-bin directory holding a TAMPERED copy
# of gemini-node. The canonical-cache still holds a clean copy
# (heal source). Two distinct files so tampering doesn't break the
# heal source.
mkdir -p "$EVE_BASE/canonical-cache" "$EVE_BASE/runtime-bin"
echo "preparing eve's clean canonical-cache (heal source)..."
cp -f "$NODE_BIN" "$EVE_BASE/canonical-cache/gemini-node"
chmod +x "$EVE_BASE/canonical-cache/gemini-node"

echo "preparing eve's runtime-bin (will be tampered)..."
cp -f "$NODE_BIN" "$EVE_BASE/runtime-bin/gemini-node"
chmod +x "$EVE_BASE/runtime-bin/gemini-node"

# Tamper: flip a single byte 1 MiB into the binary.
echo "tampering eve's runtime binary (XOR 0xFF at offset 1 MiB)..."
python3 -c "
import sys
path = sys.argv[1]
with open(path, 'r+b') as f:
    f.seek(1024 * 1024)
    b = f.read(1)
    if not b:
        raise SystemExit('binary < 1 MiB; pick a different offset')
    f.seek(-1, 1)
    f.write(bytes([b[0] ^ 0xFF]))
" "$EVE_BASE/runtime-bin/gemini-node"

TAMPERED_HASH="$(python3 -c "import hashlib,sys;print(hashlib.blake2b(open(sys.argv[1],'rb').read(),digest_size=32).hexdigest())" "$EVE_BASE/runtime-bin/gemini-node")"
if [[ "$TAMPERED_HASH" == "$GEMINI_NODE_HASH" ]]; then
	echo "FAIL: tampering didn't change the hash" >&2
	exit 1
fi
echo "  tampered hash:  0x${TAMPERED_HASH}"
echo "  canonical hash: 0x${GEMINI_NODE_HASH}"
echo "  (mismatch confirmed — verifier should detect + heal)"

# Validator keys for Alice/Bob/Charlie ONLY.
echo "injecting Sassafras + GRANDPA keys for 3 validators..."
"$NODE_BIN" key insert --key-type sass --suri //Alice   --base-path "$ALICE_BASE"   --chain gemini-star
"$NODE_BIN" key insert --key-type sass --suri //Bob     --base-path "$BOB_BASE"     --chain gemini-star
"$NODE_BIN" key insert --key-type sass --suri //Charlie --base-path "$CHARLIE_BASE" --chain gemini-star
"$NODE_BIN" key insert --suri //Alice   --key-type gran --base-path "$ALICE_BASE"   --chain star
"$NODE_BIN" key insert --suri //Bob     --key-type gran --base-path "$BOB_BASE"     --chain star
"$NODE_BIN" key insert --suri //Charlie --key-type gran --base-path "$CHARLIE_BASE" --chain star

COMMON_VALIDATOR=(--chain star --no-mdns --validator --rpc-cors=all -l "$LOG_FILTER")
COMMON_NONVALIDATOR=(--chain star --no-mdns --rpc-cors=all -l "$LOG_FILTER")
BOOTNODES_MULTIADDR="/ip4/127.0.0.1/tcp/30333/p2p/${ALICE_PEER_ID}"

cleanup() {
	echo
	echo "stopping quintet..."
	for pid in "${PIDS[@]:-}"; do
		[[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
	done
	wait 2>/dev/null || true
}
trap cleanup INT TERM EXIT

PIDS=()

echo
echo "starting alice (validator, bootnode)..."
"$SUPERVISOR_BIN" --child "$ALICE_BASE/canonical-cache/gemini-node" --canonical-dir "$ALICE_BASE/canonical-cache" -- \
	"${COMMON_VALIDATOR[@]}" --name alice-star --base-path "$ALICE_BASE" \
	--node-key "$ALICE_NODE_KEY" --port 30333 --rpc-port 9944 --prometheus-port 9615 \
	--canonical-files-dir "$ALICE_BASE/canonical-cache" --alice 2>&1 | tee "$ALICE_BASE/run.log" | sed 's/^/[alice]   /' &
PIDS+=($!)

sleep 3

echo "starting bob (validator)..."
"$SUPERVISOR_BIN" --child "$BOB_BASE/canonical-cache/gemini-node" --canonical-dir "$BOB_BASE/canonical-cache" -- \
	"${COMMON_VALIDATOR[@]}" --name bob-star --base-path "$BOB_BASE" \
	--node-key "$BOB_NODE_KEY" --port 30334 --rpc-port 9945 --prometheus-port 9616 \
	--bootnodes "$BOOTNODES_MULTIADDR" \
	--canonical-files-dir "$BOB_BASE/canonical-cache" --bob 2>&1 | tee "$BOB_BASE/run.log" | sed 's/^/[bob]     /' &
PIDS+=($!)

echo "starting charlie (validator)..."
"$SUPERVISOR_BIN" --child "$CHARLIE_BASE/canonical-cache/gemini-node" --canonical-dir "$CHARLIE_BASE/canonical-cache" -- \
	"${COMMON_VALIDATOR[@]}" --name charlie-star --base-path "$CHARLIE_BASE" \
	--node-key "$CHARLIE_NODE_KEY" --port 30335 --rpc-port 9946 --prometheus-port 9617 \
	--bootnodes "$BOOTNODES_MULTIADDR" \
	--canonical-files-dir "$CHARLIE_BASE/canonical-cache" --charlie 2>&1 | tee "$CHARLIE_BASE/run.log" | sed 's/^/[charlie] /' &
PIDS+=($!)

echo "starting dave (non-validator eavesdropper)..."
"$SUPERVISOR_BIN" --child "$DAVE_BASE/canonical-cache/gemini-node" --canonical-dir "$DAVE_BASE/canonical-cache" -- \
	"${COMMON_NONVALIDATOR[@]}" --name dave-eavesdropper --base-path "$DAVE_BASE" \
	--node-key "$DAVE_NODE_KEY" --port 30336 --rpc-port 9947 --prometheus-port 9618 \
	--bootnodes "$BOOTNODES_MULTIADDR" \
	--canonical-files-dir "$DAVE_BASE/canonical-cache" 2>&1 | tee "$DAVE_BASE/run.log" | sed 's/^/[dave]    /' &
PIDS+=($!)

echo "starting eve (non-validator, TAMPERED binary — should heal+restart)..."
# Note: --child points to the TAMPERED runtime-bin/gemini-node.
# --canonical-dir is the same dir, so the supervisor will rotate
# `gemini-node.new` (staged by the verifier) over the tampered
# binary on exit 90.
"$SUPERVISOR_BIN" --child "$EVE_BASE/runtime-bin/gemini-node" --canonical-dir "$EVE_BASE/runtime-bin" -- \
	"${COMMON_NONVALIDATOR[@]}" --name eve-heal --base-path "$EVE_BASE" \
	--node-key "$EVE_NODE_KEY" --port 30337 --rpc-port 9948 --prometheus-port 9619 \
	--bootnodes "$BOOTNODES_MULTIADDR" \
	--canonical-files-dir "$EVE_BASE/canonical-cache" 2>&1 | tee "$EVE_BASE/run.log" | sed 's/^/[eve]     /' &
PIDS+=($!)

wait
