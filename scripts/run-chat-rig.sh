#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Combined chat send-test rig (single box): 2 block-producing validators
# + 2 NON-validator chat relays, ALL on one network (--chain star). This
# is the topology the dotwave first-message-send test needs:
#
#   * Validators produce blocks so the device admission cert (and any RNS
#     name) actually mints into chain state — cert-auth on the onion drop
#     reads it via the runtime API at best_hash.
#   * The mandatory 2-hop onion (guard forwards -> relay-2 delivers) needs
#     TWO chat-capable relays, and chat_admission rejects chat traffic to
#     any known validator — so guard + relay-2 must both be non-validators.
#   * The relays bootnode into alice-star, so they sync chain state and
#     propagate the phone's mint/register extrinsics to the validators.
#
# Topology:
#   alice-star   validator, bootnode   p2p 30333  rpc 9944
#   bob-star     validator             p2p 30334  rpc 9945
#   guard        non-validator relay   p2p 30340  rpc 9954   <- phone Guard
#   relay2       non-validator relay   p2p 30341  rpc 9955   <- phone Relay-2
#
# Block production uses a subset (2 of the star spec's 5 genesis
# authorities); finality (needs >=4) will NOT progress, which is fine —
# the cert mint only needs best_hash to advance. If blocks stall at #0,
# add charlie-star (a 3rd validator) — run-trio.sh proves 3 produce.
#
# Usage:  scripts/run-chat-rig.sh        # foreground; Ctrl-C kills all
#
# SECURITY: lab/dev only. Localhost RPC (reach phones over USB with
# `adb reverse tcp:9954 tcp:9954` + `... 9955 ...`).

set -euo pipefail

LOG_FILTER="${LOG_FILTER:-info,rostro-chat-gossip=debug,rostro-chat-rpc=debug,rostro-chat-stripe=debug,rostro-chat-fetch=debug,rostro-chat-onion-forward=debug}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NODE_BIN="${GEMINI_NODE:-${REPO_ROOT}/target/release/gemini-node}"

# We launch gemini-node DIRECTLY, not via rostro-supervisor. The
# supervisor installs the Cannae sandbox, whose mount-namespace
# primitive needs CAP_SYS_ADMIN (unshare(CLONE_NEWNS)) — unavailable
# under WSL without root. The sandbox + canonical-files supervision are
# irrelevant to a chat send-test, so we skip the supervisor entirely.
if [[ ! -x "$NODE_BIN" ]]; then
	echo "binary not found at $NODE_BIN" >&2
	echo "  build first:  \\" >&2
	echo "                  cargo build --release -p gemini-node" >&2
	exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
	echo "python3 is required to compute the gemini-node canonical hash" >&2
	exit 1
fi

GEMINI_NODE_HASH="$(python3 -c "import hashlib,sys;print(hashlib.blake2b(open(sys.argv[1],'rb').read(),digest_size=32).hexdigest())" "$NODE_BIN")"
if [[ ${#GEMINI_NODE_HASH} -ne 64 ]]; then
	echo "computed canonical hash is ${#GEMINI_NODE_HASH} chars; expected 64" >&2
	exit 1
fi
export ROSTRO_CANONICAL_GEMINI_NODE_HASH="$GEMINI_NODE_HASH"
echo "canonical gemini-node hash (blake2_256): 0x${GEMINI_NODE_HASH}"

# Deterministic libp2p node-keys. Validators reuse the well-known star
# keys (alice=..01, bob=..02); relays get fresh keys (..0a, ..0b) so
# their peer IDs don't collide on the same box. The relay's node-key is
# its Ed25519 chat identity — what the phone seals an onion layer to via
# chat_nodeInfo.
ALICE_NODE_KEY="0000000000000000000000000000000000000000000000000000000000000001"
BOB_NODE_KEY="0000000000000000000000000000000000000000000000000000000000000002"
GUARD_NODE_KEY="000000000000000000000000000000000000000000000000000000000000000a"
RELAY2_NODE_KEY="000000000000000000000000000000000000000000000000000000000000000b"
ALICE_PEER_ID="12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp"

RIG="${REPO_ROOT}/.chat-rig"
ALICE_BASE="${RIG}/alice"
BOB_BASE="${RIG}/bob"
GUARD_BASE="${RIG}/guard"
RELAY2_BASE="${RIG}/relay2"

setup_node_cache() {
	local base="$1"
	mkdir -p "$base/canonical-cache"
	rm -f "$base/canonical-cache/gemini-node"
	ln "$NODE_BIN" "$base/canonical-cache/gemini-node"
}
for b in "$ALICE_BASE" "$BOB_BASE" "$GUARD_BASE" "$RELAY2_BASE"; do
	mkdir -p "$b"
	setup_node_cache "$b"
done

echo "injecting Sassafras + GRANDPA keys for the 2 validators..."
"$NODE_BIN" key insert --key-type sass --suri //Alice --base-path "$ALICE_BASE" --chain gemini-star
"$NODE_BIN" key insert --key-type sass --suri //Bob   --base-path "$BOB_BASE"   --chain gemini-star
"$NODE_BIN" key insert --suri //Alice --key-type gran --base-path "$ALICE_BASE" --chain star
"$NODE_BIN" key insert --suri //Bob   --key-type gran --base-path "$BOB_BASE"   --chain star

BOOTNODES_MULTIADDR="/ip4/127.0.0.1/tcp/30333/p2p/${ALICE_PEER_ID}"

COMMON_VALIDATOR=(--chain star --no-mdns --validator --rpc-cors=all -l "$LOG_FILTER")
COMMON_RELAY=(--chain star --no-mdns --rpc-cors=all -l "$LOG_FILTER")

ALICE_ARGS=(
	"${COMMON_VALIDATOR[@]}"
	--name alice-star --base-path "$ALICE_BASE"
	--node-key "$ALICE_NODE_KEY"
	--port 30333 --rpc-port 9944 --prometheus-port 9615
	--canonical-files-dir "$ALICE_BASE/canonical-cache"
	--alice
)
BOB_ARGS=(
	"${COMMON_VALIDATOR[@]}"
	--name bob-star --base-path "$BOB_BASE"
	--node-key "$BOB_NODE_KEY"
	--port 30334 --rpc-port 9945 --prometheus-port 9616
	--bootnodes "$BOOTNODES_MULTIADDR"
	--canonical-files-dir "$BOB_BASE/canonical-cache"
	--bob
)
GUARD_ARGS=(
	"${COMMON_RELAY[@]}"
	--name guard --base-path "$GUARD_BASE"
	--node-key "$GUARD_NODE_KEY"
	--listen-addr "/ip4/0.0.0.0/tcp/30340"
	--rpc-port 9954 --prometheus-port 9670
	--bootnodes "$BOOTNODES_MULTIADDR"
	--canonical-files-dir "$GUARD_BASE/canonical-cache"
)
RELAY2_ARGS=(
	"${COMMON_RELAY[@]}"
	--name relay2 --base-path "$RELAY2_BASE"
	--node-key "$RELAY2_NODE_KEY"
	--listen-addr "/ip4/0.0.0.0/tcp/30341"
	--rpc-port 9955 --prometheus-port 9671
	--bootnodes "$BOOTNODES_MULTIADDR"
	--canonical-files-dir "$RELAY2_BASE/canonical-cache"
)

cleanup() {
	echo
	echo "stopping chat rig..."
	for pid in "${PIDS[@]:-}"; do
		[[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
	done
	wait 2>/dev/null || true
}
trap cleanup INT TERM EXIT

PIDS=()

launch() {
	local label="$1" base="$2"; shift 2
	"$NODE_BIN" "$@" \
		2>&1 | tee "$base/run.log" | sed "s/^/[$label] /" &
	PIDS+=($!)
}

echo "starting alice-star (validator, bootnode)..."
launch "alice " "$ALICE_BASE" "${ALICE_ARGS[@]}"
sleep 4
echo "starting bob-star (validator)..."
launch "bob   " "$BOB_BASE" "${BOB_ARGS[@]}"
echo "starting guard (non-validator relay)..."
launch "guard " "$GUARD_BASE" "${GUARD_ARGS[@]}"
echo "starting relay2 (non-validator relay)..."
launch "relay2" "$RELAY2_BASE" "${RELAY2_ARGS[@]}"

wait
