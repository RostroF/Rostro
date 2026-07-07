#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# 5-node witnessed-spend test rig (single box):
#   2 block-producing validators + 3 NON-validator chat guards, all on
#   --chain star. The guards are pinned with the anonymous-membership vk so
#   chat_authenticateMembership is ACTIVE, which fires the witnessed-spend
#   committee flow. 3 guards is the minimum for a k-committee: the verifier
#   guard excludes itself, so it needs >= t=2 OTHER guards to counter-sign.
#
# Topology:
#   alice-star   validator, bootnode   p2p 30333  rpc 9944
#   bob-star     validator             p2p 30334  rpc 9945
#   guard        non-validator guard   p2p 30340  rpc 9954   <- membership auth
#   relay2       non-validator guard   p2p 30341  rpc 9955   <- membership auth
#   relay3       non-validator guard   p2p 30342  rpc 9956   <- membership auth
#
# Finality (GRANDPA needs ~4 of 5 genesis authorities) will NOT progress with
# only 2 validators, which is fine: the guard set + roots are read at the BEST
# head, and the test-harness enroll only needs best_hash to advance.
#
# Usage:  scripts/run-spend-rig.sh        # foreground; Ctrl-C kills all
#
# SECURITY: lab/dev only. Localhost RPC.

set -euo pipefail

export SUBSTRATE_ENABLE_POLKAVM="${SUBSTRATE_ENABLE_POLKAVM:-1}"
LOG_FILTER="${LOG_FILTER:-info,rostro-chat-rpc=debug,rostro-chat-spend=debug,rostro-chat-gossip=info}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NODE_BIN="${GEMINI_NODE:-${REPO_ROOT}/target/release/gemini-node}"
MEMBERSHIP_VK="${MEMBERSHIP_VK:-/home/coder/rostro-testnet-lab/binaries/membership-keys/membership_vk.bin}"

if [[ ! -x "$NODE_BIN" ]]; then
	echo "binary not found at $NODE_BIN — build first:" >&2
	echo "  SUBSTRATE_ENABLE_POLKAVM=1 SUBSTRATE_RUNTIME_TARGET=riscv cargo build --release -p gemini-node" >&2
	exit 1
fi
if [[ ! -f "$MEMBERSHIP_VK" ]]; then
	echo "membership vk not found at $MEMBERSHIP_VK (set MEMBERSHIP_VK=...)" >&2
	exit 1
fi

GEMINI_NODE_HASH="$(python3 -c "import hashlib,sys;print(hashlib.blake2b(open(sys.argv[1],'rb').read(),digest_size=32).hexdigest())" "$NODE_BIN")"
export ROSTRO_CANONICAL_GEMINI_NODE_HASH="$GEMINI_NODE_HASH"
echo "canonical gemini-node hash (blake2_256): 0x${GEMINI_NODE_HASH}"
echo "membership vk:                           $MEMBERSHIP_VK"

ALICE_NODE_KEY="0000000000000000000000000000000000000000000000000000000000000001"
BOB_NODE_KEY="0000000000000000000000000000000000000000000000000000000000000002"
GUARD_NODE_KEY="000000000000000000000000000000000000000000000000000000000000000a"
RELAY2_NODE_KEY="000000000000000000000000000000000000000000000000000000000000000b"
RELAY3_NODE_KEY="000000000000000000000000000000000000000000000000000000000000000c"
ALICE_PEER_ID="12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp"

RIG="${REPO_ROOT}/.spend-rig"
ALICE_BASE="${RIG}/alice"; BOB_BASE="${RIG}/bob"
GUARD_BASE="${RIG}/guard"; RELAY2_BASE="${RIG}/relay2"; RELAY3_BASE="${RIG}/relay3"

setup_node_cache() {
	local base="$1"
	mkdir -p "$base/canonical-cache"
	rm -f "$base/canonical-cache/gemini-node"
	ln "$NODE_BIN" "$base/canonical-cache/gemini-node"
}
for b in "$ALICE_BASE" "$BOB_BASE" "$GUARD_BASE" "$RELAY2_BASE" "$RELAY3_BASE"; do
	mkdir -p "$b"; setup_node_cache "$b"
done

echo "injecting Sassafras + GRANDPA keys for the 2 validators..."
"$NODE_BIN" key insert --key-type sass --suri //Alice --base-path "$ALICE_BASE" --chain gemini-star
"$NODE_BIN" key insert --key-type sass --suri //Bob   --base-path "$BOB_BASE"   --chain gemini-star
"$NODE_BIN" key insert --suri //Alice --key-type gran --base-path "$ALICE_BASE" --chain star
"$NODE_BIN" key insert --suri //Bob   --key-type gran --base-path "$BOB_BASE"   --chain star

BOOTNODES_MULTIADDR="/ip4/127.0.0.1/tcp/30333/p2p/${ALICE_PEER_ID}"
COMMON_VALIDATOR=(--chain star --no-mdns --validator --rpc-cors=all -l "$LOG_FILTER")
COMMON_GUARD=(--chain star --no-mdns --rpc-cors=all -l "$LOG_FILTER" --chat-membership-vk "$MEMBERSHIP_VK")

ALICE_ARGS=("${COMMON_VALIDATOR[@]}" --name alice-star --base-path "$ALICE_BASE"
	--node-key "$ALICE_NODE_KEY" --port 30333 --rpc-port 9944 --prometheus-port 9615
	--canonical-files-dir "$ALICE_BASE/canonical-cache" --alice)
BOB_ARGS=("${COMMON_VALIDATOR[@]}" --name bob-star --base-path "$BOB_BASE"
	--node-key "$BOB_NODE_KEY" --port 30334 --rpc-port 9945 --prometheus-port 9616
	--bootnodes "$BOOTNODES_MULTIADDR" --canonical-files-dir "$BOB_BASE/canonical-cache" --bob)
GUARD_ARGS=("${COMMON_GUARD[@]}" --name guard --base-path "$GUARD_BASE"
	--node-key "$GUARD_NODE_KEY" --listen-addr "/ip4/0.0.0.0/tcp/30340" --rpc-port 9954 --prometheus-port 9670
	--bootnodes "$BOOTNODES_MULTIADDR" --canonical-files-dir "$GUARD_BASE/canonical-cache")
RELAY2_ARGS=("${COMMON_GUARD[@]}" --name relay2 --base-path "$RELAY2_BASE"
	--node-key "$RELAY2_NODE_KEY" --listen-addr "/ip4/0.0.0.0/tcp/30341" --rpc-port 9955 --prometheus-port 9671
	--bootnodes "$BOOTNODES_MULTIADDR" --canonical-files-dir "$RELAY2_BASE/canonical-cache")
RELAY3_ARGS=("${COMMON_GUARD[@]}" --name relay3 --base-path "$RELAY3_BASE"
	--node-key "$RELAY3_NODE_KEY" --listen-addr "/ip4/0.0.0.0/tcp/30342" --rpc-port 9956 --prometheus-port 9672
	--bootnodes "$BOOTNODES_MULTIADDR" --canonical-files-dir "$RELAY3_BASE/canonical-cache")

cleanup() {
	echo; echo "stopping spend rig..."
	for pid in "${PIDS[@]:-}"; do [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true; done
	wait 2>/dev/null || true
}
trap cleanup INT TERM EXIT
PIDS=()
launch() {
	local label="$1" base="$2"; shift 2
	"$NODE_BIN" "$@" 2>&1 | tee "$base/run.log" | sed "s/^/[$label] /" &
	PIDS+=($!)
}

echo "starting alice-star (validator, bootnode)..."
launch "alice " "$ALICE_BASE" "${ALICE_ARGS[@]}"
sleep 4
echo "starting bob-star (validator)..."
launch "bob   " "$BOB_BASE" "${BOB_ARGS[@]}"
echo "starting guard, relay2, relay3 (non-validator guards, membership auth ON)..."
launch "guard " "$GUARD_BASE" "${GUARD_ARGS[@]}"
launch "relay2" "$RELAY2_BASE" "${RELAY2_ARGS[@]}"
launch "relay3" "$RELAY3_BASE" "${RELAY3_ARGS[@]}"

echo
echo "rig up. guard node-keys (for enroll-node):"
echo "  guard  (rpc 9954): node-key ...0a"
echo "  relay2 (rpc 9955): node-key ...0b"
echo "  relay3 (rpc 9956): node-key ...0c"
echo "query each guard's pubkey with: labtool ... / rpc chat_nodeInfo"
wait
