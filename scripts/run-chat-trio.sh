#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Three-node NON-validator chat-relay trio. Spawns three gemini-node
# processes peered in a star topology where none of them are
# validators (no Sassafras keys, no GRANDPA keys, no --validator
# flag). They exist purely to carry chat-gossip + chat-stripe +
# chat-fetch protocols.
#
# Why non-validators specifically: the chat layer's channel-split
# invariant rejects chat traffic between known validators (validators
# focus on consensus; chat is for non-validators). For a chat demo
# to actually show cross-node distribution, we need a non-validator
# relay fabric. This script provides that fabric.
#
# The chain runs but produces no blocks (no validator quorum) —
# that's fine for chat, which doesn't depend on block production.
#
# Topology:
#   alice-chat   — non-validator, bootnode (port 30340, RPC 9954)
#   bob-chat     — non-validator, dials alice (port 30341, RPC 9955)
#   charlie-chat — non-validator, dials alice (port 30342, RPC 9956)
#
# All three subscribe to all 256 buckets on /rostro/chat-gossip/1 by
# default (v0.1 demo behavior), so any node can receive any message
# regardless of pickup-key bucket. Bucket-filtering kicks in only
# once operators dial subscriptions down for capacity reasons.
#
# Usage:
#   scripts/run-chat-trio.sh        # foreground; Ctrl-C kills all

set -euo pipefail

LOG_FILTER="${LOG_FILTER:-info,rostro-chat-gossip=debug,rostro-chat-rpc=debug,rostro-chat-stripe=debug,rostro-chat-fetch=debug}"

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
if [[ ${#GEMINI_NODE_HASH} -ne 64 ]]; then
	echo "computed canonical hash is ${#GEMINI_NODE_HASH} chars; expected 64" >&2
	exit 1
fi
export ROSTRO_CANONICAL_GEMINI_NODE_HASH="$GEMINI_NODE_HASH"
echo "canonical gemini-node hash: 0x${GEMINI_NODE_HASH}"

# Deterministic libp2p node-keys for the chat trio. Same caveat as
# the validator trio: dev-only, do NOT use on production.
ALICE_NODE_KEY="000000000000000000000000000000000000000000000000000000000000000a"
BOB_NODE_KEY="000000000000000000000000000000000000000000000000000000000000000b"
CHARLIE_NODE_KEY="000000000000000000000000000000000000000000000000000000000000000c"

# Peer ID for the bootnode, derived from ALICE_NODE_KEY via
#   echo -n 000000000000000000000000000000000000000000000000000000000000000a \
#     | <node-bin> key inspect-node-key --file <(cat)
# Pinned here so the script is self-contained.
ALICE_PEER_ID="12D3KooWFNChUebWM7RHCWhypQs6rvs6B8RtKeFXxtR3zT3fchCU"

ALICE_BASE="${REPO_ROOT}/.chat-trio/alice"
BOB_BASE="${REPO_ROOT}/.chat-trio/bob"
CHARLIE_BASE="${REPO_ROOT}/.chat-trio/charlie"

mkdir -p "$ALICE_BASE" "$BOB_BASE" "$CHARLIE_BASE"

setup_node_cache() {
	local base="$1"
	mkdir -p "$base/canonical-cache"
	rm -f "$base/canonical-cache/gemini-node"
	ln "$NODE_BIN" "$base/canonical-cache/gemini-node"
}
setup_node_cache "$ALICE_BASE"
setup_node_cache "$BOB_BASE"
setup_node_cache "$CHARLIE_BASE"

# NO Sassafras keys, NO GRANDPA keys, NO --validator flag.
# Channel-split admission requires this: validators reject chat
# traffic between themselves.
COMMON=(--chain star --no-mdns --rpc-cors=all -l "$LOG_FILTER")
BOOTNODES_MULTIADDR="/ip4/127.0.0.1/tcp/30340/p2p/${ALICE_PEER_ID}"

# --listen-addr explicit plain TCP. Upstream Substrate's default
# listener branches on is_validator || is_dev: validators get plain
# /tcp, non-validators get /tcp/ws (WebSocket upgrade for browser-
# light-client convenience). Our non-validator chat trio wants
# peer-to-peer TCP, not WS, so we override the default explicitly.
# Without this override, bob/charlie dial plain TCP into alice's
# /ws listener and multistream-select fails to negotiate.
# See substrate/client/cli/src/params/network_params.rs:208-232.
ALICE_ARGS=(
	"${COMMON[@]}"
	--name alice-chat --base-path "$ALICE_BASE"
	--node-key "$ALICE_NODE_KEY"
	--listen-addr "/ip4/0.0.0.0/tcp/30340"
	--rpc-port 9954 --prometheus-port 9670
	--canonical-files-dir "$ALICE_BASE/canonical-cache"
)
BOB_ARGS=(
	"${COMMON[@]}"
	--name bob-chat --base-path "$BOB_BASE"
	--node-key "$BOB_NODE_KEY"
	--listen-addr "/ip4/0.0.0.0/tcp/30341"
	--rpc-port 9955 --prometheus-port 9671
	--bootnodes "$BOOTNODES_MULTIADDR"
	--canonical-files-dir "$BOB_BASE/canonical-cache"
)
CHARLIE_ARGS=(
	"${COMMON[@]}"
	--name charlie-chat --base-path "$CHARLIE_BASE"
	--node-key "$CHARLIE_NODE_KEY"
	--listen-addr "/ip4/0.0.0.0/tcp/30342"
	--rpc-port 9956 --prometheus-port 9672
	--bootnodes "$BOOTNODES_MULTIADDR"
	--canonical-files-dir "$CHARLIE_BASE/canonical-cache"
)

cleanup() {
	echo
	echo "stopping chat trio..."
	for pid in "${PIDS[@]:-}"; do
		[[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
	done
	wait 2>/dev/null || true
}
trap cleanup INT TERM EXIT

PIDS=()

echo "starting alice-chat (non-validator, bootnode)..."
"$SUPERVISOR_BIN" --child "$ALICE_BASE/canonical-cache/gemini-node" --canonical-dir "$ALICE_BASE/canonical-cache" -- "${ALICE_ARGS[@]}" 2>&1 | tee "$ALICE_BASE/run.log" | sed 's/^/[alice]   /' &
PIDS+=($!)

sleep 3

echo "starting bob-chat (non-validator)..."
"$SUPERVISOR_BIN" --child "$BOB_BASE/canonical-cache/gemini-node" --canonical-dir "$BOB_BASE/canonical-cache" -- "${BOB_ARGS[@]}" 2>&1 | tee "$BOB_BASE/run.log" | sed 's/^/[bob]     /' &
PIDS+=($!)

echo "starting charlie-chat (non-validator)..."
"$SUPERVISOR_BIN" --child "$CHARLIE_BASE/canonical-cache/gemini-node" --canonical-dir "$CHARLIE_BASE/canonical-cache" -- "${CHARLIE_ARGS[@]}" 2>&1 | tee "$CHARLIE_BASE/run.log" | sed 's/^/[charlie] /' &
PIDS+=($!)

wait
