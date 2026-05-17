#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Spawn the Phase Star 5-node star — five `gemini-node` processes on
# this machine that peer in a star topology (Alice is the bootnode;
# Bob, Charlie, Dave, Eve all dial Alice), rotate Sassafras block
# authoring across the five-element authority set, and finalize blocks
# via GRANDPA. Phase Star's deliverable — earns the gemini-node rename
# per memory `[network_vs_binary_lineage]` once the star peers + finalizes.
#
# Usage:
#   scripts/run-star.sh              # all five in foreground (Ctrl-C kills all)
#
# All five nodes use deterministic libp2p node-keys so peer ids are stable
# across runs.

set -euo pipefail

# Required at runtime so polkavm-magic blobs are accepted.
export SUBSTRATE_ENABLE_POLKAVM="${SUBSTRATE_ENABLE_POLKAVM:-1}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NODE_BIN="${GEMINI_NODE:-${REPO_ROOT}/target/release/gemini-node}"

if [[ ! -x "$NODE_BIN" ]]; then
	echo "gemini-node binary not found at $NODE_BIN" >&2
	echo "  build it first:  SUBSTRATE_ENABLE_POLKAVM=1 cargo build --release -p gemini-node" >&2
	exit 1
fi

# Deterministic libp2p node-keys for the five-node star. Dev-only —
# DO NOT use on the production network. Anyone with the repo can derive
# the corresponding peer ids and impersonate any node.
ALICE_NODE_KEY="0000000000000000000000000000000000000000000000000000000000000001"
BOB_NODE_KEY="0000000000000000000000000000000000000000000000000000000000000002"
CHARLIE_NODE_KEY="0000000000000000000000000000000000000000000000000000000000000003"
DAVE_NODE_KEY="0000000000000000000000000000000000000000000000000000000000000004"
EVE_NODE_KEY="0000000000000000000000000000000000000000000000000000000000000005"

# Peer ids derived once via `gemini-node key inspect-node-key` and pinned
# so the script is self-contained:
#   echo -n <NODE_KEY> | gemini-node key inspect-node-key
ALICE_PEER_ID="12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp"

ALICE_BASE="${REPO_ROOT}/.star/alice"
BOB_BASE="${REPO_ROOT}/.star/bob"
CHARLIE_BASE="${REPO_ROOT}/.star/charlie"
DAVE_BASE="${REPO_ROOT}/.star/dave"
EVE_BASE="${REPO_ROOT}/.star/eve"

mkdir -p "$ALICE_BASE" "$BOB_BASE" "$CHARLIE_BASE" "$DAVE_BASE" "$EVE_BASE"

# Inject the Sassafras (bandersnatch) authority key for each validator.
# Stock `--alice` / `--bob` / etc only cover sr25519/ed25519/ecdsa.
# Idempotent — safe to re-run.
echo "injecting Sassafras bandersnatch keys for all 5 nodes..."
"$NODE_BIN" insert-sassafras-key --suri //Alice   --base-path "$ALICE_BASE"   --chain-id gemini-star
"$NODE_BIN" insert-sassafras-key --suri //Bob     --base-path "$BOB_BASE"     --chain-id gemini-star
"$NODE_BIN" insert-sassafras-key --suri //Charlie --base-path "$CHARLIE_BASE" --chain-id gemini-star
"$NODE_BIN" insert-sassafras-key --suri //Dave    --base-path "$DAVE_BASE"    --chain-id gemini-star
"$NODE_BIN" insert-sassafras-key --suri //Eve     --base-path "$EVE_BASE"     --chain-id gemini-star

COMMON_ARGS=(
	--chain star
	--no-mdns
	--validator
	--rpc-cors=all
)

# Leaves dial Alice (the bootnode). Star topology = one hub + four spokes.
BOOTNODES_MULTIADDR="/ip4/127.0.0.1/tcp/30333/p2p/${ALICE_PEER_ID}"

ALICE_ARGS=(
	"${COMMON_ARGS[@]}"
	--name "alice-star" --base-path "$ALICE_BASE"
	--node-key "$ALICE_NODE_KEY"
	--port 30333 --rpc-port 9944 --prometheus-port 9615
	--alice
)
BOB_ARGS=(
	"${COMMON_ARGS[@]}"
	--name "bob-star" --base-path "$BOB_BASE"
	--node-key "$BOB_NODE_KEY"
	--port 30334 --rpc-port 9945 --prometheus-port 9616
	--bootnodes "$BOOTNODES_MULTIADDR"
	--bob
)
CHARLIE_ARGS=(
	"${COMMON_ARGS[@]}"
	--name "charlie-star" --base-path "$CHARLIE_BASE"
	--node-key "$CHARLIE_NODE_KEY"
	--port 30335 --rpc-port 9946 --prometheus-port 9617
	--bootnodes "$BOOTNODES_MULTIADDR"
	--charlie
)
DAVE_ARGS=(
	"${COMMON_ARGS[@]}"
	--name "dave-star" --base-path "$DAVE_BASE"
	--node-key "$DAVE_NODE_KEY"
	--port 30336 --rpc-port 9947 --prometheus-port 9618
	--bootnodes "$BOOTNODES_MULTIADDR"
	--dave
)
EVE_ARGS=(
	"${COMMON_ARGS[@]}"
	--name "eve-star" --base-path "$EVE_BASE"
	--node-key "$EVE_NODE_KEY"
	--port 30337 --rpc-port 9948 --prometheus-port 9619
	--bootnodes "$BOOTNODES_MULTIADDR"
	--eve
)

cleanup() {
	echo
	echo "stopping star..."
	for pid in "${ALICE_PID:-}" "${BOB_PID:-}" "${CHARLIE_PID:-}" "${DAVE_PID:-}" "${EVE_PID:-}"; do
		[[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
	done
	wait 2>/dev/null || true
}
trap cleanup INT TERM EXIT

echo "starting alice-star (bootnode, port 30333, rpc 9944, peer id $ALICE_PEER_ID)..."
"$NODE_BIN" "${ALICE_ARGS[@]}" 2>&1 | sed 's/^/[alice]   /' &
ALICE_PID=$!

# Alice needs a beat to bind the listener before the leaves dial.
sleep 3

echo "starting bob-star (port 30334, rpc 9945)..."
"$NODE_BIN" "${BOB_ARGS[@]}" 2>&1 | sed 's/^/[bob]     /' &
BOB_PID=$!

echo "starting charlie-star (port 30335, rpc 9946)..."
"$NODE_BIN" "${CHARLIE_ARGS[@]}" 2>&1 | sed 's/^/[charlie] /' &
CHARLIE_PID=$!

echo "starting dave-star (port 30336, rpc 9947)..."
"$NODE_BIN" "${DAVE_ARGS[@]}" 2>&1 | sed 's/^/[dave]    /' &
DAVE_PID=$!

echo "starting eve-star (port 30337, rpc 9948)..."
"$NODE_BIN" "${EVE_ARGS[@]}" 2>&1 | sed 's/^/[eve]     /' &
EVE_PID=$!

wait
