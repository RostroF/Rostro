#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Spawn the Gemini twin lab — two `rostro-node` processes on this machine
# that peer with each other, rotate authority (Alice + Bob), and finalize
# blocks via GRANDPA. Phase Gemini's primary verification harness.
#
# Usage:
#   scripts/run-gemini.sh            # both twins in the foreground (Ctrl-C kills both)
#   scripts/run-gemini.sh --tmux     # split into a tmux pane (one node per pane)
#
# Both twins use deterministic libp2p node-keys (32-byte hex), so peer ids
# are stable across runs and the second twin can dial the first by a
# fixed multiaddr.

set -euo pipefail

# Phase Star B8: required at runtime to load the PVM runtime blob.
# `RuntimeBlob::new` rejects PolkaVM-magic blobs unless this is set.
export SUBSTRATE_ENABLE_POLKAVM="${SUBSTRATE_ENABLE_POLKAVM:-1}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Phase Star B8: switched from rostro-node to gemini-node. gemini-node is
# the Sassafras-flavoured binary that loads `gemini-runtime` (compiled
# to PVM via SUBSTRATE_RUNTIME_TARGET=riscv). rostro-node runs the
# Aura-based rostro-runtime and has no `gemini-local` chain spec.
NODE_BIN="${GEMINI_NODE:-${REPO_ROOT}/target/release/gemini-node}"

if [[ ! -x "$NODE_BIN" ]]; then
	echo "gemini-node binary not found at $NODE_BIN" >&2
	echo "  build it first:  SUBSTRATE_ENABLE_POLKAVM=1 cargo build --release -p gemini-node" >&2
	exit 1
fi

# Deterministic libp2p node-keys for the twins. These are dev-only
# constants — DO NOT use them on the production network. Anyone with the
# repo can derive the corresponding peer id and impersonate the node.
ALICE_NODE_KEY="0000000000000000000000000000000000000000000000000000000000000001"
BOB_NODE_KEY="0000000000000000000000000000000000000000000000000000000000000002"

# Peer id derived from ALICE_NODE_KEY (computed once via:
#   echo -n "$ALICE_NODE_KEY" | hex2bin | rostro-node key inspect-node-key
# pinned here so the script is self-contained).
ALICE_PEER_ID="12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp"

# Working directories — distinct per twin so neither stomps on the other.
ALICE_BASE="${REPO_ROOT}/.gemini/alice"
BOB_BASE="${REPO_ROOT}/.gemini/bob"

mkdir -p "$ALICE_BASE" "$BOB_BASE"

# Phase Star B8: gemini's Sassafras (bandersnatch) authority key isn't
# injected by the stock `--alice` / `--bob` keyring flags. Inject the
# bandersnatch keys via `key insert --key-type sass` (scheme derived
# from the key type) before launch. Safe
# to re-run: keystore inserts are idempotent for the same SURI.
echo "injecting Alice + Bob Sassafras (bandersnatch) keys..."
"$NODE_BIN" key insert --key-type sass \
	--suri //Alice --base-path "$ALICE_BASE" --chain gemini-local
"$NODE_BIN" key insert --key-type sass \
	--suri //Bob --base-path "$BOB_BASE" --chain gemini-local

# Common arguments. --no-mdns avoids cross-machine surprises during the
# lab; we explicitly set the bootnodes multiaddr.
COMMON_ARGS=(
	--chain local
	--no-mdns
	--validator
	--rpc-cors=all
)

ALICE_ARGS=(
	"${COMMON_ARGS[@]}"
	--name "alice-twin"
	--base-path "$ALICE_BASE"
	--node-key "$ALICE_NODE_KEY"
	--port 30333
	--rpc-port 9944
	--prometheus-port 9615
	--alice
)

BOB_ARGS=(
	"${COMMON_ARGS[@]}"
	--name "bob-twin"
	--base-path "$BOB_BASE"
	--node-key "$BOB_NODE_KEY"
	--port 30334
	--rpc-port 9945
	--prometheus-port 9616
	--bootnodes "/ip4/127.0.0.1/tcp/30333/p2p/${ALICE_PEER_ID}"
	--bob
)

cleanup() {
	echo
	echo "stopping twins..."
	[[ -n "${ALICE_PID:-}" ]] && kill "$ALICE_PID" 2>/dev/null || true
	[[ -n "${BOB_PID:-}" ]] && kill "$BOB_PID" 2>/dev/null || true
	wait 2>/dev/null || true
}
trap cleanup INT TERM EXIT

echo "starting alice-twin (port 30333, rpc 9944, peer id $ALICE_PEER_ID)..."
"$NODE_BIN" "${ALICE_ARGS[@]}" 2>&1 | sed 's/^/[alice] /' &
ALICE_PID=$!

# Give Alice a beat to boot before Bob tries to dial.
sleep 2

echo "starting bob-twin (port 30334, rpc 9945, dialing alice)..."
"$NODE_BIN" "${BOB_ARGS[@]}" 2>&1 | sed 's/^/[bob]   /' &
BOB_PID=$!

wait
