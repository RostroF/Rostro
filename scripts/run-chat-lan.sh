#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# LAN chat-relay node — Phase 0 lab variant of run-chat-trio.sh, for
# running ONE non-validator relay per machine across the 3 lab laptops
# so the 2 Samsung phones can reach the chat RPC over the network.
#
# Difference from run-chat-trio.sh (single-box): one role per host,
# the bootnode points at the alice-laptop's LAN IP, and the JSON-RPC
# is exposed on all interfaces (--rpc-external) so the phones can call
# chat_send_envelope / chat_fetch_shares over the LAN. The single-box
# trio keeps RPC on localhost, which phones can't reach.
#
# Topology (one per laptop):
#   alice   — bootnode      P2P 30340  RPC 9954   (run FIRST)
#   bob     — dials alice    P2P 30341  RPC 9955
#   charlie — dials alice    P2P 30342  RPC 9956
#
# Usage (run on each laptop):
#   # laptop 1 (the bootnode) — note its LAN IP, e.g. 192.168.1.10:
#   ROLE=alice scripts/run-chat-lan.sh
#   # laptop 2:
#   ROLE=bob   BOOTNODE_IP=192.168.1.10 scripts/run-chat-lan.sh
#   # laptop 3:
#   ROLE=charlie BOOTNODE_IP=192.168.1.10 scripts/run-chat-lan.sh
#
# Then point the phones (dotwave → Messages → node setting) at a relay:
#   phone A:  ws://192.168.1.10:9954   (alice)
#   phone B:  ws://<charlie-laptop-ip>:9956   (charlie) — cross-node test
#
# SECURITY: --rpc-external + --rpc-methods unsafe is LAN-LAB ONLY. Never
# expose this to a public network.

set -euo pipefail

ROLE="${ROLE:-}"
if [[ -z "$ROLE" ]]; then
	echo "set ROLE=alice|bob|charlie (see header for usage)" >&2
	exit 1
fi

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

command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }

GEMINI_NODE_HASH="$(python3 -c "import hashlib,sys;print(hashlib.blake2b(open(sys.argv[1],'rb').read(),digest_size=32).hexdigest())" "$NODE_BIN")"
[[ ${#GEMINI_NODE_HASH} -eq 64 ]] || { echo "bad canonical hash length" >&2; exit 1; }
export ROSTRO_CANONICAL_GEMINI_NODE_HASH="$GEMINI_NODE_HASH"
echo "canonical gemini-node hash: 0x${GEMINI_NODE_HASH}"

# Deterministic libp2p node-keys (dev-only — do NOT use in production).
ALICE_NODE_KEY="000000000000000000000000000000000000000000000000000000000000000a"
BOB_NODE_KEY="000000000000000000000000000000000000000000000000000000000000000b"
CHARLIE_NODE_KEY="000000000000000000000000000000000000000000000000000000000000000c"
# Pinned peer id for ALICE_NODE_KEY (bootnode address component).
ALICE_PEER_ID="12D3KooWFNChUebWM7RHCWhypQs6rvs6B8RtKeFXxtR3zT3fchCU"

case "$ROLE" in
	alice)   NODE_KEY="$ALICE_NODE_KEY"; NAME="alice-chat";   P2P=30340; RPC=9954; PROM=9670; NEEDS_BOOT=0 ;;
	bob)     NODE_KEY="$BOB_NODE_KEY";   NAME="bob-chat";     P2P=30341; RPC=9955; PROM=9671; NEEDS_BOOT=1 ;;
	charlie) NODE_KEY="$CHARLIE_NODE_KEY"; NAME="charlie-chat"; P2P=30342; RPC=9956; PROM=9672; NEEDS_BOOT=1 ;;
	*) echo "ROLE must be alice|bob|charlie (got '$ROLE')" >&2; exit 1 ;;
esac

BASE="${REPO_ROOT}/.chat-lan/${ROLE}"
mkdir -p "$BASE/canonical-cache"
rm -f "$BASE/canonical-cache/gemini-node"
ln "$NODE_BIN" "$BASE/canonical-cache/gemini-node"

ARGS=(
	--chain star --no-mdns --rpc-cors=all -l "$LOG_FILTER"
	--name "$NAME" --base-path "$BASE"
	--node-key "$NODE_KEY"
	--listen-addr "/ip4/0.0.0.0/tcp/${P2P}"
	--rpc-port "$RPC" --prometheus-port "$PROM"
	# Expose RPC on the LAN so the phones can reach chat_send/chat_fetch.
	# LAB ONLY.
	--rpc-external --rpc-methods unsafe
	--canonical-files-dir "$BASE/canonical-cache"
)

if [[ "$NEEDS_BOOT" -eq 1 ]]; then
	BOOTNODE_IP="${BOOTNODE_IP:-}"
	if [[ -z "$BOOTNODE_IP" ]]; then
		echo "ROLE=$ROLE requires BOOTNODE_IP=<alice-laptop-LAN-ip>" >&2
		exit 1
	fi
	ARGS+=(--bootnodes "/ip4/${BOOTNODE_IP}/tcp/30340/p2p/${ALICE_PEER_ID}")
fi

cleanup() { echo; echo "stopping ${NAME}..."; [[ -n "${PID:-}" ]] && kill "$PID" 2>/dev/null || true; wait 2>/dev/null || true; }
trap cleanup INT TERM EXIT

echo "starting ${NAME} (non-validator relay, P2P ${P2P}, RPC ${RPC} exposed on LAN)..."
echo "  phones reach this node at:  ws://<this-laptop-LAN-ip>:${RPC}"
"$SUPERVISOR_BIN" --child "$BASE/canonical-cache/gemini-node" --canonical-dir "$BASE/canonical-cache" -- "${ARGS[@]}" 2>&1 | tee "$BASE/run.log" | sed "s/^/[${ROLE}] /" &
PID=$!
wait
