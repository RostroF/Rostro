#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# 3-validator + 1-eavesdropper smoke test of the canonical-files
# gate + validator-channel stack.
#
# Roles:
#   alice    — validator, bootnode (port 30333)
#   bob      — validator (port 30334)
#   charlie  — validator (port 30335)
#   dave     — NON-validator eavesdropper (port 30336): same binary,
#              same canonical-cache, joins libp2p, but no Sassafras
#              key and no --validator flag, so:
#                * He has no local GRANDPA key → asker doesn't start
#                * His handshake-server isn't registered → validators
#                  trying to initiate with him get "protocol not
#                  supported"
#                * He receives encrypted notification-protocol bytes
#                  but has no Session keys to decrypt them
#              He sees that wire traffic exists between validators
#              but cannot read it.
#
# What this demonstrates:
#   * Canonical-files gate fires on all 4 nodes →
#     "all 1 canonical files verified" on each.
#   * 3 pairwise validator-channel sessions among Alice/Bob/Charlie
#     (alice↔bob, alice↔charlie, bob↔charlie) → each validator
#     logs sessions with 2 distinct peers.
#   * Dave logs NO sessions established (eavesdropper locked out).
#   * Encrypted heartbeats flow between validators after ~10s.
#   * Block production rotates among Alice/Bob/Charlie.
#
# Known limitation: GRANDPA finality needs 4 of 5 votes from the
# baked-in 5-authority set. Running 3 won't reach the quorum, so
# finality WILL stall. Block PRODUCTION should still rotate. Use
# `run-star.sh` for full 5-of-5 finality testing.

set -euo pipefail

# Log filter for the gemini-node `-l` flag (Substrate uses `--log`,
# not RUST_LOG). Default: INFO for everything. Override to debug a
# specific target, e.g. `LOG_FILTER="info,rostro-validator-channel=debug"`.
LOG_FILTER="${LOG_FILTER:-info}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NODE_BIN="${GEMINI_NODE:-${REPO_ROOT}/target/release/gemini-node}"
SUPERVISOR_BIN="${ROSTRO_SUPERVISOR:-${REPO_ROOT}/target/release/rostro-supervisor}"

for bin in "$NODE_BIN" "$SUPERVISOR_BIN"; do
	if [[ ! -x "$bin" ]]; then
		echo "binary not found at $bin" >&2
		echo "  build first:  \\" >&2
		echo "                  cargo build --release -p gemini-node -p rostro-supervisor" >&2
		echo "  (the part embeds a PVM-compiled runtime blob;" >&2
		echo "   without it the executor errors with 'blob doesn't start with the expected magic bytes')" >&2
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

ALICE_NODE_KEY="0000000000000000000000000000000000000000000000000000000000000001"
BOB_NODE_KEY="0000000000000000000000000000000000000000000000000000000000000002"
CHARLIE_NODE_KEY="0000000000000000000000000000000000000000000000000000000000000003"
DAVE_NODE_KEY="0000000000000000000000000000000000000000000000000000000000000004"
ALICE_PEER_ID="12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp"

ALICE_BASE="${REPO_ROOT}/.star/alice"
BOB_BASE="${REPO_ROOT}/.star/bob"
CHARLIE_BASE="${REPO_ROOT}/.star/charlie"
DAVE_BASE="${REPO_ROOT}/.star/dave"

mkdir -p "$ALICE_BASE" "$BOB_BASE" "$CHARLIE_BASE" "$DAVE_BASE"

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

# Sassafras keys ONLY for the 3 validators. Dave deliberately skipped.
echo "injecting Sassafras keys for 3 validators (NOT dave)..."
"$NODE_BIN" key insert --key-type sass --suri //Alice   --base-path "$ALICE_BASE"   --chain gemini-star
"$NODE_BIN" key insert --key-type sass --suri //Bob     --base-path "$BOB_BASE"     --chain gemini-star
"$NODE_BIN" key insert --key-type sass --suri //Charlie --base-path "$CHARLIE_BASE" --chain gemini-star

# GRANDPA Ed25519 keys for the 3 validators. The `--alice` etc. dev
# flags do NOT auto-inject GRANDPA keys into the local keystore in
# this runtime; we have to do it explicitly. Without this, GRANDPA
# voting can't happen (no local signing key) AND the validator-
# channel asker thinks we're not a validator (no GRANDPA pubkey to
# claim).
echo "injecting GRANDPA Ed25519 keys for 3 validators..."
"$NODE_BIN" key insert --suri //Alice   --key-type gran --base-path "$ALICE_BASE"   --chain star
"$NODE_BIN" key insert --suri //Bob     --key-type gran --base-path "$BOB_BASE"     --chain star
"$NODE_BIN" key insert --suri //Charlie --key-type gran --base-path "$CHARLIE_BASE" --chain star

COMMON_VALIDATOR=(--chain star --no-mdns --validator --rpc-cors=all -l "$LOG_FILTER")
COMMON_EAVESDROPPER=(--chain star --no-mdns --rpc-cors=all -l "$LOG_FILTER")
BOOTNODES_MULTIADDR="/ip4/127.0.0.1/tcp/30333/p2p/${ALICE_PEER_ID}"

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
CHARLIE_ARGS=(
	"${COMMON_VALIDATOR[@]}"
	--name charlie-star --base-path "$CHARLIE_BASE"
	--node-key "$CHARLIE_NODE_KEY"
	--port 30335 --rpc-port 9946 --prometheus-port 9617
	--bootnodes "$BOOTNODES_MULTIADDR"
	--canonical-files-dir "$CHARLIE_BASE/canonical-cache"
	--charlie
)
# Dave: NO --validator flag, NO well-known dev-key flag (--alice/etc),
# NO Sassafras key in keystore. He's a vanilla full node that
# happens to be on the same chain.
DAVE_ARGS=(
	"${COMMON_EAVESDROPPER[@]}"
	--name dave-eavesdropper --base-path "$DAVE_BASE"
	--node-key "$DAVE_NODE_KEY"
	--port 30336 --rpc-port 9947 --prometheus-port 9618
	--bootnodes "$BOOTNODES_MULTIADDR"
	--canonical-files-dir "$DAVE_BASE/canonical-cache"
)

cleanup() {
	echo
	echo "stopping trio + eavesdropper..."
	for pid in "${PIDS[@]:-}"; do
		[[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
	done
	wait 2>/dev/null || true
}
trap cleanup INT TERM EXIT

PIDS=()

echo "starting alice (validator, bootnode)..."
"$SUPERVISOR_BIN" --child "$ALICE_BASE/canonical-cache/gemini-node" --canonical-dir "$ALICE_BASE/canonical-cache" -- "${ALICE_ARGS[@]}" 2>&1 | tee "$ALICE_BASE/run.log" | sed 's/^/[alice]   /' &
PIDS+=($!)

sleep 3

echo "starting bob (validator)..."
"$SUPERVISOR_BIN" --child "$BOB_BASE/canonical-cache/gemini-node" --canonical-dir "$BOB_BASE/canonical-cache" -- "${BOB_ARGS[@]}" 2>&1 | tee "$BOB_BASE/run.log" | sed 's/^/[bob]     /' &
PIDS+=($!)

echo "starting charlie (validator)..."
"$SUPERVISOR_BIN" --child "$CHARLIE_BASE/canonical-cache/gemini-node" --canonical-dir "$CHARLIE_BASE/canonical-cache" -- "${CHARLIE_ARGS[@]}" 2>&1 | tee "$CHARLIE_BASE/run.log" | sed 's/^/[charlie] /' &
PIDS+=($!)

echo "starting dave (NON-validator eavesdropper)..."
"$SUPERVISOR_BIN" --child "$DAVE_BASE/canonical-cache/gemini-node" --canonical-dir "$DAVE_BASE/canonical-cache" -- "${DAVE_ARGS[@]}" 2>&1 | tee "$DAVE_BASE/run.log" | sed 's/^/[dave]    /' &
PIDS+=($!)

wait
