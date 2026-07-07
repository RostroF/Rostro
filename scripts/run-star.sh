#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Spawn the Phase Star 5-node star — five `gemini-node` processes on
# this machine that peer in a star topology (Alice is the bootnode;
# Bob, Charlie, Dave, Eve all dial Alice), rotate Sassafras block
# authoring across the five-element authority set, and finalize blocks
# via GRANDPA.
#
# Phase 7 v2 wiring (added 2026-05-16):
#   * each gemini-node is wrapped in `rostro-supervisor` so heal-on-
#     mismatch can drive exit-90 → swap → restart
#   * each node has its own canonical-cache dir hard-linking the
#     gemini-node binary, served via `/rostro/canonical-fetch-attested/1`
#   * the gemini-node binary's blake2_256 is computed locally and
#     exported as `ROSTRO_CANONICAL_GEMINI_NODE_HASH` so genesis seeds
#     the canonical-files registry with the real value (verifier
#     runs an actual check, not the empty-registry skip path)
#
# Usage:
#   scripts/run-star.sh              # all five in foreground (Ctrl-C kills all)

set -euo pipefail

# Required at runtime so polkavm-magic blobs are accepted.
export SUBSTRATE_ENABLE_POLKAVM="${SUBSTRATE_ENABLE_POLKAVM:-1}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NODE_BIN="${GEMINI_NODE:-${REPO_ROOT}/target/release/gemini-node}"
SUPERVISOR_BIN="${ROSTRO_SUPERVISOR:-${REPO_ROOT}/target/release/rostro-supervisor}"

for bin in "$NODE_BIN" "$SUPERVISOR_BIN"; do
	if [[ ! -x "$bin" ]]; then
		echo "binary not found at $bin" >&2
		echo "  build first:  SUBSTRATE_ENABLE_POLKAVM=1 cargo build --release -p gemini-node -p rostro-supervisor" >&2
		exit 1
	fi
done

# Compute blake2_256 of the gemini-node binary so the chain spec can
# seed the canonical-files registry at genesis. Python's blake2b with
# digest_size=32 is bit-identical to sp_io::hashing::blake2_256.
if ! command -v python3 >/dev/null 2>&1; then
	echo "python3 is required to compute the gemini-node canonical hash" >&2
	exit 1
fi
GEMINI_NODE_HASH="$(
	python3 -c "import hashlib,sys;print(hashlib.blake2b(open(sys.argv[1],'rb').read(),digest_size=32).hexdigest())" "$NODE_BIN"
)"
if [[ ${#GEMINI_NODE_HASH} -ne 64 ]]; then
	echo "computed canonical hash is ${#GEMINI_NODE_HASH} chars; expected 64" >&2
	exit 1
fi
export ROSTRO_CANONICAL_GEMINI_NODE_HASH="$GEMINI_NODE_HASH"
echo "canonical gemini-node hash (blake2_256): 0x${GEMINI_NODE_HASH}"

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

# Per-node canonical-cache dirs. Each contains a hard-link to the
# gemini-node binary, so:
#   * `--canonical-files-dir` points here for the heal-fetch server
#     to serve canonical bytes to peers
#   * `rostro-supervisor`'s `--child` points to the hard-link inside
#     this dir so `current_exe()` resolves under the cache and
#     post-exit-90 `*.new` rotations land in the right place
#
# Per-node (not shared) so the lab actually exercises cross-node
# heal-fetch: each node serves heal bytes from its own copy. Hard-
# links keep disk usage flat (one inode per binary).
setup_node_cache() {
	local base="$1"
	mkdir -p "$base/canonical-cache"
	# Idempotent: remove + relink so a freshly-built binary picks up.
	rm -f "$base/canonical-cache/gemini-node"
	ln "$NODE_BIN" "$base/canonical-cache/gemini-node"
}
setup_node_cache "$ALICE_BASE"
setup_node_cache "$BOB_BASE"
setup_node_cache "$CHARLIE_BASE"
setup_node_cache "$DAVE_BASE"
setup_node_cache "$EVE_BASE"

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

# GRANDPA Ed25519 keys for each validator. The `--alice` etc. dev
# flags do NOT auto-inject GRANDPA keys into the local keystore in
# this runtime; we have to do it explicitly. Without these,
# GRANDPA voting can't happen (no local signing key) AND the
# validator-channel asker thinks we're not a validator (no GRANDPA
# pubkey in the keystore to claim).
echo "injecting GRANDPA Ed25519 keys for all 5 nodes..."
"$NODE_BIN" key insert --suri //Alice   --key-type gran --scheme rostro-hybrid --base-path "$ALICE_BASE"   --chain star
"$NODE_BIN" key insert --suri //Bob     --key-type gran --scheme rostro-hybrid --base-path "$BOB_BASE"     --chain star
"$NODE_BIN" key insert --suri //Charlie --key-type gran --scheme rostro-hybrid --base-path "$CHARLIE_BASE" --chain star
"$NODE_BIN" key insert --suri //Dave    --key-type gran --scheme rostro-hybrid --base-path "$DAVE_BASE"    --chain star
"$NODE_BIN" key insert --suri //Eve     --key-type gran --scheme rostro-hybrid --base-path "$EVE_BASE"     --chain star

# `--canonical-files-dir` makes the running binary advertise the heal-
# fetch server and serve canonical bytes to peers. Same dir is the
# heal source if our own verifier finds a mismatch on boot.
COMMON_CHILD_ARGS=(
	--chain star
	--no-mdns
	--validator
	--rpc-cors=all
)

# Leaves dial Alice (the bootnode). Star topology = one hub + four spokes.
BOOTNODES_MULTIADDR="/ip4/127.0.0.1/tcp/30333/p2p/${ALICE_PEER_ID}"

# Build the per-node `gemini-node` args. The supervisor wraps these.
ALICE_CHILD_ARGS=(
	"${COMMON_CHILD_ARGS[@]}"
	--name "alice-star" --base-path "$ALICE_BASE"
	--node-key "$ALICE_NODE_KEY"
	--port 30333 --rpc-port 9944 --prometheus-port 9615
	--canonical-files-dir "$ALICE_BASE/canonical-cache"
	--alice
)
BOB_CHILD_ARGS=(
	"${COMMON_CHILD_ARGS[@]}"
	--name "bob-star" --base-path "$BOB_BASE"
	--node-key "$BOB_NODE_KEY"
	--port 30334 --rpc-port 9945 --prometheus-port 9616
	--bootnodes "$BOOTNODES_MULTIADDR"
	--canonical-files-dir "$BOB_BASE/canonical-cache"
	--bob
)
CHARLIE_CHILD_ARGS=(
	"${COMMON_CHILD_ARGS[@]}"
	--name "charlie-star" --base-path "$CHARLIE_BASE"
	--node-key "$CHARLIE_NODE_KEY"
	--port 30335 --rpc-port 9946 --prometheus-port 9617
	--bootnodes "$BOOTNODES_MULTIADDR"
	--canonical-files-dir "$CHARLIE_BASE/canonical-cache"
	--charlie
)
DAVE_CHILD_ARGS=(
	"${COMMON_CHILD_ARGS[@]}"
	--name "dave-star" --base-path "$DAVE_BASE"
	--node-key "$DAVE_NODE_KEY"
	--port 30336 --rpc-port 9947 --prometheus-port 9618
	--bootnodes "$BOOTNODES_MULTIADDR"
	--canonical-files-dir "$DAVE_BASE/canonical-cache"
	--dave
)
EVE_CHILD_ARGS=(
	"${COMMON_CHILD_ARGS[@]}"
	--name "eve-star" --base-path "$EVE_BASE"
	--node-key "$EVE_NODE_KEY"
	--port 30337 --rpc-port 9948 --prometheus-port 9619
	--bootnodes "$BOOTNODES_MULTIADDR"
	--canonical-files-dir "$EVE_BASE/canonical-cache"
	--eve
)

# Build the supervisor command. `--child` points at the per-node
# hard-link so `current_exe()` resolves under that cache (which is
# also `--canonical-dir`); the verifier's hardcoded check path
# resolves "gemini-node" → that hard-link, which hashes to the
# canonical value seeded at genesis.
supervisor_cmd() {
	local base="$1"
	shift
	echo "$SUPERVISOR_BIN --child $base/canonical-cache/gemini-node --canonical-dir $base/canonical-cache -- $*"
}

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
"$SUPERVISOR_BIN" --child "$ALICE_BASE/canonical-cache/gemini-node" --canonical-dir "$ALICE_BASE/canonical-cache" -- "${ALICE_CHILD_ARGS[@]}" 2>&1 | tee "$ALICE_BASE/run.log" | sed 's/^/[alice]   /' &
ALICE_PID=$!

# Alice needs a beat to bind the listener before the leaves dial.
sleep 3

echo "starting bob-star (port 30334, rpc 9945)..."
"$SUPERVISOR_BIN" --child "$BOB_BASE/canonical-cache/gemini-node" --canonical-dir "$BOB_BASE/canonical-cache" -- "${BOB_CHILD_ARGS[@]}" 2>&1 | tee "$BOB_BASE/run.log" | sed 's/^/[bob]     /' &
BOB_PID=$!

echo "starting charlie-star (port 30335, rpc 9946)..."
"$SUPERVISOR_BIN" --child "$CHARLIE_BASE/canonical-cache/gemini-node" --canonical-dir "$CHARLIE_BASE/canonical-cache" -- "${CHARLIE_CHILD_ARGS[@]}" 2>&1 | tee "$CHARLIE_BASE/run.log" | sed 's/^/[charlie] /' &
CHARLIE_PID=$!

echo "starting dave-star (port 30336, rpc 9947)..."
"$SUPERVISOR_BIN" --child "$DAVE_BASE/canonical-cache/gemini-node" --canonical-dir "$DAVE_BASE/canonical-cache" -- "${DAVE_CHILD_ARGS[@]}" 2>&1 | tee "$DAVE_BASE/run.log" | sed 's/^/[dave]    /' &
DAVE_PID=$!

echo "starting eve-star (port 30337, rpc 9948)..."
"$SUPERVISOR_BIN" --child "$EVE_BASE/canonical-cache/gemini-node" --canonical-dir "$EVE_BASE/canonical-cache" -- "${EVE_CHILD_ARGS[@]}" 2>&1 | tee "$EVE_BASE/run.log" | sed 's/^/[eve]     /' &
EVE_PID=$!

wait
