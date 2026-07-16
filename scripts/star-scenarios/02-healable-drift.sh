#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Scenario 2 — healable drift.
#
# One node (bob) has a tampered gemini-node binary AND has the
# correct canonical bytes in its `--canonical-files-dir`. Expected:
#
#   1. Bob's verifier detects the hash mismatch on boot.
#   2. Bob heals: pulls canonical bytes from his canonical-cache,
#      stages at `<exe>.new`, exits 90.
#   3. Bob's supervisor rotates the staged file over the running
#      binary, re-spawns.
#   4. Bob's fresh child boots clean, attest passes, rejoins star.
#
# The trick: bob's `canonical-cache/gemini-node` (the hard-link)
# matches genesis canonical hash; bob's running binary path
# (current_exe() → canonical-cache/gemini-node) IS the hard-link
# AND IS what gets tampered. So we tamper the hard-link, then the
# canonical-cache has the wrong bytes too... that's not how the
# real heal flow works.
#
# To exercise the real heal flow, we need TWO copies: a known-good
# canonical copy in a separate cache dir, and a corrupted copy that
# the supervisor runs. We achieve this by:
#
#   * making bob's canonical-cache a SEPARATE directory (not a
#     hard-link to target/release)
#   * putting a fresh COPY (not hard-link) of gemini-node in
#     bob's canonical-cache as the heal source
#   * placing a CORRUPTED copy at bob's bin path that the
#     supervisor runs
#
# This script overrides the standard run-star.sh layout to set
# this up for bob, then verifies the heal+restart sequence.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

NODE_BIN="${GEMINI_NODE:-${REPO_ROOT}/target/release/gemini-node}"
SUPERVISOR_BIN="${ROSTRO_SUPERVISOR:-${REPO_ROOT}/target/release/rostro-supervisor}"

for bin in "$NODE_BIN" "$SUPERVISOR_BIN"; do
	if [[ ! -x "$bin" ]]; then
		echo "binary not found at $bin" >&2
		echo "  build first:  cargo build --release -p gemini-node -p rostro-supervisor" >&2
		exit 1
	fi
done

# Compute canonical hash (real, untampered).
GEMINI_NODE_HASH="$(python3 -c "import hashlib,sys;print(hashlib.blake2b(open(sys.argv[1],'rb').read(),digest_size=32).hexdigest())" "$NODE_BIN")"
export ROSTRO_CANONICAL_GEMINI_NODE_HASH="$GEMINI_NODE_HASH"
echo "canonical hash (seeded): 0x${GEMINI_NODE_HASH}"

# Set up bob's bases differently from the standard layout.
BOB_BASE="$REPO_ROOT/.star/bob"
mkdir -p "$BOB_BASE/canonical-cache"
# Heal source: a fresh COPY (not hard-link) of the canonical binary.
# The verifier hashes current_exe() (which we'll tamper); on
# mismatch, fetches by hash from --canonical-files-dir (which is
# this canonical-cache).
echo "preparing bob's canonical-cache (heal source) and corrupted runtime binary..."
cp -f "$NODE_BIN" "$BOB_BASE/canonical-cache/gemini-node"
chmod +x "$BOB_BASE/canonical-cache/gemini-node"

# Bob's runtime binary path: the supervisor's --child points here.
# We corrupt this so the verifier detects mismatch on boot. The
# supervisor will heal-rotate the .new file over this on exit-90.
#
# IMPORTANT: must be a COPY, not a hard-link, so the canonical-cache
# stays intact when we tamper this one. (Hard-link would tamper both.)
BOB_RUNTIME_BIN="$BOB_BASE/runtime-bin/gemini-node"
mkdir -p "$BOB_BASE/runtime-bin"
cp -f "$NODE_BIN" "$BOB_RUNTIME_BIN"
chmod +x "$BOB_RUNTIME_BIN"

# Tamper: flip a single byte deep in the binary. blake2_256 of the
# whole file changes; verifier's hash comparison fails.
echo "tampering bob's runtime binary (flipping one byte)..."
python3 -c "
import sys
path = sys.argv[1]
with open(path, 'r+b') as f:
    f.seek(1024 * 1024)  # 1 MiB in
    b = f.read(1)
    if not b: raise SystemExit('binary < 1 MiB; pick a different offset')
    f.seek(-1, 1)
    f.write(bytes([b[0] ^ 0xFF]))
print('tampered byte at offset 1048576')
" "$BOB_RUNTIME_BIN"

# Verify the tampered hash differs from canonical.
TAMPERED_HASH="$(python3 -c "import hashlib,sys;print(hashlib.blake2b(open(sys.argv[1],'rb').read(),digest_size=32).hexdigest())" "$BOB_RUNTIME_BIN")"
echo "tampered hash:     0x${TAMPERED_HASH}"
if [[ "$TAMPERED_HASH" == "$GEMINI_NODE_HASH" ]]; then
	echo "FAIL: tampering didn't change the hash (1MiB offset is past EOF?)"
	exit 1
fi
echo "OK: tamper produced a hash mismatch"

# Set up alice/charlie/dave/eve normally (hard-link from target/release).
for base in "$REPO_ROOT/.star/alice" "$REPO_ROOT/.star/charlie" "$REPO_ROOT/.star/dave" "$REPO_ROOT/.star/eve"; do
	mkdir -p "$base/canonical-cache"
	rm -f "$base/canonical-cache/gemini-node"
	ln "$NODE_BIN" "$base/canonical-cache/gemini-node"
done

# Inject Sassafras keys (idempotent).
echo "injecting Sassafras keys..."
"$NODE_BIN" key insert --key-type sass --suri //Alice   --base-path "$REPO_ROOT/.star/alice"   --chain gemini-star
"$NODE_BIN" key insert --key-type sass --suri //Bob     --base-path "$BOB_BASE"                --chain gemini-star
"$NODE_BIN" key insert --key-type sass --suri //Charlie --base-path "$REPO_ROOT/.star/charlie" --chain gemini-star
"$NODE_BIN" key insert --key-type sass --suri //Dave    --base-path "$REPO_ROOT/.star/dave"    --chain gemini-star
"$NODE_BIN" key insert --key-type sass --suri //Eve     --base-path "$REPO_ROOT/.star/eve"     --chain gemini-star

ALICE_PEER_ID="12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp"
BOOTNODES_MULTIADDR="/ip4/127.0.0.1/tcp/30333/p2p/${ALICE_PEER_ID}"

cleanup() {
	for pid in "${PIDS[@]:-}"; do
		[[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
	done
	wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

PIDS=()

start_node_with_supervisor() {
	local name="$1" base="$2" runtime_bin="$3" canonical_cache="$4"
	shift 4
	"$SUPERVISOR_BIN" --child "$runtime_bin" --canonical-dir "$canonical_cache" -- "$@" 2>&1 | tee "$base/run.log" | sed "s/^/[$name] /" &
	PIDS+=($!)
}

COMMON=(--chain star --no-mdns --validator --rpc-cors=all)

echo "starting alice (bootnode)..."
start_node_with_supervisor alice "$REPO_ROOT/.star/alice" \
	"$REPO_ROOT/.star/alice/canonical-cache/gemini-node" \
	"$REPO_ROOT/.star/alice/canonical-cache" \
	"${COMMON[@]}" --name alice-star --base-path "$REPO_ROOT/.star/alice" \
	--node-key "0000000000000000000000000000000000000000000000000000000000000001" \
	--port 30333 --rpc-port 9944 --prometheus-port 9615 \
	--canonical-files-dir "$REPO_ROOT/.star/alice/canonical-cache" \
	--alice

sleep 3

echo "starting bob (tampered, expects heal+restart)..."
start_node_with_supervisor bob "$BOB_BASE" \
	"$BOB_RUNTIME_BIN" \
	"$BOB_BASE/canonical-cache" \
	"${COMMON[@]}" --name bob-star --base-path "$BOB_BASE" \
	--node-key "0000000000000000000000000000000000000000000000000000000000000002" \
	--port 30334 --rpc-port 9945 --prometheus-port 9616 \
	--bootnodes "$BOOTNODES_MULTIADDR" \
	--canonical-files-dir "$BOB_BASE/canonical-cache" \
	--bob

# Give bob enough time to: detect mismatch, heal, exit 90,
# supervisor rotate, respawn, verify clean, attest.
echo "waiting ~60s for bob's heal+restart cycle..."
sleep 60

cleanup

# Assert: bob's log shows the heal sequence.
BOB_LOG="$BOB_BASE/run.log"
FAIL=0

if ! grep -q "binary hash mismatch\|FOUNDATION FILESET MISMATCH\|files differ" "$BOB_LOG" 2>/dev/null; then
	echo "FAIL [bob]: verifier did not detect mismatch on boot"
	FAIL=1
else
	echo "OK [bob]: verifier detected mismatch"
fi

if ! grep -q "heal staged\|all .* canonical files staged" "$BOB_LOG" 2>/dev/null; then
	echo "FAIL [bob]: heal did not stage canonical bytes"
	FAIL=1
else
	echo "OK [bob]: heal staged bytes"
fi

if ! grep -q "swap-and-restart\|exiting code 90" "$BOB_LOG" 2>/dev/null; then
	echo "FAIL [bob]: supervisor did not see exit-90 swap request"
	FAIL=1
else
	echo "OK [bob]: supervisor saw swap request"
fi

if ! grep -q "rotated.*gemini-node" "$BOB_LOG" 2>/dev/null; then
	echo "FAIL [bob]: supervisor did not rotate staged binary"
	FAIL=1
else
	echo "OK [bob]: supervisor rotated"
fi

# After restart, the new child should verify clean.
if ! grep -q "canonical files verified" "$BOB_LOG" 2>/dev/null; then
	echo "FAIL [bob]: post-restart verifier did not pass"
	FAIL=1
else
	echo "OK [bob]: post-restart verifier passed"
fi

if [[ $FAIL -ne 0 ]]; then
	echo
	echo "=== scenario 02 FAILED ==="
	echo
	echo "bob's recent log:"
	tail -50 "$BOB_LOG" | sed 's/^/  /'
	exit 1
fi
echo
echo "=== scenario 02 PASSED ==="
