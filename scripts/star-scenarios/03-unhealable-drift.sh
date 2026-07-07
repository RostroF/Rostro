#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Scenario 3 — unhealable drift.
#
# One node (bob) has a tampered gemini-node binary AND no canonical
# bytes available (--canonical-files-dir points at an empty dir).
# Expected:
#
#   1. Bob's verifier detects the hash mismatch on boot.
#   2. With no heal source matching the canonical hash, the
#      verifier returns Err with "FOUNDATION FILESET MISMATCH".
#   3. Bob's gemini-node exits non-zero. Supervisor sees the
#      non-90 exit and gives up (no swap attempt).
#   4. Other 4 nodes continue without bob.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

NODE_BIN="${GEMINI_NODE:-${REPO_ROOT}/target/release/gemini-node}"
SUPERVISOR_BIN="${ROSTRO_SUPERVISOR:-${REPO_ROOT}/target/release/rostro-supervisor}"

for bin in "$NODE_BIN" "$SUPERVISOR_BIN"; do
	if [[ ! -x "$bin" ]]; then
		echo "binary not found at $bin" >&2
		echo "  build first:  SUBSTRATE_ENABLE_POLKAVM=1 cargo build --release -p gemini-node -p rostro-supervisor" >&2
		exit 1
	fi
done

GEMINI_NODE_HASH="$(python3 -c "import hashlib,sys;print(hashlib.blake2b(open(sys.argv[1],'rb').read(),digest_size=32).hexdigest())" "$NODE_BIN")"
export ROSTRO_CANONICAL_GEMINI_NODE_HASH="$GEMINI_NODE_HASH"
export SUBSTRATE_ENABLE_POLKAVM="${SUBSTRATE_ENABLE_POLKAVM:-1}"
echo "canonical hash (seeded): 0x${GEMINI_NODE_HASH}"

BOB_BASE="$REPO_ROOT/.star/bob"
# Empty canonical-cache for bob → no heal source.
rm -rf "$BOB_BASE/canonical-cache"
mkdir -p "$BOB_BASE/canonical-cache"
echo "bob's canonical-cache: EMPTY (no heal source)"

BOB_RUNTIME_BIN="$BOB_BASE/runtime-bin/gemini-node"
mkdir -p "$BOB_BASE/runtime-bin"
cp -f "$NODE_BIN" "$BOB_RUNTIME_BIN"
chmod +x "$BOB_RUNTIME_BIN"

echo "tampering bob's runtime binary..."
python3 -c "
import sys
path = sys.argv[1]
with open(path, 'r+b') as f:
    f.seek(1024 * 1024)
    b = f.read(1)
    if not b: raise SystemExit('binary < 1 MiB')
    f.seek(-1, 1)
    f.write(bytes([b[0] ^ 0xFF]))
" "$BOB_RUNTIME_BIN"

# Set up the other 4 normally.
for base in "$REPO_ROOT/.star/alice" "$REPO_ROOT/.star/charlie" "$REPO_ROOT/.star/dave" "$REPO_ROOT/.star/eve"; do
	mkdir -p "$base/canonical-cache"
	rm -f "$base/canonical-cache/gemini-node"
	ln "$NODE_BIN" "$base/canonical-cache/gemini-node"
done

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
COMMON=(--chain star --no-mdns --validator --rpc-cors=all)

echo "starting alice (bootnode)..."
"$SUPERVISOR_BIN" --child "$REPO_ROOT/.star/alice/canonical-cache/gemini-node" --canonical-dir "$REPO_ROOT/.star/alice/canonical-cache" -- \
	"${COMMON[@]}" --name alice-star --base-path "$REPO_ROOT/.star/alice" \
	--node-key "0000000000000000000000000000000000000000000000000000000000000001" \
	--port 30333 --rpc-port 9944 --prometheus-port 9615 \
	--canonical-files-dir "$REPO_ROOT/.star/alice/canonical-cache" \
	--alice 2>&1 | tee "$REPO_ROOT/.star/alice/run.log" | sed 's/^/[alice] /' &
PIDS+=($!)

sleep 3

echo "starting bob (tampered + empty cache → expects fail-stop)..."
"$SUPERVISOR_BIN" --child "$BOB_RUNTIME_BIN" --canonical-dir "$BOB_BASE/canonical-cache" -- \
	"${COMMON[@]}" --name bob-star --base-path "$BOB_BASE" \
	--node-key "0000000000000000000000000000000000000000000000000000000000000002" \
	--port 30334 --rpc-port 9945 --prometheus-port 9616 \
	--bootnodes "$BOOTNODES_MULTIADDR" \
	--canonical-files-dir "$BOB_BASE/canonical-cache" \
	--bob 2>&1 | tee "$BOB_BASE/run.log" | sed 's/^/[bob]   /' &
PIDS+=($!)

# Bob should fail-stop within seconds.
echo "waiting 20s for bob to fail-stop..."
sleep 20

cleanup

BOB_LOG="$BOB_BASE/run.log"
FAIL=0

if ! grep -q "FOUNDATION FILESET MISMATCH\|files differ" "$BOB_LOG" 2>/dev/null; then
	echo "FAIL [bob]: verifier did not emit FOUNDATION FILESET MISMATCH"
	FAIL=1
else
	echo "OK [bob]: verifier emitted FOUNDATION FILESET MISMATCH"
fi

# Bob's gemini-node should have exited non-zero. The supervisor
# treats non-90 child exits as fatal and exits with the child's
# code.
if ! grep -q "child exited with code\|supervisor giving up\|HEAL FAILED" "$BOB_LOG" 2>/dev/null; then
	echo "FAIL [bob]: supervisor did not log a non-zero child exit"
	FAIL=1
else
	echo "OK [bob]: supervisor logged non-zero exit"
fi

# Critically: NO heal succeeded. The "heal staged" line must be absent.
if grep -q "heal staged" "$BOB_LOG" 2>/dev/null; then
	echo "FAIL [bob]: heal succeeded but should have failed (no canonical bytes in cache)"
	FAIL=1
else
	echo "OK [bob]: no heal staged (as expected)"
fi

if [[ $FAIL -ne 0 ]]; then
	echo
	echo "=== scenario 03 FAILED ==="
	echo
	echo "bob's recent log:"
	tail -30 "$BOB_LOG" | sed 's/^/  /'
	exit 1
fi
echo
echo "=== scenario 03 PASSED ==="
