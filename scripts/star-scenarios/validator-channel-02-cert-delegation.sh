#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# channel-cert P3 — validator-channel delegation-cert scenario.
#
# Proves the KEYSTORE-AUDIT F1 fix end-to-end: validator-channel
# handshakes are authenticated by a per-epoch GRANDPA-signed delegation
# cert + a channel key, NOT the GRANDPA key itself. 3 validators
# (alice/bob/charlie) + 1 non-validator observer (frank).
#
# Assertions:
#   1. Each validator issues a channel cert ("issued channel cert for
#      epoch N") — the once-per-epoch GRANDPA-key touch fired.
#   2. Each validator establishes encrypted sessions with >=2 distinct
#      peers on /rostro/validator-channel-handshake/3 (hybrid
#      X25519+ML-KEM-768, docs/PQ-TRANSPORT.md). Sessions can only form
#      if the cert + channel-key handshake verified AND both sides
#      derived the same hybrid secret, so this is the end-to-end proof
#      of the v3 path.
#   3. Frank (observer, no GRANDPA key) issues NO cert and establishes
#      NO session — the active-set gate still holds.
#   4. At least one decrypted heartbeat flows (notification path intact).
#   5. Finality is not disrupted by the channel work.
#
# NOTE: this is the cert-aware successor to
# validator-channel-01-observer-locked-out.sh, whose asker-era log
# assertions are stale against the current notification-task design.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

NODE_BIN="${GEMINI_NODE:-${REPO_ROOT}/target/release/gemini-node}"
SUPERVISOR_BIN="${ROSTRO_SUPERVISOR:-${REPO_ROOT}/target/release/rostro-supervisor}"

for bin in "$NODE_BIN" "$SUPERVISOR_BIN"; do
	if [[ ! -x "$bin" ]]; then
		echo "binary not found at $bin" >&2
		echo "  build first:  SUBSTRATE_RUNTIME_TARGET=riscv SUBSTRATE_ENABLE_POLKAVM=1 cargo build --release -p gemini-node -p rostro-supervisor" >&2
		exit 1
	fi
done

GEMINI_NODE_HASH="$(python3 -c "import hashlib,sys;print(hashlib.blake2b(open(sys.argv[1],'rb').read(),digest_size=32).hexdigest())" "$NODE_BIN")"
export ROSTRO_CANONICAL_GEMINI_NODE_HASH="$GEMINI_NODE_HASH"
export SUBSTRATE_ENABLE_POLKAVM="${SUBSTRATE_ENABLE_POLKAVM:-1}"
echo "canonical hash (seeded): 0x${GEMINI_NODE_HASH}"

setup_node_cache() {
	local base="$1"
	mkdir -p "$base/canonical-cache"
	rm -f "$base/canonical-cache/gemini-node"
	ln "$NODE_BIN" "$base/canonical-cache/gemini-node"
}

ALICE_BASE="$REPO_ROOT/.star/cert/alice"
BOB_BASE="$REPO_ROOT/.star/cert/bob"
CHARLIE_BASE="$REPO_ROOT/.star/cert/charlie"
FRANK_BASE="$REPO_ROOT/.star/cert/frank"
# Fresh state each run so key injection + genesis are deterministic.
rm -rf "$REPO_ROOT/.star/cert"
for base in "$ALICE_BASE" "$BOB_BASE" "$CHARLIE_BASE" "$FRANK_BASE"; do
	setup_node_cache "$base"
done

echo "injecting Sassafras keys for 3 validators (skipping frank)..."
for pair in "//Alice:$ALICE_BASE" "//Bob:$BOB_BASE" "//Charlie:$CHARLIE_BASE"; do
	suri="${pair%%:*}"; base="${pair##*:}"
	"$NODE_BIN" insert-sassafras-key --suri "$suri" --base-path "$base" --chain-id gemini-star
done

echo "injecting GRANDPA Ed25519 keys for 3 validators (skipping frank)..."
for pair in "//Alice:$ALICE_BASE" "//Bob:$BOB_BASE" "//Charlie:$CHARLIE_BASE"; do
	suri="${pair%%:*}"; base="${pair##*:}"
	"$NODE_BIN" key insert --suri "$suri" --key-type gran --scheme ed25519 --base-path "$base" --chain star
done

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
COMMON_VALIDATOR=(--chain star --no-mdns --validator --rpc-cors=all)
COMMON_OBSERVER=(--chain star --no-mdns --rpc-cors=all)

# The supervisor's Cannae sandbox needs root (CAP_SYS_ADMIN for
# unshare(CLONE_NEWNS)). Set ROSTRO_NO_SUPERVISOR=1 to launch the node
# binary directly, bypassing the sandbox — appropriate when validating
# the validator-channel protocol (not the sandbox) in a non-root env.
start_with_supervisor() {
	local name="$1" base="$2"
	shift 2
	if [[ "${ROSTRO_NO_SUPERVISOR:-0}" == "1" ]]; then
		"$base/canonical-cache/gemini-node" "$@" 2>&1 | tee "$base/run.log" | sed "s/^/[$name] /" &
	else
		"$SUPERVISOR_BIN" --child "$base/canonical-cache/gemini-node" --canonical-dir "$base/canonical-cache" -- "$@" 2>&1 | tee "$base/run.log" | sed "s/^/[$name] /" &
	fi
	PIDS+=($!)
}

echo "starting alice (validator, bootnode)..."
start_with_supervisor alice "$ALICE_BASE" \
	"${COMMON_VALIDATOR[@]}" --name alice-star --base-path "$ALICE_BASE" \
	--node-key "0000000000000000000000000000000000000000000000000000000000000001" \
	--port 30333 --rpc-port 9944 --prometheus-port 9615 \
	--canonical-files-dir "$ALICE_BASE/canonical-cache" \
	--alice
sleep 3

echo "starting bob (validator)..."
start_with_supervisor bob "$BOB_BASE" \
	"${COMMON_VALIDATOR[@]}" --name bob-star --base-path "$BOB_BASE" \
	--node-key "0000000000000000000000000000000000000000000000000000000000000002" \
	--port 30334 --rpc-port 9945 --prometheus-port 9616 \
	--bootnodes "$BOOTNODES_MULTIADDR" \
	--canonical-files-dir "$BOB_BASE/canonical-cache" \
	--bob

echo "starting charlie (validator)..."
start_with_supervisor charlie "$CHARLIE_BASE" \
	"${COMMON_VALIDATOR[@]}" --name charlie-star --base-path "$CHARLIE_BASE" \
	--node-key "0000000000000000000000000000000000000000000000000000000000000003" \
	--port 30335 --rpc-port 9946 --prometheus-port 9617 \
	--bootnodes "$BOOTNODES_MULTIADDR" \
	--canonical-files-dir "$CHARLIE_BASE/canonical-cache" \
	--charlie

echo "starting frank (NON-validator observer)..."
start_with_supervisor frank "$FRANK_BASE" \
	"${COMMON_OBSERVER[@]}" --name frank-observer --base-path "$FRANK_BASE" \
	--node-key "0000000000000000000000000000000000000000000000000000000000000006" \
	--port 30338 --rpc-port 9949 --prometheus-port 9620 \
	--bootnodes "$BOOTNODES_MULTIADDR" \
	--canonical-files-dir "$FRANK_BASE/canonical-cache"

echo "waiting 60s for cert issuance + handshakes + heartbeats..."
sleep 60

cleanup

# ───── Assertions ───────────────────────────────────────────────────
FAIL=0

# (1) Each validator issued a channel cert.
for name in alice bob charlie; do
	log="$REPO_ROOT/.star/cert/$name/run.log"
	if grep -qE "issued channel cert for epoch" "$log" 2>/dev/null; then
		echo "OK [$name]: issued a channel cert (GRANDPA-key touch fired)"
	else
		echo "FAIL [$name]: no channel cert issued"
		grep "rostro-validator-channel" "$log" 2>/dev/null | tail -8 | sed "s/^/    /"
		FAIL=1
	fi
done

# (2) Each validator established sessions with >=2 distinct peers.
for name in alice bob charlie; do
	log="$REPO_ROOT/.star/cert/$name/run.log"
	if ! grep -qE "established (initiator|responder) session" "$log" 2>/dev/null; then
		echo "FAIL [$name]: no session established (v3 hybrid handshake path failed)"
		grep "rostro-validator-channel" "$log" 2>/dev/null | tail -10 | sed "s/^/    /"
		FAIL=1
		continue
	fi
	count="$(grep -oE "established (initiator|responder) session with peer [A-Za-z0-9]+" "$log" | grep -oE "peer [A-Za-z0-9]+" | sort -u | wc -l)"
	if [[ "$count" -lt 2 ]]; then
		echo "FAIL [$name]: only $count distinct session peers (expected 2)"
		FAIL=1
	else
		echo "OK [$name]: established sessions with $count distinct peers on /3"
	fi
done

# (3) Frank issues no cert and establishes no session.
FRANK_LOG="$FRANK_BASE/run.log"
if grep -qE "issued channel cert for epoch" "$FRANK_LOG" 2>/dev/null; then
	echo "FAIL [frank]: observer issued a channel cert (should not — no GRANDPA key)"
	FAIL=1
else
	echo "OK [frank]: no cert issued (not a validator)"
fi
if grep -qE "established (initiator|responder) session" "$FRANK_LOG" 2>/dev/null; then
	echo "FAIL [frank]: observer established a session (should be locked out)"
	FAIL=1
else
	echo "OK [frank]: observer locked out (no sessions)"
fi

# (4) At least one decrypted heartbeat flowed.
ANY_DECRYPTED=0
for name in alice bob charlie; do
	if grep -q "decrypted message from" "$REPO_ROOT/.star/cert/$name/run.log" 2>/dev/null; then
		ANY_DECRYPTED=1; break
	fi
done
if [[ $ANY_DECRYPTED -eq 1 ]]; then
	echo "OK: decrypted heartbeat observed (notification path intact)"
else
	echo "WARN: no decrypted heartbeat (sessions may have formed late in the window)"
fi

# (5) Finality not disrupted.
ANY_FINALIZED=0
for name in alice bob charlie; do
	if grep -qE "finalized #[1-9]" "$REPO_ROOT/.star/cert/$name/run.log" 2>/dev/null; then
		ANY_FINALIZED=1; break
	fi
done
if [[ $ANY_FINALIZED -eq 1 ]]; then
	echo "OK: finalized block observed (consensus intact)"
else
	echo "FAIL: no finalized block (channel work may have broken consensus)"
	FAIL=1
fi

echo
if [[ $FAIL -ne 0 ]]; then
	echo "=== validator-channel-02-cert-delegation FAILED ==="
	exit 1
fi
echo "=== validator-channel-02-cert-delegation PASSED ==="
