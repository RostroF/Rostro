#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Phase Z6 — validator-channel scenario:
# all 5 validators establish pairwise encrypted sessions among
# themselves; a 6th non-validator observer joins the network but
# cannot establish any sessions. Demonstrates the active-set gate
# on the validator-only encrypted channel.
#
# Assertions:
#   1. Each of Alice/Bob/Charlie/Dave/Eve logs at least one
#      "established initiator session" or "established responder
#      session" log line. With 5 validators and the lower-PeerId-
#      initiates rule, there should be N(N-1)/2 = 10 sessions total
#      (5 from each side's view, with each pair counted once).
#   2. Frank (the non-validator observer) logs NO established
#      sessions. He's connected at libp2p but locked out of the
#      validator channel because (a) he has no local GRANDPA key,
#      so his asker doesn't run, and (b) when validators initiate
#      with him, his handshake-server isn't registered, so the
#      request fails.
#   3. Block production + finality still work (the validator
#      channel doesn't break consensus).

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

# Canonical-files setup so the boot-verifier passes for all 6 nodes.
GEMINI_NODE_HASH="$(python3 -c "import hashlib,sys;print(hashlib.blake2b(open(sys.argv[1],'rb').read(),digest_size=32).hexdigest())" "$NODE_BIN")"
export ROSTRO_CANONICAL_GEMINI_NODE_HASH="$GEMINI_NODE_HASH"
export SUBSTRATE_ENABLE_POLKAVM="${SUBSTRATE_ENABLE_POLKAVM:-1}"
echo "canonical hash (seeded): 0x${GEMINI_NODE_HASH}"

# Per-node canonical-cache dirs with hardlinked binary. Same as
# run-star.sh's pattern — all 6 nodes use the same canonical bytes.
setup_node_cache() {
	local base="$1"
	mkdir -p "$base/canonical-cache"
	rm -f "$base/canonical-cache/gemini-node"
	ln "$NODE_BIN" "$base/canonical-cache/gemini-node"
}
ALICE_BASE="$REPO_ROOT/.star/alice"
BOB_BASE="$REPO_ROOT/.star/bob"
CHARLIE_BASE="$REPO_ROOT/.star/charlie"
DAVE_BASE="$REPO_ROOT/.star/dave"
EVE_BASE="$REPO_ROOT/.star/eve"
FRANK_BASE="$REPO_ROOT/.star/frank"
for base in "$ALICE_BASE" "$BOB_BASE" "$CHARLIE_BASE" "$DAVE_BASE" "$EVE_BASE" "$FRANK_BASE"; do
	setup_node_cache "$base"
done

# Inject Sassafras (bandersnatch) authority key for the 5 validators
# ONLY. Frank does NOT get a Sassafras key — he's not a validator.
echo "injecting Sassafras keys for 5 validators (skipping frank)..."
"$NODE_BIN" insert-sassafras-key --suri //Alice   --base-path "$ALICE_BASE"   --chain-id gemini-star
"$NODE_BIN" insert-sassafras-key --suri //Bob     --base-path "$BOB_BASE"     --chain-id gemini-star
"$NODE_BIN" insert-sassafras-key --suri //Charlie --base-path "$CHARLIE_BASE" --chain-id gemini-star
"$NODE_BIN" insert-sassafras-key --suri //Dave    --base-path "$DAVE_BASE"    --chain-id gemini-star
"$NODE_BIN" insert-sassafras-key --suri //Eve     --base-path "$EVE_BASE"     --chain-id gemini-star

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

start_with_supervisor() {
	local name="$1" base="$2"
	shift 2
	"$SUPERVISOR_BIN" --child "$base/canonical-cache/gemini-node" --canonical-dir "$base/canonical-cache" -- "$@" 2>&1 | tee "$base/run.log" | sed "s/^/[$name] /" &
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

echo "starting dave (validator)..."
start_with_supervisor dave "$DAVE_BASE" \
	"${COMMON_VALIDATOR[@]}" --name dave-star --base-path "$DAVE_BASE" \
	--node-key "0000000000000000000000000000000000000000000000000000000000000004" \
	--port 30336 --rpc-port 9947 --prometheus-port 9618 \
	--bootnodes "$BOOTNODES_MULTIADDR" \
	--canonical-files-dir "$DAVE_BASE/canonical-cache" \
	--dave

echo "starting eve (validator)..."
start_with_supervisor eve "$EVE_BASE" \
	"${COMMON_VALIDATOR[@]}" --name eve-star --base-path "$EVE_BASE" \
	--node-key "0000000000000000000000000000000000000000000000000000000000000005" \
	--port 30337 --rpc-port 9948 --prometheus-port 9619 \
	--bootnodes "$BOOTNODES_MULTIADDR" \
	--canonical-files-dir "$EVE_BASE/canonical-cache" \
	--eve

echo "starting frank (NON-validator observer)..."
start_with_supervisor frank "$FRANK_BASE" \
	"${COMMON_OBSERVER[@]}" --name frank-observer --base-path "$FRANK_BASE" \
	--node-key "0000000000000000000000000000000000000000000000000000000000000006" \
	--port 30338 --rpc-port 9949 --prometheus-port 9620 \
	--bootnodes "$BOOTNODES_MULTIADDR" \
	--canonical-files-dir "$FRANK_BASE/canonical-cache"

# Wait for handshakes to complete. Validators connect over a few
# seconds; handshakes execute after the first NotificationStreamOpened
# event for each peer. Generous budget so the assertion isn't flaky.
echo "waiting 60s for handshakes + heartbeats..."
sleep 60

cleanup

# ───── Assertions ───────────────────────────────────────────────────
FAIL=0

# (1) Each validator should have established at least one session.
for name in alice bob charlie dave eve; do
	log="$REPO_ROOT/.star/$name/run.log"
	if [[ ! -f "$log" ]]; then
		echo "FAIL [$name]: no log file"
		FAIL=1
		continue
	fi
	if ! grep -qE "established (initiator|responder) session" "$log"; then
		echo "FAIL [$name]: no session established"
		echo "  recent validator-channel log lines:"
		grep "rostro-validator-channel" "$log" | tail -10 | sed "s/^/    /"
		FAIL=1
		continue
	fi
	# How many distinct peers?
	count="$(grep -E "established (initiator|responder) session with peer ([A-Za-z0-9]+)" "$log" | grep -oE "peer [A-Za-z0-9]+" | sort -u | wc -l)"
	if [[ "$count" -lt 4 ]]; then
		echo "FAIL [$name]: only $count distinct peers in sessions (expected 4 — every other validator)"
		FAIL=1
	else
		echo "OK [$name]: established sessions with $count distinct peers"
	fi
done

# (2) Frank should have NO sessions established (he's not a validator).
FRANK_LOG="$FRANK_BASE/run.log"
if grep -qE "established (initiator|responder) session" "$FRANK_LOG" 2>/dev/null; then
	echo "FAIL [frank]: observer established a session (should not have any)"
	grep -E "established (initiator|responder) session" "$FRANK_LOG" | sed "s/^/  /"
	FAIL=1
else
	echo "OK [frank]: observer locked out (no sessions established)"
fi

# (3) Frank should NOT have a validator-channel asker running
# (he has no local GRANDPA key).
if grep -q "validator-channel asker started" "$FRANK_LOG" 2>/dev/null; then
	echo "FAIL [frank]: asker started (should not have, no local GRANDPA key)"
	FAIL=1
else
	echo "OK [frank]: asker did not start (no GRANDPA key, as expected)"
fi

# (4) Validators should at least attempt to log "validator-channel
# asker started" (proves the asker came online).
for name in alice bob charlie dave eve; do
	log="$REPO_ROOT/.star/$name/run.log"
	if ! grep -q "validator-channel asker started" "$log" 2>/dev/null; then
		echo "FAIL [$name]: asker never logged start"
		FAIL=1
	fi
done

# (5) Block production + finality should not be disrupted by the
# validator-channel work. Look for a finalized block.
ANY_FINALIZED=0
for name in alice bob charlie dave eve; do
	log="$REPO_ROOT/.star/$name/run.log"
	if grep -qE "finalized #[1-9]" "$log" 2>/dev/null; then
		ANY_FINALIZED=1
		break
	fi
done
if [[ $ANY_FINALIZED -eq 0 ]]; then
	echo "FAIL: no node logged a finalized block (validator-channel may have broken consensus)"
	FAIL=1
else
	echo "OK: at least one finalized block observed (consensus intact)"
fi

# (6) Optional heartbeat traffic check. Heartbeats fire every ~10s;
# after 60s each validator should have decrypted at least one
# heartbeat from a peer.
ANY_DECRYPTED=0
for name in alice bob charlie dave eve; do
	log="$REPO_ROOT/.star/$name/run.log"
	if grep -q "decrypted message from" "$log" 2>/dev/null; then
		ANY_DECRYPTED=1
		break
	fi
done
if [[ $ANY_DECRYPTED -eq 0 ]]; then
	echo "WARN: no node logged a decrypted heartbeat (may indicate notification protocol not flowing)"
	# Not a hard FAIL — sessions may have just been established near
	# the end of the wait window. Document and move on.
else
	echo "OK: at least one decrypted heartbeat observed"
fi

if [[ $FAIL -ne 0 ]]; then
	echo
	echo "=== validator-channel-01 FAILED ==="
	exit 1
fi
echo
echo "=== validator-channel-01 PASSED ==="
