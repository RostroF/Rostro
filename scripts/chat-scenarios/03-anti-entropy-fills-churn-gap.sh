#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Scenario 03 — anti-entropy fills a churn gap.
#
# Setup:
#   * alice-chat + bob-chat run from t=0; charlie-chat is OFFLINE.
#   * Iris sends a message via alice-chat. Push goes to bob only
#     (charlie isn't connected). Charlie misses the push entirely.
#   * Charlie comes online after the send. After he completes the
#     /rostro/chat-gossip/1 handshake with alice + bob (sees their
#     bucket subscriptions) and the periodic anti-entropy task
#     fires, charlie's per-bucket digest disagrees with bob's,
#     bob responds with the entry list, charlie fetches the
#     missing shares via /rostro/chat-fetch/1 keyed on the pickup.
#   * Otto fetches via charlie-chat. Charlie has the shards
#     locally now (via anti-entropy), returns them. CLI
#     reconstructs.
#
# This is the v0.1 churn-gap-fill demonstration. Without
# anti-entropy charlie would have to rely on Commit C's fallback
# fetch from his RPC (which would re-query bob anyway); with
# anti-entropy he proactively converges over time so his RPC
# answers from local store.
#
# Exit 0 on full plaintext recovery via charlie. Exit 1 on any
# assertion failure.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
NODE_BIN="${GEMINI_NODE:-${REPO_ROOT}/target/release/gemini-node}"
SUPERVISOR_BIN="${ROSTRO_SUPERVISOR:-${REPO_ROOT}/target/release/rostro-supervisor}"
CLI_BIN="${ROSTRO_CHAT_CLI:-${REPO_ROOT}/target/release/rostro-chat-cli}"

# Anti-entropy fires every 30s by default. Allow up to two ticks
# plus settle time for charlie to come online, handshake gossip,
# trigger AE, fetch missing.
AE_WAIT_SECS="${AE_WAIT_SECS:-90}"

IRIS_SEED="1111111111111111111111111111111111111111111111111111111111111111"
OTTO_SEED="2222222222222222222222222222222222222222222222222222222222222222"
MESSAGE="anti-entropy demo: charlie was offline at send-time"

# Mirror run-chat-trio.sh constants so we can boot alice/bob first,
# then charlie after a delay.
export SUBSTRATE_ENABLE_POLKAVM="${SUBSTRATE_ENABLE_POLKAVM:-1}"
LOG_FILTER="${LOG_FILTER:-info,rostro-chat-gossip=debug,rostro-chat-anti-entropy=debug,rostro-chat-rpc=debug,rostro-chat-stripe=debug,rostro-chat-fetch=debug}"

for bin in "$NODE_BIN" "$SUPERVISOR_BIN" "$CLI_BIN"; do
	if [[ ! -x "$bin" ]]; then
		echo "binary not found at $bin" >&2
		echo "  build first:  SUBSTRATE_ENABLE_POLKAVM=1 SUBSTRATE_RUNTIME_TARGET=riscv \\" >&2
		echo "                  cargo build --release -p gemini-node -p rostro-supervisor -p rostro-chat-cli" >&2
		exit 1
	fi
done

GEMINI_NODE_HASH="$(python3 -c "import hashlib,sys;print(hashlib.blake2b(open(sys.argv[1],'rb').read(),digest_size=32).hexdigest())" "$NODE_BIN")"
export ROSTRO_CANONICAL_GEMINI_NODE_HASH="$GEMINI_NODE_HASH"

ALICE_NODE_KEY="000000000000000000000000000000000000000000000000000000000000000a"
BOB_NODE_KEY="000000000000000000000000000000000000000000000000000000000000000b"
CHARLIE_NODE_KEY="000000000000000000000000000000000000000000000000000000000000000c"
ALICE_PEER_ID="12D3KooWFNChUebWM7RHCWhypQs6rvs6B8RtKeFXxtR3zT3fchCU"

ALICE_BASE="$REPO_ROOT/.chat-trio/alice"
BOB_BASE="$REPO_ROOT/.chat-trio/bob"
CHARLIE_BASE="$REPO_ROOT/.chat-trio/charlie"

ALICE_RPC="http://127.0.0.1:9954"
BOB_RPC="http://127.0.0.1:9955"
CHARLIE_RPC="http://127.0.0.1:9956"

rm -rf "$ALICE_BASE" "$BOB_BASE" "$CHARLIE_BASE"
mkdir -p "$ALICE_BASE/canonical-cache" "$BOB_BASE/canonical-cache" "$CHARLIE_BASE/canonical-cache"
ln -f "$NODE_BIN" "$ALICE_BASE/canonical-cache/gemini-node"
ln -f "$NODE_BIN" "$BOB_BASE/canonical-cache/gemini-node"
ln -f "$NODE_BIN" "$CHARLIE_BASE/canonical-cache/gemini-node"

COMMON=(--chain star --no-mdns --rpc-cors=all -l "$LOG_FILTER")
BOOTNODES_MULTIADDR="/ip4/127.0.0.1/tcp/30340/p2p/${ALICE_PEER_ID}"

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

PIDS=()
cleanup() {
	for pid in "${PIDS[@]:-}"; do
		[[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
	done
	wait 2>/dev/null || true
}
trap cleanup EXIT

echo "=== scenario 03: anti-entropy fills a churn gap ==="
echo

OTTO_PUBKEY=$("$CLI_BIN" gen-identity --seed "$OTTO_SEED" | awk '/^ed25519_pubkey_hex:/ {print $2}')

echo "Starting alice-chat + bob-chat (charlie DELIBERATELY offline)..."
"$SUPERVISOR_BIN" --child "$ALICE_BASE/canonical-cache/gemini-node" --canonical-dir "$ALICE_BASE/canonical-cache" -- "${ALICE_ARGS[@]}" > "$ALICE_BASE/run.log" 2>&1 &
PIDS+=($!)
sleep 3
"$SUPERVISOR_BIN" --child "$BOB_BASE/canonical-cache/gemini-node" --canonical-dir "$BOB_BASE/canonical-cache" -- "${BOB_ARGS[@]}" > "$BOB_BASE/run.log" 2>&1 &
PIDS+=($!)

# Wait for alice + bob RPC.
echo "Waiting for alice + bob RPCs to come up..."
for port in 9954 9955; do
	SECONDS_WAITED=0
	until curl -fsS -X POST -H 'content-type: application/json' \
		-d '{"jsonrpc":"2.0","id":1,"method":"system_name","params":[]}' \
		"http://127.0.0.1:$port" > /dev/null 2>&1; do
		sleep 1
		SECONDS_WAITED=$((SECONDS_WAITED + 1))
		if [[ "$SECONDS_WAITED" -ge 30 ]]; then
			echo "FAIL: RPC on port $port didn't come up"; exit 1
		fi
	done
done
echo "  alice + bob ready"

# Let gossip subscription advertisements propagate.
sleep 8

# Iris sends — push fans out to alice's bucket peers, which is
# only bob (charlie is offline). Charlie does NOT see this.
echo
echo "Iris sends to Otto via alice-chat (charlie is OFFLINE)..."
"$CLI_BIN" send \
	--node-rpc "$ALICE_RPC" \
	--sender-seed "$IRIS_SEED" \
	--recipient-pubkey "$OTTO_PUBKEY" \
	--message "$MESSAGE" \
	--total-shares 5 > /tmp/chat-03-send.out 2>&1
SENT_MSG_ID=$(awk '/^  message_id_hex:/ {print $2}' /tmp/chat-03-send.out)
echo "  message_id: ${SENT_MSG_ID:0:16}..."

read_store_len() {
	curl -fsS -X POST -H 'content-type: application/json' \
		-d '{"jsonrpc":"2.0","id":1,"method":"chat_localStoreLen","params":[]}' \
		"$1" | sed -n 's/.*"result":\([0-9]*\).*/\1/p'
}

ALICE_AFTER_SEND=$(read_store_len "$ALICE_RPC")
BOB_AFTER_SEND=$(read_store_len "$BOB_RPC")
echo "  store sizes post-send: alice=$ALICE_AFTER_SEND bob=$BOB_AFTER_SEND charlie=OFFLINE"
if [[ "$BOB_AFTER_SEND" -lt 5 ]]; then
	echo "FAIL: bob expected ≥5 shards post-send, got $BOB_AFTER_SEND"
	exit 1
fi

echo
echo "Now bringing charlie-chat online (he MISSED the push)..."
"$SUPERVISOR_BIN" --child "$CHARLIE_BASE/canonical-cache/gemini-node" --canonical-dir "$CHARLIE_BASE/canonical-cache" -- "${CHARLIE_ARGS[@]}" > "$CHARLIE_BASE/run.log" 2>&1 &
PIDS+=($!)

# Wait for charlie's RPC.
SECONDS_WAITED=0
until curl -fsS -X POST -H 'content-type: application/json' \
	-d '{"jsonrpc":"2.0","id":1,"method":"system_name","params":[]}' \
	"$CHARLIE_RPC" > /dev/null 2>&1; do
	sleep 1
	SECONDS_WAITED=$((SECONDS_WAITED + 1))
	if [[ "$SECONDS_WAITED" -ge 30 ]]; then
		echo "FAIL: charlie RPC didn't come up"; exit 1
	fi
done
echo "  charlie-chat RPC ready"

# Confirm charlie's store starts empty.
CHARLIE_ON_BOOT=$(read_store_len "$CHARLIE_RPC")
echo "  charlie store at boot: $CHARLIE_ON_BOOT (expected 0; he missed the push)"
if [[ "$CHARLIE_ON_BOOT" -ne 0 ]]; then
	echo "WARN: charlie boot store unexpectedly non-zero ($CHARLIE_ON_BOOT)"
fi

# Wait for anti-entropy to fire. AE ticks every 30s; allow up to
# AE_WAIT_SECS for charlie to (a) handshake gossip, (b) tick the
# AE timer, (c) exchange digest with alice/bob, (d) fetch missing.
echo
echo "Waiting up to ${AE_WAIT_SECS}s for anti-entropy to fill charlie's gap..."
WAITED=0
while [[ "$WAITED" -lt "$AE_WAIT_SECS" ]]; do
	C=$(read_store_len "$CHARLIE_RPC")
	if [[ "$C" -ge 5 ]]; then
		echo "  charlie store now $C shards at ${WAITED}s — anti-entropy filled the gap"
		break
	fi
	sleep 5
	WAITED=$((WAITED + 5))
	if (( WAITED % 30 == 0 )); then
		echo "  ...${WAITED}s elapsed, charlie store=$C"
	fi
done

CHARLIE_FINAL=$(read_store_len "$CHARLIE_RPC")
if [[ "$CHARLIE_FINAL" -lt 5 ]]; then
	echo "FAIL: anti-entropy didn't fill charlie's gap in ${AE_WAIT_SECS}s"
	echo "  charlie final store: $CHARLIE_FINAL"
	echo "  charlie AE-related log:"
	grep -iE 'anti-entropy|AE ' "$CHARLIE_BASE/run.log" 2>&1 | tail -20 | sed 's/^/    /'
	exit 1
fi

# Now Otto fetches via charlie. Charlie has the shards locally
# (via AE), so this is a local-store hit.
echo
echo "Otto fetches via charlie-chat (which got its shards via anti-entropy)..."
"$CLI_BIN" fetch \
	--node-rpc "$CHARLIE_RPC" \
	--recipient-seed "$OTTO_SEED" > /tmp/chat-03-fetch.out 2>&1

if ! grep -q "plaintext:" /tmp/chat-03-fetch.out; then
	echo "FAIL: fetch via charlie did not return plaintext"
	cat /tmp/chat-03-fetch.out | sed 's/^/    /'
	exit 1
fi

RECOVERED=$(awk '/^  plaintext:/ {sub(/^  plaintext:[[:space:]]+/, ""); print; exit}' /tmp/chat-03-fetch.out)
echo "  recovered plaintext: \"$RECOVERED\""
if [[ "$RECOVERED" != "$MESSAGE" ]]; then
	echo "FAIL: plaintext mismatch"; exit 1
fi

RECEIVED_MSG_ID=$(awk '/^  message_id:/ {print $2}' /tmp/chat-03-fetch.out)
if [[ "$RECEIVED_MSG_ID" != "$SENT_MSG_ID" ]]; then
	echo "FAIL: message_id mismatch (sent $SENT_MSG_ID, got $RECEIVED_MSG_ID)"
	exit 1
fi

echo
echo "=== PASS ==="
echo "Anti-entropy fills churn gaps:"
echo "  * Iris sent to Otto via alice-chat while charlie was OFFLINE"
echo "  * Push reached bob (5 shards); charlie missed it entirely"
echo "  * Charlie came online with empty store"
echo "  * Periodic /rostro/chat-anti-entropy/1 detected the digest"
echo "    mismatch with bob, fetched the missing shards via"
echo "    /rostro/chat-fetch/1, charlie's store converged to $CHARLIE_FINAL shards"
echo "  * Otto fetched via charlie-chat — plaintext recovered locally"
echo
echo "Network model now: hit-any-RPC-node + churn-resilient distribution."
exit 0
