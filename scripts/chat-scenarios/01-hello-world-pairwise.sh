#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Scenario 01 — pairwise hello-world over the chat layer.
#
# Demonstrates the end-user-via-RPC model:
#
#   * Iris and Otto are USERS with chat-identity Ed25519 keypairs
#     derived from deterministic seeds (0x11..11 and 0x22..22).
#     Their identities have NOTHING to do with the running nodes —
#     no gemini-node holds Iris's or Otto's secret keys.
#
#   * The 5-node star runs as INFRASTRUCTURE. Each node exposes
#     JSON-RPC; Iris and Otto's CLI processes talk to whichever
#     node they choose.
#
#   * Iris's rostro-chat-cli builds + signs + sealed-sender-seals
#     the envelope locally, then calls chat_send_envelope on
#     alice-star's RPC (port 9944).
#
#   * Otto's rostro-chat-cli calls chat_fetch_shares on the same
#     node, reconstructs + unseals + verifies on-device, prints
#     the plaintext.
#
# The node sees only ciphertext + routing metadata. Even if the
# node were compromised, the attacker could not read the message.
#
# Exit 0 on plaintext-matches-input. Exit 1 on any assertion
# failure (with logs dumped).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
STAR_SCRIPT="$REPO_ROOT/scripts/run-star.sh"
CLI_BIN="${ROSTRO_CHAT_CLI:-${REPO_ROOT}/target/release/rostro-chat-cli}"

# Star startup + propagation budget. RPCs come up before consensus
# is fully going; for chat we only need RPC, so 15s is comfortable
# in CI. Bump via env var for slower hosts.
STAR_WAIT_SECS="${STAR_WAIT_SECS:-15}"

# Deterministic chat-identity seeds for the two demo users. These
# have NOTHING to do with the validator dev keys (--alice etc.) —
# they're user-side identity material, independent of any node.
IRIS_SEED="1111111111111111111111111111111111111111111111111111111111111111"
OTTO_SEED="2222222222222222222222222222222222222222222222222222222222222222"
MESSAGE="hello otto, from iris over the rostro chat layer"

# alice-star is our chosen gateway for both Iris and Otto in this
# scenario. Same-node send + fetch is the simplest path. Cross-node
# scenarios live in 02-*.
ALICE_RPC="http://127.0.0.1:9944"

# Build prerequisites. The CLI + node + supervisor must exist.
for bin in "$CLI_BIN"; do
	if [[ ! -x "$bin" ]]; then
		echo "binary not found at $bin" >&2
		echo "  build first:  cargo build --release -p rostro-chat-cli" >&2
		exit 1
	fi
done

cleanup() {
	if [[ -n "${STAR_PID:-}" ]]; then
		# run-star.sh's own trap handles its child gemini-nodes;
		# SIGINT it and wait for it to drain.
		kill -INT "$STAR_PID" 2>/dev/null || true
		wait "$STAR_PID" 2>/dev/null || true
	fi
}
trap cleanup EXIT

echo "=== scenario 01: chat hello-world (pairwise, same-node) ==="
echo
echo "users (chat-identity holders, NOT nodes):"

# Derive both users' pubkeys + pickup keys locally so we can use
# them downstream. The CLI prints lines like:
#   ed25519_pubkey_hex:  <hex>
# `awk` extracts each field.
IRIS_OUT=$("$CLI_BIN" gen-identity --seed "$IRIS_SEED")
IRIS_PUBKEY=$(echo "$IRIS_OUT" | awk '/^ed25519_pubkey_hex:/ {print $2}')
IRIS_PICKUP=$(echo "$IRIS_OUT" | awk '/^pickup_key_hex:/ {print $2}')

OTTO_OUT=$("$CLI_BIN" gen-identity --seed "$OTTO_SEED")
OTTO_PUBKEY=$(echo "$OTTO_OUT" | awk '/^ed25519_pubkey_hex:/ {print $2}')
OTTO_PICKUP=$(echo "$OTTO_OUT" | awk '/^pickup_key_hex:/ {print $2}')

echo "  Iris ed25519_pubkey: ${IRIS_PUBKEY:0:16}... (pickup ${IRIS_PICKUP:0:16}...)"
echo "  Otto ed25519_pubkey: ${OTTO_PUBKEY:0:16}... (pickup ${OTTO_PICKUP:0:16}...)"
echo

echo "starting star (RPC + chat protocols, wait ${STAR_WAIT_SECS}s)..."
"$STAR_SCRIPT" > /tmp/chat-01-star.out 2>&1 &
STAR_PID=$!

# Poll alice-star's RPC until it responds. Don't sleep blindly —
# slower hosts need more time.
echo "waiting for alice-star RPC to come up..."
SECONDS_WAITED=0
until curl -fsS -X POST -H 'content-type: application/json' \
	-d '{"jsonrpc":"2.0","id":1,"method":"system_name","params":[]}' \
	"$ALICE_RPC" > /dev/null 2>&1; do
	sleep 1
	SECONDS_WAITED=$((SECONDS_WAITED + 1))
	if [[ "$SECONDS_WAITED" -ge "$STAR_WAIT_SECS" ]]; then
		echo "FAIL: alice-star RPC did not come up within ${STAR_WAIT_SECS}s"
		echo "  last 20 lines of star output:"
		tail -20 /tmp/chat-01-star.out | sed 's/^/    /'
		exit 1
	fi
done
echo "  alice-star RPC reachable after ${SECONDS_WAITED}s"
echo

# Confirm chat_nodeInfo works (diagnostic — proves the chat RPC
# surface is live).
echo "diagnostic: alice-star's chat_nodeInfo:"
NODE_INFO=$(curl -fsS -X POST -H 'content-type: application/json' \
	-d '{"jsonrpc":"2.0","id":1,"method":"chat_nodeInfo","params":[]}' \
	"$ALICE_RPC")
echo "  $NODE_INFO"
ALICE_NODE_PUBKEY=$(echo "$NODE_INFO" | sed -n 's/.*"node_pubkey_ed25519_hex":"\([0-9a-f]*\)".*/\1/p')
if [[ -z "$ALICE_NODE_PUBKEY" ]]; then
	echo "FAIL: could not parse alice-star's node_pubkey_ed25519_hex"
	exit 1
fi
echo "  alice-star node pubkey: ${ALICE_NODE_PUBKEY:0:16}..."
echo

# Iris sends to Otto. Note: Iris connects to alice-star via RPC.
# Iris's CHAT identity has nothing to do with alice-star's NODE
# identity; the gemini-node is just acting as Iris's gateway to
# the chat network.
echo "Iris sends to Otto via alice-star RPC..."
"$CLI_BIN" send \
	--node-rpc "$ALICE_RPC" \
	--sender-seed "$IRIS_SEED" \
	--recipient-pubkey "$OTTO_PUBKEY" \
	--message "$MESSAGE" \
	--total-shares 5 > /tmp/chat-01-send.out 2>&1

if ! grep -q "^sent\\.$" /tmp/chat-01-send.out; then
	echo "FAIL: send command did not report success"
	echo "  send output:"
	cat /tmp/chat-01-send.out | sed 's/^/    /'
	exit 1
fi
SENT_MSG_ID=$(awk '/^  message_id_hex:/ {print $2}' /tmp/chat-01-send.out)
echo "  message_id: ${SENT_MSG_ID:0:16}..."
echo

# Diagnostic: confirm alice-star's local store grew.
STORE_LEN_AFTER_SEND=$(curl -fsS -X POST -H 'content-type: application/json' \
	-d '{"jsonrpc":"2.0","id":1,"method":"chat_localStoreLen","params":[]}' \
	"$ALICE_RPC" | sed -n 's/.*"result":\([0-9]*\).*/\1/p')
echo "diagnostic: alice-star chat_localStoreLen after send: $STORE_LEN_AFTER_SEND"
if [[ "$STORE_LEN_AFTER_SEND" -lt 5 ]]; then
	echo "FAIL: expected at least 5 shares stored, got $STORE_LEN_AFTER_SEND"
	exit 1
fi
echo

# Otto fetches via alice-star (same-node path, no --relay-peer).
echo "Otto fetches via alice-star RPC..."
"$CLI_BIN" fetch \
	--node-rpc "$ALICE_RPC" \
	--recipient-seed "$OTTO_SEED" > /tmp/chat-01-fetch.out 2>&1

if ! grep -q "plaintext:" /tmp/chat-01-fetch.out; then
	echo "FAIL: fetch did not return any plaintext"
	echo "  fetch output:"
	cat /tmp/chat-01-fetch.out | sed 's/^/    /'
	exit 1
fi

# Assert the plaintext matches.
RECOVERED=$(awk '/^  plaintext:/ {sub(/^  plaintext:[[:space:]]+/, ""); print; exit}' /tmp/chat-01-fetch.out)
echo "  recovered plaintext: \"$RECOVERED\""
if [[ "$RECOVERED" != "$MESSAGE" ]]; then
	echo "FAIL: plaintext mismatch"
	echo "  expected: \"$MESSAGE\""
	echo "  got:      \"$RECOVERED\""
	echo "  full fetch output:"
	cat /tmp/chat-01-fetch.out | sed 's/^/    /'
	exit 1
fi

# Assert the message_id matches (defensive — ensures we got the
# message we just sent, not a stale one from a previous run).
RECEIVED_MSG_ID=$(awk '/^  message_id:/ {print $2}' /tmp/chat-01-fetch.out)
if [[ "$RECEIVED_MSG_ID" != "$SENT_MSG_ID" ]]; then
	echo "FAIL: message_id mismatch"
	echo "  sent:     $SENT_MSG_ID"
	echo "  received: $RECEIVED_MSG_ID"
	exit 1
fi

# Assert the verified sender pubkey is Iris's.
RECEIVED_SENDER=$(awk '/^  sender_pubkey:/ {print $2}' /tmp/chat-01-fetch.out)
if [[ "$RECEIVED_SENDER" != "$IRIS_PUBKEY" ]]; then
	echo "FAIL: sender_pubkey mismatch"
	echo "  expected: $IRIS_PUBKEY  (Iris)"
	echo "  got:      $RECEIVED_SENDER"
	exit 1
fi

echo
echo "=== PASS ==="
echo "Iris -> Otto round-trip succeeded over the chat layer."
echo "  Iris's identity stayed on the CLI (never reached the node)"
echo "  Otto's X25519 secret stayed on the CLI (decryption was on-device)"
echo "  alice-star saw only ciphertext + routing metadata"
exit 0
