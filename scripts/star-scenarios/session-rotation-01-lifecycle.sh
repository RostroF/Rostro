#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# session-rotation P3 — consensus-key lifecycle star proof
# (docs/CONSENSUS-KEY-LIFECYCLE.md, workstream 1).
#
# REQUIRES a gemini-node built with the lab-fast-lifecycle feature
# (25-block sessions, 25-block lineage eras):
#
#   SUBSTRATE_RUNTIME_TARGET=riscv cargo build --release \
#     -p gemini-node -p rostro-supervisor --features gemini-node/lab-fast-lifecycle
#
# and the rotation probe:
#
#   (cd scripts/star-scenarios/rotation-probe && cargo build --release)
#
# Proves, on the live 5-node star, in order:
#   1. Genesis boots with session-owned GRANDPA authorities; the lineage
#      pallet captures the roster + genesis keys at the first rotation.
#   2. LIVE KEY ROTATION: bob registers a fresh GRANDPA key via
#      account-signed set_keys (real keystore insert + proof-of-
#      possession); the key activates at a session boundary, GRANDPA's
#      set_id advances, and FINALITY RIDES THROUGH the authority-set
#      change. Lineage records old-key retirement and new-key activation
#      with adjacent set ids.
#   3. RETIRED-KEY CANARY: a signature by bob's retired genesis key over
#      a GRANDPA-domain preimage scoped past its retirement is submitted
#      by ferdie (any account) and accepted; bob is disabled out of the
#      next authority set (disable-and-record).
#   4. HEALING: bob registers another fresh key (account-key authority)
#      and re-enters the set.
#   5. FORCED-ROTATION DEADLINE: alice/charlie/dave rotate in time; eve
#      never rotates. When her key age exceeds K=7 eras she is excluded
#      from the next set (hard cutover), reason DeadlineMissed; finality
#      continues with 4 authorities.
#   6. The validator channel keeps operating across the set changes
#      (certs issued, heartbeats still flowing at the end).
#
# Runtime: ~25-30 min at 6s blocks (era 8 boundary = block 200).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

NODE_BIN="${GEMINI_NODE:-${REPO_ROOT}/target/release/gemini-node}"
SUPERVISOR_BIN="${ROSTRO_SUPERVISOR:-${REPO_ROOT}/target/release/rostro-supervisor}"
PROBE="${ROTATION_PROBE:-${SCRIPT_DIR}/rotation-probe/target/release/rotation-probe}"

for bin in "$NODE_BIN" "$SUPERVISOR_BIN" "$PROBE"; do
	if [[ ! -x "$bin" ]]; then
		echo "binary not found at $bin (see header for build commands)" >&2
		exit 1
	fi
done

# NOTE: a production-lifecycle binary (4h sessions) fails fast in phase 1:
# "session 1 reached" times out at 7 min because the first rotation is 4h
# away. If phase 1 times out while blocks ARE finalizing, rebuild with
# --features gemini-node/lab-fast-lifecycle.

GEMINI_NODE_HASH="$(python3 -c "import hashlib,sys;print(hashlib.blake2b(open(sys.argv[1],'rb').read(),digest_size=32).hexdigest())" "$NODE_BIN")"
export ROSTRO_CANONICAL_GEMINI_NODE_HASH="$GEMINI_NODE_HASH"
export SUBSTRATE_ENABLE_POLKAVM="${SUBSTRATE_ENABLE_POLKAVM:-1}"
echo "canonical hash (seeded): 0x${GEMINI_NODE_HASH}"

STAR_DIR="$REPO_ROOT/.star/rotation"
rm -rf "$STAR_DIR"

setup_node_cache() {
	local base="$1"
	mkdir -p "$base/canonical-cache"
	rm -f "$base/canonical-cache/gemini-node"
	ln "$NODE_BIN" "$base/canonical-cache/gemini-node"
}

for name in alice bob charlie dave eve; do
	setup_node_cache "$STAR_DIR/$name"
done

echo "injecting Sassafras + GRANDPA keys for 5 validators..."
for pair in "//Alice:alice" "//Bob:bob" "//Charlie:charlie" "//Dave:dave" "//Eve:eve"; do
	suri="${pair%%:*}"; name="${pair##*:}"; base="$STAR_DIR/$name"
	"$NODE_BIN" insert-sassafras-key --suri "$suri" --base-path "$base" --chain-id gemini-star
	"$NODE_BIN" key insert --suri "$suri" --key-type gran --scheme ed25519 --base-path "$base" --chain star
done

# Genesis GRANDPA public keys + secret seeds (dev keys; the canary phase
# signs with bob's retired genesis seed — the "leaked old key" threat).
gran_pub() { "$NODE_BIN" key inspect --scheme ed25519 "$1" 2>/dev/null | awk '/Public key \(hex\)/ {print $NF}'; }
gran_seed() { "$NODE_BIN" key inspect --scheme ed25519 "$1" 2>/dev/null | awk '/Secret seed/ {print $NF}'; }
ALICE_GRAN_PUB="$(gran_pub //Alice)"; BOB_GRAN_PUB="$(gran_pub //Bob)"
EVE_GRAN_PUB="$(gran_pub //Eve)"; BOB_GRAN_SEED="$(gran_seed //Bob)"
[[ -n "$BOB_GRAN_PUB" && -n "$BOB_GRAN_SEED" ]] || { echo "failed to derive dev GRANDPA keys" >&2; exit 1; }
echo "bob genesis GRANDPA key: $BOB_GRAN_PUB"

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
# NOTE: gemini validators refuse --rpc-methods=unsafe (by design), so key
# rotation inserts the fresh secret via the file keystore (`key insert`
# against the running node's base path — LocalKeystore scans the directory
# per lookup) and the probe only submits the account-signed set_keys.
COMMON=(--chain star --no-mdns --validator --rpc-cors=all)

start_node() {
	local name="$1" base="$2"
	shift 2
	if [[ "${ROSTRO_NO_SUPERVISOR:-0}" == "1" ]]; then
		"$base/canonical-cache/gemini-node" "$@" \
			> >(tee "$base/run.log" | sed "s/^/[$name] /") 2>&1 &
	else
		"$SUPERVISOR_BIN" --child "$base/canonical-cache/gemini-node" --canonical-dir "$base/canonical-cache" -- "$@" \
			> >(tee "$base/run.log" | sed "s/^/[$name] /") 2>&1 &
	fi
	PIDS+=($!)
}

echo "starting the 5-validator star..."
start_node alice "$STAR_DIR/alice" "${COMMON[@]}" --name alice-star --base-path "$STAR_DIR/alice" \
	--node-key "0000000000000000000000000000000000000000000000000000000000000001" \
	--port 30333 --rpc-port 9944 --prometheus-port 9615 \
	--canonical-files-dir "$STAR_DIR/alice/canonical-cache" --alice
sleep 3
i=1
for name in bob charlie dave eve; do
	i=$((i+1))
	start_node "$name" "$STAR_DIR/$name" "${COMMON[@]}" --name "$name-star" --base-path "$STAR_DIR/$name" \
		--node-key "000000000000000000000000000000000000000000000000000000000000000$i" \
		--port $((30332+i)) --rpc-port $((9943+i)) --prometheus-port $((9614+i)) \
		--bootnodes "$BOOTNODES_MULTIADDR" \
		--canonical-files-dir "$STAR_DIR/$name/canonical-cache" "--$name"
done

WS_ALICE="ws://127.0.0.1:9944"
WS_BOB="ws://127.0.0.1:9945"
WS_CHARLIE="ws://127.0.0.1:9946"
WS_DAVE="ws://127.0.0.1:9947"
WS_EVE="ws://127.0.0.1:9948"

FAIL=0
note() { echo; echo "───── $*"; }

# JSON helpers (python3; jq is not a devbox guarantee). jtest exits 0/1 on
# a python expression over the parsed object `d`; jfield prints a field.
jtest() { python3 -c 'import sys,json; d=json.load(sys.stdin); sys.exit(0 if (eval(sys.argv[1])) else 1)' "$1" 2>/dev/null; }
jfield() { python3 -c 'import sys,json; d=json.load(sys.stdin); print(eval(sys.argv[1]))' "$1"; }

# Rotate a validator's GRANDPA key: fresh seed → file-keystore insert on the
# RUNNING node → probe submits account-signed set_keys (with PoP). Prints
# the probe's JSON result ({account, new_pub, seed}).
rotate_validator() {
	local name="$1" ws="$2" suri="$3"
	local seed
	seed="0x$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
	"$NODE_BIN" key insert --suri "$seed" --key-type gran --scheme ed25519 \
		--base-path "$STAR_DIR/$name" --chain star
	"$PROBE" rotate --ws "$ws" --suri "$suri" --seed "$seed"
}

finalized_number() {
	local h
	h=$(curl -sS -H 'Content-Type: application/json' --max-time 5 \
		-d '{"id":1,"jsonrpc":"2.0","method":"chain_getFinalizedHead","params":[]}' http://127.0.0.1:9944 \
		| jfield 'd["result"]' 2>/dev/null) || { echo 0; return; }
	curl -sS -H 'Content-Type: application/json' --max-time 5 \
		-d "{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"chain_getHeader\",\"params\":[\"$h\"]}" http://127.0.0.1:9944 \
		| jfield 'int(d["result"]["number"], 16)' 2>/dev/null || echo 0
}

session_state() { "$PROBE" session-state --ws "$WS_ALICE"; }

# Poll until `jq expr` over session-state is true, or timeout.
wait_state() {
	local expr="$1" timeout="$2" label="$3"
	local start now
	start=$(date +%s)
	while true; do
		if session_state 2>/dev/null | jtest "$expr"; then
			echo "OK: $label"
			return 0
		fi
		now=$(date +%s)
		if (( now - start > timeout )); then
			echo "FAIL: timeout ($timeout s) waiting for: $label"
			session_state || true
			return 1
		fi
		sleep 6
	done
}

wait_finality_past() {
	local target="$1" timeout="$2"
	local start now n
	start=$(date +%s)
	while true; do
		n=$(finalized_number)
		if (( n > target )); then
			echo "OK: finality advanced past block $target (now #$n)"
			return 0
		fi
		now=$(date +%s)
		if (( now - start > timeout )); then
			echo "FAIL: finality stuck at #$n (needed > $target)"
			return 1
		fi
		sleep 6
	done
}

note "phase 1: boot + first rotation (roster capture, genesis lineage)"
wait_state 'd["session"] >= 1 and d["validator_count"] == 5' 420 \
	"session 1 reached with 5 session-owned validators" || FAIL=1
wait_finality_past 25 300 || FAIL=1
if "$PROBE" lineage-key --ws "$WS_ALICE" --key "$BOB_GRAN_PUB" | jtest 'd["activated"] is not None and d["retired"] is None'; then
	echo "OK: bob's genesis key captured + active in lineage"
else
	echo "FAIL: bob's genesis key not captured in lineage"
	"$PROBE" lineage-key --ws "$WS_ALICE" --key "$BOB_GRAN_PUB" || true
	FAIL=1
fi

note "phase 2: live rotation — bob registers a fresh GRANDPA key"
SET_ID_BEFORE=$(session_state | jfield 'd["set_id"]')
BOB_ROT1_JSON=$(rotate_validator bob "$WS_BOB" //Bob)
echo "$BOB_ROT1_JSON"
BOB_NEW_PUB=$(echo "$BOB_ROT1_JSON" | jfield 'd["new_pub"]')

# Registered key activates two session boundaries later (queue, then live).
wait_state "d[\"set_id\"] >= $((SET_ID_BEFORE + 2))" 500 \
	"set_id advanced across rotation boundaries" || FAIL=1
if "$PROBE" lineage-key --ws "$WS_ALICE" --key "$BOB_GRAN_PUB" | jtest 'd["retired"] is not None'; then
	echo "OK: bob's genesis key RETIRED in lineage"
else
	echo "FAIL: bob's genesis key not retired after rotation"; FAIL=1
fi
RETIRED_SET=$("$PROBE" lineage-key --ws "$WS_ALICE" --key "$BOB_GRAN_PUB" | jfield 'd["retired"]["set_id"]')
ACTIVATED_SET=$("$PROBE" lineage-key --ws "$WS_ALICE" --key "$BOB_NEW_PUB" | jfield 'd["activated"]["set_id"]')
if [[ "$ACTIVATED_SET" == "$((RETIRED_SET + 1))" ]]; then
	echo "OK: lineage set-id continuity (retired at set $RETIRED_SET, successor active at set $ACTIVATED_SET)"
else
	echo "FAIL: set-id continuity broken (retired $RETIRED_SET, activated $ACTIVATED_SET)"; FAIL=1
fi
ROTATION_BLOCK=$(finalized_number)
wait_finality_past $((ROTATION_BLOCK + 10)) 300 || FAIL=1
echo "OK: finality riding through the authority-set change"

note "phase 3: retired-key canary — bob's leaked genesis key self-incriminates"
if "$PROBE" canary --ws "$WS_ALICE" --signer //Ferdie \
	--retired-seed "$BOB_GRAN_SEED" --round 42 --set-id $((RETIRED_SET + 1)) \
	--message "forged-grandpa-domain-preimage"; then
	echo "OK: canary evidence accepted (reported by ferdie, a non-validator)"
else
	echo "FAIL: canary evidence rejected"; FAIL=1
fi
if "$PROBE" disabled --ws "$WS_ALICE" --account bob | jtest 'd["disabled"] and d["reason"] == "Offence"'; then
	echo "OK: bob disabled with reason Offence"
else
	echo "FAIL: bob not offence-disabled"; "$PROBE" disabled --ws "$WS_ALICE" --account bob || true; FAIL=1
fi
wait_state 'd["validator_count"] == 4' 500 "bob excluded from the active set" || FAIL=1

note "phase 4: healing — bob re-keys and re-enters"
rotate_validator bob "$WS_BOB" //Bob >/dev/null
if "$PROBE" disabled --ws "$WS_ALICE" --account bob | jtest 'not d["disabled"]'; then
	echo "OK: fresh set_keys cleared bob's disable record (healing)"
else
	echo "FAIL: bob still disabled after fresh keys"; FAIL=1
fi
wait_state 'd["validator_count"] == 5' 500 "bob back in the active set" || FAIL=1

note "phase 5: forced-rotation deadline — alice/charlie/dave rotate, eve does not"
rotate_validator alice "$WS_ALICE" //Alice >/dev/null
rotate_validator charlie "$WS_CHARLIE" //Charlie >/dev/null
rotate_validator dave "$WS_DAVE" //Dave >/dev/null
echo "rotated alice, charlie, dave; eve left on her genesis key (era-1 registration)"
# Eve's key ages out when era - registered_era > 7 → era 9 → block 225.
# Exclusion lands in the active set one session later. Generous timeout.
wait_state 'd["validator_count"] == 4' 2000 "eve excluded from the active set (deadline miss)" || FAIL=1
if "$PROBE" disabled --ws "$WS_ALICE" --account eve | jtest 'd["disabled"] and d["reason"] == "DeadlineMissed"'; then
	echo "OK: eve disabled with reason DeadlineMissed"
else
	echo "FAIL: eve's disable record wrong"; "$PROBE" disabled --ws "$WS_ALICE" --account eve || true; FAIL=1
fi
if "$PROBE" lineage-key --ws "$WS_ALICE" --key "$EVE_GRAN_PUB" | jtest 'd["retired"] is not None'; then
	echo "OK: eve's genesis key retired on drop-out"
else
	echo "FAIL: eve's key not retired"; FAIL=1
fi
DEADLINE_BLOCK=$(finalized_number)
wait_finality_past $((DEADLINE_BLOCK + 10)) 300 || FAIL=1
echo "OK: finality continues with 4 authorities"

note "phase 6: validator channel across set changes"
HEARTBEATS_BEFORE=$(grep -c "decrypted message from" "$STAR_DIR/bob/run.log" 2>/dev/null || echo 0)
sleep 60
HEARTBEATS_AFTER=$(grep -c "decrypted message from" "$STAR_DIR/bob/run.log" 2>/dev/null || echo 0)
if (( HEARTBEATS_AFTER > HEARTBEATS_BEFORE )); then
	echo "OK: heartbeats still flowing after all set changes ($HEARTBEATS_BEFORE → $HEARTBEATS_AFTER)"
else
	echo "FAIL: no heartbeat progress after set changes ($HEARTBEATS_BEFORE → $HEARTBEATS_AFTER)"
	FAIL=1
fi
for name in alice bob charlie dave; do
	if grep -qE "issued channel cert for epoch" "$STAR_DIR/$name/run.log"; then
		echo "OK [$name]: channel cert issued"
	else
		echo "FAIL [$name]: no channel cert"; FAIL=1
	fi
done

note "final state"
session_state || true
cleanup

echo
if [[ $FAIL -ne 0 ]]; then
	echo "=== session-rotation-01-lifecycle FAILED ==="
	exit 1
fi
echo "=== session-rotation-01-lifecycle PASSED ==="
