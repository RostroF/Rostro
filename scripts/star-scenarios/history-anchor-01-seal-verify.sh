#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# history-anchor P3 — dual-hash anchor star proof
# (pallet-rostro-history-anchor, spec 104).
#
# REQUIRES a gemini-node built with the lab-fast-lifecycle feature
# (25-block sessions):
#
#   SUBSTRATE_ENABLE_POLKAVM=1 SUBSTRATE_RUNTIME_TARGET=riscv \
#     cargo build --release -p gemini-node --features gemini-node/lab-fast-lifecycle
#
# and the offline verifier:
#
#   cargo build --release -p rostro-history-anchor-verify
#
# Proves, on the live 5-validator star, in order:
#   1. Genesis boots WITH the mandatory-on-schedule seal inherent: block 1
#      seals the genesis header and finality advances (the inherent does
#      not brick authoring).
#   2. FIRST SESSION ROTATION (block 25): the incoming set's first block
#      seals the outgoing set's final header. The offline verifier
#      recomputes the whole Keccak-512 chain from raw headers over RPC
#      and reproduces every on-chain snapshot + the live head (exit 0).
#   3. SECOND ROTATION: verifier passes again AND reproduces the head
#      captured at phase 2 via --expect-head — the published-head
#      workflow an archive/SRT would use decades later.
#   4. NEGATIVE CONTROL: --expect-head with 64 junk bytes must FAIL
#      (the verifier is capable of saying no).
#   5. Finality still advancing at the end.
#
# Runtime: ~8-10 min at lab-fast timings. Keep well under block ~200:
# nobody rotates GRANDPA keys in this scenario, so the K=7 lineage
# deadline would start excluding validators around era 8.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

NODE_BIN="${GEMINI_NODE:-${REPO_ROOT}/target/release/gemini-node}"
VERIFIER="${ANCHOR_VERIFIER:-${REPO_ROOT}/target/release/rostro-history-anchor-verify}"
SUPERVISOR_BIN="${ROSTRO_SUPERVISOR:-${REPO_ROOT}/target/release/rostro-supervisor}"
ROSTRO_NO_SUPERVISOR="${ROSTRO_NO_SUPERVISOR:-1}"

for bin in "$NODE_BIN" "$VERIFIER"; do
	if [[ ! -x "$bin" ]]; then
		echo "binary not found at $bin (see header for build commands)" >&2
		exit 1
	fi
done
if [[ "$ROSTRO_NO_SUPERVISOR" != "1" && ! -x "$SUPERVISOR_BIN" ]]; then
	echo "supervisor not found at $SUPERVISOR_BIN" >&2
	exit 1
fi

# Preflight: refuse to start over leftovers (the pq-finality lesson —
# stale star nodes share the fixed dev node-keys, collide on peer IDs,
# and produce hours of red herrings). We never kill blindly; we refuse.
if pgrep -x gemini-node >/dev/null 2>&1; then
	echo "REFUSING to start: gemini-node processes already running:" >&2
	pgrep -ax gemini-node >&2
	echo "kill them BY PID first (never unscoped pkill)." >&2
	exit 1
fi
for port in 9944 9945 9946 9947 9948 30333 30334 30335 30336 30337; do
	if ss -tln 2>/dev/null | grep -q ":$port "; then
		echo "REFUSING to start: port $port already bound." >&2
		exit 1
	fi
done

GEMINI_NODE_HASH="$(python3 -c "import hashlib,sys;print(hashlib.blake2b(open(sys.argv[1],'rb').read(),digest_size=32).hexdigest())" "$NODE_BIN")"
export ROSTRO_CANONICAL_GEMINI_NODE_HASH="$GEMINI_NODE_HASH"
export SUBSTRATE_ENABLE_POLKAVM="${SUBSTRATE_ENABLE_POLKAVM:-1}"
echo "canonical hash (seeded): 0x${GEMINI_NODE_HASH}"

STAR_DIR="$REPO_ROOT/.star/history-anchor"
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

# Hybrid GRANDPA keys (post-PQ-cutover: --scheme rostro-hybrid).
echo "injecting Sassafras + HYBRID GRANDPA keys for 5 validators..."
for pair in "//Alice:alice" "//Bob:bob" "//Charlie:charlie" "//Dave:dave" "//Eve:eve"; do
	suri="${pair%%:*}"; name="${pair##*:}"; base="$STAR_DIR/$name"
	"$NODE_BIN" insert-sassafras-key --suri "$suri" --base-path "$base" --chain-id gemini-star
	"$NODE_BIN" key insert --suri "$suri" --key-type gran --scheme rostro-hybrid --base-path "$base" --chain star
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
COMMON=(--chain star --no-mdns --validator --rpc-cors=all)

start_node() {
	local name="$1" base="$2"
	shift 2
	if [[ "$ROSTRO_NO_SUPERVISOR" == "1" ]]; then
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

RPC_ALICE="http://127.0.0.1:9944"
FAIL=0
note() { echo; echo "───── $*"; }

jfield() { python3 -c 'import sys,json; d=json.load(sys.stdin); print(eval(sys.argv[1]))' "$1"; }

finalized_number() {
	local h
	h=$(curl -sS -H 'Content-Type: application/json' --max-time 5 \
		-d '{"id":1,"jsonrpc":"2.0","method":"chain_getFinalizedHead","params":[]}' "$RPC_ALICE" \
		| jfield 'd["result"]' 2>/dev/null) || { echo 0; return; }
	curl -sS -H 'Content-Type: application/json' --max-time 5 \
		-d "{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"chain_getHeader\",\"params\":[\"$h\"]}" "$RPC_ALICE" \
		| jfield 'int(d["result"]["number"], 16)' 2>/dev/null || echo 0
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

# Run the verifier; capture output; assert exit code and minimum seal
# count; return the recomputed head via the VERIFIER_HEAD global.
VERIFIER_HEAD=""
run_verifier() {
	local min_seals="$1"; shift
	local out rc=0
	out=$("$VERIFIER" --url "$RPC_ALICE" "$@" 2>&1) || rc=$?
	echo "$out" | sed 's/^/    | /'
	if (( rc != 0 )); then
		echo "FAIL: verifier exit $rc"
		return 1
	fi
	local seals
	seals=$(echo "$out" | sed -n 's/^seals verified: \([0-9]*\),.*/\1/p')
	if [[ -z "$seals" || "$seals" -lt "$min_seals" ]]; then
		echo "FAIL: expected >= $min_seals seals, got '${seals:-none}'"
		return 1
	fi
	VERIFIER_HEAD=$(echo "$out" | sed -n 's/^current head (publish this): \(0x[0-9a-f]*\)$/\1/p')
	if [[ -z "$VERIFIER_HEAD" ]]; then
		echo "FAIL: no head in verifier output"
		return 1
	fi
	echo "OK: verifier passed with $seals seals, head ${VERIFIER_HEAD:0:18}…"
	return 0
}

note "phase 1: genesis + block-1 seal — finality must advance"
wait_finality_past 2 420 || FAIL=1

note "phase 2: first session rotation (block ~25) — full offline recompute"
wait_finality_past 30 420 || FAIL=1
run_verifier 2 || FAIL=1
HEAD_A="$VERIFIER_HEAD"

note "phase 3: second rotation — recompute + published-head (--expect-head) check"
wait_finality_past 55 420 || FAIL=1
run_verifier 3 --expect-head "$HEAD_A" || FAIL=1

note "phase 4: publication payload + century capsule (P4)"
PUB=$("$VERIFIER" --url "$RPC_ALICE" publication 2>"$STAR_DIR/pub.stderr") || { echo "FAIL: publication exit"; FAIL=1; }
echo "$PUB" | sed 's/^/    | /'
sed 's/^/    | /' "$STAR_DIR/pub.stderr"
if ! echo "$PUB" | head -1 | grep -q "^ROSTRO HISTORY ANCHOR PUBLICATION v1$"; then
	echo "FAIL: payload header line wrong"
	FAIL=1
fi
PUB_HEAD=$(echo "$PUB" | sed -n 's/^head: \(0x[0-9a-f]\{128\}\)$/\1/p')
if [[ -z "$PUB_HEAD" ]]; then
	echo "FAIL: no well-formed head in payload"
	FAIL=1
elif "$VERIFIER" --url "$RPC_ALICE" --expect-head "$PUB_HEAD" >/dev/null 2>&1; then
	echo "OK: publication payload head verifies against the live chain"
else
	echo "FAIL: payload head not reproduced by the live chain"
	FAIL=1
fi
CAPSULE_DIR="$STAR_DIR/capsule"
CAPOUT=$("$VERIFIER" --url "$RPC_ALICE" capsule --out "$CAPSULE_DIR" 2>&1) || { echo "FAIL: capsule exit"; FAIL=1; }
echo "$CAPOUT" | tail -3 | sed 's/^/    | /'
if ! echo "$CAPOUT" | grep -q "capsule re-verified offline"; then
	echo "FAIL: capsule self-reverification missing"
	FAIL=1
fi
if "$VERIFIER" verify-capsule --dir "$CAPSULE_DIR" >/dev/null 2>&1; then
	echo "OK: independent offline verify-capsule passed (no RPC)"
else
	echo "FAIL: offline verify-capsule failed"
	FAIL=1
fi

note "phase 5: negative control — junk published head must FAIL"
if "$VERIFIER" --url "$RPC_ALICE" --expect-head "0x$(printf '00%.0s' {1..64})" >/dev/null 2>&1; then
	echo "FAIL: verifier accepted a junk published head"
	FAIL=1
else
	echo "OK: junk published head rejected (nonzero exit)"
fi

note "phase 6: finality still advancing with seals live"
n=$(finalized_number)
wait_finality_past "$n" 120 || FAIL=1

if grep -l "panicked" "$STAR_DIR"/*/run.log 2>/dev/null; then
	echo "FAIL: node panic found in logs above"
	FAIL=1
fi

echo
if (( FAIL == 0 )); then
	echo "═════ history-anchor-01: ALL PHASES PASSED ═════"
else
	echo "═════ history-anchor-01: FAILURES (see above) ═════"
fi
exit "$FAIL"
