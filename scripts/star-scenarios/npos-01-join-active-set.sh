#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# npos-01 — active-set churn proof (docs/NPOS.md)
#
# REQUIRES a gemini-node built with the lab-fast-lifecycle feature
# (25-slot sassafras epochs = sessions; 6-session eras = 150 blocks):
#
#   SUBSTRATE_ENABLE_POLKAVM=1 SUBSTRATE_RUNTIME_TARGET=riscv cargo build \
#     --release -p gemini-node --features gemini-node/lab-fast-lifecycle
#
# and the rotation probe:
#
#   (cd scripts/star-scenarios/rotation-probe && cargo build --release)
#
# Proves, on a live 4-node gemini-local network, in order:
#   1. Genesis boots with the STAKING-ELECTED set (alice + bob, from the
#      genesis phragmen election over the genesis stakers), produces and
#      finalizes.
#   2. JOINER: charlie — NOT a genesis authority — bonds, declares
#      validator intent, and registers session keys (fresh hybrid GRANDPA
#      + bandersnatch, two-signature PoP tuple) from a plain account.
#   3. sudo raises validator_count 2 → 3 (the farm churn knob).
#   4. At the next era election charlie ENTERS THE ACTIVE SET: session
#      validators become 3, GRANDPA set rotates, and charlie AUTHORS
#      blocks (sassafras authorities follow the elected set — the
#      genesis-lock is gone).
#
# TOPOLOGY: validators are NOT RPC nodes (Rostro's three-tier submission
# model; external clients hit dedicated RPC nodes behind the operator
# firewall). All probe traffic — state reads AND extrinsic submission —
# goes through `dave`, a non-validator full node. Extrinsics gossip to
# the validators from there. This mirrors the VM farm's control-box
# shape.
#
# Runtime: ~20-30 min at 6s blocks (needs up to two era boundaries after
# the join lands).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

NODE_BIN="${GEMINI_NODE:-${REPO_ROOT}/target/release/gemini-node}"
PROBE="${ROTATION_PROBE:-${SCRIPT_DIR}/rotation-probe/target/release/rotation-probe}"
WORK="${NPOS01_WORK:-/tmp/npos-01-join}"

for bin in "$NODE_BIN" "$PROBE"; do
	if [[ ! -x "$bin" ]]; then
		echo "binary not found at $bin (see header for build commands)" >&2
		exit 1
	fi
done

CHAIN=gemini-local
# Single RPC endpoint: dave, the non-validator full node.
WS=ws://127.0.0.1:9984

# Fail fast on port squatters: a stray node from an earlier run holding an
# RPC port silently redirects the whole scenario onto the wrong chain.
for port in 9981 9982 9983 9984 30411 30412 30413 30414; do
	if ss -tln 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${port}$"; then
		echo "port ${port} already in use — stray gemini-node from an earlier run? kill it first" >&2
		exit 1
	fi
done

note() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

cleanup() {
	[[ -f "$WORK/pids" ]] && kill $(cat "$WORK/pids") 2>/dev/null || true
}
trap cleanup EXIT

rm -rf "$WORK"
mkdir -p "$WORK"/{alice,bob,charlie,dave}

note "phase 0: keystores"
# Genesis validators: session keys must match the chainspec (dev suris).
"$NODE_BIN" key insert --key-type sass --suri //Alice --base-path "$WORK/alice" --chain $CHAIN
"$NODE_BIN" key insert --key-type gran --suri //Alice --base-path "$WORK/alice" --chain $CHAIN
"$NODE_BIN" key insert --key-type sass --suri //Bob --base-path "$WORK/bob" --chain $CHAIN
"$NODE_BIN" key insert --key-type gran --suri //Bob --base-path "$WORK/bob" --chain $CHAIN
# Joiner: bandersnatch from the dev suri; GRANDPA gets a FRESH hybrid key
# (lineage accepts a grandpa key exactly once in chain history).
"$NODE_BIN" key insert --key-type sass --suri //Charlie --base-path "$WORK/charlie" --chain $CHAIN
CHARLIE_GRAN_SEED="0x$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
"$NODE_BIN" key insert --key-type gran --suri "$CHARLIE_GRAN_SEED" --base-path "$WORK/charlie" --chain $CHAIN

note "phase 1: boot validators alice (bootnode), bob, charlie + RPC node dave"
"$NODE_BIN" --chain $CHAIN --validator --base-path "$WORK/alice" \
	--port 30411 --prometheus-port 9631 --unsafe-force-node-key-generation \
	--rpc-port 9981 --name npos-alice > "$WORK/alice.log" 2>&1 &
echo -n "$! " >> "$WORK/pids"

for i in $(seq 1 60); do
	PEER=$(grep -oE "Local node identity is: .*" "$WORK/alice.log" | awk '{print $NF}' | head -1) && [[ -n "${PEER:-}" ]] && break
	sleep 1
done
[[ -n "${PEER:-}" ]] || { echo "alice never printed a peer id" >&2; exit 1; }
BOOT="/ip4/127.0.0.1/tcp/30411/p2p/$PEER"

"$NODE_BIN" --chain $CHAIN --validator --base-path "$WORK/bob" \
	--port 30412 --prometheus-port 9632 --rpc-port 9982 --bootnodes "$BOOT" \
	--unsafe-force-node-key-generation --name npos-bob \
	> "$WORK/bob.log" 2>&1 &
echo -n "$! " >> "$WORK/pids"
"$NODE_BIN" --chain $CHAIN --validator --base-path "$WORK/charlie" \
	--port 30413 --prometheus-port 9633 --rpc-port 9983 --bootnodes "$BOOT" \
	--unsafe-force-node-key-generation --name npos-charlie \
	> "$WORK/charlie.log" 2>&1 &
echo -n "$! " >> "$WORK/pids"
# dave: NOT a validator — the RPC endpoint everything below talks to.
"$NODE_BIN" --chain $CHAIN --base-path "$WORK/dave" \
	--port 30414 --prometheus-port 9634 --rpc-port 9984 --bootnodes "$BOOT" \
	--unsafe-force-node-key-generation --name npos-dave \
	> "$WORK/dave.log" 2>&1 &
echo -n "$! " >> "$WORK/pids"

note "phase 2: genesis set is the staking election result (2 validators)"
for i in $(seq 1 90); do
	STATE=$("$PROBE" session-state --ws $WS 2>/dev/null) && break || sleep 2
done
echo "$STATE"
[[ $(echo "$STATE" | grep -o '"validator_count":[0-9]*' | cut -d: -f2) == 2 ]] \
	|| { echo "expected 2 genesis validators" >&2; exit 1; }

note "phase 3: charlie bonds + validates + registers session keys (via dave)"
"$PROBE" bond-validate --ws $WS --suri //Charlie --bond-ros 100000
"$PROBE" rotate --ws $WS --suri //Charlie --seed "$CHARLIE_GRAN_SEED"

note "phase 4: sudo raises validator_count to 3"
"$PROBE" set-validator-count --ws $WS --suri //Alice --count 3
"$PROBE" staking-state --ws $WS

note "phase 5: wait for charlie to enter the active set at an era boundary"
CHARLIE_SS58=5FLSigC9HGRKVhB9FiEo4Y3koPsNmBmLJbpXg2mp1hXcS59Y
deadline=$((SECONDS + 2100)) # up to two eras + margin
while (( SECONDS < deadline )); do
	STATE=$("$PROBE" session-state --ws $WS 2>/dev/null || true)
	if echo "$STATE" | grep -q "$CHARLIE_SS58"; then
		echo "$STATE"
		break
	fi
	sleep 15
done
echo "$STATE" | grep -q "$CHARLIE_SS58" || { echo "charlie never entered the active set" >&2; exit 1; }

note "phase 6: charlie authors blocks (sassafras follows the elected set)"
deadline=$((SECONDS + 600))
while (( SECONDS < deadline )); do
	if grep -q "Pre-sealed block" "$WORK/charlie.log"; then
		grep -m1 "Pre-sealed block" "$WORK/charlie.log"
		break
	fi
	sleep 10
done
grep -q "Pre-sealed block" "$WORK/charlie.log" || { echo "charlie never authored" >&2; exit 1; }

note "PASS: joiner bonded, was elected, entered the active set, and authored"
"$PROBE" staking-state --ws $WS
"$PROBE" session-state --ws $WS
