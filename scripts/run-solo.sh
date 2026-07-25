#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Spawn a single-node solochain — one `gemini-node` Alice validator on the
# `dev` chain spec that authors and finalizes blocks by itself. The modern
# equivalent of the historical "solochain" bootstrap: no farm, no quorum.
#
# A lone Sassafras authority self-authors every slot via the deterministic
# round-robin fallback (one authority => `% 1 == 0` => Alice always wins),
# and single-node GRANDPA finalizes 1-of-1. Use it for metadata regen,
# extrinsic round-trips, and quick chain-side smoke tests without the lab.
#
# Usage:
#   scripts/run-solo.sh                 # launch on ws://127.0.0.1:9944 (Ctrl-C stops)
#   scripts/run-solo.sh --fresh         # wipe the base-path first (needed after a spec bump)
#   scripts/run-solo.sh --rpc-port 9955 # override the RPC port
#   GEMINI_NODE=/path/to/gemini-node scripts/run-solo.sh   # use a specific binary
#
# After it is up:
#   subxt metadata --url ws://127.0.0.1:9944 -f bytes > out.scale   # regen metadata
#   curl -s -H 'Content-Type: application/json' \
#     -d '{"id":1,"jsonrpc":"2.0","method":"state_getRuntimeVersion","params":[]}' \
#     http://127.0.0.1:9944                                          # check spec version

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NODE_BIN="${GEMINI_NODE:-${REPO_ROOT}/target/release/gemini-node}"
BASE="${REPO_ROOT}/.solo"
RPC_PORT=9944
FRESH=0

# Dev-only deterministic libp2p node-key. Recent Substrate no longer
# auto-generates the network identity key, so we pin one. DO NOT use on any
# real network — anyone with the repo can derive the peer id.
NODE_KEY="0000000000000000000000000000000000000000000000000000000000000001"

while [[ $# -gt 0 ]]; do
	case "$1" in
		--fresh) FRESH=1; shift ;;
		--rpc-port) RPC_PORT="$2"; shift 2 ;;
		-h|--help) sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
		*) echo "unknown argument: $1" >&2; exit 2 ;;
	esac
done

if [[ ! -x "$NODE_BIN" ]]; then
	echo "gemini-node binary not found at $NODE_BIN" >&2
	echo "  build it first:  cargo build --release -p gemini-node" >&2
	exit 1
fi

if [[ "$FRESH" == "1" ]]; then
	echo "wiping base-path $BASE ..."
	rm -rf "$BASE"
fi
mkdir -p "$BASE"

# Inject Alice's Sassafras (bandersnatch) authority key. The stock `--alice`
# keyring flag does NOT provide it, so without this the validator logs
# "no local bandersnatch key in the active authority set" and stalls at #0.
# Keystore inserts are idempotent for the same SURI, so this is safe to re-run.
echo "injecting Alice's Sassafras (bandersnatch) key..."
"$NODE_BIN" key insert --key-type sass \
	--suri //Alice --base-path "$BASE" --chain dev

cleanup() {
	echo
	echo "stopping solo node..."
	[[ -n "${NODE_PID:-}" ]] && kill "$NODE_PID" 2>/dev/null || true
	wait 2>/dev/null || true
}
trap cleanup INT TERM EXIT

echo "starting solo node (dev chain, rpc ws://127.0.0.1:${RPC_PORT})..."
echo "  (if it aborts on a WSL sandbox/mount error, prefix with:"
echo "   ROSTRO_SKIP_LANDLOCK=1 ROSTRO_SKIP_SECCOMP=1 ROSTRO_SKIP_NOEXEC=1)"
"$NODE_BIN" \
	--chain dev \
	--validator \
	--alice \
	--base-path "$BASE" \
	--node-key "$NODE_KEY" \
	--rpc-port "$RPC_PORT" \
	--rpc-cors=all \
	--no-mdns \
	--name solo 2>&1 | sed 's/^/[solo] /' &
NODE_PID=$!

wait
