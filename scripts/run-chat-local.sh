#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# LOCAL chat-relay trio for dev testing — runs three non-validator
# gemini-node processes directly on 127.0.0.1 with NO supervisor and
# NO Cannae sandbox. The sandbox needs CAP_SYS_ADMIN (root) which a
# dev box / WSL doesn't have; it's production hardening and orthogonal
# to validating the chat send/recover path. For sandbox-on testing use
# run-chat-trio.sh (as root) or the lab.
#
# RPC: alice 9954, bob 9955, charlie 9956 (localhost). No blocks are
# produced (non-validators) — fine for chat.
#
#   scripts/run-chat-local.sh start   # launch in background
#   scripts/run-chat-local.sh stop    # kill
#   scripts/run-chat-local.sh logs    # tail all three

set -uo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${GEMINI_NODE:-${REPO_ROOT}/target/release/gemini-node}"
DIR="${REPO_ROOT}/.chat-local"
# RISC-V / RostroVM is the ONLY runtime executor (wasm-cull W4/W5);
# the old SUBSTRATE_ENABLE_POLKAVM / ROSTRO_DISABLE_POLKAVM toggles no
# longer exist.

ALICE_KEY="000000000000000000000000000000000000000000000000000000000000000a"
BOB_KEY="000000000000000000000000000000000000000000000000000000000000000b"
CHARLIE_KEY="000000000000000000000000000000000000000000000000000000000000000c"
ALICE_PEER_ID="12D3KooWFNChUebWM7RHCWhypQs6rvs6B8RtKeFXxtR3zT3fchCU"
BOOT="/ip4/127.0.0.1/tcp/30340/p2p/${ALICE_PEER_ID}"
COMMON=(--chain star --no-mdns --rpc-cors=all --rpc-methods unsafe
        -l "info,rostro-chat-gossip=info,rostro-chat-rpc=info,rostro-chat-stripe=info,rostro-chat-fetch=info")

start_one() {
  local name="$1" key="$2" p2p="$3" rpc="$4" prom="$5"; shift 5
  nohup "$BIN" "${COMMON[@]}" \
    --name "$name" --base-path "$DIR/$name" --node-key "$key" \
    --listen-addr "/ip4/0.0.0.0/tcp/${p2p}" \
    --rpc-port "$rpc" --prometheus-port "$prom" "$@" \
    > "$DIR/$name.log" 2>&1 &
  echo "  $name → pid $! (RPC ws://127.0.0.1:$rpc)"
}

case "${1:-start}" in
  start)
    [[ -x "$BIN" ]] || { echo "gemini-node not at $BIN — build it or set GEMINI_NODE=" >&2; exit 1; }
    pkill -f "$DIR" 2>/dev/null; sleep 1; rm -rf "$DIR"; mkdir -p "$DIR"
    echo "starting local chat trio (no supervisor/sandbox):"
    start_one alice "$ALICE_KEY" 30340 9954 9670
    sleep 3
    start_one bob     "$BOB_KEY"     30341 9955 9671 --bootnodes "$BOOT"
    start_one charlie "$CHARLIE_KEY" 30342 9956 9672 --bootnodes "$BOOT"
    echo "--- trio up; holding foreground so the harness keeps it alive ---"
    wait
    ;;
  stop)  pkill -f "$DIR" 2>/dev/null && echo "stopped" || echo "nothing running" ;;
  logs)  tail -n 40 -F "$DIR"/alice.log "$DIR"/bob.log "$DIR"/charlie.log ;;
  *) echo "usage: $0 {start|stop|logs}" >&2; exit 1 ;;
esac
