#!/usr/bin/env bash
# Restart node against post-fault data dir; check 3 gates:
#   1. DB reopens and RPC responds within 30s
#   2. Best-block hash matches canonical for every oracle height <= best
#   3. Recovery time <= 30s
# Emits: <PASS|FAIL_xxx>,<recovery_s>,<best_after>,<mismatches>
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"

DATA_DIR="${1:?data dir}"
BACKEND="${2:?backend}"
ITER="${3:?iter}"
TAG="${4:?tag (pl|oom)}"

LOG_DIR="$RESULTS/logs"
NODE_LOG="$LOG_DIR/$TAG-$BACKEND-$ITER.verify.log"

# Distinct ports per (iter, tag, backend) — avoid TIME_WAIT collisions across
# the 4 quadrants of a single iteration. PORT_BASE / P2P_BASE can be overridden
# so parallel sweeps (e.g. byteflip running alongside cascade) don't collide.
case "$TAG/$BACKEND" in
  pl/paritydb)  OFF=0 ;;
  pl/rocksdb)   OFF=1 ;;
  oom/paritydb) OFF=2 ;;
  oom/rocksdb)  OFF=3 ;;
  *)            OFF=0 ;;
esac
PORT=$(( ${PORT_BASE:-39000} + (ITER % 200) * 4 + OFF ))
P2P=$(( ${P2P_BASE:-41000} + (ITER % 200) * 4 + OFF ))

# Launch as RPC-only node, no networking, no validator
"$GEMINI_NODE" \
  --chain star \
  --database="$BACKEND" \
  --base-path "$DATA_DIR" \
  --rpc-port "$PORT" \
  --port "$P2P" \
  --no-mdns --no-prometheus --no-telemetry \
  --offchain-worker=never \
  > "$NODE_LOG" 2>&1 &
NODE_PID=$!

START=$(date +%s)
DEADLINE=$(( START + 30 ))
RPC_OK=false
BEST_HEX=""

while [ "$(date +%s)" -lt "$DEADLINE" ]; do
  RESP=$(curl -s -m 2 -H 'Content-Type: application/json' \
    -d '{"id":1,"jsonrpc":"2.0","method":"chain_getHeader","params":[]}' \
    "http://127.0.0.1:$PORT" 2>/dev/null || true)
  if printf '%s' "$RESP" | grep -q '"number"'; then
    BEST_HEX=$(printf '%s' "$RESP" | sed -n 's/.*"number":"\(0x[0-9a-f]*\)".*/\1/p')
    RPC_OK=true
    break
  fi
  sleep 0.5
done
RECOVERY=$(( $(date +%s) - START ))

if ! $RPC_OK; then
  # Capture forensics BEFORE killing the hung node — once we kill, the on-disk
  # state gets clobbered by the next iter's rm -rf and the smoking gun is gone.
  HANG_DIR="$RESULTS/hangs/$TAG-$BACKEND-$ITER"
  mkdir -p "$HANG_DIR"
  # 1. Stack trace of every thread (sudo needed: ptrace_scope=1)
  sudo gdb -batch -p "$NODE_PID" \
    -ex 'set pagination off' \
    -ex 'thread apply all bt' \
    -ex detach -ex quit \
    > "$HANG_DIR/backtrace.txt" 2>&1 || true
  # 2. 5 s of syscall trace — what is it actually doing? Use --kill-after so
  # we don't deadlock when SIGTERM fails to propagate through sudo to strace.
  timeout --kill-after=2 5 sudo strace -f -p "$NODE_PID" -e trace=openat,read,write,fsync,futex \
    -o "$HANG_DIR/strace.log" 2>/dev/null || true
  # 3. Frozen snapshot of the data dir at moment of hang
  tar -cf - -C "$(dirname "$DATA_DIR")" "$(basename "$DATA_DIR")" 2>/dev/null \
    | gzip > "$HANG_DIR/data-dir.tar.gz" || true
  # 4. Verify log up to this point
  cp "$NODE_LOG" "$HANG_DIR/verify.log" 2>/dev/null || true

  kill -9 "$NODE_PID" 2>/dev/null || true
  wait "$NODE_PID" 2>/dev/null || true
  echo "FAIL_REOPEN,$RECOVERY,0,0"
  exit 0
fi

BEST=$(( BEST_HEX ))   # bash treats 0x... as hex

# Sample-check every oracle height <= BEST
MISMATCH=0
CHECKED=0
while read -r height expected; do
  [ -z "$height" ] && continue
  if [ "$height" -gt "$BEST" ]; then continue; fi
  CHECKED=$((CHECKED + 1))
  RESP=$(curl -s -m 2 -H 'Content-Type: application/json' \
    -d "{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"chain_getBlockHash\",\"params\":[$height]}" \
    "http://127.0.0.1:$PORT" 2>/dev/null || true)
  got=$(printf '%s' "$RESP" | sed -n 's/.*"result":"\(0x[0-9a-f]*\)".*/\1/p')
  if [ "$got" != "$expected" ]; then
    MISMATCH=$((MISMATCH + 1))
    echo "MISMATCH height=$height expected=$expected got=$got" >&2
  fi
done < "$ORACLE"

kill -9 "$NODE_PID" 2>/dev/null || true
wait "$NODE_PID" 2>/dev/null || true

if [ "$MISMATCH" -gt 0 ]; then
  echo "FAIL_HASH,$RECOVERY,$BEST,$MISMATCH"
elif [ "$RECOVERY" -gt 30 ]; then
  echo "FAIL_SLOW,$RECOVERY,$BEST,0"
else
  echo "PASS,$RECOVERY,$BEST,0"
fi
