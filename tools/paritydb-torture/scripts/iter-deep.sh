#!/usr/bin/env bash
# Single deep-pass: import 50k blocks, fault at depth, verify against deep oracle.
# Expensive — ~90-120 min per iter. Run a small handful per (backend × fault mode).
#
# Args: BACKEND FAULT_MODE ITER [FAULT_DELAY_S]
#   FAULT_MODE: pl (power-loss) | oom (SIGKILL) | none (import-to-completion sanity)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"

BACKEND="${1:?backend}"
MODE="${2:?mode: pl|oom|none}"
ITER="${3:?iter}"
# Default fault delay: ~4500s aims for ~block 31500 at 7 bps (60-70% through the import).
FAULT_DELAY="${4:-4500}"

LOG_DIR="$RESULTS/logs"
mkdir -p "$LOG_DIR"
IMPORT_LOG="$LOG_DIR/deep-$MODE-$BACKEND-$ITER.import.log"

case "$MODE" in
  pl)
    DATA_DIR="$MOUNT/data"
    sudo rm -rf "$DATA_DIR"
    mkdir -p "$DATA_DIR"
    "$HERE/dm-mode.sh" pass >/dev/null
    ;;
  oom|none)
    DATA_DIR="/var/lib/paritydb-torture/deep-data"
    sudo rm -rf "$DATA_DIR"
    sudo mkdir -p "$DATA_DIR"
    sudo chown coder:coder "$DATA_DIR"
    ;;
  *) die "unknown mode: $MODE" ;;
esac

"$GEMINI_NODE" import-blocks \
  --chain star --database="$BACKEND" --base-path "$DATA_DIR" \
  --binary "$CORPUS_DEEP" > "$IMPORT_LOG" 2>&1 &
NODE_PID=$!

if [ "$MODE" = "none" ]; then
  # Sanity baseline: let import complete (no fault). Bounds the upper time.
  wait "$NODE_PID" || true
else
  sleep "$FAULT_DELAY"
fi

PRE_FAULT_HEIGHT=$(grep -oE 'best block: [0-9]+' "$IMPORT_LOG" | tail -1 | grep -oE '[0-9]+' || true)
PRE_FAULT_HEIGHT="${PRE_FAULT_HEIGHT:-0}"

case "$MODE" in
  pl)
    "$HERE/dm-mode.sh" drop >/dev/null
    sleep 0.3
    kill -9 "$NODE_PID" 2>/dev/null || true
    wait "$NODE_PID" 2>/dev/null || true
    sudo umount "$MOUNT" 2>/dev/null || sudo umount -l "$MOUNT" 2>/dev/null || true
    "$HERE/dm-mode.sh" pass >/dev/null
    sudo mount "$DM_DEV" "$MOUNT" || {
      echo "deep-$MODE,$BACKEND,$ITER,$FAULT_DELAY,$PRE_FAULT_HEIGHT,FAIL_REMOUNT,,,,"
      exit 0
    }
    sudo chown coder:coder "$MOUNT"
    ;;
  oom)
    kill -9 "$NODE_PID" 2>/dev/null || true
    wait "$NODE_PID" 2>/dev/null || true
    ;;
esac

# Verify against the DEEP oracle (100 samples across 1..50000).
VERIFY_LINE=$(ORACLE="$ORACLE_DEEP" "$HERE/verify.sh" "$DATA_DIR" "$BACKEND" "$ITER" "deep-$MODE" 2>>"$LOG_DIR/deep-$MODE-$BACKEND-$ITER.verify.log" || true)
echo "deep-$MODE,$BACKEND,$ITER,$FAULT_DELAY,$PRE_FAULT_HEIGHT,$VERIFY_LINE"
