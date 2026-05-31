#!/usr/bin/env bash
# Single power-loss torture iteration.
# Args: BACKEND ITER [MIN_DELAY MAX_DELAY]
# Emits one CSV line to stdout:
#   power-loss,<backend>,<iter>,<fault_delay_s>,<pre_fault_height>,<verify_result>,<recovery_s>,<best_after>,<mismatches>
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"

BACKEND="${1:?backend: paritydb|rocksdb}"
ITER="${2:?iteration number}"
# Import rate is ~7 blocks/sec on this host (slower under lab load). Window
# [20, 60] s lands faults at block ~70 to ~420 — well into active writes,
# past DB-open / runtime-init init noise, but short enough to keep 400-iter
# sweep tractable. The DB's durability behaviour shouldn't depend on whether
# the fault hits block 100 or 4000.
MIN_DELAY="${3:-20}"
MAX_DELAY="${4:-60}"

LOG_DIR="$RESULTS/logs"
mkdir -p "$LOG_DIR"
IMPORT_LOG="$LOG_DIR/pl-$BACKEND-$ITER.import.log"

# Fresh data dir each iter — exercise full open-from-genesis behaviour
DATA_DIR="$MOUNT/data"
sudo rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"

# Ensure dm-flakey starts pass-through
"$HERE/dm-mode.sh" pass >/dev/null

# Launch import. Detach so we can fault mid-flight.
"$GEMINI_NODE" import-blocks \
  --chain star \
  --database="$BACKEND" \
  --base-path "$DATA_DIR" \
  --binary "$CORPUS" \
  > "$IMPORT_LOG" 2>&1 &
NODE_PID=$!

# Random fault delay
FAULT_DELAY=$(( MIN_DELAY + RANDOM % (MAX_DELAY - MIN_DELAY + 1) ))
sleep "$FAULT_DELAY"

# Capture last-best-block from the log BEFORE we fault.
# Substrate logs lines like "Imported #123 (...)" or "best: #123" — match either.
PRE_FAULT_HEIGHT=$(grep -oE '#[0-9]+' "$IMPORT_LOG" | tr -d '#' | sort -n | tail -1 || true)
PRE_FAULT_HEIGHT="${PRE_FAULT_HEIGHT:-0}"

# Flip to drop_writes. Any fsync issued after this point returns success but data
# never reaches the backing image — the "power loss" model.
"$HERE/dm-mode.sh" drop >/dev/null

# Give the DB a brief window to attempt writes that will silently vanish, then kill.
sleep 0.3
kill -9 "$NODE_PID" 2>/dev/null || true
wait "$NODE_PID" 2>/dev/null || true

# Unmount WHILE in drop_writes mode so any dirty pages are dropped, not flushed.
# This is what makes this a real power-loss model (no kernel page cache leak).
sudo umount "$MOUNT" 2>/dev/null || sudo umount -l "$MOUNT" || true

# Restore pass-through, remount (forces ext4 journal replay against post-fault disk).
"$HERE/dm-mode.sh" pass >/dev/null
sudo mount "$DM_DEV" "$MOUNT" || {
  echo "power-loss,$BACKEND,$ITER,$FAULT_DELAY,$PRE_FAULT_HEIGHT,FAIL_REMOUNT,,,,"
  exit 0
}
sudo chown coder:coder "$MOUNT"

# Verify
VERIFY_LINE=$("$HERE/verify.sh" "$DATA_DIR" "$BACKEND" "$ITER" "pl" 2>>"$LOG_DIR/pl-$BACKEND-$ITER.verify.log" || true)
# verify.sh emits: <result>,<recovery_s>,<best_after>,<mismatches>
echo "power-loss,$BACKEND,$ITER,$FAULT_DELAY,$PRE_FAULT_HEIGHT,$VERIFY_LINE"
