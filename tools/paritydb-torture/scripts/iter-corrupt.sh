#!/usr/bin/env bash
# Single corrupt_bio_byte torture iteration.
# Like iter-power-loss, but dm-flakey corrupts byte 1 of each write to 0xff
# during the down interval rather than silently dropping. CRUEL: the FS
# metadata is also subject to corruption, so this tests the FS+DB stack
# together. Per-iter mkfs to keep iterations independent.
#
# Args: BACKEND ITER [MIN_DELAY MAX_DELAY]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"

BACKEND="${1:?backend}"
ITER="${2:?iter}"
MIN_DELAY="${3:-20}"
MAX_DELAY="${4:-60}"

LOG_DIR="$RESULTS/logs"
mkdir -p "$LOG_DIR"
IMPORT_LOG="$LOG_DIR/cor-$BACKEND-$ITER.import.log"

# Per-iter mkfs so each iter is independent (corruption from a previous iter
# would otherwise contaminate this one).
"$HERE/dm-mode.sh" pass >/dev/null
sudo umount "$MOUNT" 2>/dev/null || sudo umount -l "$MOUNT" 2>/dev/null || true
sudo mkfs.ext4 -q -F "$DM_DEV"
sudo mount "$DM_DEV" "$MOUNT"
sudo chown coder:coder "$MOUNT"

DATA_DIR="$MOUNT/data"
mkdir -p "$DATA_DIR"

"$GEMINI_NODE" import-blocks \
  --chain star \
  --database="$BACKEND" \
  --base-path "$DATA_DIR" \
  --binary "$CORPUS" \
  > "$IMPORT_LOG" 2>&1 &
NODE_PID=$!

FAULT_DELAY=$(( MIN_DELAY + RANDOM % (MAX_DELAY - MIN_DELAY + 1) ))
sleep "$FAULT_DELAY"

PRE_FAULT_HEIGHT=$(grep -oE 'best block: [0-9]+' "$IMPORT_LOG" | tail -1 | grep -oE '[0-9]+' || true)
PRE_FAULT_HEIGHT="${PRE_FAULT_HEIGHT:-0}"

"$HERE/dm-mode.sh" corrupt >/dev/null
sleep 0.3
kill -9 "$NODE_PID" 2>/dev/null || true
wait "$NODE_PID" 2>/dev/null || true

# umount while corruption is active — any flushed-to-corrupt-device writes get byte-flipped.
sudo umount "$MOUNT" 2>/dev/null || sudo umount -l "$MOUNT" 2>/dev/null || true

"$HERE/dm-mode.sh" pass >/dev/null

# Remount may fail if ext4 superblock got corrupted. Treat as FAIL_REMOUNT.
if ! sudo mount "$DM_DEV" "$MOUNT" 2>/dev/null; then
  echo "corrupt,$BACKEND,$ITER,$FAULT_DELAY,$PRE_FAULT_HEIGHT,FAIL_REMOUNT,,,,"
  exit 0
fi
sudo chown coder:coder "$MOUNT"

VERIFY_LINE=$("$HERE/verify.sh" "$DATA_DIR" "$BACKEND" "$ITER" "cor" 2>>"$LOG_DIR/cor-$BACKEND-$ITER.verify.log" || true)
echo "corrupt,$BACKEND,$ITER,$FAULT_DELAY,$PRE_FAULT_HEIGHT,$VERIFY_LINE"
