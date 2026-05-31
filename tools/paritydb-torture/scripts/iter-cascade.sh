#!/usr/bin/env bash
# Cascading-crash torture iteration: power-loss, brief recovery, power-loss again.
# Models a flapping host (intermittent power, bad supervisor).
#
# Args: BACKEND ITER [DELAY1 DELAY2]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"

BACKEND="${1:?backend}"
ITER="${2:?iter}"
DELAY1="${3:-$(( 20 + RANDOM % 21 ))}"  # 20-40s before first fault
DELAY2="${4:-$(( 10 + RANDOM % 16 ))}"  # 10-25s between first recovery and second fault

LOG_DIR="$RESULTS/logs"
mkdir -p "$LOG_DIR"
IMPORT1_LOG="$LOG_DIR/cas-$BACKEND-$ITER.import1.log"
IMPORT2_LOG="$LOG_DIR/cas-$BACKEND-$ITER.import2.log"

DATA_DIR="$MOUNT/data"
sudo rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"
"$HERE/dm-mode.sh" pass >/dev/null

fault_cycle() {
  local pid="$1"
  "$HERE/dm-mode.sh" drop >/dev/null
  sleep 0.3
  kill -9 "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  sudo umount "$MOUNT" 2>/dev/null || sudo umount -l "$MOUNT" 2>/dev/null || true
  "$HERE/dm-mode.sh" pass >/dev/null
  sudo mount "$DM_DEV" "$MOUNT" 2>/dev/null || return 1
  sudo chown coder:coder "$MOUNT"
}

# --- First import attempt ---
"$GEMINI_NODE" import-blocks \
  --chain star --database="$BACKEND" --base-path "$DATA_DIR" \
  --binary "$CORPUS" > "$IMPORT1_LOG" 2>&1 &
PID1=$!
sleep "$DELAY1"
PRE1=$(grep -oE 'best block: [0-9]+' "$IMPORT1_LOG" | tail -1 | grep -oE '[0-9]+' || echo 0)

if ! fault_cycle "$PID1"; then
  echo "cascade,$BACKEND,$ITER,${DELAY1}+${DELAY2},$PRE1,FAIL_REMOUNT1,,,,"
  exit 0
fi

# --- Second import attempt (resumes from wherever DB recovered to) ---
"$GEMINI_NODE" import-blocks \
  --chain star --database="$BACKEND" --base-path "$DATA_DIR" \
  --binary "$CORPUS" > "$IMPORT2_LOG" 2>&1 &
PID2=$!
sleep "$DELAY2"
PRE2=$(grep -oE 'best block: [0-9]+' "$IMPORT2_LOG" | tail -1 | grep -oE '[0-9]+' || echo 0)

if ! fault_cycle "$PID2"; then
  echo "cascade,$BACKEND,$ITER,${DELAY1}+${DELAY2},${PRE1}+${PRE2},FAIL_REMOUNT2,,,,"
  exit 0
fi

# --- Verify (third start; should be clean) ---
VERIFY_LINE=$("$HERE/verify.sh" "$DATA_DIR" "$BACKEND" "$ITER" "cas" 2>>"$LOG_DIR/cas-$BACKEND-$ITER.verify.log" || true)
echo "cascade,$BACKEND,$ITER,${DELAY1}+${DELAY2},${PRE1}+${PRE2},$VERIFY_LINE"
