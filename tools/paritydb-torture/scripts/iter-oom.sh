#!/usr/bin/env bash
# Single "OOM" torture iteration.
#
# Scientifically: OOM-killer delivers SIGKILL to a process with page cache
# intact. Functionally equivalent to an external SIGKILL — the kernel will
# subsequently flush whatever dirty pages the dead process wrote. The cgroup
# ceremony is just a (load-dependent, hard-to-tune) way to deliver SIGKILL at
# an unpredictable moment. We deliver SIGKILL at a random delay instead — same
# DB-durability test, no MEM_MAX bracketing required.
#
# Power-loss is the strictly harder cousin (iter-power-loss.sh), where the
# page cache is denied; here it survives.
#
# Args: BACKEND ITER [MIN_DELAY MAX_DELAY]
# Emits one CSV line:
#   oom,<backend>,<iter>,<kill_delay_s>,<pre_kill_height>,<verify_result>,<recovery_s>,<best_after>,<mismatches>
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"

BACKEND="${1:?backend: paritydb|rocksdb}"
ITER="${2:?iteration number}"
MIN_DELAY="${3:-20}"
MAX_DELAY="${4:-60}"

LOG_DIR="$RESULTS/logs"
mkdir -p "$LOG_DIR"
IMPORT_LOG="$LOG_DIR/oom-$BACKEND-$ITER.import.log"

# Plain disk dir — no dm-flakey since the page cache is supposed to survive.
DATA_DIR="/var/lib/paritydb-torture/oom-data"
sudo rm -rf "$DATA_DIR"
sudo mkdir -p "$DATA_DIR"
sudo chown coder:coder "$DATA_DIR"

"$GEMINI_NODE" import-blocks \
  --chain star \
  --database="$BACKEND" \
  --base-path "$DATA_DIR" \
  --binary "$CORPUS" \
  > "$IMPORT_LOG" 2>&1 &
NODE_PID=$!

KILL_DELAY=$(( MIN_DELAY + RANDOM % (MAX_DELAY - MIN_DELAY + 1) ))
sleep "$KILL_DELAY"

PRE_KILL_HEIGHT=$(grep -oE 'best block: [0-9]+' "$IMPORT_LOG" | tail -1 | grep -oE '[0-9]+' || true)
PRE_KILL_HEIGHT="${PRE_KILL_HEIGHT:-0}"

kill -9 "$NODE_PID" 2>/dev/null || true
wait "$NODE_PID" 2>/dev/null || true

VERIFY_LINE=$("$HERE/verify.sh" "$DATA_DIR" "$BACKEND" "$ITER" "oom" 2>>"$LOG_DIR/oom-$BACKEND-$ITER.verify.log" || true)
echo "oom,$BACKEND,$ITER,$KILL_DELAY,$PRE_KILL_HEIGHT,$VERIFY_LINE"
