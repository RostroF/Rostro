#!/usr/bin/env bash
# Wait for the currently-running baseline sweep to finish, then sequentially:
#   1. corrupt_bio_byte sweep (N=100)
#   2. cascading-crash sweep (N=100)
#   3. deep-pass (1 per quadrant)
# All output to results/. Self-contained — launch with nohup &.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"

PID_FILE="$RESULTS/sweep.pid"
[ -r "$PID_FILE" ] || die "$PID_FILE missing — is the baseline sweep running?"
BASELINE_PID="$(cat "$PID_FILE")"
log "waiting for baseline sweep pid=$BASELINE_PID"
while kill -0 "$BASELINE_PID" 2>/dev/null; do sleep 60; done
log "baseline done — starting corrupt sweep"

"$HERE/run-corrupt-sweep.sh" 100 > "$RESULTS/corrupt-stdout.log" 2>&1 || log "corrupt sweep exited non-zero"

log "corrupt done — starting cascade sweep"
"$HERE/run-cascade-sweep.sh" 100 > "$RESULTS/cascade-stdout.log" 2>&1 || log "cascade sweep exited non-zero"

log "cascade done — starting deep-pass"
"$HERE/run-deep.sh" no > "$RESULTS/deep-stdout.log" 2>&1 || log "deep-pass exited non-zero"

log "ALL FOLLOWUPS COMPLETE"
