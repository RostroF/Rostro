#!/usr/bin/env bash
# Switch dm-flakey between pass-through and drop-writes modes.
# Usage: dm-mode.sh {pass|drop}
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"

if [ -z "${1:-}" ]; then die "usage: dm-mode.sh {pass|drop}"; fi
MODE="$1"
LOOP="$(current_loop_dev)"

case "$MODE" in
  pass)    TABLE="$(printf "$PASSTHRU_TABLE_FMT" "$LOOP")" ;;
  drop)    TABLE="$(printf "$DROP_WRITES_TABLE_FMT" "$LOOP")" ;;
  corrupt) TABLE="$(printf "$CORRUPT_TABLE_FMT" "$LOOP")" ;;
  *) die "unknown mode: $MODE (want: pass|drop|corrupt)" ;;
esac

sudo dmsetup suspend "$DM_NAME"
echo "$TABLE" | sudo dmsetup load "$DM_NAME"
sudo dmsetup resume "$DM_NAME"
log "dm-flakey now in $MODE mode: $TABLE"
