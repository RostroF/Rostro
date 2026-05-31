#!/usr/bin/env bash
# Deep-pass driver: one pass per (backend × fault_mode), plus an optional baseline.
# Usage: run-deep.sh [include_baseline=no]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"

INCLUDE_BASELINE="${1:-no}"

TS="$(date +%Y%m%dT%H%M%S)"
CSV="$RESULTS/deep-$TS.csv"
mkdir -p "$RESULTS"
echo "mode,backend,iter,fault_param,pre_fault_height,verify_result,recovery_s,best_after,mismatches" > "$CSV"
log "writing $CSV"

"$HERE/setup-flakey-dev.sh" >/dev/null

modes="pl oom"
[ "$INCLUDE_BASELINE" = "yes" ] && modes="none $modes"

i=1
for mode in $modes; do
  for backend in paritydb rocksdb; do
    line=$("$HERE/iter-deep.sh" "$backend" "$mode" "$i" || echo "deep-$mode,$backend,$i,,,ITER_CRASHED,,,")
    echo "$line" | tee -a "$CSV"
    i=$((i + 1))
  done
done

log "deep-pass complete: $CSV"
"$HERE/summary.sh" "$CSV"
