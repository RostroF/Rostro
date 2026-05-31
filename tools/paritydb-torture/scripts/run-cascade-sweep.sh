#!/usr/bin/env bash
# Sweep driver for cascading-crash: N iterations × 2 backends.
# Usage: run-cascade-sweep.sh [N=100]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"

N="${1:-100}"
TS="$(date +%Y%m%dT%H%M%S)"
CSV="$RESULTS/cascade-$TS.csv"
mkdir -p "$RESULTS"
echo "mode,backend,iter,fault_param,pre_fault_height,verify_result,recovery_s,best_after,mismatches" > "$CSV"
log "writing $CSV"

"$HERE/setup-flakey-dev.sh" >/dev/null

for i in $(seq 1 "$N"); do
  for backend in paritydb rocksdb; do
    line=$("$HERE/iter-cascade.sh" "$backend" "$i" || echo "cascade,$backend,$i,,,ITER_CRASHED,,,")
    echo "$line" | tee -a "$CSV"
  done
done

log "cascade sweep complete: $CSV"
"$HERE/summary.sh" "$CSV"
