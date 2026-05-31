#!/usr/bin/env bash
# Byte-flip sweep: N iters per (backend × K-level).
# K-levels exercise different recovery paths:
#   K=1     — single bit-flip; should trip per-block CRC if backend uses them
#   K=100   — small region; likely within one block
#   K=1024  — mid-region (1 KB)
#   K=10240 — multi-block region (10 KB)
#
# Usage: run-byteflip-sweep.sh [N=25]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"

N="${1:-25}"
TS="$(date +%Y%m%dT%H%M%S)"
CSV="$RESULTS/byteflip-$TS.csv"
mkdir -p "$RESULTS/logs"
echo "mode,backend,iter,fault_param,pre_fault_height,verify_result,recovery_s,best_after,mismatches" > "$CSV"
log "writing $CSV"

"$HERE/setup-warm-snapshots.sh" >&2

for K in 1 100 1024 10240; do
  log "--- K=$K bytes ---"
  for i in $(seq 1 "$N"); do
    for backend in paritydb rocksdb; do
      line=$("$HERE/iter-byteflip.sh" "$backend" "$i" "$K" \
        || echo "byteflip-$K,$backend,$i,$K,,ITER_CRASHED,,,")
      echo "$line" | tee -a "$CSV"
    done
  done
done

log "byteflip sweep complete: $CSV"
"$HERE/summary.sh" "$CSV"
