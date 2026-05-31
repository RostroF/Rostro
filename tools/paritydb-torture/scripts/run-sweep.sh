#!/usr/bin/env bash
# Sweep driver: N iterations × 2 fault modes × 2 backends.
# Writes one CSV file in results/.
# Usage: run-sweep.sh [N=100]
# Iteration timing is roughly: setup ~3s + delay 20-60s + verify ~12s ≈ 50s.
# At N=100 the full sweep is ~5.5 hours of wall time.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"

N="${1:-100}"

[ -x "$GEMINI_NODE" ] || die "gemini-node binary missing: $GEMINI_NODE"
[ -f "$CORPUS" ] || die "corpus missing: $CORPUS"
[ -f "$ORACLE" ] || die "oracle missing: $ORACLE"

TS="$(date +%Y%m%dT%H%M%S)"
CSV="$RESULTS/sweep-$TS.csv"
mkdir -p "$RESULTS"
echo "mode,backend,iter,fault_param,pre_fault_height,verify_result,recovery_s,best_after,mismatches" > "$CSV"
log "writing $CSV"

# Ensure dm-flakey setup once
"$HERE/setup-flakey-dev.sh" >/dev/null

run_one() {
  local mode="$1" backend="$2" iter="$3"
  if [ "$mode" = "power-loss" ]; then
    "$HERE/iter-power-loss.sh" "$backend" "$iter"
  else
    "$HERE/iter-oom.sh" "$backend" "$iter"
  fi
}

# Interleave backends so transient host-state effects (cache warmth, etc.) don't bias one DB.
for i in $(seq 1 "$N"); do
  for mode in power-loss oom; do
    for backend in paritydb rocksdb; do
      line=$(run_one "$mode" "$backend" "$i" || echo "$mode,$backend,$i,,,ITER_CRASHED,,,")
      echo "$line" | tee -a "$CSV"
    done
  done
done

log "sweep complete: $CSV"
log "summary:"
awk -F, 'NR>1 {key=$1"/"$2; tot[key]++; if($6=="PASS")pass[key]++} END{for(k in tot)printf "  %-22s %d/%d pass\n", k, pass[k]+0, tot[k]}' "$CSV"
