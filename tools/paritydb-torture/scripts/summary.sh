#!/usr/bin/env bash
# Print running distribution from a sweep CSV. One self-contained block of text.
# Usage: summary.sh <csv>
set -euo pipefail
CSV="${1:?usage: summary.sh <csv>}"

awk -F, '
NR == 1 { next }
{
  k = $1 "/" $2
  total[k]++
  if ($6 == "PASS")        pass[k]++
  if ($6 ~ /^FAIL_/)       fail[k]++
  rec[k, total[k]] = $7
  best[k, total[k]] = $8
}
function pct(arr, k, n, p,    i, vals, idx) {
  for (i = 1; i <= n; i++) vals[i] = arr[k, i] + 0
  # insertion sort, fine for n <= a few hundred
  for (i = 2; i <= n; i++) {
    v = vals[i]; j = i - 1
    while (j > 0 && vals[j] > v) { vals[j+1] = vals[j]; j-- }
    vals[j+1] = v
  }
  idx = int(p * n / 100 + 0.5); if (idx < 1) idx = 1; if (idx > n) idx = n
  return vals[idx]
}
END {
  printf "%-22s %-9s %-9s %-18s %-18s\n", "mode/backend", "PASS", "FAIL", "recovery_s p50/p95", "best_after p50/p95"
  # Collect & sort keys from the data, not a hardcoded list — works for any sweep type.
  n = 0
  for (k in total) keys[++n] = k
  # Simple alpha sort
  for (i = 2; i <= n; i++) { v = keys[i]; j = i - 1
    while (j > 0 && keys[j] > v) { keys[j+1] = keys[j]; j-- }
    keys[j+1] = v }
  for (i = 1; i <= n; i++) {
    k = keys[i]; t = total[k] + 0
    if (t == 0) continue
    p50r = pct(rec, k, t, 50); p95r = pct(rec, k, t, 95)
    p50b = pct(best, k, t, 50); p95b = pct(best, k, t, 95)
    printf "%-22s %d/%-7d %-9d %d / %-13d %d / %d\n", k, pass[k]+0, t, fail[k]+0, p50r, p95r, p50b, p95b
  }
}' "$CSV"
