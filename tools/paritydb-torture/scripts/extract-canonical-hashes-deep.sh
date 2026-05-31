#!/usr/bin/env bash
# 100 sample heights across 1..50000 as ground-truth for deep-pass tests.
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$HERE/fixtures/canonical-hashes-deep.txt"
RPC="${RPC:-http://127.0.0.1:9945}"
CORPUS_MAX=50000
SAMPLES=100

: > "$OUT"
for i in $(seq 1 $SAMPLES); do
  h=$(( i * CORPUS_MAX / SAMPLES ))
  resp=$(curl -s -m 4 -H 'Content-Type: application/json' \
    -d "{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"chain_getBlockHash\",\"params\":[$h]}" \
    "$RPC")
  hash=$(printf '%s' "$resp" | sed -n 's/.*"result":"\(0x[0-9a-f]*\)".*/\1/p')
  if [ -z "$hash" ]; then echo "FAIL: no hash for height $h. resp=$resp" >&2; exit 1; fi
  printf '%s %s\n' "$h" "$hash" >> "$OUT"
done
echo "wrote $(wc -l <"$OUT") samples to $OUT"
