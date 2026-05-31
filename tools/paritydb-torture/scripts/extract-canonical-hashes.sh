#!/usr/bin/env bash
# Sample 50 block hashes from the live lab as the ground-truth oracle.
# Output: fixtures/canonical-hashes.txt (one line per sample: "<height> <hash>")
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$HERE/fixtures/canonical-hashes.txt"
RPC="${RPC:-http://127.0.0.1:9945}"   # bob, since alice's 9944 is taken by bp-final
CORPUS_MAX=5000

: > "$OUT"
for i in $(seq 1 50); do
  h=$(( i * CORPUS_MAX / 50 ))
  resp=$(curl -s -m 4 -H 'Content-Type: application/json' \
    -d "{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"chain_getBlockHash\",\"params\":[$h]}" \
    "$RPC")
  hash=$(printf '%s' "$resp" | sed -n 's/.*"result":"\(0x[0-9a-f]*\)".*/\1/p')
  if [ -z "$hash" ]; then
    echo "FAIL: no hash for height $h. resp=$resp" >&2
    exit 1
  fi
  printf '%s %s\n' "$h" "$hash" | tee -a "$OUT"
done
echo "wrote $(wc -l <"$OUT") samples to $OUT"
