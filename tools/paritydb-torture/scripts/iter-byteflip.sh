#!/usr/bin/env bash
# Post-fault byte-flip corruption iteration: restore warm DB snapshot, flip K
# random bytes in a random DB file, restart, verify. Surgical — only DB files
# touched, FS metadata untouched. Differential signal between backends is
# pure DB-recovery behaviour.
#
# Args: BACKEND ITER K_BYTES
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"

BACKEND="${1:?backend}"
ITER="${2:?iter}"
K="${3:?bytes to flip}"

WARM_BASE="/var/lib/paritydb-torture/warm"
SNAPSHOT="$WARM_BASE/${BACKEND}-snapshot"
DATA_DIR="/var/lib/paritydb-torture/byteflip-data"

[ -d "$SNAPSHOT" ] || die "snapshot missing: $SNAPSHOT — run setup-warm-snapshots.sh first"

# Restore snapshot to fresh data dir (cp -a preserves owner; we'll fix below)
sudo rm -rf "$DATA_DIR"
sudo cp -a "$SNAPSHOT" "$DATA_DIR"
sudo chown -R coder:coder "$DATA_DIR"

case "$BACKEND" in
  paritydb) DB_PATH="$DATA_DIR/chains/gemini-star/paritydb/full" ;;
  rocksdb)  DB_PATH="$DATA_DIR/chains/gemini-star/db/full" ;;
esac

# Pick a random file >100 bytes, write-flip K random byte positions (XOR with 0xFF)
TARGET=$(find "$DB_PATH" -type f -size +100c | shuf -n 1)
[ -n "$TARGET" ] || die "no DB file to corrupt in $DB_PATH"

python3 - "$TARGET" "$K" <<'PY'
import os, random, sys
target, k = sys.argv[1], int(sys.argv[2])
size = os.path.getsize(target)
with open(target, 'r+b') as f:
    for _ in range(k):
        off = random.randint(0, size - 1)
        f.seek(off)
        b = f.read(1)
        if not b:
            continue
        f.seek(off)
        f.write(bytes([b[0] ^ 0xFF]))
PY

FILENAME=$(basename "$TARGET")

# Verify with isolated port range so we don't collide with cascade/deep running
# in parallel on the main mount.
VERIFY_LINE=$(PORT_BASE=43000 P2P_BASE=45000 \
  "$HERE/verify.sh" "$DATA_DIR" "$BACKEND" "$ITER" "bf-${K}" \
  2>>"$RESULTS/logs/bf-${K}-$BACKEND-$ITER.verify.log" || true)

echo "byteflip-$K,$BACKEND,$ITER,$K,$FILENAME,$VERIFY_LINE"
