#!/usr/bin/env bash
# Build a "warm" snapshot for each backend by importing the 5000-block corpus
# cleanly (no fault). The byteflip sweep restores from these snapshots per
# iteration, so we pay the ~12 min import cost twice instead of 200 times.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"

WARM_BASE="/var/lib/paritydb-torture/warm"
sudo mkdir -p "$WARM_BASE"
sudo chown coder:coder "$WARM_BASE"

for backend in paritydb rocksdb; do
  SNAP="$WARM_BASE/${backend}-snapshot"
  if [ -d "$SNAP" ]; then
    log "$backend snapshot already exists at $SNAP — skipping"
    continue
  fi
  STAGING="$WARM_BASE/${backend}-staging"
  rm -rf "$STAGING" "$SNAP"
  mkdir -p "$STAGING"
  log "importing 5000 blocks into $STAGING (this takes ~12 min)"
  "$GEMINI_NODE" import-blocks \
    --chain star --database="$backend" --base-path "$STAGING" \
    --binary "$CORPUS"
  log "import done — sealing snapshot"
  mv "$STAGING" "$SNAP"
  log "$backend warm snapshot ready: $(du -sh "$SNAP" | cut -f1)"
done

log "warm snapshots ready under $WARM_BASE"
