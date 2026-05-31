#!/usr/bin/env bash
# Idempotent: create sparse backing file, losetup, dm-flakey device, ext4, mount.
# After this, /mnt/paritydb-torture/ is the torture filesystem.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"

require_root_tools

sudo mkdir -p "$(dirname "$BACKING_IMG")" "$MOUNT"

if [ ! -f "$BACKING_IMG" ]; then
  log "creating sparse backing file ${BACKING_SIZE_GB}G at $BACKING_IMG"
  sudo truncate -s "${BACKING_SIZE_GB}G" "$BACKING_IMG"
fi

if [ -r "$LOOP_DEV_FILE" ] && sudo losetup "$(cat "$LOOP_DEV_FILE")" 2>/dev/null | grep -q "$BACKING_IMG"; then
  LOOP="$(cat "$LOOP_DEV_FILE")"
  log "reusing loop dev $LOOP"
else
  LOOP=$(sudo losetup --find --show "$BACKING_IMG")
  log "attached $BACKING_IMG to $LOOP"
  echo "$LOOP" | sudo tee "$LOOP_DEV_FILE" >/dev/null
fi

if ! sudo dmsetup info "$DM_NAME" >/dev/null 2>&1; then
  log "creating dm-flakey device $DM_DEV in pass-through mode"
  # shellcheck disable=SC2059
  TABLE="$(printf "$PASSTHRU_TABLE_FMT" "$LOOP")"
  echo "$TABLE" | sudo dmsetup create "$DM_NAME"
else
  log "dm-flakey device $DM_NAME already exists"
fi

# Wait for udev to settle and the device node to materialize
for _ in 1 2 3 4 5; do
  [ -b "$DM_DEV" ] && break
  sleep 0.2
done
[ -b "$DM_DEV" ] || die "$DM_DEV did not appear"

# mkfs only if the device has no ext4 signature yet
if ! sudo blkid "$DM_DEV" | grep -q 'TYPE="ext4"'; then
  log "mkfs.ext4 on $DM_DEV"
  sudo mkfs.ext4 -q -F "$DM_DEV"
fi

if ! mountpoint -q "$MOUNT"; then
  log "mounting $DM_DEV at $MOUNT"
  sudo mount "$DM_DEV" "$MOUNT"
  sudo chown coder:coder "$MOUNT"
fi

log "setup complete. loop=$LOOP dm=$DM_DEV mount=$MOUNT"
