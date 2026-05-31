#!/usr/bin/env bash
# Reverse setup. Leaves the backing image in place (delete manually if you want).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"

if mountpoint -q "$MOUNT"; then
  log "unmount $MOUNT"
  sudo umount "$MOUNT" || sudo umount -l "$MOUNT" || true
fi

if sudo dmsetup info "$DM_NAME" >/dev/null 2>&1; then
  log "remove dm-flakey $DM_NAME"
  sudo dmsetup remove "$DM_NAME"
fi

if [ -r "$LOOP_DEV_FILE" ]; then
  LOOP="$(cat "$LOOP_DEV_FILE")"
  if sudo losetup "$LOOP" >/dev/null 2>&1; then
    log "detach loop $LOOP"
    sudo losetup -d "$LOOP" || true
  fi
  sudo rm -f "$LOOP_DEV_FILE"
fi

log "teardown complete (backing image $BACKING_IMG kept)"
