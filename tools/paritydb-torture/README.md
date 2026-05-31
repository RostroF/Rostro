# paritydb torture

Compares ParityDB vs RocksDB under two failure modes on the gemini-node binary:

1. **Power loss during write** — `dm-flakey` switched to `drop_writes` mid-import, then
   the node is SIGKILL'd and the filesystem unmounted *while still in drop_writes*. Any
   dirty page-cache pages are dropped instead of flushed. Disk reflects only what was
   actually `fsync()`'d before the fault. The closest user-space approximation of a
   sudden power-off short of pulling the plug on a real machine.

2. **OOM mid-write** — `systemd-run --scope -p MemoryMax=...` runs the import inside a
   cgroup with a tight memory cap. Kernel OOM-killer fires when the DB's working set
   exceeds the cap during a heavy write batch, SIGKILL'ing the process. Page cache
   survives, so this is a strictly weaker disk-durability test than the dm-flakey
   one — but it covers a real production failure mode (OOM is how Linux actually
   kills processes that run out of memory).

Both backends are compiled into the same gemini-node binary; `--database=paritydb`
vs `--database=rocksdb` is the only difference between A/B runs.

## Pass criteria (all three must hold per iteration)

1. **Reopen** — node restarts, RPC responds to `chain_getHeader` within 30 s.
2. **No silent data loss** — for every (height, expected_hash) in the oracle where
   height ≤ best-after-restart, `chain_getBlockHash(height)` returns the expected hash.
3. **Recovery time ≤ 30 s** — from process launch to first RPC response.

## Files

- `fixtures/corpus-5000.scale` — first 5000 blocks of Gemini Star, binary SCALE.
  Regenerate with the snapshot+export ceremony in commit history.
- `fixtures/canonical-hashes.txt` — 50 sample heights with their canonical hashes,
  ground-truth oracle. Regenerate with `scripts/extract-canonical-hashes.sh`.
- `scripts/lib.sh` — shared paths and helpers. Source, don't exec.
- `scripts/setup-flakey-dev.sh` / `teardown-flakey-dev.sh` — sparse file + loopback
  + dm-flakey + ext4 + mount. Idempotent.
- `scripts/dm-mode.sh {pass|drop}` — flip dm-flakey table without tearing it down.
- `scripts/iter-power-loss.sh BACKEND ITER` — one power-loss iteration.
- `scripts/iter-oom.sh BACKEND ITER [MEM_MAX]` — one OOM iteration.
- `scripts/verify.sh DATA_DIR BACKEND ITER TAG` — restart + 3-gate check.
- `scripts/run-sweep.sh [N=100] [MEM_MAX=256M]` — full N × 2 × 2 sweep, CSV out.
- `results/` — CSVs + per-iter logs.

## Requirements

- Linux with `dm-flakey` module loaded (verify with `lsmod | grep dm_flakey`)
- cgroup v2 mounted at `/sys/fs/cgroup`
- Passwordless sudo for the operator
- `losetup`, `dmsetup`, `mkfs.ext4`, `systemd-run`
- ~12 GB free disk for the 10 GB sparse backing file

## Quickstart

```bash
# one-time
cargo build --release -p gemini-node
./scripts/extract-canonical-hashes.sh   # needs a live lab on 127.0.0.1:9945
./scripts/setup-flakey-dev.sh

# smoke
./scripts/iter-power-loss.sh paritydb 1
./scripts/iter-oom.sh paritydb 1

# full sweep (100 × 2 × 2 = 400 iterations)
./scripts/run-sweep.sh 100
```

## What this *doesn't* test

- Actual hardware power loss (no on-disk caches simulated; SSDs have their own
  capacitor-backed write caches that can lie even to fsync — a separate concern).
- Concurrent multi-process database use (gemini-node opens the DB exclusively).
- Filesystem corruption modes other than dropped writes (no torn-write, no bit-flip).
- Long-running fragmentation / compaction behaviour (5000-block corpus is short).
