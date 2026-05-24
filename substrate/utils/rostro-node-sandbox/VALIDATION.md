# rostro-node-sandbox — Phase 5 Validation Runbook

This document is a step-by-step procedure for validating the host-level
sandbox on a real Linux host. WSL2 can't exercise the apply path
(namespace setup times out), and `cargo test` on dev only covers
construction logic — so the actual "does it kill the right things, does
it pass the right things, what's the perf cost" answer lives here.

Run this whenever:

- The seccomp allowlist changes (entries added or removed).
- The Landlock baseline paths change.
- The kernel version on validator hosts changes substantially.
- A new validator hardware shape comes online (especially non-Intel).

Run it once before testnet ramp; after that, the inputs above are the
re-run triggers.

## 0. Prerequisites

- Linux validator host, x86_64. Hetzner CPX or similar.
- Distro: Ubuntu 22.04 LTS / Debian 12 / Fedora ≥ 38. Anything with:
  - Kernel ≥ 5.13 (Landlock minimum)
  - Kernel ≥ 4.19 (memory.oom.group; older kernels work with degraded OOM)
  - cgroup v2 unified hierarchy mounted at `/sys/fs/cgroup` (default on
    every modern systemd distro)
- Sudo, internet, ssh.
- Cargo toolchain installed (or pre-built binaries copied over).
- Free disk: ~5GB for build artifacts.
- Estimated wall time: 30-60 min for a clean run.

Confirm with:

```bash
uname -r                                  # ≥ 5.13.0
ls /sys/fs/cgroup/cgroup.controllers       # file exists
grep -E '^\s*landlock\b' /sys/kernel/security/lsm  # or: cat /sys/kernel/security/lsm | tr ',' '\n' | grep landlock
```

## 1. Build

```bash
ssh hetzner-validator
git clone -b sandbox-v0 <repo-url> Rostro && cd Rostro
cargo build --release -p rostro-supervisor -p gemini-node
ls -la target/release/{rostro-supervisor,gemini-node}
```

Both binaries should be present. Co-locate them — the supervisor looks
for `gemini-node` next to itself by default.

```bash
cp target/release/rostro-supervisor target/release/gemini-node /opt/rostro/bin/
```

## 2. Strace baseline (the truth set)

Run gemini-node **without** the sandbox to collect every syscall the
real workload makes. We compare that against the allowlist to find
gaps.

```bash
sudo strace -ff -c -e signal=none -o /tmp/strace \
    /opt/rostro/bin/gemini-node --tmp --dev &
STRACE_PID=$!

# A full production cycle is ~30-60s. Wait at least 120s to capture
# all init paths + steady-state.
sleep 180

sudo kill -INT $STRACE_PID
sleep 5
```

Extract observed syscalls:

```bash
# Names from the per-thread strace files (-ff). The summary lines
# have the form "  12.34   0.001234           5    1234        read"
awk '$NF !~ /^[0-9]/ && NF > 0 { print $NF }' /tmp/strace.* \
    | sort -u > /tmp/observed-syscalls.txt
wc -l /tmp/observed-syscalls.txt
head -20 /tmp/observed-syscalls.txt
```

Extract the allowed-syscall names from the source for diffing:

```bash
# Picks up every libc::SYS_* reference in linux.rs — both
# PLAIN_ALLOWED_SYSCALLS entries and the argument-filtered ones
# (mmap, mprotect, clone, socket, ioctl). That's the complete set
# of syscall numbers we accept at the seccomp layer.
grep -oP 'libc::SYS_\w+' substrate/utils/rostro-node-sandbox/src/linux.rs \
    | sed 's/libc::SYS_//' \
    | sort -u > /tmp/allowed-names.txt

# Show what's observed but NOT allowed:
comm -23 /tmp/observed-syscalls.txt /tmp/allowed-names.txt > /tmp/syscall-gaps.txt
cat /tmp/syscall-gaps.txt
```

**Paste `/tmp/syscall-gaps.txt` back to me** if running this with
Claude — even a few entries can hide a substantive false-positive
risk and we should triage each one.

**Action items from the diff:**

- **In observed but NOT in allowlist** → MUST add before testnet. These
  would be killed under sandbox; the validator would crash-restart
  in a loop until the supervisor's `--max-crash-restarts` (default 5
  in 60s) gives up. Take the validator offline.
- **In allowlist but NOT observed** → leave alone. Probably hit by
  panic handlers, signal paths, or RPC-method-specific code that
  didn't fire in this run. Pruning aggressively risks false positives
  on rare paths.

## 3. ioctl cmd inventory

`ioctl` is a multiplexer with hundreds of possible cmds; our allowlist
permits only 5 by default. Find what the real workload uses:

```bash
grep -ho 'ioctl([^,]*, [^,]*,' /tmp/strace.* \
    | awk '{print $2}' \
    | tr -d ',' \
    | sort -u > /tmp/observed-ioctls.txt
cat /tmp/observed-ioctls.txt
```

Cross-reference against `ioctl_safe_cmds_rules()` in linux.rs.
Currently allowed: `TIOCGWINSZ`, `FIONREAD`, `FIONBIO`, `TCGETS`,
`TIOCGPGRP`. Add any others that appear — common ones to expect:

- `TIOCGPTN`, `TIOCSPTLCK` — pty allocation for tracing tools
- `RTC_*` — real-time clock; substrate doesn't use these directly
- `BLKGETSIZE64` — block device size; only relevant for disk-direct workloads

For each new cmd, add a line to the `SAFE_IOCTLS` table with a comment
explaining what subsystem needs it.

## 4. Sandbox install — smoke test

Run the supervisor with the sandbox on, verify it starts the child
cleanly:

```bash
sudo /opt/rostro/bin/rostro-supervisor \
    --sandbox-rw-path /opt/rostro/data \
    --sandbox-ro-path /opt/rostro/chain-spec.json \
    --sandbox-memory-max-bytes 4294967296 \
    --sandbox-cpu-max-micros 200000 \
    -- --base-path /opt/rostro/data --tmp --dev
```

Expected log lines:

```
[INFO]  rostro-supervisor starting; ...
[INFO]  rostro-node-sandbox cgroup: installed; supervisor in /sys/fs/cgroup/rostro-node-<pid>/ (uncapped), child cgroup at /sys/fs/cgroup/rostro-node-<pid>/child/ ...
[INFO]  rostro-node-sandbox landlock: fully enforced (no_new_privs=true)
[INFO]  rostro-node-sandbox seccomp: filter installed (KILL_PROCESS on violation, TSYNC across all threads)
[INFO]  rostro-node-sandbox: installed (cgroup=enabled, landlock=with operator paths, seccomp=enabled)
[INFO]  spawning child (swap_count=0, recent_crashes=0): /opt/rostro/bin/gemini-node
```

If the child immediately exits with SIGKILL → strace step 2 missed
something; iterate.

If Landlock logs `PartiallyEnforced` → kernel doesn't support full
feature set; acceptable but note for follow-up.

If Landlock logs `NotEnforced` → kernel < 5.13 or Landlock disabled at
boot. Fall back to cgroup + seccomp only or pick a different host.

## 5. Adversarial violation test

Confirm seccomp actually kills on forbidden syscalls.

```bash
# Write a small test that attempts ptrace from inside the sandbox.
cat > /tmp/sandbox-violation-test.sh <<'EOF'
#!/bin/bash
# Try to attach to PID 1 via ptrace — denied by seccomp.
# We use strace itself (which uses ptrace internally) as a quick proxy.
strace -p 1 2>&1 || echo "denied as expected"
EOF
chmod +x /tmp/sandbox-violation-test.sh

# Run via the supervisor in --unsafe-skip-sandbox to capture baseline.
sudo /opt/rostro/bin/rostro-supervisor --unsafe-skip-sandbox \
    --child /tmp/sandbox-violation-test.sh
# Expected: shell exits with "ptrace: ..." error from kernel
# (operation not permitted via standard EPERM), NOT a SIGKILL.

# Re-run with sandbox on:
sudo /opt/rostro/bin/rostro-supervisor \
    --sandbox-rw-path /tmp \
    --child /tmp/sandbox-violation-test.sh
```

With sandbox on, expected log progression:

```
[INFO]  spawning child (swap_count=0, recent_crashes=0): ...
[ERROR] child crashed (signal kill); 1 crashes in last 60s (cap 5)
[INFO]  backing off 1s before respawn
[INFO]  spawning child (swap_count=0, recent_crashes=1): ...
[ERROR] child crashed (signal kill); 2 crashes in last 60s (cap 5)
... (continues until cap)
[ERROR] max_crash_restarts=5 exceeded in 60s window; supervisor giving up
```

Verify the kill is from seccomp (not OOM, not Landlock):

```bash
sudo dmesg | grep -i seccomp | tail -5
# Expected: "audit: ... type=1326 ... syscall=101"  (101 = ptrace on x86_64)
```

If you see no seccomp audit lines → the filter isn't applying. Triage
via `cat /proc/<pid>/status | grep Seccomp` (should be 2 = filter mode)
on a sandboxed child while it's running.

## 6. OOM cgroup behavior

Confirm OOM kills only the child cgroup, not the supervisor.

```bash
# Tight memory cap — 256MB. gemini-node will OOM during state load.
sudo /opt/rostro/bin/rostro-supervisor \
    --sandbox-rw-path /opt/rostro/data \
    --sandbox-memory-max-bytes 268435456 \
    --max-crash-restarts 3 \
    -- --base-path /opt/rostro/data --tmp --dev
```

Expected: child OOMs, supervisor logs crash + backoff, validator restarts.
After 3 OOMs in 60s the supervisor gives up (which is correct — memory cap
is the wrong size for this workload; operator should reconfigure).

Verify only the child died:

```bash
# Inspect cgroup state during a crash cycle:
ls /sys/fs/cgroup/rostro-node-*/
cat /sys/fs/cgroup/rostro-node-*/cgroup.procs  # should contain supervisor PID
cat /sys/fs/cgroup/rostro-node-*/child/cgroup.procs  # should be empty after kill
cat /sys/fs/cgroup/rostro-node-*/child/memory.events  # oom_kill counter > 0
```

If supervisor PID appears in `child/cgroup.procs` → bug, supervisor was
placed in the wrong group.

## 7. Perf delta

Three runs each, sandbox-on and sandbox-off. Capture:

| Metric | How to measure | Target |
|---|---|---|
| Time to first block | `journalctl ... \| grep 'best block #1'` | < +5% sandbox-on vs off |
| Block production rate | blocks/min over 10 minutes after steady-state | < +5% |
| RPC p95 latency | `wrk` or `vegeta` against a `state_getStorage` endpoint | < +10% |
| Steady-state CPU% | `top -bn1` averaged over 1 min after 5-min ramp | < +3pp |
| RSS | `ps -o rss -p <pid>` | < +5% |

**Acceptable delta**: sandbox overhead < 5% on throughput metrics, < 3pp
on CPU. Higher → the seccomp filter is too coarse, the Landlock policy
includes paths it shouldn't, or the cgroup is mis-configured.
Investigate before merging.

## 8. Sign-off checklist

- [ ] Strace observed-syscall set is a subset of allowlist (or
      allowlist updated to cover gaps)
- [ ] ioctl cmd allowlist covers all observed cmds
- [ ] Sandbox install logs show `FullyEnforced` for Landlock,
      `installed` for seccomp, two-tier cgroup for cgroup v2
- [ ] Adversarial ptrace test produces SIGKILL + supervisor restart
      + dmesg audit line (syscall=101 on x86_64)
- [ ] OOM test: child cgroup dies, supervisor stays in outer cgroup,
      restart loop engages, gives up after configured cap
- [ ] Perf delta within budget on all five metrics
- [ ] Results documented as a follow-up commit on sandbox-v0 (or
      a Phase 5 outcome memo committed alongside) so the merge to
      rostro-main records the validation evidence

When everything ticks: merge `sandbox-v0` → `rostro-main` with
`--no-ff`, push.

## Rollback

If Phase 5 surfaces blockers we can't fix in the runbook session:

1. Don't merge sandbox-v0.
2. Document the blockers in a follow-up commit on the branch (commit
   message: "sandbox-v0: Phase 5 deferred — <reason>"; no code change).
3. Operator workaround: launch gemini-node via the *old* supervisor
   path (or directly), accepting the audit's "no host-level sandbox"
   risk for testnet.
4. Triage the blockers async; re-run Phase 5 when ready.

## Known caveats

- This runbook is **x86_64 only**. ARM64 sandbox install is currently
  a stub that logs a warning and skips seccomp; if a Hetzner ARM box
  joins the validator roster, the runbook needs an ARM-specific
  syscall-number translation in `linux.rs` first.
- Landlock network restrictions (kernel 6.7+) aren't currently used.
  If observed traffic profile changes substantially in the future,
  consider adding the bind/connect-TCP ruleset.
- The polkavm Linux sandbox inside `substrate/external/rostrovm/` is
  unrelated to this work and stays disabled (current rostro-executor
  default). Don't confuse the two.
- This runbook does NOT cover bring-up of TPM/HIP attestation, which
  is a separate prelaunch item ([[prelaunch_items]] memory).
