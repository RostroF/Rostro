# Phase 5 — first-pass outcome (2026-05-23)

Real-Linux validation of **Cannae** (the `rostro-node-sandbox` crate plus
its `rostro-supervisor` driver — host-level isolation envelope installed
before `gemini-node` exec) against the bare-metal lab described in
[VALIDATION.md](VALIDATION.md). This document captures what was caught,
what was fixed, what's still open, and how to run the next iteration.

## Lab configuration

Three validator laptops on the home LAN:

| Hostname | Distro | Kernel | CPU | TPM |
|---|---|---|---|---|
| rostro-fedora-01 | Fedora 44 Server | 6.19.10-300.fc44 | i7-10610U | Intel PTT (fTPM) |
| rostro-debian-01 | Debian 13 (trixie) | 6.12.88+deb13 | i7-12800H | Intel PTT (fTPM) |
| rostro-ubuntu-01 | Ubuntu 24.04.4 LTS | 6.8.0-117 | i7-10850H | Intel PTT (fTPM) |

Hardening baseline applied to each (sysctl + GRUB cmdline): `io_uring`
disabled, CPU mitigations on, unprivileged BPF/user-namespaces blocked,
`kernel.yama.ptrace_scope=1` (lab profile; production target = 3),
`kernel.kexec_load_disabled=1`, `kernel.dmesg_restrict=1`.

## Methodology

Per VALIDATION.md step 2:

```bash
SUBSTRATE_ENABLE_POLKAVM=1 strace -ff -e signal=none -o /tmp/strace \
    /opt/rostro/bin/gemini-node --tmp --dev
```

180s observation window per node. 60–118 strace files per run (one per
thread); larger thread counts on the Alder Lake box (12c/20t) than Comet
Lake (4c/8t).

**Important: this is the INIT + IDLE profile.** No peers, no submitted
transactions, no sustained block production. PolkaVM JIT/recompiler is
exercised once at genesis init but not under sustained block-execution
load. Workloads NOT covered by this first pass:

- Multi-node peering (libp2p connection establishment, gossip)
- Sustained block production + import
- Transaction validation through the runtime
- Long-tail RPC-driven runtime invocations

A second iteration must capture those before the merge to rostro-main.

## Cross-distro result

After `LC_ALL=C sort -u` of each node's observed-syscalls file:

- **Identical 63-syscall set across all three distros.** Different glibc
  versions (Fedora glibc 2.41, Debian 13 glibc 2.41, Ubuntu 24.04 glibc
  2.39), different libc patches, identical syscall preferences.
- **Identical 3-cmd ioctl set** (`FIONBIO`, `TCGETS2`, `TIOCGWINSZ`).
  Per-distro union added `TCGETS` from baseline = 4 cmds total.
- **No per-distro deltas** to add to the allowlist conditional on distro.

This is unusual — usually heterogeneity surfaces *something*. Means our
allowlist can be node-agnostic, at least for INIT + IDLE.

## Bugs found + fixes applied

### Bug 1 — cgroup v2 "no internal processes" violation

**Symptom:** `sandbox install failed at cgroup: write
/sys/fs/cgroup/rostro-node-<pid>/cgroup.procs="<pid>": Device or resource
busy (os error 16)` on every supervisor start.

**Cause:** `install_cgroup` enabled `+memory +cpu` in
`supervisor_group/subtree_control` (so the child cgroup gets caps), THEN
attempted to write the supervisor's PID to `supervisor_group/cgroup.procs`.
cgroup v2 rejects this: once `subtree_control` enables controllers for
descendants, the cgroup is "internal" and cannot host processes,
regardless of whether descendants currently have processes.

The comment on the original `cgroup.procs` write was incorrect; it
referenced the population of descendant cgroups rather than the
propagation of controllers via `subtree_control`. The unit tests passed
because they used a `fake_cgroup_root()` tmpdir that doesn't enforce
real cgroup v2 semantics — exactly the bug class Phase 5 is for.

**Fix:** Don't move the supervisor. It stays in its inherited cgroup
(`/user.slice/user-<uid>.slice/session-N.scope` under systemd), which is
uncapped from our perspective and functionally equivalent to the
original two-tier intent. Only the child cgroup needs to hold processes
(the gemini-node child, post-spawn via `place_child_in_cgroup`).

Test renamed: `install_cgroup_writes_self_pid_to_supervisor_procs` →
`install_cgroup_does_not_move_supervisor_pid`. Inverted assertion.

### Bug 2 — `clone3` deliberately omitted but glibc uses it

**Symptom:** Supervisor SIGKILLs the instant it calls
`Command::spawn(child)`, before any "child crashed" log fires. No
gemini-node log lines printed.

**Cause:** The original allowlist omitted `clone3` on the rationale
"glibc and rust std use plain `clone()` for thread creation through
current versions; clone3 calls will die. Revisit if Phase 5 strace
shows them." Phase 5 strace on kernel 6.19 + glibc 2.41 showed
**43 clone3 calls during 180s init+idle.** Modern glibc uses `clone3`
directly on Linux ≥5.5, including from `posix_spawn` (which Rust's
`std::process::Command::spawn` calls). Omitting `clone3` makes the
sandbox unusable on any current distro.

**Fix (initial, 2026-05-23 first-pass):** Add `libc::SYS_clone3` to
`PLAIN_ALLOWED_SYSCALLS` with an explicit rationale block. Soundness
gap accepted: seccomp can't inspect `clone_args` (struct behind a
pointer), so namespace-creation flags (`CLONE_NEW*`) pass through
unfiltered.

**Fix (revised, 2026-05-23 red-team follow-up):** The accepted gap was
red-teamed and confirmed reachable — a `clone3(CLONE_NEWUSER)` call
from inside the sandbox successfully created a user namespace, then
chained to a systemd-reachable escape. Closed by installing a **second**
stacked seccomp BPF filter — `force_clone3_enosys_filter()` — that
returns `ENOSYS` for `clone3`. glibc ≥2.34's `__clone3` reacts to
`-ENOSYS` by retrying with legacy `SYS_clone`, which then hits the
existing `clone_no_namespace_rules()` `CLONE_NEW*` MaskedEq filter and
is SIGKILL'd if it asks for any namespace flag.

**Subtlety that bit the first deploy attempt (2026-05-23 v1 → v2):**
The kernel stacks filters and picks the **signed minimum** of their
return actions — `kernel/seccomp.c`: `ACTION_ONLY(ret) ((s32)(ret &
SECCOMP_RET_ACTION_FULL))`. The `s32` cast puts `KILL_PROCESS
(0x80000000)` at `INT_MIN`, so it WINS every contest. v1 of this fix
removed `SYS_clone3` from `PLAIN_ALLOWED_SYSCALLS` on the assumption
that ERRNO (`0x00050000` = +327680 signed) would beat KILL_PROCESS in
unsigned-min stacking. Deploy to debian-01 SIGSYS'd the supervisor on
its first `Command::spawn` (audit: `pid=2057 syscall=435 code=0x80000000`).
v2 keeps `SYS_clone3` IN the main allowlist so main returns ALLOW
(+2.1B signed) and the ENOSYS shadow filter's ERRNO (+327680 signed)
wins the min — supervisor stays alive, glibc fallback engages, legacy
`clone(CLONE_NEW*)` SIGKILLs as designed. The takeaway: stacked
seccomp filters are SIGNED-min, not unsigned-min; KILL_PROCESS cannot
be overridden by a stacked ERRNO. Shadow-not-replace is the load-bearing
pattern.

**Operator requirement: glibc ≥2.34** (Aug 2021). Older glibc lacks the
`__clone3` ENOSYS-fallback, so process spawns will fail outright on
those hosts. Every supported validator distro ships ≥2.34 (Ubuntu
22.04+, Debian 12+, Fedora 36+, RHEL 9+). musl static builds do NOT
ship the fallback; Rostro releases are glibc — this becomes a concern
only if the build ever switches to musl-static for portability.

Why `ENOSYS` and not `EPERM`/`EACCES`: only `ENOSYS` triggers glibc's
fallback path. `EPERM` would bubble to the caller as a clone failure
and break every `Command::spawn` in tokio/libp2p. `ENOSYS` is the
"syscall does not exist" contract; the fallback engages transparently.

**Defense-in-depth still applies** (now redundant with the ENOSYS
intercept, but kept):
- `kernel.unprivileged_userns_clone = 0` (set in our hardening sysctls)
  blocks unprivileged user-namespace creation at the kernel level.
- v2 hardening item: production validators should drop `CAP_SYS_ADMIN`
  before exec'ing the child so even root can't create namespaces.

### Bug 3 — `mmap PROT_EXEC` blanket-denied breaks every dynamic loader

**Symptom:** With `clone3` allowed (above), the supervisor's `spawn()`
returns successfully but then immediately reports `Permission denied
(os error 13)` and no gemini-node log lines print.

**Cause:** The original `mmap_no_exec_rules` rule was a single condition
`(prot & PROT_EXEC) == 0` — any `mmap` with `PROT_EXEC` set was killed.
This breaks the kernel's `exec` of dynamically-linked binaries: the
kernel reads `PT_INTERP` from the ELF header (`/lib64/ld-linux-x86-64.so.2`)
and the dynamic loader needs to map `libc.so.6`'s `.text` segment with
`PROT_EXEC`. The kernel converts the Landlock/seccomp-blocked exec
attempt into EACCES.

**Fix:** Split `mmap_no_exec_rules` → `mmap_safe_rules` with two OR'd
rules:

1. `(prot & PROT_EXEC) == 0` — any flags, file-backed or anonymous.
   Covers Rust heap, stack growth, anonymous RW allocations.
2. `(prot & PROT_EXEC) != 0 AND (flags & MAP_ANONYMOUS) == 0` —
   file-backed executable mappings, i.e. `ld.so` mapping library text.

What's still **DENIED** (no rule matches): `PROT_EXEC` AND `MAP_ANONYMOUS`,
i.e. classic JIT-spray. A compromised in-sandbox process could still
write to a permitted RW path and re-mmap that file executable — closing
that gap requires Landlock execute-denial on RW paths, tracked as a v2
hardening item.

### Bug 4 — BASELINE_RO_PATHS missing dynamic loader + /proc/meminfo

**Symptom:** With Bugs 1–3 fixed, supervisor's `spawn` succeeds but the
exec immediately returns EACCES from the kernel — same as Bug 3 but for
a different reason — and once that's fixed, gemini-node panics with
"Not enough memory to initialize shared trie cache. Cache size:
1073741824 bytes. System memory: used 0 bytes, total 0 bytes".

**Cause:** Landlock's `BASELINE_RO_PATHS` only granted read access to
a small set: `/dev/urandom`, `/dev/null`, `/proc/self`, `/etc/resolv.conf`,
`/etc/hosts`, `/etc/nsswitch.conf`, `/etc/ssl/certs`, `/etc/pki/tls/certs`.

Two categories were missing:

1. **Dynamic loader + shared libraries.** The ELF interpreter
   (`/lib64/ld-linux-x86-64.so.2`), the loader cache (`/etc/ld.so.cache`,
   `/etc/ld.so.conf`, `/etc/ld.so.conf.d`), and the library directories
   themselves (`/lib`, `/lib64`, `/usr/lib`, `/usr/lib64`). Without these
   the kernel's exec fails with EACCES because Landlock denies read on
   the interpreter.
2. **System info under /proc.** Substrate sizes its trie cache from
   `/proc/meminfo`; without it sees "total 0 bytes" and panics.
   `/proc/cpuinfo`, `/proc/loadavg`, `/proc/uptime`, `/proc/stat`, and
   `/sys/devices/system/cpu` are read by tokio + rayon for thread-pool
   sizing.

**Fix:** Added 11 paths to `BASELINE_RO_PATHS`. All silently skipped
if absent (per-distro variance fine).

### Bug 5 — strace baseline missed 7 syscalls + 1 ioctl

Real-hardware run produced syscalls not in the existing allowlist:

| Syscall | Class | Why missed before |
|---|---|---|
| `access`           | old-style file check     | Modern code prefers `faccessat2` but glibc still hits it on some paths |
| `mkdir`            | old-style FS op          | Some Rust crates / RocksDB legacy paths |
| `readlink`         | old-style FS op          | Same |
| `rename`           | old-style FS op          | Same |
| `unlink`           | old-style FS op          | Same |
| `rseq`             | Rust/glibc TLS           | Required for restartable sequences on Linux ≥4.18; thread setup |
| `restart_syscall`  | kernel-internal          | Returned by kernel to resume interrupted syscalls; signal handling |
| `TCGETS2` (ioctl)  | modern terminal config   | Replaces TCGETS for c_ispeed/c_ospeed |

**Fix:** Added all 8 to `PLAIN_ALLOWED_SYSCALLS` and `SAFE_IOCTLS` with
2026-05-23 attribution comments.

### Build env-var pitfall (not a fix, but caught)

`SUBSTRATE_RUNTIME_TARGET=riscv` is required at BUILD time for the
runtime to compile to PolkaVM/RISC-V. Without it, wasm-builder defaults
to WASM and the resulting `gemini-node` fails at first runtime call with
`"blob doesn't start with the expected magic bytes"`. The
star-scenarios scripts mentioned only `SUBSTRATE_ENABLE_POLKAVM=1` in
their build-hint messages; the newer `run-trio.sh` / `run-chat-trio.sh`
scripts include both. Memory updated to require both env vars going
forward.

## What works after the fixes

With all 5 bugs fixed and the production seccomp action restored to
`KillProcess`, the sandbox installs cleanly and gemini-node boots
through the full chain init:

```
[INFO] rostro-supervisor starting; ...
[INFO] rostro-node-sandbox cgroup: installed; supervisor stays in its
       inherited cgroup (uncapped), child cgroup at
       /sys/fs/cgroup/rostro-node-<pid>/child (memory_max=Some(4 GiB),
       cpu_max=Some((400000, 100000)), oom_kill_atomic=true)
[WARN] rostro-node-sandbox landlock: partially enforced (kernel <
       requested ABI); strictest available subset is active
[INFO] rostro-node-sandbox seccomp: filter installed (KILL_PROCESS on
       violation, TSYNC across all threads)
[INFO] rostro-node-sandbox: installed (cgroup=enabled, landlock=...,
       seccomp=enabled)
[INFO] spawning child: /opt/rostro/bin/gemini-node
2026-05-23 ... Gemini Node
2026-05-23 ... Initializing Genesis block/state (state: 0xcb1d…52c9)
2026-05-23 ... Loading GRANDPA authority set from genesis on what
              appears to be first startup
2026-05-23 ... chat-stripe + chat-fetch protocols registered
2026-05-23 ... Local node identity is: 12D3KooW...
2026-05-23 ... Operating system: linux | CPU: i7-10610U | Memory: 15648MB
2026-05-23 ... Prometheus exporter started at 127.0.0.1:9615
2026-05-23 ... Running JSON-RPC server: addr=127.0.0.1:9944,[::1]:9944
2026-05-23 ... Idle (0 peers) ...
```

## What's still incomplete

### Pending #1 — re-baseline UNDER the supervisor — CLOSED 2026-05-23

Root cause of the `KillProcess`-mode early SIGKILL was NOT a missing
plain syscall. The supervised gemini-node uses exactly 61 unique plain
syscalls during 5min INIT+IDLE — **zero of them outside the existing
`PLAIN_ALLOWED_SYSCALLS`.** First-pass instinct ("the supervised process
makes syscalls the direct baseline didn't capture") was wrong.

The real cause was three categories of denial surfacing once the
process ran far enough into init. Found by capturing under
`ROSTRO_SKIP_SECCOMP=1` (Landlock still active) with strace as the
supervisor's child, looking for `EACCES` returns; then narrowing to
the specific paths/syscalls and tightening one layer at a time.

**(a) `mprotect(addr, 8MiB, PROT_READ|PROT_EXEC)`** — PolkaVM's runtime
executor flips a freshly-JIT'd 8MiB page from RW to RX (W^X). The
original `mprotect_no_exec_rules` denied any `mprotect` with
`PROT_EXEC` set, killing the process the first time the runtime
compiled a function. Observed: **1035 such calls in 5min idle.**

`mprotect_no_exec_rules` → renamed `mprotect_safe_rules`, two rules:
`(prot & PROT_EXEC) == 0` (existing) plus `(prot & PROT_EXEC) != 0
AND (prot & PROT_WRITE) == 0` (W^X-preserving JIT flip). True W^X
violations (`PROT_WRITE` AND `PROT_EXEC`) remain denied by absence.

**(b) `socket(AF_NETLINK, SOCK_DGRAM|SOCK_CLOEXEC, NETLINK_ROUTE)`** —
`std::net` / libp2p enumerate local interfaces via netlink-route
during bind. The original `socket_safe_families_rules` allowed only
INET/INET6/UNIX, so the first netlink socket call SIGKILL'd. Observed:
2 calls.

`socket_safe_families_rules` adds one tight rule:
`(domain == AF_NETLINK) AND (protocol == NETLINK_ROUTE)`. Other
netlink protocols (`NETLINK_AUDIT`, `NETLINK_NETFILTER`,
`NETLINK_KOBJECT_UEVENT`, etc.) remain denied. Doc comment updated
to reflect the new position.

**(c) Five Landlock RO-path gaps.** With (a) and (b) fixed, gemini-node
still SIGKILL'd — turned out the failure had shifted to Landlock,
not seccomp. Strace surfaced these `EACCES` returns under the active
Landlock policy:

| Path | Used by | Note |
|---|---|---|
| `/proc/self/cgroup`, `/proc/self/maps`, `/proc/self/task/<tid>/comm`, `/proc/sys/kernel/random/uuid` | substrate sysinfo, tokio thread metadata, glibc UUID | `/proc/self` is a **symlink** to `/proc/<pid>`; Landlock evaluates the resolved target, so granting only `/proc/self` denies every actual descendant read |
| `/sys/devices/virtual/block/<dev>/queue/logical_block_size` | RocksDB I/O sizing | the supervised gemini-node's data dir often sits on a dm/loop device |
| `/etc/localtime`, `/usr/share/zoneinfo/<TZ>` | substrate logging timestamps + chrono | `/etc/localtime` is a symlink into `/usr/share/zoneinfo/` |
| `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem` | rustls-native-certs | on Fedora, files visible at `/etc/pki/tls/certs/*.0` are hash-named symlinks into `/etc/pki/ca-trust/extracted/`; Debian/Ubuntu store the bundle directly in `/etc/ssl/certs` |

`BASELINE_RO_PATHS` updated: `/proc/self` → `/proc` (Landlock needs the
parent of the symlink target, not the symlink itself; matches what
Bubblewrap / Firejail do — info-leak surface accepted, PID-namespace
masking is a v2 hardening item), plus `/sys/block`,
`/sys/devices/virtual/block`, `/etc/localtime`, `/usr/share/zoneinfo`,
`/etc/pki/ca-trust/extracted`. Missing entries are silently skipped
per the existing convention, so Debian/Ubuntu nodes ignore the
Fedora-specific cert path.

**Verified 2026-05-23** on all three lab nodes simultaneously in
KillProcess + active-Landlock mode (no `ROSTRO_SKIP_*` env vars):

| Node | Distro | Idle ticks (5min) | Errors |
|---|---|---|---|
| rostro-fedora-01 | Fedora 44 / kernel 6.19.10 | 63 | 0 |
| rostro-debian-01 | Debian 13 / kernel 6.12.88 | 54 | 0 |
| rostro-ubuntu-01 | Ubuntu 24.04.4 / kernel 6.8.0 | 54 | 0 |

How the gap was found: `ROSTRO_SKIP_LANDLOCK=1 ROSTRO_SKIP_SECCOMP=1`,
supervisor exec's `/usr/bin/strace -ff -e signal=none -o ...`, which
exec's gemini-node — strace captures from the first syscall, no
strace-attach blind spot. Capture machinery preserved under
`~/rostro-testnet-lab/playbooks/under-supervisor-{strace,syscalls}.sh`.

Diagnostic env var also added in this pass:
`ROSTRO_SECCOMP_ACTION=log` flips the default seccomp action to
`SeccompAction::Log` (emits one audit record per denied syscall and
ALLOWS the call). Sibling to the existing `ROSTRO_SKIP_*` Phase 5
diagnostic pattern. Unset/`kill` = production. Anything else =
install fails fast (no silent fallback).

### Pending #2 — runtime-execution baseline

INIT + IDLE doesn't exercise PolkaVM during sustained block production.
The runtime gets called once at genesis for `Core_initialize_block` etc.
Under load it's called per-block (`Core_execute_block`), per-extrinsic
(`TaggedTransactionQueue_validate_transaction`), per-pool-revalidation,
etc. Each of those paths might exercise PolkaVM JIT/interpreter code we
haven't seen.

**Action:** Once Pending #1 is closed, run a peering scenario (2+ nodes,
sustained block production) under the sandbox + Log mode for ≥10
minutes, capture the syscall delta, re-baseline.

### Pending #3 — Landlock partially-enforced warning

`partially enforced (kernel < requested ABI)` on all three nodes. The
crate is `landlock-rust 0.4.4`, code requests `ABI::V1`, kernels are
6.8 / 6.12 / 6.19 — all newer than V1's introduction in 5.13. Likely
the crate considers V1 the floor and warns when kernel is *strictly
greater*. Cosmetic but worth investigating; might be a crate-version
issue.

### Pending #4 — separate dev-mode regression — RETRACTED 2026-05-23

This item was **a false alarm** and is retracted.

The "Essential task `txpool-background` failed" log we observed at
~30–45s on the lab was the **orderly SIGTERM shutdown sequence**, not a
regression. Two substrate-internal subtleties stack to produce the
misleading log line:

1. `TaskManager::into_task_registry(self)` does a partial move out of
   `self.task_registry`, so Rust skips the struct-level `Drop`. The
   inner `_signal: Signal` still drops individually, firing `on_exit`
   to all spawned tasks.
2. `sync_bridge_task` (the second of two essential tasks named
   `txpool-background`, in
   `substrate/client/transaction-pool/src/fork_aware_txpool/tx_mem_pool.rs`)
   is a `for request in rx` over a `std::sync::mpsc::Receiver` running
   on a tokio blocking thread. It can't observe `on_exit` (synchronous recv blocks the
   thread). It only exits when its `Sender` is dropped, which happens
   *after* the rest of the service has torn down. So sync_bridge_task
   dies last and naturally, its `catch_unwind.map(...)` callback at
   `task_manager/mod.rs:283` fires, and we see the misleading error
   log even though shutdown was clean.

**Repro confirmation on 2026-05-23:**
- WSL `gemini-node --dev` + `timeout 130s` → dies at 127s with the
  misleading log line.
- WSL `gemini-node --dev` with NO timeout → ran 5 minutes clean,
  block #49 produced and finalized normally.
- Lab 3-node trio (Alice on rostro-fedora-01 validator + Bob on
  rostro-debian-01 validator + Charlie on rostro-ubuntu-01
  non-validator, `--chain local`, deterministic node-keys, started
  via `nohup` over SSH to avoid session-timeout SIGTERM) produced
  thousands of blocks over hours with zero failures.

The earlier "30–45s on all three lab nodes" observation was most
likely also SIGTERM-driven by something in the test harness
(supervisor, SSH timeout, shell timeout). It is not reproducible
from a clean direct-run-as-rostro-user invocation.

Lesson captured for future-me in memory `feedback_substrate_shutdown_shape`.

### Pending #5 — adversarial + OOM + perf-delta sign-off

Phase 5 steps 5–7 in VALIDATION.md (ptrace adversarial test, OOM cgroup
behavior, perf-delta sandbox-on vs sandbox-off) are gated on the
Pending #1 fixes surviving a clean `KillProcess`-mode run on the lab.
The second-pass capture itself was under `ROSTRO_SKIP_SECCOMP=1` (the
"allow-all then narrow" strategy), so KillProcess behavior with the
new `mprotect_safe_rules` + AF_NETLINK rule has been validated by
unit tests + filter compilation only. Next work: build, ship, run
the full sandbox on the lab for ≥5min, confirm gemini-node stays
alive, then walk the three remaining sign-off steps.

### Pending #6 — Landlock execute-denial on RW paths (v2 hardening)

Bug 3's fix allows `mmap(PROT_EXEC + file-backed)`. A compromised
in-sandbox process can write malicious code to a permitted RW path
(`/opt/rostro/data`) and mmap it executable. Landlock 6.4+ supports
denying execute on RW paths; adopt when we bump the kernel floor.

### Pending #7 — CAP_SYS_ADMIN drop — CLOSED 2026-05-24 (`6c59927c9e`)

Originally tracked as v2 hardening, demoted to belt-and-suspenders
after Bug 2's clone3 ENOSYS fix, then promoted back to load-bearing
by the [[least_privilege_validator_principle]] (Parity dev's
"polkadot basically runs with sudo" framing). Closed via
`Command::pre_exec` hook on every child spawn calling
`prctl(PR_CAPBSET_DROP, CAP_SYS_ADMIN=21)`. Supervisor itself keeps
the capability for cgroup writes; the bounding-set drop is permanent
+ can't be raised.

## Red-team follow-up (2026-05-23 → ongoing)

After Phase 5 second-pass landed, an adversarial pass on
rostro-debian-01 produced a finding catalogue with F-numbers
(`~/rostro-testnet-lab/notes/redteam-2026-05-23/REPORT.md`).
Two ROE-bounded escapes (F01 prlimit64 cross-PID brick on PID 1;
F02 clone3 namespace creation) plus a cgroup containment failure
(F12 memory.swap.max spill) and assorted arg-filter bypasses.
Each commit below is verified end-to-end with a probe that mirrors
the original PoC against the deployed lab nodes.

### Closed

| Finding | Severity | Commit | Fix shape |
|---|---|---|---|
| F02 clone3(CLONE_NEW*) namespace creation | CONFIRMED ESCAPE | `0e725eb425` | Stacked seccomp filter returns `ENOSYS` for clone3; glibc ≥2.34 falls back to legacy `clone()` which hits the existing `CLONE_NEW*` MaskedEq filter and SIGKILLs. Bug 2 entry above has the signed-min-stacking subtlety that bit v1 (`919fadd8ce`). |
| F12 memory.max silently exceeded via swap | CONTAINMENT BROKEN | `076e6ac462` | `memory.swap.max=0` adjacent to `memory.max` write. Install log gains `swap_max_pinned=true\|false` so operators can see at boot whether the cap is real. Verified: 1.5 GiB allocation under a 1 GiB cap now OOM-killed instead of spilling. |
| F01 prlimit64 cross-PID write | CONFIRMED ESCAPE (bricked debian-01) | `43b8aab94f` | `prlimit64_self_only_rules()` requires arg0 (pid) == 0. Verified: `prlimit64(pid=1, RLIMIT_NOFILE, ...)` now SIGKILL'd at seccomp before kernel sees it; `prlimit64(pid=0, ...)` (the legitimate getrlimit/setrlimit path) still works. |
| F08 fadvise64 crash-restart loop | RELIABILITY (validator can't run) | `43b8aab94f` | `SYS_fadvise64` added to plain allowlist. RocksDB's `posix_fadvise()` no longer SIGSYSes during compaction. |
| F17 symlink(2) denied while symlinkat(2) allowed | RELIABILITY oversight | `43b8aab94f` | `SYS_symlink` added; Landlock still gates the path policy. |
| F09 `--state-file` / `--canonical-dir` docstring lied | DOC DISCONNECT | `43b8aab94f` | Both docstrings rewritten to describe actual clap behavior. `--canonical-dir` gets a workaround (point at a `*.new`-free dir); `--state-file` honestly says no disable mechanism exists today. |
| F15 / F16 state-file / canonical-dir overlapping sandbox RW path | MISCONFIG-CONDITIONAL ESCALATION | `f6de430a54` | `validate_no_rw_path_overlap()` runs before sandbox install and refuses the launch with a clear F-numbered error if either path sits inside any `--sandbox-rw-path`. Verified: F15 attack (`--state-file /opt/rostro/data/state --sandbox-rw-path /opt/rostro/data`) exits 1 with the F15 error; F16 attack (`--canonical-dir /opt/rostro/data --sandbox-rw-path /opt/rostro/data`) exits 1 with the F16 error; clean config still runs through to sandbox install. |
| F13 fchmod/fchown bypass via /proc/self/fd reopen | CONFIRMED ESCAPE (host file perms) | `92fd518af7` | Removed `fchmod`, `fchown`, `fchmodat`, `fchownat` from `PLAIN_ALLOWED_SYSCALLS` outright. fsetxattr was already denied by absence. Phase A 10-min sustained strace (102 blocks on debian-01) + Phase 5 5-min fedora baseline both observed ZERO calls to any of the four from substrate + libp2p + tokio + rust-std + RocksDB, so denial is safe. Verified: F13 probe in-sandbox observes SIGSYS on all five syscalls (fchmod / fchown / fchmodat / fchownat / fsetxattr) under the new build. Residual: ftruncate-via-reopen attack on inherited fds remains (ftruncate kept because RocksDB needs it); mitigation is supervisor CLOEXEC discipline — open follow-up item. |
| F07 prctl multiplexer flat-allowed | ARG-FILTER BYPASS | `e135235b8e` | Removed `SYS_prctl` from plain allowlist; added `prctl_safe_options_rules()` whitelisting only `PR_SET_NAME` (option=15). Phase A 600s sustained baseline observed prctl 53 times, ALL `PR_SET_NAME` (Rust std + tokio worker thread naming). Closes the F07 escape paths: `PR_SET_PTRACER_ANY` (Yama bypass), `PR_SET_DUMPABLE`, `PR_CAPBSET_DROP`, `PR_SET_MM`. Phase C LOG-mode round on all 3 lab nodes captured zero unexpected prctl operations under sustained block production; flipped to KILL mode 2026-05-24 with 0 SIGSYS audits. |
| F03 socket(AF_INET6, SOCK_RAW, IPPROTO_RAW) — raw IPv6 packet injection | ARG-FILTER BYPASS | `e135235b8e` | Rewrote `socket_safe_families_rules()` from "domain-only" to (domain, type) pairs requiring `(type & 0xF) ∈ {SOCK_STREAM, SOCK_DGRAM}` for AF_INET/AF_INET6. SOCK_RAW (3) denied by absence. AF_UNIX kept domain-only (local IPC). AF_NETLINK still gated to NETLINK_ROUTE. UDP kept for future QUIC libp2p paths. Phase C LOG-mode round confirmed zero unexpected socket combinations across all 3 lab nodes; flipped to KILL mode 2026-05-24 with 0 SIGSYS audits. |
| Lab-bring-up gap: readahead | RELIABILITY (ubuntu-only crash) | `2cbff9bf00` | ubuntu-01 (Ubuntu 24.04, kernel 6.8, glibc 2.39) hit `readahead(2)` 10x in 18min sustained operation; debian-01 (6.12, glibc 2.41) and fedora-01 (6.19, glibc 2.41) didn't. Surfaced via ROSTRO_SECCOMP_ACTION=log diagnostic mode during lab bring-up. RocksDB sequential SST scan / WAL replay paths use it on some glibc/kernel combos. Added `SYS_readahead` to plain allowlist; benign advisory syscall like fadvise64. Updates the cross-distro consistency note: sustained operation diverges where init+idle didn't. |
| F04 setsockopt SO_ATTACH_FILTER + multiplexer reach | ARG-FILTER BYPASS | `e6bb1c35e7` + `dde3a211df` (iter 2) | Removed `SYS_setsockopt` from plain allowlist; added `setsockopt_safe_options_rules()` whitelisting (level, option) pairs. iter 1 shipped the 4 pairs from Phase A's `--dev --no-mdns` strace baseline; lab `--chain=local` (mDNS enabled by default) immediately crashed on `tokio-runtime-w` syscall=54. Direct strace on fedora-01 with `--chain=local` surfaced 3 mDNS pairs (`IP_MULTICAST_TTL`, `IP_MULTICAST_LOOP`, `IP_ADD_MEMBERSHIP` for joining 224.0.0.251). iter 2 whitelist = 7 pairs total. Verified: all 3 nodes synced at block #931 with 0 KILL audits under sustained peering. Methodological lesson saved: [[feedback_cannae_baseline_methodology]] — Phase A baseline workload must match deployment CLI; audit aggregation must filter `exe=` not `comm=` (worker threads have different names). |
| Pending #7 CAP_SYS_ADMIN drop | DEFENSE-IN-DEPTH (promoted from belt-and-suspenders) | `6c59927c9e` + `03d68cf919` (memfd cascade) | Supervisor adds `Command::pre_exec` hook calling `prctl(PR_CAPBSET_DROP, CAP_SYS_ADMIN=21)`. Bounding-set drop is monotone + permanent, can't be raised. Supervisor itself keeps cap for cgroup writes. F07 whitelist extended to allow `PR_CAPBSET_DROP` (cap drops only reduce privilege). Cascade fix: polkavm JIT falls off its linux-raw-sandbox path without CAP_SYS_ADMIN onto a memfd_create-based generic backend; `SYS_memfd_create` added to allowlist (still gated by mmap W^X arg filter). Lab verified at #1184 with all 3 nodes synced, 0 SIGSYS. |
| F13 ftruncate residual (inherited writable fds) | CONFIRMED ESCAPE residual | `226c2d0225` | Supervisor adds second `Command::pre_exec` hook calling `close_range(3, UINT_MAX, 0)` to close every inherited fd above stdio. Defeats the `/proc/self/fd/N`-reopen attack chain on any inherited writable inode, even if some C-dependency holds non-CLOEXEC fds (libsystemd journal, landlock-rs ruleset, glibc nss). Linux 5.9+; ENOSYS-tolerant fallback for older kernels. Lab verified at #1223 with 0 KILL audits. |
| F05 mmap PROT_EXEC file-backed (shellcode in RW path) | DESIGN-PERMITTED → ~~CLOSED via Landlock~~ → RE-OPENED as DESIGN-PERMITTED (2026-05-25) → **CLOSED via Phase H MS_NOEXEC bind-remount (2026-05-25)** | Phase H — `install_noexec_remount` in `linux.rs` between cgroup + Landlock install | Resolution: instead of relying on Landlock (which gates `execve` not `mmap`), the supervisor now bind-mounts each `--sandbox-rw-path` onto itself and remounts with `MS_NOEXEC` before installing Landlock + seccomp. Mount-layer enforcement is upstream of both: `mmap(PROT_EXEC, fd, …)` on any inode under these paths returns `EACCES` from the kernel. `mount(2)` is not in `PLAIN_ALLOWED_SYSCALLS` so the child can't undo it post-install. EBUSY on the first mount (idempotent restart case) is tolerated; the remount step is the load-bearing one. `ROSTRO_SKIP_NOEXEC=1` available as diagnostic escape hatch. |
| F06 mprotect W→X JIT-flip | DESIGN-PERMITTED (PolkaVM JIT) → **CLOSED via mprotect Rule 2 removal (Phase H, 2026-05-25)** | Phase H — `mprotect_safe_rules` simplified to single rule `PROT_EXEC == 0` | Carve-out (Rule 2: `PROT_EXEC = set AND PROT_WRITE = 0`) existed only because polkavm 0.32's JIT required anonymous W→X mappings. Phase H pinned `RostroCodeExecutor` to PolkaVM's interpreter backend, retiring the JIT and its W→X requirement. Any `mprotect` requesting `PROT_EXEC` now SIGKILLs. The 2026-05-25 pen-test confirmed F06 executed shellcode under the previous rule (`/tmp/redteam-cannae-2026-05-24/runs/F06-mprotect-wx.out`). Regression test `mprotect_rule_denies_all_exec_transitions` enforces the single-rule contract. |
| F-MEMFD memfd_create + mmap(PROT_EXEC) (NEW finding, 2026-05-25) | CONFIRMED ESCAPE (third shellcode lane, beyond F05/F06) → **CLOSED via SYS_memfd_create removal (Phase H, 2026-05-25)** | Phase H — `SYS_memfd_create` removed from `PLAIN_ALLOWED_SYSCALLS`; comment block at lines 705-719 replaced with denial rationale + regression-test pointer | Surfaced by the 2026-05-25 WSL pen-test (agent A, `/tmp/redteam-cannae-2026-05-24/runs/F-MEMFD.out`). Strictly more powerful than F05/F06: memfd's only path is `/memfd:<name> (deleted)` reflected through `/proc/self/fd/N`, so Landlock has no vfs surface to gate, and no on-disk artifact for forensics. The carve-out was inherited from commit `03d68cf919` (Pending #7 cascade) where polkavm's generic-sandbox memfd fallback path needed it. Interpreter pinning made it dead permission — and the pen-test demonstrated dead permission = live attack surface. Regression test `memfd_create_not_in_plain_allowlist`. |
| F-NEW-01 / F-NEW-04 TOCTOU host-memory burst + unbounded rlimits (NEW finding, 2026-05-25) | SUSPECTED REACHABLE (host-wide OOM via burst-mmap before `place_child_in_cgroup` lands) → **CLOSED via `apply_rlimits_in_child` pre_exec hook (2026-05-25)** | `lib.rs` `SandboxHandle::apply_rlimits_in_child` + `main.rs` pre_exec chain insertion (position 4 of 5) + new flags `--sandbox-rlimit-as-bytes` / `--sandbox-rlimit-nproc` / `--sandbox-rlimit-memlock-bytes` | The supervisor's `Command::spawn` returns after the child is already executing; only then does it write the child PID into `cgroup.procs`. During the window the child runs in the supervisor's inherited root cgroup with no `memory.max` enforcement (cgroup v2 charges pages at allocation, won't retroactively reclaim). The 2026-05-25 open-exploration agent identified this as the most concerning structural finding. Fix: `prlimit64(pid=0, RLIMIT_AS, sandbox_memory_max + 1 GiB)` in pre_exec bounds the burst before exec; RLIMIT_NPROC=256 caps fork bombs; RLIMIT_MEMLOCK=0 denies `mlock`. `prlimit64` was already in the seccomp allowlist via `prlimit64_self_only_rules`, so the hook runs cleanly. Verified live: `cat /proc/<child>/limits` shows `Max address space 5368709120` / `Max processes 256` / `Max locked memory 0` under the new build. |
| F-NEW-02 inherited stdio fd escapes RW path (NEW finding, 2026-05-25) | CONFIRMED REACHABLE (compromised child writes to operator's log file outside sandbox) → **CLOSED via `Command::stdout/stderr` redirect in supervisor (2026-05-25)** | `main.rs` opens `<first-sandbox-rw-path>/.gemini-node-stdio.log` (override: `--sandbox-stdio-log <path>`) with `O_CREAT|O_APPEND|O_WRONLY,0644` BEFORE `cmd.spawn`; passes via `Stdio::from(file)` for both stdout and stderr | Live observation by the 2026-05-25 open-exploration agent showed `/proc/<child>/fd/{1,2} → /tmp/rostro-smoke/tightened.log` — outside the sandbox RW path. `close_inherited_fds_in_child` runs `close_range(3, UINT_MAX)` by design, leaving 0/1/2 open per pre_exec convention. Under systemd `ExecStart`, those inherited fds would be root-owned journal-stream sockets — strictly worse. Fix opens the redirect in the supervisor (still root, unfiltered) before fork. Verified live: `/proc/<child>/fd/{1,2} → /tmp/rostro-bp-fixed/.gemini-node-stdio.log` (inside the noexec bind-mount). Block production unaffected (12 blocks in 80s, prep times 201-204ms). |
| F-NEW-03 same-UID lateral signal reach (NEW finding, 2026-05-25) | CONFIRMED REACHABLE (compromised validator-A can SIGSTOP/SIGKILL sibling validators on same host running as uid 1000) → **CLOSED via per-role dedicated UIDs in lab wrapper (2026-05-25)** | `playbooks/lab-supervisor-wrapper.sh` — per-role mapping `alice→2001 / bob→2002 / observer→2003`; deployment playbook (`01-from-devbox.sh`) creates `rostro-{alice,bob,observer}` users + chowns `$DATA` accordingly | Phase G drops CAP_KILL so cross-UID signal is denied, but the kernel's `kill(2)` UID check passes freely for same-UID processes. Yesterday's lab had all roles at uid 1000 — same-host lateral signal reachable. Fix: each role's gemini-node child runs as its own dedicated UID, no two roles share. Wrapper fails fast if the per-role user isn't provisioned. Local WSL devbox unchanged (single role, uid 1000 fine). |
| F-NEW-R2-01 RLIMIT_AS=0 footgun (NEW finding, round-2 pen-test 2026-05-25) | SUSPECTED REACHABLE (operator misconfig re-opens F-NEW-01) → **CLOSED via parse-time refusal (2026-05-25)** | `main.rs` `run()` — explicit `Some(0)` rejection with operator-facing error | The agent flagged that `Some(0) → None` for RLIMIT_AS inverts the MEMLOCK convention (`0 = hard-deny`); operators with the MEMLOCK muscle memory could re-open F-NEW-01 by passing `--sandbox-rlimit-as-bytes=0`. Fix refuses at parse time with a clear error pointing at the right usage. Empirically verified: supervisor exits with `F-NEW-R2-01 misconfig` log + non-zero status. Dead-arm in pre_exec wiring removed. |
| F-NEW-R2-02 symlink at default stdio-log path (NEW finding, round-2 pen-test 2026-05-25) | CONFIRMED REACHABLE (supervisor opens symlink as root → child writes through inherited fd into attacker-chosen target inside RW path) → **CLOSED via `O_NOFOLLOW` + fail-stop (2026-05-25)** | `main.rs` stdio-log open uses `OpenOptions::custom_flags(libc::O_NOFOLLOW)`; any open error fails the spawn instead of falling back to inherited stdio | The agent's strongest finding: the F-NEW-02 fix opens a file as ROOT *before* fork, then hands fd 1/2 to the child. Without `O_NOFOLLOW`, a symlink at `<rw>/.gemini-node-stdio.log` would redirect writes to (e.g.) RocksDB MANIFEST. Fix: refuse symlinks at the stdio path. Empirically verified: planted symlink → ELOOP → supervisor logs `F-NEW-R2 (ELOOP — symlink at the stdio path; possible attack: ...)` + refuses to spawn. |
| F-NEW-R2-03 stdio-log deep in RW path (NEW finding, round-2 pen-test 2026-05-25) | SUSPECTED REACHABLE (operator points stdio at RocksDB WAL/internal-file → DB corruption via inherited fd) → **CLOSED via `validate_stdio_log_placement` (2026-05-25)** | `main.rs` new validation function, called from `run()` before sandbox install. Permits immediate-child of an rw_path, paths outside all rw_paths, or `/dev/null`; refuses deep RW subpaths | Structurally identical to the F15/F16 overlap-rejection pattern for `--state-file` / `--canonical-dir`. The F-NEW-02 closure introduced a new operator-controlled file-open path that wasn't covered by the existing validation family; R2-03 extends the family. 7 new unit tests cover the validation matrix (none, dev-null, immediate child, outside-RW, deep RW, component-aware non-overlap). |
| F-NEW-R2-04 `--sandbox-rw-path` top-level system dir (NEW finding, round-2 pen-test 2026-05-25) | CONFIRMED REACHABLE (operator misconfig `--sandbox-rw-path /etc` → host-global `MS_NOEXEC` remount breaks system services) → **PARTIALLY CLOSED via denylist (2026-05-25)** + **R3-03 path-normalization addendum** | `main.rs` new `validate_rw_paths_not_system_dirs` + `SYSTEM_TOPLEVEL_DENYLIST` const | Stopgap, not architectural. The denylist refuses exact-match of well-known top-level system directories; nested paths under those remain valid. R3-03 (below) extends the validation with path normalization to refuse trailing-slash + double-slash + `.`-component bypasses. The architectural fix is `unshare(CLONE_NEWNS)` to contain the noexec bind-remount to the supervisor's mount namespace — tracked for a separate decision because the UX tradeoff (host-visible mounts for operator debugging) deserves a deliberate call. 5 + 7 new unit tests cover the matrix. |
| F-NEW-R3-01 supervisor state-file persist broken by Cannae (NEW finding, round-3 pen-test 2026-05-25) | CONFIRMED REACHABLE (`save_atomic` always returns EACCES under Cannae's Landlock; counter caps degraded to per-supervisor-lifetime) → **CLOSED via journald-mirror STATE_DELTA emission (2026-05-25)** | `main.rs` `SupervisorState::emit_delta_to_journal` + `save_and_mirror` wrapper; both crash + swap call sites updated; persist-failure log tightened WARN → ERROR with reconstruction command | The user's "mirror to some other unreachable part of the drive" hint pointed at journald — already running on every lab node, writes to `/var/log/journal/` outside Cannae's policy envelope and outside the child's DAC reach. Structured single-line format (`STATE_DELTA schema=1 swap_count=N crashes=[T1,T2,...]`) for `journalctl --output=cat \| grep STATE_DELTA \| tail -1` reconstruction. Empirically verified live: every crash + swap emits a STATE_DELTA line to stderr; ERROR log loud and operator-actionable. Architectural follow-up (Landlock-child-only refactor) deferred. 2 new unit tests cover format stability. |
| F-NEW-R3-02 child ftruncates inherited stdio fd (NEW finding, round-3 pen-test 2026-05-25) | CONFIRMED REACHABLE (148 bytes of pre-attack content vanished, attacker banner alone remained) → **CLOSED via pipe-relay + chattr +a (2026-05-25)** | `main.rs` stdio block: replaced file-fd-passing with `pipe2(O_CLOEXEC)`; per-spawn reader thread forwards lines to (a) global in-sandbox mirror file (opened ONCE pre-Cannae with `FS_APPEND_FL` ioctl) and (b) supervisor stderr with `[child-stdio] ` prefix (→ journald) | The user's "forensic mirror" insight: don't share writable fds across the privilege boundary. Child's 1/2 are now pipe write-ends; `ftruncate(pipe, 0)` returns EINVAL — pipes have no size to truncate. Defense-in-depth: mirror file gets `chattr +a` at supervisor startup (pre-Cannae since post-Cannae ioctl is arg-filtered to terminal-config-only) — kernel refuses ftruncate/unlink on the inode even if a future bypass gets the child a fd. Empirically verified live: PoC's `ftruncate(1, 0)` returns "Invalid argument" (EINVAL); pre-attack content preserved; `[child-stdio]` prefix forwards each line to journald. gemini-node block production unaffected (8 blocks in 60s). Mirror file `/tmp/rostro-bp-r3/.gemini-node-stdio.log` accumulates child output across restart cycles. |
| F-NEW-R3-03 non-canonical paths bypass `validate_rw_paths_not_system_dirs` (NEW finding, round-3 pen-test 2026-05-25) | CONFIRMED REACHABLE (`/etc/`, `//etc`, `/etc/.`, `/etc/foo/..` all accepted; kernel `mount(2)` resolves to same dentry; host's `/etc` got noexec bind-remounted in the pen-test) → **CLOSED via `normalize_path_for_denylist` (2026-05-25)** | `main.rs` new `normalize_path_for_denylist` runs before the denylist compare; uses `Path::components().collect()` for textual canonicalization + refuses `..` components outright | Whitehat-grade finding — the user named it as the "opening throw of an attack chain": a trailing-slash typo on a deployed config template + the supervisor would have noexec-remounted the host's `/etc` host-globally, breaking cron/init/security-monitoring services and chaining into operator-confusion-driven escalation. Fix normalizes textually (trailing/double slashes, `.` components) and refuses `..` (can't be statically resolved without filesystem traversal under symlinks). Empirically verified live: re-run of `--sandbox-rw-path /etc/` / `//etc` / `/etc/foo/..` all refused; `mount` confirms `/etc` no longer touched. 6 new parameterized unit tests cover the bypass matrix. |
| F-NEW-R4-01 stdio-log into system-managed directory tree (NEW finding, /security-review 2026-05-25, confidence 8/10 after FP-filter) | CONFIRMED REACHABLE (operator passes `--sandbox-stdio-log /etc/sudoers.d/foo` → supervisor opens AS ROOT pre-Cannae → pipe-relay reader appends child-controlled bytes verbatim → sudo parses on next invocation → root escalation; same shape for `/etc/cron.d/`, `/etc/profile.d/*.sh`, `/etc/ld.so.conf.d/*.conf`, `/etc/logrotate.d/*`, `/etc/systemd/*`, `/etc/init.d/*`, `/etc/sysctl.d/*`, `/etc/modprobe.d/*`, `/etc/pam.d/*`) → **CLOSED via tree-denylist on `validate_stdio_log_placement` (2026-05-25)** | `main.rs` new `STDIO_LOG_SYSTEM_PREFIX_DENYLIST` (`/etc`, `/usr`, `/bin`, `/sbin`, `/lib*`, `/boot`) + `path_is_under_stdio_system_prefix` (matches any descendant, not just exact match); `validate_stdio_log_placement` "outside-rw-paths" branch now refuses descendants of these prefixes after normalizing via `normalize_path_for_denylist` (R3-03 closure); stdio file mode tightened `0644` → `0600` (defense-in-depth — even if a future bypass lands a file in a daemon-scanned dir, the non-root daemon can't read it) | The /security-review's HIGH-severity finding. The R2-03 closure permitted ANY path outside rw_paths; the symmetric `SYSTEM_TOPLEVEL_DENYLIST` that R2-04 used for `--sandbox-rw-path` exact-match was NOT applied to stdio_log. Operator can still use `/var/log/rostro.log`, `/srv/rostro/log/`, `/opt/rostro/log/`, `/tmp/rostro-stdio.log`, `/home/<user>/rostro-stdio.log`, or any path inside an rw_path. 11 new parameterized unit tests cover sudoers.d / cron.d / profile.d / ld.so.conf.d / logrotate.d / systemd / usr-subpaths / bin-lib-boot + positive cases (var/log, srv, opt, tmp, home) + R3-03 bypass-shape interactions. Empirically verified live: `--sandbox-stdio-log /etc/sudoers.d/foo` refused with F-NEW-R4-01 error; `/var/log/rostro-test.log` accepted with FS_APPEND_FL set, mode 0600 root:root. |
| F-NEW-R4-02 child STATE_DELTA injection defeats reconstruction grep (NEW finding, /security-review 2026-05-25, confidence 8/10 after FP-filter) | CONFIRMED REACHABLE (compromised child `println!("STATE_DELTA schema=1 swap_count=0 crashes=[]")` → reader thread forwards as `[child-stdio] STATE_DELTA …` → un-anchored `grep STATE_DELTA \| tail -1` returns the attacker's line → operator hand-seeds zero counters → R3-01 cap-bypass that journald-mirror was meant to close is restored) → **CLOSED at two layers (2026-05-25)** | `main.rs` `emit_delta_to_journal` docstring + persist-failure ERROR log + `THREAT_MODEL.md` F-NEW-R3-01 row all updated to anchored `grep '^STATE_DELTA'`; new `sanitize_state_delta_for_relay` in `main.rs` substring-replaces `STATE_DELTA` → `STATE_DELTA_FROM_CHILD` in child bytes BEFORE writing to supervisor stderr (defense-in-depth) | The /security-review's MEDIUM-severity finding. Two-layer fix matches the agent's recommendation exactly. **Layer 1**: anchored grep — supervisor emits via `eprintln!` directly to stderr at column 0; pipe-relay reader prefixes child lines with `[child-stdio] `, so child can never produce a column-0 STATE_DELTA. **Layer 2**: byte-level substring mangling in the reader thread for the journald leg — operators running ad-hoc un-anchored greps, OR future changes that drop the prefix, still get non-confusable lines. The in-sandbox mirror file gets verbatim child bytes (operator's local-grep convenience preserved). 5 unit tests cover sanitize matrix (pass-through, plain inject, embedded inject, multi-occurrence, partial-at-end safety). Empirically verified live: 3-line PoC injection (plain + embedded + 3-occurrence) all mangled to `STATE_DELTA_FROM_CHILD` in supervisor stderr; anchored `grep '^STATE_DELTA'` returns zero matches; in-sandbox mirror file has verbatim child bytes. |
| F-AGENT-C-01 / F-AGENT-C-03 cgroup-cap reversal via child write to own `memory.max` / `memory.swap.max` / `cpu.max` | CONFIRMED ESCAPE (cgroup containment bypass) | Phase G — `(lib.rs `drop_to_uid_gid_in_child` + main.rs `--sandbox-child-uid/gid` flags + lab-supervisor-wrapper chown` | The child inherited root caps from the setuid-root supervisor. cgroup interface files are root-owned; only DAC was missing to enforce the caps. New pre_exec chain: close_fds → drop_cap_sys_admin (still root, needs CAP_SETPCAP) → drop_root_caps_for_uid_drop (drops CAP_SETUID/SETGID/KILL from bounding set) → drop_to_uid_gid (setgroups + setresgid + setresuid). Supervisor refuses to launch as root without both flags. Verified by Wave-2 (`redteam-2026-05-24/runs/agent-A-v2.out`): all 6 cgroup-write PoCs return EACCES at the kernel DAC layer. |
| F-AGENT-C-05 child kills supervisor via `kill(getppid(), SIGTERM)` | CONFIRMED ESCAPE (supervisor compromise) | Phase G (same commit set as C-01/03) | `kill(2)` across UIDs requires `CAP_KILL`. The Phase G bounding-set drop removes it before the UID drop, so the post-uid-drop child has no `CAP_KILL` in effective. Kernel UID check fails → EPERM. Verified by Wave-2: both `kill(getppid(), SIGTERM)` and `kill(getppid(), SIGKILL)` return EPERM. UID-reclaim defense (setresuid(0,0,0)) similarly returns EPERM. |
| F-AGENT-C-04 cgroup directory leak on supervisor exit | RELIABILITY (debian-01 accumulated 196 stale dirs in one red-team session) | Phase G — `lib.rs` `Drop for SandboxHandle` via `unlinkat(AT_REMOVEDIR)` + `linux.rs` Landlock REMOVE_DIR grant on cgroup root | Two stacked subtleties bit this fix iteration. v1 of Drop used `std::fs::remove_dir` which compiles to `rmdir(2)` — not in PLAIN_ALLOWED_SYSCALLS — SIGSYS-killed. v2 used `unlinkat(AT_REMOVEDIR)` (allowed) but EACCES'd at Landlock because `LANDLOCK_ACCESS_FS_REMOVE_DIR` was not granted on the parent of the cgroup dir. v3 (current) widens the Landlock ruleset to grant `RemoveDir + ReadDir` on the cgroup root (`/sys/fs/cgroup`) — safe for the inherited child since DAC blocks non-root writes to root-owned cgroup interface files and rmdir of in-use cgroups returns EBUSY. Verified by Wave-4 (`redteam-2026-05-24/runs/agent-A-v3-leak-only.out`): 3 test-supervisor invocations → 0 leaked dirs → 0 Drop warnings. |

### Still open

Tracked separately in `~/rostro-testnet-lab/notes/redteam-2026-05-23/REPORT.md`:

- ~~**F05** file-backed `mmap(PROT_EXEC)`~~ — **CLOSED via Phase H MS_NOEXEC bind-remount (2026-05-25).** See closed table above.
- ~~**F06** mprotect W→X~~ — **CLOSED via Phase H mprotect Rule 2 removal (2026-05-25).** See closed table above.
- **F13 ftruncate residual** — fchmod/fchown family closed (see above);
  ftruncate kept for RocksDB still allows the /proc/self/fd-reopen
  pattern against inherited writable-inode fds. Mitigation is
  supervisor CLOEXEC discipline (audit + close non-essential fds
  before exec) — separate work item.
- **F14 / F22 / F25 / F28-31** — /proc info leak surfaces.
  Documented in [`THREAT_MODEL.md`](THREAT_MODEL.md) §3 — design-
  implied because supervisor runs as root and we don't PID-namespace.
  Lateral recon, not escalation.
- **Supervisor SIGINT/TERM propagation** — when the supervisor exits,
  its child gemini-node is orphaned to systemd rather than killed.
  Caused operator confusion during Phase G lab bring-up (orphaned
  child held the RocksDB lock; the supervisor's next restart's child
  failed to acquire it). Not a security issue; reliability gap to
  close with a signal handler that propagates to the child.

## Diagnostic tooling added

For future iterations, the install function now respects two env vars
that skip individual primitives without rebuilding:

- `ROSTRO_SKIP_LANDLOCK=1` — install cgroup + seccomp only
- `ROSTRO_SKIP_SECCOMP=1` — install cgroup + Landlock only

Both skipped = effectively `--unsafe-skip-sandbox` minus the supervisor
warnings. Useful for isolating which primitive is responsible for a
failure mode during Phase 5 iteration. **NEVER set these in production.**

## How to run the next iteration

```bash
# On the lab dev box (~/Rostro-sandbox/):
SUBSTRATE_RUNTIME_TARGET=riscv SUBSTRATE_ENABLE_POLKAVM=1 \
  cargo build --release --locked -p gemini-node -p rostro-supervisor

# Sign + push (see ~/rostro-testnet-lab/playbooks/release-sign.sh)
bash ~/rostro-testnet-lab/playbooks/release-sign.sh ~/rostro-testnet-lab/binaries/

# Push to all 3 nodes via ssh
for n in rostro-fedora-01 rostro-debian-01 rostro-ubuntu-01; do
  scp ~/rostro-testnet-lab/binaries/{rostro-supervisor,gemini-node,manifest.txt,manifest.txt.sig} "$n:/tmp/"
done

# Run supervisor under each primitive in isolation:
ssh rostro-fedora-01 'sudo timeout 60 \
  env SUBSTRATE_ENABLE_POLKAVM=1 ROSTRO_SKIP_LANDLOCK=1 \
  /opt/rostro/bin/rostro-supervisor \
    --sandbox-rw-path /opt/rostro/data --sandbox-ro-path /opt/rostro/bin \
    --sandbox-memory-max-bytes 4294967296 --sandbox-cpu-max-micros 400000 \
    -- --base-path /opt/rostro/data --dev'
```

Lab-side detailed report + raw baselines:
`~/rostro-testnet-lab/strace-baselines/` and
`~/rostro-testnet-lab/notes/phase-5-outcome-20260523.md`.
