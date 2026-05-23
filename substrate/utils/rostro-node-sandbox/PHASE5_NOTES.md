# Phase 5 — first-pass outcome (2026-05-23)

Real-Linux validation of `rostro-node-sandbox` against the bare-metal lab
described in [VALIDATION.md](VALIDATION.md). This document captures what
was caught, what was fixed, what's still open, and how to run the next
iteration.

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

**Fix:** Add `libc::SYS_clone3` to `PLAIN_ALLOWED_SYSCALLS` with an
explicit rationale block. Soundness gap accepted: seccomp can't inspect
`clone_args` (struct behind a pointer), so namespace-creation flags
(`CLONE_NEW*`) pass through unfiltered.

**Mitigation:**
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

### Pending #1 — re-baseline UNDER the supervisor

In `KillProcess` mode (production action), gemini-node SIGKILLs early in
startup. In `Log` mode (diagnostic action), the same gemini-node runs
through full init + idle for ~30s. Means the supervised process makes
syscalls that the strace baseline didn't capture — likely because the
baseline ran `gemini-node` directly, not under `rostro-supervisor`. The
parent-process / env / inheritance shape differs and surfaces additional
early-startup syscalls.

**Action:** Capture a baseline UNDER the supervisor. Either:
- `SeccompAction::Log` + audit subsystem reading the denial log (Fedora
  doesn't have `auditd` running by default; install + start)
- Or: `perf trace --pid <supervised-gemini-node>` from outside
- Or: temporarily allow ALL syscalls (broad-then-narrow), capture under
  sandbox, then re-tighten

The new `ROSTRO_SKIP_LANDLOCK` and `ROSTRO_SKIP_SECCOMP` env vars
(added in this commit) help isolate per-primitive failures during this
work.

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

### Pending #4 — separate dev-mode regression

`gemini-node --dev` (raw, NO supervisor, NO sandbox) terminates after
~30–45 seconds of idle with:

```
ERROR tokio-runtime-worker rc_service::task_manager:
Essential task `txpool-background` failed. Shutting down service.
```

This reproduces on all three lab nodes, with and without sandbox.

The user reports that "before messing with any kind of sandbox, the
nodes ran and peered" — meaning gemini-node ran indefinitely in prior
testing. **Something in sandbox-v0 (or between Phase Z's ship date
2026-05-16 and now) introduced a dev-mode txpool-background regression.**

Most likely culprits to investigate:
- Recent fork-aware txpool changes
- PolkaVM runtime revalidation timer
- Some periodic task ending its input stream

This is NOT a sandbox concern but it blocks Phase Star bring-up
(can't peer if nodes die after 30s) — high priority to find and fix.

### Pending #5 — adversarial + OOM + perf-delta sign-off

Phase 5 steps 5–7 in VALIDATION.md (ptrace adversarial test, OOM cgroup
behavior, perf-delta sandbox-on vs sandbox-off) cannot run until #1 is
closed — they require gemini-node to actually stay alive under
`KillProcess` mode.

### Pending #6 — Landlock execute-denial on RW paths (v2 hardening)

Bug 3's fix allows `mmap(PROT_EXEC + file-backed)`. A compromised
in-sandbox process can write malicious code to a permitted RW path
(`/opt/rostro/data`) and mmap it executable. Landlock 6.4+ supports
denying execute on RW paths; adopt when we bump the kernel floor.

### Pending #7 — CAP_SYS_ADMIN drop (v2 hardening)

Bug 2's fix accepts the `clone3` soundness gap (no arg filtering
possible). The defense-in-depth path is dropping `CAP_SYS_ADMIN` before
exec'ing the child so even root inside the child can't create
namespaces with `CLONE_NEW*`. Supervisor needs root for cgroup setup;
drop the cap between setup and exec.

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
