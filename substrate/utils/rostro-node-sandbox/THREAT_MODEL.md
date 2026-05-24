# Aegis sandbox — threat model

What the host-level isolation envelope wrapping `gemini-node`
actually protects against, what it deliberately accepts, and what
remains residual under the current design.

This document is the public contract. Everything in scope of "what
Aegis defends" is something a red-team should expect to fail against
a compliant deployment; everything in "accepted by design" is fair
game for an attacker who has already gained code execution in the
sandboxed process.

## 1. Adversary model

We assume a **compromised gemini-node**: an attacker has achieved
arbitrary native-code execution inside the sandboxed validator
process. Specifically:

- They can call any syscall they want — modulo the seccomp filter.
- They can read+write the process's own memory.
- They can read filesystem paths granted via Landlock (BASELINE_RO
  + `--sandbox-ro-path` + `--sandbox-rw-path`).
- They can write to `--sandbox-rw-path` and inherited file descriptors.
- They have whatever Linux capabilities the supervisor passed down,
  minus `CAP_SYS_ADMIN` (dropped via pre_exec — Pending #7).

We do NOT assume:

- Physical access to the host.
- Network access beyond what gemini-node already had (the libp2p
  + RPC listeners on configured ports).
- Knowledge of supervisor-internal secrets (release-signing key,
  state file contents).

## 2. What Aegis defends against (closed)

Every item below has been red-teamed and verified to fail under the
current build. F-numbers map to entries in
`~/rostro-testnet-lab/notes/redteam-2026-05-23/REPORT.md`.

### 2.1. Process-level escape primitives

| Attack | Mechanism | Defended by |
|---|---|---|
| F02 | `clone3(CLONE_NEWUSER)` namespace creation → systemd-reachable chain | Stacked seccomp filter returns ENOSYS for clone3; glibc falls back to legacy `clone()` which the existing CLONE_NEW* MaskedEq filter SIGKILLs |
| F01 | `prlimit64(pid=1, RLIMIT_NOFILE=8)` → brick sshd | `prlimit64` arg-filtered to `pid == 0` (self) only |
| F13 | `fchmod 0666 /etc/resolv.conf` via `/proc/self/fd/N` reopen | `fchmod` / `fchown` / `fchmodat` / `fchownat` denied; `close_range(3, UINT_MAX)` in child pre_exec eliminates inherited fds |
| F03 | `socket(AF_INET6, SOCK_RAW, IPPROTO_RAW)` → raw packet injection | `socket` arg-filtered: `(domain ∈ {AF_INET, AF_INET6}) ∧ ((type & 0xF) ∈ {SOCK_STREAM, SOCK_DGRAM})`. SOCK_RAW denied by absence |
| F04 | `setsockopt(SO_ATTACH_FILTER)` → kernel cBPF VM reach | `setsockopt` arg-filtered to 7 known-safe `(level, option)` pairs |
| F07 | `prctl(PR_SET_PTRACER_ANY)` → Yama bypass; `PR_SET_DUMPABLE`, `PR_SET_MM` etc | `prctl` arg-filtered to `PR_SET_NAME` + `PR_CAPBSET_DROP` only |
| F05 | mmap `PROT_READ\|PROT_EXEC` file-backed against attacker-written `/opt/rostro/data/sc.bin` | Landlock denies `LANDLOCK_ACCESS_FS_EXECUTE` on every `--sandbox-rw-path`; kernel rejects exec mappings of inodes in RW paths |
| F12 | Allocate 5 GiB under a 4 GiB `memory.max` cap → swap spill | cgroup `memory.swap.max = 0` pinned alongside `memory.max`; OOM kill fires at the cap |
| F08 | RocksDB `posix_fadvise(2)` → continuous SIGSYS crash loop | `fadvise64` allowed; same for `readahead` (ubuntu cross-distro variant) |
| F15 / F16 | Operator misconfig: `--state-file` or `--canonical-dir` inside `--sandbox-rw-path` → child rewrites supervisor counters / drops `*.new` for atomic rotation | Supervisor refuses to launch with overlap; clear F-numbered error before any privileged resource committed |
| F09 | `--state-file ""` documented but rejected by clap → operators stranded | Docstrings rewritten to describe actual behavior |
| F17 | `symlink(2)` denied while `symlinkat(2)` allowed | `symlink` added to allowlist; Landlock still gates path policy |
| (Pending #7 — promoted to load-bearing) | Future kernel adds a new `CAP_SYS_ADMIN`-gated operation whose syscall isn't in our deny list | Child pre_exec calls `prctl(PR_CAPBSET_DROP, CAP_SYS_ADMIN)`; drop is to bounding set so permanent + cannot be raised |

### 2.2. Containment guarantees the kernel + Landlock provide

These are not red-team findings but the positive defense the sandbox
provides:

- **Memory cap.** Hard limit at `--sandbox-memory-max-bytes` via cgroup
  `memory.max` + `memory.swap.max=0`. OOM kills the entire cgroup
  atomically (`memory.oom.group=1`) so a partial OOM can't leave the
  child in a half-state.
- **CPU cap.** Hard limit at `--sandbox-cpu-max-micros` per
  `--sandbox-cpu-period-micros` window via cgroup `cpu.max`.
- **Filesystem scope.** Landlock denies *all* paths outside the union
  of `BASELINE_RO_PATHS` + `--sandbox-ro-path` + `--sandbox-rw-path` +
  the cgroup directory. Even root-owned files outside these are
  unreachable.
- **Filesystem mutation.** Within `--sandbox-rw-path`, the child can
  read/write/create/delete files, but cannot exec them (F05 fix).
- **Syscall surface.** ~60 specific syscalls allowed; everything else
  is `SIGKILL` via `SECCOMP_RET_KILL_PROCESS`. Argument-filtered for
  `mmap`, `mprotect`, `clone`, `clone3` (via stacked ENOSYS),
  `socket`, `setsockopt`, `prctl`, `prlimit64`, `ioctl`.
- **W^X memory.** mmap arg filter rejects simultaneous
  `PROT_WRITE | PROT_EXEC`. JIT-flip pattern (write fill →
  `mprotect(PROT_READ | PROT_EXEC)`) is the only way to get
  executable memory.
- **Namespace creation.** Both legacy `clone(CLONE_NEW*)` (direct
  arg-filter) and `clone3(CLONE_NEW*)` (via ENOSYS-fallback-to-legacy)
  refused.
- **Network surface.** Only `AF_INET`, `AF_INET6` (STREAM + DGRAM),
  `AF_UNIX`, and `AF_NETLINK + NETLINK_ROUTE` (for interface
  enumeration) reachable. AF_PACKET, AF_VSOCK, AF_BLUETOOTH, all
  other NETLINK protocols denied.

## 3. Accepted by design

These are reachable from inside the sandbox and **will not be
defended against** without a fundamental architecture change. An
attacker with code execution can use them; the design accepts that.

### F06 — anonymous `mprotect` W→X JIT flip

Pattern: `mmap(NULL, n, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE)`,
write shellcode, `mprotect(p, n, PROT_READ|PROT_EXEC)`, jump.

The `mprotect` arg filter explicitly allows this transition because
**PolkaVM's JIT requires it.** The Rostro runtime executor builds
native code for the RISC-V runtime at runtime; without the W→X flip
there's no JIT.

**Implication:** any memory-corruption bug in gemini-node that gives
an attacker arbitrary writes will let them stage and execute
shellcode entirely in anonymous memory. Landlock can't gate this
(no file backing). The host-impact mitigations (cgroup caps,
syscall denials, dropped CAP_SYS_ADMIN, Landlock fs scope) still
apply, but in-sandbox native code execution is the threat-model
ceiling, not a target.

### F14 / F22 — `/proc` host-process inventory

`/proc` is in the Landlock baseline RO paths (substrate reads
`/proc/self/cgroup`, `/proc/cpuinfo`, etc.). Reading `/proc/<pid>`
for arbitrary `<pid>` enumerates host processes, their cmdlines,
their `/proc/<pid>/maps`, their `/proc/<pid>/environ`,
`/proc/net/tcp` (every listening port + UNIX socket), the ARP cache.

**Why accepted:** the "right" fix is mounting `/proc` with
`hidepid=invisible,subset=pid` inside a PID namespace. We've ruled
out PID namespaces as a design choice (validator processes are
identifiable on the host for ops + audit reasons; PID namespacing
breaks systemd cgroup accounting; the cost outweighs the leak).

**Implication:** a compromised validator can learn what else runs
on the host, who's listening on what port, and the ARP cache
contents (peer lab node IPs, MACs). This is lateral recon material,
not privilege escalation. The supervisor's own
`/proc/<sup_pid>/environ` exposes `SUDO_COMMAND` (cgroup caps,
state-file path) — minor info leak.

### F25 — `/proc/kcore` readable by root

Reachable because the child inherits root caps (modulo CAP_SYS_ADMIN
post-Pending #7). Pending #7's bounding-set drop reduces this
exposure but `CAP_SYS_RAWIO` would also need to drop to fully gate
`/proc/kcore` read. Tracking as future work.

### F23 / F24 / F26 / F27 / F33 — kernel introspection

`kallsyms`, `/proc/modules`, `/proc/iomem`, `/proc/ioports`,
`/proc/slabinfo`, `/proc/keys`, `/proc/swaps`, `/proc/zoneinfo` are
all readable. `kallsyms` addresses are zeroed by
`kptr_restrict=2` (set in our lab hardening sysctls). The structure
is visible but the addresses aren't, which is what matters for
typical kernel exploitation.

### F28 — F30 — host identity + HW + timing

CPU model (`/proc/cpuinfo`), vulnerabilities list
(`/sys/devices/system/cpu/vulnerabilities/*`), boot_id, uptime,
loadavg, pressure stats all readable. Timing-channel surface via
`clock_gettime` (allowed; required for correctness).

**Why accepted:** these are how legitimate substrate code adapts
to host capabilities (e.g., CPUID-based feature detection). Hiding
them breaks more than it protects.

### F31 — userns uid_map reads

`/proc/<pid>/uid_map = 0 0 4294967295` is readable for every host
PID — documents that no host process is in a user namespace. Same
PID-namespacing decision applies; gated under "info leak, not
escalation."

## 4. Residual gaps (known, not yet closed)

### F13 ftruncate-via-reopen — *partially* closed

The fchmod family is denied outright (Pending #7 close_range also
removes inherited writable fds), but `ftruncate(2)` itself remains
allowed because RocksDB needs it.

An attacker who can obtain a writable-inode fd via a path Landlock
doesn't deny (i.e., something in `--sandbox-rw-path`) can still
truncate that file. The path scope means they cannot truncate host
config files like `/etc/resolv.conf` — but they CAN truncate any
file in `/opt/rostro/data` (validator state, keystore, RocksDB).

This is consistent with the threat model: the attacker can already
write to those paths, so truncating them adds no privilege; it's
just destruction within reach. Treated as in-scope vandalism, not
escalation.

### Supervisor state-file write under Aegis

The supervisor process is itself sandboxed (same Landlock + seccomp
filter as the child). After Aegis install, the supervisor cannot
write to `<canonical_dir>/.supervisor-state` because that path
isn't in `--sandbox-rw-path` (and F15/F16 validation refuses to put
it there). State persistence WARN's are logged each restart; the
supervisor still functions, counters just reset.

The architectural fix is to refactor so the supervisor is NOT
itself sandboxed — only the child via pre_exec. Bigger refactor
deferred; current behavior tracked.

### TLS root CA loading under Landlock

Observed during lab bring-up on debian-01: gemini-node's TLS client
flooded the log with `/usr/lib/ssl/certs/*` permission-denied errors.
That path isn't in `BASELINE_RO_PATHS`. Substrate's libp2p uses
noise (not TLS), so chain operation isn't affected, but any
reqwest/rustls HTTPS client from inside the node would fail. Add to
ro_paths via operator config if HTTPS is needed.

## 5. Operator security posture

Mainnet operators should:

1. **Run `rostro-supervisor` as root** (required for cgroup
   v2 + Landlock install). The Pending #7 cap-drop neuters the
   risk; root is needed only for setup.
2. **Pass `--sandbox-rw-path`, `--sandbox-ro-path`, `--sandbox-memory-max-bytes`,
   `--sandbox-cpu-max-micros`** for every deployment. Without caps
   configured the cgroup install is skipped, and Landlock is configured
   with whatever paths you do pass.
3. **Run on a host with `kernel.unprivileged_userns_clone = 0`,
   `kernel.kexec_load_disabled = 1`, `kernel.dmesg_restrict = 1`,
   `kernel.yama.ptrace_scope = 3`** (production target;
   the lab uses scope=1).
4. **Disable `io_uring`** at boot (`io_uring_disabled=2`).
5. **Apply CPU mitigations** (`mitigations=auto,nosmt`).

The lab tests reproduce all of the above; `~/rostro-testnet-lab/playbooks/sysctl-99-rostro.conf`
is the reference config.

## 6. What this doc is NOT

- Not a guarantee of soundness against unknown bugs. Aegis reduces
  the blast radius of a compromised validator; it cannot prevent
  every novel kernel bug from being weaponized.
- Not a substitute for keeping `gemini-node` itself bug-free. The
  most secure sandbox in the world is still a defense-in-depth
  layer behind correctness of the validator binary.
- Not exhaustive of all configurations. Operator misconfig outside
  the F15/F16 validator (e.g., pointing `--sandbox-rw-path` at `/`)
  can still create gaps not enumerated here. Default to the lab
  configuration as reference.

## 7. Update cadence

This document is generated by hand and lags reality. When a fix
lands that closes a residual or accepts a new design item, edit
the relevant section in the same PR. The `PHASE5_NOTES.md`
red-team-follow-up tracker is the authoritative per-commit record;
this doc is the user-facing summary.

Last revised: 2026-05-24 (Phase E close, all F-numbers except F06
+ residuals addressed).
