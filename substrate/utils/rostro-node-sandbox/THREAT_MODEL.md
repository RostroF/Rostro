# Cannae sandbox — threat model

What the host-level isolation envelope wrapping `gemini-node`
actually protects against, what it deliberately accepts, and what
remains residual under the current design.

This document is the public contract. Everything in scope of "what
Cannae defends" is something a red-team should expect to fail against
a compliant deployment; everything in "accepted by design" is fair
game for an attacker who has already gained code execution in the
sandboxed process.

> **Naming.** The sandbox was originally named "Aegis." It was renamed
> to "Cannae" on 2026-05-25 after the Phase G work closed the last
> wave of bypasses. The name refers to Hannibal's 216 BC double
> envelopment at Cannae: a smaller force defeating a larger one
> through concentric tactical layering. The same shape applies here —
> small auditable code surface, with cgroup + Landlock + seccomp +
> UID drop + capability drops forming concentric layers around a
> compromised validator's full ambient authority.

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

## 2. What Cannae defends against (closed)

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
| F12 | Allocate 5 GiB under a 4 GiB `memory.max` cap → swap spill | cgroup `memory.swap.max = 0` pinned alongside `memory.max`; OOM kill fires at the cap |
| F-AGENT-C-01 / C-03 | Child writes `memory.max=max` / `memory.swap.max=max` / `cpu.max="max …"` to its own `/sys/fs/cgroup/rostro-node-<pid>/child/` files → reverses every cgroup cap in one syscall each | Phase G child UID drop: pre_exec calls `setresgid` + `setresuid` to a non-root `(--sandbox-child-uid, --sandbox-child-gid)`. cgroup interface files are root-owned; kernel DAC blocks non-root writes. Supervisor refuses to launch as root without both flags |
| F-AGENT-C-05 | Child calls `kill(getppid(), SIGTERM)` to kill the root supervisor and run unsupervised | Phase G drops `CAP_SETUID + CAP_SETGID + CAP_KILL` from the bounding set before the UID drop. After the drop, child's effective set is filtered through bounding → kernel's `kill(2)` UID check fails (cross-UID kill requires CAP_KILL); also defeats the `setresuid(0,…)` reclaim path |
| F-AGENT-C-04 | Per-invocation cgroup tree `/sys/fs/cgroup/rostro-node-<pid>/{child,}` leaks on every supervisor exit — 196+ dirs accumulated during one red-team session | `Drop for SandboxHandle` calls `unlinkat(AT_FDCWD, path, AT_REMOVEDIR)` for child then parent. Landlock ruleset grants `RemoveDir + ReadDir` on the cgroup ROOT so both rmdirs succeed |
| F08 | RocksDB `posix_fadvise(2)` → continuous SIGSYS crash loop | `fadvise64` allowed; same for `readahead` (ubuntu cross-distro variant) |
| F15 / F16 | Operator misconfig: `--state-file` or `--canonical-dir` inside `--sandbox-rw-path` → child rewrites supervisor counters / drops `*.new` for atomic rotation | Supervisor refuses to launch with overlap; clear F-numbered error before any privileged resource committed |
| F09 | `--state-file ""` documented but rejected by clap → operators stranded | Docstrings rewritten to describe actual behavior |
| F17 | `symlink(2)` denied while `symlinkat(2)` allowed | `symlink` added to allowlist; Landlock still gates path policy |
| (Pending #7 — promoted to load-bearing) | Future kernel adds a new `CAP_SYS_ADMIN`-gated operation whose syscall isn't in our deny list | Child pre_exec calls `prctl(PR_CAPBSET_DROP, CAP_SYS_ADMIN)`; drop is to bounding set so permanent + cannot be raised |
| F05 | Write shellcode into `--sandbox-rw-path` file, `mmap(PROT_EXEC, fd, …)`, jump | **Phase H (2026-05-25):** `install_noexec_remount` bind-mounts each `--sandbox-rw-path` onto itself with `MS_NOEXEC` before Landlock + seccomp install. The kernel's mount layer denies `mmap(PROT_EXEC, fd, …)` on any inode under those mounts with `EACCES` — VFS-layer enforcement, upstream of Landlock + seccomp. Previously (commit `23a8410f4c`) attempted via `LANDLOCK_ACCESS_FS_EXECUTE`; 2026-05-24 Wave-2 red-team proved that bit gates `execve(2)` only and not `mmap`. |
| F06 | Anonymous `mmap(W) → mprotect(R|X)` JIT-flip → execute in-process shellcode | **Phase H (2026-05-25):** `mprotect_safe_rules` Rule 2 (PROT_EXEC + PROT_WRITE-clear) removed. Single remaining rule: `PROT_EXEC == 0`. Any `mprotect` requesting `PROT_EXEC` SIGKILLs. Carve-out existed only because polkavm 0.32's JIT path needed it; Phase H's `RostroCodeExecutor::new` pinned the executor to PolkaVM's interpreter backend, retiring the JIT (and its W→X requirement) entirely. |
| F-MEMFD | `memfd_create("sc", 0)` + `ftruncate` + `write` + `mmap(PROT_EXEC, memfd, …)` → execute shellcode from kernel memory with no vfs path Landlock can gate | **Phase H (2026-05-25):** `SYS_memfd_create` removed from `PLAIN_ALLOWED_SYSCALLS`. Was previously allowed (commit `03d68cf919`) as a fallback for polkavm's JIT generic-sandbox path after CAP_SYS_ADMIN drop; interpreter pinning made it dead permission. The 2026-05-25 pen-test (agent A) demonstrated the carve-out as live attack surface — strictly more powerful than F05/F06 because the memfd's only path is `/memfd:<name> (deleted)` and leaves no on-disk artifact. Closed in code; regression test `memfd_create_not_in_plain_allowlist` enforces the contract. |

### 2.2. Containment guarantees the kernel + Landlock provide

These are not red-team findings but the positive defense the sandbox
provides:

- **Memory cap.** Hard limit at `--sandbox-memory-max-bytes` via cgroup
  `memory.max` + `memory.swap.max=0`. OOM kills the entire cgroup
  atomically (`memory.oom.group=1`) so a partial OOM can't leave the
  child in a half-state. **Load-bearing requirement:** the child must
  run as a non-root UID (Phase G `--sandbox-child-uid`/`-gid` flags) —
  cgroup interface files are root-owned and only DAC keeps a
  compromised child from overwriting `memory.max` directly.
- **CPU cap.** Hard limit at `--sandbox-cpu-max-micros` per
  `--sandbox-cpu-period-micros` window via cgroup `cpu.max`. Same
  Phase G load-bearing requirement as the memory cap.
- **Process privilege.** Child drops to non-root in pre_exec
  (`setgroups(0,NULL)` + `setresgid` + `setresuid`) with
  `CAP_SYS_ADMIN`, `CAP_SETUID`, `CAP_SETGID`, `CAP_KILL` already
  removed from the bounding set. Reclaim via `setresuid(0,…)` returns
  EPERM (no `CAP_SETUID` in effective). Cross-UID `kill(2)` returns
  EPERM (no `CAP_KILL`). Operator paths under `--sandbox-rw-path` must
  be owned by `--sandbox-child-uid:--sandbox-child-gid` or the child
  cannot read/write them after the drop.
- **Filesystem scope.** Landlock denies *all* paths outside the union
  of `BASELINE_RO_PATHS` + `--sandbox-ro-path` + `--sandbox-rw-path` +
  the cgroup directory + cgroup root (with `RemoveDir`/`ReadDir` only,
  for `Drop for SandboxHandle` to rmdir the per-invocation cgroup
  tree on supervisor exit). Even root-owned files outside these are
  unreachable.
- **Filesystem mutation.** Within `--sandbox-rw-path`, the child can
  read/write/create/delete files. Phase H (2026-05-25) added a
  `MS_BIND | MS_NOEXEC` bind-remount on every `--sandbox-rw-path` at
  install time, so the kernel's mount layer rejects
  `mmap(PROT_EXEC, fd, …)` on any file under these paths — closes F05.
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

> **Phase H closures (2026-05-25).** F05 (file-backed mmap PROT_EXEC),
> F06 (anonymous mprotect W→X), and F-MEMFD (memfd-backed mmap
> PROT_EXEC) were the three in-sandbox shellcode lanes previously
> accepted-by-design as costs of running PolkaVM's JIT. Pinning the
> runtime executor to PolkaVM's interpreter backend retired the JIT;
> the corresponding seccomp + mount-layer carve-outs were then removed.
> All three now appear in §2 (closed). The architecture-level claim is:
> **interpreter-mode RostroVM has zero in-sandbox native code execution
> lanes.** Any future re-introduction of any of these carve-outs MUST
> be paired with a documented runtime-executor need and a counter-PoC.

### F-NEW-05 — `/proc/<sup_pid>/cmdline` is world-readable

The supervisor's own `cmdline` exposes the full launch invocation
verbatim — `--state-file <path>`, every `--sandbox-rw-path`, every
`--sandbox-ro-path`, `--sandbox-stdio-log <path>`, child-UID/GID, etc.
This is world-readable by Linux's DAC contract on `/proc/<pid>/cmdline`
(no `dumpable=0` restriction applies to that specific file).

**Why accepted:** the cmdline contents are also visible via `ps` to
any host user, and the supervisor's CLI argv is structural information,
not a secret. Documenting alongside the existing `environ` info-leak
in this section makes the threat model honest. The supervisor binary
itself, the canonical-files dir, and the chain-spec hashes are also
discoverable by any host user via `ps` / `/proc/*/status`.

**Implication:** treat the supervisor argv as observable to any local
user, including the sandboxed child (even before its Landlock kicks in,
since `/proc/<sup_pid>/cmdline` is in the BASELINE_RO set). Don't
embed secrets in supervisor argv; pass them via env or a file with
restrictive DAC.

### F-NEW-06 — Child raises its own `oom_score_adj`

The child can write any value in `[-1000, +1000]` to its own
`/proc/self/oom_score_adj`. Writing a high positive value biases the
kernel's host-wide OOM target *toward* the attacker's own cgroup,
which sounds benign — but in a multi-validator topology (or any
shared host) under genuine memory pressure, the attacker can make
their cgroup the *least* likely OOM victim by writing `-1000`,
re-targeting the kernel toward peer same-UID processes (lab
validators, the supervisor, other workload). cgroup `memory.oom.group=1`
makes the attacker's cgroup an atomic-kill target *under its own cap*,
but doesn't help under *host-wide* pressure.

**Why accepted:** the kernel permits a process to adjust its own
`oom_score_adj` by design — it's the documented hook for processes
to declare their own OOM disposability. Landlock doesn't gate procfs
writes (no path-policy equivalent for `/proc/self/*`). Closing this
would require either patching the kernel or having the supervisor
poll-and-reset every child's score, which races and adds attack
surface. The marginal-alone-but-dangerous-with-F-NEW-01 framing from
the 2026-05-25 pen-test stands; F-NEW-01 is closed (rlimits + cgroup
pre-bind window narrowed), and so this finding falls back to marginal.

**Implication:** on multi-tenant hosts, don't assume the OOM killer
will fairly distribute kills among gemini-node and other workload.

### F-NEW-08 — Localhost JSON-RPC reach to peer node

`socket(AF_INET, SOCK_STREAM)` + `connect(127.0.0.1:9944)` is allowed
by the seccomp filter (no arg-filter on TCP destination). On a host
running multiple validators bound to localhost RPC, a compromised
validator-A can connect to validator-B's RPC and call every
"safe-by-default" method — `system_chain`, `chain_getHeader`,
`chat_nodeInfo`, `author_submitExtrinsic` (this one is *safe* in
substrate's gating model, surprisingly), etc. `author_rotateKeys` /
`author_insertKey` are gated behind `--rpc-methods unsafe` which is
NOT set on lab nodes, so those remain unreachable.

**Why accepted:** outbound TCP is required for libp2p; arg-filtering
`connect(2)` on destination address would need to inspect a sockaddr
structure that seccomp can't reliably evaluate (TOCTOU on the
sockaddr pointer). Architectural fix would be one of:

- Switch RPC to a UNIX socket (Linux-only; breaks substrate's HTTP/WS
  defaults).
- Default substrate to `--rpc-bind 0.0.0.0` `bind(2)`-deny on the
  local interface unless `--rpc-listen` is passed.
- Per-validator network namespace (rules out cross-validator-on-same-
  host attacks; rules in PID-namespace machinery we've otherwise
  declined; see §3.1's PID-namespace rejection).

None of these is small; tracking for a separate decision.

**Implication:** on multi-validator hosts, treat localhost RPC as a
reachable side-channel from any sandboxed validator. The lab
documents this and the deployment playbook should consider a per-host
firewall rule blocking 127.0.0.1:9944 from non-supervisor UIDs (the
sandboxed child's UID is known + dedicated per F-NEW-03; an
nftables/iptables `--match owner --uid-owner !root` rule would close
the cross-process leg cleanly).

### F-NEW-09 — Stale `MS_NOEXEC` bind-mounts persist on supervisor exit

`Drop for SandboxHandle` cleans the per-invocation cgroup tree via
`unlinkat(AT_REMOVEDIR)` (the only-allowed rmdir-equivalent). It does
NOT `umount2(MNT_DETACH)` the noexec bind-mounts because `umount2(2)`
is not in `PLAIN_ALLOWED_SYSCALLS` — adding it would re-open
filesystem manipulation as a child-reachable syscall, defeating the
point of refusing `mount(2)` in the first place.

**Why accepted:** the bind-mounts are idempotent on re-install
(EBUSY-tolerant), so the operational impact is "first launch
bind-mounts; subsequent launches no-op the bind + idempotent remount
applies noexec." If an operator switches `--sandbox-rw-path`,
the old path's bind-mount remains until reboot or manual `umount`.
The leftover bind-mount is functionally a no-op against any non-Cannae
process (it just shadows the same inode set with `noexec`); the only
real cost is mount-table clutter visible in `mount | grep`.

**Implication:** operator-facing reliability gap, not security.
Document in deployment playbook: `mount | grep rostro` before each
deploy; manually `umount` retired RW-path binds if operator paths
have changed since the last supervisor run.

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

### Supervisor state-file write under Cannae

The supervisor process is itself sandboxed (same Landlock + seccomp
filter as the child). After Cannae install, the supervisor cannot
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

- Not a guarantee of soundness against unknown bugs. Cannae reduces
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

Last revised: 2026-05-25 (Phase G close — child UID drop +
CAP_KILL/SETUID/SETGID bounding-set drop closes
F-AGENT-C-01/03/05 + UID-reclaim; `Drop for SandboxHandle` via
`unlinkat(AT_REMOVEDIR)` plus Landlock REMOVE_DIR grant on cgroup
root closes F-AGENT-C-04 leak; F05 demoted to accepted-by-design —
Phase E's `LANDLOCK_ACCESS_FS_EXECUTE` deny gates `execve(2)` only,
not `mmap(PROT_EXEC)`).
