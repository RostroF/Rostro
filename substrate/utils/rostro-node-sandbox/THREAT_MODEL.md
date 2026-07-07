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
| F13 | `fchmod 0666 /etc/resolv.conf` via `/proc/self/fd/N` reopen | `fchmod` / `fchown` / `fchmodat` / `fchownat` silently shadowed to `ERRNO(0)` via `force_fchmod_family_silent_filter` (stacked seccomp; signed-min stacking gives ERRNO=0 over main filter's ALLOW). Attacker's `chmod 0666` succeeds at the syscall return path but the kernel performs no permission change — same security outcome as KILL_PROCESS, no remote-induced DoS. F-LAB-RT-01 (2026-05-25) drove the architecture: legitimate keystore `set_permissions(0o600)` hit the original denial and SIGSYS'd the child. `close_range(3, UINT_MAX)` in child pre_exec still eliminates inherited fds. |
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
| F-NEW-R2-01 | Operator passes `--sandbox-rlimit-as-bytes=0` thinking they're hardening; semantics actually mean "skip RLIMIT_AS" (inherited unlimited), re-opening F-NEW-01 host-burst | **F-NEW-R2 closure (2026-05-25):** parse-time refusal in supervisor `run()`. `Some(0)` no longer reaches the pre_exec wiring; the operator gets a clear error pointing at the right usage (omit the flag entirely OR pass a real byte ceiling). |
| F-NEW-R2-02 | Symlink planted at the default `<rw>/.gemini-node-stdio.log` → supervisor (root) opens the symlink target, hands fd 1/2 to child with attacker-chosen write target inside the RW path (RocksDB MANIFEST etc.) | **F-NEW-R2 closure (2026-05-25):** stdio-log open uses `OpenOptions::custom_flags(libc::O_NOFOLLOW)`. ELOOP on symlink. Any open error here is fail-stop (no fall-back to inherited stdio, which would silently re-open F-NEW-02). |
| F-NEW-R2-03 | Operator points `--sandbox-stdio-log` deep into an `--sandbox-rw-path` subtree (RocksDB WAL, etc.); supervisor opens it as root, child writes through inherited fd 1/2 → DB corruption | **F-NEW-R2 closure (2026-05-25):** new `validate_stdio_log_placement` runs before sandbox install. Permits the immediate-child default (`<rw>/.gemini-node-stdio.log`), any path outside every rw_path, or `/dev/null`. Deep RW subpaths fail-stop with an F-NEW-R2-03 error pointing at the corruption risk. Structurally identical to F15/F16 validation. |
| F-NEW-R2-04 | Operator passes `--sandbox-rw-path /etc` (or any top-level system dir); `install_noexec_remount` mounts `MS_BIND\|MS_NOEXEC` host-globally, breaking system services that exec from there | **F-NEW-R2 closure (2026-05-25):** new `validate_rw_paths_not_system_dirs` runs at parse time. Denylist refuses exact-match top-level system dirs (`/`, `/etc`, `/usr`, `/var`, `/tmp`, `/proc`, `/sys`, `/dev`, …); nested paths under those (e.g., `/var/lib/rostro`) remain valid. Path-normalization addendum (F-NEW-R3-03 closure 2026-05-25): trailing slashes, double slashes, `.` components are normalized away before the denylist compare; `..` components are refused outright. **Architectural follow-up** — the `unshare(CLONE_NEWNS)` fix that would contain the noexec to the supervisor's mount namespace remains tracked separately (UX tradeoff: operator debugging expects host-visible mounts). |
| F-NEW-R3-01 | Supervisor's own Landlock blocks state-file persist; `swap_count` + `crashes` degrade from per-deployment-lifetime caps to per-supervisor-lifetime, and an operator-triggered `systemctl restart` clears them | **F-NEW-R3 closure (2026-05-25)** + **F-NEW-R4-02 hardening (2026-05-25)**: structured `STATE_DELTA schema=1 swap_count=N crashes=[T1,T2,...]` lines emitted to supervisor stderr on every mutation. systemd's `ExecStart` forwards supervisor stderr → systemd-journald → `/var/log/journal/`, which sits outside Cannae's policy envelope and outside the child's DAC reach. Persist-failure log tightened from WARN → ERROR with operator-facing reconstruction command (`journalctl -u rostro-supervisor --output=cat \| grep '^STATE_DELTA' \| tail -1` — **anchored** per R4-02 to prevent child-injected `[child-stdio] STATE_DELTA …` lines from being matched). The pipe-relay reader substring-mangles any `STATE_DELTA` occurrence in child bytes to `STATE_DELTA_FROM_CHILD` (defense-in-depth for operators running ad-hoc un-anchored greps). Architectural follow-up — Landlock-child-only refactor — would restore disk persist but is a meaningful design change; deferred. |
| F-NEW-R3-02 | Child uses `ftruncate(fd, 0)` on the inherited stdio fd to wipe the supervisor's stdio log; kernel ftruncate checks `FMODE_WRITE` on the open fd, not the caller's permission on the inode | **F-NEW-R3 closure (2026-05-25):** supervisor no longer hands the child a file fd. Pipe-relay shape: supervisor creates a `pipe2(O_CLOEXEC)`, hands the write-end to the child as 1/2 via `Command::stdout/stderr`, and runs a per-spawn reader thread that reads from the read-end and forwards each line to (a) the in-sandbox mirror file (opened ONCE pre-Cannae with `chattr +a` — `FS_APPEND_FL` denies ftruncate/unlink-while-open at the inode layer; best-effort, tmpfs falls back to pipe-relay only) and (b) supervisor's own stderr with `[child-stdio] ` prefix (→ journald). `ftruncate(pipe, 0)` returns EINVAL — pipes have no size. Even if a future bypass gets the child a file fd, chattr +a refuses ftruncate at the inode layer. |
| F-NEW-R3-03 | `validate_rw_paths_not_system_dirs` exact-string match bypassable via non-canonical paths (`/etc/`, `//etc`, `/etc/.`, `/etc/foo/..`); kernel `mount(2)` resolves to the same dentry, host's `/etc` gets `MS_NOEXEC` bind-remounted | **F-NEW-R3 closure (2026-05-25):** new `normalize_path_for_denylist` runs before the denylist compare. Normalizes trailing slashes / double slashes / `.` components via `Path::components().collect()`. Refuses `..` components outright with an F-NEW-R3-03 error pointing at the bypass shape (`..` can't be statically resolved without filesystem traversal, especially under symlinks). Parameterized regression tests cover `/etc/`, `//etc`, `/etc/.`, `/etc/./`, `/etc/foo/..`, `/var/lib/rostro/../../etc`. |
| F-NEW-R4-01 | Operator passes `--sandbox-stdio-log /etc/sudoers.d/foo` (or `/etc/cron.d/*`, `/etc/profile.d/*.sh`, `/etc/ld.so.conf.d/*.conf`, `/etc/logrotate.d/*`, `/etc/systemd/*`, etc.); supervisor opens AS ROOT pre-Cannae and the pipe-relay reader appends child-controlled bytes verbatim. A compromised child emits attacker-controlled bytes that the host daemon parses as root on next invocation → root escalation. Surfaced by `/security-review` 2026-05-25. | **F-NEW-R4 closure (2026-05-25):** `validate_stdio_log_placement` extended with a tree-denylist (`path_is_under_stdio_system_prefix` against `STDIO_LOG_SYSTEM_PREFIX_DENYLIST` = `/etc`, `/usr`, `/bin`, `/sbin`, `/lib*`, `/boot`). Normalize the path first via `normalize_path_for_denylist` (R3-03 closure) so bypass-shapes like `/etc//sudoers.d/foo`, `/etc/./sudoers.d/foo` also catch. Stdio file open mode tightened from `0644` → `0600` so even if a future bypass lands the file in a daemon-scanned dir, non-root parsers can't read it. Permitted log targets: `/var/log/*`, `/srv/*`, `/opt/*`, `/tmp/*`, `/home/*`, `/dev/null`, or any path inside `--sandbox-rw-path`. 11 parameterized regression tests cover the denylist matrix + R3-03 bypass shapes. |
| F-NEW-R4-02 | A compromised child emits raw `STATE_DELTA schema=1 swap_count=0 crashes=[]` on its stdout. The pipe-relay reader prepends `[child-stdio] ` and forwards to journald. The R3-01 docstring's documented operator recovery `grep STATE_DELTA \| tail -1` is un-anchored substring match — accepts the child-injected line, defeats reconstruction. Surfaced by `/security-review` 2026-05-25. | **F-NEW-R4 closure (2026-05-25):** two layers. **(1)** Anchored grep — all docstring references updated to `grep '^STATE_DELTA' \| tail -1`. Supervisor's own emissions go to stderr at column 0 via `eprintln!`; child lines start with `[child-stdio] `, never at column 0. **(2)** Defense-in-depth substring mangling — new `sanitize_state_delta_for_relay` in `main.rs` replaces every `STATE_DELTA` substring in child bytes with `STATE_DELTA_FROM_CHILD` BEFORE writing to supervisor stderr. The in-sandbox mirror file gets the verbatim bytes (operator-local grep convenience). Even an operator running ad-hoc un-anchored grep, OR a future change that drops the `[child-stdio] ` prefix, gets non-confusable lines. 5 unit tests cover the sanitization matrix. |
| F-NEW-R4-FOLLOWUP-1 (host mount-NS containment) | `install_noexec_remount` previously mutated the HOST mount namespace, so any `--sandbox-rw-path` got a host-visible `MS_BIND \| MS_NOEXEC` remount. R2-04 + R3-03 denylists caught the worst operator-misconfig cases, but supply-chain compromise of `landlock` / `seccompiler` between cgroup-install and seccomp-install could have called `mount(MS_BIND \| MS_NOEXEC, "/")` host-globally. The 2026-05-25 audit empirically verified the host-visibility was live (WSL `/etc` was actually remounted). | **F-NEW-R4 closure (2026-05-25):** new `install_mount_ns` runs FIRST in the install sequence (cgroup → mount-NS → noexec → Landlock → seccomp). Calls `unshare(CLONE_NEWNS)` to give supervisor + descendants a private mount namespace, then `mount(NULL, "/", NULL, MS_REC\|MS_PRIVATE, NULL)` to disable upward mount-event propagation. Subsequent bind-remounts stay contained — the host's `/proc/self/mountinfo` shows no Cannae mounts. Diagnostic `ROSTRO_SKIP_MOUNT_NS=1` available **only in a `--features sandbox-diagnostics` build** (see §2.3; compiled out of canonical binaries). R2-04 + R3-03 demote to defense-in-depth. Operator UX caveat: `mount \| grep` on the host no longer shows Cannae mounts; use `nsenter -t <sup_pid> -m mount` to inspect from inside the NS. Empirically verified live: bind-remounted path NOT in host mount table after the fix. |
| F-NEW-R4-FOLLOWUP-3 (cross-validator localhost RPC reach — lab-side stopgap) | Documented as `F-NEW-08` residual in earlier rounds: compromised validator-A on the same host as validator-B can `connect(127.0.0.1:9944)` to validator-B's RPC and call every "safe-by-default" method. Phase G's CAP_KILL drop closes cross-UID signal but not cross-UID localhost TCP. | **F-NEW-R4 closure (2026-05-25) — REPLACED by F-LAB-RT-03 (2026-05-26).** The original closure used `meta skuid != $CHILD_UID iif "lo" tcp dport $RPC_PORT drop` on the netfilter input hook. F-LAB-RT-03 found this is a no-op: `meta skuid` on input matches the SERVER socket's owner UID (the gemini-node's own UID), NOT the client's UID. Every connection to that socket therefore matched the accept rule; the drop rule never fired. Empirically confirmed: uid=1000 → 127.0.0.1:9944 → HTTP 200. See F-LAB-RT-03 row below for the working rule. |
| F-LAB-RT-04 (jsonrpsee/soketto accepts unmasked client WebSocket frames) | RFC 6455 §5.1 violation: a WebSocket server MUST close the connection upon receiving an unmasked frame from the client. Upstream soketto 0.8.0 (jsonrpsee 0.24.10's WS dependency) silently accepts unmasked frames — the mask bit is parsed at `base.rs:416` but never enforced on the receive path. Sovereign-chain principle ([[feedback_sovereign_chain_vendored_is_ours]]): a CVE/RFC-violation in a crate Rostro ships is OUR issue, not upstream's. | **F-LAB-RT-04 closure (2026-05-26):** vendored soketto 0.8.0 into `substrate/external/soketto/`; patched `Receiver::receive` in `connection.rs:222-242` to check `self.mode.is_server() && !header.is_masked()` immediately after `receive_header()` and return new `Error::UnmaskedClientFrame` variant. Restores symmetry with the existing sender-side check that enforces client-frame masking. `[patch.crates-io]` entry in workspace Cargo.toml routes all downstream consumers (jsonrpsee-server, etc.) to the patched copy. Two new regression tests pin the behavior: `server_rejects_unmasked_client_frame` (RFC-violating bytes → Error::UnmaskedClientFrame), `server_accepts_masked_client_frame` (RFC-conforming bytes → Ok). Patched site carries `Rostro: F-LAB-RT-04 closure` comment so the next upstream-merge audit can locate + re-apply. |
| F-LAB-RT-05 (hyper accepts requests with both Transfer-Encoding AND Content-Length) | RFC 7230 §3.3.3 rule 3 violation: a message with both `Transfer-Encoding` and `Content-Length` headers "ought to be handled as an error" — the classic HTTP request-smuggling primitive when a fronting proxy uses CL and a backend uses TE (or vice versa), allowing an attacker to smuggle one request inside another. Upstream hyper 1.6.0 silently prefers TE and drops CL via an `if is_te { continue }` short-circuit in `proto/h1/role.rs`. Sovereign-chain principle applies. | **F-LAB-RT-05 closure (2026-05-26):** vendored hyper 1.6.0 into `substrate/external/hyper/`; patched `Server::parse` header-loop in `proto/h1/role.rs:255-310` to reject hard with `Parse::content_length_invalid()` (which maps to 400 Bad Request) when both headers are present. Symmetric check: TE-arm rejects if `con_len.is_some()`; CL-arm rejects if `is_te`. Three existing upstream tests in `test_decoder_request` were codifying the vulnerable behavior (asserting TE silently wins over CL); flipped from `assert_eq!(parse(...).decode, CHUNKED)` to `parse_err(...)` so the regression coverage now confirms rejection. Patched sites carry `Rostro: F-LAB-RT-05 closure` comments. |
| F-LAB-RT-03 (nftables `meta skuid` no-op + cgroup naming PID-dependent) | Two-part architectural finding from 2026-05-25 pen-test, closed together. **(a)** The F-NEW-08 closure's `meta skuid` rule never gated anything because it matched the server side. **(b)** Even with a corrected rule, the sandbox crate named the cgroup `rostro-node-<pid>/child` — PID-dependent, so any nftables rule keyed on the cgroup name had to be re-installed on every supervisor restart, leaving a race window where the gate was open. | **F-LAB-RT-03 closure (2026-05-26):** **(a)** Sandbox crate (`src/linux.rs`) now names the cgroup `rostro-node-uid-<uid>/child` when `--sandbox-child-uid` is set, falling back to PID-based naming only for tests. New `child_uid` field on `NodeSandboxConfig`; supervisor's `build_sandbox_config` threads `args.sandbox_child_uid` through. Stable across restarts. **(b)** Wrapper installs nftables on the OUTPUT hook (not INPUT — input-side cgroup match has murky semantics around SYN handshake): `oif "lo" socket cgroupv2 level 1 "rostro-node-uid-<uid>" tcp dport $RPC_PORT accept; oif "lo" tcp dport $RPC_PORT drop`. Uses `socket cgroupv2` (the cgroup-v2-path-aware expression in nftables ≥0.9.5 / kernel ≥5.6) — NOT `meta cgroupv2` which doesn't exist (the meta family only has `meta cgroup` for v1 net_cls classid). On OUTPUT, `socket cgroupv2` resolves the cgroup of the socket associated with the packet, which is unambiguously the connecting (client) process. Cross-host TCP unaffected — the `oif "lo"` qualifier pins scope to same-host loopback. Wrapper pre-creates the cgroup parent dir BEFORE the nft install (the kernel returns ENOENT at rule-install time if the path doesn't exist yet); the supervisor's `install_cgroup` then reuses the existing parent and creates `/child` under it (idempotent). Per-host stopgap; per-validator netns remains the architectural fix and is documented as deferred (significant libp2p discovery cost). Three new sandbox regression tests: `install_cgroup_uses_stable_uid_name_when_child_uid_set`, `install_cgroup_is_idempotent_for_stable_uid_name` (restart-survives), and the existing PID-fallback path remains tested. Live verification 2026-05-26: uid=1000 → 127.0.0.1:9944 → TimeoutError (was HTTP 200 pre-fix); chain finalizes at #1759 across all 3 nodes with normal 2-block lag. |
| F-NEW-R4-V2 (pipe-relay unbounded line) | Compromised child writes a single multi-GiB line (no newline) to stdout. `BufReader::read_until(b'\n', ...)` in the pipe-relay reader thread grows `buf` unboundedly, driving supervisor RSS up until host OOM killer fires. Surfaced by 2026-05-25 audit. | **F-NEW-R4 closure (2026-05-25):** new `bounded_read_until_newline` caps per-line at `MAX_RELAY_LINE_BYTES` (64 KiB). On cap-hit, appends `[cannae: line truncated]\n` marker + returns. Pipe-relay reader factored into `relay_reader_body` for testability + `catch_unwind` support. 4 unit tests cover short-line, truncation-at-cap, EOF-without-newline, empty-input cases. |
| F-NEW-R4-V3 (pipe-relay reader thread panic isolation) | Reader thread panic (today or under a future change) leaves the supervisor running with a defunct relay; child blocks on a full pipe; block production stops without forensics or supervisor restart. Surfaced by 2026-05-25 audit. | **F-NEW-R4 closure (2026-05-25):** reader-thread body wrapped in `std::panic::catch_unwind` + on panic the supervisor calls `std::process::exit(2)` (loud failure → systemd ExecStart restart vs. silent hang). Pre-panic panic-payload extraction logs the panic message to stderr (→ journald). |
| F-NEW-R4-V5 (`--state-file` ↔ `--sandbox-stdio-log` path collision) | Operator passes the same path for both flags. Supervisor opens stdio O_APPEND for lifetime AND uses `save_atomic` (`write .tmp + rename`) for state — the rename atomically replaces the open stdio fd's inode with the state file's inode, orphaning the stdio writes and overwriting operator-visible content. Forensics broken silently. Surfaced by 2026-05-25 audit. | **F-NEW-R4 closure (2026-05-25):** new `validate_state_and_stdio_disjoint` runs at parse time. Normalizes both paths via `normalize_path_for_denylist` (R3-03 closure) so trailing-slash / dot-component / double-slash variants are caught. Refuses with F-NEW-R4-V5 error. Symmetric with the F15/F16 overlap-rejection family. 5 unit tests (None+None, distinct, exact collision, normalized collision, R3-03-dotdot-refusal). |
| F-NEW-R4-V8 (state.tmp open without O_NOFOLLOW) | `SupervisorState::save_atomic` used `std::fs::write` (no `O_NOFOLLOW`). A local non-root attacker with write access to the state-file directory (operator misconfig — `chmod 777`) plants `<state-file>.tmp → /etc/passwd`; supervisor (root) clobbers `/etc/passwd` with serialized state content. Surfaced by 2026-05-25 audit. | **F-NEW-R4 closure (2026-05-25):** `save_atomic` now uses explicit `OpenOptions::new().create(true).write(true).truncate(true).custom_flags(libc::O_NOFOLLOW).mode(0o600).open(&tmp)`. ELOOP on symlink. Symmetric with the stdio mirror file's R2-02 open. Empirically verified live: planted symlink → ELOOP → state-file persist failed with `Too many levels of symbolic links (os error 40)`; symlink target NOT clobbered; STATE_DELTA still emits to journald via R3-01 fallback. |
| F-NEW-R4-01b (stdio-log denylist asymmetric with kernel-interface trees) | Follow-on `/security-review` 2026-05-25 found `STDIO_LOG_SYSTEM_PREFIX_DENYLIST` covered `/etc /usr /bin /sbin /lib* /boot` but omitted `/proc /sys /dev /run` — asymmetric with `SYSTEM_TOPLEVEL_DENYLIST` (which already listed all four). Operator passes `--sandbox-stdio-log /proc/sys/kernel/core_pattern` (or `/proc/sys/kernel/modprobe`, `/proc/sys/kernel/hotplug`, `/sys/kernel/uevent_helper`, `/proc/sysrq-trigger`, `/run/systemd/system/*.conf`, `/run/sudo/ts/*`, …); supervisor opens AS ROOT with `O_APPEND \| O_NOFOLLOW, mode 0600` — `O_NOFOLLOW` does NOT block real procfs/sysfs files, `mode 0600` is a no-op on existing virtual-fs nodes, `O_APPEND` is irrelevant for sysctl-shaped files where every write goes to offset 0. The per-spawn pipe-relay reader appends child-controlled bytes verbatim to the file leg (STATE_DELTA sanitizer is journald-leg-only). A compromised child emits `\|/tmp/pwn.sh\n` on stdout → kernel executes `/tmp/pwn.sh` AS ROOT on next crash / autoload / uevent — full sandbox escape. SHARPER than the R4-01 `/etc/*` family because no daemon-parser indirection — the kernel itself executes the bytes. | **F-NEW-R4 closure (2026-05-25):** `STDIO_LOG_SYSTEM_PREFIX_DENYLIST` extended with `/proc`, `/sys`, `/dev`, `/run` (now 13 entries, symmetric with `SYSTEM_TOPLEVEL_DENYLIST` coverage of kernel-interface trees). `/dev/null` short-circuits at the top of `validate_stdio_log_placement` (line ~380) BEFORE the denylist check, so the legitimate operator-discard target still works. Normalization via `normalize_path_for_denylist` (R3-03 closure) catches bypass shapes like `/proc//sys/kernel/core_pattern`, `/sys/./kernel/uevent_helper`, `/var/log/../proc/sys/kernel/core_pattern`. 8 new parameterized regression tests cover: `core_pattern`, `modprobe`, `sysrq-trigger`, `uevent_helper`, `/proc/sys/*` + `/sys/*` matrix, `/dev/{sda,mem,kmsg,random}` (with `/dev/null` sanity check), `/run/systemd/system/*` + `/run/sudo/ts/*` + `/run/cron.d/*`, R3-03 bypass-shape interactions against the new entries. Total: 25 stdio_log_placement tests, 108 supervisor tests pass. |

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
- **No privilege regain via exec.** `PR_SET_NO_NEW_PRIVS` is set
  unconditionally at the top of `install()` (item 4b, 2026-07-07),
  independent of whether Landlock/seccomp run. No `execve` after that
  point — including the child's exec of gemini-node or any setuid binary
  reachable on an RO path — can gain privilege via setuid/setgid bits or
  file capabilities. Monotone and inherited across fork+exec.
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
  The Landlock ruleset is built at ABI v3 (item 2, 2026-07-07; floor is
  kernel 6.6 / ABI v3, `BestEffort` degrades below): `Truncate` is granted
  on RW paths but withheld from RO paths, so a writable-inode fd obtained
  by reopening an RO-path file via `/proc/self/fd/N` can no longer be
  `ftruncate`d (the RO-reopen leg of F13 — see §4). `Refer` is likewise
  RW-only, so cross-directory rename/link out of an RO path is denied.
- **Syscall surface.** ~60 specific syscalls allowed; everything else
  is `SIGKILL` via `SECCOMP_RET_KILL_PROCESS`. Argument-filtered for
  `mmap`, `mprotect`, `clone`, `clone3` (via stacked ENOSYS),
  `socket`, `setsockopt`, `prctl`, `prlimit64`, `ioctl`. **x86_64 only**:
  on any other arch a canonical build has no allowlist and `install_seccomp`
  fails closed — `install()` aborts and the supervisor exits rather than
  run without the filter (item 4a, 2026-07-07). The deliberate
  run-unfiltered path is `--unsafe-skip-sandbox`, never a silent default.
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

### 2.3. Build-integrity guarantees (no diagnostic downgrade surface)

The layer-skip env vars (`ROSTRO_SKIP_MOUNT_NS`, `ROSTRO_SKIP_NOEXEC`,
`ROSTRO_SKIP_LANDLOCK`, `ROSTRO_SKIP_SECCOMP`) and the
`ROSTRO_SECCOMP_ACTION=log` (log-and-**allow**, non-enforcing) seccomp
mode are Phase-5 diagnostics that would let whoever controls the
supervisor's launch environment weaken or disable a layer at start-up —
not a compromised-child escape, but a launch-time downgrade surface.

As of 2026-07-06 they live behind the crate's `sandbox-diagnostics`
Cargo feature, which is **off** in the canonical feature set
(`default = []`):

- In a canonical build the skip helper compiles to a constant `false`
  (the env vars are never read; every layer is unconditionally
  installed) and `seccomp_default_action` returns `KillProcess`
  unconditionally — the `Log` action does not exist in the compiled
  binary. There is no runtime input that downgrades the envelope.
- Building with `--features sandbox-diagnostics` changes the compiled
  output and therefore the binary hash. Such a binary no longer matches
  the on-chain canonical-files registry, so the canonical-files gate
  quarantines the node until self-heal restores the canonical build.

This makes "no diagnostic escape hatch on a networked validator" a
consensus-enforced property rather than an operator-discipline one:
enabling a hatch is a build-output change the network detects, not an
env var an operator might set unnoticed. Diagnostics are for a
hand-built, non-networked lab box only. Regression test
`seccomp_default_action_is_always_kill_in_canonical_build` pins the
canonical-build behavior.

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

The fchmod family is silent-shadowed to `ERRNO(0)` (see §2.1 F13 row
and the `force_fchmod_family_silent_filter` rationale in `src/linux.rs`),
so an attacker's `fchmod(fd, 0666)` succeeds at the syscall ABI but
performs no actual permission flip. `ftruncate(2)` itself remains
allowed because RocksDB needs it.

The silent-shadow trade-off: legitimate code that calls `fchmod` for
correctness (rc-keystore's `set_permissions(0o600)` is the canonical
case) also gets the no-op. Files end up with their `O_CREAT` default
mode (`0o600` if the operator process has `umask 077`, `0o644`
otherwise). Mitigations: the rc-keystore RW path is Landlock-restricted
to the dedicated role UID plus supervisor root; operator deploys
should set `umask 077` so newly-created files inherit restrictive
modes by default. F-NEW-R4-V8's `O_NOFOLLOW` close on the state-file
write path remains independent of this layer.

RO-reopen leg closed (item 2, 2026-07-07). The Landlock ruleset now
handles `Truncate` at ABI v3 and grants it only on RW paths, so an
attacker who reopens an RO-path inode as writable via `/proc/self/fd/N`
gets EACCES on `ftruncate` — the trick that let `fchmod`-style reopen
attacks reach truncate on a read-only file no longer works.

What remains: `ftruncate` on a file that is genuinely inside
`--sandbox-rw-path` (e.g. `/opt/rostro/data` — validator state, keystore,
ParityDB). Landlock grants `Truncate` there because ParityDB legitimately
truncates its own files, and there is no way to distinguish the node's
truncate from an attacker's within the same inode set. This is consistent
with the threat model: the attacker can already write to those paths, so
truncating them adds no privilege; it's just destruction within reach.
Treated as in-scope vandalism, not escalation.

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

Last revised: 2026-07-07 (hardening round 2: (item 2) Landlock ruleset
raised from ABI v1 to v3 — `Truncate` + `Refer` now RW-only, closing the
RO-reopen leg of the F13 ftruncate residual (§4); network gating (v4)
deliberately NOT used, F-NEW-08 stays on the address-aware nftables
stopgap since Landlock net rules are port-keyed. (item 4a) non-x86_64
`install_seccomp` now fails closed in canonical builds instead of running
without a syscall filter; also fixed a latent bug where the crate did not
compile on non-x86_64 Linux at all (`install_noexec_remount` lacked a
non-x86 stub). (item 4b) `PR_SET_NO_NEW_PRIVS` set unconditionally at
`install()` entry, independent of Landlock/seccomp.)

Prior revision: 2026-07-06 (§2.3 added — the diagnostic escape hatches
(`ROSTRO_SKIP_*` layer skips + `ROSTRO_SECCOMP_ACTION=log`) moved behind
the `sandbox-diagnostics` Cargo feature, off in the canonical
`default = []` set. Canonical builds compile the hatches out entirely, so
enabling one changes the binary hash and the canonical-files gate
quarantines the node. Turns "no downgrade surface on a networked
validator" into a consensus-enforced property).

Prior revision: 2026-05-26 (F-LAB-RT-04 + F-LAB-RT-05 close — vendored
soketto 0.8.0 + hyper 1.6.0 into `substrate/external/` with surgical
RFC-compliance patches. soketto's `Receiver::receive` now enforces
RFC 6455 §5.1 server-side mask check; hyper's request parser now
rejects RFC 7230 §3.3.3 TE+CL smuggling primitive with 400 Bad
Request. Sovereign-chain principle: vulnerabilities in third-party
crates we ship are OURS to fix, not upstream's. Re-apply patches on
every upstream merge — each site carries `Rostro: F-LAB-RT-NN closure`
comment for locating).

Prior revision: 2026-05-26 (F-LAB-RT-03 close — stable per-role cgroup
naming `rostro-node-uid-<uid>` in the sandbox crate + corrected
nftables OUTPUT-hook rule `socket cgroupv2 level 1` in the wrapper
replaces the F-NEW-08 stopgap which had been verified as a no-op during
the pen-test. `meta skuid` on the netfilter input hook matches the
server socket's owner UID not the client's — the original rule accepted
every local connection; the corrected OUTPUT-hook rule keys on the
client process's cgroup at level 1 which is unambiguous on the
connect path).

Prior revision: 2026-05-25 (F-LAB-RT-01 close — fchmod-family silent-
shadow filter replaces outright denial; legitimate keystore
`set_permissions(0o600)` no longer SIGSYS'es the child, F13's
`/proc/self/fd/N` bypass still defeated by ERRNO=0 no-op. Supervisor
`classify_exit` now distinguishes SIGSYS / SIGKILL / SIGSEGV / SIGABRT
/ SIGTERM so future seccomp policy gaps surface in operator logs with
an audit-log pointer instead of generic "signal kill").
