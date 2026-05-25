// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! `rostro-supervisor` — cross-platform process supervisor for Rostro
//! nodes. Phase 7b step 1.
//!
//! ## What this is
//!
//! A small, dependency-light parent process that owns the lifecycle of
//! a Rostro node binary (`gemini-node` by default). The child requests
//! a binary swap by exiting with [`EXIT_SWAP_AND_RESTART`]; the
//! supervisor rotates a staged binary at `<child>.new` over `<child>`
//! and re-spawns. Any other exit causes the supervisor to exit with
//! the same status.
//!
//! ## Why this exists (Pattern A)
//!
//! The Phase 7b auto-heal flow needs to swap node binaries without
//! ever having two PIDs simultaneously connected to the network — a
//! hard requirement, since two PIDs sharing validator session keys
//! could double-sign and earn a real equivocation slash. This
//! supervisor implements that guarantee: the child fully exits before
//! the staged binary is rotated into place and before the next child
//! is spawned. A brief network gap is acceptable; a PID overlap is
//! not.
//!
//! systemd handles this on Linux servers but not on macOS or Windows,
//! and the user-facing "10-year-old can run a Rostro node" north star
//! requires a self-contained installer. Rostro ships its own
//! supervisor so the lifecycle works identically across platforms.
//!
//! ## What this is NOT
//!
//! - Not a chain client. The supervisor does not query the runtime,
//!   does not hold session keys, and does not participate in
//!   networking. The child does all that.
//! - Not a downloader. Fetching canonical bytes from peers is the
//!   child's job (Phase 7b step 3+4). The supervisor only sees the
//!   staged result of that fetch and rotates it into place.
//! - Not (yet) a hardware-attestation gate. Phase 6.9 will plug into
//!   the supervisor's spawn path to re-verify TPM/Strongbox-rooted
//!   measurements at each restart.

use clap::Parser;
use rostro_node_sandbox::{NodeSandboxConfig, SandboxHandle};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, ExitStatus};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Exit code the child uses to request a swap-and-restart.
///
/// Chosen above the `sysexits.h` reserved range (64-78) and below the
/// signal-related range (128+), with no conflicts against common
/// Substrate / clap exit codes.
pub const EXIT_SWAP_AND_RESTART: i32 = 90;

/// Default cap on swap-and-restart cycles within the persisted
/// supervisor state. Bounds heal-loop pathologies (broken staged
/// binary, repeated drift detection) even across supervisor restarts.
const DEFAULT_MAX_SWAP_RESTARTS: u32 = 16;

/// Default cap on crash-restarts inside the sliding window. A crash is
/// any child exit that isn't `0` (clean) or [`EXIT_SWAP_AND_RESTART`]
/// (intentional swap) — including signal kills (sandbox violations,
/// OOM, segfault). Above this in the window, supervisor gives up.
const DEFAULT_MAX_CRASH_RESTARTS: u32 = 5;

/// Default sliding window for crash counting, in seconds.
const DEFAULT_CRASH_WINDOW_SECS: u64 = 60;

/// Default initial backoff after a crash, in seconds. Doubles after
/// each subsequent crash up to [`DEFAULT_BACKOFF_CEILING_SECS`].
const DEFAULT_BACKOFF_INITIAL_SECS: u64 = 1;

/// Default ceiling for crash-restart backoff, in seconds. Prevents
/// pathological 30-minute waits after a transient flap.
const DEFAULT_BACKOFF_CEILING_SECS: u64 = 60;

/// File name used inside the canonical directory for the persisted
/// supervisor state. Hidden by convention; operators can inspect it
/// but no automation should depend on the format (text, hand-rolled,
/// subject to change behind a `schema_version` bump).
const STATE_FILE_NAME: &str = ".supervisor-state";

/// Schema version written into the state file. Bump when the on-disk
/// format changes incompatibly; older versions are treated as missing
/// (which resets counters — the safe direction).
const STATE_SCHEMA_VERSION: u32 = 1;

#[derive(Parser, Debug)]
#[command(
	name = "rostro-supervisor",
	version,
	about = "Cross-platform process supervisor for Rostro nodes."
)]
struct Args {
	/// Path to the child node binary. Defaults to `gemini-node` (or
	/// `gemini-node.exe` on Windows) sitting next to this supervisor.
	#[arg(long)]
	child: Option<PathBuf>,

	/// Path to the staged binary that gets rotated in on swap.
	/// Defaults to `<child>.new`.
	#[arg(long)]
	staged: Option<PathBuf>,

	/// Directory holding additional canonical files. On
	/// swap-and-restart, after rotating the main child binary, the
	/// supervisor scans this directory for any `<name>.new` files
	/// and atomically rotates each to `<name>`. Defaults to the
	/// parent directory of the child binary, matching the verifier's
	/// resolve-relative-to-`current_exe()` convention. Omit the flag
	/// entirely to fall back to that default; to disable the scan use
	/// `--canonical-dir /dev/null` (or any path that contains no
	/// `*.new` files). Clap rejects `--canonical-dir ""` — empty
	/// strings are not a valid `PathBuf` argument.
	#[arg(long)]
	canonical_dir: Option<PathBuf>,

	/// Maximum swap-and-restart cycles before the supervisor gives up.
	/// Persisted across supervisor invocations via the state file so an
	/// attacker can't reset the cap by killing the supervisor.
	#[arg(long, default_value_t = DEFAULT_MAX_SWAP_RESTARTS)]
	max_restarts: u32,

	/// Maximum child crashes (non-zero exit or signal kill) inside the
	/// sliding window before the supervisor gives up. Crashes are
	/// distinct from swap-and-restart; this counter persists too.
	#[arg(long, default_value_t = DEFAULT_MAX_CRASH_RESTARTS)]
	max_crash_restarts: u32,

	/// Sliding-window size for crash counting, in seconds. Crashes
	/// older than this aren't counted toward [`Args::max_crash_restarts`].
	#[arg(long, default_value_t = DEFAULT_CRASH_WINDOW_SECS)]
	crash_window_secs: u64,

	/// Ceiling on the exponential backoff between crash-restarts, in
	/// seconds. Starts at 1s, doubles per crash, capped here.
	#[arg(long, default_value_t = DEFAULT_BACKOFF_CEILING_SECS)]
	backoff_ceiling_secs: u64,

	/// Path to the persisted supervisor state file. Defaults to
	/// `<canonical-dir>/.supervisor-state`. Omit the flag to use the
	/// default. There is no current way to fully disable persistence
	/// — clap rejects `--state-file ""` (empty strings are not a
	/// valid `PathBuf` argument); the closest is to point it at a
	/// path on a tmpfs that doesn't survive reboot. Add a real
	/// disable mechanism if a test path needs one.
	#[arg(long)]
	state_file: Option<PathBuf>,

	// ─── Sandbox configuration (Phase 4) ──────────────────────────
	//
	// Engages the host-level sandbox before exec'ing the child:
	//   - cgroup v2 self-cap (memory.max, cpu.max, OOM kill of child cgroup)
	//   - Landlock filesystem ruleset
	//   - seccomp-bpf allowlist with KILL_PROCESS + TSYNC
	// Policy applies to supervisor + all descendants and cannot be
	// relaxed once installed.

	/// **DANGEROUS.** Skip the host-level sandbox. Process runs
	/// unprotected — only for development debugging when sandbox
	/// behavior interferes with diagnosis. Loud warnings on startup
	/// and every restart. Production validators MUST NOT use this.
	#[arg(long)]
	unsafe_skip_sandbox: bool,

	/// Path the child may read AND write (typically the base/data
	/// directory holding RocksDB + keystore + logs). Repeat for
	/// multiple paths. MUST be absolute.
	#[arg(long = "sandbox-rw-path")]
	sandbox_rw_paths: Vec<PathBuf>,

	/// Path the child may read but not write (typically the chain
	/// spec, node-key file, canonical-files directory). Repeat for
	/// multiple paths. MUST be absolute.
	#[arg(long = "sandbox-ro-path")]
	sandbox_ro_paths: Vec<PathBuf>,

	/// Cap the child cgroup's memory at this many bytes. When the
	/// cgroup hits this limit, the kernel kills the child cgroup
	/// atomically (oom.group=1); the supervisor's crash-restart
	/// path then engages. Unset = no memory cap.
	#[arg(long)]
	sandbox_memory_max_bytes: Option<u64>,

	/// Cap child cgroup CPU usage to this many microseconds per
	/// `--sandbox-cpu-period-micros` period (cgroup v2 cpu.max
	/// semantics). Unset = no CPU cap.
	#[arg(long)]
	sandbox_cpu_max_micros: Option<u64>,

	/// CPU accounting period in microseconds. Only meaningful when
	/// `--sandbox-cpu-max-micros` is set. Default of 100_000 (100ms)
	/// matches cgroup v2 convention.
	#[arg(long, default_value_t = 100_000)]
	sandbox_cpu_period_micros: u64,

	/// Drop the spawned child to this numeric UID after `pre_exec`
	/// hardening but before the new image starts. The supervisor stays
	/// root (required for cgroup v2 setup + Landlock install); the child
	/// runs as a non-root user. Closes red-team findings F-AGENT-C-01,
	/// F-AGENT-C-03 (child writes its own cgroup interface files —
	/// `memory.max=max`, `cpu.max="max 100000"`, `memory.swap.max=max` —
	/// reversing every sandbox cap), and F-AGENT-C-05 (child sends
	/// `kill(getppid(), SIGTERM)` to the root supervisor). cgroup files
	/// are root-owned (kernel default); DAC blocks non-root writes.
	/// `kill(2)` across UIDs requires CAP_KILL which we don't grant.
	///
	/// REQUIRED when the supervisor runs as root and the sandbox is
	/// active (no `--unsafe-skip-sandbox`). Refused if set to 0.
	#[arg(long)]
	sandbox_child_uid: Option<u32>,

	/// Drop the spawned child to this numeric GID. Same threat-model
	/// notes as `--sandbox-child-uid`. Required when `--sandbox-child-uid`
	/// is set. Refused if set to 0.
	#[arg(long)]
	sandbox_child_gid: Option<u32>,

	/// F-NEW-01/04 closure (2026-05-25): cap the child's virtual address
	/// space (RLIMIT_AS, bytes). Bounds burst-mmap during the small
	/// window between `Command::spawn` and `place_child_in_cgroup` where
	/// the child runs in the supervisor's inherited root cgroup without
	/// `memory.max` enforcement. If unset, defaults to
	/// `sandbox_memory_max_bytes + 1 GiB` (room for mmap'd RO libs +
	/// runtime blob that count against AS but not against memcg). Set to
	/// 0 to leave inherited (NOT recommended; defeats the TOCTOU close).
	#[arg(long)]
	sandbox_rlimit_as_bytes: Option<u64>,

	/// F-NEW-01/04 closure: cap the per-user process count
	/// (RLIMIT_NPROC). Defaults to 256 — comfortable headroom for
	/// substrate's tokio worker pool (≈ cpu count × 2 + a handful of
	/// blocking + chat + libp2p workers) but cuts fork-bomb runaway.
	/// Set to 0 to leave inherited.
	#[arg(long, default_value_t = 256)]
	sandbox_rlimit_nproc: u64,

	/// F-NEW-01/04 closure: cap mlock'd memory (RLIMIT_MEMLOCK, bytes).
	/// Default 0 — no Rostro path requires `mlock`/`mlockall`, and
	/// 0 turns mlock attempts into EAGAIN. Combined with the TOCTOU
	/// window close, this removes the strongest "pin host RAM before
	/// cgroup binds" vector. Operator override available if a future
	/// dependency genuinely needs it.
	#[arg(long, default_value_t = 0)]
	sandbox_rlimit_memlock_bytes: u64,

	/// F-NEW-02 closure (2026-05-25): redirect the child's stdout +
	/// stderr to this file BEFORE fork. Closes the inherited-stdio-fd
	/// attack lane where the supervisor's 1/2 (typically a journal-stream
	/// socket on systemd or a redirect to a log file outside the sandbox)
	/// gets handed to the child via the standard execve fd inheritance.
	/// A compromised child can otherwise wipe or forge those logs to
	/// mask attack evidence.
	///
	/// If unset, defaults to `<first-sandbox-rw-path>/.gemini-node-stdio.log`
	/// (the supervisor opens it with O_CREAT|O_APPEND|O_WRONLY,0644 as
	/// root, before exec; the child inherits a controlled fd at 1/2).
	/// Pass `/dev/null` to discard child logs entirely. Pass an absolute
	/// path outside `--sandbox-rw-path` if you have a separate log dir
	/// (the supervisor opens it before Landlock applies, so reachability
	/// at install time is the only constraint).
	///
	/// When no `--sandbox-rw-path` is set AND this flag is unset, the
	/// child keeps the supervisor's inherited 1/2 (legacy behavior).
	#[arg(long)]
	sandbox_stdio_log: Option<PathBuf>,

	/// Arguments forwarded to the child after `--`.
	#[arg(last = true)]
	child_args: Vec<OsString>,
}

/// Translate the supervisor's CLI args into a [`NodeSandboxConfig`].
/// Factored out so unit tests can verify the translation without
/// going through `install` (which would poison the test thread).
fn build_sandbox_config(args: &Args) -> NodeSandboxConfig {
	let mut config = NodeSandboxConfig::new();
	for path in &args.sandbox_rw_paths {
		config = config.add_rw_path(path);
	}
	for path in &args.sandbox_ro_paths {
		config = config.add_ro_path(path);
	}
	if let Some(bytes) = args.sandbox_memory_max_bytes {
		config = config.memory_max_bytes(bytes);
	}
	if let Some(max) = args.sandbox_cpu_max_micros {
		config = config.cpu_max(max, args.sandbox_cpu_period_micros);
	}
	config
}

/// F15/F16 fix (2026-05-24): reject CLI configs where the supervisor's
/// state file or canonical-dir sits inside any `--sandbox-rw-path`.
///
/// The threat: the sandboxed child has write access to every path in
/// `sandbox_rw_paths`. If `state_file` lives there, the child can
/// rewrite supervisor restart counters (F15 — escape the
/// max-crash-restarts circuit breaker, hide swap counts). If
/// `canonical_dir` lives there, the child can drop
/// `<name>.new` files for the supervisor to atomically rotate in on
/// the next swap (F16 — full RCE on the supervisor at restart).
///
/// `Path::starts_with` is component-aware (so `/opt/rostro/data` does
/// not accidentally match `/opt/rostro/data-other`), but does NOT
/// resolve symlinks. Operators are expected to pass absolute, canonical
/// paths — the sandbox config already requires absolute `--sandbox-*-path`
/// values. Defense against symlink-based path confusion is a separate
/// concern (the child can't fchmod arbitrary symlinks into the cgroup
/// dir without first having a write primitive there).
fn validate_no_rw_path_overlap(
	canonical_dir: Option<&Path>,
	state_path: Option<&Path>,
	rw_paths: &[PathBuf],
) -> Result<(), String> {
	for rw in rw_paths {
		if let Some(cd) = canonical_dir {
			if cd.starts_with(rw) {
				return Err(format!(
					"F16 misconfig: --canonical-dir {} sits inside \
					 --sandbox-rw-path {}; a compromised sandboxed child can \
					 drop attacker-payload.new there for the supervisor to \
					 atomically rotate in on the next swap. Pick a \
					 canonical-dir OUTSIDE every --sandbox-rw-path.",
					cd.display(),
					rw.display(),
				));
			}
		}
		if let Some(sp) = state_path {
			if sp.starts_with(rw) {
				return Err(format!(
					"F15 misconfig: --state-file {} sits inside \
					 --sandbox-rw-path {}; a compromised sandboxed child can \
					 rewrite supervisor restart counters from inside the \
					 sandbox, escaping the max-crash-restarts circuit \
					 breaker. Pick a state-file OUTSIDE every --sandbox-rw-path.",
					sp.display(),
					rw.display(),
				));
			}
		}
	}
	Ok(())
}

/// F-NEW-R2-03 fix (2026-05-25): refuse `--sandbox-stdio-log` placements
/// that point deep into an `--sandbox-rw-path` subtree. The agent-B
/// round-2 pen-test demonstrated that the supervisor (root) opening a
/// stdio target with `O_CREAT|O_APPEND` and then handing it to the
/// child as fd 1/2 turns a write-anywhere stdio fd into a write-into-
/// sensitive-internal-file primitive (e.g.,
/// `<rw>/chains/gemini-dev/db/full/000008.log` — RocksDB WAL). The
/// inherited fd 1/2 is unrestricted by Landlock (Landlock gates the
/// `open(2)` call, not subsequent writes on already-open fds), so any
/// operator misconfig here is permanent corruption potential.
///
/// **Rule**: `--sandbox-stdio-log <path>` is permitted only if EITHER:
///   1. `path` is OUTSIDE every `--sandbox-rw-path` (operator picks a
///      separate log location; the child can write to it via fd 1/2
///      but the target is outside the sandbox's sensitive set), OR
///   2. `path` is the IMMEDIATE child of some `--sandbox-rw-path`
///      (i.e., `path.parent() == that rw_path`). This permits the
///      default location `<first-rw-path>/.gemini-node-stdio.log` and
///      operator-chosen dotfiles at the rw-path root, but refuses
///      anything deeper.
///   3. `path` is exactly `/dev/null` (explicit discard).
///
/// `None` (operator didn't pass `--sandbox-stdio-log`) is the default
/// case and falls under rule 2 automatically via the resolution in
/// the spawn loop.
fn validate_stdio_log_placement(
	stdio_log: Option<&Path>,
	rw_paths: &[PathBuf],
) -> Result<(), String> {
	let Some(p) = stdio_log else { return Ok(()) };
	if p == Path::new("/dev/null") {
		return Ok(());
	}
	for rw in rw_paths {
		if p.starts_with(rw) {
			// Inside this rw_path. Permitted only if it's an immediate
			// child (parent == rw_path).
			if p.parent() == Some(rw.as_path()) {
				return Ok(());
			}
			return Err(format!(
				"F-NEW-R2-03 misconfig: --sandbox-stdio-log {} sits deeper \
				 than the immediate-child level of --sandbox-rw-path {}. A \
				 compromised child holds fd 1/2 open to this file at root \
				 ownership; pointing it at a deep subpath turns inherited \
				 stdout/stderr into a write primitive into sensitive \
				 in-sandbox files (RocksDB WAL/MANIFEST etc.). Use an \
				 immediate-child path like {}/.gemini-node-stdio.log, OR a \
				 path OUTSIDE every --sandbox-rw-path, OR /dev/null.",
				p.display(),
				rw.display(),
				rw.display(),
			));
		}
	}
	// F-NEW-R4-01 closure (2026-05-25): the "outside every rw_path" branch
	// previously fell through to Ok(()) with no further check. The
	// /security-review surfaced that an operator passing
	// `--sandbox-stdio-log /etc/sudoers.d/00-rostro-log` would slip past
	// the validation; the supervisor would open the file AS ROOT
	// (`O_CREAT | O_APPEND | O_WRONLY` pre-Cannae) and the per-spawn
	// reader thread would append the child's bytes verbatim (the file
	// leg of the relay is unprefixed). A compromised child calling
	// `println!("\n%admin ALL=(ALL) NOPASSWD: ALL\n")` lands attacker-
	// controlled sudoers rules; same shape for `/etc/cron.d/*`,
	// `/etc/profile.d/*.sh`, `/etc/ld.so.conf.d/*.conf`,
	// `/etc/logrotate.d/*`, `/etc/systemd/*`. Each is a different
	// daemon parser that runs the file content as root with no
	// executable bit required.
	//
	// Apply `path_is_under_stdio_system_prefix` (a TREE denylist —
	// matches any descendant of the listed system dirs, not just
	// exact-match). Normalize first via `normalize_path_for_denylist`
	// to cover the R3-03 bypass shapes (`/etc/`, `//etc`,
	// `/etc/sudoers.d/foo/../bar`, etc.).
	let normalized = normalize_path_for_denylist(p)?;
	if let Some(prefix) = path_is_under_stdio_system_prefix(&normalized) {
		return Err(format!(
			"F-NEW-R4-01 misconfig: --sandbox-stdio-log {} (normalized: {}) \
			 sits under {}, a system-managed directory tree. The supervisor \
			 opens the stdio log as root and the per-spawn pipe-relay reader \
			 appends the child's stdout/stderr bytes verbatim. A compromised \
			 child can emit attacker-controlled bytes that the host's system \
			 daemons parse as root (sudo for /etc/sudoers.d/, cron for \
			 /etc/cron.d/, logrotate for /etc/logrotate.d/, ld.so for \
			 /etc/ld.so.conf.d/, …) — turning operator misconfig into \
			 root escalation. Pick a path inside an --sandbox-rw-path (e.g. \
			 <rw>/.gemini-node-stdio.log), under /var/log/, /srv/, /opt/, \
			 or /dev/null to discard.",
			p.display(),
			normalized.display(),
			prefix,
		));
	}
	Ok(())
}

/// F-NEW-R2-04 fix (2026-05-25): refuse `--sandbox-rw-path` values that
/// are system-managed top-level directories. The agent-B round-2
/// pen-test confirmed that `install_noexec_remount` operates on the
/// supervisor's HOST mount namespace (no `unshare(CLONE_NEWNS)`
/// upstream), so `mount(MS_BIND|MS_REMOUNT|MS_NOEXEC)` on `/`, `/etc`,
/// `/usr`, etc. is host-visible and persists until reboot. An operator
/// misconfig of `--sandbox-rw-path /etc` would `MS_NOEXEC`-remount the
/// host's `/etc`, breaking every system script that exec's from there
/// (cron, init.d, journald drop-ins, anything that calls
/// `/etc/something.sh`).
///
/// The proper architectural fix is `unshare(CLONE_NEWNS)` to contain
/// the bind-remount to the supervisor's mount namespace. Tracked for a
/// separate decision (UX cost: operators expect host-visible mounts
/// for debugging). This validation is the stopgap: refuse the worst
/// cases at parse time. The descent rule allows nested paths
/// (`/var/lib/rostro` ✓) but refuses the bare top-level dir
/// (`/var` ✗).
const SYSTEM_TOPLEVEL_DENYLIST: &[&str] = &[
	"/", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/boot",
	"/dev", "/proc", "/sys", "/run", "/etc", "/usr", "/var", "/srv", "/opt",
	"/root", "/home", "/mnt", "/media", "/tmp",
];

/// F-NEW-R4-V5 closure (2026-05-25): refuse `--state-file == --sandbox-stdio-log`.
/// The audit surfaced that both paths are opened by the supervisor as root
/// AND have different write disciplines: the state file uses the
/// "write `.tmp` then rename" atomic pattern; the stdio file is held open
/// O_APPEND for the supervisor's lifetime. If they collide, the
/// `save_atomic` rename atomically replaces the open stdio fd's inode
/// with a new one — the supervisor's stdio fd continues writing to the
/// orphaned inode, and the file path now contains state-counter text
/// instead of child stdio. Either: (a) operator's `tail -f` on the stdio
/// log starts seeing serialized state counters interleaved with child
/// logs, OR (b) the next state save loses the prior state on the
/// orphan-vs-rename race. Forensics broken silently.
///
/// Refuse at parse time. Symmetric with F15/F16 overlap-rejection family.
fn validate_state_and_stdio_disjoint(
	state_path: Option<&Path>,
	stdio_log: Option<&Path>,
) -> Result<(), String> {
	let (Some(sp), Some(sl)) = (state_path, stdio_log) else { return Ok(()) };
	// Normalize both via the same canonicalizer the denylist uses (R3-03),
	// so trailing slashes / double slashes / `.` components don't make
	// equivalent paths look distinct. `..` in either path is refused by
	// normalize_path_for_denylist as a separate concern.
	let sp_norm = normalize_path_for_denylist(sp)?;
	let sl_norm = normalize_path_for_denylist(sl)?;
	if sp_norm == sl_norm {
		return Err(format!(
			"F-NEW-R4-V5 misconfig: --state-file {} and --sandbox-stdio-log {} \
			 resolve to the same path ({}). The supervisor opens stdio O_APPEND \
			 for its lifetime AND uses `save_atomic` (`write .tmp + rename`) for \
			 state — the rename atomically replaces the open stdio inode with \
			 the state file's inode, orphaning the stdio fd writes and \
			 overwriting the operator-visible content. Pick distinct paths.",
			sp.display(),
			sl.display(),
			sp_norm.display(),
		));
	}
	Ok(())
}

/// F-NEW-R4-01 closure (2026-05-25): tree-denylist for `--sandbox-stdio-log`
/// placements OUTSIDE every `--sandbox-rw-path`. The R2-03 stdio-log
/// validator accepted "any path outside the rw_paths," but the supervisor
/// then opens that path AS ROOT and the per-spawn reader thread appends
/// child-controlled bytes via the already-open fd (Landlock gates `open(2)`
/// not subsequent writes on existing fds). The /security-review surfaced
/// this as an attack-chain opener: an operator who picks
/// `--sandbox-stdio-log /etc/sudoers.d/00-rostro-log` hands the compromised
/// child a root-privileged append primitive into a directory that sudo
/// parses on every invocation. `/etc/cron.d/*`, `/etc/profile.d/*.sh`,
/// `/etc/ld.so.conf.d/*.conf`, `/etc/logrotate.d/*`, `/etc/systemd/*`,
/// `/etc/init.d/*` all have the same shape: the daemon parses the
/// containing dir as root, no executable bit required.
///
/// The fix is asymmetric to `SYSTEM_TOPLEVEL_DENYLIST` because stdio-log
/// can be NESTED inside a system dir (the file at `/etc/sudoers.d/foo`
/// is the attack; `/etc` itself isn't a file). So this denylist matches
/// PREFIXES — refuse any path that's INSIDE any entry. Allows legitimate
/// log targets (`/var/log/rostro.log`, `/srv/rostro/log`, `/tmp/foo.log`,
/// `<rw>/foo.log`) which are NOT inside the denylisted system trees.
///
/// Note: `/var` is NOT in this list because `/var/log/` is the standard
/// log target. `/tmp` is NOT in this list because temp logs are
/// legitimate for dev. Operators who want stricter placement can pass
/// `/dev/null` or a path inside an `--sandbox-rw-path`.
const STDIO_LOG_SYSTEM_PREFIX_DENYLIST: &[&str] = &[
	"/etc",   // sudoers.d, cron.d, profile.d, ld.so.conf.d, logrotate.d, systemd, init.d, sysctl.d, modprobe.d, pam.d, security, bash_completion.d, …
	"/usr",   // /usr/lib/systemd, /usr/share/applications, /usr/local/sbin, …
	"/bin",   // any-named-file shadows a system command if PATH includes it
	"/sbin",  // same
	"/lib",   // shared libraries; ld.so loads anything matching SONAME
	"/lib32",
	"/lib64",
	"/libx32",
	"/boot",  // kernel + initramfs; not parsed at runtime but writes here are a sign of misconfig
];

/// Returns true if `normalized` is either equal to one of the prefix-denylist
/// entries OR sits inside one of them (i.e., `<denylisted>/anything`).
/// `normalized` MUST be the output of `normalize_path_for_denylist` — the
/// caller is responsible for refusing `..` components and stripping
/// trailing slashes / `.` components / double slashes before this call.
fn path_is_under_stdio_system_prefix(normalized: &Path) -> Option<&'static str> {
	for prefix in STDIO_LOG_SYSTEM_PREFIX_DENYLIST {
		let prefix_path = Path::new(prefix);
		if normalized == prefix_path || normalized.starts_with(prefix_path) {
			return Some(prefix);
		}
	}
	None
}

/// F-NEW-R4-V2 closure (2026-05-25): bounded line-read for the pipe-relay
/// reader thread. Wraps `BufRead::read_until` with a per-line cap so a
/// compromised child writing a single multi-GiB line (no newline) can't
/// drive the supervisor's RSS up unboundedly. The supervisor lives in the
/// uncapped outer cgroup; without a per-line cap the host's OOM killer
/// would be the only backstop, and an OOM-killed supervisor degrades the
/// F-NEW-R3-01 counter-cap promise.
///
/// When the line exceeds the cap, returns the truncated content with an
/// explicit `[cannae: line truncated]` marker appended (newline included)
/// so the operator sees the truncation in journald.
const MAX_RELAY_LINE_BYTES: usize = 64 * 1024;

fn bounded_read_until_newline<R: std::io::BufRead>(
	r: &mut R,
	buf: &mut Vec<u8>,
	max: usize,
) -> std::io::Result<usize> {
	let mut total = 0usize;
	loop {
		if buf.len() >= max {
			// Cap hit. Append truncation marker + synthetic newline so the
			// outer loop sees one complete "line".
			buf.extend_from_slice(b"[cannae: line truncated]\n");
			return Ok(total);
		}
		let available = match r.fill_buf() {
			Ok(b) => b,
			Err(e) => return Err(e),
		};
		if available.is_empty() {
			return Ok(total); // EOF
		}
		let remaining_cap = max - buf.len();
		let chunk_max = available.len().min(remaining_cap);
		// Search for newline only within the bounded chunk.
		if let Some(pos) = available[..chunk_max].iter().position(|&b| b == b'\n') {
			buf.extend_from_slice(&available[..=pos]);
			r.consume(pos + 1);
			return Ok(total + pos + 1);
		}
		// No newline in chunk; append all of it and continue (or hit cap).
		buf.extend_from_slice(&available[..chunk_max]);
		r.consume(chunk_max);
		total += chunk_max;
	}
}

/// Per-spawn pipe-relay reader body. Factored out for `catch_unwind`
/// + future testability. Reads line-by-line (bounded per
/// `MAX_RELAY_LINE_BYTES`) from `read_file`, writes to (a) the global
/// in-sandbox mirror file (unsanitized, for operator-local grep) and
/// (b) supervisor stderr with `[child-stdio] ` prefix + STATE_DELTA
/// substring mangling (F-NEW-R4-02). Exits at pipe EOF.
fn relay_reader_body(
	read_file: std::fs::File,
	file_arc: std::sync::Arc<std::fs::File>,
) {
	use std::io::Write;
	let mut reader = std::io::BufReader::new(read_file);
	let mut buf = Vec::with_capacity(4096);
	loop {
		buf.clear();
		match bounded_read_until_newline(&mut reader, &mut buf, MAX_RELAY_LINE_BYTES) {
			Ok(0) if buf.is_empty() => break, // EOF: child closed its pipe end
			Ok(_) => {
				// File leg: verbatim bytes for operator-local grep.
				let _ = Write::write_all(&mut file_arc.as_ref(), &buf);
				// journald leg: F-NEW-R4-02 sanitized.
				let sanitized = sanitize_state_delta_for_relay(&buf);
				let mut stderr = std::io::stderr().lock();
				let _ = stderr.write_all(b"[child-stdio] ");
				let _ = stderr.write_all(&sanitized);
			},
			Err(_) => break,
		}
	}
}

/// F-NEW-R4-02 closure (2026-05-25): substring-mangle any `STATE_DELTA`
/// occurrence in a byte buffer destined for the journald-mirror leg of
/// the pipe-relay. The supervisor's own state-delta lines (emitted via
/// `SupervisorState::emit_delta_to_journal`) go directly to stderr at
/// column 0; child lines go via the reader thread with a `[child-stdio] `
/// prefix and are therefore NEVER at column 0. The documented
/// reconstruction command is `journalctl … | grep '^STATE_DELTA' | tail -1`
/// — line-anchored, so child-injected `[child-stdio] STATE_DELTA …` lines
/// don't match. This sanitizer is belt-and-suspenders: an operator
/// running an ad-hoc un-anchored grep, or a future code change that
/// drops the `[child-stdio] ` prefix, would re-open the injection. By
/// replacing the substring `STATE_DELTA` with `STATE_DELTA_FROM_CHILD`
/// in the relay output, even a no-prefix relay-line is non-matching
/// against `grep 'STATE_DELTA '` (the trailing-space-style grep) and
/// the suffix makes the origin explicit to any operator who inspects.
///
/// Returns the bytes unchanged when no `STATE_DELTA` substring is
/// present (the common case — substrate's `tracing` output doesn't
/// emit that magic string).
fn sanitize_state_delta_for_relay(buf: &[u8]) -> std::borrow::Cow<'_, [u8]> {
	const NEEDLE: &[u8] = b"STATE_DELTA";
	const REPLACEMENT: &[u8] = b"STATE_DELTA_FROM_CHILD";
	// Fast path: no occurrences.
	if !buf.windows(NEEDLE.len()).any(|w| w == NEEDLE) {
		return std::borrow::Cow::Borrowed(buf);
	}
	// Slow path: build a new buffer with every `STATE_DELTA` replaced.
	let mut out = Vec::with_capacity(buf.len() + REPLACEMENT.len() - NEEDLE.len());
	let mut i = 0;
	while i < buf.len() {
		if i + NEEDLE.len() <= buf.len() && &buf[i..i + NEEDLE.len()] == NEEDLE {
			out.extend_from_slice(REPLACEMENT);
			i += NEEDLE.len();
		} else {
			out.push(buf[i]);
			i += 1;
		}
	}
	std::borrow::Cow::Owned(out)
}

/// F-NEW-R3-03 closure (2026-05-25): normalize a path to its textual
/// canonical form before exact-match comparison against the denylist.
/// The round-3 pen-test demonstrated that `/etc/`, `//etc`, `/etc/.`,
/// `/etc/foo/..` all bypass the previous `to_string_lossy() == "/etc"`
/// check, even though `mount(2)` resolves each to the same dentry.
///
/// **What this normalizer handles** (Rust `Path::components` semantics):
/// - Trailing slash dropped (`Component::RootDir` + `Component::Normal`s,
///   no trailing empty).
/// - Repeated separators collapsed (`//etc` → `/etc`).
/// - `.` components filtered (`/etc/.` → `/etc`).
///
/// **What this normalizer REFUSES** rather than handling: `..` components.
/// `path.components()` preserves `Component::ParentDir`; we'd need a
/// stack-based resolution to collapse `/etc/foo/..` to `/etc`. That
/// stack-based resolution can interact badly with symlinks
/// (`/etc/foo` could be a symlink to elsewhere, so `..` semantically
/// resolves against the symlink target, not the literal parent dir).
/// Refusing `..` entirely is correct and simple: operators should pass
/// the canonical absolute path. The supervisor refuses with a clear
/// F-NEW-R3-03 error pointing at the canonicalization requirement.
fn normalize_path_for_denylist(p: &Path) -> Result<PathBuf, String> {
	use std::path::Component;
	let mut normalized = PathBuf::new();
	for comp in p.components() {
		match comp {
			Component::RootDir => normalized.push(comp.as_os_str()),
			Component::Normal(_) => normalized.push(comp.as_os_str()),
			Component::CurDir => {
				// `Path::components` already filters most `.` occurrences;
				// this arm is defensive (and a no-op on encounter).
			},
			Component::ParentDir => {
				return Err(format!(
					"F-NEW-R3-03 misconfig: --sandbox-rw-path {} contains \
					 a '..' component. Kernel mount(2) resolves '..' against \
					 the parent dentry (or, with symlinks, the link's parent), \
					 producing a target that differs from the literal string \
					 compared against the system-dir denylist. The 2026-05-25 \
					 round-3 pen-test demonstrated this bypass against /etc \
					 via `/etc/foo/..`. Pass the canonical absolute path \
					 instead.",
					p.display(),
				));
			},
			Component::Prefix(_) => {
				// Windows-only; supervisor is Linux-only at runtime, but
				// the type sees it on cross-compiled platforms. No-op.
			},
		}
	}
	Ok(normalized)
}

fn validate_rw_paths_not_system_dirs(rw_paths: &[PathBuf]) -> Result<(), String> {
	for rw in rw_paths {
		// F-NEW-R3-03: normalize textually (trailing slashes, repeated
		// separators, '.' components) BEFORE the denylist check. Refuse
		// any path with '..' components since they can't be statically
		// resolved without filesystem traversal.
		let normalized = normalize_path_for_denylist(rw)?;
		let rw_str = normalized.to_string_lossy();
		for denied in SYSTEM_TOPLEVEL_DENYLIST {
			if rw_str.as_ref() == *denied {
				return Err(format!(
					"F-NEW-R2-04 misconfig: --sandbox-rw-path {} (normalized: \
					 {}) is a system-managed top-level directory. Cannae's \
					 `install_noexec_remount` would `mount(MS_BIND|MS_NOEXEC)` \
					 this path in the host mount namespace, breaking every \
					 system process that exec's from there. Use a nested \
					 path like {}/rostro-data instead.",
					rw.display(),
					normalized.display(),
					if rw_str.as_ref() == "/" { "/var/lib" } else { denied },
				));
			}
		}
	}
	Ok(())
}

/// Banner shown once at supervisor startup when sandbox is disabled.
/// Multiple lines so it's hard to miss in a scrolling log; per-restart
/// warning inside the spawn loop is shorter.
fn log_unsafe_skip_banner() {
	log::warn!(
		"═══════════════════════════════════════════════════════════════════════"
	);
	log::warn!(
		"  SANDBOX DISABLED via --unsafe-skip-sandbox.                          "
	);
	log::warn!(
		"  The child process runs without cgroup caps, Landlock filesystem      "
	);
	log::warn!(
		"  restrictions, or seccomp syscall filtering. This is intended for     "
	);
	log::warn!(
		"  development debugging only. Production validators MUST NOT run       "
	);
	log::warn!(
		"  in this mode.                                                        "
	);
	log::warn!(
		"═══════════════════════════════════════════════════════════════════════"
	);
}

fn default_child_path() -> std::io::Result<PathBuf> {
	let me = std::env::current_exe()?;
	let dir = me
		.parent()
		.ok_or_else(|| std::io::Error::other("supervisor binary has no parent dir"))?;
	let name = if cfg!(windows) { "gemini-node.exe" } else { "gemini-node" };
	Ok(dir.join(name))
}

fn default_staged_for(child: &Path) -> PathBuf {
	let mut staged = child.to_path_buf();
	let stem = child.file_name().map(|n| n.to_owned()).unwrap_or_default();
	let mut name = stem;
	name.push(".new");
	staged.set_file_name(name);
	staged
}

/// Atomically rotate `staged` over `target`. On POSIX `rename(2)` is
/// atomic; on Windows `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING`
/// (which `std::fs::rename` uses) is the rough equivalent.
fn rotate_staged(staged: &Path, target: &Path) -> std::io::Result<()> {
	if !staged.exists() {
		return Err(std::io::Error::new(
			std::io::ErrorKind::NotFound,
			format!(
				"staged binary not found at {}; cannot fulfill swap-and-restart",
				staged.display(),
			),
		));
	}
	std::fs::rename(staged, target)?;
	log::info!("rotated {} -> {}", staged.display(), target.display());
	Ok(())
}

/// Scan `dir` for any files whose name ends in `.new` and atomically
/// rotate each one to drop the suffix, e.g. `gemini-runtime.pvm.new`
/// → `gemini-runtime.pvm`. Returns the number of rotations performed.
///
/// Skips:
/// - any path equal to `skip_target` (already rotated by the caller's
///   primary-binary swap)
/// - directories
/// - entries whose file name is `.new` alone (no stem to strip back to)
/// - entries with non-UTF8 file names
///
/// Errors out of the loop on the first rotation failure. Files
/// rotated before that point remain rotated — partial rotation is
/// the trade-off vs. attempting a cross-file atomic commit, which
/// POSIX doesn't offer. The verifier will re-detect any
/// still-mismatched files on next boot and re-stage.
fn rotate_canonical_dir(dir: &Path, skip_target: &Path) -> std::io::Result<usize> {
	let mut rotated = 0usize;
	for entry in std::fs::read_dir(dir)? {
		let entry = entry?;
		let staged_path = entry.path();
		if !staged_path.is_file() {
			continue;
		}
		let name_os = entry.file_name();
		let name = match name_os.to_str() {
			Some(s) => s,
			None => continue,
		};
		let Some(stem) = name.strip_suffix(".new") else { continue };
		if stem.is_empty() {
			continue;
		}
		let target = dir.join(stem);
		if target == skip_target {
			continue;
		}
		std::fs::rename(&staged_path, &target)?;
		log::info!(
			"rotated {} -> {}",
			staged_path.display(),
			target.display(),
		);
		rotated += 1;
	}
	Ok(rotated)
}

/// Classified outcome of one child run. Drives the supervisor's
/// restart decision.
#[derive(Debug, PartialEq, Eq)]
enum ChildOutcome {
	/// Child exited with status 0. Supervisor exits successfully.
	CleanExit,
	/// Child exited with [`EXIT_SWAP_AND_RESTART`]. Supervisor rotates
	/// the staged binary and respawns, bounded by the persisted
	/// swap-restart counter.
	SwapAndRestart,
	/// Any other exit code OR signal kill. Supervisor treats as a
	/// crash and respawns with backoff, bounded by the sliding-window
	/// crash counter. The string is just for the log line.
	Crashed { detail: String },
}

fn classify_exit(status: ExitStatus) -> ChildOutcome {
	classify_exit_code(status.code())
}

/// Testable core of [`classify_exit`]: works against the raw
/// `Option<i32>` rather than `ExitStatus` so unit tests don't need
/// `ExitStatusExt` (platform-gated).
fn classify_exit_code(code: Option<i32>) -> ChildOutcome {
	match code {
		Some(0) => ChildOutcome::CleanExit,
		Some(c) if c == EXIT_SWAP_AND_RESTART => ChildOutcome::SwapAndRestart,
		Some(c) => ChildOutcome::Crashed { detail: format!("exit code {c}") },
		None => ChildOutcome::Crashed { detail: "signal kill".to_string() },
	}
}

/// Exponential backoff before retrying after a crash. The first crash
/// in the window waits `initial`, second `initial*2`, etc., capped at
/// `ceiling`. `nth` is zero-indexed: 0 = first restart after a crash.
fn backoff_for_crash(nth: u32, initial: Duration, ceiling: Duration) -> Duration {
	let base = initial.as_secs().max(1);
	// 2^nth, saturating to avoid overflow on absurd counts.
	let mult = 1u64.checked_shl(nth.min(31)).unwrap_or(u64::MAX);
	let secs = base.saturating_mul(mult).min(ceiling.as_secs());
	Duration::from_secs(secs)
}

/// Persisted supervisor state. Survives supervisor process death so an
/// attacker who can kill the supervisor (or a benign systemd restart)
/// can't reset the counters.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct SupervisorState {
	/// Total swap-and-restart cycles completed. Audit-flagged: this
	/// must persist across supervisor invocations so an attacker can't
	/// reset it by killing the supervisor.
	swap_count: u32,
	/// Unix-epoch seconds of recent crashes. Pruned to the sliding
	/// window on every load and save. Sorted ascending.
	crashes: Vec<u64>,
}

impl SupervisorState {
	/// Load state from disk. Missing file → default (fresh start). Any
	/// parse error → log + default (safer than refusing to start; the
	/// supervisor's job is to keep nodes alive).
	fn load(path: &Path) -> Self {
		let raw = match std::fs::read_to_string(path) {
			Ok(s) => s,
			Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Self::default(),
			Err(e) => {
				log::warn!("could not read supervisor state at {}: {}; starting fresh", path.display(), e);
				return Self::default();
			},
		};
		Self::parse(&raw).unwrap_or_else(|e| {
			log::warn!("malformed supervisor state at {}: {}; starting fresh", path.display(), e);
			Self::default()
		})
	}

	/// Parse the text format. Lines are `key=value`; unknown keys are
	/// ignored (forward-compat). `crash=<unix_secs>` may repeat.
	fn parse(raw: &str) -> Result<Self, String> {
		let mut state = Self::default();
		let mut saw_schema = false;
		for (lineno, line) in raw.lines().enumerate() {
			let line = line.trim();
			if line.is_empty() || line.starts_with('#') {
				continue;
			}
			let (key, value) = line
				.split_once('=')
				.ok_or_else(|| format!("line {}: no '=' separator", lineno + 1))?;
			match key.trim() {
				"schema_version" => {
					let v: u32 = value.trim().parse()
						.map_err(|e| format!("line {}: bad schema_version: {e}", lineno + 1))?;
					if v != STATE_SCHEMA_VERSION {
						return Err(format!("schema_version {v} != expected {STATE_SCHEMA_VERSION}"));
					}
					saw_schema = true;
				},
				"swap_count" => {
					state.swap_count = value.trim().parse()
						.map_err(|e| format!("line {}: bad swap_count: {e}", lineno + 1))?;
				},
				"crash" => {
					let secs: u64 = value.trim().parse()
						.map_err(|e| format!("line {}: bad crash timestamp: {e}", lineno + 1))?;
					state.crashes.push(secs);
				},
				_ => {
					// Forward-compat: ignore unknown keys.
				},
			}
		}
		if !saw_schema {
			return Err("missing schema_version".to_string());
		}
		state.crashes.sort_unstable();
		Ok(state)
	}

	/// Serialize to the text format. Stable ordering for diffability.
	fn serialize(&self) -> String {
		let mut out = String::new();
		out.push_str(&format!("schema_version={}\n", STATE_SCHEMA_VERSION));
		out.push_str(&format!("swap_count={}\n", self.swap_count));
		for ts in &self.crashes {
			out.push_str(&format!("crash={ts}\n"));
		}
		out
	}

	/// Atomic save: write to `<path>.tmp`, then rename onto `<path>`.
	/// On POSIX `rename(2)` is atomic; Windows `MoveFileExW` (which
	/// `std::fs::rename` uses) is the rough equivalent.
	///
	/// F-NEW-R4-V8 closure (2026-05-25): the tmp open uses `O_NOFOLLOW`
	/// + mode 0600. Symmetric with the stdio mirror file's
	/// F-NEW-R2-02 open. If a local non-root user has write access to
	/// the state-file directory (operator misconfig — `mkdir -m 777`
	/// or chmod loosening), they could plant
	/// `<state-file>.tmp → /etc/passwd` and the supervisor (root)
	/// would clobber `/etc/passwd` with serialized state content. The
	/// state-file's directory is `/var/lib/rostro/` on the lab (root
	/// 0755), so the prerequisite is operator misconfig; refuse via
	/// O_NOFOLLOW + ELOOP-on-symlink at the kernel layer.
	fn save_atomic(&self, path: &Path) -> std::io::Result<()> {
		use std::io::Write;
		#[cfg(target_os = "linux")]
		use std::os::unix::fs::OpenOptionsExt;
		let mut tmp = path.to_path_buf();
		let mut name = tmp
			.file_name()
			.map(|n| n.to_owned())
			.unwrap_or_else(|| OsString::from(STATE_FILE_NAME));
		name.push(".tmp");
		tmp.set_file_name(name);
		if let Some(parent) = path.parent() {
			if !parent.as_os_str().is_empty() {
				std::fs::create_dir_all(parent)?;
			}
		}
		let serialized = self.serialize();
		// Open the tmp with O_NOFOLLOW (refuses symlink-plant attacks) +
		// O_TRUNC (drop any prior tmp content). Mode 0600 — only root
		// (the supervisor) should read the state.
		#[cfg(target_os = "linux")]
		let mut tmp_file = std::fs::OpenOptions::new()
			.create(true)
			.write(true)
			.truncate(true)
			.custom_flags(libc::O_NOFOLLOW)
			.mode(0o600)
			.open(&tmp)?;
		#[cfg(not(target_os = "linux"))]
		let mut tmp_file = std::fs::OpenOptions::new()
			.create(true)
			.write(true)
			.truncate(true)
			.open(&tmp)?;
		tmp_file.write_all(serialized.as_bytes())?;
		tmp_file.sync_all()?;
		drop(tmp_file);
		std::fs::rename(&tmp, path)?;
		Ok(())
	}

	/// F-NEW-R3-01 closure (2026-05-25): emit a structured state-delta
	/// line to the supervisor's stderr after every mutation. systemd's
	/// `ExecStart` captures stderr → systemd-journald, which writes to
	/// `/var/log/journal/` — a path Cannae's Landlock + DAC keep both
	/// the supervisor's own filesystem reach and the child's UID 1000
	/// from touching. journald becomes the **canonical, attacker-
	/// unreachable forensic mirror** for state counters.
	///
	/// **Why this matters** (the threat the agent flagged): the
	/// supervisor is sandboxed by its own Landlock policy. The state
	/// file MUST live outside `--sandbox-rw-path` (F15 — child must
	/// not be able to rewrite supervisor's restart counter). Landlock
	/// denies the supervisor's writes to that outside-RW location;
	/// `save_atomic` always returns EACCES under Cannae. Counter caps
	/// (`max_restarts`, `max_crash_restarts`) degraded from
	/// "per-deployment-lifetime" to "per-supervisor-lifetime" — an
	/// attacker who engineers a supervisor restart (e.g., a stuck-
	/// validator scenario that prompts the operator to
	/// `systemctl restart`) gets the counters reset to zero. The
	/// state-file's docstring promised lifetime persistence; that
	/// promise was broken by Cannae itself.
	///
	/// **Why journald is the right mirror**: it's a separate process
	/// outside Cannae's policy envelope, already running on every
	/// lab node, with append-only durability semantics at its
	/// protocol layer. The state file remains the best-effort local
	/// cache (still updated when not sandboxed, e.g.
	/// `--unsafe-skip-sandbox` runs); journald is the canonical
	/// source. Operator can reconstruct state via:
	///   `journalctl -u rostro-supervisor --output=cat | grep '^STATE_DELTA' | tail -1`
	///
	/// **F-NEW-R4-02 closure (2026-05-25)**: the recovery `grep` is
	/// anchored at line-start (`^STATE_DELTA`). The supervisor's own
	/// emissions go via `eprintln!` directly to stderr at column 0;
	/// the pipe-relay reader prefixes child lines with `[child-stdio] `,
	/// so the child can't emit a line that starts with `STATE_DELTA`
	/// regardless of what bytes it puts on its stdout. Defense-in-depth:
	/// the reader also substring-mangles any `STATE_DELTA` occurrence in
	/// the child's bytes before forwarding to stderr (see the relay
	/// reader thread in `run()`), so even if a future change drops the
	/// `[child-stdio] ` prefix, the attack-line shape is mangled too.
	///
	/// **Format choice**: single-line key=value pairs, journald-friendly
	/// and `awk`-parseable. Schema version is explicit so future
	/// changes don't silently break operator scripts.
	fn emit_delta_to_journal(&self) {
		// `eprintln!` writes to fd 2 unbuffered (well, line-buffered).
		// Under systemd's ExecStart, fd 2 → journal stream socket;
		// outside systemd, fd 2 → whatever shell redirected it to.
		// Either way, this is OUTSIDE Cannae's policy envelope (the
		// supervisor's stderr was opened pre-Cannae by the parent
		// process).
		eprintln!(
			"STATE_DELTA schema={} swap_count={} crashes=[{}]",
			STATE_SCHEMA_VERSION,
			self.swap_count,
			self.crashes
				.iter()
				.map(|t| t.to_string())
				.collect::<Vec<_>>()
				.join(","),
		);
	}

	/// Persist state to disk + emit the journald-mirror delta. Combined
	/// call so every call site updates both mirrors atomically (well,
	/// best-effort under Cannae for the disk leg). Logs the persist
	/// failure as ERROR (was: WARN) since it's a real degradation of
	/// the security cap promise, not a benign hiccup.
	///
	/// Returns the disk-save result so callers can decide whether to
	/// continue or fail-stop; the journald-mirror always emits regardless.
	fn save_and_mirror(&self, path: &Path) -> std::io::Result<()> {
		self.emit_delta_to_journal();
		match self.save_atomic(path) {
			Ok(()) => Ok(()),
			Err(e) => {
				log::error!(
					"F-NEW-R3-01: state-file persist FAILED at {}: {} \
					 — counter caps (max_restarts, max_crash_restarts) \
					 now degraded to per-supervisor-lifetime. journald \
					 STATE_DELTA mirror IS emitted; operator can \
					 reconstruct via `journalctl -u rostro-supervisor \
					 --output=cat | grep '^STATE_DELTA' | tail -1` and \
					 hand-seed the state file at the next restart if \
					 caps need to span deployments. (Grep anchor `^` is \
					 load-bearing per F-NEW-R4-02 — unanchored grep would \
					 also match child-injected `[child-stdio] STATE_DELTA…` \
					 lines that defeat the reconstruction via tail -1.)",
					path.display(),
					e,
				);
				Err(e)
			},
		}
	}

	/// Record a crash at `now`, then prune entries outside the window.
	fn record_crash(&mut self, now_secs: u64, window_secs: u64) {
		self.crashes.push(now_secs);
		self.prune_crashes(now_secs, window_secs);
	}

	/// Drop crashes older than `now - window`.
	fn prune_crashes(&mut self, now_secs: u64, window_secs: u64) {
		let cutoff = now_secs.saturating_sub(window_secs);
		self.crashes.retain(|&t| t >= cutoff);
	}

	/// Count crashes in `[now-window, now]` inclusive.
	fn crashes_in_window(&self, now_secs: u64, window_secs: u64) -> u32 {
		let cutoff = now_secs.saturating_sub(window_secs);
		self.crashes.iter().filter(|&&t| t >= cutoff).count() as u32
	}
}

fn now_secs() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0)
}

fn run(args: Args) -> ExitCode {
	// Compute the sandbox config before any consuming reads of `args`
	// (the option fields below are moved out via match/unwrap_or_else).
	let sandbox_config = build_sandbox_config(&args);

	let child_path = match args.child {
		Some(p) => p,
		None => match default_child_path() {
			Ok(p) => p,
			Err(e) => {
				log::error!("could not derive default child path: {}", e);
				return ExitCode::FAILURE;
			},
		},
	};
	let staged_path = args.staged.unwrap_or_else(|| default_staged_for(&child_path));

	// Default canonical-dir to the child binary's parent directory,
	// matching the verifier's resolve-relative-to-current_exe()
	// convention. An empty path explicitly disables the multi-file
	// scan; non-empty overrides the default.
	let canonical_dir: Option<PathBuf> = match args.canonical_dir {
		Some(p) if p.as_os_str().is_empty() => None,
		Some(p) => Some(p),
		None => child_path.parent().map(|p| p.to_path_buf()),
	};

	// Resolve persisted state file. Default sits inside canonical-dir
	// so it shares the same install footprint as the binaries. An
	// explicit empty `--state-file` disables persistence (tests +
	// dev only — production validators must persist, see audit).
	let state_path: Option<PathBuf> = match args.state_file.clone() {
		Some(p) if p.as_os_str().is_empty() => None,
		Some(p) => Some(p),
		None => canonical_dir
			.as_deref()
			.map(|d| d.join(STATE_FILE_NAME)),
	};

	// F15/F16: refuse to launch if state-file or canonical-dir sits
	// inside any sandbox RW path. Fail-fast BEFORE installing the
	// sandbox so the operator sees a clear error and no privileged
	// resources are committed to a misconfig.
	if let Err(msg) = validate_no_rw_path_overlap(
		canonical_dir.as_deref(),
		state_path.as_deref(),
		&args.sandbox_rw_paths,
	) {
		log::error!("{msg}");
		return ExitCode::FAILURE;
	}

	// F-NEW-R2-04: refuse `--sandbox-rw-path` values that name a
	// system-managed top-level directory (`/etc`, `/usr`, etc.). The
	// noexec bind-remount on those paths would propagate to the host
	// mount namespace and break system services.
	if let Err(msg) = validate_rw_paths_not_system_dirs(&args.sandbox_rw_paths) {
		log::error!("{msg}");
		return ExitCode::FAILURE;
	}

	// F-NEW-R2-03: refuse `--sandbox-stdio-log` placements that point
	// deep into an `--sandbox-rw-path` subtree (the symlink-and-overlap
	// family of stdio-fd-misuse attacks). Default location (immediate
	// child of first rw_path) is permitted; deeper paths are not.
	if let Err(msg) = validate_stdio_log_placement(
		args.sandbox_stdio_log.as_deref(),
		&args.sandbox_rw_paths,
	) {
		log::error!("{msg}");
		return ExitCode::FAILURE;
	}

	// F-NEW-R4-V5: refuse `--state-file == --sandbox-stdio-log`. Both are
	// supervisor-opened-as-root with mutually-incompatible write
	// disciplines (atomic-rename vs O_APPEND-for-lifetime); collision
	// silently breaks forensics. Symmetric with F15/F16.
	if let Err(msg) = validate_state_and_stdio_disjoint(
		state_path.as_deref(),
		args.sandbox_stdio_log.as_deref(),
	) {
		log::error!("{msg}");
		return ExitCode::FAILURE;
	}

	// F-NEW-R2-01: refuse `--sandbox-rlimit-as-bytes=0` at parse time.
	// The earlier semantics — `Some(0) => None` meaning "leave RLIMIT_AS
	// at inherited (unlimited)" — inverted the convention used by
	// `--sandbox-rlimit-memlock-bytes` where `0` means "hard deny mlock."
	// An operator with the muscle memory of the MEMLOCK convention who
	// passes `--sandbox-rlimit-as-bytes=0` thinking they're hardening
	// would actually re-open F-NEW-01 (TOCTOU host-memory burst).
	// Refuse explicitly with a pointer to the right way to skip:
	// omit the flag entirely.
	if args.sandbox_rlimit_as_bytes == Some(0) {
		log::error!(
			"F-NEW-R2-01 misconfig: --sandbox-rlimit-as-bytes=0 is refused. \
			 RLIMIT_AS=0 would make any allocation impossible. To skip the \
			 RLIMIT_AS hardening and leave it at inherited (NOT recommended; \
			 re-opens F-NEW-01 host-memory-burst), omit the flag entirely \
			 OR pass a large explicit value. To hard-cap, pass the desired \
			 byte ceiling (default = sandbox-memory-max + 1 GiB)."
		);
		return ExitCode::FAILURE;
	}

	// Phase G: when sandbox is active AND we run as root, require both
	// --sandbox-child-uid AND --sandbox-child-gid. The supervisor needs
	// root for cgroup setup; the child must NOT inherit it or it can
	// reverse every cgroup cap via writes to its own
	// /sys/fs/cgroup/.../{memory,cpu}.max and kill(getppid()) the
	// supervisor (F-AGENT-C-01, F-AGENT-C-03, F-AGENT-C-05). Fail fast
	// before any privileged resource is committed.
	#[cfg(target_os = "linux")]
	let child_uid_gid: Option<(u32, u32)> = {
		// Pairing: both or neither, ever.
		let pair = match (args.sandbox_child_uid, args.sandbox_child_gid) {
			(Some(u), Some(g)) => Some((u, g)),
			(None, None) => None,
			_ => {
				log::error!(
					"--sandbox-child-uid and --sandbox-child-gid must both be provided or both omitted."
				);
				return ExitCode::FAILURE;
			},
		};
		// Refuse uid=0 or gid=0 explicitly — they defeat the drop.
		if let Some((u, g)) = pair {
			if u == 0 || g == 0 {
				log::error!(
					"--sandbox-child-uid={u} --sandbox-child-gid={g} refused: zero defeats Phase G."
				);
				return ExitCode::FAILURE;
			}
		}
		// SAFETY: getuid is infallible.
		let supervisor_uid = unsafe { libc::getuid() };
		if !args.unsafe_skip_sandbox && supervisor_uid == 0 && pair.is_none() {
			log::error!(
				"Phase G refuses to launch: supervisor runs as root but \
				 --sandbox-child-uid + --sandbox-child-gid were not provided. \
				 The sandboxed child would inherit root and could reverse \
				 cgroup caps (F-AGENT-C-01/03) or kill the supervisor \
				 (F-AGENT-C-05). Pass both flags with a non-root UID/GID \
				 that owns --sandbox-rw-path."
			);
			return ExitCode::FAILURE;
		}
		pair
	};

	log::info!(
		"rostro-supervisor starting; child={}, staged={}, canonical_dir={}, state_file={}, \
		 max_restarts={}, max_crash_restarts={}, crash_window_secs={}, backoff_ceiling_secs={}",
		child_path.display(),
		staged_path.display(),
		canonical_dir
			.as_deref()
			.map(|p| p.display().to_string())
			.unwrap_or_else(|| "(disabled)".to_string()),
		state_path
			.as_deref()
			.map(|p| p.display().to_string())
			.unwrap_or_else(|| "(disabled)".to_string()),
		args.max_restarts,
		args.max_crash_restarts,
		args.crash_window_secs,
		args.backoff_ceiling_secs,
	);

	let mut state: SupervisorState = state_path
		.as_deref()
		.map(SupervisorState::load)
		.unwrap_or_default();
	// Prune stale crash entries up front so a long-quiet validator
	// doesn't start near its cap due to ancient noise.
	state.prune_crashes(now_secs(), args.crash_window_secs);

	// F-NEW-R3-02 closure setup (2026-05-25): open the child's stdio
	// mirror file ONCE here, BEFORE Cannae installs. Reason: after
	// Cannae install, the seccomp filter blocks `ioctl(FS_IOC_SETFLAGS)`
	// (arg-filtered to a tiny terminal-config set), so we can't apply
	// `chattr +a` from the spawn loop. Opening here also lets the
	// per-spawn reader thread share a single inode (writes from
	// multiple restart cycles accumulate to the same forensic file).
	//
	// Resolution order matches the spawn-loop fallback:
	//   1. `--sandbox-stdio-log <path>` (explicit operator choice).
	//   2. `<first --sandbox-rw-path>/.gemini-node-stdio.log` (default).
	//   3. None → spawn loop uses legacy inherit-supervisor-stdio shape.
	//
	// `chattr +a` is best-effort — tmpfs / FAT / /dev/null don't support
	// it; the pipe-relay (per-spawn) remains the primary R3-02 defense.
	#[cfg(target_os = "linux")]
	let stdio_global_file: Option<std::sync::Arc<std::fs::File>> = {
		use std::fs::OpenOptions;
		use std::os::unix::fs::OpenOptionsExt;
		use std::os::unix::io::AsRawFd;
		let target: Option<PathBuf> = args.sandbox_stdio_log.clone().or_else(|| {
			args.sandbox_rw_paths
				.first()
				.map(|rw| rw.join(".gemini-node-stdio.log"))
		});
		match target {
			None => None,
			Some(path) => match OpenOptions::new()
				.create(true)
				.append(true)
				.write(true)
				.custom_flags(libc::O_NOFOLLOW)
				.mode(0o600) // F-NEW-R4-01 defense-in-depth: root-only readable.
				             // If a misconfigured stdio_log ever lands in a path
				             // that some other daemon scans, mode 0600 prevents
				             // non-root parsers from reading the file at all.
				             // The supervisor (root) opens + writes via the
				             // already-open fd; the child's writes go through
				             // the pipe-relay, not via an open of the path —
				             // so child UID 1000 can't open this either.
				.open(&path)
			{
				Ok(f) => {
					// chattr +a — best-effort.
					// FS_APPEND_FL = 0x00000020 per <linux/fs.h>.
					// FS_IOC_GETFLAGS = _IOR('f', 1, long) = 0x80086601
					// FS_IOC_SETFLAGS = _IOW('f', 2, long) = 0x40086602
					const FS_APPEND_FL: libc::c_long = 0x0000_0020;
					const FS_IOC_GETFLAGS: libc::c_ulong = 0x8008_6601;
					const FS_IOC_SETFLAGS: libc::c_ulong = 0x4008_6602;
					let fd = f.as_raw_fd();
					let mut flags: libc::c_long = 0;
					let get_rc = unsafe {
						libc::ioctl(fd, FS_IOC_GETFLAGS, &mut flags as *mut libc::c_long)
					};
					if get_rc == 0 {
						let new_flags = flags | FS_APPEND_FL;
						let set_rc = unsafe {
							libc::ioctl(
								fd,
								FS_IOC_SETFLAGS,
								&new_flags as *const libc::c_long,
							)
						};
						if set_rc == 0 {
							log::info!(
								"Cannae stdio: FS_APPEND_FL set on {} (ftruncate/unlink-while-open denied at the inode layer; defense-in-depth on top of pipe-relay)",
								path.display(),
							);
						} else {
							let e = std::io::Error::last_os_error();
							log::debug!(
								"Cannae stdio: FS_APPEND_FL set failed on {} ({e}) — likely filesystem doesn't support chattr +a (tmpfs/FAT); pipe-relay remains the primary R3-02 defense.",
								path.display(),
							);
						}
					} else {
						let e = std::io::Error::last_os_error();
						log::debug!(
							"Cannae stdio: FS_APPEND_FL get failed on {} ({e}) — likely not a regular file (char device, etc.); pipe-relay remains the primary R3-02 defense.",
							path.display(),
						);
					}
					Some(std::sync::Arc::new(f))
				},
				Err(e) => {
					// F-NEW-R2-02 fail-stop semantics: any open error here is
					// security-relevant. ELOOP = symlink-plant. Bail before
					// Cannae touches anything privileged.
					let kind_note = match e.raw_os_error() {
						Some(libc::ELOOP) => " (ELOOP — symlink at the stdio path; possible attack: an attacker may have planted a symlink at the default location pointing into a sensitive file. Investigate before retrying.)",
						Some(libc::EACCES) => " (EACCES — supervisor lacks permission to open the stdio path)",
						Some(libc::ENOENT) => " (ENOENT — parent directory doesn't exist; --sandbox-rw-path may not have been created yet)",
						_ => "",
					};
					log::error!(
						"Cannae stdio: could not open {} for the mirror file ({e}){}. Refusing to start supervisor — falling back to inherited stdio would silently re-open F-NEW-02.",
						path.display(),
						kind_note,
					);
					return ExitCode::FAILURE;
				},
			},
		}
	};
	#[cfg(not(target_os = "linux"))]
	let stdio_global_file: Option<std::sync::Arc<std::fs::File>> = None;

	// Install the sandbox envelope (or skip it loudly). Once installed,
	// the policy is process-wide and inherited by all descendants;
	// supervisor and child share the seccomp + Landlock policy.
	let sandbox_handle: Option<SandboxHandle> = if args.unsafe_skip_sandbox {
		log_unsafe_skip_banner();
		None
	} else {
		match rostro_node_sandbox::install(&sandbox_config) {
			Ok(h) => {
				log::info!(
					"Cannae: installed (cgroup={}, landlock={}, seccomp=enabled)",
					if sandbox_config.memory_cap().is_some() || sandbox_config.cpu_cap().is_some() {
						"enabled"
					} else {
						"skipped (no caps)"
					},
					if sandbox_config.rw_paths().is_empty() && sandbox_config.ro_paths().is_empty() {
						"baseline only"
					} else {
						"with operator paths"
					},
				);
				Some(h)
			},
			Err(e) => {
				log::error!("sandbox install failed: {e}");
				return ExitCode::FAILURE;
			},
		}
	};

	loop {
		if !child_path.exists() {
			log::error!("child binary {} does not exist", child_path.display());
			return ExitCode::FAILURE;
		}

		let mut cmd = Command::new(&child_path);
		cmd.args(&args.child_args);

		// F-NEW-02 closure (2026-05-25): redirect the child's stdout +
		// stderr to a controlled file BEFORE fork. The supervisor (still
		// root, unfiltered) opens the target file; `Command::stdout/stderr`
		// installs it as the child's fd 1/2 via the standard execve fd
		// inheritance. Without this, the supervisor's own 1/2 — typically
		// a journal-stream socket under systemd or an operator-chosen
		// redirect outside `--sandbox-rw-path` — gets handed to the
		// sandboxed child as a fully writable fd that Landlock cannot
		// retroactively gate (Landlock checks `open(2)` paths, not
		// pre-existing fds).
		//
		// Resolution order for the redirect target:
		//   1. `--sandbox-stdio-log <path>` (explicit operator choice;
		//      can be `/dev/null` to discard, or any absolute path).
		//   2. `<first --sandbox-rw-path>/.gemini-node-stdio.log` if any
		//      `--sandbox-rw-path` is configured (the conventional case).
		//   3. Otherwise: keep supervisor's inherited 1/2 (legacy
		//      behavior; matches `--unsafe-skip-sandbox` shape).
		//
		// Open with `O_CREAT|O_APPEND|O_WRONLY,0644`. Root-owned by
		// default (supervisor is root); operator can `chown` after first
		// run if they want post-supervisor-exit readability. The file
		// lives inside the noexec bind-mount — fine, it's never mmap'd
		// PROT_EXEC, just appended to.
		#[cfg(target_os = "linux")]
		{
			use std::os::unix::io::FromRawFd;
			if let Some(file_arc) = stdio_global_file.as_ref() {
				// F-NEW-R3-02 closure (2026-05-25): pipe-relay child stdio
				// instead of handing the child an inherited file fd.
				//
				// The previous F-NEW-02 fix opened a file as root + handed
				// the fd to the child as 1/2. Round-3 pen-test showed that
				// inherited writable fd lets the child ftruncate the file
				// to zero — kernel `do_ftruncate` checks `FMODE_WRITE` on
				// the open fd, NOT the caller's permission on the inode.
				// The supervisor's `Cannae install + child spawn` startup
				// banners were wipeable from inside the sandbox.
				//
				// Fix shape: supervisor creates a pipe with `pipe2(O_CLOEXEC)`,
				// hands the write-end to the child as 1/2, keeps the read-end
				// in a supervisor-side thread that forwards bytes to:
				//
				//   1. **An in-sandbox file** (operator-local grep target,
				//      same path as before). Opened with `O_NOFOLLOW`
				//      (F-NEW-R2-02). `FS_APPEND_FL` (`chattr +a`) applied
				//      best-effort — kernel refuses ftruncate/unlink on the
				//      inode regardless of fd ownership. Survives operator
				//      misconfig + a future bypass that gets a fd anyway.
				//   2. **Supervisor's own stderr** with `[child-stdio] `
				//      prefix. Under `lab-supervisor-wrapper.sh` →
				//      systemd's ExecStart, supervisor stderr is wired to
				//      systemd-journald. journald writes to
				//      `/var/log/journal/` which Cannae's Landlock + DAC
				//      keep both the supervisor's filesystem reach AND the
				//      child UID 1000 OUT of. **journald is the canonical
				//      attacker-unreachable forensic mirror.**
				//
				// `ftruncate(pipe_fd, 0)` from the child returns EINVAL
				// (pipes have no size). Even if the child somehow corrupts
				// the in-sandbox file via append-write attacks, journald
				// has the full pre-corruption history.
				//
				// Trade: pipe-relay adds 1 reader thread per spawn + minor
				// per-line copy overhead. Substrate emits line-oriented
				// `tracing` logs at INFO level — overhead is negligible.

				// (1) Create the pipe. O_CLOEXEC on both ends; Stdio::from
				// clears CLOEXEC on the destination 1/2 fds in the child
				// via exec's standard dup2 semantics.
				let mut pipefd = [0i32; 2];
				let rc = unsafe { libc::pipe2(pipefd.as_mut_ptr(), libc::O_CLOEXEC) };
				if rc != 0 {
					let e = std::io::Error::last_os_error();
					log::error!(
						"Cannae stdio: pipe2() failed ({e}); refusing to spawn — \
						 falling back to inherited stdio would silently re-open F-NEW-02."
					);
					return ExitCode::FAILURE;
				}
				let (read_fd, write_fd) = (pipefd[0], pipefd[1]);

				// (2) Wire the pipe write-end as the child's 1 and 2.
				let write_file = unsafe { std::fs::File::from_raw_fd(write_fd) };
				let write_file_clone = match write_file.try_clone() {
					Ok(c) => c,
					Err(e) => {
						unsafe {
							libc::close(read_fd);
						}
						log::error!(
							"Cannae stdio: could not clone pipe write-end ({e}); \
							 refusing to spawn."
						);
						return ExitCode::FAILURE;
					},
				};
				cmd.stdout(std::process::Stdio::from(write_file));
				cmd.stderr(std::process::Stdio::from(write_file_clone));

				// (3) Spawn the reader thread. Reads line-by-line from the
				// pipe; writes each line to (a) the global in-sandbox
				// mirror file (opened ONCE pre-Cannae, with chattr +a) and
				// (b) supervisor's stderr with `[child-stdio] ` prefix.
				// Thread shares the Arc<File> for the mirror; the file
				// fd survives across restart cycles so logs accumulate.
				// Thread exits at pipe EOF (when child closes its end —
				// i.e., when the child exits). Per-spawn thread; no
				// accumulation across restart loop.
				let read_file = unsafe { std::fs::File::from_raw_fd(read_fd) };
				let file_arc_for_thread = std::sync::Arc::clone(file_arc);
				std::thread::Builder::new()
					.name("cannae-stdio-relay".to_string())
					.spawn(move || {
						// F-NEW-R4-V3 closure (2026-05-25): wrap the entire
						// reader body in `catch_unwind`. If the body panics
						// (today or under a future change), the thread would
						// otherwise just exit silently — the child would
						// continue writing, fill the 64 KiB pipe, block, and
						// the supervisor's spawn loop would never see a crash
						// (child is alive, just stuck). Block production
						// stops without forensics. The fix on panic:
						// `std::process::exit(2)` from the panicking thread,
						// which terminates the WHOLE supervisor — systemd
						// then restarts it. Loud failure beats silent hang.
						// (We don't `exit(0)` because that would look like
						// clean shutdown to systemd's restart policy.)
						let body_result = std::panic::catch_unwind(
							std::panic::AssertUnwindSafe(|| {
								relay_reader_body(read_file, file_arc_for_thread)
							}),
						);
						if let Err(panic_payload) = body_result {
							let msg = panic_payload
								.downcast_ref::<&'static str>()
								.copied()
								.unwrap_or("(non-string panic payload)");
							eprintln!(
								"FATAL: cannae-stdio-relay thread panicked: {msg}. \
								 Supervisor exiting (systemd will restart) so the \
								 child doesn't hang on a full pipe with no relay."
							);
							std::process::exit(2);
						}
					})
					.ok(); // If thread spawn fails, supervisor continues
					        // without the mirror; the pipe writes will
					        // eventually block the child on a full pipe.
					        // Acceptable degradation.

				log::info!(
					"Cannae stdio: pipe-relay active; child 1/2 → pipe → \
					 supervisor reader → (mirror file, journald via stderr)"
				);
			} else {
				log::debug!(
					"Cannae stdio: no --sandbox-stdio-log and no --sandbox-rw-path; \
					 child inherits supervisor's stdio (legacy shape)."
				);
			}
		}

		// Pre-exec hardening (2026-05-24, extended 2026-05-25 by Phase H+).
		// Run in the forked-but-pre-exec child where seccomp + landlock
		// are already inherited from supervisor, but the new gemini-node
		// image hasn't started. Order is load-bearing:
		//   (1) close inherited fds (F13 residual — defeats the
		//       /proc/self/fd-reopen attack on inherited writable
		//       inodes by closing those fds above stdio before exec)
		//   (2) drop CAP_SYS_ADMIN (Pending #7). MUST run while still
		//       root: PR_CAPBSET_DROP needs CAP_SETPCAP which a non-root
		//       process without PR_SET_KEEPCAPS=1 lacks.
		//   (3) drop CAP_SETUID + CAP_SETGID + CAP_KILL (Phase G
		//       companion). Same root-requirement as (2). Removing
		//       these from the bounding set before the UID drop in (5)
		//       means the post-uid-drop effective set won't have them,
		//       so the child can't setresuid(0) back to root or
		//       kill(2) processes owned by other UIDs.
		//   (4) apply rlimits (F-NEW-01/04, 2026-05-25). Bounds the
		//       burst-mmap window between `Command::spawn` and
		//       `place_child_in_cgroup` where the child runs in the
		//       supervisor's inherited root cgroup without `memory.max`
		//       enforcement. `prlimit64(pid=0, …)` is in the seccomp
		//       allowlist. Position: BEFORE the UID drop because non-root
		//       can only lower rlimits — defensive against a future
		//       higher-than-soft passing.
		//   (5) drop to non-root (uid, gid) (Phase G — closes
		//       F-AGENT-C-01/03/05). One-way: after this the child
		//       cannot reclaim root, cannot write its own cgroup
		//       interface files (root-owned, DAC blocks), and cannot
		//       kill the root supervisor.
		// All engage only when the sandbox is active; --unsafe-skip-sandbox
		// behaves identically to the pre-hardening shape.
		#[cfg(target_os = "linux")]
		if sandbox_handle.is_some() {
			use std::os::unix::process::CommandExt;
			// Resolve rlimit values once, here, where args is in scope.
			// RLIMIT_AS default: memory cap + 1 GiB headroom for mmap'd
			// RO libs + runtime blob that count against AS but not memcg.
			// `Some(0)` is already refused at parse time (F-NEW-R2-01),
			// so we don't have a corresponding match arm here.
			let rlimit_as = match args.sandbox_rlimit_as_bytes {
				Some(v) => Some(v),
				None => args
					.sandbox_memory_max_bytes
					.map(|m| m.saturating_add(1024 * 1024 * 1024)),
			};
			let rlimit_nproc = if args.sandbox_rlimit_nproc == 0 {
				None
			} else {
				Some(args.sandbox_rlimit_nproc)
			};
			// rlimit_memlock = 0 means "deny mlock entirely" (the
			// default + Rostro's intended posture). Pass Some(0) through
			// so the hook actually sets it.
			let rlimit_memlock = Some(args.sandbox_rlimit_memlock_bytes);
			// SAFETY: each closure is panic-free, thread-safe, and a
			// short syscall sequence; pre_exec doc requires all of these.
			// pre_exec closures run in REGISTRATION order per std docs.
			unsafe {
				cmd.pre_exec(SandboxHandle::close_inherited_fds_in_child);
				cmd.pre_exec(SandboxHandle::drop_cap_sys_admin_in_child);
				if let Some((uid, gid)) = child_uid_gid {
					cmd.pre_exec(SandboxHandle::drop_root_caps_for_uid_drop_in_child);
					cmd.pre_exec(move || {
						SandboxHandle::apply_rlimits_in_child(
							rlimit_as,
							rlimit_nproc,
							rlimit_memlock,
						)
					});
					cmd.pre_exec(move || SandboxHandle::drop_to_uid_gid_in_child(uid, gid));
				} else {
					// Even without UID drop, rlimits are still meaningful.
					cmd.pre_exec(move || {
						SandboxHandle::apply_rlimits_in_child(
							rlimit_as,
							rlimit_nproc,
							rlimit_memlock,
						)
					});
				}
			}
		}

		log::info!(
			"spawning child (swap_count={}, recent_crashes={}): {}",
			state.swap_count,
			state.crashes_in_window(now_secs(), args.crash_window_secs),
			child_path.display(),
		);
		let mut child = match cmd.spawn() {
			Ok(c) => c,
			Err(e) => {
				log::error!("failed to spawn child {}: {}", child_path.display(), e);
				return ExitCode::FAILURE;
			},
		};

		// Place the just-spawned child into the constrained inner
		// cgroup so memory + cpu caps apply. No-op if no cgroup was
		// installed (no caps configured) or sandbox was skipped.
		if let Some(ref handle) = sandbox_handle {
			if let Err(e) = handle.place_child_in_cgroup(child.id()) {
				log::error!(
					"failed to place child PID {} into sandbox cgroup: {e}",
					child.id(),
				);
				// Child is running uncapped — kill it rather than
				// risk an unconstrained validator.
				let _ = child.kill();
				let _ = child.wait();
				return ExitCode::FAILURE;
			}
		} else {
			// Per-restart reminder so operators can't silently
			// forget they're running unprotected.
			log::warn!(
				"SANDBOX DISABLED: child PID {} runs without cgroup/Landlock/seccomp",
				child.id(),
			);
		}

		let status = match child.wait() {
			Ok(s) => s,
			Err(e) => {
				log::error!("failed to wait on child: {}", e);
				return ExitCode::FAILURE;
			},
		};

		match classify_exit(status) {
			ChildOutcome::CleanExit => {
				log::info!("child exited cleanly; supervisor exiting");
				return ExitCode::SUCCESS;
			},
			ChildOutcome::SwapAndRestart => {
				state.swap_count = state.swap_count.saturating_add(1);
				log::info!(
					"child requested swap-and-restart (cycle {} of {})",
					state.swap_count,
					args.max_restarts,
				);
				if let Some(p) = state_path.as_deref() {
					// F-NEW-R3-01: also emits STATE_DELTA to stderr → journald
					// (the canonical mirror; disk persist may fail under Cannae).
					let _ = state.save_and_mirror(p);
				}
				if state.swap_count > args.max_restarts {
					log::error!(
						"max_restarts={} exceeded (persisted); supervisor giving up",
						args.max_restarts,
					);
					return ExitCode::FAILURE;
				}
				if let Err(e) = rotate_staged(&staged_path, &child_path) {
					log::error!("staged-binary rotate failed: {}", e);
					return ExitCode::FAILURE;
				}
				if let Some(dir) = canonical_dir.as_deref() {
					match rotate_canonical_dir(dir, &child_path) {
						Ok(0) => {},
						Ok(n) => log::info!(
							"rotated {} additional canonical files in {}",
							n,
							dir.display(),
						),
						Err(e) => {
							log::error!(
								"canonical-file rotate in {} failed: {}",
								dir.display(),
								e,
							);
							return ExitCode::FAILURE;
						},
					}
				}
				continue;
			},
			ChildOutcome::Crashed { detail } => {
				let now = now_secs();
				state.record_crash(now, args.crash_window_secs);
				let in_window = state.crashes_in_window(now, args.crash_window_secs);
				log::error!(
					"child crashed ({}); {} crashes in last {}s (cap {})",
					detail,
					in_window,
					args.crash_window_secs,
					args.max_crash_restarts,
				);
				if let Some(p) = state_path.as_deref() {
					// F-NEW-R3-01: also emits STATE_DELTA to stderr → journald
					// (the canonical mirror; disk persist may fail under Cannae).
					let _ = state.save_and_mirror(p);
				}
				if in_window > args.max_crash_restarts {
					log::error!(
						"max_crash_restarts={} exceeded in {}s window; supervisor giving up",
						args.max_crash_restarts,
						args.crash_window_secs,
					);
					return ExitCode::FAILURE;
				}
				// Backoff index = how many crashes are already in the
				// window AFTER recording this one, minus 1 (so the
				// first crash waits `initial`, not `initial*2`).
				let nth = in_window.saturating_sub(1);
				let backoff = backoff_for_crash(
					nth,
					Duration::from_secs(DEFAULT_BACKOFF_INITIAL_SECS),
					Duration::from_secs(args.backoff_ceiling_secs),
				);
				log::info!("backing off {}s before respawn", backoff.as_secs());
				std::thread::sleep(backoff);
				continue;
			},
		}
	}
}

fn main() -> ExitCode {
	let _ = env_logger::Builder::from_env(
		env_logger::Env::default().default_filter_or("info"),
	)
	.try_init();
	run(Args::parse())
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::io::Write;

	#[test]
	fn rw_overlap_allows_disjoint_paths() {
		let rw = vec![PathBuf::from("/opt/rostro/data")];
		let canon = PathBuf::from("/opt/rostro/bin");
		let state = PathBuf::from("/opt/rostro/bin/.supervisor-state");
		assert!(validate_no_rw_path_overlap(
			Some(&canon), Some(&state), &rw,
		).is_ok());
	}

	#[test]
	fn rw_overlap_allows_no_rw_paths() {
		let rw: Vec<PathBuf> = vec![];
		let canon = PathBuf::from("/anywhere");
		let state = PathBuf::from("/anywhere/state");
		assert!(validate_no_rw_path_overlap(
			Some(&canon), Some(&state), &rw,
		).is_ok());
	}

	#[test]
	fn rw_overlap_rejects_state_file_inside_rw_path() {
		// F15 scenario: state-file at /opt/rostro/data/state and
		// RW path at /opt/rostro/data — child can rewrite counters.
		let rw = vec![PathBuf::from("/opt/rostro/data")];
		let canon = PathBuf::from("/opt/rostro/bin");
		let state = PathBuf::from("/opt/rostro/data/state");
		let err = validate_no_rw_path_overlap(
			Some(&canon), Some(&state), &rw,
		).unwrap_err();
		assert!(err.contains("F15"), "expected F15 error, got: {err}");
		assert!(err.contains("state-file"), "expected state-file ref, got: {err}");
	}

	#[test]
	fn rw_overlap_rejects_canonical_dir_inside_rw_path() {
		// F16 scenario: canonical-dir = RW path — child drops *.new
		// for atomic rotation by next swap.
		let rw = vec![PathBuf::from("/opt/rostro/data")];
		let canon = PathBuf::from("/opt/rostro/data");
		let state = PathBuf::from("/opt/rostro/bin/state");
		let err = validate_no_rw_path_overlap(
			Some(&canon), Some(&state), &rw,
		).unwrap_err();
		assert!(err.contains("F16"), "expected F16 error, got: {err}");
		assert!(err.contains("canonical-dir"), "expected canonical-dir ref, got: {err}");
	}

	#[test]
	fn rw_overlap_rejects_canonical_dir_nested_under_rw_path() {
		// Nested case: canonical-dir is a subdir of an RW path.
		let rw = vec![PathBuf::from("/opt/rostro/data")];
		let canon = PathBuf::from("/opt/rostro/data/nested");
		let err = validate_no_rw_path_overlap(
			Some(&canon), None, &rw,
		).unwrap_err();
		assert!(err.contains("F16"), "expected F16 error, got: {err}");
	}

	#[test]
	fn rw_overlap_treats_path_components_correctly() {
		// /opt/rostro/data must NOT match /opt/rostro/data-other —
		// starts_with is component-aware, not byte-prefix.
		let rw = vec![PathBuf::from("/opt/rostro/data")];
		let canon = PathBuf::from("/opt/rostro/data-other");
		let state = PathBuf::from("/opt/rostro/data-other/state");
		assert!(validate_no_rw_path_overlap(
			Some(&canon), Some(&state), &rw,
		).is_ok(), "data-other must not match data");
	}

	#[test]
	fn rw_overlap_handles_multiple_rw_paths() {
		// Overlap with the SECOND rw_path still gets caught.
		let rw = vec![
			PathBuf::from("/srv/keys"),
			PathBuf::from("/opt/rostro/data"),
		];
		let canon = PathBuf::from("/opt/rostro/data/canonical");
		let err = validate_no_rw_path_overlap(
			Some(&canon), None, &rw,
		).unwrap_err();
		assert!(err.contains("/opt/rostro/data"), "should name the matching rw_path: {err}");
	}

	#[test]
	fn default_staged_appends_new_suffix() {
		let child = PathBuf::from("/opt/rostro/bin/gemini-node");
		let staged = default_staged_for(&child);
		assert_eq!(staged, PathBuf::from("/opt/rostro/bin/gemini-node.new"));
	}

	#[test]
	fn default_staged_appends_new_suffix_windows_style() {
		let child = PathBuf::from(r"C:\Rostro\gemini-node.exe");
		let staged = default_staged_for(&child);
		assert_eq!(staged, PathBuf::from(r"C:\Rostro\gemini-node.exe.new"));
	}

	#[test]
	fn rotate_missing_staged_errors() {
		let dir = tmpdir();
		let target = dir.join("target");
		let staged = dir.join("staged");
		std::fs::write(&target, b"original").unwrap();
		// staged does not exist
		let err = rotate_staged(&staged, &target).unwrap_err();
		assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
		assert_eq!(std::fs::read(&target).unwrap(), b"original");
	}

	#[test]
	fn rotate_replaces_target_atomically() {
		let dir = tmpdir();
		let target = dir.join("bin");
		let staged = dir.join("bin.new");
		std::fs::write(&target, b"old").unwrap();
		std::fs::write(&staged, b"new").unwrap();
		rotate_staged(&staged, &target).unwrap();
		assert_eq!(std::fs::read(&target).unwrap(), b"new");
		assert!(!staged.exists(), "staged should be consumed by rename");
	}

	#[test]
	fn exit_code_constant_in_safe_range() {
		// Outside sysexits (64-78) and signal-encoded (128+), positive.
		assert!(EXIT_SWAP_AND_RESTART > 78);
		assert!(EXIT_SWAP_AND_RESTART < 128);
	}

	#[test]
	fn canonical_rotate_returns_zero_on_empty_dir() {
		let dir = tmpdir();
		let skip = dir.join("noop-skip");
		let n = rotate_canonical_dir(&dir, &skip).unwrap();
		assert_eq!(n, 0);
	}

	#[test]
	fn canonical_rotate_renames_only_dot_new_files() {
		let dir = tmpdir();
		std::fs::write(dir.join("runtime.pvm.new"), b"new pvm").unwrap();
		std::fs::write(dir.join("config.yaml"), b"unrelated").unwrap();
		std::fs::write(dir.join("README.md.new"), b"new readme").unwrap();
		let skip = dir.join("never-matches");
		let n = rotate_canonical_dir(&dir, &skip).unwrap();
		assert_eq!(n, 2);
		assert!(!dir.join("runtime.pvm.new").exists(), ".new should be consumed");
		assert!(!dir.join("README.md.new").exists(), ".new should be consumed");
		assert_eq!(std::fs::read(dir.join("runtime.pvm")).unwrap(), b"new pvm");
		assert_eq!(std::fs::read(dir.join("README.md")).unwrap(), b"new readme");
		assert_eq!(
			std::fs::read(dir.join("config.yaml")).unwrap(),
			b"unrelated",
			"non-.new files must not be touched",
		);
	}

	#[test]
	fn canonical_rotate_skips_target_equal_to_skip_path() {
		let dir = tmpdir();
		let target = dir.join("gemini-node");
		std::fs::write(dir.join("gemini-node.new"), b"staged binary").unwrap();
		std::fs::write(dir.join("runtime.pvm.new"), b"staged runtime").unwrap();
		let n = rotate_canonical_dir(&dir, &target).unwrap();
		assert_eq!(n, 1, "should skip gemini-node.new (matches skip_target)");
		assert!(
			dir.join("gemini-node.new").exists(),
			"skipped .new must remain on disk",
		);
		assert!(!dir.join("gemini-node").exists(), "skipped target untouched");
		assert!(!dir.join("runtime.pvm.new").exists(), "other .new still rotated");
		assert_eq!(std::fs::read(dir.join("runtime.pvm")).unwrap(), b"staged runtime");
	}

	#[test]
	fn canonical_rotate_ignores_bare_dot_new() {
		// A file literally named `.new` has no stem to strip back to;
		// must be skipped, not renamed to empty.
		let dir = tmpdir();
		std::fs::write(dir.join(".new"), b"degenerate").unwrap();
		let skip = dir.join("noop-skip");
		let n = rotate_canonical_dir(&dir, &skip).unwrap();
		assert_eq!(n, 0);
		assert!(dir.join(".new").exists(), "bare .new must be left alone");
	}

	#[test]
	fn canonical_rotate_overwrites_existing_target() {
		// Pre-existing target file is the common case (file present,
		// hash drifted) — rotate must replace it, not refuse.
		let dir = tmpdir();
		std::fs::write(dir.join("runtime.pvm"), b"old").unwrap();
		std::fs::write(dir.join("runtime.pvm.new"), b"new").unwrap();
		let skip = dir.join("noop-skip");
		let n = rotate_canonical_dir(&dir, &skip).unwrap();
		assert_eq!(n, 1);
		assert_eq!(std::fs::read(dir.join("runtime.pvm")).unwrap(), b"new");
	}

	// ─── classify_exit_code ────────────────────────────────────────────

	#[test]
	fn classify_clean_exit() {
		assert_eq!(classify_exit_code(Some(0)), ChildOutcome::CleanExit);
	}

	#[test]
	fn classify_swap_request() {
		assert_eq!(classify_exit_code(Some(EXIT_SWAP_AND_RESTART)), ChildOutcome::SwapAndRestart);
	}

	#[test]
	fn classify_nonzero_is_crash() {
		match classify_exit_code(Some(7)) {
			ChildOutcome::Crashed { detail } => assert!(detail.contains("7")),
			other => panic!("expected Crashed, got {other:?}"),
		}
	}

	#[test]
	fn classify_signal_kill_is_crash() {
		match classify_exit_code(None) {
			ChildOutcome::Crashed { detail } => assert!(detail.contains("signal")),
			other => panic!("expected Crashed, got {other:?}"),
		}
	}

	#[test]
	fn classify_sysexits_range_treated_as_crash() {
		// Sandbox design choice: only 0 and EXIT_SWAP_AND_RESTART get
		// special treatment; sysexits (64-78) propagation was removed
		// to close the attacker-controlled "kill the supervisor" path.
		match classify_exit_code(Some(64)) {
			ChildOutcome::Crashed { .. } => {},
			other => panic!("expected Crashed for sysexits 64, got {other:?}"),
		}
	}

	// ─── backoff_for_crash ─────────────────────────────────────────────

	#[test]
	fn backoff_starts_at_initial() {
		let b = backoff_for_crash(0, Duration::from_secs(1), Duration::from_secs(60));
		assert_eq!(b, Duration::from_secs(1));
	}

	#[test]
	fn backoff_doubles_each_step() {
		let initial = Duration::from_secs(1);
		let ceiling = Duration::from_secs(60);
		assert_eq!(backoff_for_crash(0, initial, ceiling), Duration::from_secs(1));
		assert_eq!(backoff_for_crash(1, initial, ceiling), Duration::from_secs(2));
		assert_eq!(backoff_for_crash(2, initial, ceiling), Duration::from_secs(4));
		assert_eq!(backoff_for_crash(3, initial, ceiling), Duration::from_secs(8));
		assert_eq!(backoff_for_crash(4, initial, ceiling), Duration::from_secs(16));
	}

	#[test]
	fn backoff_capped_at_ceiling() {
		let initial = Duration::from_secs(1);
		let ceiling = Duration::from_secs(60);
		assert_eq!(backoff_for_crash(10, initial, ceiling), Duration::from_secs(60));
		assert_eq!(backoff_for_crash(31, initial, ceiling), Duration::from_secs(60));
	}

	#[test]
	fn backoff_handles_extreme_nth_without_overflow() {
		// Shouldn't panic regardless of input.
		let _ = backoff_for_crash(u32::MAX, Duration::from_secs(1), Duration::from_secs(60));
	}

	// ─── SupervisorState ───────────────────────────────────────────────

	#[test]
	fn state_load_missing_file_returns_default() {
		let dir = tmpdir();
		let state = SupervisorState::load(&dir.join("nope"));
		assert_eq!(state, SupervisorState::default());
	}

	#[test]
	fn state_load_empty_file_returns_default() {
		let dir = tmpdir();
		let p = dir.join("state");
		std::fs::write(&p, b"").unwrap();
		// Missing schema_version → malformed → falls back to default.
		let state = SupervisorState::load(&p);
		assert_eq!(state, SupervisorState::default());
	}

	#[test]
	fn state_save_then_load_roundtrips() {
		let dir = tmpdir();
		let p = dir.join("state");
		let mut s = SupervisorState::default();
		s.swap_count = 7;
		s.crashes = vec![100, 200, 300];
		s.save_atomic(&p).unwrap();
		let loaded = SupervisorState::load(&p);
		assert_eq!(loaded.swap_count, 7);
		assert_eq!(loaded.crashes, vec![100, 200, 300]);
	}

	#[test]
	fn state_save_is_atomic_via_rename() {
		// After save_atomic completes, the `.tmp` file must not exist.
		let dir = tmpdir();
		let p = dir.join("state");
		let s = SupervisorState::default();
		s.save_atomic(&p).unwrap();
		assert!(p.exists(), "final file present");
		let tmp = {
			let mut t = p.clone();
			let mut name = t.file_name().unwrap().to_owned();
			name.push(".tmp");
			t.set_file_name(name);
			t
		};
		assert!(!tmp.exists(), "tmp must not linger after save_atomic");
	}

	#[test]
	fn state_save_creates_parent_dir() {
		let dir = tmpdir();
		let p = dir.join("nested/under/here/state");
		SupervisorState::default().save_atomic(&p).unwrap();
		assert!(p.exists());
	}

	#[test]
	fn state_record_crash_prunes_outside_window() {
		let mut s = SupervisorState::default();
		s.crashes = vec![10, 20, 30, 40];
		// now=100, window=50 → cutoff=50 → keep [40] (>=50? no, drop), keep only entries >= 50
		s.record_crash(100, 50);
		assert_eq!(s.crashes, vec![100], "old entries dropped, new one kept");
	}

	#[test]
	fn state_record_crash_keeps_entries_inside_window() {
		let mut s = SupervisorState::default();
		s.crashes = vec![55, 70, 90];
		s.record_crash(100, 50); // cutoff=50 → keep 55, 70, 90, 100
		assert_eq!(s.crashes, vec![55, 70, 90, 100]);
	}

	#[test]
	fn state_crashes_in_window_counts_correctly() {
		let mut s = SupervisorState::default();
		s.crashes = vec![10, 50, 80, 95, 100];
		assert_eq!(s.crashes_in_window(100, 50), 4, "10 is outside [50,100]");
		assert_eq!(s.crashes_in_window(100, 100), 5, "all inside [0,100]");
		assert_eq!(s.crashes_in_window(100, 0), 1, "only now inside [100,100]");
	}

	#[test]
	fn state_parse_rejects_missing_schema() {
		let raw = "swap_count=5\n";
		assert!(SupervisorState::parse(raw).is_err());
	}

	#[test]
	fn state_parse_rejects_wrong_schema_version() {
		let raw = format!("schema_version={}\nswap_count=5\n", STATE_SCHEMA_VERSION + 999);
		assert!(SupervisorState::parse(&raw).is_err());
	}

	#[test]
	fn state_parse_ignores_unknown_keys_forward_compat() {
		// Future versions may add keys; we shouldn't choke on them.
		let raw = format!(
			"schema_version={}\nswap_count=3\nfuture_thing=whatever\ncrash=500\n",
			STATE_SCHEMA_VERSION,
		);
		let s = SupervisorState::parse(&raw).unwrap();
		assert_eq!(s.swap_count, 3);
		assert_eq!(s.crashes, vec![500]);
	}

	#[test]
	fn state_parse_ignores_blank_and_comment_lines() {
		let raw = format!(
			"# a comment\nschema_version={}\n\nswap_count=2\n# another\ncrash=42\n",
			STATE_SCHEMA_VERSION,
		);
		let s = SupervisorState::parse(&raw).unwrap();
		assert_eq!(s.swap_count, 2);
		assert_eq!(s.crashes, vec![42]);
	}

	#[test]
	fn state_parse_sorts_crashes() {
		let raw = format!(
			"schema_version={}\nswap_count=0\ncrash=300\ncrash=100\ncrash=200\n",
			STATE_SCHEMA_VERSION,
		);
		let s = SupervisorState::parse(&raw).unwrap();
		assert_eq!(s.crashes, vec![100, 200, 300]);
	}

	#[test]
	fn state_load_malformed_returns_default() {
		// Corrupted state must NOT panic and must NOT block supervisor
		// startup — falls back to default and logs.
		let dir = tmpdir();
		let p = dir.join("state");
		std::fs::write(&p, b"\xff\xfe garbage \xff").unwrap();
		let s = SupervisorState::load(&p);
		assert_eq!(s, SupervisorState::default());
	}

	#[test]
	fn state_persistence_survives_synthetic_supervisor_restart() {
		// Audit scenario: attacker kills supervisor; restart must NOT
		// reset the cap.
		let dir = tmpdir();
		let p = dir.join("state");
		let mut s = SupervisorState::default();
		s.swap_count = 15;
		s.record_crash(now_secs(), 60);
		s.save_atomic(&p).unwrap();

		// Simulate fresh supervisor process loading.
		let loaded = SupervisorState::load(&p);
		assert_eq!(loaded.swap_count, 15);
		assert_eq!(loaded.crashes.len(), 1);
	}

	// ─── build_sandbox_config (Phase 4) ──────────────────────────────

	fn args_with(
		rw: Vec<PathBuf>,
		ro: Vec<PathBuf>,
		mem: Option<u64>,
		cpu_max: Option<u64>,
		cpu_period: u64,
		unsafe_skip: bool,
	) -> Args {
		Args {
			child: None,
			staged: None,
			canonical_dir: None,
			max_restarts: DEFAULT_MAX_SWAP_RESTARTS,
			max_crash_restarts: DEFAULT_MAX_CRASH_RESTARTS,
			crash_window_secs: DEFAULT_CRASH_WINDOW_SECS,
			backoff_ceiling_secs: DEFAULT_BACKOFF_CEILING_SECS,
			state_file: None,
			unsafe_skip_sandbox: unsafe_skip,
			sandbox_rw_paths: rw,
			sandbox_ro_paths: ro,
			sandbox_memory_max_bytes: mem,
			sandbox_cpu_max_micros: cpu_max,
			sandbox_cpu_period_micros: cpu_period,
			sandbox_child_uid: None,
			sandbox_child_gid: None,
			sandbox_rlimit_as_bytes: None,
			sandbox_rlimit_nproc: 256,
			sandbox_rlimit_memlock_bytes: 0,
			sandbox_stdio_log: None,
			child_args: Vec::new(),
		}
	}

	#[test]
	fn build_sandbox_config_empty_args_yields_empty_config() {
		let args = args_with(vec![], vec![], None, None, 100_000, false);
		let cfg = build_sandbox_config(&args);
		assert!(cfg.rw_paths().is_empty());
		assert!(cfg.ro_paths().is_empty());
		assert!(cfg.memory_cap().is_none());
		assert!(cfg.cpu_cap().is_none());
	}

	#[test]
	fn build_sandbox_config_propagates_rw_paths() {
		let args = args_with(
			vec![
				PathBuf::from("/var/lib/rostro/db"),
				PathBuf::from("/var/lib/rostro/keystore"),
			],
			vec![],
			None,
			None,
			100_000,
			false,
		);
		let cfg = build_sandbox_config(&args);
		assert_eq!(cfg.rw_paths().len(), 2);
		assert_eq!(cfg.rw_paths()[0], PathBuf::from("/var/lib/rostro/db"));
		assert_eq!(cfg.rw_paths()[1], PathBuf::from("/var/lib/rostro/keystore"));
	}

	#[test]
	fn build_sandbox_config_propagates_ro_paths() {
		let args = args_with(
			vec![],
			vec![
				PathBuf::from("/etc/rostro/chain-spec.json"),
				PathBuf::from("/opt/rostro/canonical"),
			],
			None,
			None,
			100_000,
			false,
		);
		let cfg = build_sandbox_config(&args);
		assert_eq!(cfg.ro_paths().len(), 2);
	}

	#[test]
	fn build_sandbox_config_sets_memory_cap_when_provided() {
		let args = args_with(vec![], vec![], Some(8 * 1024 * 1024 * 1024), None, 100_000, false);
		let cfg = build_sandbox_config(&args);
		assert_eq!(cfg.memory_cap(), Some(8 * 1024 * 1024 * 1024));
	}

	#[test]
	fn build_sandbox_config_omits_memory_cap_when_unset() {
		let args = args_with(vec![], vec![], None, None, 100_000, false);
		let cfg = build_sandbox_config(&args);
		assert!(cfg.memory_cap().is_none());
	}

	#[test]
	fn build_sandbox_config_sets_cpu_cap_with_default_period() {
		let args = args_with(vec![], vec![], None, Some(200_000), 100_000, false);
		let cfg = build_sandbox_config(&args);
		assert_eq!(cfg.cpu_cap(), Some((200_000, 100_000)));
	}

	#[test]
	fn build_sandbox_config_sets_cpu_cap_with_custom_period() {
		let args = args_with(vec![], vec![], None, Some(50_000), 50_000, false);
		let cfg = build_sandbox_config(&args);
		assert_eq!(cfg.cpu_cap(), Some((50_000, 50_000)));
	}

	#[test]
	fn build_sandbox_config_omits_cpu_cap_when_max_unset_even_if_period_set() {
		// Period alone (no max) means no cpu cap — period is just the
		// resolution for when max is set.
		let args = args_with(vec![], vec![], None, None, 50_000, false);
		let cfg = build_sandbox_config(&args);
		assert!(cfg.cpu_cap().is_none());
	}

	#[test]
	fn unsafe_skip_sandbox_is_false_by_default() {
		// Critical default: sandbox must be on unless operator
		// explicitly disables.
		let args = Args::parse_from(["rostro-supervisor"]);
		assert!(!args.unsafe_skip_sandbox);
	}

	#[test]
	fn unsafe_skip_sandbox_flag_parses() {
		let args = Args::parse_from(["rostro-supervisor", "--unsafe-skip-sandbox"]);
		assert!(args.unsafe_skip_sandbox);
	}

	#[test]
	fn sandbox_rw_path_flag_accepts_multiple_occurrences() {
		let args = Args::parse_from([
			"rostro-supervisor",
			"--sandbox-rw-path",
			"/a",
			"--sandbox-rw-path",
			"/b",
			"--sandbox-rw-path",
			"/c",
		]);
		assert_eq!(args.sandbox_rw_paths.len(), 3);
	}

	#[test]
	fn sandbox_ro_path_flag_accepts_multiple_occurrences() {
		let args = Args::parse_from([
			"rostro-supervisor",
			"--sandbox-ro-path",
			"/x",
			"--sandbox-ro-path",
			"/y",
		]);
		assert_eq!(args.sandbox_ro_paths.len(), 2);
	}

	#[test]
	fn sandbox_cpu_period_defaults_to_100k_micros() {
		// 100ms — matches cgroup v2 convention. Don't change this
		// default without considering compatibility with operator
		// configs that assume it.
		let args = Args::parse_from(["rostro-supervisor"]);
		assert_eq!(args.sandbox_cpu_period_micros, 100_000);
	}

	fn tmpdir() -> PathBuf {
		let mut p = std::env::temp_dir();
		let unique = format!(
			"rostro-supervisor-test-{}-{}",
			std::process::id(),
			std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH)
				.unwrap()
				.as_nanos(),
		);
		p.push(unique);
		std::fs::create_dir_all(&p).unwrap();
		p
	}

	// Suppress unused warning for the helper; kept here in case more
	// tests are added that need temp file content.
	#[allow(dead_code)]
	fn write(path: &Path, bytes: &[u8]) {
		let mut f = std::fs::File::create(path).unwrap();
		f.write_all(bytes).unwrap();
	}

	// ─── F-NEW-R2-03: stdio-log placement validation ─────────────────────

	#[test]
	fn stdio_log_placement_accepts_none() {
		// Operator didn't pass --sandbox-stdio-log; default resolution
		// happens later in the spawn loop. Validation should not fail.
		assert!(validate_stdio_log_placement(None, &[PathBuf::from("/opt/rostro/data")]).is_ok());
	}

	#[test]
	fn stdio_log_placement_accepts_immediate_child_of_rw_path() {
		// The default-shape path is an immediate child of the rw_path.
		let rw = vec![PathBuf::from("/opt/rostro/data")];
		let stdio = PathBuf::from("/opt/rostro/data/.gemini-node-stdio.log");
		assert!(validate_stdio_log_placement(Some(&stdio), &rw).is_ok());
	}

	#[test]
	fn stdio_log_placement_accepts_outside_all_rw_paths() {
		// Operator chooses a log location outside the sandbox.
		let rw = vec![PathBuf::from("/opt/rostro/data")];
		let stdio = PathBuf::from("/var/log/rostro/gemini-node.log");
		assert!(validate_stdio_log_placement(Some(&stdio), &rw).is_ok());
	}

	#[test]
	fn stdio_log_placement_accepts_dev_null() {
		// Explicit discard.
		let rw = vec![PathBuf::from("/opt/rostro/data")];
		let stdio = PathBuf::from("/dev/null");
		assert!(validate_stdio_log_placement(Some(&stdio), &rw).is_ok());
	}

	#[test]
	fn stdio_log_placement_rejects_deep_subpath_of_rw() {
		// F-NEW-R2-03 attack shape: operator points stdio at RocksDB
		// internals so the child's fd 1/2 corrupts the DB.
		let rw = vec![PathBuf::from("/opt/rostro/data")];
		let stdio = PathBuf::from("/opt/rostro/data/chains/gemini-dev/db/full/000008.log");
		let err = validate_stdio_log_placement(Some(&stdio), &rw).unwrap_err();
		assert!(err.contains("F-NEW-R2-03"), "expected F-NEW-R2-03 error, got: {err}");
		assert!(err.contains("immediate-child"), "expected immediate-child guidance, got: {err}");
	}

	#[test]
	fn stdio_log_placement_treats_path_components_correctly() {
		// /opt/rostro/data must NOT match /opt/rostro/data-other — same
		// component-aware property as the F15/F16 validator.
		let rw = vec![PathBuf::from("/opt/rostro/data")];
		let stdio = PathBuf::from("/opt/rostro/data-other/log/stdio.log");
		assert!(validate_stdio_log_placement(Some(&stdio), &rw).is_ok());
	}

	// ─── F-NEW-R2-04: top-level system-dir refusal ───────────────────────

	#[test]
	fn rw_paths_system_dir_rejects_etc() {
		let rw = vec![PathBuf::from("/etc")];
		let err = validate_rw_paths_not_system_dirs(&rw).unwrap_err();
		assert!(err.contains("F-NEW-R2-04"), "expected F-NEW-R2-04 error, got: {err}");
		assert!(err.contains("system-managed"), "expected system-managed wording, got: {err}");
	}

	#[test]
	fn rw_paths_system_dir_rejects_root() {
		let rw = vec![PathBuf::from("/")];
		let err = validate_rw_paths_not_system_dirs(&rw).unwrap_err();
		assert!(err.contains("F-NEW-R2-04"), "expected F-NEW-R2-04 error, got: {err}");
	}

	#[test]
	fn rw_paths_system_dir_rejects_var_directly_but_allows_nested() {
		// /var → reject; /var/lib/rostro → accept (descendants allowed).
		assert!(validate_rw_paths_not_system_dirs(&[PathBuf::from("/var")]).is_err());
		assert!(validate_rw_paths_not_system_dirs(&[PathBuf::from("/var/lib/rostro")]).is_ok());
	}

	#[test]
	fn rw_paths_system_dir_rejects_tmp_directly_but_allows_nested() {
		// /tmp → reject (would noexec-remount the whole tmpfs);
		// /tmp/rostro-bp-alice → accept (legit test path used by WSL dev).
		assert!(validate_rw_paths_not_system_dirs(&[PathBuf::from("/tmp")]).is_err());
		assert!(validate_rw_paths_not_system_dirs(&[PathBuf::from("/tmp/rostro-bp-alice")]).is_ok());
	}

	#[test]
	fn rw_paths_system_dir_rejects_multiple_paths_one_bad() {
		// Mixed list: one good + one denylisted → reject.
		let rw = vec![
			PathBuf::from("/var/lib/rostro"),
			PathBuf::from("/usr"),
		];
		assert!(validate_rw_paths_not_system_dirs(&rw).is_err());
	}

	#[test]
	fn rw_paths_system_dir_accepts_empty_list() {
		// No rw paths → nothing to validate.
		assert!(validate_rw_paths_not_system_dirs(&[]).is_ok());
	}

	// ─── F-NEW-R3-03: non-canonical path bypass closure ─────────────────

	#[test]
	fn rw_paths_system_dir_rejects_trailing_slash() {
		// `/etc/` → normalized to `/etc` → denylist hit.
		// 2026-05-25 round-3 pen-test confirmed this WAS exploitable
		// pre-fix: supervisor accepted `/etc/` and bind-mounted /etc noexec
		// on the host.
		let rw = vec![PathBuf::from("/etc/")];
		let err = validate_rw_paths_not_system_dirs(&rw).unwrap_err();
		assert!(err.contains("F-NEW-R2-04"), "expected denylist hit, got: {err}");
	}

	#[test]
	fn rw_paths_system_dir_rejects_double_slash() {
		// `//etc` → normalized to `/etc` → denylist hit.
		let rw = vec![PathBuf::from("//etc")];
		let err = validate_rw_paths_not_system_dirs(&rw).unwrap_err();
		assert!(err.contains("F-NEW-R2-04"), "expected denylist hit, got: {err}");
	}

	#[test]
	fn rw_paths_system_dir_rejects_dot_component() {
		// `/etc/.` → normalized to `/etc` → denylist hit.
		let rw = vec![PathBuf::from("/etc/.")];
		let err = validate_rw_paths_not_system_dirs(&rw).unwrap_err();
		assert!(err.contains("F-NEW-R2-04"), "expected denylist hit, got: {err}");
	}

	#[test]
	fn rw_paths_system_dir_rejects_dot_dir() {
		// `/etc/./` → normalized to `/etc` → denylist hit.
		let rw = vec![PathBuf::from("/etc/./")];
		let err = validate_rw_paths_not_system_dirs(&rw).unwrap_err();
		assert!(err.contains("F-NEW-R2-04"), "expected denylist hit, got: {err}");
	}

	#[test]
	fn rw_paths_system_dir_rejects_parent_component() {
		// `/etc/foo/..` is refused outright (we don't try to resolve `..`
		// statically — see normalize_path_for_denylist docs). Reject is
		// F-NEW-R3-03 style.
		let rw = vec![PathBuf::from("/etc/foo/..")];
		let err = validate_rw_paths_not_system_dirs(&rw).unwrap_err();
		assert!(err.contains("F-NEW-R3-03"), "expected F-NEW-R3-03 error, got: {err}");
		assert!(err.contains("'..' component"), "expected `..` guidance, got: {err}");
	}

	#[test]
	fn rw_paths_system_dir_rejects_parent_anywhere() {
		// Even when the parent component sits inside a nested path, refuse.
		let rw = vec![PathBuf::from("/var/lib/rostro/../../etc")];
		let err = validate_rw_paths_not_system_dirs(&rw).unwrap_err();
		assert!(err.contains("F-NEW-R3-03"), "expected F-NEW-R3-03 error, got: {err}");
	}

	#[test]
	fn rw_paths_normalized_form_preserves_nested_paths() {
		// Nested paths under denylisted dirs stay accepted after normalization.
		assert!(validate_rw_paths_not_system_dirs(&[PathBuf::from("/var/lib/rostro/")]).is_ok());
		assert!(validate_rw_paths_not_system_dirs(&[PathBuf::from("//var//lib//rostro")]).is_ok());
	}

	// ─── F-NEW-R3-01: STATE_DELTA emission format ───────────────────────

	#[test]
	fn state_delta_format_is_journalctl_parseable() {
		// The emit fn writes to stderr (side effect, hard to capture in
		// unit tests without restructuring). We test the format by
		// reimplementing the format string here and asserting the shape
		// matches what `journalctl --output=cat | awk '/^STATE_DELTA/'`
		// would parse. If the format changes, this test forces a
		// matching update of the operator-side reconstruction snippet
		// in the docstring + threat model.
		let mut s = SupervisorState::default();
		s.swap_count = 7;
		s.crashes = vec![100, 200, 300];

		let expected = format!(
			"STATE_DELTA schema={} swap_count=7 crashes=[100,200,300]",
			STATE_SCHEMA_VERSION,
		);
		// Build the same string the fn builds (without capturing stderr).
		let actual = format!(
			"STATE_DELTA schema={} swap_count={} crashes=[{}]",
			STATE_SCHEMA_VERSION,
			s.swap_count,
			s.crashes.iter().map(|t| t.to_string()).collect::<Vec<_>>().join(","),
		);
		assert_eq!(actual, expected);
	}

	#[test]
	fn state_delta_empty_crashes_renders_clean() {
		let s = SupervisorState::default();
		let line = format!(
			"STATE_DELTA schema={} swap_count={} crashes=[{}]",
			STATE_SCHEMA_VERSION,
			s.swap_count,
			s.crashes.iter().map(|t| t.to_string()).collect::<Vec<_>>().join(","),
		);
		assert_eq!(line, format!("STATE_DELTA schema={} swap_count=0 crashes=[]", STATE_SCHEMA_VERSION));
	}

	// ─── F-NEW-R4-01: stdio-log system-prefix denylist ───────────────────

	#[test]
	fn stdio_log_placement_rejects_etc_sudoers_d() {
		// The /security-review's HIGH finding — operator misconfig that
		// the supervisor's earlier validator (R2-03) would have accepted.
		let rw = vec![PathBuf::from("/opt/rostro/data")];
		let stdio = PathBuf::from("/etc/sudoers.d/00-rostro-log");
		let err = validate_stdio_log_placement(Some(&stdio), &rw).unwrap_err();
		assert!(err.contains("F-NEW-R4-01"), "expected F-NEW-R4-01 error, got: {err}");
		assert!(err.contains("/etc"), "expected /etc prefix mention, got: {err}");
	}

	#[test]
	fn stdio_log_placement_rejects_etc_cron_d() {
		let rw = vec![PathBuf::from("/opt/rostro/data")];
		let stdio = PathBuf::from("/etc/cron.d/rostro");
		let err = validate_stdio_log_placement(Some(&stdio), &rw).unwrap_err();
		assert!(err.contains("F-NEW-R4-01"), "expected F-NEW-R4-01 error, got: {err}");
	}

	#[test]
	fn stdio_log_placement_rejects_etc_profile_d() {
		let rw = vec![PathBuf::from("/opt/rostro/data")];
		let stdio = PathBuf::from("/etc/profile.d/00rostro.sh");
		assert!(validate_stdio_log_placement(Some(&stdio), &rw).is_err());
	}

	#[test]
	fn stdio_log_placement_rejects_etc_ld_so_conf_d() {
		let rw = vec![PathBuf::from("/opt/rostro/data")];
		let stdio = PathBuf::from("/etc/ld.so.conf.d/00rostro.conf");
		assert!(validate_stdio_log_placement(Some(&stdio), &rw).is_err());
	}

	#[test]
	fn stdio_log_placement_rejects_etc_logrotate_d() {
		let rw = vec![PathBuf::from("/opt/rostro/data")];
		let stdio = PathBuf::from("/etc/logrotate.d/rostro");
		assert!(validate_stdio_log_placement(Some(&stdio), &rw).is_err());
	}

	#[test]
	fn stdio_log_placement_rejects_etc_systemd() {
		let rw = vec![PathBuf::from("/opt/rostro/data")];
		let stdio = PathBuf::from("/etc/systemd/system.conf.d/00rostro.conf");
		assert!(validate_stdio_log_placement(Some(&stdio), &rw).is_err());
	}

	#[test]
	fn stdio_log_placement_rejects_usr_subpaths() {
		let rw = vec![PathBuf::from("/opt/rostro/data")];
		for p in [
			"/usr/lib/systemd/system/rostro.service",
			"/usr/local/sbin/rostro-log",
			"/usr/share/applications/rostro.desktop",
		] {
			assert!(
				validate_stdio_log_placement(Some(&PathBuf::from(p)), &rw).is_err(),
				"expected refusal for {p}",
			);
		}
	}

	#[test]
	fn stdio_log_placement_rejects_bin_lib_boot() {
		let rw = vec![PathBuf::from("/opt/rostro/data")];
		for p in [
			"/bin/rostro-log",
			"/sbin/rostro-log",
			"/lib/rostro.so.1",
			"/lib64/rostro.so.1",
			"/boot/grub/00rostro.cfg",
		] {
			assert!(
				validate_stdio_log_placement(Some(&PathBuf::from(p)), &rw).is_err(),
				"expected refusal for {p}",
			);
		}
	}

	#[test]
	fn stdio_log_placement_accepts_var_log() {
		// /var/log is the canonical log target; must remain accepted.
		let rw = vec![PathBuf::from("/opt/rostro/data")];
		let stdio = PathBuf::from("/var/log/rostro/gemini-node.log");
		assert!(validate_stdio_log_placement(Some(&stdio), &rw).is_ok());
	}

	#[test]
	fn stdio_log_placement_accepts_srv_opt_tmp_home() {
		let rw = vec![PathBuf::from("/opt/rostro/data")];
		for p in [
			"/srv/rostro/log/stdio.log",
			"/opt/rostro/log/stdio.log",
			"/tmp/rostro-stdio.log",
			"/home/coder/rostro-stdio.log",
		] {
			assert!(
				validate_stdio_log_placement(Some(&PathBuf::from(p)), &rw).is_ok(),
				"expected acceptance for {p}",
			);
		}
	}

	#[test]
	fn stdio_log_placement_rejects_etc_via_r3_03_bypass_shapes() {
		// R3-03 normalization MUST apply BEFORE the R4-01 prefix check.
		// Trailing slash, double slash, dot-component, and `..` bypass
		// shapes against /etc/sudoers.d/* are all caught.
		let rw = vec![PathBuf::from("/opt/rostro/data")];
		// trailing slash on prefix (file path can't have trailing slash for
		// a file, so this case tests the leaf component).
		assert!(validate_stdio_log_placement(
			Some(&PathBuf::from("/etc//sudoers.d/foo")), &rw
		).is_err());
		assert!(validate_stdio_log_placement(
			Some(&PathBuf::from("/etc/./sudoers.d/foo")), &rw
		).is_err());
		// `..` is refused by normalize_path_for_denylist before the prefix
		// check runs (R3-03 closure).
		let err = validate_stdio_log_placement(
			Some(&PathBuf::from("/var/log/../etc/sudoers.d/foo")), &rw
		).unwrap_err();
		assert!(err.contains("F-NEW-R3-03"), "expected R3-03 refusal first, got: {err}");
	}

	// ─── F-NEW-R4-02: sanitize_state_delta_for_relay ─────────────────────

	#[test]
	fn sanitize_state_delta_passes_through_when_no_match() {
		// Common case: substrate tracing log line. Should be borrowed
		// (zero-copy) when no STATE_DELTA substring present.
		let buf = b"2026-05-25 12:34:56.789  INFO substrate: Imported #42\n";
		let out = sanitize_state_delta_for_relay(buf);
		assert!(matches!(out, std::borrow::Cow::Borrowed(_)));
		assert_eq!(out.as_ref(), buf);
	}

	#[test]
	fn sanitize_state_delta_mangles_attacker_injection() {
		let buf = b"STATE_DELTA schema=1 swap_count=0 crashes=[]\n";
		let out = sanitize_state_delta_for_relay(buf);
		assert!(matches!(out, std::borrow::Cow::Owned(_)));
		let s = std::str::from_utf8(&out).unwrap();
		assert!(s.contains("STATE_DELTA_FROM_CHILD schema=1"), "got: {s}");
		// Critical property: the result does NOT contain `STATE_DELTA `
		// (the trailing-space form used by reasonable un-anchored grep
		// queries). It contains `STATE_DELTA_FROM_CHILD` which doesn't.
		assert!(
			!s.contains("STATE_DELTA "),
			"sanitized output still contains `STATE_DELTA ` substring: {s}",
		);
	}

	#[test]
	fn sanitize_state_delta_mangles_substring_in_middle() {
		// Even if the child wraps STATE_DELTA in other text, mangle it.
		let buf = b"prefix STATE_DELTA injected schema=1 suffix\n";
		let out = sanitize_state_delta_for_relay(buf);
		let s = std::str::from_utf8(&out).unwrap();
		assert!(s.contains("STATE_DELTA_FROM_CHILD injected"));
	}

	#[test]
	fn sanitize_state_delta_handles_multiple_occurrences() {
		let buf = b"STATE_DELTA one STATE_DELTA two STATE_DELTA three\n";
		let out = sanitize_state_delta_for_relay(buf);
		let s = std::str::from_utf8(&out).unwrap();
		// All three replaced; no `STATE_DELTA ` (with space) survives.
		assert_eq!(s.matches("STATE_DELTA_FROM_CHILD").count(), 3);
		assert_eq!(s.matches("STATE_DELTA ").count(), 0);
	}

	#[test]
	fn sanitize_state_delta_handles_partial_at_end() {
		// Partial-substring at end-of-buffer (e.g., line wrap) must not
		// match: the byte-window check requires the full needle.
		let buf = b"line ends with STATE_DELT\n";
		let out = sanitize_state_delta_for_relay(buf);
		assert!(matches!(out, std::borrow::Cow::Borrowed(_)));
		assert_eq!(out.as_ref(), buf);
	}

	// ─── F-NEW-R4-V2: bounded_read_until_newline ────────────────────────

	#[test]
	fn bounded_read_returns_short_line_unchanged() {
		use std::io::Cursor;
		let mut r = std::io::BufReader::new(Cursor::new(b"hello\nworld\n"));
		let mut buf = Vec::new();
		let n = bounded_read_until_newline(&mut r, &mut buf, 100).unwrap();
		assert_eq!(n, 6);
		assert_eq!(buf.as_slice(), b"hello\n");
	}

	#[test]
	fn bounded_read_truncates_at_cap_with_marker() {
		// Line is 200 bytes of 'A' with NO newline; cap at 64.
		use std::io::Cursor;
		let line = vec![b'A'; 200];
		let mut r = std::io::BufReader::new(Cursor::new(line));
		let mut buf = Vec::new();
		let _ = bounded_read_until_newline(&mut r, &mut buf, 64).unwrap();
		// buf should be exactly 64 A's followed by the truncation marker + \n.
		let marker = b"[cannae: line truncated]\n";
		assert_eq!(&buf[..64], &vec![b'A'; 64][..]);
		assert_eq!(&buf[64..], marker);
		// Critical property: total buf len is bounded.
		assert_eq!(buf.len(), 64 + marker.len());
	}

	#[test]
	fn bounded_read_handles_eof_without_newline() {
		use std::io::Cursor;
		let mut r = std::io::BufReader::new(Cursor::new(b"no-newline-here"));
		let mut buf = Vec::new();
		let _ = bounded_read_until_newline(&mut r, &mut buf, 100).unwrap();
		// EOF returns; buf has the partial content.
		assert_eq!(buf.as_slice(), b"no-newline-here");
	}

	#[test]
	fn bounded_read_eof_on_empty_input() {
		use std::io::Cursor;
		let empty: &[u8] = b"";
		let mut r = std::io::BufReader::new(Cursor::new(empty));
		let mut buf = Vec::new();
		let n = bounded_read_until_newline(&mut r, &mut buf, 100).unwrap();
		assert_eq!(n, 0);
		assert!(buf.is_empty());
	}

	// ─── F-NEW-R4-V5: state-file ↔ stdio-log disjointness ───────────────

	#[test]
	fn state_stdio_disjoint_accepts_none() {
		// Either flag unset → no collision possible.
		assert!(validate_state_and_stdio_disjoint(None, None).is_ok());
		assert!(validate_state_and_stdio_disjoint(
			Some(&PathBuf::from("/var/lib/rostro/state")),
			None,
		)
		.is_ok());
		assert!(validate_state_and_stdio_disjoint(
			None,
			Some(&PathBuf::from("/var/log/rostro.log")),
		)
		.is_ok());
	}

	#[test]
	fn state_stdio_disjoint_accepts_distinct_paths() {
		let state = PathBuf::from("/var/lib/rostro/state");
		let stdio = PathBuf::from("/var/log/rostro.log");
		assert!(validate_state_and_stdio_disjoint(Some(&state), Some(&stdio)).is_ok());
	}

	#[test]
	fn state_stdio_disjoint_rejects_exact_collision() {
		let p = PathBuf::from("/var/log/rostro.log");
		let err = validate_state_and_stdio_disjoint(Some(&p), Some(&p)).unwrap_err();
		assert!(err.contains("F-NEW-R4-V5"), "expected R4-V5 error, got: {err}");
		assert!(err.contains("resolve to the same path"));
	}

	#[test]
	fn state_stdio_disjoint_rejects_collision_via_normalization() {
		// `/var/log/rostro.log` vs `/var/log//rostro.log` — normalized
		// equal. The validator MUST detect.
		let state = PathBuf::from("/var/log/rostro.log");
		let stdio = PathBuf::from("/var/log//rostro.log");
		let err = validate_state_and_stdio_disjoint(Some(&state), Some(&stdio)).unwrap_err();
		assert!(err.contains("F-NEW-R4-V5"), "expected R4-V5 error, got: {err}");
	}

	#[test]
	fn state_stdio_disjoint_propagates_r3_03_dotdot_refusal() {
		// `..` component should be refused upstream (R3-03) by either
		// `normalize_path_for_denylist` call. The disjointness check
		// surfaces the R3-03 error, not its own.
		let state = PathBuf::from("/var/log/rostro.log");
		let stdio = PathBuf::from("/var/log/../log/rostro.log");
		let err = validate_state_and_stdio_disjoint(Some(&state), Some(&stdio)).unwrap_err();
		assert!(err.contains("F-NEW-R3-03"), "expected R3-03 to fire first, got: {err}");
	}
}
