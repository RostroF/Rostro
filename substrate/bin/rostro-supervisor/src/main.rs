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
	fn save_atomic(&self, path: &Path) -> std::io::Result<()> {
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
		std::fs::write(&tmp, self.serialize())?;
		std::fs::rename(&tmp, path)?;
		Ok(())
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
					"Aegis: installed (cgroup={}, landlock={}, seccomp=enabled)",
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

		// Pending #7 fix (2026-05-24): drop CAP_SYS_ADMIN from the child
		// between fork() and execve(). Runs in the forked-but-pre-exec
		// child where seccomp + landlock are already inherited from
		// supervisor, but the new gemini-node image hasn't started. Drop
		// is to the bounding set so it's permanent + cannot be raised.
		// Supervisor itself keeps CAP_SYS_ADMIN to write cgroup files.
		// pre_exec only engages when the sandbox is active — skipping
		// when --unsafe-skip-sandbox so the diagnostic mode behaves
		// identically to pre-Pending-#7.
		#[cfg(target_os = "linux")]
		if sandbox_handle.is_some() {
			use std::os::unix::process::CommandExt;
			// SAFETY: closure is panic-free + thread-safe (single
			// prctl(2) call); pre_exec doc requires both.
			unsafe {
				cmd.pre_exec(SandboxHandle::drop_cap_sys_admin_in_child);
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
					if let Err(e) = state.save_atomic(p) {
						log::warn!("could not persist supervisor state to {}: {}", p.display(), e);
					}
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
					if let Err(e) = state.save_atomic(p) {
						log::warn!("could not persist supervisor state to {}: {}", p.display(), e);
					}
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
}
