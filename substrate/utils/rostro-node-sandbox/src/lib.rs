// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! `rostro-node-sandbox` — implementation of **Aegis**, the host-level
//! isolation envelope applied by `rostro-supervisor` before exec'ing
//! the node binary.
//!
//! "Aegis" is the user-facing name (matches the Gemini / Star phase
//! naming arc). The crate name stays descriptive so external readers
//! can find it; operator-facing log lines use `Aegis: ...`.
//!
//! ## What this is
//!
//! A small crate that exposes one entry point — [`install`] — which
//! the supervisor calls immediately before spawning `gemini-node`. The
//! call installs three Linux primitives on the current process:
//!
//! 1. **cgroup v2 self-cap** — memory + cpu caps + `cgroup.kill` on
//!    OOM, scoped to the supervisor + its child.
//! 2. **Landlock filesystem ruleset** — RW to the operator-supplied
//!    data paths, RO to chain spec + canonical files dir, deny everywhere
//!    else.
//! 3. **seccomp-bpf allowlist** — `SECCOMP_RET_KILL_PROCESS` on
//!    violation, with `SECCOMP_FILTER_FLAG_TSYNC` so all threads of
//!    the child inherit the filter.
//!
//! After install, the policy applies to the calling process **and all
//! its descendants** and **cannot be relaxed by the same process**.
//! The supervisor then `exec`s the child, which wakes up already
//! inside the envelope.
//!
//! ## What this is NOT
//!
//! - **Not** per-call / per-instance isolation. RostroVM runs the
//!   trusted runtime blob; there's no per-extrinsic worker process.
//!   That model would apply to a future smart-contract layer, not the
//!   chain runtime. See memory `rostro_vm_unsandboxed.md` for the gap
//!   analysis that motivated this crate.
//! - **Not** a defense against bugs in the kernel itself; the
//!   isolation surface is "what the kernel agrees to deny." Kernel
//!   CVEs are a separate threat track.
//! - **Not** cross-platform yet. Linux is the only strong path;
//!   Windows/macOS return [`SandboxError::PlatformUnsupported`].
//!   See memory `testnet_linux_only_validators.md`.
//!
//! ## Phasing
//!
//! - **Phase 2 (this commit)** — crate scaffold: API surface, Config
//!   builder, error types, Linux stub that logs but installs nothing,
//!   non-Linux stub returning `PlatformUnsupported`. Caller-side
//!   integration (Phase 4) can already wire against this surface.
//! - **Phase 3a** — cgroup v2 self-cap inside `linux::install`.
//! - **Phase 3b** — Landlock ruleset.
//! - **Phase 3c** — seccomp-bpf allowlist.
//! - **Phase 4** — supervisor calls into this crate before exec.
//! - **Phase 5** — real-Linux validation on Hetzner. Runbook lives at
//!   `VALIDATION.md` in the crate root; re-run whenever the allowlist
//!   or Landlock baseline changes.

#![deny(missing_docs)]

use std::path::PathBuf;

#[cfg(target_os = "linux")]
mod linux;

// ─── Config ────────────────────────────────────────────────────────────────

/// Operator-derived sandbox configuration. Built by the supervisor
/// from its CLI args; consumed by [`install`].
///
/// Construct via [`NodeSandboxConfig::new`] and the builder methods.
#[derive(Debug, Clone, Default)]
pub struct NodeSandboxConfig {
	rw_paths: Vec<PathBuf>,
	ro_paths: Vec<PathBuf>,
	memory_max_bytes: Option<u64>,
	cpu_max_micros: Option<(u64, u64)>,
	cgroup_root: Option<PathBuf>,
}

impl NodeSandboxConfig {
	/// Construct an empty config. At minimum, callers should add the
	/// node's base path via [`Self::add_rw_path`] before calling
	/// [`install`], or the node won't be able to write its database.
	pub fn new() -> Self {
		Self::default()
	}

	/// Add a path the node may read AND write inside the sandbox.
	/// Typical: `--base-path` (RocksDB + keystore), log file.
	pub fn add_rw_path(mut self, p: impl Into<PathBuf>) -> Self {
		self.rw_paths.push(p.into());
		self
	}

	/// Add a path the node may read but not write inside the sandbox.
	/// Typical: chain spec file, canonical-files directory,
	/// `--node-key-file`.
	pub fn add_ro_path(mut self, p: impl Into<PathBuf>) -> Self {
		self.ro_paths.push(p.into());
		self
	}

	/// Cap the cgroup's `memory.max` (bytes). Exceeding this triggers
	/// `cgroup.kill`, which signals all PIDs in the cgroup; the
	/// supervisor's crash-restart pathway then engages.
	pub fn memory_max_bytes(mut self, bytes: u64) -> Self {
		self.memory_max_bytes = Some(bytes);
		self
	}

	/// Cap CPU usage via cgroup v2 `cpu.max` semantics: `max`
	/// microseconds of cpu time per `period` microseconds. Pass
	/// `(50_000, 100_000)` for half a core, `(200_000, 100_000)` for
	/// two cores, etc.
	pub fn cpu_max(mut self, max_micros: u64, period_micros: u64) -> Self {
		self.cpu_max_micros = Some((max_micros, period_micros));
		self
	}

	/// Override the cgroup v2 root mount point. Default is
	/// `/sys/fs/cgroup`. Override for cgroup-namespace setups or for
	/// tests against a tmpfs.
	pub fn cgroup_root(mut self, p: impl Into<PathBuf>) -> Self {
		self.cgroup_root = Some(p.into());
		self
	}

	/// Read-write path list — public for callers that build the
	/// config and want to log/inspect it.
	pub fn rw_paths(&self) -> &[PathBuf] {
		&self.rw_paths
	}

	/// Read-only path list.
	pub fn ro_paths(&self) -> &[PathBuf] {
		&self.ro_paths
	}

	/// Memory cap if set.
	pub fn memory_cap(&self) -> Option<u64> {
		self.memory_max_bytes
	}

	/// CPU cap if set, returned as `(max_micros, period_micros)`.
	pub fn cpu_cap(&self) -> Option<(u64, u64)> {
		self.cpu_max_micros
	}

	/// Cgroup root (default `/sys/fs/cgroup` if unset).
	pub fn cgroup_root_or_default(&self) -> PathBuf {
		self.cgroup_root
			.clone()
			.unwrap_or_else(|| PathBuf::from("/sys/fs/cgroup"))
	}

	/// Validate the config. Run by [`install`] before touching any
	/// platform primitives; returns [`SandboxError::InvalidConfig`]
	/// on rejection.
	pub(crate) fn validate(&self) -> Result<(), SandboxError> {
		for p in self.rw_paths.iter().chain(self.ro_paths.iter()) {
			if !p.is_absolute() {
				return Err(SandboxError::InvalidConfig(format!(
					"sandbox paths must be absolute; got {}",
					p.display(),
				)));
			}
		}
		if let Some(0) = self.memory_max_bytes {
			return Err(SandboxError::InvalidConfig(
				"memory_max_bytes must be > 0 if set".into(),
			));
		}
		if let Some((max, period)) = self.cpu_max_micros {
			if max == 0 || period == 0 {
				return Err(SandboxError::InvalidConfig(
					"cpu_max max and period must both be > 0 if set".into(),
				));
			}
		}
		Ok(())
	}
}

// ─── Errors ────────────────────────────────────────────────────────────────

/// Failures the sandbox install can surface to the supervisor.
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
	/// A specific primitive (cgroup, landlock, seccomp) refused. The
	/// `primitive` is a short label for log routing; `reason` is the
	/// platform-specific description.
	#[error("sandbox install failed at {primitive}: {reason}")]
	InstallFailed {
		/// Short label identifying which primitive failed (e.g.
		/// `"cgroup"`, `"landlock"`, `"seccomp"`). Stable across
		/// minor revs so log scrapers can route on it.
		primitive: &'static str,
		/// Platform-specific description of the failure. Free-form;
		/// surface to operators for triage.
		reason: String,
	},
	/// The host platform doesn't have a strong sandbox implementation
	/// yet. Linux is the only supported target as of testnet
	/// (`testnet_linux_only_validators.md`).
	#[error("platform does not have a strong sandbox implementation yet")]
	PlatformUnsupported,
	/// The caller supplied a [`NodeSandboxConfig`] that was rejected
	/// before any primitive was touched — bad paths, zero caps, etc.
	#[error("invalid config: {0}")]
	InvalidConfig(String),
}

// ─── Public entry ──────────────────────────────────────────────────────────

/// Install the sandbox envelope on the current process. On success:
///
/// - The current process is bound to a cgroup v2 hierarchy. Children
///   spawned afterward must be moved into the `child` cgroup via
///   [`SandboxHandle::place_child_in_cgroup`] to inherit the caps.
/// - (Phase 3b) The current process and all descendants can only
///   access the filesystem paths specified in the config.
/// - (Phase 3c) The current process and all descendants can only
///   invoke the syscalls on the seccomp allowlist; violations trigger
///   `SECCOMP_RET_KILL_PROCESS`.
///
/// The policy cannot be relaxed by the same process after install;
/// the supervisor `exec`s the child immediately after this returns,
/// and the child inherits the envelope.
///
/// **Why two-tier cgroup**: a single cgroup with OOM-kill enabled
/// would take the supervisor down alongside the child on memory
/// pressure, defeating the restart pathway. The supervisor lives in
/// an outer cgroup (no caps); only the inner `child` cgroup carries
/// memory/cpu caps and `memory.oom.group=1`.
///
/// **Phase 3a status**: cgroup v2 self-cap landed; Landlock (3b) +
/// seccomp-bpf (3c) are stubs. On non-Linux, returns
/// [`SandboxError::PlatformUnsupported`].
pub fn install(config: &NodeSandboxConfig) -> Result<SandboxHandle, SandboxError> {
	config.validate()?;

	#[cfg(target_os = "linux")]
	{
		linux::install(config)
	}
	#[cfg(not(target_os = "linux"))]
	{
		let _ = config;
		Err(SandboxError::PlatformUnsupported)
	}
}

/// Returned by [`install`] on success. Carries the per-invocation
/// state the supervisor needs for follow-on operations (currently:
/// moving spawned child PIDs into the constrained cgroup).
#[derive(Debug)]
pub struct SandboxHandle {
	#[cfg(target_os = "linux")]
	pub(crate) cgroup_child: Option<std::path::PathBuf>,
}

impl SandboxHandle {
	/// Move a child PID into the constrained cgroup so the memory and
	/// cpu caps apply. Call this immediately after `Command::spawn`
	/// (before the child's first significant allocation, ideally).
	///
	/// If no cgroup was installed (no caps configured), this is a
	/// no-op; the supervisor can call it unconditionally.
	pub fn place_child_in_cgroup(&self, child_pid: u32) -> Result<(), SandboxError> {
		#[cfg(target_os = "linux")]
		{
			if let Some(p) = self.cgroup_child.as_deref() {
				return linux::write_cgroup_file(p, "cgroup.procs", &child_pid.to_string());
			}
		}
		let _ = child_pid;
		Ok(())
	}

	/// Inspect the child cgroup path, if any. Useful for logging in
	/// the supervisor; callers shouldn't write to this directly.
	#[cfg(target_os = "linux")]
	pub fn cgroup_child_path(&self) -> Option<&std::path::Path> {
		self.cgroup_child.as_deref()
	}

	/// Pending #7 fix (2026-05-24): drop `CAP_SYS_ADMIN` from the
	/// calling process's capability bounding set. Intended to be
	/// installed as a [`std::os::unix::process::CommandExt::pre_exec`]
	/// hook on the child binary — runs in the forked-but-not-yet-execed
	/// child, before its first instruction of gemini-node code.
	///
	/// **Why bounding-set drop and not just effective-set:** dropping
	/// from the bounding set is permanent for the process AND all its
	/// descendants — a process can never RAISE a cap above its bounding
	/// set, even via setuid binaries or `cap_raise`. Effective-set drops
	/// can be undone if other bits are still set. Bounding-set drop is
	/// the only one-way mechanism.
	///
	/// **Why CAP_SYS_ADMIN specifically:** the catch-all "root-can-do-
	/// anything" capability for ~30 admin operations including
	/// `mount(2)`, `setns(2)`, `unshare(NEWUSER)`, `pivot_root`,
	/// `quotactl`, `bpf(2)` (already denied at seccomp), `keyctl`,
	/// `swapon`, etc. With seccomp blocking most of these directly,
	/// dropping CAP_SYS_ADMIN closes any kernel path we missed — a
	/// future kernel might add a new admin operation whose syscall isn't
	/// in our deny list but whose semantics need CAP_SYS_ADMIN. This is
	/// belt-and-suspenders defense-in-depth, aligned with
	/// [[least_privilege_validator_principle]].
	///
	/// **Why pre_exec and not the supervisor's own drop:** the supervisor
	/// itself needs CAP_SYS_ADMIN (or root + CAP_DAC_OVERRIDE) to write
	/// `/sys/fs/cgroup/...` files during cgroup setup. Dropping in
	/// pre_exec — which runs AFTER the supervisor has done its setup
	/// but BEFORE the child becomes gemini-node — preserves the
	/// supervisor's ability while neutering the child.
	///
	/// **F07 prctl filter interaction:** `PR_CAPBSET_DROP` is explicitly
	/// allowed in `prctl_safe_options_rules`. The threat F07 named
	/// ("attacker drops caps for evasion") is countered by the fact
	/// that cap drops are monotone — calling `PR_CAPBSET_DROP` only
	/// REDUCES privilege, never adds.
	///
	/// `CAP_SYS_ADMIN` = 21 per `<linux/capability.h>`. libc has no
	/// constant for this; the literal is documented at use site.
	#[cfg(target_os = "linux")]
	pub fn drop_cap_sys_admin_in_child() -> std::io::Result<()> {
		// CAP_SYS_ADMIN per <linux/capability.h> — not in libc 0.2.
		const CAP_SYS_ADMIN: libc::c_ulong = 21;
		// SAFETY: prctl with PR_CAPBSET_DROP + a valid cap number has no
		// memory-safety implications; failure returns -1/errno per usual
		// syscall contract.
		let rc = unsafe {
			libc::prctl(libc::PR_CAPBSET_DROP, CAP_SYS_ADMIN, 0, 0, 0)
		};
		if rc != 0 {
			return Err(std::io::Error::last_os_error());
		}
		Ok(())
	}
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn config_builder_records_rw_paths() {
		let cfg = NodeSandboxConfig::new()
			.add_rw_path("/var/lib/rostro/db")
			.add_rw_path("/var/lib/rostro/keystore");
		assert_eq!(
			cfg.rw_paths(),
			&[
				PathBuf::from("/var/lib/rostro/db"),
				PathBuf::from("/var/lib/rostro/keystore"),
			]
		);
	}

	#[test]
	fn config_builder_records_ro_paths() {
		let cfg = NodeSandboxConfig::new()
			.add_ro_path("/etc/rostro/chain-spec.json")
			.add_ro_path("/opt/rostro/canonical");
		assert_eq!(
			cfg.ro_paths(),
			&[
				PathBuf::from("/etc/rostro/chain-spec.json"),
				PathBuf::from("/opt/rostro/canonical"),
			]
		);
	}

	#[test]
	fn config_memory_cap_round_trips() {
		let cfg = NodeSandboxConfig::new().memory_max_bytes(8 * 1024 * 1024 * 1024);
		assert_eq!(cfg.memory_cap(), Some(8 * 1024 * 1024 * 1024));
	}

	#[test]
	fn config_cpu_cap_round_trips() {
		let cfg = NodeSandboxConfig::new().cpu_max(200_000, 100_000);
		assert_eq!(cfg.cpu_cap(), Some((200_000, 100_000)));
	}

	#[test]
	fn config_cgroup_root_defaults_to_sys_fs() {
		let cfg = NodeSandboxConfig::new();
		assert_eq!(cfg.cgroup_root_or_default(), PathBuf::from("/sys/fs/cgroup"));
	}

	#[test]
	fn config_cgroup_root_override_round_trips() {
		let cfg = NodeSandboxConfig::new().cgroup_root("/tmp/test-cgroup");
		assert_eq!(cfg.cgroup_root_or_default(), PathBuf::from("/tmp/test-cgroup"));
	}

	#[test]
	fn validate_rejects_relative_rw_path() {
		let cfg = NodeSandboxConfig::new().add_rw_path("relative/path");
		match cfg.validate() {
			Err(SandboxError::InvalidConfig(msg)) => assert!(msg.contains("absolute")),
			other => panic!("expected InvalidConfig, got {other:?}"),
		}
	}

	#[test]
	fn validate_rejects_relative_ro_path() {
		let cfg = NodeSandboxConfig::new().add_ro_path("not/absolute");
		assert!(matches!(cfg.validate(), Err(SandboxError::InvalidConfig(_))));
	}

	#[test]
	fn validate_rejects_zero_memory_cap() {
		let cfg = NodeSandboxConfig::new().memory_max_bytes(0);
		assert!(matches!(cfg.validate(), Err(SandboxError::InvalidConfig(_))));
	}

	#[test]
	fn validate_rejects_zero_cpu_max() {
		let cfg = NodeSandboxConfig::new().cpu_max(0, 100_000);
		assert!(matches!(cfg.validate(), Err(SandboxError::InvalidConfig(_))));
	}

	#[test]
	fn validate_rejects_zero_cpu_period() {
		let cfg = NodeSandboxConfig::new().cpu_max(100_000, 0);
		assert!(matches!(cfg.validate(), Err(SandboxError::InvalidConfig(_))));
	}

	#[test]
	fn validate_accepts_empty_config() {
		// An empty config is valid — no caps, no paths. The Phase 2
		// scaffold permits this; Phase 3+ may tighten if e.g. running
		// with no rw_paths would brick the node.
		assert!(NodeSandboxConfig::new().validate().is_ok());
	}

	#[test]
	fn validate_accepts_well_formed_config() {
		let cfg = NodeSandboxConfig::new()
			.add_rw_path("/var/lib/rostro/db")
			.add_ro_path("/etc/rostro/chain-spec.json")
			.memory_max_bytes(8 * 1024 * 1024 * 1024)
			.cpu_max(200_000, 100_000);
		assert!(cfg.validate().is_ok());
	}

	// NOTE: there's no positive-path unit test calling the public
	// `install` directly. Once Phase 3b's Landlock branch runs
	// `restrict_self`, the calling thread becomes restricted — and
	// cargo's test runner reuses threads across tests, so any
	// subsequent test scheduled on that thread that touches paths
	// outside the ruleset would flake. End-to-end coverage of the
	// public `install` entry point lives in Phase 5 (real-Linux
	// Hetzner validation), not here. Unit tests in this module
	// cover the building blocks (config builder, validation,
	// `linux::install_cgroup`, `linux::build_landlock_ruleset`)
	// independently.

	#[cfg(not(target_os = "linux"))]
	#[test]
	fn install_returns_platform_unsupported_on_non_linux() {
		let cfg = NodeSandboxConfig::new();
		assert!(matches!(install(&cfg), Err(SandboxError::PlatformUnsupported)));
	}

	#[test]
	fn install_propagates_config_validation_failure() {
		// Even on Linux, a bad config should fail before touching any
		// primitives.
		let cfg = NodeSandboxConfig::new().add_rw_path("relative/path");
		assert!(matches!(install(&cfg), Err(SandboxError::InvalidConfig(_))));
	}

	#[test]
	fn error_install_failed_message_includes_primitive_and_reason() {
		let err = SandboxError::InstallFailed {
			primitive: "cgroup",
			reason: "permission denied".into(),
		};
		let msg = format!("{err}");
		assert!(msg.contains("cgroup"));
		assert!(msg.contains("permission denied"));
	}
}
