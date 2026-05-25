// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! `rostro-node-sandbox` — implementation of **Cannae**, the host-level
//! isolation envelope applied by `rostro-supervisor` before exec'ing
//! the node binary.
//!
//! "Cannae" is the user-facing name — a nod to Hannibal's 216 BC
//! double envelopment, where a smaller force surrounded a larger one
//! through concentric tactical layering. The sandbox follows the
//! same shape: small auditable code surface, with cgroup + Landlock +
//! seccomp + UID drop + capability drops forming concentric layers
//! around a compromised validator's full ambient authority. Renamed
//! from "Cannae" after the Phase G work (2026-05-25) — see
//! `THREAT_MODEL.md`. The crate name stays descriptive so external
//! readers can find it; operator-facing log lines use `Cannae: ...`.
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
///
/// **Cleanup (Drop, 2026-05-24)**: when the handle is dropped (typically
/// supervisor exit), the per-invocation cgroup tree
/// `/sys/fs/cgroup/rostro-node-<sup_pid>/{child,}` is rmdir'd. Closes
/// red-team finding F-AGENT-C-04 (cgroup directory leak — debian-01
/// accumulated 196 stale entries during one red-team session). cgroup v2
/// requires the inner cgroup to be empty (no processes) before rmdir; if
/// the supervisor drops the handle while a child is still running, the
/// rmdir fails EBUSY and we log a warning rather than panic. Drop can't
/// propagate errors so this is best-effort by design.
#[derive(Debug)]
pub struct SandboxHandle {
	#[cfg(target_os = "linux")]
	pub(crate) cgroup_child: Option<std::path::PathBuf>,
}

#[cfg(target_os = "linux")]
impl Drop for SandboxHandle {
	fn drop(&mut self) {
		let Some(child) = self.cgroup_child.as_deref() else { return };
		// Inner cgroup first — must be empty (no procs) before parent.
		// We call unlinkat(AT_FDCWD, path, AT_REMOVEDIR) explicitly rather
		// than std::fs::remove_dir, which compiles to rmdir(2). rmdir
		// is NOT in PLAIN_ALLOWED_SYSCALLS (Phase 5 deliberately limited
		// to *at-family path syscalls; see comment above SYS_unlinkat at
		// linux.rs:693). Wave-2 verification confirmed std::fs::remove_dir
		// in this Drop body got SIGKILL'd by seccomp on every supervisor
		// exit, leaving cgroup directories to leak — exactly the
		// F-AGENT-C-04 reliability bug this Drop is meant to fix.
		// unlinkat IS allowed; same syscall under the hood for a dir
		// with AT_REMOVEDIR.
		let rmdir_at = |p: &std::path::Path| -> std::io::Result<()> {
			use std::os::unix::ffi::OsStrExt;
			let bytes = p.as_os_str().as_bytes();
			// Stack-allocated NUL-terminated buffer for paths <= 4095 bytes
			// (PATH_MAX). cgroup paths are ~80 chars in practice; the
			// PATH_MAX cap is defense against pathological inputs.
			if bytes.len() >= libc::PATH_MAX as usize {
				return Err(std::io::Error::new(
					std::io::ErrorKind::InvalidInput,
					"path exceeds PATH_MAX",
				));
			}
			let mut buf = [0u8; libc::PATH_MAX as usize];
			buf[..bytes.len()].copy_from_slice(bytes);
			// SAFETY: AT_FDCWD = -100 i32; cstr is NUL-terminated;
			// AT_REMOVEDIR is the documented flag for unlinkat-as-rmdir.
			let rc = unsafe {
				libc::unlinkat(
					libc::AT_FDCWD,
					buf.as_ptr() as *const libc::c_char,
					libc::AT_REMOVEDIR,
				)
			};
			if rc != 0 {
				return Err(std::io::Error::last_os_error());
			}
			Ok(())
		};
		if let Err(e) = rmdir_at(child) {
			log::warn!(
				"Cannae cgroup: failed to remove {} on drop: {e} \
				 (may leak; check /sys/fs/cgroup for stale rostro-node-* dirs)",
				child.display(),
			);
			// Don't even try the parent if the child rmdir failed —
			// the parent rmdir would fail with ENOTEMPTY anyway.
			return;
		}
		// Parent cgroup (rostro-node-<pid>) — should now be empty.
		if let Some(parent) = child.parent() {
			if let Err(e) = rmdir_at(parent) {
				log::warn!(
					"Cannae cgroup: failed to remove {} on drop: {e} \
					 (child cgroup removed but parent leaked)",
					parent.display(),
				);
			}
		}
	}
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

	/// F13 residual fix (2026-05-24): close every inherited fd above
	/// stdin/stdout/stderr in the forked-but-pre-exec child. Intended
	/// to run as a [`std::os::unix::process::CommandExt::pre_exec`]
	/// hook, BEFORE [`drop_cap_sys_admin_in_child`] (ordering is for
	/// auditability — neither depends on the other).
	///
	/// **Why:** F13 closed the fchmod-family via seccomp, but the
	/// underlying primitive (open /proc/self/fd/N to reopen an inherited
	/// fd with different mode) still works for any syscall we DIDN'T
	/// deny — most importantly `ftruncate(2)`, which RocksDB needs and
	/// so couldn't be denied outright. If the supervisor opened a file
	/// without `O_CLOEXEC`, the child inherits that fd; reopening via
	/// `/proc/self/fd/<N>` as `O_RDWR` lets the child truncate the file.
	///
	/// Rust's `std::fs::File` opens with `O_CLOEXEC` by default, but
	/// supervisor-side C dependencies (libsystemd journal socket,
	/// landlock-rs ruleset fds, sd_notify, glibc nss caches) may keep
	/// long-lived fds without the flag. Explicit close-range in pre_exec
	/// removes that uncertainty entirely.
	///
	/// Uses `close_range(2)` (Linux 5.9+, kernel commit `278a5fbaed89`).
	/// Falls back to ENOSYS-tolerant no-op on older kernels — those
	/// would need a manual `/proc/self/fd` walk, but our lab floor is
	/// 6.8 so the fallback is not implemented.
	///
	/// Phase G companion (2026-05-24): drop CAP_SETUID + CAP_SETGID +
	/// CAP_KILL from the bounding set so the post-UID-drop child cannot
	/// (a) reclaim root via `setresuid(0, 0, 0)` or (b) signal processes
	/// owned by other UIDs (kernel's `kill(2)` UID check requires
	/// CAP_KILL to cross UID boundaries). Runs AFTER
	/// [`drop_cap_sys_admin_in_child`] and BEFORE
	/// [`drop_to_uid_gid_in_child`] in the pre_exec chain. Same
	/// PR_CAPBSET_DROP mechanism as the CAP_SYS_ADMIN drop — permanent,
	/// monotone, requires CAP_SETPCAP in the caller's effective set (we
	/// still have it because we're still root at this point).
	///
	/// **CAP_SETPCAP is NOT dropped here.** PR_CAPBSET_DROP itself
	/// requires CAP_SETPCAP, so dropping it would prevent any further
	/// bounding-set tightening. Per capabilities(7) the cap is only
	/// dangerous if combined with file caps; the post-exec child has no
	/// file caps and is non-root so the effective set is zero anyway.
	///
	/// **CAP numbers per `<linux/capability.h>`:**
	///   CAP_SETUID = 7, CAP_SETGID = 6, CAP_KILL = 5.
	/// libc has no constants; literals documented at use site.
	#[cfg(target_os = "linux")]
	pub fn drop_root_caps_for_uid_drop_in_child() -> std::io::Result<()> {
		// SAFETY: same as drop_cap_sys_admin_in_child — single syscall,
		// scalar args, no memory deref. Failure returns -1/errno.
		for cap in [/* CAP_KILL */ 5, /* CAP_SETGID */ 6, /* CAP_SETUID */ 7] {
			let rc = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) };
			if rc != 0 {
				return Err(std::io::Error::last_os_error());
			}
		}
		Ok(())
	}

	/// Phase G fix (2026-05-24): drop the calling process to a non-root
	/// (uid, gid). Intended as the LAST pre_exec hook before exec — after
	/// [`close_inherited_fds_in_child`] and [`drop_cap_sys_admin_in_child`].
	///
	/// **Closes red-team findings** F-AGENT-C-01 (child writes
	/// `memory.swap.max=max` to its own cgroup file), F-AGENT-C-03 (child
	/// writes `memory.max=max` + `cpu.max="max 100000"` — full cgroup cap
	/// bypass), and F-AGENT-C-05 (child sends `kill(getppid(), SIGTERM)`
	/// to the supervisor). Root cause of all three: the child inherits
	/// root caps from the (setuid-root) supervisor. cgroup interface files
	/// are root-owned; DAC blocks non-root writes. `kill(2)` between
	/// different UIDs requires CAP_KILL (we don't grant it).
	///
	/// **Order matters:** must run AFTER `drop_cap_sys_admin_in_child` —
	/// `PR_CAPBSET_DROP` requires CAP_SETPCAP, which a non-root process
	/// without `PR_SET_KEEPCAPS=1` lacks. We don't set KEEPCAPS, so cap
	/// drops as root-then-uid-drop is the only working order. The
	/// supervisor registers these in order:
	///   (1) close_inherited_fds_in_child
	///   (2) drop_cap_sys_admin_in_child  (still root + caps)
	///   (3) drop_to_uid_gid_in_child     (loses caps + becomes uid)
	///
	/// **Order of (setgroups, setresgid, setresuid) inside this fn:**
	/// `setgroups` must come first — only root can call it, and we lose
	/// root after `setresuid`. Then `setresgid` (root can drop to any gid).
	/// Then `setresuid` (root → non-root; one-way, can't undo).
	#[cfg(target_os = "linux")]
	pub fn drop_to_uid_gid_in_child(uid: u32, gid: u32) -> std::io::Result<()> {
		if uid == 0 || gid == 0 {
			return Err(std::io::Error::new(
				std::io::ErrorKind::InvalidInput,
				format!(
					"refusing to drop to uid={uid} gid={gid}: zero defeats the \
					 purpose; pass a non-root --sandbox-child-uid"
				),
			));
		}
		// SAFETY: setgroups(0, NULL) drops all supplementary groups —
		// no memory dereference, single syscall. Must precede setresuid
		// (root-only operation).
		let rc = unsafe { libc::setgroups(0, std::ptr::null()) };
		if rc != 0 {
			return Err(std::io::Error::last_os_error());
		}
		// SAFETY: setresgid with three scalar args, no memory deref.
		let rc = unsafe { libc::setresgid(gid, gid, gid) };
		if rc != 0 {
			return Err(std::io::Error::last_os_error());
		}
		// SAFETY: setresuid with three scalar args, no memory deref.
		// This is the one-way step — after success, the process is
		// non-root and can never reclaim root unless it had a setuid
		// binary on a non-noexec path AND the bounding set still
		// includes CAP_SYS_ADMIN (we dropped it in step 2 above) AND
		// no further Landlock fs restriction (defense in depth still
		// holds).
		let rc = unsafe { libc::setresuid(uid, uid, uid) };
		if rc != 0 {
			return Err(std::io::Error::last_os_error());
		}
		Ok(())
	}

	/// F-NEW-01 + F-NEW-04 closure (2026-05-25): set per-resource rlimits
	/// on the child before exec. Bounds the burst-allocation window between
	/// `Command::spawn` (which returns after the child is already executing)
	/// and `place_child_in_cgroup` (which writes the child PID into
	/// `cgroup.procs`). During that window the child sits in the
	/// supervisor's inherited root cgroup with no `memory.max` /
	/// `swap.max=0` / `cpu.max` enforcement — cgroup v2 charges pages at
	/// allocation time and won't retroactively reclaim. A compromised
	/// static initializer (or a malicious runtime blob's startup hook) can
	/// `MADV_POPULATE_WRITE` multi-GB before the move-in lands, risking
	/// host-wide OOM that the cgroup's atomic-kill can't prevent.
	///
	/// **Mitigation shape**: `prlimit64(pid=0, …)` with `arg0 == 0` is
	/// already in the seccomp allowlist via [`super::linux::prlimit64_self_only_rules`],
	/// so this hook runs cleanly under the inherited filter. RLIMIT_AS is
	/// the load-bearing one — it bounds virtual address space, defeating
	/// the burst-mmap vector even before the cgroup applies. RLIMIT_NPROC
	/// caps fork bombs from inside the sandbox. RLIMIT_MEMLOCK = 0 denies
	/// `mlock`/`mlockall` outright; no Rostro path needs locked pages.
	///
	/// **Ordering**: must run while the hook still has CAP_SYS_RESOURCE
	/// (i.e., before [`drop_to_uid_gid_in_child`]). A non-root caller can
	/// only *lower* an rlimit, but lowering is exactly what we want; the
	/// CAP_SYS_RESOURCE point is defensive — if a future caller passes a
	/// limit higher than the inherited soft limit, only root can raise.
	/// Position in the chain: AFTER `close_inherited_fds_in_child` (any
	/// order vs. the cap drops), BEFORE `drop_to_uid_gid_in_child`.
	///
	/// `None` for any value leaves that rlimit at its inherited setting
	/// (operator opt-out). Pass `Some(0)` for hard refusal (e.g.
	/// `rlimit_memlock = Some(0)` is the default-deny for mlock).
	#[cfg(target_os = "linux")]
	pub fn apply_rlimits_in_child(
		rlimit_as_bytes: Option<u64>,
		rlimit_nproc: Option<u64>,
		rlimit_memlock_bytes: Option<u64>,
	) -> std::io::Result<()> {
		let set = |resource: u32, value: u64| -> std::io::Result<()> {
			let lim = libc::rlimit64 { rlim_cur: value, rlim_max: value };
			// SAFETY: prlimit64(pid=0, resource, &new_lim, NULL) — pid=0 means
			// self (the only shape allowed by `prlimit64_self_only_rules`).
			// `new_lim` is stack-allocated and valid for the duration of the
			// syscall; `old_lim` is NULL (we don't read the old value).
			let rc = unsafe {
				libc::prlimit64(
					0,
					resource,
					&lim as *const libc::rlimit64,
					std::ptr::null_mut(),
				)
			};
			if rc != 0 {
				return Err(std::io::Error::last_os_error());
			}
			Ok(())
		};
		if let Some(v) = rlimit_as_bytes {
			set(libc::RLIMIT_AS, v)?;
		}
		if let Some(v) = rlimit_nproc {
			set(libc::RLIMIT_NPROC, v)?;
		}
		if let Some(v) = rlimit_memlock_bytes {
			set(libc::RLIMIT_MEMLOCK, v)?;
		}
		Ok(())
	}

	/// `close_range` IS in the seccomp allowlist (sibling of `close`).
	#[cfg(target_os = "linux")]
	pub fn close_inherited_fds_in_child() -> std::io::Result<()> {
		// SAFETY: close_range(first, last, flags) closes fds in [first, last].
		// Range is "3..=UINT_MAX" — close everything except stdio. Failure
		// returns -1/errno per syscall contract. ENOSYS on kernel <5.9 is
		// the only expected error and is tolerated (best-effort hardening).
		let rc = unsafe {
			libc::syscall(
				libc::SYS_close_range,
				3 as libc::c_uint,
				libc::c_uint::MAX,
				0 as libc::c_uint,
			)
		};
		if rc != 0 {
			let err = std::io::Error::last_os_error();
			if err.raw_os_error() == Some(libc::ENOSYS) {
				// Pre-5.9 kernel; can't close inherited fds without a
				// /proc walk. Lab floor is 6.8 so this branch is unused.
				// Don't fail the spawn — the F13 residual remains open
				// on truly ancient kernels but the rest of the sandbox
				// still applies.
				return Ok(());
			}
			return Err(err);
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
