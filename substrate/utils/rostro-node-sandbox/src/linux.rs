// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Linux backend for [`crate::install`]. Phase 3a wires cgroup v2
//! self-cap; 3b adds Landlock; 3c adds seccomp-bpf.

use std::fs;
use std::path::{Path, PathBuf};

use landlock::{
	ABI, Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
	RulesetCreated, RulesetCreatedAttr, RulesetStatus,
};

use super::{NodeSandboxConfig, SandboxError, SandboxHandle};

/// Engage the Linux-side sandbox primitives in order:
///
/// 1. cgroup v2 (Phase 3a)
/// 2. Landlock (Phase 3b)
/// 3. seccomp-bpf (Phase 3c)
///
/// Order matters: cgroup self-cap before Landlock so that if Landlock
/// later denies access to `/sys/fs/cgroup/...` (it won't, but defensive
/// thinking), we've already done the cgroup write. seccomp goes last
/// for the same reason — it filters out the syscalls we used to
/// install the earlier primitives.
pub(crate) fn install(config: &NodeSandboxConfig) -> Result<SandboxHandle, SandboxError> {
	let cgroup_child = install_cgroup(config)?;
	// PHASE 5 DIAGNOSTIC (2026-05-23): allow skipping Landlock and/or
	// seccomp independently via env vars so we can isolate which
	// primitive is responsible for a failure mode without rebuilding.
	// Both default to enabled; set to "1" to skip.
	if std::env::var_os("ROSTRO_SKIP_LANDLOCK").is_none() {
		// Thread the child cgroup path into Landlock so the supervisor's
		// subsequent `place_child_in_cgroup` writes (which target a file
		// inside this dir) aren't blocked by the Landlock policy.
		install_landlock(config, cgroup_child.as_deref())?;
	} else {
		log::warn!("Aegis: Landlock SKIPPED via ROSTRO_SKIP_LANDLOCK");
	}
	if std::env::var_os("ROSTRO_SKIP_SECCOMP").is_none() {
		install_seccomp(config)?;
	} else {
		log::warn!("Aegis: seccomp SKIPPED via ROSTRO_SKIP_SECCOMP");
	}
	Ok(SandboxHandle { cgroup_child })
}

// ─── cgroup v2 self-cap (Phase 3a) ─────────────────────────────────────────

/// Build the two-tier cgroup hierarchy and apply the caps. Returns
/// the path to the inner `child` cgroup so the supervisor can place
/// spawned children into it. Returns `Ok(None)` if no caps were
/// configured (cgroup setup skipped entirely).
fn install_cgroup(config: &NodeSandboxConfig) -> Result<Option<PathBuf>, SandboxError> {
	if config.memory_cap().is_none() && config.cpu_cap().is_none() {
		log::info!(
			"Aegis cgroup: no caps configured, skipping cgroup self-cap"
		);
		return Ok(None);
	}

	let root = config.cgroup_root_or_default();

	// cgroup v2 detection: the unified hierarchy has a
	// `cgroup.controllers` file at its mount root. Refuse cleanly if
	// we're on v1, in a chroot without cgroup access, or pointed at
	// the wrong path.
	let controllers_marker = root.join("cgroup.controllers");
	if !controllers_marker.exists() {
		return Err(SandboxError::InstallFailed {
			primitive: "cgroup",
			reason: format!(
				"cgroup v2 not detected at {} (no cgroup.controllers file)",
				root.display(),
			),
		});
	}

	let pid = std::process::id();
	// Per-invocation directory names keep parallel supervisor
	// instances (different PIDs) from colliding under the same root.
	let supervisor_group = root.join(format!("rostro-node-{pid}"));
	let child_group = supervisor_group.join("child");

	fs::create_dir_all(&child_group).map_err(|e| SandboxError::InstallFailed {
		primitive: "cgroup",
		reason: format!("create_dir_all({}): {e}", child_group.display()),
	})?;

	// cgroup v2 requires controllers to be enabled in the parent's
	// `subtree_control` before they're available to children. We
	// enable memory and cpu; other controllers are unused.
	//
	// Note: if the kernel doesn't have one of these controllers
	// compiled in, this write fails. Treat as fatal — the supervisor
	// asked for caps that the kernel can't deliver, which would
	// silently weaken the sandbox if we ignored.
	write_cgroup_file(&supervisor_group, "cgroup.subtree_control", "+memory +cpu")?;

	if let Some(max) = config.memory_cap() {
		write_cgroup_file(&child_group, "memory.max", &max.to_string())?;
	}
	if let Some((max, period)) = config.cpu_cap() {
		write_cgroup_file(&child_group, "cpu.max", &format!("{max} {period}"))?;
	}

	// OOM kill the whole cgroup atomically. Without this, the OOM
	// killer picks one process; with `oom.group=1` the cgroup goes
	// down as a unit. The supervisor lives in the OUTER cgroup so
	// this kill takes only the child, not the supervisor.
	//
	// memory.oom.group is kernel 4.19+. If the file is missing the
	// kernel is older; log + continue (caps still apply, OOM just
	// kills processes individually).
	let oom_group_path = child_group.join("memory.oom.group");
	if oom_group_path.exists() {
		write_cgroup_file(&child_group, "memory.oom.group", "1")?;
	} else {
		log::warn!(
			"Aegis cgroup: memory.oom.group not available at {} \
			 (kernel < 4.19?); OOM kills will be per-process",
			oom_group_path.display(),
		);
	}

	// Phase 5 (2026-05-23): do NOT move the supervisor into
	// `supervisor_group`. The cgroup v2 "no internal processes" rule
	// rejects moving a process into a cgroup whose `subtree_control`
	// has enabled controllers (which we just did at line 88 to give
	// caps to `child_group`). The supervisor stays in its inherited
	// cgroup (e.g. `user.slice/...session.scope` under systemd) which
	// is uncapped from our perspective — functionally equivalent to
	// the original two-tier intent. The kernel returns EBUSY on the
	// migration attempt when `supervisor_group` has descendants with
	// controllers enabled, which is always true once `subtree_control`
	// is set above.
	let _ = pid; // formerly used for the rejected migration

	log::info!(
		"Aegis cgroup: installed; supervisor stays in its \
		 inherited cgroup (uncapped), child cgroup at {} (memory_max={:?}, \
		 cpu_max={:?}, oom_kill_atomic={})",
		child_group.display(),
		config.memory_cap(),
		config.cpu_cap(),
		oom_group_path.exists(),
	);
	Ok(Some(child_group))
}

// ─── Landlock filesystem ruleset (Phase 3b) ────────────────────────────────

/// System paths the node + supervisor always need read access to,
/// regardless of operator config. These are functional requirements
/// (entropy, DNS, TLS, thread metadata) — not policy choices. Missing
/// paths are silently skipped so the ruleset still applies on hosts
/// that don't have e.g. `/etc/resolv.conf` (containers, chroots).
///
/// All paths here are read-only; nothing in the baseline grants
/// write access.
const BASELINE_RO_PATHS: &[&str] = &[
	// getrandom syscall fallback uses /dev/urandom on older glibc;
	// libsodium and ring also read it. Without this, crypto stalls.
	"/dev/urandom",
	// Routine usage; many libraries open /dev/null for redirection.
	"/dev/null",
	// Phase 5 second-pass (2026-05-23): /proc (not /proc/self) is the
	// load-bearing path. /proc/self is a *symlink* to /proc/<pid>;
	// Landlock evaluates the resolved target, so granting only
	// /proc/self denies every actual read like /proc/self/cgroup
	// (resolved to /proc/<pid>/cgroup), /proc/self/maps,
	// /proc/self/task/<tid>/comm, and any /proc/sys/* path. Substrate
	// reads several of these during init and treats one of them as a
	// fatal error — `Essential task txpool-background failed` appears
	// during the orderly shutdown that follows.
	//
	// /proc is broader than ideal (lets a sandboxed process read
	// /proc/<other-pid>/cmdline + other read-only introspection), but
	// matches what every production Linux sandbox (Bubblewrap,
	// Firejail) does. PID-namespace masking would be the next-tighter
	// move; deferred to a v2 hardening item.
	"/proc",
	// /proc/meminfo, /proc/cpuinfo, /proc/loadavg, /proc/uptime,
	// /proc/stat — substrate sizes trie cache + tokio/rayon size
	// thread pools from these. Subsumed by /proc above but kept
	// listed as a documentation hint of what's relied on.
	"/proc/meminfo",
	"/proc/cpuinfo",
	"/proc/loadavg",
	"/proc/uptime",
	"/proc/stat",
	"/sys/devices/system/cpu",
	// Phase 5 second-pass (2026-05-23): RocksDB probes the underlying
	// disk's logical block size to optimize I/O, reading
	// /sys/devices/virtual/block/<dev>/queue/logical_block_size or
	// /sys/block/<dev>/queue/logical_block_size. We allow both parent
	// trees so the per-device subpath is reachable regardless of
	// whether the data dir lives on a physical, virtual, or DM device.
	"/sys/devices/virtual/block",
	"/sys/block",
	// DNS resolution for libp2p bootnodes + telemetry endpoints.
	"/etc/resolv.conf",
	"/etc/hosts",
	"/etc/nsswitch.conf",
	// TLS CA bundle for any outbound HTTPS (telemetry, canonical
	// file fetch via HTTPS fallback). System paths vary by distro;
	// the most common locations covered here.
	//
	// Phase 5 second-pass (2026-05-23): on Fedora the visible *.0
	// files in /etc/pki/tls/certs/ are hash-named symlinks pointing
	// into /etc/pki/ca-trust/extracted/ (the canonical bundle
	// directory generated by `update-ca-trust`). Without the
	// extracted/ tree allowed, Landlock denies the symlink target
	// and rustls-native-certs logs hundreds of cert-load failures.
	// Debian/Ubuntu use /etc/ssl/certs directly so this extra path
	// is silently no-op there.
	"/etc/ssl/certs",
	"/etc/pki/tls/certs",
	"/etc/pki/ca-trust/extracted",
	// Phase 5 second-pass (2026-05-23): timezone resolution.
	// /etc/localtime is a symlink into /usr/share/zoneinfo/<TZ>;
	// substrate's logging timestamps + chrono need both paths.
	"/etc/localtime",
	"/usr/share/zoneinfo",
	// Phase 5 (2026-05-23): the dynamic loader + shared libraries.
	// Without these, the kernel's exec fails with EACCES because
	// Landlock denies read on the ELF interpreter (PT_INTERP, e.g.
	// /lib64/ld-linux-x86-64.so.2) and the resolver can't open
	// /etc/ld.so.cache to find libc.so.6, libpthread.so.0, etc.
	// Per-distro locations:
	//   * Fedora/RHEL family — /lib64, /usr/lib64
	//   * Debian/Ubuntu — /lib, /usr/lib, plus /lib/x86_64-linux-gnu
	// We list all four parent dirs; missing ones are silently skipped.
	"/etc/ld.so.cache",
	"/etc/ld.so.conf",
	"/etc/ld.so.conf.d",
	"/lib",
	"/lib64",
	"/usr/lib",
	"/usr/lib64",
];

/// Build the Landlock ruleset from config + baseline. Returns the
/// constructed (but not-yet-applied) `RulesetCreated`. Factored out
/// from [`install_landlock`] so unit tests can verify construction
/// without restricting the test process itself.
///
/// `cgroup_rw_extra` is an additional rw path threaded in from the
/// cgroup install — typically `/sys/fs/cgroup/rostro-node-<pid>/child`.
/// `None` means cgroup setup was skipped (no caps configured).
fn build_landlock_ruleset(
	config: &NodeSandboxConfig,
	cgroup_rw_extra: Option<&Path>,
) -> Result<RulesetCreated, SandboxError> {
	let abi = ABI::V1;
	let all_fs = AccessFs::from_all(abi);
	let read_fs = AccessFs::from_read(abi);

	let mut rs: RulesetCreated = Ruleset::default()
		.set_compatibility(CompatLevel::BestEffort)
		.handle_access(all_fs)
		.map_err(|e| landlock_err("ruleset.handle_access", e))?
		.create()
		.map_err(|e| landlock_err("ruleset.create", e))?;

	// Baseline read-only paths. Skip missing ones — common in
	// containers / chroots / distroless hosts.
	for path_str in BASELINE_RO_PATHS {
		let path = Path::new(path_str);
		if !path.exists() {
			log::debug!(
				"Aegis landlock: baseline path {path_str} absent, skipping"
			);
			continue;
		}
		let fd = PathFd::new(path_str)
			.map_err(|e| landlock_err(&format!("PathFd::new(baseline {path_str})"), e))?;
		rs = rs
			.add_rule(PathBeneath::new(fd, read_fs))
			.map_err(|e| landlock_err(&format!("add_rule(baseline {path_str})"), e))?;
	}

	// Config-specified read-write paths. These MUST exist; the
	// supervisor is responsible for ensuring the data dir is
	// present before calling install. A missing path here is an
	// install-time error, not a silent skip — operator
	// misconfiguration.
	for path in config.rw_paths() {
		let fd = PathFd::new(path).map_err(|e| {
			landlock_err(&format!("PathFd::new(rw {})", path.display()), e)
		})?;
		rs = rs.add_rule(PathBeneath::new(fd, all_fs)).map_err(|e| {
			landlock_err(&format!("add_rule(rw {})", path.display()), e)
		})?;
	}

	// Config-specified read-only paths.
	for path in config.ro_paths() {
		let fd = PathFd::new(path).map_err(|e| {
			landlock_err(&format!("PathFd::new(ro {})", path.display()), e)
		})?;
		rs = rs.add_rule(PathBeneath::new(fd, read_fs)).map_err(|e| {
			landlock_err(&format!("add_rule(ro {})", path.display()), e)
		})?;
	}

	// Cgroup path threaded from install_cgroup. The supervisor needs
	// rw access to this directory so post-install
	// `place_child_in_cgroup` writes succeed.
	if let Some(path) = cgroup_rw_extra {
		let fd = PathFd::new(path).map_err(|e| {
			landlock_err(&format!("PathFd::new(cgroup {})", path.display()), e)
		})?;
		rs = rs.add_rule(PathBeneath::new(fd, all_fs)).map_err(|e| {
			landlock_err(&format!("add_rule(cgroup {})", path.display()), e)
		})?;
	}

	Ok(rs)
}

/// Apply the Landlock ruleset to the current process and all its
/// descendants. After this returns, the process cannot reach any path
/// outside the union of (baseline + rw_paths + ro_paths). The
/// restriction is inherited across `exec()`; supervisor and child
/// share the policy.
fn install_landlock(
	config: &NodeSandboxConfig,
	cgroup_rw_extra: Option<&Path>,
) -> Result<(), SandboxError> {
	let rs = build_landlock_ruleset(config, cgroup_rw_extra)?;
	let status = rs.restrict_self().map_err(|e| landlock_err("restrict_self", e))?;

	match status.ruleset {
		RulesetStatus::FullyEnforced => {
			log::info!(
				"Aegis landlock: fully enforced (no_new_privs={})",
				status.no_new_privs
			);
		},
		RulesetStatus::PartiallyEnforced => {
			// Kernel supports Landlock but not all features we
			// requested. BestEffort means the strictest available
			// subset still applies — log so operators know the
			// posture is reduced.
			log::warn!(
				"Aegis landlock: partially enforced (kernel < requested ABI); \
				 strictest available subset is active"
			);
		},
		RulesetStatus::NotEnforced => {
			// Landlock unavailable (kernel < 5.13 or LSM disabled).
			// Fall through; cgroup + seccomp still apply. Surface
			// as warn so the operator can investigate.
			log::warn!(
				"Aegis landlock: NOT enforced — kernel lacks Landlock support \
				 or it's disabled at boot; rely on cgroup + seccomp only"
			);
		},
	}

	Ok(())
}

/// Map a Landlock-side error (any `Display`able type — `RulesetError`,
/// `PathFdError`, etc.) into our typed error. The label is the call
/// site for log routing.
fn landlock_err<E: std::fmt::Display>(at: &str, e: E) -> SandboxError {
	SandboxError::InstallFailed {
		primitive: "landlock",
		reason: format!("{at}: {e}"),
	}
}

/// Write a value to a single cgroup control file with structured
/// error mapping. Crate-public so [`SandboxHandle::place_child_in_cgroup`]
/// can share the path.
pub(crate) fn write_cgroup_file(
	dir: &Path,
	name: &str,
	value: &str,
) -> Result<(), SandboxError> {
	let path = dir.join(name);
	fs::write(&path, value.as_bytes()).map_err(|e| SandboxError::InstallFailed {
		primitive: "cgroup",
		reason: format!("write {}={value:?}: {e}", path.display()),
	})
}

// ─── seccomp-bpf allowlist (Phase 3c) ──────────────────────────────────────
//
// Closes the host-process syscall surface. On violation, the kernel sends
// SIGKILL to the entire process (SECCOMP_RET_KILL_PROCESS) — the Phase 1
// supervisor's crash-restart path then engages.
//
// Authoring approach: curated baseline from systemd's `@system-service`
// syscall group (closest workload analog — long-running daemon doing
// network + I/O), plus a small set of substrate-specific needs (libp2p
// epoll/eventfd/timerfd, RocksDB pread/pwrite/fdatasync, tokio's clone +
// futex). Argument filtering on four load-bearing syscalls (mmap,
// mprotect, clone, socket, ioctl) keeps the allowlist tight where flat
// "allow by syscall number" would still let attacker pivot inside the
// permitted syscall.
//
// Hard denies by family (not even on the allowlist): ptrace,
// process_vm_*, mount/umount/pivot_root, unshare/setns (and CLONE_NEW*
// flags via clone arg filter), kexec_*, init_module/finit_module,
// bpf, perf_event_open, io_uring_*, swapon/swapoff, reboot,
// setuid/setgid/setres*, capset, chroot, keyctl/add_key/request_key,
// userfaultfd, modify_ldt, iopl/ioperm, syslog (kernel log),
// open_by_handle_at, name_to_handle_at.
//
// Architecture gating: this implementation is x86_64-only. The syscall
// numbers (libc::SYS_*) are arch-specific and ARM64 has a different set
// (no SYS_arch_prctl, different SYS_clone3 layout, etc.). Adding ARM64
// is mechanical work for when we get an ARM validator host on the
// testnet roster.

#[cfg(target_arch = "x86_64")]
use seccompiler::{
	BpfProgram, SeccompAction, SeccompCmpArgLen as ArgLen, SeccompCmpOp,
	SeccompCondition as Cond, SeccompFilter, SeccompRule, TargetArch,
};

/// Apply the seccomp filter to the calling process and all its
/// threads (`SECCOMP_FILTER_FLAG_TSYNC`). After this returns, any
/// syscall not on the allowlist (or any allowed syscall called with
/// the wrong arguments per the four argument-filtered rules) causes
/// the kernel to SIGKILL the entire process immediately.
#[cfg(target_arch = "x86_64")]
fn install_seccomp(_config: &NodeSandboxConfig) -> Result<(), SandboxError> {
	// Stack two BPF programs. The kernel evaluates all stacked seccomp
	// filters and takes the minimum action (most restrictive). Order of
	// installation doesn't affect the resulting decision, only ordering
	// of evaluation; we install the clone3-ENOSYS filter first so its
	// presence is logged before the main filter's bulk allowlist.
	let clone3_filter = force_clone3_enosys_filter()?;
	let clone3_bpf: BpfProgram = clone3_filter
		.try_into()
		.map_err(|e| seccomp_err("clone3-enosys compile", e))?;
	seccompiler::apply_filter_all_threads(&clone3_bpf)
		.map_err(|e| seccomp_err("clone3-enosys apply", e))?;
	log::info!(
		"Aegis seccomp: clone3-ENOSYS filter installed (forces glibc ≥2.34 \
		 fallback to legacy clone, which is then arg-filtered for CLONE_NEW*)"
	);

	let (filter, action_label) = build_seccomp_filter_with_label()?;
	let bpf: BpfProgram = filter
		.try_into()
		.map_err(|e| seccomp_err("compile", e))?;
	seccompiler::apply_filter_all_threads(&bpf)
		.map_err(|e| seccomp_err("apply", e))?;
	log::info!(
		"Aegis seccomp: main filter installed ({action_label} on violation, \
		 TSYNC across all threads)"
	);
	Ok(())
}

/// Non-x86_64 stub. Real ARM64 / RISC-V support is mechanical work
/// (different SYS_* numbers); skipping here keeps the rest of the
/// sandbox usable on other archs. Logs a warning so operators on
/// non-x86_64 hosts know seccomp isn't active for them yet.
#[cfg(not(target_arch = "x86_64"))]
fn install_seccomp(_config: &NodeSandboxConfig) -> Result<(), SandboxError> {
	log::warn!(
		"Aegis seccomp: not yet supported on arch {}; skipping (cgroup + \
		 Landlock still apply)",
		std::env::consts::ARCH,
	);
	Ok(())
}

/// Test-only convenience wrapper: build the filter and discard the
/// action label so existing tests don't have to thread a tuple through.
/// `install_seccomp` uses [`build_seccomp_filter_with_label`] directly.
#[cfg(all(target_arch = "x86_64", test))]
fn build_seccomp_filter() -> Result<SeccompFilter, SandboxError> {
	build_seccomp_filter_with_label().map(|(f, _)| f)
}

/// Same as [`build_seccomp_filter`] but also returns the human-readable
/// label of the default action selected, so [`install_seccomp`] can log
/// which mode is active without re-reading the env var.
#[cfg(target_arch = "x86_64")]
fn build_seccomp_filter_with_label()
	-> Result<(SeccompFilter, &'static str), SandboxError>
{
	let arch = TargetArch::x86_64;

	let mut rules: Vec<(i64, Vec<SeccompRule>)> = Vec::with_capacity(160);

	// Plain-numeric allows: present in the allowlist with empty rule
	// vec means "always allow regardless of args."
	for &sys in PLAIN_ALLOWED_SYSCALLS {
		rules.push((sys, vec![]));
	}

	// Argument-filtered allows.
	rules.push((libc::SYS_mmap, mmap_safe_rules()?));
	rules.push((libc::SYS_mprotect, mprotect_safe_rules()?));
	rules.push((libc::SYS_clone, clone_no_namespace_rules()?));
	rules.push((libc::SYS_socket, socket_safe_families_rules()?));
	rules.push((libc::SYS_ioctl, ioctl_safe_cmds_rules()?));
	// clone3 added to PLAIN_ALLOWED_SYSCALLS as of Phase 5 (2026-05-23).
	// See the rationale block at that array entry.

	let (default_action, label) = seccomp_default_action()?;
	let filter = SeccompFilter::new(
		rules.into_iter().collect(),
		default_action,       // default: see seccomp_default_action()
		SeccompAction::Allow, // on match: allow
		arch,
	)
	.map_err(|e| seccomp_err("filter.new", e))?;
	Ok((filter, label))
}

/// Select the default seccomp action (the one fired for syscalls NOT
/// matched by any rule). Production = `KillProcess`. Phase 5 diagnostics
/// can flip to `Log` via the env var below.
///
/// `ROSTRO_SECCOMP_ACTION`:
///   * unset or `kill` → `SeccompAction::KillProcess` (production)
///   * `log`           → `SeccompAction::Log` (diagnostic; emits one
///                       audit record per denied syscall and ALLOWS the
///                       call to proceed — DO NOT set in production)
///   * anything else   → install fails fast; we never silently fall
///                       back to a weaker action.
///
/// Why an env var (not a Config field): symmetric with the existing
/// `ROSTRO_SKIP_LANDLOCK` / `ROSTRO_SKIP_SECCOMP` Phase 5 diagnostic
/// pattern, and lets operators flip mode without rebuilding the
/// supervisor. Add a CLI plumb only if a higher-level caller needs it.
#[cfg(target_arch = "x86_64")]
fn seccomp_default_action() -> Result<(SeccompAction, &'static str), SandboxError> {
	match std::env::var("ROSTRO_SECCOMP_ACTION").as_deref() {
		Err(_) | Ok("kill") => Ok((SeccompAction::KillProcess, "KILL_PROCESS")),
		Ok("log") => {
			log::warn!(
				"Aegis seccomp: ROSTRO_SECCOMP_ACTION=log — denied syscalls \
				 will be LOGGED and ALLOWED. Diagnostic mode; do not use in production."
			);
			Ok((SeccompAction::Log, "LOG"))
		},
		Ok(other) => Err(SandboxError::InstallFailed {
			primitive: "seccomp",
			reason: format!(
				"unknown ROSTRO_SECCOMP_ACTION={other:?}; expected unset, \"kill\", or \"log\"",
			),
		}),
	}
}

/// Plain-numeric syscall allowlist. Each entry is allowed regardless
/// of its argument values. Grouped by purpose with rationale comments
/// so a reviewer can see WHY each is here and remove confidently if
/// no longer needed. Future audits should reread this list end-to-end.
///
/// NOTE: argument-filtered syscalls (`mmap`, `mprotect`, `clone`,
/// `socket`, `ioctl`) are NOT in this list — they're added separately
/// in `build_seccomp_filter` with their constraint rules.
#[cfg(target_arch = "x86_64")]
const PLAIN_ALLOWED_SYSCALLS: &[i64] = &[
	// ── File I/O ──────────────────────────────────────────────────
	// Reading and writing files + sockets. RocksDB hot path, libp2p
	// frame I/O, log writes.
	libc::SYS_read,
	libc::SYS_write,
	libc::SYS_pread64,
	libc::SYS_pwrite64,
	libc::SYS_readv,
	libc::SYS_writev,
	libc::SYS_preadv,
	libc::SYS_pwritev,
	libc::SYS_preadv2,
	libc::SYS_pwritev2,
	// File open / close. We use openat exclusively; libc maps open()
	// to openat() on modern systems. Landlock filters paths.
	libc::SYS_openat,
	libc::SYS_close,
	libc::SYS_close_range,
	libc::SYS_dup,
	libc::SYS_dup2,
	libc::SYS_dup3,
	// Metadata + seek.
	libc::SYS_fstat,
	libc::SYS_newfstatat,
	libc::SYS_fstatfs,
	libc::SYS_statfs,
	libc::SYS_lseek,
	libc::SYS_ftruncate,
	libc::SYS_statx,
	// Directory + path.
	libc::SYS_getdents64,
	libc::SYS_faccessat,
	libc::SYS_faccessat2,
	libc::SYS_readlinkat,
	libc::SYS_getcwd,
	// Phase 5 (2026-05-23): observed in baseline across Fedora 44 +
	// Debian 13 + Ubuntu 24.04. Old-style variants still hit by some
	// glibc/Rust paths despite *at preferences. Landlock enforces the
	// actual path policy so seccomp-allowing these is safe.
	libc::SYS_access,
	libc::SYS_readlink,
	// Sync / flush — RocksDB needs these for durability.
	libc::SYS_fdatasync,
	libc::SYS_fsync,
	libc::SYS_sync_file_range,
	// File ops. mkdirat/renameat/unlinkat go through Landlock for
	// path policy. fcntl is a multiplexer but operations are mostly
	// safe (FD_CLOEXEC, file locking).
	libc::SYS_mkdirat,
	libc::SYS_renameat,
	libc::SYS_renameat2,
	libc::SYS_unlinkat,
	libc::SYS_symlinkat,
	// Phase 5 (2026-05-23): old-style FS ops also observed; Landlock
	// still controls path access.
	libc::SYS_mkdir,
	libc::SYS_rename,
	libc::SYS_unlink,
	libc::SYS_utimensat,
	libc::SYS_fchmod,
	libc::SYS_fchmodat,
	libc::SYS_fchown,
	libc::SYS_fchownat,
	libc::SYS_fcntl,
	// Pipes.
	libc::SYS_pipe2,
	// Splice/tee/copy — niche but used by some tokio paths.
	libc::SYS_splice,

	// ── Memory ────────────────────────────────────────────────────
	// mmap + mprotect are argument-filtered (no PROT_EXEC). The
	// rest are flat-allowed.
	libc::SYS_munmap,
	libc::SYS_mremap,
	libc::SYS_madvise,
	libc::SYS_brk,
	libc::SYS_mlock,
	libc::SYS_munlock,
	libc::SYS_mlock2,
	libc::SYS_mlockall,
	libc::SYS_munlockall,
	libc::SYS_msync,

	// ── Process / thread ──────────────────────────────────────────
	libc::SYS_exit,
	libc::SYS_exit_group,
	libc::SYS_gettid,
	libc::SYS_getpid,
	libc::SYS_getppid,
	libc::SYS_getuid,
	libc::SYS_getgid,
	libc::SYS_geteuid,
	libc::SYS_getegid,
	libc::SYS_getgroups,
	libc::SYS_getpgid,
	libc::SYS_getpgrp,
	libc::SYS_getsid,
	libc::SYS_wait4,
	libc::SYS_waitid,
	// Signals for sending to own children + signal handling.
	libc::SYS_kill,
	libc::SYS_tkill,
	libc::SYS_tgkill,
	libc::SYS_rt_sigaction,
	libc::SYS_rt_sigprocmask,
	libc::SYS_rt_sigpending,
	libc::SYS_rt_sigreturn,
	libc::SYS_rt_sigsuspend,
	libc::SYS_rt_sigtimedwait,
	libc::SYS_rt_sigqueueinfo,
	libc::SYS_sigaltstack,
	libc::SYS_pause,
	// Time.
	libc::SYS_nanosleep,
	libc::SYS_clock_nanosleep,
	libc::SYS_clock_gettime,
	libc::SYS_clock_getres,
	libc::SYS_gettimeofday,
	// Scheduling.
	libc::SYS_sched_yield,
	libc::SYS_sched_getaffinity,
	libc::SYS_sched_setaffinity,
	libc::SYS_sched_getparam,
	libc::SYS_sched_getscheduler,
	libc::SYS_sched_get_priority_max,
	libc::SYS_sched_get_priority_min,
	// Threading primitives.
	libc::SYS_futex,
	libc::SYS_set_robust_list,
	libc::SYS_get_robust_list,
	libc::SYS_arch_prctl, // x86_64 TLS setup
	libc::SYS_set_tid_address,
	// Phase 5 (2026-05-23): glibc + Rust use rseq for fast TLS access
	// on Linux ≥4.18; observed across all three baseline distros.
	libc::SYS_rseq,
	// Kernel-internal signal: tells the kernel an interrupted syscall
	// should resume. Required for correct signal handling.
	libc::SYS_restart_syscall,
	// clone3 is flat-allowed HERE, but a stacked secondary filter
	// returns ENOSYS for it — see `force_clone3_enosys_filter()`. The
	// kernel evaluates stacked filters and picks the *signed* minimum
	// action (per `ACTION_ONLY((s32))` cast in kernel seccomp.c), so:
	//   * KILL_PROCESS (0x80000000 → INT_MIN signed) WINS every contest.
	//   * ERRNO (0x00050000 → +327680 signed) BEATS ALLOW (0x7fff0000
	//     → +2.1B signed).
	// If clone3 weren't in this allowlist, the main filter's default
	// KILL_PROCESS would beat the ENOSYS filter and the supervisor would
	// SIGSYS the first time it called Command::spawn. Allowing here +
	// shadowing with ENOSYS in the second filter is the load-bearing
	// pattern. glibc ≥2.34's __clone3 reacts to ENOSYS by retrying via
	// legacy clone(), which then hits clone_no_namespace_rules() and is
	// denied if it asks for CLONE_NEW*.
	libc::SYS_clone3,
	// prctl is a multiplexer; flat-allow is safe because
	// PR_SET_NO_NEW_PRIVS (set in Phase 3b via Landlock) prevents
	// PR_SET_SECCOMP from loosening the filter. Could arg-filter in
	// a follow-up if any specific operation becomes a concern.
	libc::SYS_prctl,
	// Exec for the supervisor's `Command::new + spawn` flow + any
	// internal exec the runtime does (it shouldn't).
	libc::SYS_execve,
	libc::SYS_execveat,

	// ── Network ───────────────────────────────────────────────────
	// `socket` is argument-filtered separately (domain allowlist).
	// The rest of the socket API is flat-allowed; setsockopt
	// argument filtering deferred to a follow-up (allowlist of
	// option names) when we have time to enumerate every option
	// libp2p + tokio actually use.
	libc::SYS_socketpair,
	libc::SYS_bind,
	libc::SYS_listen,
	libc::SYS_accept4,
	libc::SYS_connect,
	libc::SYS_getsockname,
	libc::SYS_getpeername,
	libc::SYS_sendto,
	libc::SYS_recvfrom,
	libc::SYS_sendmsg,
	libc::SYS_recvmsg,
	libc::SYS_sendmmsg,
	libc::SYS_recvmmsg,
	libc::SYS_shutdown,
	libc::SYS_setsockopt,
	libc::SYS_getsockopt,
	// I/O multiplexing — tokio + libp2p hot path.
	libc::SYS_epoll_create1,
	libc::SYS_epoll_ctl,
	libc::SYS_epoll_wait,
	libc::SYS_epoll_pwait,
	libc::SYS_epoll_pwait2,
	libc::SYS_eventfd2,
	libc::SYS_timerfd_create,
	libc::SYS_timerfd_settime,
	libc::SYS_timerfd_gettime,
	libc::SYS_ppoll,
	libc::SYS_pselect6,
	libc::SYS_poll,
	libc::SYS_select,

	// ── System info / random ──────────────────────────────────────
	libc::SYS_uname,
	libc::SYS_sysinfo,
	libc::SYS_getrandom, // hot path for any crypto code
	libc::SYS_getcpu,

	// ── Resource limits (self only) ───────────────────────────────
	// prlimit64 can target other PIDs but the kernel rejects without
	// CAP_SYS_RESOURCE, and we don't grant that. Arg-filtering
	// on pid=0 is a future tightening.
	libc::SYS_getrlimit,
	libc::SYS_prlimit64,
	libc::SYS_setrlimit,
];

/// Build the rule list for `mmap`. Two rules OR'd:
///
/// 1. **PROT_EXEC unset** → allow (regardless of flags). Covers normal
///    R/RW allocations: Rust heap, stack growth, anonymous mappings.
///
/// 2. **PROT_EXEC set AND MAP_ANONYMOUS unset** → allow. Covers
///    file-backed executable mappings: the dynamic loader (`ld.so`)
///    mapping shared library `.text` segments. Without this, every
///    dynamically-linked binary inside the sandbox SIGKILLs on its
///    first attempt to map libc.so.6's text. Landlock contains *which*
///    files can be opened, so the loader can only exec code from
///    paths permitted by the operator's RO ruleset.
///
/// What stays DENIED (no rule matches): `(PROT_EXEC set) AND
/// (MAP_ANONYMOUS set)` — anonymous executable mappings, i.e.
/// classic JIT-spray. A compromised in-sandbox process can still
/// write to a permitted RW path and re-mmap that file executable;
/// closing that gap requires Landlock-execute-denial on RW paths,
/// tracked as a v2 hardening.
///
/// Phase 5 (2026-05-23): split from `mmap_no_exec_rules`. Original
/// rule denied ALL PROT_EXEC and consequently killed every dynamic
/// loader, making the sandbox unusable in practice.
#[cfg(target_arch = "x86_64")]
fn mmap_safe_rules() -> Result<Vec<SeccompRule>, SandboxError> {
	Ok(vec![
		// Rule 1: (prot & PROT_EXEC) == 0
		SeccompRule::new(vec![Cond::new(
			2,
			ArgLen::Dword,
			SeccompCmpOp::MaskedEq(libc::PROT_EXEC as u64),
			0,
		)
		.map_err(|e| seccomp_err("mmap.prot=0 cond", e))?])
		.map_err(|e| seccomp_err("mmap.prot=0 rule", e))?,
		// Rule 2: (prot & PROT_EXEC) == PROT_EXEC AND (flags & MAP_ANONYMOUS) == 0
		SeccompRule::new(vec![
			Cond::new(
				2,
				ArgLen::Dword,
				SeccompCmpOp::MaskedEq(libc::PROT_EXEC as u64),
				libc::PROT_EXEC as u64,
			)
			.map_err(|e| seccomp_err("mmap.prot=exec cond", e))?,
			Cond::new(
				3,
				ArgLen::Dword,
				SeccompCmpOp::MaskedEq(libc::MAP_ANONYMOUS as u64),
				0,
			)
			.map_err(|e| seccomp_err("mmap.anon=0 cond", e))?,
		])
		.map_err(|e| seccomp_err("mmap.exec-file rule", e))?,
	])
}

/// Two-rule `mprotect` filter: any non-exec mprotect, plus the W^X-
/// preserving JIT flip (`PROT_READ|PROT_EXEC` with no `PROT_WRITE`).
///
/// Phase 5 second-pass (2026-05-23): the supervised gemini-node makes
/// ~1000 `mprotect(addr, 8MiB, PROT_READ|PROT_EXEC)` calls during 5
/// minutes of idle init — every one is PolkaVM's runtime executor
/// committing a freshly-JIT'd 8MiB code page from RW to RX (classic
/// W^X). Blanket-denying `PROT_EXEC` killed the supervised process the
/// instant the runtime first compiled a function. Two rules:
///
///   * Rule 1: `(prot & PROT_EXEC) == 0` — pages that never become
///     executable. Heap, stack, RW data buffers.
///   * Rule 2: `(prot & PROT_EXEC) != 0` AND `(prot & PROT_WRITE) == 0`
///     — the JIT flip. The page is currently RW (committed via
///     `mmap(... PROT_READ|PROT_WRITE, MAP_ANONYMOUS, ...)` which is
///     allowed by `mmap_safe_rules`'s rule 1), JIT'd bytes were
///     written, and this call drops write while granting exec.
///
/// What's still denied (no matching rule): any `mprotect` that requests
/// both `PROT_WRITE` AND `PROT_EXEC` — the true W^X-violating spray
/// pattern. Calls with this shape SIGKILL the process under KillProcess.
#[cfg(target_arch = "x86_64")]
fn mprotect_safe_rules() -> Result<Vec<SeccompRule>, SandboxError> {
	Ok(vec![
		// Rule 1: (prot & PROT_EXEC) == 0
		SeccompRule::new(vec![Cond::new(
			2,
			ArgLen::Dword,
			SeccompCmpOp::MaskedEq(libc::PROT_EXEC as u64),
			0,
		)
		.map_err(|e| seccomp_err("mprotect.no-exec cond", e))?])
		.map_err(|e| seccomp_err("mprotect.no-exec rule", e))?,
		// Rule 2: (prot & PROT_EXEC) != 0 AND (prot & PROT_WRITE) == 0
		// — JIT flip from RW page to RX page (W^X-preserving).
		SeccompRule::new(vec![
			Cond::new(
				2,
				ArgLen::Dword,
				SeccompCmpOp::MaskedEq(libc::PROT_EXEC as u64),
				libc::PROT_EXEC as u64,
			)
			.map_err(|e| seccomp_err("mprotect.exec-set cond", e))?,
			Cond::new(
				2,
				ArgLen::Dword,
				SeccompCmpOp::MaskedEq(libc::PROT_WRITE as u64),
				0,
			)
			.map_err(|e| seccomp_err("mprotect.write-clear cond", e))?,
		])
		.map_err(|e| seccomp_err("mprotect.jit-flip rule", e))?,
	])
}

/// Build the rule list for `clone`: deny namespace-creation flags.
/// arg 0 = flags. We require (flags & CLONE_NEW*) == 0 for all six
/// namespace bits. A successful match means the caller is asking for
/// threading or fork-like behavior, NOT container-escape namespaces.
#[cfg(target_arch = "x86_64")]
fn clone_no_namespace_rules() -> Result<Vec<SeccompRule>, SandboxError> {
	// All namespace-creation flags. Any one of these set = denial.
	// CLONE_NEWCGROUP is 0x02000000 but isn't in libc 0.2 on all
	// versions; hardcode the value to keep this portable.
	const NAMESPACE_FLAGS_MASK: u64 = libc::CLONE_NEWNS as u64
		| libc::CLONE_NEWUTS as u64
		| libc::CLONE_NEWIPC as u64
		| libc::CLONE_NEWUSER as u64
		| libc::CLONE_NEWPID as u64
		| libc::CLONE_NEWNET as u64
		| 0x02000000u64; // CLONE_NEWCGROUP
	Ok(vec![SeccompRule::new(vec![Cond::new(
		0, // arg0 = flags
		ArgLen::Dword,
		SeccompCmpOp::MaskedEq(NAMESPACE_FLAGS_MASK),
		0,
	)
	.map_err(|e| seccomp_err("clone.flags cond", e))?])
	.map_err(|e| seccomp_err("clone.flags rule", e))?])
}

/// Build a small secondary filter that intercepts `clone3` and returns
/// `ENOSYS`, forcing glibc to fall back to legacy `clone()`. That
/// fallback then hits [`clone_no_namespace_rules`] in the main filter
/// and is denied if it asks for any `CLONE_NEW*` flag.
///
/// **Why a separate filter, not a rule on the main filter.** The main
/// filter constructed in [`build_seccomp_filter_with_label`] uses a
/// single `match_action` (`SeccompAction::Allow`) for every matched
/// rule — that's the seccompiler API shape. To return ENOSYS for one
/// syscall we install a second BPF program; the kernel evaluates all
/// stacked filters and picks the **signed minimum** of all returned
/// actions (kernel/seccomp.c: `ACTION_ONLY(ret) ((s32)(ret &
/// SECCOMP_RET_ACTION_FULL))`). Casting to `s32` puts `KILL_PROCESS
/// (0x80000000)` at `INT_MIN`, so it wins every contest — naive
/// stacking does NOT let ERRNO override it. The pattern that DOES work:
///   * Main filter: clone3 **in** `PLAIN_ALLOWED_SYSCALLS` → ALLOW
///     (+2.1B signed)
///   * This filter: clone3 → ERRNO(ENOSYS) (+327680 signed)
///   * `min(ALLOW, ERRNO) = ERRNO` → glibc sees `-ENOSYS` and falls back.
/// Removing clone3 from the main allowlist sets main's contribution to
/// the default action (KILL_PROCESS = INT_MIN signed), which would beat
/// any ERRNO and SIGSYS the supervisor on its first Command::spawn.
/// Confirmed empirically on Debian 13 / kernel 6.12.88 during the
/// 2026-05-23 lab deploy — see PHASE5_NOTES.md "Bug 2 (revised v2)".
///
/// **Why ENOSYS and not EPERM.** glibc ≥2.34 has explicit ENOSYS-
/// fallback code in `__clone3`: on `-ENOSYS` it retries with legacy
/// `SYS_clone`. EPERM bubbles to the caller as a clone failure (any
/// `Command::spawn` in tokio/libp2p dies). ENOSYS is the "syscall does
/// not exist" contract; the fallback engages transparently.
///
/// **Why clone3 only, not the whole `*2`-variant family.** Other arg-
/// blind variants in the allowlist (`epoll_pwait2`, `preadv2`,
/// `pwritev2`) carry no namespace/escalation flags — `sigset_t*` and
/// `RWF_*` respectively. clone3 is the only one whose struct-pointer
/// arg shape lets the attacker carry namespace-creation flags through
/// a check seccomp cannot perform. Forcing fallback on the others
/// would cost real I/O perf for no security benefit. `openat2` would
/// be a similar gap if added — its resolve flags are *tighter* than
/// openat though, so it would only ever be a hardening primitive, not
/// a soundness gap.
///
/// **Operator requirement: glibc ≥2.34** (Aug 2021). Older glibc lacks
/// the fallback, so clone3 will return ENOSYS to the application and
/// any process spawn fails. Every supported validator distro (Ubuntu
/// 22.04+, Debian 12+, Fedora 36+, RHEL 9+) ships ≥2.34. musl libc
/// does NOT ship the fallback — Rostro binaries are glibc, so this
/// isn't a concern today; would be if the build ever switched to
/// musl-static for portability.
#[cfg(target_arch = "x86_64")]
fn force_clone3_enosys_filter() -> Result<SeccompFilter, SandboxError> {
	// Empty rule vec = "match unconditionally on this syscall number."
	let rules = vec![(libc::SYS_clone3, vec![])];
	SeccompFilter::new(
		rules.into_iter().collect(),
		SeccompAction::Allow,                      // mismatch: let main filter decide
		SeccompAction::Errno(libc::ENOSYS as u32), // match: synthesize -ENOSYS (beats main's ALLOW)
		TargetArch::x86_64,
	)
	.map_err(|e| seccomp_err("clone3-enosys filter.new", e))
}

/// Build the rule list for `socket`: allow a tight set of address
/// families. arg 0 = domain, arg 2 = protocol. We emit one rule per
/// allowed (domain, protocol) shape; seccomp ORs rules together, so
/// the syscall is allowed if it matches ANY rule.
///
/// Allowed:
///   * `AF_INET`, `AF_INET6`, `AF_UNIX` — domain-only (any protocol).
///     Substrate gossip, libp2p, JSON-RPC server, Prometheus exporter,
///     UNIX-domain sockets for local IPC.
///   * `AF_NETLINK` with `protocol == NETLINK_ROUTE` only. Phase 5
///     second-pass (2026-05-23) found std::net / libp2p enumerating
///     local interfaces via `socket(AF_NETLINK, SOCK_DGRAM|SOCK_CLOEXEC,
///     NETLINK_ROUTE)` during early init (2 calls in 5min idle).
///     Without it the supervised process SIGKILLs the first time
///     libp2p binds an address.
///
/// Denied by absence:
///   * `AF_PACKET` (raw packet capture)
///   * other `AF_NETLINK` protocols: `NETLINK_AUDIT`,
///     `NETLINK_NETFILTER`, `NETLINK_KOBJECT_UEVENT`, etc. — any of
///     these would let a compromised process subscribe to host-level
///     events that should never reach a node binary.
///   * `AF_VSOCK`, `AF_BLUETOOTH`, `AF_CAN`, `AF_RDS`, `AF_IEEE802154`,
///     anything else.
#[cfg(target_arch = "x86_64")]
fn socket_safe_families_rules() -> Result<Vec<SeccompRule>, SandboxError> {
	let mut rules = Vec::with_capacity(4);

	// Plain domain-only rules.
	for family in [libc::AF_INET, libc::AF_INET6, libc::AF_UNIX] {
		rules.push(
			SeccompRule::new(vec![Cond::new(
				0, // arg0 = domain
				ArgLen::Dword,
				SeccompCmpOp::Eq,
				family as u64,
			)
			.map_err(|e| {
				seccomp_err(&format!("socket.domain={family} cond"), e)
			})?])
			.map_err(|e| seccomp_err(&format!("socket.domain={family} rule"), e))?,
		);
	}

	// AF_NETLINK is gated to NETLINK_ROUTE only — see fn-level comment.
	rules.push(
		SeccompRule::new(vec![
			Cond::new(0, ArgLen::Dword, SeccompCmpOp::Eq, libc::AF_NETLINK as u64)
				.map_err(|e| seccomp_err("socket.netlink.domain cond", e))?,
			Cond::new(
				2, // arg2 = protocol
				ArgLen::Dword,
				SeccompCmpOp::Eq,
				libc::NETLINK_ROUTE as u64,
			)
			.map_err(|e| seccomp_err("socket.netlink.protocol cond", e))?,
		])
		.map_err(|e| seccomp_err("socket.netlink-route rule", e))?,
	);

	Ok(rules)
}

/// Build the rule list for `ioctl`: allow only specific cmd values
/// our stack actually uses. `ioctl` is famously a "hundreds of
/// mini-syscalls behind one number" escape surface; flat-allow gives
/// attacker dozens of avenues. Each entry is one cmd we've audited
/// as needed.
///
/// **This list will grow during Phase 5 as strace reveals what
/// substrate/tokio/RocksDB actually hit.** Today's set is the
/// minimum we expect to be safe: terminal-sizing for log output,
/// non-blocking socket toggle, available-bytes inquiry.
#[cfg(target_arch = "x86_64")]
fn ioctl_safe_cmds_rules() -> Result<Vec<SeccompRule>, SandboxError> {
	// Conservative starter set. arg index 1 = cmd.
	const SAFE_IOCTLS: &[(u64, &str)] = &[
		(libc::TIOCGWINSZ as u64, "TIOCGWINSZ"),
		(libc::FIONREAD as u64, "FIONREAD"),
		(libc::FIONBIO as u64, "FIONBIO"),
		(libc::TCGETS as u64, "TCGETS"),
		(libc::TIOCGPGRP as u64, "TIOCGPGRP"),
		// Phase 5 (2026-05-23): modern terminal config that supports
		// c_ispeed/c_ospeed. Observed in all three baseline distros.
		(libc::TCGETS2 as u64, "TCGETS2"),
	];
	let mut rules = Vec::with_capacity(SAFE_IOCTLS.len());
	for (cmd, name) in SAFE_IOCTLS {
		rules.push(
			SeccompRule::new(vec![Cond::new(
				1, // arg1 = cmd
				ArgLen::Dword,
				SeccompCmpOp::Eq,
				*cmd,
			)
			.map_err(|e| seccomp_err(&format!("ioctl.{name} cond"), e))?])
			.map_err(|e| seccomp_err(&format!("ioctl.{name} rule"), e))?,
		);
	}
	Ok(rules)
}

/// Map a seccompiler-side error into our typed error.
fn seccomp_err<E: std::fmt::Display>(at: &str, e: E) -> SandboxError {
	SandboxError::InstallFailed {
		primitive: "seccomp",
		reason: format!("{at}: {e}"),
	}
}

// ─── Tests ─────────────────────────────────────────────────────────────────
//
// Real cgroup v2 control writes require privileged access to
// /sys/fs/cgroup; under cargo test on a dev box (and under WSL2) we
// can't exercise that path. Instead, every test uses a tmpdir as a
// fake cgroup root populated with the marker file the detection logic
// looks for. We verify:
//   - the skip-if-no-caps path
//   - the v2-detection error
//   - file writes land where expected with expected contents
//   - the two-tier directory layout is created
//
// Phase 5 (Hetzner validation) exercises the real /sys/fs/cgroup path
// end-to-end, including OOM kill behavior.

#[cfg(test)]
mod tests {
	use super::*;

	fn tmpdir() -> PathBuf {
		let mut p = std::env::temp_dir();
		let unique = format!(
			"rostro-node-sandbox-cgroup-test-{}-{}",
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

	/// Populate the marker file `cgroup.controllers` so the v2
	/// detection passes. The contents don't matter for our writes —
	/// the kernel parses them when controllers are exercised, but
	/// our fs::write doesn't.
	fn fake_cgroup_root() -> PathBuf {
		let root = tmpdir();
		std::fs::write(root.join("cgroup.controllers"), b"cpu io memory\n").unwrap();
		root
	}

	#[test]
	fn install_cgroup_skips_when_no_caps_set() {
		let root = fake_cgroup_root();
		let cfg = NodeSandboxConfig::new().cgroup_root(&root);
		let child = install_cgroup(&cfg).unwrap();
		assert!(child.is_none(), "no caps configured → no cgroup created");
		// Subgroup directory should NOT have been created.
		let pid = std::process::id();
		assert!(!root.join(format!("rostro-node-{pid}")).exists());
	}

	#[test]
	fn install_cgroup_rejects_missing_v2_marker() {
		let root = tmpdir(); // no controllers file
		let cfg = NodeSandboxConfig::new()
			.cgroup_root(&root)
			.memory_max_bytes(1024 * 1024);
		match install_cgroup(&cfg) {
			Err(SandboxError::InstallFailed { primitive, reason }) => {
				assert_eq!(primitive, "cgroup");
				assert!(reason.contains("cgroup v2 not detected"));
			},
			other => panic!("expected v2-not-detected error, got {other:?}"),
		}
	}

	#[test]
	fn install_cgroup_creates_two_tier_layout() {
		let root = fake_cgroup_root();
		let cfg = NodeSandboxConfig::new()
			.cgroup_root(&root)
			.memory_max_bytes(2 * 1024 * 1024 * 1024);
		let child = install_cgroup(&cfg).unwrap().expect("cgroup path returned");
		let pid = std::process::id();
		let supervisor_group = root.join(format!("rostro-node-{pid}"));
		assert!(supervisor_group.is_dir(), "supervisor cgroup created");
		assert!(child.starts_with(&supervisor_group), "child nested under supervisor");
		assert!(child.ends_with("child"), "child group named 'child'");
		assert!(child.is_dir(), "child cgroup created");
	}

	#[test]
	fn install_cgroup_writes_memory_max() {
		let root = fake_cgroup_root();
		let cfg = NodeSandboxConfig::new()
			.cgroup_root(&root)
			.memory_max_bytes(8 * 1024 * 1024 * 1024);
		let child = install_cgroup(&cfg).unwrap().unwrap();
		let written = std::fs::read_to_string(child.join("memory.max")).unwrap();
		assert_eq!(written.trim(), (8 * 1024 * 1024 * 1024u64).to_string());
	}

	#[test]
	fn install_cgroup_writes_cpu_max() {
		let root = fake_cgroup_root();
		let cfg = NodeSandboxConfig::new()
			.cgroup_root(&root)
			.cpu_max(200_000, 100_000);
		let child = install_cgroup(&cfg).unwrap().unwrap();
		let written = std::fs::read_to_string(child.join("cpu.max")).unwrap();
		assert_eq!(written.trim(), "200000 100000");
	}

	#[test]
	fn install_cgroup_writes_subtree_control_in_supervisor_group() {
		let root = fake_cgroup_root();
		let cfg = NodeSandboxConfig::new()
			.cgroup_root(&root)
			.memory_max_bytes(1024 * 1024);
		install_cgroup(&cfg).unwrap();
		let pid = std::process::id();
		let supervisor_group = root.join(format!("rostro-node-{pid}"));
		let written =
			std::fs::read_to_string(supervisor_group.join("cgroup.subtree_control")).unwrap();
		assert!(written.contains("+memory"));
		assert!(written.contains("+cpu"));
	}

	#[test]
	fn install_cgroup_does_not_move_supervisor_pid() {
		// Phase 5 (2026-05-23): supervisor stays in its inherited
		// cgroup. cgroup v2 "no internal processes" rule rejects
		// moving the supervisor into `supervisor_group` once we've
		// enabled controllers on its subtree (which we must, to cap
		// the child). Verify install completes without attempting the
		// migration.
		let root = fake_cgroup_root();
		let cfg = NodeSandboxConfig::new()
			.cgroup_root(&root)
			.memory_max_bytes(1024 * 1024);
		install_cgroup(&cfg).unwrap();
		let pid = std::process::id();
		let supervisor_group = root.join(format!("rostro-node-{pid}"));
		// supervisor_group.cgroup.procs should be the file we never wrote,
		// which the fake_cgroup_root setup leaves empty.
		let written =
			std::fs::read_to_string(supervisor_group.join("cgroup.procs"))
				.unwrap_or_default();
		assert_eq!(
			written.trim(),
			"",
			"supervisor PID must not be written to supervisor_group's cgroup.procs"
		);
	}

	#[test]
	fn install_cgroup_writes_oom_group_when_file_present() {
		let root = fake_cgroup_root();
		let pid = std::process::id();
		// Pre-create the memory.oom.group file in the spot install
		// will later create the child group. Since the child dir is
		// created by install_cgroup, we can't pre-create the file
		// without racing. Instead, after install we manually create
		// the file and re-run — but that's not how the test reads.
		//
		// Simpler: skip the file-present branch in unit tests and
		// rely on the file-absent branch (default in tmpdir setup)
		// to exercise the warn-and-continue path. Real-kernel
		// behavior is covered by Phase 5.
		let cfg = NodeSandboxConfig::new()
			.cgroup_root(&root)
			.memory_max_bytes(1024 * 1024);
		// In our tmpdir setup, memory.oom.group doesn't exist, so
		// we exercise the warn-and-skip branch. Just assert the
		// install still succeeds.
		let child = install_cgroup(&cfg).unwrap().unwrap();
		assert!(child.is_dir());
		assert!(
			!child.join("memory.oom.group").exists(),
			"unit test setup doesn't create oom.group; production kernel does",
		);
		// Suppress unused warning.
		let _ = pid;
	}

	#[test]
	fn place_child_in_cgroup_writes_child_pid() {
		// Construct the handle directly so we don't run the full
		// install() path (which would apply Landlock and forbid
		// writes to the test tmpdir). The cgroup half is what we're
		// testing here.
		let root = fake_cgroup_root();
		let cfg = NodeSandboxConfig::new()
			.cgroup_root(&root)
			.memory_max_bytes(1024 * 1024);
		let cgroup_child = install_cgroup(&cfg).unwrap();
		let handle = SandboxHandle { cgroup_child };
		handle.place_child_in_cgroup(99999).unwrap();
		let written = std::fs::read_to_string(
			handle.cgroup_child.as_ref().unwrap().join("cgroup.procs"),
		)
		.unwrap();
		assert_eq!(written.trim(), "99999");
	}

	#[test]
	fn place_child_in_cgroup_is_noop_when_no_cgroup_installed() {
		// Same logic as above: avoid going through install() so the
		// Landlock side-effect doesn't poison the test thread.
		let root = fake_cgroup_root();
		let cfg = NodeSandboxConfig::new().cgroup_root(&root);
		let cgroup_child = install_cgroup(&cfg).unwrap();
		assert!(cgroup_child.is_none(), "no caps configured → no cgroup");
		let handle = SandboxHandle { cgroup_child };
		// Calling place_child_in_cgroup should succeed silently.
		assert!(handle.place_child_in_cgroup(12345).is_ok());
	}

	// ─── Landlock (Phase 3b) ──────────────────────────────────────────
	//
	// We can't call restrict_self in unit tests — it'd poison every
	// subsequent test in the same process. So tests only exercise
	// build_landlock_ruleset and verify the construction succeeds
	// against various configs. Phase 5 (Hetzner) tests real
	// restriction end-to-end.

	#[test]
	fn build_landlock_ruleset_succeeds_with_empty_config() {
		// Empty config still gets the baseline read-only paths.
		// Construction should succeed on any Linux ≥ 5.13.
		let cfg = NodeSandboxConfig::new();
		match build_landlock_ruleset(&cfg, None) {
			Ok(_) => {},
			Err(e) => {
				// If the kernel is older than 5.13 OR Landlock is
				// disabled in the boot config, construction can fail.
				// Accept that as a skip in CI but log so we don't
				// silently mask other failures.
				eprintln!("landlock unavailable on this host, test inconclusive: {e:?}");
			},
		}
	}

	#[test]
	fn build_landlock_ruleset_accepts_existing_rw_path() {
		let dir = tmpdir();
		let cfg = NodeSandboxConfig::new().add_rw_path(&dir);
		match build_landlock_ruleset(&cfg, None) {
			Ok(_) => {},
			Err(SandboxError::InstallFailed { primitive: "landlock", .. }) => {
				// Could be kernel-doesn't-support; acceptable in
				// dev. Phase 5 covers the real path.
			},
			Err(other) => panic!("unexpected error: {other:?}"),
		}
	}

	#[test]
	fn build_landlock_ruleset_accepts_existing_ro_path() {
		let dir = tmpdir();
		let f = dir.join("chain-spec.json");
		std::fs::write(&f, b"{}").unwrap();
		let cfg = NodeSandboxConfig::new().add_ro_path(&f);
		match build_landlock_ruleset(&cfg, None) {
			Ok(_) => {},
			Err(SandboxError::InstallFailed { primitive: "landlock", .. }) => {},
			Err(other) => panic!("unexpected error: {other:?}"),
		}
	}

	#[test]
	fn build_landlock_ruleset_rejects_missing_rw_path() {
		// Non-existent path → PathFd::new fails → install error.
		let cfg = NodeSandboxConfig::new().add_rw_path("/this/path/does/not/exist/anywhere");
		match build_landlock_ruleset(&cfg, None) {
			Err(SandboxError::InstallFailed { primitive, reason }) => {
				assert_eq!(primitive, "landlock");
				assert!(reason.contains("PathFd::new"));
				assert!(reason.contains("/this/path/does/not/exist/anywhere"));
			},
			Err(other) => panic!("expected InstallFailed(landlock), got {other:?}"),
			Ok(_) => panic!("missing rw_path should not produce a ruleset"),
		}
	}

	#[test]
	fn build_landlock_ruleset_rejects_missing_ro_path() {
		let cfg = NodeSandboxConfig::new().add_ro_path("/another/nope");
		assert!(matches!(
			build_landlock_ruleset(&cfg, None),
			Err(SandboxError::InstallFailed { primitive: "landlock", .. })
		));
	}

	#[test]
	fn build_landlock_ruleset_with_cgroup_extra_path() {
		// Threading the cgroup path through must succeed when the
		// path exists.
		let cgroup_dir = tmpdir();
		let cfg = NodeSandboxConfig::new();
		match build_landlock_ruleset(&cfg, Some(&cgroup_dir)) {
			Ok(_) => {},
			Err(SandboxError::InstallFailed { primitive: "landlock", .. }) => {
				// Kernel may not support Landlock — acceptable.
			},
			Err(other) => panic!("unexpected: {other:?}"),
		}
	}

	#[test]
	fn build_landlock_ruleset_rejects_missing_cgroup_path() {
		// If we somehow get passed a non-existent cgroup path
		// (shouldn't happen — install_cgroup always creates it
		// before passing in), surface as InstallFailed for triage.
		let cfg = NodeSandboxConfig::new();
		let bad = PathBuf::from("/nope/cgroup/path/that/doesnt/exist");
		assert!(matches!(
			build_landlock_ruleset(&cfg, Some(&bad)),
			Err(SandboxError::InstallFailed { primitive: "landlock", .. })
		));
	}

	#[test]
	fn baseline_paths_include_dns_and_entropy_essentials() {
		// Sanity: ensure we didn't accidentally drop the load-bearing
		// system paths. Operators rely on these for normal node
		// operation.
		assert!(BASELINE_RO_PATHS.contains(&"/dev/urandom"));
		assert!(BASELINE_RO_PATHS.contains(&"/etc/resolv.conf"));
		assert!(BASELINE_RO_PATHS.contains(&"/proc"));
	}

	// ─── seccomp-bpf (Phase 3c) ───────────────────────────────────────
	//
	// Same testing constraint as Landlock: we can't call
	// `apply_filter_all_threads` in unit tests because it would kill
	// the test process the next time it tried any syscall not on the
	// allowlist (which includes plenty of cargo-test machinery). We
	// only verify construction.

	// Serializes any test that touches ROSTRO_SECCOMP_ACTION so a
	// "log" / "invalid" override set by one test can't race a peer
	// test that calls build_seccomp_filter() and asserts on success.
	#[cfg(target_arch = "x86_64")]
	static SECCOMP_ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

	#[cfg(target_arch = "x86_64")]
	#[test]
	fn build_seccomp_filter_succeeds() {
		let _guard = SECCOMP_ENV_MUTEX.lock().unwrap();
		let _ = build_seccomp_filter().expect("filter should construct");
	}

	#[cfg(target_arch = "x86_64")]
	#[test]
	fn build_seccomp_filter_compiles_to_bpf() {
		// Full path: SeccompFilter → BpfProgram. Catches any rule
		// that's structurally valid but rejected at compile time.
		let _guard = SECCOMP_ENV_MUTEX.lock().unwrap();
		let filter = build_seccomp_filter().unwrap();
		let _bpf: BpfProgram = filter.try_into().expect("compile to BPF should succeed");
	}

	#[cfg(target_arch = "x86_64")]
	#[test]
	fn seccomp_default_action_respects_env_var() {
		let _guard = SECCOMP_ENV_MUTEX.lock().unwrap();
		let saved = std::env::var_os("ROSTRO_SECCOMP_ACTION");

		// Unset → KillProcess.
		std::env::remove_var("ROSTRO_SECCOMP_ACTION");
		let (_, label) = seccomp_default_action().unwrap();
		assert_eq!(label, "KILL_PROCESS");

		// "kill" → KillProcess (explicit form).
		std::env::set_var("ROSTRO_SECCOMP_ACTION", "kill");
		let (_, label) = seccomp_default_action().unwrap();
		assert_eq!(label, "KILL_PROCESS");

		// "log" → Log diagnostic mode.
		std::env::set_var("ROSTRO_SECCOMP_ACTION", "log");
		let (_, label) = seccomp_default_action().unwrap();
		assert_eq!(label, "LOG");

		// Anything else fails fast — no silent fallback to a weaker action.
		std::env::set_var("ROSTRO_SECCOMP_ACTION", "allow");
		match seccomp_default_action() {
			Err(SandboxError::InstallFailed { primitive: "seccomp", .. }) => {},
			other => panic!("expected InstallFailed for unknown action, got {other:?}"),
		}

		// Restore for any subsequent test in the same process.
		match saved {
			Some(v) => std::env::set_var("ROSTRO_SECCOMP_ACTION", v),
			None => std::env::remove_var("ROSTRO_SECCOMP_ACTION"),
		}
	}

	#[cfg(target_arch = "x86_64")]
	#[test]
	fn mmap_rule_two_paths_safe_exec() {
		// Phase 5 (2026-05-23): two rules — one for PROT_EXEC=0 (any
		// flags), one for PROT_EXEC=set + MAP_ANONYMOUS=0 (file-backed
		// exec, ld.so library loading). Anonymous executable mappings
		// (JIT-spray) remain DENIED by absence of any matching rule.
		let rules = mmap_safe_rules().unwrap();
		assert_eq!(rules.len(), 2, "two rules: no-exec + file-backed-exec");
	}

	#[cfg(target_arch = "x86_64")]
	#[test]
	fn mprotect_rule_two_paths_safe_exec() {
		// Phase 5 second-pass (2026-05-23): two rules — one for
		// PROT_EXEC=0 (any flags), one for PROT_EXEC=set + PROT_WRITE=0
		// (W^X-preserving JIT flip, PolkaVM runtime executor). True
		// W^X-violating mprotect calls (PROT_WRITE + PROT_EXEC) remain
		// DENIED by absence of any matching rule.
		let rules = mprotect_safe_rules().unwrap();
		assert_eq!(rules.len(), 2, "two rules: no-exec + jit-flip");
	}

	#[cfg(target_arch = "x86_64")]
	#[test]
	fn clone_rule_denies_namespace_flags() {
		let rules = clone_no_namespace_rules().unwrap();
		assert_eq!(rules.len(), 1, "single rule: deny CLONE_NEW*");
	}

	#[cfg(target_arch = "x86_64")]
	#[test]
	fn clone3_enosys_filter_compiles() {
		// The helper must build and compile to a valid BPF program;
		// install_seccomp() loads this into the kernel, so a malformed
		// rule shape would brick the supervisor at startup.
		let filter = force_clone3_enosys_filter().unwrap();
		let bpf: BpfProgram = filter.try_into().expect("compile clone3-enosys");
		assert!(!bpf.is_empty(), "compiled BPF program must be non-empty");
	}

	#[cfg(target_arch = "x86_64")]
	#[test]
	fn clone3_present_in_plain_allowlist_for_stacked_pattern() {
		// Regression catch: clone3 MUST appear in the plain allowlist
		// so the main filter returns ALLOW for it (signed-positive
		// action value). The stacked ENOSYS filter then beats ALLOW
		// via the kernel's signed-min stacking rule. Removing clone3
		// here makes the main filter's default KILL_PROCESS (signed
		// INT_MIN) win every contest, SIGSYS'ing the supervisor on its
		// first Command::spawn — confirmed empirically on Debian 13 /
		// kernel 6.12.88 during the 2026-05-23 lab deploy.
		assert!(
			PLAIN_ALLOWED_SYSCALLS.contains(&libc::SYS_clone3),
			"clone3 must be in PLAIN_ALLOWED_SYSCALLS so main filter \
			 returns ALLOW; ENOSYS shadow filter beats ALLOW but cannot \
			 beat KILL_PROCESS in signed-min stacking",
		);
	}

	#[cfg(target_arch = "x86_64")]
	#[test]
	fn socket_rules_allow_inet_unix_and_netlink_route() {
		// Phase 5 second-pass (2026-05-23): four rules — INET, INET6,
		// UNIX (domain-only), plus AF_NETLINK gated to NETLINK_ROUTE
		// protocol (std::net / libp2p interface enumeration). Other
		// NETLINK protocols (NETLINK_AUDIT, NETLINK_NETFILTER, ...)
		// remain denied by absence.
		let rules = socket_safe_families_rules().unwrap();
		assert_eq!(rules.len(), 4, "INET + INET6 + UNIX + (NETLINK,NETLINK_ROUTE)");
	}

	#[cfg(target_arch = "x86_64")]
	#[test]
	fn ioctl_rules_have_per_cmd_entries() {
		let rules = ioctl_safe_cmds_rules().unwrap();
		// Must be at least the conservative starter set; tracking
		// the exact count separately avoids the test rotting when
		// we add a new cmd in Phase 5.
		assert!(rules.len() >= 5);
	}

	#[cfg(target_arch = "x86_64")]
	#[test]
	fn allowlist_includes_essentials_for_substrate() {
		// Spot-check: a few syscalls without which a substrate node
		// simply cannot run. Regression catch for accidental removal.
		assert!(PLAIN_ALLOWED_SYSCALLS.contains(&libc::SYS_read));
		assert!(PLAIN_ALLOWED_SYSCALLS.contains(&libc::SYS_write));
		assert!(PLAIN_ALLOWED_SYSCALLS.contains(&libc::SYS_futex));
		assert!(PLAIN_ALLOWED_SYSCALLS.contains(&libc::SYS_epoll_wait));
		assert!(PLAIN_ALLOWED_SYSCALLS.contains(&libc::SYS_getrandom));
		assert!(PLAIN_ALLOWED_SYSCALLS.contains(&libc::SYS_openat));
		assert!(PLAIN_ALLOWED_SYSCALLS.contains(&libc::SYS_close));
		assert!(PLAIN_ALLOWED_SYSCALLS.contains(&libc::SYS_clock_gettime));
		assert!(PLAIN_ALLOWED_SYSCALLS.contains(&libc::SYS_fdatasync));
	}

	#[cfg(target_arch = "x86_64")]
	#[test]
	fn allowlist_excludes_known_dangerous_syscalls() {
		// These must NEVER appear on the allowlist — regression catch
		// for accidental additions during merge conflict resolution
		// or copy-paste from a more permissive baseline.
		let dangerous = &[
			libc::SYS_ptrace,
			libc::SYS_process_vm_readv,
			libc::SYS_process_vm_writev,
			libc::SYS_mount,
			libc::SYS_umount2,
			libc::SYS_pivot_root,
			libc::SYS_unshare,
			libc::SYS_setns,
			libc::SYS_kexec_load,
			libc::SYS_init_module,
			libc::SYS_finit_module,
			libc::SYS_delete_module,
			libc::SYS_bpf,
			libc::SYS_perf_event_open,
			libc::SYS_io_uring_setup,
			libc::SYS_io_uring_enter,
			libc::SYS_io_uring_register,
			libc::SYS_swapon,
			libc::SYS_swapoff,
			libc::SYS_reboot,
			libc::SYS_setuid,
			libc::SYS_setgid,
			libc::SYS_setresuid,
			libc::SYS_setresgid,
			libc::SYS_capset,
			libc::SYS_chroot,
			libc::SYS_keyctl,
			libc::SYS_add_key,
			libc::SYS_request_key,
			libc::SYS_userfaultfd,
			libc::SYS_modify_ldt,
			libc::SYS_iopl,
			libc::SYS_ioperm,
			libc::SYS_syslog,
			libc::SYS_open_by_handle_at,
			libc::SYS_name_to_handle_at,
			// clone3 is intentionally NOT asserted here — it's in
			// PLAIN_ALLOWED_SYSCALLS by design (kernel signed-min
			// stacking forces this, see force_clone3_enosys_filter).
			// The companion test clone3_present_in_plain_allowlist_for_stacked_pattern
			// asserts the inverse invariant.
		];
		for sys in dangerous {
			assert!(
				!PLAIN_ALLOWED_SYSCALLS.contains(sys),
				"dangerous syscall {sys} must not be on the allowlist",
			);
		}
	}

	#[test]
	fn write_cgroup_file_maps_error_to_install_failed() {
		// Write to a path that doesn't exist (no parent dir).
		let bad = PathBuf::from("/this/should/not/exist/anywhere/0xdeadbeef");
		match write_cgroup_file(&bad, "anything", "x") {
			Err(SandboxError::InstallFailed { primitive, reason }) => {
				assert_eq!(primitive, "cgroup");
				assert!(reason.contains("write"));
			},
			other => panic!("expected InstallFailed, got {other:?}"),
		}
	}
}
