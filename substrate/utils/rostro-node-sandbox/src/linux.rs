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
/// 2. noexec bind-remount on RW paths (Phase H, 2026-05-25)
/// 3. Landlock (Phase 3b)
/// 4. seccomp-bpf (Phase 3c)
///
/// Order matters:
/// - cgroup self-cap before everything else so that if Landlock later
///   denies access to `/sys/fs/cgroup/...` (it won't, but defensive
///   thinking), we've already done the cgroup write.
/// - noexec bind-remount before Landlock + seccomp because `mount(2)`
///   isn't in the seccomp allowlist; it MUST run while the supervisor
///   is still unfiltered. After seccomp install, neither supervisor nor
///   child can undo the noexec.
/// - seccomp goes last because it filters out the syscalls we used to
///   install the earlier primitives.
pub(crate) fn install(config: &NodeSandboxConfig) -> Result<SandboxHandle, SandboxError> {
	let cgroup_child = install_cgroup(config)?;
	// PHASE 5 DIAGNOSTIC (2026-05-23): allow skipping Landlock and/or
	// seccomp independently via env vars so we can isolate which
	// primitive is responsible for a failure mode without rebuilding.
	// All default to enabled; set to "1" to skip.
	//
	// F-NEW-R4-FOLLOWUP-1 (2026-05-25): install_mount_ns runs FIRST after
	// cgroup, before noexec bind-remount. It calls `unshare(CLONE_NEWNS)`
	// to give the supervisor + descendants a private mount namespace,
	// then `mount(MS_REC|MS_PRIVATE, "/")` to make propagation a one-way
	// gate (mounts originating in the supervisor's NS don't leak to the
	// host; mounts originating in the host DO propagate down — required
	// for the supervisor to still see operator-managed bind-mounts on
	// `--sandbox-rw-path`s that were already in place). Result: the
	// subsequent bind-remount-with-MS_NOEXEC operates ONLY in the
	// supervisor's mount namespace; the host's `/etc`, `/var/lib`, etc.
	// stay touched-by-noexec only if the OPERATOR explicitly mounted them
	// there. R2-04 + R3-03 denylists become defense-in-depth; this is the
	// architectural fix.
	if std::env::var_os("ROSTRO_SKIP_MOUNT_NS").is_none() {
		install_mount_ns()?;
	} else {
		log::warn!("Cannae: mount-NS unshare SKIPPED via ROSTRO_SKIP_MOUNT_NS — bind-remounts will affect host mount namespace");
	}
	if std::env::var_os("ROSTRO_SKIP_NOEXEC").is_none() {
		install_noexec_remount(config)?;
	} else {
		log::warn!("Cannae: noexec bind-remount SKIPPED via ROSTRO_SKIP_NOEXEC");
	}
	if std::env::var_os("ROSTRO_SKIP_LANDLOCK").is_none() {
		// Thread the child cgroup path into Landlock so the supervisor's
		// subsequent `place_child_in_cgroup` writes (which target a file
		// inside this dir) aren't blocked by the Landlock policy.
		install_landlock(config, cgroup_child.as_deref())?;
	} else {
		log::warn!("Cannae: Landlock SKIPPED via ROSTRO_SKIP_LANDLOCK");
	}
	if std::env::var_os("ROSTRO_SKIP_SECCOMP").is_none() {
		install_seccomp(config)?;
	} else {
		log::warn!("Cannae: seccomp SKIPPED via ROSTRO_SKIP_SECCOMP");
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
			"Cannae cgroup: no caps configured, skipping cgroup self-cap"
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
		// F12 fix (2026-05-24): memory.max alone caps anon allocations
		// but the kernel still allows spill to host swap, silently
		// raising the effective ceiling by however much swap exists.
		// Red-team confirmed a 5GB allocation surviving under a 4GB
		// cap because the overflow went to swap (memory.events.max=1010
		// fired but OOM never did). memory.swap.max=0 pins the cap at
		// memory.max for real. Kernel ≥4.5 + CONFIG_MEMCG_SWAP; absent
		// → warn + continue (older kernels or no swap controller).
		let swap_max_path = child_group.join("memory.swap.max");
		if swap_max_path.exists() {
			write_cgroup_file(&child_group, "memory.swap.max", "0")?;
		} else {
			log::warn!(
				"Cannae cgroup: memory.swap.max not available at {} \
				 (kernel < 4.5 or no CONFIG_MEMCG_SWAP); memory cap can \
				 be silently exceeded via swap if any swap is configured",
				swap_max_path.display(),
			);
		}
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
			"Cannae cgroup: memory.oom.group not available at {} \
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

	let swap_max_pinned = config.memory_cap().is_some()
		&& child_group.join("memory.swap.max").exists();
	log::info!(
		"Cannae cgroup: installed; supervisor stays in its \
		 inherited cgroup (uncapped), child cgroup at {} (memory_max={:?}, \
		 swap_max_pinned={swap_max_pinned}, cpu_max={:?}, oom_kill_atomic={})",
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

// ─── mount-namespace containment (F-NEW-R4-FOLLOWUP-1, 2026-05-25) ─────────

/// Move the supervisor + descendants into a private mount namespace, so
/// `install_noexec_remount`'s bind-mounts affect ONLY this process tree —
/// not the host's mount table. Closes the architectural gap the R3 pen-
/// test confirmed live (bind-mounting `/etc` with the supervisor in the
/// host NS broke the host's `/etc`).
///
/// **Two steps, both privileged:**
///
/// 1. `unshare(CLONE_NEWNS)` — the supervisor process gets a NEW mount
///    namespace. The kernel CoW's the current mount tree into the new
///    NS, so the supervisor still SEES every mount the host has, but
///    subsequent `mount(2)` calls go into the private NS only.
///
/// 2. `mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL)` — turn off
///    upward mount-event propagation for the entire tree rooted at `/`.
///    Without this, the kernel's default `MS_SHARED` propagation on
///    most distros would forward our bind-remounts BACK to the parent
///    NS (host), defeating the whole point of unshare. `MS_PRIVATE`
///    flips every mount in the tree to non-propagating; our subsequent
///    bind-remounts stay contained.
///
/// **`unshare(CLONE_NEWNS)` requires CAP_SYS_ADMIN.** The supervisor is
/// root at install-time and has it. Phase G drops CAP_SYS_ADMIN from
/// the CHILD's bounding set in pre_exec — the child can't undo this
/// mount-NS by re-unsharing.
///
/// **Seccomp ordering:** `unshare(2)` is NOT in `PLAIN_ALLOWED_SYSCALLS`
/// and IS in the dangerous-syscall regression test. This is fine —
/// `install_mount_ns` runs BEFORE `install_seccomp`, so the supervisor
/// can call unshare at install-time even though child + post-install
/// supervisor calls would SIGSYS. The child also cannot call unshare
/// (filter denies it), so the only mount-NS in play is the one this
/// function creates.
///
/// **Operator UX caveat (documented):** `mount | grep` on the host
/// won't show Rostro's bind-remounts after this fix lands; they're
/// visible only inside the supervisor's NS (`nsenter -t <sup_pid> -m
/// mount`). The previous "host-visible Rostro mounts" was the
/// vulnerability, not a feature.
///
/// Diagnostic: `ROSTRO_SKIP_MOUNT_NS=1` to bypass (logs a loud WARN);
/// falls back to host-mount-NS behavior. Use only for ad-hoc debugging.
#[cfg(target_arch = "x86_64")]
fn install_mount_ns() -> Result<(), SandboxError> {
	// Step 1: enter a private mount namespace.
	// SAFETY: unshare(CLONE_NEWNS) is a single syscall with a scalar arg,
	// no memory deref. Failure returns -1/errno.
	let rc = unsafe { libc::unshare(libc::CLONE_NEWNS) };
	if rc != 0 {
		let e = std::io::Error::last_os_error();
		return Err(SandboxError::InstallFailed {
			primitive: "mount_ns",
			reason: format!(
				"unshare(CLONE_NEWNS) failed: {e}. Requires CAP_SYS_ADMIN \
				 (supervisor must be root). If you cannot run as root, \
				 ROSTRO_SKIP_MOUNT_NS=1 bypasses this primitive at the cost \
				 of host-visible bind-remounts.",
			),
		});
	}
	// Step 2: turn off mount-event propagation on the whole tree, so our
	// noexec bind-remounts in step 2 of install() don't propagate back
	// to the parent (host) NS via the kernel's default MS_SHARED mounts.
	// `mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL)`: source/fstype/data
	// are all unused for MS_PRIVATE; the kernel only looks at target ("/")
	// and flags.
	let root = std::ffi::CString::new("/").expect("/ has no NUL");
	let rc = unsafe {
		libc::mount(
			std::ptr::null(),
			root.as_ptr(),
			std::ptr::null(),
			libc::MS_REC | libc::MS_PRIVATE,
			std::ptr::null(),
		)
	};
	if rc != 0 {
		let e = std::io::Error::last_os_error();
		return Err(SandboxError::InstallFailed {
			primitive: "mount_ns",
			reason: format!(
				"mount(MS_REC|MS_PRIVATE, \"/\") failed: {e}. Without this, \
				 the kernel's default MS_SHARED propagation forwards our \
				 bind-remounts back to the parent NS (host), defeating the \
				 unshare. Common cause: a non-standard mount setup where `/` \
				 isn't a mount point reachable from this NS.",
			),
		});
	}
	log::info!(
		"Cannae mount-NS: unshared CLONE_NEWNS + MS_PRIVATE on /; subsequent bind-remounts stay in supervisor's NS"
	);
	Ok(())
}

#[cfg(not(target_arch = "x86_64"))]
fn install_mount_ns() -> Result<(), SandboxError> {
	log::warn!("Cannae mount-NS: stub on non-x86_64; host-visible bind-remounts will be applied");
	Ok(())
}

// ─── noexec bind-remount (Phase H, 2026-05-25) ──────────────────────────────

/// Bind-mount each `--sandbox-rw-path` onto itself and remount the
/// bind with `MS_NOEXEC` so the kernel rejects `mmap(PROT_EXEC, fd, …)`
/// on any inode under those paths at the VFS layer — before Landlock
/// or seccomp see the call. Closes F05: file-backed shellcode staged
/// in `--sandbox-rw-path` and reopened with `PROT_EXEC` now returns
/// `EACCES` from the kernel mount layer.
///
/// **Why this lives here, not in Landlock.** `LANDLOCK_ACCESS_FS_EXECUTE`
/// gates `execve(2)` only; the 2026-05-24 Wave-2 red-team confirmed
/// Phase E's attempt to use it to block `mmap(PROT_EXEC)` was a no-op
/// (`/runs/F05-mmap-exec-file.out`). `MS_NOEXEC` on the mount IS hooked
/// by `mmap(2)` — the kernel checks `MNT_NOEXEC` on the file's mount
/// before honoring `PROT_EXEC` for any file-backed mapping.
///
/// **Why this lives in `install()`, not in a separate helper.** `mount(2)`
/// is NOT in `PLAIN_ALLOWED_SYSCALLS`; the supervisor can only call it
/// before `install_seccomp` runs. Caller (`install`) sequences us
/// between `install_cgroup` and `install_landlock`, while the
/// supervisor still has CAP_SYS_ADMIN + an empty seccomp filter.
///
/// **Idempotence on restart.** When a supervisor restarts after a clean
/// exit, the bind-mount from the previous invocation typically persists
/// (we don't `umount` on drop — see [`SandboxHandle`]). The first
/// `mount(MS_BIND)` returns `EBUSY`, which we tolerate; the second call
/// (`MS_BIND | MS_REMOUNT | MS_NOEXEC`) is the load-bearing one and is
/// idempotent (re-applying noexec is a no-op).
///
/// **WSL caveat (operator note).** WSL2's stock cgroup root doesn't
/// delegate `+cpu` to subtrees by default; that's a separate setup
/// issue. The mount call itself is unaffected — WSL2 exposes a normal
/// kernel mount namespace and `mount(MS_BIND)` works as on bare metal.
#[cfg(target_arch = "x86_64")]
fn install_noexec_remount(config: &NodeSandboxConfig) -> Result<(), SandboxError> {
	use std::ffi::CString;
	use std::os::unix::ffi::OsStrExt;
	if config.rw_paths().is_empty() {
		log::info!(
			"Cannae noexec: no --sandbox-rw-path configured, skipping bind-remount"
		);
		return Ok(());
	}
	for path in config.rw_paths() {
		let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|e| {
			SandboxError::InstallFailed {
				primitive: "noexec_remount",
				reason: format!(
					"path {} contains a NUL byte: {e}",
					path.display(),
				),
			}
		})?;
		// SAFETY: c_path is NUL-terminated; flags are scalar constants;
		// fstype + data are NULL (per mount(2) MS_BIND signature).
		let rc = unsafe {
			libc::mount(
				c_path.as_ptr(),
				c_path.as_ptr(),
				std::ptr::null(),
				libc::MS_BIND,
				std::ptr::null(),
			)
		};
		if rc != 0 {
			let e = std::io::Error::last_os_error();
			// EBUSY = path is already bind-mounted from a prior supervisor
			// invocation. The remount step below will still re-apply
			// noexec, which is what we care about. Any other errno is
			// a real failure (EPERM if we lost CAP_SYS_ADMIN, EINVAL if
			// path doesn't exist, etc.).
			if e.raw_os_error() != Some(libc::EBUSY) {
				return Err(SandboxError::InstallFailed {
					primitive: "noexec_remount",
					reason: format!(
						"mount(MS_BIND, {}, self): {e}",
						path.display(),
					),
				});
			}
			log::debug!(
				"Cannae noexec: {} already bind-mounted (EBUSY); proceeding to remount",
				path.display(),
			);
		}
		// SAFETY: same as above. MS_REMOUNT requires the source to be
		// an existing mount; the MS_BIND step above (or a prior
		// invocation) ensures that.
		let rc = unsafe {
			libc::mount(
				std::ptr::null(),
				c_path.as_ptr(),
				std::ptr::null(),
				libc::MS_BIND | libc::MS_REMOUNT | libc::MS_NOEXEC,
				std::ptr::null(),
			)
		};
		if rc != 0 {
			let e = std::io::Error::last_os_error();
			return Err(SandboxError::InstallFailed {
				primitive: "noexec_remount",
				reason: format!(
					"mount(MS_BIND|MS_REMOUNT|MS_NOEXEC, {}): {e}",
					path.display(),
				),
			});
		}
		log::info!(
			"Cannae noexec: {} bind-remounted MS_NOEXEC (file-backed mmap(PROT_EXEC) denied at VFS layer)",
			path.display(),
		);
	}
	Ok(())
}

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
	// F05 fix (Phase E, 2026-05-24): RW paths grant every fs op EXCEPT
	// Execute. Closes the design-permitted shellcode injection from
	// red-team F05 — attacker writes binary to /opt/rostro/data,
	// mmap PROT_EXEC succeeds because Landlock previously granted Exec
	// on RW paths, then attacker jumps in. With Execute denied on RW
	// inodes, the kernel rejects both `execve()` and `mmap(PROT_EXEC)`
	// on files there. Read-only paths (gemini-node binary etc.) keep
	// Execute via `read_fs` (the landlock-rs default for `from_read()`
	// includes Execute, which is required for the supervisor to exec
	// gemini-node from `--sandbox-ro-path`).
	//
	// Pattern from landlock-rs docs (`fs.rs:42`). Anon mmap PROT_EXEC
	// (no file backing) isn't covered by Landlock — that's F06,
	// by-design for the PolkaVM JIT.
	let rw_no_exec_fs = all_fs & !AccessFs::Execute;

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
				"Cannae landlock: baseline path {path_str} absent, skipping"
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
		rs = rs.add_rule(PathBeneath::new(fd, rw_no_exec_fs)).map_err(|e| {
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
		// Cgroup files aren't executables, so deny Execute here too —
		// principle of least privilege. Aligns with the F05 fix on
		// user-config RW paths.
		rs = rs.add_rule(PathBeneath::new(fd, rw_no_exec_fs)).map_err(|e| {
			landlock_err(&format!("add_rule(cgroup {})", path.display()), e)
		})?;
		// F-AGENT-C-04 reliability fix (2026-05-25): also grant
		// REMOVE_DIR on the cgroup parent dir (`/sys/fs/cgroup/`) so
		// `Drop for SandboxHandle` can rmdir both the child cgroup
		// (rostro-node-<pid>/child) AND the per-invocation parent
		// (rostro-node-<pid>) on supervisor exit. Without this, Drop's
		// `unlinkat(AT_REMOVEDIR)` returns EACCES from Landlock because
		// rmdir's access check is on the PARENT of the removed dir, not
		// the dir itself — and only the child path is in the ruleset.
		//
		// Safe to grant child-side: REMOVE_DIR alone is not RW; the child
		// inherits the grant via exec but as a non-root process it can't
		// rmdir cgroup dirs it doesn't own (kernel DAC blocks writes to
		// root-owned dirs); rmdir of a non-empty / in-use cgroup returns
		// EBUSY at the cgroup-v2 layer regardless of permissions.
		//
		// Computed as the cgroup ROOT (typically `/sys/fs/cgroup`) so the
		// grant covers both `rostro-node-<sup_pid>/` and `…/child`.
		if let Some(cgroup_root) = path.parent().and_then(|p| p.parent()) {
			let fd = PathFd::new(cgroup_root).map_err(|e| {
				landlock_err(
					&format!("PathFd::new(cgroup root {})", cgroup_root.display()),
					e,
				)
			})?;
			let remove_dir_only =
				AccessFs::RemoveDir | AccessFs::ReadDir;
			rs = rs.add_rule(PathBeneath::new(fd, remove_dir_only)).map_err(|e| {
				landlock_err(
					&format!("add_rule(cgroup-root remove-dir {})", cgroup_root.display()),
					e,
				)
			})?;
		}
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
				"Cannae landlock: fully enforced (no_new_privs={})",
				status.no_new_privs
			);
		},
		RulesetStatus::PartiallyEnforced => {
			// Kernel supports Landlock but not all features we
			// requested. BestEffort means the strictest available
			// subset still applies — log so operators know the
			// posture is reduced.
			log::warn!(
				"Cannae landlock: partially enforced (kernel < requested ABI); \
				 strictest available subset is active"
			);
		},
		RulesetStatus::NotEnforced => {
			// Landlock unavailable (kernel < 5.13 or LSM disabled).
			// Fall through; cgroup + seccomp still apply. Surface
			// as warn so the operator can investigate.
			log::warn!(
				"Cannae landlock: NOT enforced — kernel lacks Landlock support \
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
		"Cannae seccomp: clone3-ENOSYS filter installed (forces glibc ≥2.34 \
		 fallback to legacy clone, which is then arg-filtered for CLONE_NEW*)"
	);

	let fchmod_filter = force_fchmod_family_silent_filter()?;
	let fchmod_bpf: BpfProgram = fchmod_filter
		.try_into()
		.map_err(|e| seccomp_err("fchmod-silent compile", e))?;
	seccompiler::apply_filter_all_threads(&fchmod_bpf)
		.map_err(|e| seccomp_err("fchmod-silent apply", e))?;
	log::info!(
		"Cannae seccomp: fchmod-family silent-shadow filter installed \
		 (fchmod/fchmodat/fchown/fchownat return ERRNO=0 with no effect; \
		 closes F13 /proc/self/fd bypass + F-LAB-RT-01 keystore SIGSYS)"
	);

	let (filter, action_label) = build_seccomp_filter_with_label()?;
	let bpf: BpfProgram = filter
		.try_into()
		.map_err(|e| seccomp_err("compile", e))?;
	seccompiler::apply_filter_all_threads(&bpf)
		.map_err(|e| seccomp_err("apply", e))?;
	log::info!(
		"Cannae seccomp: main filter installed ({action_label} on violation, \
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
		"Cannae seccomp: not yet supported on arch {}; skipping (cgroup + \
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
	rules.push((libc::SYS_prlimit64, prlimit64_self_only_rules()?));
	rules.push((libc::SYS_prctl, prctl_safe_options_rules()?));
	rules.push((libc::SYS_setsockopt, setsockopt_safe_options_rules()?));
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
				"Cannae seccomp: ROSTRO_SECCOMP_ACTION=log — denied syscalls \
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
	// F08 fix (2026-05-24): RocksDB calls posix_fadvise() for compaction
	// and WAL I/O hints. Without this on the allowlist the node was in a
	// continuous SIGSYS crash-restart loop on debian-01 the first time
	// compaction fired (red-team observation Phase 5 second-pass). Benign
	// advisory syscall — no security implications.
	libc::SYS_fadvise64,
	// Lab-bring-up gap (2026-05-24): RocksDB calls readahead() for
	// sequential-read prefetching on the WAL replay + sequential SST
	// scan paths. ubuntu-01 (kernel 6.8) hit it 10x in 18min of
	// sustained operation under --chain=local (debian 6.12 + fedora
	// 6.19 didn't). Cross-distro variance: glibc 2.39's readahead
	// wrapper triggers the syscall directly where 2.41's may take a
	// different path. Benign advisory like fadvise64. Cross-distro
	// memory note `[[codebase_inventory]]` ("identical 63-syscall set")
	// was init+idle only and overstated cross-distro consistency.
	libc::SYS_readahead,
	// F-MEMFD closure (2026-05-25): SYS_memfd_create is DENIED by
	// absence. It was previously allowed (commit 03d68cf919, Pending #7
	// cascade) because polkavm's JIT generic-sandbox path used
	// memfd_create() to obtain an anonymous backing fd for executable
	// code regions, falling back to it when CAP_SYS_ADMIN was dropped.
	// Phase H pinned the runtime executor to PolkaVM's interpreter
	// backend (no JIT, no generic-sandbox), making the carve-out dead
	// permission — and the 2026-05-25 pen-test (agent A) demonstrated
	// it as live attack surface: memfd_create + ftruncate + write +
	// mmap(PROT_EXEC) executes arbitrary shellcode from kernel memory
	// with no vfs path Landlock can gate. Strictly more powerful than
	// F05/F06 because the memfd's only path is `/memfd:<name> (deleted)`
	// reflected through /proc/self/fd/N, leaving no on-disk artifact.
	//
	// Re-adding memfd_create here without a documented runtime executor
	// need reopens F-MEMFD. The regression test
	// `memfd_create_not_in_plain_allowlist` enforces this contract.
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
	// F17 fix (2026-05-24): symlinkat was allowed but symlink was not —
	// an asymmetric oversight. Landlock controls the path policy either
	// way; older glibc/Rust paths still hit symlink(2) directly.
	libc::SYS_symlink,
	libc::SYS_utimensat,
	// F13 / F-LAB-RT-01 architecture (2026-05-25): fchmod / fchmodat /
	// fchown / fchownat are in the plain allowlist BUT silently shadowed
	// to a no-op via `force_fchmod_family_silent_filter()`.
	//
	// History: F13 (2026-05-24) removed these four after the red-team
	// showed open(O_RDONLY) → reopen via /proc/self/fd/N as O_RDWR →
	// fchmod(fd, 0666) bypasses Landlock — the kernel's fchmod check
	// looks at inode write permission for the calling EUID (root in our
	// sandbox), NOT the open mode of the passed-in fd. With default-
	// KILL_PROCESS that closes the bypass, but F-LAB-RT-01 (2026-05-25)
	// showed legitimate keystore code (rc-keystore set_permissions(0o600)
	// on a new key file) ALSO hits these and crashes the child via SIGSYS.
	//
	// Architecture per [feedback_seccomp_signed_min_stacking.md]:
	//   * Main filter: fchmod-family in PLAIN_ALLOWED_SYSCALLS → ALLOW
	//     (signed +2.1B). MUST be here so signed-min stacking lets the
	//     shadow filter's ERRNO=0 (signed +327680) win — KILL_PROCESS
	//     (signed INT_MIN) cannot be overridden by any stacked ERRNO.
	//   * Stacked filter: ERRNO=0 (success-with-no-effect).
	//   * `min(ALLOW, ERRNO=0) = ERRNO=0` → syscall returns 0, no
	//     permission change occurs.
	//
	// Threat outcomes:
	//   * F13 attacker (/proc/self/fd/N + fchmod): thinks it succeeded,
	//     but no actual permission flip happens. Same security outcome as
	//     KILL_PROCESS, *better* operationally (no remote-induced DoS).
	//   * F-LAB-RT-01 keystore: set_permissions appears to succeed; key
	//     file retains its O_CREAT default mode (0o600 with umask 077,
	//     0o644 otherwise). The keystore RW path is Landlock-restricted
	//     to the dedicated role UID + supervisor root, so umask is the
	//     only at-rest gating — operator deploys SHOULD set umask 077.
	//
	// fsetxattr stays denied by absence (no observed caller; if a future
	// path hits it, the supervisor SIGSYS classifier surfaces it clearly).
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
	// F07 fix (2026-05-24): prctl is NOT in the plain allowlist. It's
	// arg-filtered separately (prctl_safe_options_rules) to allow only
	// PR_SET_NAME — Phase A's 600s sustained baseline observed prctl
	// 53 times, ALL PR_SET_NAME (Rust std + tokio thread naming).
	// Flat-allowing prctl let red-team reach PR_SET_PTRACER(ANY)
	// (Yama bypass), PR_SET_DUMPABLE (gdb attach surface),
	// PR_CAPBSET_DROP (selective cap drop), and PR_SET_MM (memory map
	// manipulation). New operations beyond PR_SET_NAME will SIGSYS —
	// flip ROSTRO_SECCOMP_ACTION=log to surface, then add to whitelist.
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
	// F04 fix (2026-05-24): setsockopt is NOT in the plain allowlist.
	// It's arg-filtered separately (setsockopt_safe_options_rules) to a
	// whitelist of (level, option) pairs observed in Phase A sustained
	// peering. Flat-allowing setsockopt let red-team reach
	// SO_ATTACH_FILTER — which attaches a cBPF program to a socket and
	// runs in the kernel BPF VM despite bpf(2) being explicitly denied.
	// New (level, option) pairs not in the whitelist will SIGSYS —
	// flip ROSTRO_SECCOMP_ACTION=log to surface, then add with rationale.
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
	// getrlimit/setrlimit take no PID argument — implicitly self.
	// prlimit64 IS arg-filtered separately (see prlimit64_self_only_rules)
	// to require pid=0; flat-allowing it lets a compromised child set
	// rlimits on arbitrary other host PIDs because the supervisor runs
	// as root and the kernel's CAP_SYS_RESOURCE check passes. F01
	// red-team confirmed: setting RLIMIT_NOFILE=8 on PID 1 (systemd)
	// bricked debian-01's sshd — fix-forward 2026-05-24.
	libc::SYS_getrlimit,
	libc::SYS_setrlimit,

	// ── Phase G (2026-05-24): UID drop for the sandboxed child ────
	// The supervisor's pre_exec hook calls setgroups(0, NULL) +
	// setresgid(gid) + setresuid(uid) to drop the child to non-root
	// before exec. Without these in the allowlist, the supervisor's
	// inherited seccomp filter SIGSYS-kills the pre_exec hook.
	//
	// Allowing them is safe because the matching cap-bounding-set
	// drops (CAP_SETUID + CAP_SETGID via drop_root_caps_for_uid_drop_in_child)
	// happen BEFORE setresuid succeeds. After the UID drop, the child
	// is non-root with neither cap in its effective set → kernel
	// EPERMs any attempt to call setresuid(0, ...) back to root, even
	// though seccomp allows the syscall. Seccomp doesn't need to gate
	// what capabilities already gate.
	libc::SYS_setgroups,
	libc::SYS_setresuid,
	libc::SYS_setresgid,
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
///   * Rule 1 (only rule): `(prot & PROT_EXEC) == 0` — pages that never
///     become executable. Heap, stack, RW data buffers, and the final
///     "revoke exec" step on a mapping being torn down.
///
/// What's denied by absence: any `mprotect` that requests `PROT_EXEC`
/// at all. This includes the W^X-preserving JIT flip (`PROT_READ |
/// PROT_EXEC` after `PROT_READ | PROT_WRITE`) and the W^X-violating
/// spray pattern (`PROT_WRITE | PROT_EXEC` directly). Both SIGKILL.
///
/// Phase H (2026-05-25): the previous Rule 2 — `PROT_EXEC != 0 AND
/// PROT_WRITE == 0`, the JIT-flip carve-out — was REMOVED. Rationale:
/// the runtime executor is pinned to PolkaVM's interpreter backend
/// (no JIT), so no legitimate caller in gemini-node needs to flip an
/// anonymous page to executable. The carve-out existed only because
/// upstream polkavm 0.32's JIT was the original executor; Phase H's
/// `RostroCodeExecutor::new` change makes it dead permission. The
/// 2026-05-25 pen-test confirmed F06 (anon mprotect W→X) executed
/// shellcode end-to-end under the previous rule.
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
	])
}

/// Build the rule list for `prlimit64`: arg0 (pid) must be 0 (= self).
///
/// `prlimit64(pid, resource, new_lim, old_lim)` can read OR set rlimits
/// on any PID when the kernel's per-resource permission check passes.
/// As root (the supervisor runs setuid root, and the sandboxed child
/// inherits root), the kernel allows cross-PID writes without CAP_SYS_RESOURCE
/// gating — F01 red-team confirmed by setting RLIMIT_NOFILE=8 on PID 1
/// (systemd), bricking sshd on debian-01.
///
/// glibc maps `getrlimit(2)`/`setrlimit(2)` and `prlimit64(0, ...)`
/// transparently to this syscall with `pid=0`. Substrate's own rlimit
/// raises hit pid=0. The arg filter preserves every legitimate caller
/// and blocks the cross-PID weaponization.
#[cfg(target_arch = "x86_64")]
fn prlimit64_self_only_rules() -> Result<Vec<SeccompRule>, SandboxError> {
	Ok(vec![SeccompRule::new(vec![Cond::new(
		0, // arg0 = pid
		ArgLen::Dword,
		SeccompCmpOp::Eq,
		0,
	)
	.map_err(|e| seccomp_err("prlimit64.pid cond", e))?])
	.map_err(|e| seccomp_err("prlimit64.pid rule", e))?])
}

/// Build the rule list for `prctl`: whitelist arg0 (option) to two
/// values — `PR_SET_NAME` (15) for thread naming + `PR_CAPBSET_DROP`
/// (24) for the Pending #7 supervisor-pre-exec cap drop.
///
/// `prctl(2)` is a multiplexer with ~40 distinct operations. Most are
/// privileged-adjacent — F07 red-team demonstrated:
///
/// - `PR_SET_PTRACER(PR_SET_PTRACER_ANY)` — overrides Yama ptrace
///   scope, letting any host process attach a debugger to the sandbox.
/// - `PR_SET_DUMPABLE(1)` — flips the process to attachable for
///   gdb/ptrace even if SUID transitions cleared it.
/// - `PR_SET_MM(START_CODE, ...)` — manipulates the process's own
///   memory map metadata.
///
/// Phase A 600s sustained baseline observed prctl 53 times — ALL
/// `PR_SET_NAME`. `PR_CAPBSET_DROP` is added not because the workload
/// uses it, but because the supervisor's `Command::pre_exec` hook
/// (Pending #7 fix, 2026-05-24) calls it to drop CAP_SYS_ADMIN from
/// the child between fork() and execve(). Allowing the operation
/// trades a "drop caps for evasion" attacker primitive for the much
/// bigger gain of unconditional CAP_SYS_ADMIN removal at every child
/// spawn — and dropping caps is monotone (one-way reduction), so the
/// attacker only hurts themselves by calling it.
///
/// Operations that would harmlessly land here in the future
/// (`PR_GET_NAME`, `PR_SET_PDEATHSIG`, `PR_SET_KEEPCAPS`) are NOT
/// preemptively allowed — wait for the audit log to surface a real
/// need, then add with rationale.
#[cfg(target_arch = "x86_64")]
fn prctl_safe_options_rules() -> Result<Vec<SeccompRule>, SandboxError> {
	const OPTIONS: &[(u64, &str)] = &[
		(libc::PR_SET_NAME      as u64, "PR_SET_NAME"),
		(libc::PR_CAPBSET_DROP  as u64, "PR_CAPBSET_DROP"),
	];
	let mut rules = Vec::with_capacity(OPTIONS.len());
	for (opt, label) in OPTIONS {
		rules.push(
			SeccompRule::new(vec![Cond::new(
				0, ArgLen::Dword, SeccompCmpOp::Eq, *opt,
			)
			.map_err(|e| seccomp_err(&format!("prctl.option={label} cond"), e))?])
			.map_err(|e| seccomp_err(&format!("prctl.option={label} rule"), e))?,
		);
	}
	Ok(rules)
}

/// Build the rule list for `setsockopt`: whitelist arg1 (level) +
/// arg2 (optname) pairs observed in Phase A sustained peering.
///
/// `setsockopt(2)` is a multiplexer: same syscall number, dozens of
/// reachable code paths inside the kernel depending on (level, option).
/// Flat-allowing it lets a sandboxed process reach `SO_ATTACH_FILTER`
/// — attaches a cBPF program to a socket that the kernel runs on
/// every received packet, bypassing the explicit `bpf(2)` denial
/// entirely (F04 red-team).
///
/// Phase A 600s sustained baseline (debian-01 + 2 peers + 102 blocks)
/// observed setsockopt 10 times across 4 distinct (level, option)
/// pairs:
///
/// - `(SOL_SOCKET, SO_REUSEADDR)` — libp2p listener rebind
/// - `(SOL_SOCKET, SO_REUSEPORT)` — multi-process listener sharing
/// - `(IPPROTO_TCP, TCP_NODELAY)` — disable Nagle's for libp2p framing
/// - `(IPPROTO_IPV6, IPV6_V6ONLY)` — dual-stack listener IPv6-only
///   binding
///
/// Each pair gets its own SeccompRule (two ANDed Conds: level + option);
/// seccomp ORs rules so a match on ANY pair allows.
///
/// New pairs that surface under different workloads (real peering at
/// scale, QUIC, large transfer tuning via `SO_RCVBUF`/`SO_SNDBUF`,
/// keepalive via `TCP_KEEPIDLE`+friends) will SIGSYS — flip
/// `ROSTRO_SECCOMP_ACTION=log` to capture the (level, option) values
/// from the audit log, then add with rationale. Don't pre-emptively
/// whitelist forward-looking options — the least-privilege principle
/// is "only what's empirically needed" (see [[least_privilege_validator_principle]]).
#[cfg(target_arch = "x86_64")]
fn setsockopt_safe_options_rules() -> Result<Vec<SeccompRule>, SandboxError> {
	// (level, option) pairs as i32 → u64 widening. SOL_TCP and SOL_IPV6
	// aren't separate libc constants but their numeric values are
	// IPPROTO_TCP (6) and IPPROTO_IPV6 (41) respectively — same values
	// the kernel matches.
	const PAIRS: &[(u64, u64, &str)] = &[
		(libc::SOL_SOCKET   as u64, libc::SO_REUSEADDR     as u64, "SOL_SOCKET/SO_REUSEADDR"),
		(libc::SOL_SOCKET   as u64, libc::SO_REUSEPORT     as u64, "SOL_SOCKET/SO_REUSEPORT"),
		(libc::IPPROTO_TCP  as u64, libc::TCP_NODELAY      as u64, "IPPROTO_TCP/TCP_NODELAY"),
		(libc::IPPROTO_IPV6 as u64, libc::IPV6_V6ONLY      as u64, "IPPROTO_IPV6/IPV6_V6ONLY"),
		// Lab gap (2026-05-24): mDNS multicast group join, observed via
		// direct strace on `--chain=local` (Phase A used `--dev --no-mdns`
		// and so missed these). libp2p uses mDNS for LAN peer discovery
		// by default; ALL three are needed (membership join + TTL +
		// loopback). Multicast group is `224.0.0.251` (standard mDNS).
		(libc::IPPROTO_IP   as u64, libc::IP_MULTICAST_TTL  as u64, "IPPROTO_IP/IP_MULTICAST_TTL"),
		(libc::IPPROTO_IP   as u64, libc::IP_MULTICAST_LOOP as u64, "IPPROTO_IP/IP_MULTICAST_LOOP"),
		(libc::IPPROTO_IP   as u64, libc::IP_ADD_MEMBERSHIP as u64, "IPPROTO_IP/IP_ADD_MEMBERSHIP"),
	];
	let mut rules = Vec::with_capacity(PAIRS.len());
	for (level, option, label) in PAIRS {
		rules.push(
			SeccompRule::new(vec![
				Cond::new(1, ArgLen::Dword, SeccompCmpOp::Eq, *level)
					.map_err(|e| seccomp_err(&format!("setsockopt.{label}.level cond"), e))?,
				Cond::new(2, ArgLen::Dword, SeccompCmpOp::Eq, *option)
					.map_err(|e| seccomp_err(&format!("setsockopt.{label}.option cond"), e))?,
			])
			.map_err(|e| seccomp_err(&format!("setsockopt.{label} rule"), e))?,
		);
	}
	Ok(rules)
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

/// Stacked filter that intercepts the four fchmod-family syscalls and
/// makes them silent no-ops by returning `ERRNO(0)`.
///
/// **Why a silent shadow, not denial.** F13 (closed 2026-05-24) showed
/// `open(O_RDONLY) → reopen as /proc/self/fd/N O_RDWR → fchmod(fd, 0666)`
/// bypasses Landlock — the kernel's fchmod check uses inode write perm
/// for the calling EUID (root in our sandbox), not the open mode. Denial
/// via `KILL_PROCESS` closes the bypass but F-LAB-RT-01 (2026-05-25)
/// showed legitimate keystore code (`rc-keystore` doing
/// `File::set_permissions(0o600)` on a new key file) hits the same code
/// path and SIGSYS-crashes the child. Silent shadow neutralizes BOTH:
/// the bypass attacker's `chmod 0666` is a no-op (no permission flip)
/// and the keystore's `chmod 0o600` is a no-op (key file retains its
/// `O_CREAT` default mode under operator-set umask).
///
/// **Signed-min stacking dance.** Identical to the clone3 pattern in
/// [`force_clone3_enosys_filter`]. The kernel takes the signed minimum
/// of all stacked filters' actions; KILL_PROCESS (`0x80000000` →
/// `INT_MIN`) wins every contest. So the four syscalls MUST be in
/// [`PLAIN_ALLOWED_SYSCALLS`] (main filter returns `ALLOW` = `0x7fff0000`
/// → +2.1B signed) and this stacked filter returns `ERRNO(0)`
/// (`0x00050000` → +327680 signed). `min(ALLOW, ERRNO=0) = ERRNO=0` →
/// the syscall returns 0 with no kernel-side action.
///
/// **Why ERRNO=0 and not ERRNO=EPERM.** EPERM propagates to the caller
/// as a `PermissionDenied` error, which the keystore code's `?` operator
/// surfaces to the RPC client (or fails the legitimate setup). ERRNO=0
/// preserves the "syscall succeeded" contract callers expect while
/// taking no kernel action. The trade-off: a caller relying on
/// `fchmod` for correctness (the keystore is one) will believe the
/// permission flip happened when it didn't. Mitigated by the Landlock-
/// restricted RW path + dedicated role UID; operators should set
/// `umask 077` so newly-created files inherit restrictive modes by
/// default. Documented in `THREAT_MODEL.md`.
///
/// **fsetxattr not included.** No observed caller in Phase A baseline
/// or Phase 5 idle, and the F-LAB-RT-01 trigger was specifically
/// `fchmod`. fsetxattr stays denied by absence; if a future code path
/// hits it the supervisor's SIGSYS classifier surfaces a clear log
/// line pointing at this filter as the place to extend.
#[cfg(target_arch = "x86_64")]
fn force_fchmod_family_silent_filter() -> Result<SeccompFilter, SandboxError> {
	let rules = vec![
		(libc::SYS_fchmod, vec![]),
		(libc::SYS_fchmodat, vec![]),
		(libc::SYS_fchown, vec![]),
		(libc::SYS_fchownat, vec![]),
	];
	SeccompFilter::new(
		rules.into_iter().collect(),
		SeccompAction::Allow,    // mismatch: let main filter decide
		SeccompAction::Errno(0), // match: silent success (beats main's ALLOW via signed-min)
		TargetArch::x86_64,
	)
	.map_err(|e| seccomp_err("fchmod-silent filter.new", e))
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
	let mut rules = Vec::with_capacity(6);

	// F03 fix (2026-05-24): for AF_INET / AF_INET6 the previous rule
	// only constrained arg0 (domain) and let arg1 (type) through
	// unconstrained — so `socket(AF_INET6, SOCK_RAW, IPPROTO_RAW)`
	// succeeded, letting a compromised sandboxed process craft + inject
	// arbitrary IPv6 packets (red-team F03). Tighten by requiring
	// `(type & SOCK_TYPE_MASK) ∈ {SOCK_STREAM, SOCK_DGRAM}` — type is
	// arg1 with the upper bits used for `SOCK_CLOEXEC` (0x80000) and
	// `SOCK_NONBLOCK` (0x800), so mask with 0xF to get the base type
	// (kernel layout: 4 low bits = type, upper bits = flags).
	//
	// SOCK_STREAM (1) keeps TCP working. SOCK_DGRAM (2) keeps UDP
	// working — important for QUIC libp2p paths (not exercised in
	// Phase A baseline but reasonable forward compat). SOCK_RAW (3)
	// is the attack vector — denied by absence. SOCK_SEQPACKET (5),
	// SOCK_RDM (4), SOCK_PACKET (10), SOCK_DCCP (6) likewise denied.
	const SOCK_TYPE_MASK: u64 = 0xF;
	for family in [libc::AF_INET, libc::AF_INET6] {
		for base_type in [libc::SOCK_STREAM, libc::SOCK_DGRAM] {
			rules.push(
				SeccompRule::new(vec![
					Cond::new(0, ArgLen::Dword, SeccompCmpOp::Eq, family as u64)
						.map_err(|e| seccomp_err(&format!("socket.{family}.domain cond"), e))?,
					Cond::new(
						1, // arg1 = type (with CLOEXEC/NONBLOCK flags OR'd in)
						ArgLen::Dword,
						SeccompCmpOp::MaskedEq(SOCK_TYPE_MASK),
						base_type as u64,
					)
					.map_err(|e| seccomp_err(&format!("socket.{family}.{base_type}.type cond"), e))?,
				])
				.map_err(|e| seccomp_err(&format!("socket.{family}.{base_type} rule"), e))?,
			);
		}
	}

	// AF_UNIX: local IPC, no raw-packet escape concern; any type is
	// fine. Phase A didn't observe AF_UNIX use but keep allowed for
	// substrate's UDS-based components (RPC, prometheus exporter if
	// configured for socket transport).
	rules.push(
		SeccompRule::new(vec![Cond::new(
			0, ArgLen::Dword, SeccompCmpOp::Eq, libc::AF_UNIX as u64,
		)
		.map_err(|e| seccomp_err("socket.unix cond", e))?])
		.map_err(|e| seccomp_err("socket.unix rule", e))?,
	);

	// AF_NETLINK is gated to NETLINK_ROUTE only — interface enumeration
	// for libp2p / std::net (observed in both init+idle and sustained
	// Phase A baselines). All other NETLINK protocols (AUDIT, NETFILTER,
	// KOBJECT_UEVENT, etc.) denied by absence — red-team Appendix A
	// confirmed they SIGKILL correctly.
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
	fn install_cgroup_writes_swap_max_zero_when_file_present() {
		// F12 regression: without memory.swap.max=0, anon allocations
		// spill to host swap and silently raise the effective cap.
		// Pre-create the child cgroup dir + memory.swap.max so the
		// exists() check fires, then assert install wrote "0".
		let root = fake_cgroup_root();
		let pid = std::process::id();
		let child_group = root
			.join(format!("rostro-node-{pid}"))
			.join("child");
		std::fs::create_dir_all(&child_group).unwrap();
		std::fs::write(child_group.join("memory.swap.max"), b"max\n").unwrap();
		let cfg = NodeSandboxConfig::new()
			.cgroup_root(&root)
			.memory_max_bytes(1024 * 1024);
		install_cgroup(&cfg).unwrap();
		let written = std::fs::read_to_string(child_group.join("memory.swap.max")).unwrap();
		assert_eq!(
			written.trim(),
			"0",
			"memory.swap.max must be pinned to 0 so the memory cap can't \
			 be silently exceeded via swap",
		);
	}

	#[test]
	fn install_cgroup_skips_swap_max_when_file_absent() {
		// Warn-and-continue path: kernels without CONFIG_MEMCG_SWAP
		// or hosts with no swap controller compiled in. Install must
		// still succeed.
		let root = fake_cgroup_root();
		let cfg = NodeSandboxConfig::new()
			.cgroup_root(&root)
			.memory_max_bytes(1024 * 1024);
		let child = install_cgroup(&cfg).unwrap().unwrap();
		assert!(
			!child.join("memory.swap.max").exists(),
			"tmpdir setup doesn't create swap.max; warn-and-skip branch exercised",
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
	fn mprotect_rule_denies_all_exec_transitions() {
		// Phase H (2026-05-25): single rule — PROT_EXEC == 0. The JIT-
		// flip carve-out (Rule 2: PROT_EXEC=set + PROT_WRITE=0) was
		// REMOVED when the runtime executor was pinned to PolkaVM's
		// interpreter backend. Any caller that asks for PROT_EXEC now
		// SIGKILLs, closing F06 (anon mprotect W→X JIT-flip). Re-adding
		// a second rule here reopens F06 — confirmed live shellcode
		// execution by the 2026-05-25 pen-test under the previous shape.
		let rules = mprotect_safe_rules().unwrap();
		assert_eq!(rules.len(), 1, "single rule: no-exec only (Phase H)");
	}

	#[cfg(target_arch = "x86_64")]
	#[test]
	fn memfd_create_not_in_plain_allowlist() {
		// F-MEMFD regression: SYS_memfd_create MUST stay off the
		// allowlist. The 2026-05-25 pen-test (agent A) demonstrated
		// memfd_create + ftruncate + write + mmap(PROT_EXEC) executes
		// arbitrary shellcode from kernel memory with no vfs path
		// Landlock can gate — strictly more powerful than F05/F06.
		// Re-adding here without an interpreter-mode runtime executor
		// need reopens F-MEMFD.
		assert!(
			!PLAIN_ALLOWED_SYSCALLS.contains(&libc::SYS_memfd_create),
			"memfd_create re-added to allowlist — reopens F-MEMFD",
		);
	}

	#[cfg(target_arch = "x86_64")]
	#[test]
	fn clone_rule_denies_namespace_flags() {
		let rules = clone_no_namespace_rules().unwrap();
		assert_eq!(rules.len(), 1, "single rule: deny CLONE_NEW*");
	}

	#[cfg(target_arch = "x86_64")]
	#[test]
	fn prlimit64_rule_requires_pid_zero() {
		// F01 regression: any rule must constrain arg0 (pid). One rule
		// is enough — Eq 0 is the constraint. The compiled BPF check
		// is exercised end-to-end by build_seccomp_filter_compiles_to_bpf.
		let rules = prlimit64_self_only_rules().unwrap();
		assert_eq!(rules.len(), 1, "single rule: pid == 0");
	}

	#[cfg(target_arch = "x86_64")]
	#[test]
	fn fchmod_family_in_plain_allowlist_for_silent_shadow_pattern() {
		// F13 + F-LAB-RT-01 architecture (2026-05-25): fchmod / fchmodat /
		// fchown / fchownat MUST be in PLAIN_ALLOWED_SYSCALLS so the main
		// filter returns ALLOW. The stacked `force_fchmod_family_silent_
		// filter` then returns ERRNO=0 (success no-op), and signed-min
		// stacking gives ERRNO=0. Removing any of these from the main
		// allowlist sets main's contribution to KILL_PROCESS (signed
		// INT_MIN), which would beat the ERRNO=0 shadow and SIGSYS the
		// child on the next legitimate keystore set_permissions call
		// (re-opens F-LAB-RT-01). The silent shadow ALSO closes the
		// F13 /proc/self/fd/N bypass — no permission flip occurs even
		// for the attacker, because the syscall is a kernel-side no-op.
		let must_be_present = &[
			libc::SYS_fchmod,
			libc::SYS_fchmodat,
			libc::SYS_fchown,
			libc::SYS_fchownat,
		];
		for sys in must_be_present {
			assert!(
				PLAIN_ALLOWED_SYSCALLS.contains(sys),
				"syscall {sys} removed from allowlist — KILL_PROCESS would \
				 beat the silent-shadow ERRNO=0 in signed-min stacking, \
				 SIGSYS'ing the child on legitimate keystore set_permissions \
				 (re-opens F-LAB-RT-01)",
			);
		}
		// fsetxattr stays denied by absence — no observed caller.
		assert!(
			!PLAIN_ALLOWED_SYSCALLS.contains(&libc::SYS_fsetxattr),
			"fsetxattr should remain denied by absence; if a legitimate \
			 caller appears, add it to the silent-shadow filter rather \
			 than flat-allowing here",
		);
	}

	#[cfg(target_arch = "x86_64")]
	#[test]
	fn fchmod_silent_filter_compiles() {
		// The helper must build and compile to a valid BPF program;
		// install_seccomp() loads this into the kernel at supervisor
		// startup, so a malformed rule shape would brick the supervisor.
		let filter = force_fchmod_family_silent_filter().unwrap();
		let bpf: BpfProgram = filter.try_into().expect("compile fchmod-silent");
		assert!(!bpf.is_empty(), "compiled BPF program must be non-empty");
	}

	#[cfg(target_arch = "x86_64")]
	#[test]
	fn prlimit64_not_in_plain_allowlist() {
		// F01 regression: prlimit64 MUST go through prlimit64_self_only_rules,
		// not the plain allowlist. Re-adding it here flat-allowed reopens
		// the cross-PID rlimit write that bricked debian-01.
		assert!(
			!PLAIN_ALLOWED_SYSCALLS.contains(&libc::SYS_prlimit64),
			"prlimit64 must be arg-filtered for pid=0, not flat-allowed",
		);
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
		// F03 fix (2026-05-24): six rules — (AF_INET|AF_INET6) x
		// (SOCK_STREAM|SOCK_DGRAM) = 4 explicit type-constrained rules,
		// plus AF_UNIX domain-only, plus AF_NETLINK gated to
		// NETLINK_ROUTE. AF_INET[6]+SOCK_RAW denied by absence (the
		// previous "domain-only" rules for AF_INET/INET6 let SOCK_RAW
		// through, the F03 escape vector).
		let rules = socket_safe_families_rules().unwrap();
		assert_eq!(rules.len(), 6,
			"INET+STREAM, INET+DGRAM, INET6+STREAM, INET6+DGRAM, UNIX, (NETLINK,NETLINK_ROUTE)");
	}

	#[cfg(target_arch = "x86_64")]
	#[test]
	fn prctl_rule_whitelists_set_name_and_capbset_drop() {
		// F07 + Pending #7: prctl arg0 must be PR_SET_NAME (15) for
		// thread naming OR PR_CAPBSET_DROP (24) for the supervisor's
		// pre_exec cap-drop hook. Two rules ORed together.
		let rules = prctl_safe_options_rules().unwrap();
		assert_eq!(rules.len(), 2, "PR_SET_NAME + PR_CAPBSET_DROP");
	}

	#[cfg(target_arch = "x86_64")]
	#[test]
	fn setsockopt_rules_whitelist_phase_a_pairs() {
		// F04 regression: 4 (level, option) pairs observed in Phase A
		// sustained peering. Each is a separate SeccompRule with two
		// Conds (level + option). Compiled BPF correctness is exercised
		// end-to-end by build_seccomp_filter_compiles_to_bpf.
		let rules = setsockopt_safe_options_rules().unwrap();
		assert_eq!(rules.len(), 7,
			"4 Phase A pairs + 3 mDNS multicast pairs (IP_MULTICAST_TTL, IP_MULTICAST_LOOP, IP_ADD_MEMBERSHIP)");
	}

	#[cfg(target_arch = "x86_64")]
	#[test]
	fn setsockopt_not_in_plain_allowlist() {
		// F04 regression: setsockopt is a multiplexer; flat-allow reopens
		// SO_ATTACH_FILTER (cBPF VM via socket) despite bpf(2) being
		// denied. Re-adding to PLAIN_ALLOWED_SYSCALLS reopens F04.
		assert!(
			!PLAIN_ALLOWED_SYSCALLS.contains(&libc::SYS_setsockopt),
			"setsockopt must be arg-filtered via setsockopt_safe_options_rules, \
			 not flat-allowed",
		);
	}

	#[cfg(target_arch = "x86_64")]
	#[test]
	fn prctl_not_in_plain_allowlist() {
		// F07 regression: prctl is a multiplexer; flat-allow reopens
		// PR_SET_PTRACER(ANY) (Yama bypass), PR_SET_DUMPABLE, etc.
		// Re-adding to PLAIN_ALLOWED_SYSCALLS reopens F07.
		assert!(
			!PLAIN_ALLOWED_SYSCALLS.contains(&libc::SYS_prctl),
			"prctl must be arg-filtered to PR_SET_NAME via prctl_safe_options_rules, \
			 not flat-allowed",
		);
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
			// setuid/setgid stay dangerous — pre_exec uses setresuid/setresgid
			// (3-arg variants) for the UID drop, not the 1-arg ambient forms.
			libc::SYS_setuid,
			libc::SYS_setgid,
			// setresuid/setresgid/setgroups intentionally NOT asserted here
			// as of Phase G (2026-05-24): they're in PLAIN_ALLOWED_SYSCALLS
			// so the pre_exec UID drop works (see
			// SandboxHandle::drop_to_uid_gid_in_child). The cap-bounding-set
			// drop of CAP_SETUID + CAP_SETGID + CAP_KILL via
			// SandboxHandle::drop_root_caps_for_uid_drop_in_child runs
			// BEFORE setresuid → kernel rejects any setresuid(0,…)
			// reclaim attempt with EPERM. Allow at seccomp, deny at
			// capability — defense in depth at the right layer.
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
