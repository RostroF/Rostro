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
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

/// Exit code the child uses to request a swap-and-restart.
///
/// Chosen above the `sysexits.h` reserved range (64-78) and below the
/// signal-related range (128+), with no conflicts against common
/// Substrate / clap exit codes.
pub const EXIT_SWAP_AND_RESTART: i32 = 90;

/// Default cap on swap-and-restart cycles per supervisor invocation.
/// Bounds crash loops if the staged binary is also broken or the
/// heal flow keeps re-firing.
const DEFAULT_MAX_RESTARTS: u32 = 16;

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
	/// resolve-relative-to-`current_exe()` convention. Pass an empty
	/// string to disable the scan entirely (single-file mode).
	#[arg(long)]
	canonical_dir: Option<PathBuf>,

	/// Maximum swap-and-restart cycles before the supervisor gives up.
	#[arg(long, default_value_t = DEFAULT_MAX_RESTARTS)]
	max_restarts: u32,

	/// Arguments forwarded to the child after `--`.
	#[arg(last = true)]
	child_args: Vec<OsString>,
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

fn run(args: Args) -> ExitCode {
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

	log::info!(
		"rostro-supervisor starting; child={}, staged={}, canonical_dir={}, max_restarts={}",
		child_path.display(),
		staged_path.display(),
		canonical_dir
			.as_deref()
			.map(|p| p.display().to_string())
			.unwrap_or_else(|| "(disabled)".to_string()),
		args.max_restarts,
	);

	let mut restart_count: u32 = 0;
	loop {
		if !child_path.exists() {
			log::error!("child binary {} does not exist", child_path.display());
			return ExitCode::FAILURE;
		}

		let mut cmd = Command::new(&child_path);
		cmd.args(&args.child_args);

		log::info!("spawning child (cycle {}): {}", restart_count, child_path.display());
		let mut child = match cmd.spawn() {
			Ok(c) => c,
			Err(e) => {
				log::error!("failed to spawn child {}: {}", child_path.display(), e);
				return ExitCode::FAILURE;
			},
		};

		let status = match child.wait() {
			Ok(s) => s,
			Err(e) => {
				log::error!("failed to wait on child: {}", e);
				return ExitCode::FAILURE;
			},
		};

		match status.code() {
			Some(code) if code == EXIT_SWAP_AND_RESTART => {
				restart_count = restart_count.saturating_add(1);
				log::info!(
					"child requested swap-and-restart (cycle {} of {})",
					restart_count,
					args.max_restarts,
				);
				if restart_count > args.max_restarts {
					log::error!(
						"max_restarts={} exceeded; supervisor giving up",
						args.max_restarts,
					);
					return ExitCode::FAILURE;
				}
				if let Err(e) = rotate_staged(&staged_path, &child_path) {
					log::error!("staged-binary rotate failed: {}", e);
					return ExitCode::FAILURE;
				}
				// Multi-file: scan the canonical-dir for any other
				// staged files (foo.new -> foo) and rotate each.
				// Order matters — child binary first (just done), so
				// the scan below won't re-see its consumed .new.
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
			Some(0) => {
				log::info!("child exited cleanly; supervisor exiting");
				return ExitCode::SUCCESS;
			},
			Some(code) => {
				log::error!("child exited with code {}; supervisor exiting", code);
				return ExitCode::from(u8::try_from(code).unwrap_or(1));
			},
			None => {
				log::error!("child terminated by signal; supervisor exiting");
				return ExitCode::FAILURE;
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
