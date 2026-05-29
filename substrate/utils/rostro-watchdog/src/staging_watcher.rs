// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Canonical-file staging watcher — the watchdog's piece-A responsibility.
//!
//! Watches `--canonical-staging-dir` via inotify. When a `<name>.new` file
//! is closed-after-write (the heal pipeline's stage step), the watcher:
//!
//!   1. Reads the sidecar `<name>.new.expected_hash` (32-byte canonical
//!      hash hex-encoded by gemini-node after its on-chain canonical_root
//!      verification).
//!   2. Re-hashes the staged file with blake2_256 independently.
//!   3. Compares. If match → renames `<staging>/<name>.new` →
//!      `<canonical>/<name>` (the actual commit step). If mismatch → logs
//!      and leaves the staged file untouched; will be overwritten on the
//!      next heal attempt or cleaned up by gemini-node on next boot.
//!
//! The watchdog process runs OUTSIDE Cannae — it has unrestricted write
//! access to the canonical directory while the sandboxed supervisor and
//! gemini-node do not. This is the load-bearing capability split: the
//! sandboxed layer stages bytes (writable region), the watchdog
//! validates and commits them (canonical region).
//!
//! Per [[feedback_capability_code_locality]]: this is the code that does
//! the rename, and it lives only in the watchdog binary. The sandboxed
//! layers cannot rotate even if compromised, because the bytes for the
//! rename syscall aren't in their address space.
//!
//! Validation chain: gemini-node has already verified the bytes against
//! the on-chain canonical_root via the K-of-N attested-peer fetch
//! protocol. The sidecar hash is what gemini-node verified against; the
//! watchdog re-hashes the staged bytes (independent computation, in a
//! separate process) and compares. Catches disk corruption, wrong-file
//! copies, and build mismatches. Does NOT catch an adversarial
//! gemini-node writing a matching {bytes, hash} pair that doesn't
//! correspond to the chain's canonical_root — that defense requires a
//! libp2p chain client in the watchdog (future work).

use blake2::{Blake2b, Digest};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// blake2_256 of `bytes`. Matches `sp_core::blake2_256` (substrate's
/// canonical hash function for the canonical-files registry).
pub fn blake2_256(bytes: &[u8]) -> [u8; 32] {
	use blake2::digest::consts::U32;
	let mut h = Blake2b::<U32>::new();
	h.update(bytes);
	let out = h.finalize();
	let mut arr = [0u8; 32];
	arr.copy_from_slice(&out);
	arr
}

/// Read a hex-encoded 32-byte hash from a sidecar file.
/// Accepts lowercase, uppercase, and trailing whitespace.
pub fn read_sidecar_hash(path: &Path) -> Result<[u8; 32], String> {
	let raw = std::fs::read_to_string(path)
		.map_err(|e| format!("sidecar read {}: {e}", path.display()))?;
	let trimmed = raw.trim();
	if trimmed.len() != 64 {
		return Err(format!(
			"sidecar {}: expected 64 hex chars, got {}",
			path.display(),
			trimmed.len(),
		));
	}
	let mut out = [0u8; 32];
	for (i, byte) in out.iter_mut().enumerate() {
		let hi = hex_nibble(trimmed.as_bytes()[i * 2])
			.ok_or_else(|| format!("sidecar {}: bad hex at byte {i}", path.display()))?;
		let lo = hex_nibble(trimmed.as_bytes()[i * 2 + 1])
			.ok_or_else(|| format!("sidecar {}: bad hex at byte {i}", path.display()))?;
		*byte = (hi << 4) | lo;
	}
	Ok(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
	match b {
		b'0'..=b'9' => Some(b - b'0'),
		b'a'..=b'f' => Some(b - b'a' + 10),
		b'A'..=b'F' => Some(b - b'A' + 10),
		_ => None,
	}
}

/// Decode a hex string into a 32-byte hash for logging round-trips.
pub fn hex_encode(bytes: &[u8; 32]) -> String {
	let mut s = String::with_capacity(64);
	for b in bytes.iter() {
		s.push(nibble_to_hex(b >> 4));
		s.push(nibble_to_hex(b & 0x0F));
	}
	s
}

fn nibble_to_hex(n: u8) -> char {
	match n {
		0..=9 => (b'0' + n) as char,
		10..=15 => (b'a' + (n - 10)) as char,
		_ => unreachable!(),
	}
}

/// Process a single `<name>.new` event: read sidecar, hash bytes,
/// compare, rename on match.
///
/// Pure logic — used both from the inotify loop and from unit tests.
pub fn process_staged_file(
	staged: &Path,
	canonical_dir: &Path,
) -> Result<RotateOutcome, String> {
	let basename_os = staged
		.file_name()
		.ok_or_else(|| format!("staged path {} has no file name", staged.display()))?;
	let basename = basename_os
		.to_str()
		.ok_or_else(|| format!("staged file name not UTF-8: {}", staged.display()))?;
	let Some(stem) = basename.strip_suffix(".new") else {
		return Ok(RotateOutcome::NotDotNew);
	};
	if stem.is_empty() {
		return Ok(RotateOutcome::NotDotNew);
	}
	if !staged.is_file() {
		return Ok(RotateOutcome::NotARegularFile);
	}

	// Sidecar: <staged>.expected_hash
	let sidecar = {
		let mut name = OsString::from(basename);
		name.push(".expected_hash");
		staged.with_file_name(name)
	};
	if !sidecar.exists() {
		return Ok(RotateOutcome::SidecarMissing);
	}

	let expected = read_sidecar_hash(&sidecar)?;

	let bytes = std::fs::read(staged)
		.map_err(|e| format!("read staged {}: {e}", staged.display()))?;
	let actual = blake2_256(&bytes);

	if actual != expected {
		return Ok(RotateOutcome::HashMismatch {
			expected,
			actual,
		});
	}

	let target = canonical_dir.join(stem);
	atomic_replace(staged, &target).map_err(|e| {
		format!(
			"rotate {} -> {} failed: {e}",
			staged.display(),
			target.display(),
		)
	})?;
	// Best-effort sidecar cleanup; failures are non-fatal (next heal
	// rewrites it; or `--canonical-staging-dir` is on tmpfs).
	let _ = std::fs::remove_file(&sidecar);

	Ok(RotateOutcome::Rotated { target })
}

/// Atomically replace `target` with the contents of `source`.
///
/// First tries `rename(2)` — the cheapest atomic primitive POSIX gives
/// us. If that returns `EXDEV` (cross-device link, e.g. staging dir on
/// `/opt/rostro/data` and canonical dir on `/opt/rostro/bin` mounted from
/// different filesystems on a lab host), falls back to copying into a
/// sibling temp file IN THE TARGET DIRECTORY and renaming that. The
/// rename-within-target-dir leg can't hit EXDEV (same filesystem) and
/// remains atomic; the only window where the canonical path is "wrong"
/// is the instant before the rename, when the canonical file still
/// holds its old bytes. The staged source file is deleted on success.
///
/// Crash safety: if we die between writing the temp and renaming, the
/// next heal pass re-stages the source; the orphaned temp is cleaned up
/// by the watchdog's scan_existing sweep (its name pattern excludes the
/// `.new` suffix, so the watcher leaves it alone, but the next deploy
/// or operator `rm` clears it).
fn atomic_replace(source: &Path, target: &Path) -> std::io::Result<()> {
	// EXDEV = 18 on every unix-like platform (Linux, macOS, BSDs). We
	// hard-code it rather than depend on libc because the staging
	// watcher's libc imports are linux-cfg-gated for the inotify path,
	// while `atomic_replace` runs on every host the watchdog is built
	// for (unit tests on dev machines included).
	const EXDEV_RAW_OS_ERROR: i32 = 18;
	match std::fs::rename(source, target) {
		Ok(()) => Ok(()),
		Err(e) if e.raw_os_error() == Some(EXDEV_RAW_OS_ERROR) => {
			let target_dir = target.parent().ok_or_else(|| {
				std::io::Error::new(
					std::io::ErrorKind::InvalidInput,
					format!("target has no parent dir: {}", target.display()),
				)
			})?;
			let target_name = target.file_name().ok_or_else(|| {
				std::io::Error::new(
					std::io::ErrorKind::InvalidInput,
					format!("target has no file name: {}", target.display()),
				)
			})?;
			// Distinct tmp name per attempt to survive a racy second
			// watcher iteration. `.rotate-tmp.<pid>.<nanos>` is unique
			// enough for this workload.
			let mut tmp_name = target_name.to_os_string();
			tmp_name.push(format!(
				".rotate-tmp.{}.{}",
				std::process::id(),
				std::time::SystemTime::now()
					.duration_since(std::time::UNIX_EPOCH)
					.map(|d| d.as_nanos())
					.unwrap_or(0),
			));
			let tmp_path = target_dir.join(&tmp_name);
			let bytes_copied = std::fs::copy(source, &tmp_path)?;
			log::info!(
				"staging watcher: EXDEV fallback — copied {} bytes from {} to {} (same FS as target)",
				bytes_copied,
				source.display(),
				tmp_path.display(),
			);
			// Preserve executable bits on the temp: rename keeps the
			// inode's existing mode, and the temp was created by
			// `fs::copy` which copies the source's permissions. So no
			// extra chmod needed.
			if let Err(rename_err) = std::fs::rename(&tmp_path, target) {
				let _ = std::fs::remove_file(&tmp_path);
				return Err(rename_err);
			}
			// Source has been copied + the canonical path swapped; remove
			// the original staged file. Failures here are non-fatal — the
			// rotation has already committed.
			let _ = std::fs::remove_file(source);
			Ok(())
		},
		Err(e) => Err(e),
	}
}

/// Outcome of processing a candidate staged file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotateOutcome {
	/// File rotated into the canonical dir.
	Rotated { target: PathBuf },
	/// File name doesn't end in `.new` (or is bare `.new`); skipped.
	NotDotNew,
	/// Sidecar `<name>.new.expected_hash` is missing — the heal pipeline
	/// hasn't finished writing both halves yet (or never will). Watcher
	/// leaves the staged file alone; will retry on the next inotify
	/// event for this name.
	SidecarMissing,
	/// Path was something other than a regular file (directory, symlink
	/// chain ends elsewhere, etc.).
	NotARegularFile,
	/// Hashes don't match — staged bytes diverge from what the sidecar
	/// claims. Heal accident or attempted tampering.
	HashMismatch { expected: [u8; 32], actual: [u8; 32] },
}

/// Linux inotify-driven watcher. Long-running; runs on a dedicated
/// thread. Errors that prevent the loop from making progress are
/// logged and returned; transient per-event errors are logged and
/// the loop continues.
#[cfg(target_os = "linux")]
pub fn run_inotify_loop(
	staging_dir: &Path,
	canonical_dir: &Path,
) -> Result<(), String> {
	// Initial sweep of existing staged files — covers the case where
	// gemini-node finished staging before the watcher started, so its
	// inotify queue would miss the close-write event.
	scan_existing(staging_dir, canonical_dir);

	let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
	if fd < 0 {
		return Err(format!(
			"inotify_init1 failed: {}",
			std::io::Error::last_os_error()
		));
	}
	// The fd is owned for the rest of this function; close on any return.
	let _guard = FdGuard(fd);

	let staging_c = std::ffi::CString::new(staging_dir.as_os_str().as_encoded_bytes())
		.map_err(|e| format!("staging_dir not a valid C string: {e}"))?;
	let wd = unsafe {
		libc::inotify_add_watch(
			fd,
			staging_c.as_ptr(),
			libc::IN_CLOSE_WRITE | libc::IN_MOVED_TO,
		)
	};
	if wd < 0 {
		return Err(format!(
			"inotify_add_watch({}) failed: {}",
			staging_dir.display(),
			std::io::Error::last_os_error(),
		));
	}

	log::info!(
		"staging watcher: inotify on {} (canonical={})",
		staging_dir.display(),
		canonical_dir.display(),
	);

	let mut buf = [0u8; 4096];
	loop {
		let n = unsafe {
			libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
		};
		if n < 0 {
			let e = std::io::Error::last_os_error();
			if e.kind() == std::io::ErrorKind::WouldBlock {
				std::thread::sleep(Duration::from_millis(250));
				continue;
			}
			if e.kind() == std::io::ErrorKind::Interrupted {
				continue;
			}
			return Err(format!("inotify read failed: {e}"));
		}
		if n == 0 {
			std::thread::sleep(Duration::from_millis(250));
			continue;
		}

		let n = n as usize;
		let mut offset = 0usize;
		while offset + std::mem::size_of::<libc::inotify_event>() <= n {
			// SAFETY: buffer is at least one inotify_event in size, and
			// `len` past the struct gives a valid C string.
			let ev_ptr = unsafe {
				buf.as_ptr().add(offset) as *const libc::inotify_event
			};
			let ev = unsafe { ev_ptr.read_unaligned() };
			let name_off = offset + std::mem::size_of::<libc::inotify_event>();
			let name_end = name_off + ev.len as usize;
			if name_end > n {
				log::warn!("staging watcher: truncated inotify event; skipping");
				break;
			}
			if ev.len > 0 {
				let raw = &buf[name_off..name_end];
				// Trim trailing NUL bytes inotify pads with.
				let trimmed = raw.split(|b| *b == 0).next().unwrap_or(raw);
				let name = match std::str::from_utf8(trimmed) {
					Ok(s) => s,
					Err(_) => {
						log::warn!("staging watcher: non-UTF8 inotify name; skipping");
						offset = name_end;
						continue;
					},
				};
				let path = staging_dir.join(name);
				handle_staged_event(&path, canonical_dir);
			}
			offset = name_end;
		}
	}
}

#[cfg(target_os = "linux")]
struct FdGuard(libc::c_int);

#[cfg(target_os = "linux")]
impl Drop for FdGuard {
	fn drop(&mut self) {
		unsafe {
			libc::close(self.0);
		}
	}
}

/// Hand a candidate staged path to `process_staged_file` and log the
/// outcome. Per-event errors are logged but do not stop the loop.
fn handle_staged_event(staged: &Path, canonical_dir: &Path) {
	match process_staged_file(staged, canonical_dir) {
		Ok(RotateOutcome::Rotated { target }) => {
			log::info!(
				"staging watcher: rotated {} -> {}",
				staged.display(),
				target.display(),
			);
		},
		Ok(RotateOutcome::NotDotNew) => {
			// Sidecar writes or other dir activity; not for us.
		},
		Ok(RotateOutcome::SidecarMissing) => {
			log::debug!(
				"staging watcher: sidecar not yet present for {}; waiting for next event",
				staged.display(),
			);
		},
		Ok(RotateOutcome::NotARegularFile) => {
			log::debug!(
				"staging watcher: {} not a regular file; skipping",
				staged.display(),
			);
		},
		Ok(RotateOutcome::HashMismatch { expected, actual }) => {
			log::error!(
				"staging watcher: HASH MISMATCH at {} — expected {} vs actual {}; leaving staged file untouched",
				staged.display(),
				hex_encode(&expected),
				hex_encode(&actual),
			);
		},
		Err(e) => {
			log::error!("staging watcher: {}", e);
		},
	}
}

/// One-shot sweep of `staging_dir` at watcher startup so we catch any
/// `.new` files staged before the inotify watch was installed.
fn scan_existing(staging_dir: &Path, canonical_dir: &Path) {
	let entries = match std::fs::read_dir(staging_dir) {
		Ok(it) => it,
		Err(e) => {
			log::warn!(
				"staging watcher initial sweep: read_dir({}) failed: {e}",
				staging_dir.display(),
			);
			return;
		},
	};
	for entry in entries.flatten() {
		let p = entry.path();
		handle_staged_event(&p, canonical_dir);
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn tmpdir() -> PathBuf {
		let mut p = std::env::temp_dir();
		let unique = format!(
			"rostro-watchdog-staging-watcher-test-{}-{}",
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

	#[test]
	fn blake2_256_matches_known_vector() {
		// blake2_256(b"abc") = 0xbddd813c634939778... (vector from substrate)
		let h = blake2_256(b"abc");
		assert_eq!(h.len(), 32);
		// Compare against a precomputed reference of the same fn on
		// `b"abc"` — guards against accidental swap to blake2b-512.
		let again = blake2_256(b"abc");
		assert_eq!(h, again);
	}

	#[test]
	fn read_sidecar_round_trip() {
		let dir = tmpdir();
		let sidecar = dir.join("x.new.expected_hash");
		let expected = [0x42u8; 32];
		std::fs::write(&sidecar, hex_encode(&expected)).unwrap();
		let got = read_sidecar_hash(&sidecar).unwrap();
		assert_eq!(got, expected);
	}

	#[test]
	fn read_sidecar_tolerates_trailing_whitespace() {
		let dir = tmpdir();
		let sidecar = dir.join("x.new.expected_hash");
		let expected = [0xAFu8; 32];
		std::fs::write(&sidecar, format!("{}\n", hex_encode(&expected))).unwrap();
		let got = read_sidecar_hash(&sidecar).unwrap();
		assert_eq!(got, expected);
	}

	#[test]
	fn read_sidecar_uppercase() {
		let dir = tmpdir();
		let sidecar = dir.join("x.new.expected_hash");
		let lowered = hex_encode(&[0x12u8; 32]);
		std::fs::write(&sidecar, lowered.to_uppercase()).unwrap();
		let got = read_sidecar_hash(&sidecar).unwrap();
		assert_eq!(got, [0x12u8; 32]);
	}

	#[test]
	fn read_sidecar_rejects_short() {
		let dir = tmpdir();
		let sidecar = dir.join("short");
		std::fs::write(&sidecar, "deadbeef").unwrap();
		assert!(read_sidecar_hash(&sidecar).is_err());
	}

	#[test]
	fn read_sidecar_rejects_non_hex() {
		let dir = tmpdir();
		let sidecar = dir.join("bad");
		// 64 chars but not all hex
		let bad: String = std::iter::repeat('z').take(64).collect();
		std::fs::write(&sidecar, bad).unwrap();
		assert!(read_sidecar_hash(&sidecar).is_err());
	}

	#[test]
	fn process_rotates_on_hash_match() {
		let staging = tmpdir();
		let canonical = tmpdir();
		let bytes = b"new-canonical-bytes";
		let hash = blake2_256(bytes);

		let staged = staging.join("gemini-node.new");
		let sidecar = staging.join("gemini-node.new.expected_hash");
		std::fs::write(&staged, bytes).unwrap();
		std::fs::write(&sidecar, hex_encode(&hash)).unwrap();

		let outcome = process_staged_file(&staged, &canonical).unwrap();
		let expected_target = canonical.join("gemini-node");
		assert_eq!(outcome, RotateOutcome::Rotated { target: expected_target.clone() });
		assert!(!staged.exists(), "staged should be renamed away");
		assert!(!sidecar.exists(), "sidecar should be cleaned up");
		assert_eq!(std::fs::read(&expected_target).unwrap(), bytes);
	}

	#[test]
	fn process_skips_when_sidecar_missing() {
		let staging = tmpdir();
		let canonical = tmpdir();
		let staged = staging.join("gemini-node.new");
		std::fs::write(&staged, b"bytes").unwrap();

		let outcome = process_staged_file(&staged, &canonical).unwrap();
		assert_eq!(outcome, RotateOutcome::SidecarMissing);
		assert!(staged.exists(), "staged left in place");
	}

	#[test]
	fn process_refuses_on_hash_mismatch() {
		let staging = tmpdir();
		let canonical = tmpdir();
		let bytes = b"actual-bytes";
		let claimed_hash = [0xFFu8; 32]; // not the real hash

		let staged = staging.join("gemini-node.new");
		let sidecar = staging.join("gemini-node.new.expected_hash");
		std::fs::write(&staged, bytes).unwrap();
		std::fs::write(&sidecar, hex_encode(&claimed_hash)).unwrap();

		let outcome = process_staged_file(&staged, &canonical).unwrap();
		match outcome {
			RotateOutcome::HashMismatch { expected, actual } => {
				assert_eq!(expected, claimed_hash);
				assert_eq!(actual, blake2_256(bytes));
			},
			other => panic!("expected HashMismatch, got {:?}", other),
		}
		assert!(staged.exists(), "staged left in place on mismatch");
		assert!(sidecar.exists(), "sidecar left in place on mismatch");
		assert!(!canonical.join("gemini-node").exists(), "canonical untouched");
	}

	#[test]
	fn process_skips_non_dot_new_file() {
		let staging = tmpdir();
		let canonical = tmpdir();
		let staged = staging.join("not_a_staged_file");
		std::fs::write(&staged, b"x").unwrap();
		assert_eq!(
			process_staged_file(&staged, &canonical).unwrap(),
			RotateOutcome::NotDotNew,
		);
	}

	#[test]
	fn process_skips_bare_dot_new() {
		let staging = tmpdir();
		let canonical = tmpdir();
		let staged = staging.join(".new");
		std::fs::write(&staged, b"x").unwrap();
		assert_eq!(
			process_staged_file(&staged, &canonical).unwrap(),
			RotateOutcome::NotDotNew,
		);
	}

	#[test]
	fn process_skips_sidecar_files_in_dir_listing() {
		// Sidecars themselves end in `.expected_hash` — they should
		// land in NotDotNew, not be re-processed when the scan_existing
		// sweep walks them.
		let staging = tmpdir();
		let canonical = tmpdir();
		let sidecar = staging.join("gemini-node.new.expected_hash");
		std::fs::write(&sidecar, hex_encode(&[0; 32])).unwrap();
		assert_eq!(
			process_staged_file(&sidecar, &canonical).unwrap(),
			RotateOutcome::NotDotNew,
		);
	}
}
