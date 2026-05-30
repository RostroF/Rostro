// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Watchdog recovery cascade — piece B.1 of watchdog v0.2.
//!
//! When the supervisor exits non-zero (crash budget exhausted in the
//! routine case; spawn failure in the deeper case), recovery::run runs
//! signed-manifest-rooted recovery from the local canonical-cache:
//!
//!   1. Verify `manifest.txt.sig` over `manifest.txt` using the
//!      compile-time-baked `ROSTRO_RELEASE_PUBKEY`. On fail, abort —
//!      cache is untrusted, leave the system in operator-intervention
//!      state and propagate non-zero to systemd.
//!   2. Parse manifest for `<sha256>  <basename>` lines. For each
//!      entry:
//!        a. Read `canonical-files-dir/<basename>`. SHA256 + match
//!           against the manifest. On mismatch, abort.
//!        b. Read `canonical-dir/<basename>` (the live binary) and
//!           hash it (blake2_256 + SHA256). If blake2 matches, the
//!           cache and bin are already in sync — skip this entry.
//!        c. Otherwise, write the staged file + sidecar into
//!           `canonical-staging-dir/`:
//!             `<basename>.new.expected_hash` (blake2_256 of verified
//!                                             bytes, hex-encoded)
//!             `<basename>.new`               (verified bytes)
//!           Sidecar-first matches piece A's race-free order.
//!   3. Piece A's `staging_watcher` catches the close-write events,
//!      re-hashes the staged bytes against the sidecar (defense in
//!      depth — two independent checks), and rotates atomically into
//!      `canonical-dir/`.
//!
//! The recovery flow uses the SAME staging pipe gemini-node uses, so
//! the staging_watcher's existing validation + atomic_replace +
//! EXDEV-fallback all apply unchanged.
//!
//! Per [[feedback_trust_but_verify_baked_plus_onchain]]: the trust
//! anchor is the baked pubkey (Layer 0); the manifest verification is
//! Layer 1; reconciliation against the on-chain pubkey is the Layer 2
//! that catches a stale/compromised baked pubkey (see `reconciliation.rs`).

use crate::signed_manifest;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Outcome of a recovery attempt.
#[derive(Debug, PartialEq, Eq)]
pub enum RecoveryOutcome {
	/// At least one file was staged for rotation. Caller should poll
	/// the canonical_dir for completion (staging_watcher rotates
	/// asynchronously) before respawning the supervisor.
	Staged { count: usize, files: Vec<String> },
	/// All canonical-cache files already match the live bin — nothing
	/// to do. Recovery is a no-op; caller can respawn the supervisor
	/// without delay.
	AlreadyInSync,
}

/// Errors from the recovery flow. Distinguished so the caller can log
/// + decide whether to retry or propagate to systemd.
#[derive(Debug)]
pub enum RecoveryError {
	/// `manifest.txt` is missing from the canonical-files-dir.
	ManifestMissing,
	/// `manifest.txt.sig` is missing from the canonical-files-dir.
	SignatureMissing,
	/// I/O error reading a canonical-cache file.
	IoError {
		path: PathBuf,
		err: std::io::Error,
	},
	/// `manifest.txt.sig` failed signature verification against the
	/// baked `ROSTRO_RELEASE_PUBKEY`. This is the security boundary —
	/// recovery refuses to proceed.
	SignatureInvalid(signed_manifest::VerifyError),
	/// A file named in the manifest is missing from the canonical-cache.
	CacheFileMissing { basename: String },
	/// A file in the canonical-cache hashes to something other than
	/// what the manifest claims. Manifest is internally inconsistent
	/// or the cache was tampered with after manifest signing.
	CacheHashMismatch {
		basename: String,
		expected_sha256: [u8; 32],
		actual_sha256: [u8; 32],
	},
	/// Failed to create the staging dir or write a staged file.
	StagingWriteFailed {
		path: PathBuf,
		err: std::io::Error,
	},
	/// `canonical-files-dir` cannot be the same as `canonical-staging-dir`
	/// (would create reads + writes of the same files in the same
	/// directory). Caller misconfiguration.
	BadDirectoryConfig(String),
}

impl std::fmt::Display for RecoveryError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			RecoveryError::ManifestMissing => write!(f, "manifest.txt not found in canonical-files-dir"),
			RecoveryError::SignatureMissing => write!(f, "manifest.txt.sig not found in canonical-files-dir"),
			RecoveryError::IoError { path, err } => write!(f, "I/O error on {}: {err}", path.display()),
			RecoveryError::SignatureInvalid(e) => write!(f, "manifest signature verification failed: {e}"),
			RecoveryError::CacheFileMissing { basename } => write!(f, "manifest names {basename} but it is not in canonical-files-dir"),
			RecoveryError::CacheHashMismatch { basename, expected_sha256, actual_sha256 } => {
				write!(
					f,
					"cache file {basename} sha256 mismatch: expected {} actual {}",
					hex(expected_sha256),
					hex(actual_sha256),
				)
			},
			RecoveryError::StagingWriteFailed { path, err } => write!(f, "staging write to {} failed: {err}", path.display()),
			RecoveryError::BadDirectoryConfig(s) => write!(f, "{s}"),
		}
	}
}

impl std::error::Error for RecoveryError {}

/// Namespace baked into the manifest signature by `release-sign.sh`.
const MANIFEST_NAMESPACE: &str = "rostro-release";

/// Execute the recovery cascade.
///
/// Parameters:
/// - `canonical_files_dir`: where `manifest.txt` + `manifest.txt.sig` +
///   the canonical bytes live (e.g. `/opt/rostro/canonical`).
/// - `canonical_dir`: the live binaries directory the staging_watcher
///   rotates into (e.g. `/opt/rostro/bin`).
/// - `canonical_staging_dir`: the writable staging area the staging_
///   watcher inotifies (e.g. `/opt/rostro/data/staging`).
/// - `expected_pubkey`: compile-time-baked rostro_release pubkey
///   (`crate::ROSTRO_RELEASE_PUBKEY`).
pub fn run(
	canonical_files_dir: &Path,
	canonical_dir: &Path,
	canonical_staging_dir: &Path,
	expected_pubkey: &[u8; 32],
) -> Result<RecoveryOutcome, RecoveryError> {
	if canonical_files_dir == canonical_staging_dir {
		return Err(RecoveryError::BadDirectoryConfig(format!(
			"canonical-files-dir ({}) must differ from canonical-staging-dir",
			canonical_files_dir.display(),
		)));
	}

	let manifest_path = canonical_files_dir.join("manifest.txt");
	let sig_path = canonical_files_dir.join("manifest.txt.sig");
	let manifest_bytes = match std::fs::read(&manifest_path) {
		Ok(b) => b,
		Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
			return Err(RecoveryError::ManifestMissing);
		},
		Err(e) => return Err(RecoveryError::IoError { path: manifest_path, err: e }),
	};
	let sig_bytes = match std::fs::read(&sig_path) {
		Ok(b) => b,
		Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
			return Err(RecoveryError::SignatureMissing);
		},
		Err(e) => return Err(RecoveryError::IoError { path: sig_path, err: e }),
	};

	// Layer 1: verify the manifest signature against the baked pubkey.
	// Everything downstream is conditioned on this passing.
	signed_manifest::verify_ssh_signature(
		&manifest_bytes,
		&sig_bytes,
		MANIFEST_NAMESPACE,
		expected_pubkey,
	)
	.map_err(RecoveryError::SignatureInvalid)?;

	let manifest_text = String::from_utf8_lossy(&manifest_bytes);
	let entries = parse_manifest_entries(&manifest_text);
	if entries.is_empty() {
		return Ok(RecoveryOutcome::AlreadyInSync);
	}

	// Two-pass: verify EVERY cache file against the manifest first,
	// THEN stage any that diverge. Single-pass would leave a partial
	// staging dir behind if a later entry's hash check fails (e.g.
	// gemini-node verified + staged, then rostro-supervisor's cache
	// is corrupt → rostro-supervisor rejected but gemini-node already
	// staged). With the two-pass shape, ANY error before the staging
	// phase means nothing was written.
	let mut to_stage: Vec<(ManifestEntry, Vec<u8>, [u8; 32])> = Vec::new();

	for entry in entries {
		let cache_path = canonical_files_dir.join(&entry.basename);
		let cache_bytes = match std::fs::read(&cache_path) {
			Ok(b) => b,
			Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
				return Err(RecoveryError::CacheFileMissing {
					basename: entry.basename.clone(),
				});
			},
			Err(e) => {
				return Err(RecoveryError::IoError {
					path: cache_path,
					err: e,
				});
			},
		};

		let actual_sha256 = sha256(&cache_bytes);
		if actual_sha256 != entry.sha256 {
			return Err(RecoveryError::CacheHashMismatch {
				basename: entry.basename,
				expected_sha256: entry.sha256,
				actual_sha256,
			});
		}

		// Manifest-verified bytes. Decide if it needs staging.
		let bin_path = canonical_dir.join(&entry.basename);
		let cache_blake2 = blake2_256(&cache_bytes);
		if let Ok(bin_bytes) = std::fs::read(&bin_path) {
			let bin_blake2 = blake2_256(&bin_bytes);
			if bin_blake2 == cache_blake2 {
				log::debug!(
					"recovery: {} in bin already matches canonical-cache; skipping",
					entry.basename,
				);
				continue;
			}
		}
		to_stage.push((entry, cache_bytes, cache_blake2));
	}

	if to_stage.is_empty() {
		return Ok(RecoveryOutcome::AlreadyInSync);
	}

	// All verification passed; now commit by writing staged + sidecar
	// pairs for the divergent files. From this point on, partial-
	// failure can still occur (filesystem error mid-loop) but we've
	// passed the security boundary — the bytes about to be staged are
	// the same bytes the SRT signed.
	std::fs::create_dir_all(canonical_staging_dir).map_err(|e| {
		RecoveryError::StagingWriteFailed {
			path: canonical_staging_dir.to_path_buf(),
			err: e,
		}
	})?;

	let mut staged_names: Vec<String> = Vec::with_capacity(to_stage.len());
	for (entry, cache_bytes, cache_blake2) in to_stage {
		let staged_name = format!("{}.new", entry.basename);
		let sidecar_name = format!("{}.new.expected_hash", entry.basename);
		let staged_path = canonical_staging_dir.join(&staged_name);
		let sidecar_path = canonical_staging_dir.join(&sidecar_name);

		// Sidecar first, then bytes (same order as gemini-node uses
		// in piece A — see file_check.rs::attempt_multi_heal). Race-
		// free: staging_watcher's IN_CLOSE_WRITE on the bytes file is
		// what triggers validation, and the sidecar is in place by
		// the time that fires.
		std::fs::write(&sidecar_path, hex(&cache_blake2)).map_err(|e| {
			RecoveryError::StagingWriteFailed {
				path: sidecar_path.clone(),
				err: e,
			}
		})?;
		std::fs::write(&staged_path, &cache_bytes).map_err(|e| {
			RecoveryError::StagingWriteFailed {
				path: staged_path.clone(),
				err: e,
			}
		})?;
		#[cfg(unix)]
		set_executable_mode(&staged_path);
		log::info!(
			"recovery: staged {} bytes at {} + sidecar at {}",
			cache_bytes.len(),
			staged_path.display(),
			sidecar_path.display(),
		);
		staged_names.push(entry.basename);
	}

	Ok(RecoveryOutcome::Staged {
		count: staged_names.len(),
		files: staged_names,
	})
}

/// Per-file entry in `manifest.txt` after the header lines.
#[derive(Debug)]
struct ManifestEntry {
	sha256: [u8; 32],
	basename: String,
}

/// Parse `manifest.txt`-format lines into `(sha256, basename)`.
/// Skips header lines (`#`, `key: value`, blank). Each canonical-file
/// entry is `<64 hex chars><whitespace><basename>` (output of
/// `sha256sum` is what `release-sign.sh` writes).
fn parse_manifest_entries(text: &str) -> Vec<ManifestEntry> {
	text.lines()
		.filter_map(|line| {
			let trimmed = line.trim();
			if trimmed.is_empty() || trimmed.starts_with('#') {
				return None;
			}
			// First 64 chars should be lowercase hex.
			if trimmed.len() < 65 {
				return None;
			}
			let hash_str = &trimmed[..64];
			let rest = trimmed[64..].trim();
			if rest.is_empty() {
				return None;
			}
			let mut sha = [0u8; 32];
			for (i, byte) in sha.iter_mut().enumerate() {
				let hi = hex_nibble(hash_str.as_bytes()[i * 2])?;
				let lo = hex_nibble(hash_str.as_bytes()[i * 2 + 1])?;
				*byte = (hi << 4) | lo;
			}
			Some(ManifestEntry {
				sha256: sha,
				basename: rest.to_string(),
			})
		})
		.collect()
}

fn hex_nibble(b: u8) -> Option<u8> {
	match b {
		b'0'..=b'9' => Some(b - b'0'),
		b'a'..=b'f' => Some(b - b'a' + 10),
		b'A'..=b'F' => Some(b - b'A' + 10),
		_ => None,
	}
}

fn hex(bytes: &[u8]) -> String {
	let mut s = String::with_capacity(bytes.len() * 2);
	for b in bytes {
		s.push(nib((b >> 4) as u32));
		s.push(nib((b & 0xF) as u32));
	}
	s
}

fn nib(n: u32) -> char {
	match n {
		0..=9 => (b'0' + n as u8) as char,
		10..=15 => (b'a' + (n as u8 - 10)) as char,
		_ => unreachable!(),
	}
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
	let mut h = Sha256::new();
	h.update(bytes);
	let r = h.finalize();
	let mut out = [0u8; 32];
	out.copy_from_slice(&r);
	out
}

fn blake2_256(bytes: &[u8]) -> [u8; 32] {
	crate::staging_watcher::blake2_256(bytes)
}

#[cfg(unix)]
fn set_executable_mode(path: &Path) {
	use std::os::unix::fs::PermissionsExt;
	if let Ok(metadata) = std::fs::metadata(path) {
		let mut perms = metadata.permissions();
		perms.set_mode(0o755);
		let _ = std::fs::set_permissions(path, perms);
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::path::PathBuf;

	const LAB_MANIFEST: &[u8] = include_bytes!(concat!(
		env!("CARGO_MANIFEST_DIR"),
		"/../../../../rostro-testnet-lab/binaries/watchdog-v0.2/manifest.txt"
	));
	const LAB_MANIFEST_SIG: &[u8] = include_bytes!(concat!(
		env!("CARGO_MANIFEST_DIR"),
		"/../../../../rostro-testnet-lab/binaries/watchdog-v0.2/manifest.txt.sig"
	));
	const LAB_GEMINI_NODE: &[u8] = include_bytes!(concat!(
		env!("CARGO_MANIFEST_DIR"),
		"/../../../../rostro-testnet-lab/binaries/watchdog-v0.2/gemini-node"
	));
	const LAB_ROSTRO_SUPERVISOR: &[u8] = include_bytes!(concat!(
		env!("CARGO_MANIFEST_DIR"),
		"/../../../../rostro-testnet-lab/binaries/watchdog-v0.2/rostro-supervisor"
	));

	fn tmpdir(label: &str) -> PathBuf {
		let mut p = std::env::temp_dir();
		p.push(format!(
			"rostro-watchdog-recovery-test-{}-{}-{}",
			label,
			std::process::id(),
			std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH)
				.unwrap()
				.as_nanos(),
		));
		std::fs::create_dir_all(&p).unwrap();
		p
	}

	fn populate_cache(dir: &Path) {
		std::fs::write(dir.join("manifest.txt"), LAB_MANIFEST).unwrap();
		std::fs::write(dir.join("manifest.txt.sig"), LAB_MANIFEST_SIG).unwrap();
		std::fs::write(dir.join("gemini-node"), LAB_GEMINI_NODE).unwrap();
		std::fs::write(dir.join("rostro-supervisor"), LAB_ROSTRO_SUPERVISOR).unwrap();
	}

	#[test]
	fn recovery_stages_when_bin_diverges_from_verified_cache() {
		// Positive: manifest verifies, cache files hash-match the
		// manifest, bin is empty → recovery stages both files.
		let cache = tmpdir("cache-stage");
		let bin = tmpdir("bin-stage");
		let staging = tmpdir("staging-stage");
		populate_cache(&cache);

		let outcome = run(
			&cache,
			&bin,
			&staging,
			crate::ROSTRO_RELEASE_PUBKEY,
		)
		.unwrap();
		match outcome {
			RecoveryOutcome::Staged { count, files } => {
				assert_eq!(count, 2);
				assert!(files.iter().any(|f| f == "gemini-node"));
				assert!(files.iter().any(|f| f == "rostro-supervisor"));
			},
			other => panic!("expected Staged, got {:?}", other),
		}
		// Both pairs of sidecar + bytes are present.
		assert!(staging.join("gemini-node.new").exists());
		assert!(staging.join("gemini-node.new.expected_hash").exists());
		assert!(staging.join("rostro-supervisor.new").exists());
		assert!(staging.join("rostro-supervisor.new.expected_hash").exists());

		// Sidecar's hash matches the blake2_256 of the staged file —
		// this is what staging_watcher will independently re-verify.
		let staged_bytes = std::fs::read(staging.join("gemini-node.new")).unwrap();
		let sidecar = std::fs::read_to_string(staging.join("gemini-node.new.expected_hash")).unwrap();
		assert_eq!(sidecar.trim(), hex(&blake2_256(&staged_bytes)));
	}

	#[test]
	fn recovery_noops_when_bin_already_matches() {
		// Positive: bin already has the correct bytes per the
		// manifest → recovery returns AlreadyInSync without staging
		// anything.
		let cache = tmpdir("cache-sync");
		let bin = tmpdir("bin-sync");
		let staging = tmpdir("staging-sync");
		populate_cache(&cache);
		std::fs::write(bin.join("gemini-node"), LAB_GEMINI_NODE).unwrap();
		std::fs::write(bin.join("rostro-supervisor"), LAB_ROSTRO_SUPERVISOR).unwrap();

		let outcome = run(
			&cache,
			&bin,
			&staging,
			crate::ROSTRO_RELEASE_PUBKEY,
		)
		.unwrap();
		assert_eq!(outcome, RecoveryOutcome::AlreadyInSync);
		// Staging dir should be empty.
		assert!(staging.read_dir().unwrap().next().is_none());
	}

	#[test]
	fn recovery_refuses_when_manifest_signature_invalid() {
		// Negative: forge a manifest by flipping a byte. Signature
		// verify against baked pubkey fails. Nothing staged.
		let cache = tmpdir("cache-bad-sig");
		let bin = tmpdir("bin-bad-sig");
		let staging = tmpdir("staging-bad-sig");
		populate_cache(&cache);
		// Tamper manifest content; signature no longer covers it.
		let mut tampered = LAB_MANIFEST.to_vec();
		tampered[0] ^= 0x01;
		std::fs::write(cache.join("manifest.txt"), tampered).unwrap();

		let result = run(
			&cache,
			&bin,
			&staging,
			crate::ROSTRO_RELEASE_PUBKEY,
		);
		match result {
			Err(RecoveryError::SignatureInvalid(_)) => {},
			other => panic!("expected SignatureInvalid, got {:?}", other),
		}
		assert!(staging.read_dir().unwrap().next().is_none(), "staging must be empty");
	}

	#[test]
	fn recovery_refuses_when_signature_missing() {
		let cache = tmpdir("cache-no-sig");
		let bin = tmpdir("bin-no-sig");
		let staging = tmpdir("staging-no-sig");
		std::fs::write(cache.join("manifest.txt"), LAB_MANIFEST).unwrap();
		// No manifest.txt.sig written.
		let result = run(
			&cache,
			&bin,
			&staging,
			crate::ROSTRO_RELEASE_PUBKEY,
		);
		assert!(matches!(result, Err(RecoveryError::SignatureMissing)));
		assert!(staging.read_dir().unwrap().next().is_none());
	}

	#[test]
	fn recovery_refuses_when_cache_file_hash_drifts() {
		// Negative: manifest verifies (so attacker doesn't have the
		// private key) but a cache file has been swapped underneath
		// it. Cache SHA256 won't match manifest's claimed hash;
		// recovery refuses.
		let cache = tmpdir("cache-drift");
		let bin = tmpdir("bin-drift");
		let staging = tmpdir("staging-drift");
		populate_cache(&cache);
		std::fs::write(cache.join("gemini-node"), b"replaced after signing").unwrap();
		let result = run(
			&cache,
			&bin,
			&staging,
			crate::ROSTRO_RELEASE_PUBKEY,
		);
		match result {
			Err(RecoveryError::CacheHashMismatch { basename, .. }) => {
				assert_eq!(basename, "gemini-node");
			},
			other => panic!("expected CacheHashMismatch, got {:?}", other),
		}
		assert!(staging.read_dir().unwrap().next().is_none());
	}

	#[test]
	fn recovery_refuses_when_cache_file_missing() {
		// Manifest names a file that isn't in the cache (operator
		// deleted it, partial deploy).
		let cache = tmpdir("cache-missing-file");
		let bin = tmpdir("bin-missing-file");
		let staging = tmpdir("staging-missing-file");
		populate_cache(&cache);
		std::fs::remove_file(cache.join("gemini-node")).unwrap();
		let result = run(
			&cache,
			&bin,
			&staging,
			crate::ROSTRO_RELEASE_PUBKEY,
		);
		match result {
			Err(RecoveryError::CacheFileMissing { basename }) => {
				assert_eq!(basename, "gemini-node");
			},
			other => panic!("expected CacheFileMissing, got {:?}", other),
		}
	}

	#[test]
	fn recovery_refuses_when_dirs_collide() {
		let same = tmpdir("collision");
		populate_cache(&same);
		let bin = tmpdir("bin-collide");
		let result = run(&same, &bin, &same, crate::ROSTRO_RELEASE_PUBKEY);
		assert!(matches!(result, Err(RecoveryError::BadDirectoryConfig(_))));
	}

	#[test]
	fn manifest_parse_extracts_entries() {
		let parsed = parse_manifest_entries(&String::from_utf8_lossy(LAB_MANIFEST));
		assert_eq!(parsed.len(), 2);
		assert!(parsed.iter().any(|e| e.basename == "gemini-node"));
		assert!(parsed.iter().any(|e| e.basename == "rostro-supervisor"));
	}

	#[test]
	fn recovery_stages_only_divergent_files() {
		// Mixed case: bin has the correct gemini-node but is missing
		// rostro-supervisor. Only the supervisor gets staged.
		let cache = tmpdir("cache-mixed");
		let bin = tmpdir("bin-mixed");
		let staging = tmpdir("staging-mixed");
		populate_cache(&cache);
		std::fs::write(bin.join("gemini-node"), LAB_GEMINI_NODE).unwrap();
		// rostro-supervisor NOT placed in bin.

		let outcome = run(
			&cache,
			&bin,
			&staging,
			crate::ROSTRO_RELEASE_PUBKEY,
		)
		.unwrap();
		match outcome {
			RecoveryOutcome::Staged { count, files } => {
				assert_eq!(count, 1);
				assert_eq!(files, vec!["rostro-supervisor".to_string()]);
			},
			other => panic!("expected Staged(1), got {:?}", other),
		}
		assert!(staging.join("rostro-supervisor.new").exists());
		assert!(!staging.join("gemini-node.new").exists());
	}
}
