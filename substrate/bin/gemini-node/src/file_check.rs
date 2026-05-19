// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Phase 7a + 7b: native canonical-files verifier with optional
//! peer-driven heal flow.
//!
//! At boot, before service construction, the verifier:
//!
//! 1. Pulls the full canonical fileset from the on-chain registry
//!    (`pallet-rostro-canonical-files::all_files()`).
//! 2. For each registered `(path, hash)` entry, resolves `path` to an
//!    on-disk file (the running binary itself for the canonical
//!    `gemini-node` entry; everything else relative to that binary's
//!    parent directory) and hashes the local file with blake2_256.
//! 3. Collects the diff (mismatch / missing) and one of:
//!
//!    - **Registry empty** → log "skipping" and return `Ok(())`.
//!      Foundation publishes files post-genesis via SRT extrinsic.
//!    - **All match** → log OK, return `Ok(())`, boot continues.
//!    - **One or more mismatches**, split on whether a [`HealFetcher`]
//!      is configured:
//!      - **No heal fetcher** → fail-stop with a per-file diff and
//!        operator-readable instructions.
//!      - **Heal fetcher present** → fetch canonical bytes for each
//!        mismatched file, stage at `<file>.new` (executable
//!        permissions on Unix for binaries), and call
//!        `std::process::exit(90)` once all files are staged.
//!        `rostro-supervisor` recognizes exit code 90 as the
//!        swap-and-restart sentinel and atomically rotates the
//!        staged files into place before re-spawning.
//!
//! ## Why exit-90 instead of swap-in-place
//!
//! A running binary cannot overwrite itself on Linux without races
//! (the kernel keeps the file open, and `rename(2)` over a busy
//! executable is not portable). The supervisor pattern handles this
//! cleanly: gemini-node stages new bytes, exits, supervisor swaps and
//! re-spawns. Two-PID safety is guaranteed by the supervisor; this
//! module only stages and exits. The supervisor's strict zero-PID-
//! overlap stance is load-bearing for validator session-key safety
//! and applies to all node roles in v0.
//!
//! ## What the heal flow does NOT defeat
//!
//! Sophisticated adversarial modification — a tampered binary could
//! lie about its own hash, or short-circuit this entire function.
//! That defense lives at Phase 6.9 (hardware-rooted attestation:
//! TPM/Strongbox signs over a boot measurement that the binary
//! cannot forge). Heal-on-mismatch handles honest mistakes (stale
//! build, partial download, accidental local edit) and provides the
//! network-edge transport story for canonical-file propagation;
//! hardware attestation is its complement.

use std::path::PathBuf;
use std::sync::Arc;

use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_runtime::traits::Block as BlockT;

use pallet_rostro_canonical_files::CanonicalFilesApi;

/// Canonical name used in the on-chain registry for the gemini-node
/// binary itself. SRT extrinsics registering the foundation binary's
/// hash must use this exact string as the key. The verifier resolves
/// this name to `std::env::current_exe()` regardless of where the
/// binary was launched from or whether it was renamed.
const CANONICAL_GEMINI_NODE: &str = "gemini-node";

/// Exit code understood by `rostro-supervisor` as the
/// swap-and-restart sentinel. Kept in sync with
/// `rostro_supervisor::EXIT_SWAP_AND_RESTART`.
const EXIT_SWAP_AND_RESTART: i32 = 90;

/// Heal-side abstraction. Given a canonical hash, fetch and verify
/// the bytes from some source. Implementors typically wrap a
/// `rostro_canonical_fetch::FetchTransport` and adapt its error type.
pub trait HealFetcher: Send + Sync {
	/// Fetch bytes whose blake2_256 hash equals `expected_hash`.
	/// The returned bytes MUST already be verified against the hash
	/// (impl is responsible for not returning unverified bytes; the
	/// caller of this trait will trust the result). Returns a
	/// human-readable error string on any failure.
	fn fetch(&mut self, expected_hash: [u8; 32]) -> Result<Vec<u8>, String>;
}

/// Per-file mismatch record produced by [`collect_diff`].
#[derive(Debug, Clone)]
struct FileMismatch {
	/// On-chain registered path key.
	path: Vec<u8>,
	/// Resolved local filesystem path.
	local_path: PathBuf,
	/// Local file's blake2_256 hash, or `None` if the file is missing.
	local_hash: Option<[u8; 32]>,
	/// Canonical hash registered on chain.
	canonical_hash: [u8; 32],
}

/// Synchronous boot-time verification, with optional heal-on-mismatch.
///
/// Returns `Ok(())` if every registered canonical file matches locally
/// (or the registry is empty). Returns `Err(String)` if one or more
/// files mismatch AND heal cannot recover. Does NOT return when heal
/// succeeds: `std::process::exit(90)` is called after staging all
/// canonical bytes. This is safe pre-service — no databases are open,
/// no network connections, no live state to flush.
pub fn verify_at_boot<Client, Block>(
	client: Arc<Client>,
	heal_fetcher: Option<Box<dyn HealFetcher>>,
) -> Result<(), String>
where
	Block: BlockT,
	Client: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
	Client::Api: CanonicalFilesApi<Block>,
{
	let best = client.info().best_hash;
	let api = client.runtime_api();

	let canonical_entries = api
		.all_files(best)
		.map_err(|e| format!("CanonicalFilesApi::all_files runtime API error: {e:?}"))?;

	if canonical_entries.is_empty() {
		log::info!(
			target: "rostro-file-check",
			"canonical-files registry empty; skipping verification \
			 (foundation will publish via SRT)",
		);
		return Ok(());
	}

	let mismatches = collect_diff(&canonical_entries);
	if mismatches.is_empty() {
		log::info!(
			target: "rostro-file-check",
			"all {} canonical files verified (local hashes match on-chain)",
			canonical_entries.len(),
		);
		return Ok(());
	}

	log::warn!(
		target: "rostro-file-check",
		"{} of {} canonical files differ from on-chain registry",
		mismatches.len(),
		canonical_entries.len(),
	);

	match heal_fetcher {
		Some(fetcher) => attempt_multi_heal(&mismatches, fetcher),
		None => Err(multi_mismatch_message(&mismatches)),
	}
}

/// Walk every canonical entry, resolve each registered path to its
/// local filesystem location, hash the local file, and record any
/// mismatch (including missing-locally as `local_hash = None`).
fn collect_diff(canonical: &[(Vec<u8>, [u8; 32])]) -> Vec<FileMismatch> {
	let mut mismatches = Vec::new();
	for (path, canonical_hash) in canonical {
		let local_path = match resolve_local_path(path) {
			Ok(p) => p,
			Err(e) => {
				log::warn!(
					target: "rostro-file-check",
					"could not resolve canonical path {:?}: {e}",
					String::from_utf8_lossy(path),
				);
				mismatches.push(FileMismatch {
					path: path.clone(),
					local_path: PathBuf::new(),
					local_hash: None,
					canonical_hash: *canonical_hash,
				});
				continue;
			},
		};
		let local_hash = hash_file(&local_path).ok();
		let matches = local_hash.map(|h| h == *canonical_hash).unwrap_or(false);
		if !matches {
			mismatches.push(FileMismatch {
				path: path.clone(),
				local_path,
				local_hash,
				canonical_hash: *canonical_hash,
			});
		}
	}
	mismatches
}

/// Resolve a registered canonical name to a local filesystem path.
///
/// The `gemini-node` entry resolves to [`std::env::current_exe`] itself,
/// which handles renamed binaries, symlinks, and out-of-tree launches
/// cleanly. Every other entry resolves to `<exe_parent>/<name>`,
/// matching the v0 deployment convention that all foundation
/// artifacts ship in one directory.
///
/// ## Why this path is hardcoded, not configurable
///
/// The check path MUST be derived from `current_exe()` and not from
/// any operator-supplied flag. If the operator could redirect "where
/// to look for the canonical files," a malicious operator would
/// point the check at a directory of correctly-hashed pretender
/// files while the binary actually executes from a different
/// location. The gate would pass while the running blob is
/// tampered.
///
/// `current_exe()` is the file the OS is actually running. The
/// other canonical files live next to it because that's where the
/// installer puts them, and there is no flag to redirect. This is
/// the structural defense against the
/// "directory-of-pretenders" attack — load-bearing for the gate's
/// integrity claim. `--canonical-files-dir` is ONLY the heal source
/// (where to fetch *replacement* bytes when the hardcoded check
/// path's contents are wrong); heal bytes are hash-verified
/// before being written, so a malicious heal dir cannot substitute
/// different bytes — it can only fail to provide them.
fn resolve_local_path(canonical_name: &[u8]) -> Result<PathBuf, String> {
	let name_str = std::str::from_utf8(canonical_name)
		.map_err(|e| format!("non-UTF8 canonical path: {e}"))?;

	let exe = std::env::current_exe()
		.map_err(|e| format!("could not resolve executable path: {e}"))?;

	if name_str == CANONICAL_GEMINI_NODE {
		return Ok(exe);
	}

	let dir = exe
		.parent()
		.ok_or_else(|| "executable has no parent directory".to_string())?;
	Ok(dir.join(name_str))
}

/// Stage canonical bytes for each mismatched file, then exit-90 for
/// the supervisor to perform the swap-and-restart.
///
/// On success: never returns. `std::process::exit(90)` short-circuits
/// after every file is staged. The supervisor sees the exit, rotates
/// each `<file>.new` over its target atomically, then re-spawns.
///
/// On any per-file heal failure: returns `Err` immediately. Files
/// that were already staged this run remain on disk as `<file>.new`
/// — they'll be overwritten on the next heal attempt. The supervisor
/// caps overall restart attempts so a stuck heal flow doesn't loop
/// forever.
fn attempt_multi_heal(
	mismatches: &[FileMismatch],
	mut fetcher: Box<dyn HealFetcher>,
) -> Result<(), String> {
	log::warn!(
		target: "rostro-file-check",
		"attempting heal for {} files from configured source",
		mismatches.len(),
	);

	for m in mismatches {
		let local_path = if m.local_path.as_os_str().is_empty() {
			resolve_local_path(&m.path)?
		} else {
			m.local_path.clone()
		};

		let bytes = fetcher.fetch(m.canonical_hash).map_err(|e| {
			format!(
				"FOUNDATION FILE HEAL FAILED: {}\n  \
				 canonical hash: 0x{}\n  \
				 reason:         {e}\n\n\
				 The verifier could not retrieve canonical bytes \
				 for this file from the configured heal source. Pull \
				 the foundation's signed release bundle manually or \
				 supply a different --canonical-files-dir containing \
				 the correct bytes.",
				String::from_utf8_lossy(&m.path),
				hex_lower(&m.canonical_hash),
			)
		})?;

		let staged = staged_path_for(&local_path);
		std::fs::write(&staged, &bytes).map_err(|e| {
			format!("staging write to {} failed: {e}", staged.display())
		})?;

		#[cfg(unix)]
		mark_executable_unix(&staged).map_err(|e| {
			format!("staging chmod {} failed: {e}", staged.display())
		})?;

		log::warn!(
			target: "rostro-file-check",
			"heal staged {} bytes at {} ({})",
			bytes.len(),
			staged.display(),
			String::from_utf8_lossy(&m.path),
		);
	}

	log::warn!(
		target: "rostro-file-check",
		"all {} canonical files staged; exiting code {} for supervisor swap",
		mismatches.len(),
		EXIT_SWAP_AND_RESTART,
	);
	std::process::exit(EXIT_SWAP_AND_RESTART);
}

/// Build the `<file>.new` staging path for the supervisor.
fn staged_path_for(file: &std::path::Path) -> PathBuf {
	let mut staged = file.to_path_buf();
	let stem = file.file_name().map(|n| n.to_owned()).unwrap_or_default();
	let mut name = stem;
	name.push(".new");
	staged.set_file_name(name);
	staged
}

#[cfg(unix)]
fn mark_executable_unix(path: &std::path::Path) -> std::io::Result<()> {
	use std::os::unix::fs::PermissionsExt;
	let mut perms = std::fs::metadata(path)?.permissions();
	// Match a typical release-binary mode (0o755): owner rwx,
	// group/other rx. Non-executable canonical files (e.g., chain
	// spec JSON) get the executable bit too, which is harmless —
	// they just gain `x` they wouldn't have on a fresh install.
	// Keeping a single chmod path avoids per-file metadata.
	perms.set_mode(0o755);
	std::fs::set_permissions(path, perms)
}

/// Format a per-file fail-stop message describing every mismatch and
/// the operator-side remediation. Called only when no heal fetcher is
/// configured.
fn multi_mismatch_message(mismatches: &[FileMismatch]) -> String {
	let mut buf = String::new();
	buf.push_str("FOUNDATION FILESET MISMATCH:\n");
	for m in mismatches {
		let local_hash_str = match m.local_hash {
			Some(h) => format!("0x{}", hex_lower(&h)),
			None => "(file missing locally)".to_string(),
		};
		buf.push_str(&format!(
			"  {}\n    local:     {}\n    canonical: 0x{}\n",
			String::from_utf8_lossy(&m.path),
			local_hash_str,
			hex_lower(&m.canonical_hash),
		));
	}
	buf.push_str(
		"\nThis installation does not match the canonical foundation \
		 fileset registered on-chain.\n\n\
		 No heal source configured (--canonical-files-dir not set). \
		 Pull the foundation's signed release bundle, or — if you are \
		 the foundation publishing a new release — register the new \
		 hashes via the SRT extrinsic before operators upgrade.\n",
	);
	buf
}

fn hash_file(path: &PathBuf) -> Result<[u8; 32], String> {
	use std::io::Read;
	let mut file = std::fs::File::open(path)
		.map_err(|e| format!("opening {path:?}: {e}"))?;
	let mut buf = Vec::with_capacity(64 * 1024);
	file.read_to_end(&mut buf)
		.map_err(|e| format!("reading {path:?}: {e}"))?;
	Ok(sp_core::blake2_256(&buf))
}

fn hex_lower(bytes: &[u8; 32]) -> String {
	let mut s = String::with_capacity(64);
	for b in bytes.iter() {
		s.push(nibble(b >> 4));
		s.push(nibble(b & 0x0f));
	}
	s
}

fn nibble(n: u8) -> char {
	match n {
		0..=9 => (b'0' + n) as char,
		_ => (b'a' + n - 10) as char,
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::path::Path;

	#[test]
	fn staged_path_appends_dot_new() {
		assert_eq!(
			staged_path_for(Path::new("/opt/rostro/bin/gemini-node")),
			PathBuf::from("/opt/rostro/bin/gemini-node.new"),
		);
	}

	#[test]
	fn staged_path_preserves_extension_in_dot_new_form() {
		// Windows-style `.exe` should still get `.new` appended
		// (yielding `gemini-node.exe.new`), matching the supervisor's
		// expectation.
		assert_eq!(
			staged_path_for(Path::new(r"C:\Rostro\gemini-node.exe")),
			PathBuf::from(r"C:\Rostro\gemini-node.exe.new"),
		);
	}

	#[test]
	fn staged_path_works_for_non_binary_canonical_file() {
		// Canonical fileset isn't just binaries — chain spec JSON,
		// release manifests, etc. Staging path logic must work for
		// any file shape.
		assert_eq!(
			staged_path_for(Path::new("/opt/rostro/share/chain-spec.json")),
			PathBuf::from("/opt/rostro/share/chain-spec.json.new"),
		);
	}

	#[test]
	fn multi_mismatch_message_lists_all_diffs() {
		let mismatches = vec![
			FileMismatch {
				path: b"gemini-node".to_vec(),
				local_path: PathBuf::from("/usr/local/bin/gemini-node"),
				local_hash: Some([0xAA; 32]),
				canonical_hash: [0xBB; 32],
			},
			FileMismatch {
				path: b"gemini-runtime.pvm".to_vec(),
				local_path: PathBuf::from("/usr/local/bin/gemini-runtime.pvm"),
				local_hash: None,
				canonical_hash: [0xCC; 32],
			},
		];
		let m = multi_mismatch_message(&mismatches);
		assert!(m.contains("FOUNDATION FILESET MISMATCH"));
		assert!(m.contains("gemini-node"));
		assert!(m.contains("gemini-runtime.pvm"));
		assert!(m.contains("aaaaaaaaaaaaaaaa"));
		assert!(m.contains("bbbbbbbbbbbbbbbb"));
		assert!(m.contains("cccccccccccccccc"));
		assert!(m.contains("file missing locally"));
		assert!(m.contains("No heal source configured"));
	}

	#[test]
	fn hex_lower_emits_64_hex_chars() {
		let h = hex_lower(&[0x0F; 32]);
		assert_eq!(h.len(), 64);
		assert!(h.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
	}

	#[test]
	fn resolve_gemini_node_returns_current_exe() {
		let resolved = resolve_local_path(b"gemini-node").unwrap();
		let exe = std::env::current_exe().unwrap();
		assert_eq!(resolved, exe);
	}

	#[test]
	fn resolve_other_name_returns_exe_parent_join() {
		let resolved = resolve_local_path(b"gemini-runtime.pvm").unwrap();
		let exe = std::env::current_exe().unwrap();
		let expected = exe.parent().unwrap().join("gemini-runtime.pvm");
		assert_eq!(resolved, expected);
	}

	#[test]
	fn resolve_rejects_non_utf8_name() {
		let bad = [0xFF, 0xFE, 0xFD];
		assert!(resolve_local_path(&bad).is_err());
	}

	#[test]
	fn collect_diff_returns_empty_when_no_canonical_entries() {
		let diff = collect_diff(&[]);
		assert!(diff.is_empty());
	}

	#[test]
	fn collect_diff_flags_missing_files_as_mismatch() {
		// A canonical entry that won't resolve to a real local file.
		let canonical = vec![
			(b"definitely-not-a-real-file.xyz".to_vec(), [0xAB; 32]),
		];
		let diff = collect_diff(&canonical);
		assert_eq!(diff.len(), 1);
		assert!(diff[0].local_hash.is_none(), "missing file should have local_hash=None");
		assert_eq!(diff[0].canonical_hash, [0xAB; 32]);
		assert_eq!(diff[0].path, b"definitely-not-a-real-file.xyz");
	}

	/// Heal fetcher that returns a fixed payload regardless of hash.
	/// Used to demonstrate the trait shape; real adapters wrap a
	/// `FetchTransport`.
	struct StubHealFetcher {
		payload: Vec<u8>,
	}
	impl HealFetcher for StubHealFetcher {
		fn fetch(&mut self, _hash: [u8; 32]) -> Result<Vec<u8>, String> {
			Ok(self.payload.clone())
		}
	}

	#[test]
	fn heal_fetcher_trait_object_compiles() {
		let _f: Box<dyn HealFetcher> = Box::new(StubHealFetcher { payload: vec![1, 2, 3] });
	}
}
