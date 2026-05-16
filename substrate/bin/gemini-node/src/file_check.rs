// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Phase 7a + 7b: native foundation-file verifier with optional
//! peer-driven heal flow.
//!
//! At boot, before service construction, the verifier:
//!
//! 1. Hashes the running binary (blake2_256 of `current_exe()`).
//! 2. Queries the on-chain `pallet-rostro-canonical-files` registry
//!    via the `CanonicalFilesApi` runtime API for the canonical
//!    hash registered against `"gemini-node"`.
//! 3. One of three outcomes:
//!
//!    - **Registered + matches** → log OK, return `Ok(())` so boot
//!      continues normally.
//!    - **Not registered** → log "no canonical hash registered for
//!      X, skipping" and return `Ok(())`. Files added post-genesis
//!      flow through via SRT extrinsic; until then the verifier is
//!      a no-op for that file.
//!    - **Registered + mismatch** → split on whether a
//!      [`HealFetcher`] is configured:
//!      - **No heal fetcher** → fail-stop with a clear
//!        operator-readable error (Phase 7a behavior).
//!      - **Heal fetcher present** → attempt to fetch the canonical
//!        bytes by their hash from the configured source. If
//!        successful, stage them at `<exe>.new` (with executable
//!        permissions on Unix), then `std::process::exit(90)`. The
//!        wrapping `rostro-supervisor` recognizes exit code 90 as
//!        the swap-and-restart sentinel: it atomically renames the
//!        staged binary into place and re-spawns. If heal fetch
//!        fails (peer doesn't have the bytes, transport error,
//!        etc.) → fall back to fail-stop with a combined error
//!        message naming both why heal failed and what operator
//!        should do.
//!
//! ## Why exit-90 instead of swap-in-place
//!
//! A running binary cannot overwrite itself on Linux without races
//! (the kernel keeps the file open, and `rename(2)` over a busy
//! executable is not portable). The supervisor pattern (Phase 7b
//! step 1) handles this cleanly: gemini-node stages new bytes,
//! exits, supervisor swaps and re-spawns. Two-PID safety
//! is guaranteed by the supervisor; this module only stages and
//! exits.
//!
//! ## What the heal flow does NOT defeat
//!
//! Sophisticated adversarial modification — a tampered binary
//! could lie about its own hash, or short-circuit this entire
//! function. That defense lives at Phase 6.9 (hardware-rooted
//! attestation: TPM/Strongbox signs over a boot measurement that
//! the binary cannot forge). Heal-on-mismatch handles honest
//! mistakes (stale build, partial download, accidental local edit)
//! and is the network-edge transport story for canonical-file
//! propagation; hardware attestation is its complement.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_runtime::traits::Block as BlockT;

use pallet_rostro_canonical_files::CanonicalFilesApi;

/// Canonical path used in the on-chain registry for the gemini-node
/// binary. SRT extrinsics that register the foundation binary's hash
/// must use this exact string as the key.
const CANONICAL_GEMINI_NODE: &[u8] = b"gemini-node";

/// Exit code understood by `rostro-supervisor` as the
/// swap-and-restart sentinel. Kept in sync with
/// `rostro_supervisor::EXIT_SWAP_AND_RESTART`.
const EXIT_SWAP_AND_RESTART: i32 = 90;

/// Heal-side abstraction. Given a canonical hash, fetch and verify
/// the bytes from some source. Implementors typically wrap a
/// `rostro_canonical_fetch::FetchTransport` and adapt its error
/// type.
pub trait HealFetcher: Send + Sync {
	/// Fetch bytes whose blake2_256 hash equals `expected_hash`.
	/// The returned bytes MUST already be verified against the
	/// hash (impl is responsible for not returning unverified
	/// bytes; the caller of this trait will trust the result).
	/// Returns a human-readable error string on any failure.
	fn fetch(&mut self, expected_hash: [u8; 32]) -> Result<Vec<u8>, String>;
}

/// Synchronous boot-time verification, with optional heal-on-mismatch.
///
/// Returns `Ok(())` if the binary is canonical (or the canonical
/// hash isn't registered yet — the v0 skip path). Returns
/// `Err(String)` with a human-readable message if the binary is
/// non-canonical AND heal cannot recover.
///
/// Does NOT return when heal succeeds: `std::process::exit(90)` is
/// called after staging the new bytes. This is safe pre-service —
/// no databases are open, no network connections, no live state to
/// flush.
pub fn verify_at_boot<Client, Block>(
	client: Arc<Client>,
	heal_fetcher: Option<Box<dyn HealFetcher>>,
) -> Result<(), String>
where
	Block: BlockT,
	Client: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
	Client::Api: CanonicalFilesApi<Block>,
{
	let exe_path = std::env::current_exe()
		.map_err(|e| format!("could not resolve executable path: {e}"))?;
	let local_hash = hash_file(&exe_path)?;

	let best = client.info().best_hash;
	let api = client.runtime_api();
	let registered = api
		.hash_for(best, CANONICAL_GEMINI_NODE.to_vec())
		.map_err(|e| format!("CanonicalFilesApi::hash_for runtime API error: {e:?}"))?;

	match registered {
		None => {
			log::info!(
				target: "rostro-file-check",
				"no canonical hash registered for {:?}; skipping verification \
				 (foundation will publish via SRT)",
				String::from_utf8_lossy(CANONICAL_GEMINI_NODE),
			);
			Ok(())
		},
		Some(canonical) if canonical == local_hash => {
			log::info!(
				target: "rostro-file-check",
				"foundation file {:?} verified canonical (hash matches on-chain)",
				String::from_utf8_lossy(CANONICAL_GEMINI_NODE),
			);
			Ok(())
		},
		Some(canonical) => match heal_fetcher {
			Some(fetcher) => {
				attempt_heal(&exe_path, &local_hash, &canonical, fetcher)
			},
			None => Err(mismatch_message(&exe_path, &local_hash, &canonical, None)),
		},
	}
}

/// Attempt to fetch canonical bytes, stage them, and exit-90.
///
/// On success: never returns — `std::process::exit(90)` short-
/// circuits. Supervisor sees the exit, atomically renames
/// `<exe>.new` → `<exe>`, re-spawns. The new spawn re-runs
/// `verify_at_boot`, this time matching, and continues normal boot.
///
/// On heal failure: returns `Err` with a combined fail-stop message
/// that names both the binary mismatch and why heal couldn't
/// recover — the operator can decide whether to pull canonical
/// bytes manually or rerun with a different `--canonical-files-dir`.
fn attempt_heal(
	exe_path: &Path,
	local_hash: &[u8; 32],
	canonical_hash: &[u8; 32],
	mut fetcher: Box<dyn HealFetcher>,
) -> Result<(), String> {
	log::warn!(
		target: "rostro-file-check",
		"binary hash mismatch; attempting heal from configured source",
	);

	let bytes = match fetcher.fetch(*canonical_hash) {
		Ok(b) => b,
		Err(e) => {
			return Err(mismatch_message(exe_path, local_hash, canonical_hash, Some(&e)));
		},
	};

	let staged = staged_path_for(exe_path);
	if let Err(e) = std::fs::write(&staged, &bytes) {
		return Err(mismatch_message(
			exe_path,
			local_hash,
			canonical_hash,
			Some(&format!("staging write to {} failed: {e}", staged.display())),
		));
	}

	#[cfg(unix)]
	if let Err(e) = mark_executable_unix(&staged) {
		return Err(mismatch_message(
			exe_path,
			local_hash,
			canonical_hash,
			Some(&format!("staging chmod failed: {e}")),
		));
	}

	log::warn!(
		target: "rostro-file-check",
		"heal succeeded; staged {} bytes at {}, exiting code {} for supervisor swap",
		bytes.len(),
		staged.display(),
		EXIT_SWAP_AND_RESTART,
	);
	std::process::exit(EXIT_SWAP_AND_RESTART);
}

/// Build the `<exe>.new` staging path for the supervisor.
fn staged_path_for(exe: &Path) -> PathBuf {
	let mut staged = exe.to_path_buf();
	let stem = exe.file_name().map(|n| n.to_owned()).unwrap_or_default();
	let mut name = stem;
	name.push(".new");
	staged.set_file_name(name);
	staged
}

#[cfg(unix)]
fn mark_executable_unix(path: &Path) -> std::io::Result<()> {
	use std::os::unix::fs::PermissionsExt;
	let mut perms = std::fs::metadata(path)?.permissions();
	// Match a typical release-binary mode (0o755): owner rwx, group/other rx.
	perms.set_mode(0o755);
	std::fs::set_permissions(path, perms)
}

fn mismatch_message(
	exe_path: &Path,
	local_hash: &[u8; 32],
	canonical_hash: &[u8; 32],
	heal_failure: Option<&str>,
) -> String {
	let file_name = exe_path
		.file_name()
		.map(|s| s.to_string_lossy().into_owned())
		.unwrap_or_else(|| "<unknown>".to_string());

	let heal_section = match heal_failure {
		Some(reason) => format!(
			"\n\nHeal attempt failed: {reason}\n\
			 The verifier could not retrieve the canonical bytes \
			 from the configured heal source. Pull the foundation's \
			 signed release binary manually or supply a different \
			 --canonical-files-dir containing the correct bytes."
		),
		None => "\n\nNo heal source configured (--canonical-files-dir not set). \
			 Pull the foundation's signed release binary, or — if you \
			 are the foundation publishing a new release — register the \
			 new hash via the SRT extrinsic before operators upgrade."
			.to_string(),
	};

	format!(
		"FOUNDATION FILE MISMATCH: {file_name}\n  \
		 local hash:     0x{}\n  \
		 canonical hash: 0x{}\n\n\
		 This binary is not the canonical foundation build for this chain.{heal_section}",
		hex_lower(local_hash),
		hex_lower(canonical_hash),
	)
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
	fn mismatch_message_without_heal_says_no_source_configured() {
		let m = mismatch_message(
			Path::new("/usr/local/bin/gemini-node"),
			&[0xAA; 32],
			&[0xBB; 32],
			None,
		);
		assert!(m.contains("FOUNDATION FILE MISMATCH"));
		assert!(m.contains("gemini-node"));
		assert!(m.contains("No heal source configured"));
		assert!(m.contains("aaaaaaaaaaaaaaaa"));
		assert!(m.contains("bbbbbbbbbbbbbbbb"));
	}

	#[test]
	fn mismatch_message_with_heal_failure_includes_reason() {
		let m = mismatch_message(
			Path::new("/usr/local/bin/gemini-node"),
			&[0xAA; 32],
			&[0xBB; 32],
			Some("peer returned NotAvailable"),
		);
		assert!(m.contains("Heal attempt failed"));
		assert!(m.contains("peer returned NotAvailable"));
	}

	#[test]
	fn hex_lower_emits_64_hex_chars() {
		let h = hex_lower(&[0x0F; 32]);
		assert_eq!(h.len(), 64);
		assert!(h.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
	}

	/// Heal fetcher that returns a fixed payload regardless of
	/// hash. Used to demonstrate the trait shape; real adapters
	/// wrap a `FetchTransport`.
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
