// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Phase 7a: native foundation-file verifier.
//!
//! At boot, before service construction, the verifier:
//!
//! 1. Enumerates the foundation files this binary depends on.
//! 2. Hashes each (blake2_256) from disk.
//! 3. Queries the on-chain `pallet-rostro-canonical-files` registry
//!    via the `CanonicalFilesApi` runtime API for the canonical hash.
//! 4. For each file, three outcomes:
//!    - Registered + matches → log OK, continue.
//!    - Registered + mismatch → **fail-stop** the boot with a clear
//!      operator-readable error. Operator is running a modified or
//!      out-of-date file; either re-pull the canonical binary or
//!      have SRT register the new hash.
//!    - Not registered → log "no canonical hash registered for X,
//!      skipping" and continue. Files added post-genesis flow through
//!      via SRT extrinsic; until then the verifier is a no-op for
//!      that file.
//!
//! ## What v0 enforces
//!
//! The gemini-node binary file itself, located via
//! `std::env::current_exe()`. This catches honest mistakes
//! (operator running a stale build, partial download, accidental
//! local patch) and casual tampering (file edits that don't go
//! through the foundation release pipeline).
//!
//! It does NOT defeat sophisticated adversarial modification —
//! the binary could lie about its own hash if it's been patched to
//! do so. That requires hardware attestation (Phase 6.9). v0 is
//! correct for honest operators; full adversary-defense is layered
//! on later.
//!
//! ## What's deferred
//!
//! - Hashing the gemini-runtime WASM blob: substrate already enforces
//!   one canonical runtime via on-chain `:code` + `set_code`. There's
//!   no parallel enforcement to add.
//! - Merkle-tree localization for multi-file diff: with one file in
//!   v0, per-leaf comparison is enough. As the canonical set grows
//!   we'll compose a Merkle tree locally + walk on root mismatch.
//! - Peer-handshake gate (peers verify each other's hashes): waits
//!   on Phase 6.9 hardware attestation for the trustworthy "I'm
//!   running X" claim.

use std::path::PathBuf;
use std::sync::Arc;

use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_runtime::traits::Block as BlockT;

use pallet_rostro_canonical_files::CanonicalFilesApi;

/// Canonical path used in the on-chain registry for the gemini-node
/// binary. SRT extrinsics that register the foundation binary's hash
/// must use this exact string as the key.
const CANONICAL_GEMINI_NODE: &[u8] = b"gemini-node";

/// Synchronous boot-time verification. Returns `Ok(())` if every
/// registered foundation file matches its canonical hash; returns
/// `Err(String)` with a human-readable message on the first
/// mismatch. Files not registered on chain are skipped (logged at
/// info level, not treated as failure).
///
/// Designed to run before `service::new_full` constructs the long-
/// lived service. The caller propagates the error to the CLI runner,
/// which exits the process with the message.
pub fn verify_at_boot<Client, Block>(client: Arc<Client>) -> Result<(), String>
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
		}
		Some(canonical) if canonical == local_hash => {
			log::info!(
				target: "rostro-file-check",
				"foundation file {:?} verified canonical (hash matches on-chain)",
				String::from_utf8_lossy(CANONICAL_GEMINI_NODE),
			);
			Ok(())
		}
		Some(canonical) => Err(format!(
			"FOUNDATION FILE MISMATCH: {:?}\n  \
			 local hash:     0x{}\n  \
			 canonical hash: 0x{}\n\n\
			 This binary is not the canonical foundation build for this chain. \
			 Either pull the foundation's signed release binary, or — if you \
			 are the foundation publishing a new release — register the new \
			 hash via the SRT extrinsic before operators upgrade.",
			std::path::Path::new(&exe_path)
				.file_name()
				.map(|s| s.to_string_lossy().into_owned())
				.unwrap_or_else(|| "<unknown>".to_string()),
			hex_lower(&local_hash),
			hex_lower(&canonical),
		)),
	}
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
