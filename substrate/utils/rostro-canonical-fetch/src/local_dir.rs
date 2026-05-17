// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Local directory-backed [`FetchTransport`].
//!
//! Scans a single directory at construction time, hashes each
//! top-level file with blake2_256, builds a `hash → path` index, and
//! serves [`FetchRequest`]s by looking up the requested hash in that
//! index.
//!
//! Two uses:
//!
//! - **Test fixtures.** Populate a temp dir with known canonical
//!   bytes, point the heal flow at it, drive end-to-end tests
//!   without spinning up libp2p.
//! - **Bundled-canonical-files mode.** The Rostro installer can
//!   ship a directory of foundation-canonical artifacts; on heal,
//!   `gemini-node` looks here first before going to peers. Same
//!   transport, different population.
//!
//! Non-recursive on purpose — operators put canonical files at the
//! top level of the heal-source directory. Symlinks are not
//! followed (kernel filetype check excludes them); subdirectories
//! are skipped.

use crate::{
	blake2_256_of, CanonicalFileSource, FetchRequest, FetchResponse, FetchTransport,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// `FetchTransport` impl that reads from a local directory's
/// top-level files, indexed by the blake2_256 hash of each file's
/// contents.
#[derive(Debug)]
pub struct LocalDirectoryFetchTransport {
	index: BTreeMap<[u8; 32], PathBuf>,
}

impl LocalDirectoryFetchTransport {
	/// Scan `dir` and build the hash→path index. I/O errors during
	/// scan are surfaced; individual unreadable files cause the scan
	/// to fail (rather than silently dropping entries from the
	/// index, which would mask configuration mistakes).
	pub fn scan(dir: &Path) -> std::io::Result<Self> {
		let mut index = BTreeMap::new();
		for entry in std::fs::read_dir(dir)? {
			let entry = entry?;
			let ft = entry.file_type()?;
			if !ft.is_file() {
				continue;
			}
			let path = entry.path();
			let bytes = std::fs::read(&path)?;
			let hash = blake2_256_of(&bytes);
			index.insert(hash, path);
		}
		Ok(Self { index })
	}

	/// Number of files indexed. Useful for diagnostic logging
	/// (operator can see "heal source: N canonical files indexed").
	pub fn len(&self) -> usize {
		self.index.len()
	}

	/// Whether the index is empty.
	pub fn is_empty(&self) -> bool {
		self.index.is_empty()
	}
}

impl FetchTransport for LocalDirectoryFetchTransport {
	type Error = std::io::Error;

	fn send_request(
		&mut self,
		request: FetchRequest,
	) -> Result<FetchResponse, std::io::Error> {
		match self.index.get(&request.canonical_hash) {
			Some(path) => {
				let bytes = std::fs::read(path)?;
				Ok(FetchResponse::Bytes(bytes))
			},
			None => Ok(FetchResponse::NotAvailable),
		}
	}
}

/// Server-side surface: same hash → path index, exposed as a
/// [`CanonicalFileSource`] so the [`crate::signed_fetch::handle_signed_request`]
/// helper (and any future libp2p binding) can read by hash. The
/// client and server sides of a node share one
/// [`LocalDirectoryFetchTransport`] instance to keep the cache
/// coherent. I/O errors during the per-hash read are surfaced as
/// `None` (operator sees the absence; serving an error to a peer
/// would just exfiltrate the failure mode without recovery).
impl CanonicalFileSource for LocalDirectoryFetchTransport {
	fn read_by_hash(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
		let path = self.index.get(hash)?;
		std::fs::read(path).ok()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{fetch_and_verify, FetchError};

	fn tmpdir() -> PathBuf {
		let mut p = std::env::temp_dir();
		p.push(format!(
			"rostro-canonical-fetch-test-{}-{}",
			std::process::id(),
			std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH)
				.unwrap()
				.as_nanos(),
		));
		std::fs::create_dir_all(&p).unwrap();
		p
	}

	#[test]
	fn scan_indexes_top_level_files_by_hash() {
		let dir = tmpdir();
		let alpha = b"alpha bytes".to_vec();
		let beta = b"beta bytes".to_vec();
		std::fs::write(dir.join("a.bin"), &alpha).unwrap();
		std::fs::write(dir.join("b.bin"), &beta).unwrap();

		let t = LocalDirectoryFetchTransport::scan(&dir).unwrap();
		assert_eq!(t.len(), 2);
		assert!(t.index.contains_key(&blake2_256_of(&alpha)));
		assert!(t.index.contains_key(&blake2_256_of(&beta)));
	}

	#[test]
	fn scan_skips_subdirectories() {
		let dir = tmpdir();
		std::fs::write(dir.join("top.bin"), b"top").unwrap();
		std::fs::create_dir(dir.join("sub")).unwrap();
		std::fs::write(dir.join("sub").join("nested.bin"), b"nested").unwrap();

		let t = LocalDirectoryFetchTransport::scan(&dir).unwrap();
		assert_eq!(t.len(), 1);
		assert!(t.index.contains_key(&blake2_256_of(b"top")));
		assert!(!t.index.contains_key(&blake2_256_of(b"nested")));
	}

	#[test]
	fn fetch_returns_bytes_when_hash_matches() {
		let dir = tmpdir();
		let payload = b"canonical gemini-node bytes".to_vec();
		std::fs::write(dir.join("gemini-node"), &payload).unwrap();

		let mut t = LocalDirectoryFetchTransport::scan(&dir).unwrap();
		let bytes = fetch_and_verify(&mut t, blake2_256_of(&payload)).unwrap();
		assert_eq!(bytes, payload);
	}

	#[test]
	fn fetch_returns_not_available_when_hash_unknown() {
		let dir = tmpdir();
		std::fs::write(dir.join("a.bin"), b"a").unwrap();

		let mut t = LocalDirectoryFetchTransport::scan(&dir).unwrap();
		let unknown_hash = blake2_256_of(b"definitely not in the dir");
		assert_eq!(fetch_and_verify(&mut t, unknown_hash), Err(FetchError::NotAvailable));
	}

	#[test]
	fn empty_directory_indexes_nothing() {
		let dir = tmpdir();
		let t = LocalDirectoryFetchTransport::scan(&dir).unwrap();
		assert!(t.is_empty());
	}

	#[test]
	fn scan_errors_on_missing_directory() {
		let mut bogus = std::env::temp_dir();
		bogus.push("rostro-canonical-fetch-does-not-exist-zzz");
		assert!(LocalDirectoryFetchTransport::scan(&bogus).is_err());
	}

	#[test]
	fn canonical_file_source_reads_bytes_by_hash() {
		let dir = tmpdir();
		let payload = b"canonical bytes for source impl".to_vec();
		std::fs::write(dir.join("some-file"), &payload).unwrap();

		let t = LocalDirectoryFetchTransport::scan(&dir).unwrap();
		let h = blake2_256_of(&payload);
		// Server-side surface (CanonicalFileSource), same struct
		// the client side uses as a transport.
		let got = CanonicalFileSource::read_by_hash(&t, &h).unwrap();
		assert_eq!(got, payload);
	}

	#[test]
	fn canonical_file_source_returns_none_for_unknown_hash() {
		let dir = tmpdir();
		std::fs::write(dir.join("a"), b"a").unwrap();
		let t = LocalDirectoryFetchTransport::scan(&dir).unwrap();
		let unknown = blake2_256_of(b"definitely not in the dir");
		assert!(CanonicalFileSource::read_by_hash(&t, &unknown).is_none());
	}
}
