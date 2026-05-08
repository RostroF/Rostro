// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # Rostro canonical-file fetch protocol primitives
//!
//! Phase 7b step 3.
//!
//! Bytes-by-hash p2p protocol for canonical-file fetch. Used by the
//! heal flow: when a node detects its local foundation fileset
//! diverges from the on-chain canonical-files registry, it asks a
//! peer for the bytes whose blake2_256 hash matches the canonical
//! value. Peers serve bytes best-effort; the receiver always
//! verifies the hash matches before treating the bytes as canonical.
//! **Hash is authority.** A malicious peer can serve any bytes it
//! wants, but only bytes whose hash matches the canonical-files
//! registry get written to disk.
//!
//! ## What's in this crate
//!
//! - [`FetchRequest`] / [`FetchResponse`]: SCALE-encoded wire types.
//! - [`verify_response_bytes`]: pure verification primitive
//!   (blake2_256 hash check + size cap).
//! - [`CanonicalFileSource`]: server-side trait for "look up bytes
//!   by hash."
//! - [`handle_request`]: server-side request handler.
//! - [`FetchTransport`]: client-side trait abstracting the actual
//!   request/response transport.
//! - [`fetch_and_verify`]: client-side helper that issues a request
//!   and verifies the response before returning bytes.
//!
//! ## What's NOT in this crate
//!
//! No libp2p, no `sc-network`, no async runtime. The protocol is
//! transport-agnostic so it's testable without spinning up a full
//! networking stack and so it can be re-bound to other transports
//! if needed. Phase 7b step 5 binds these primitives to a real
//! `sc-network` request/response protocol.
//!
//! ## Apache-2.0 stays Apache-2.0
//!
//! Two minimal workspace deps (`codec`, `sp-crypto-hashing`); no
//! Substrate-client dependencies. Lives in `substrate/utils/`,
//! consistent with the project's "Apache-2.0 utilities go here, not
//! in `substrate/client/`" convention.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "std")]
pub mod local_dir;

use alloc::vec::Vec;
use codec::{Decode, Encode};
use sp_crypto_hashing::blake2_256;

/// Hard cap on a single fetch response's payload size. 16 MiB.
///
/// A canonical foundation file (the `gemini-node` binary, the
/// gemini-runtime WASM blob, foundation data files) is well under
/// this in practice. The cap exists so a malicious peer can't claim
/// to have a 100 GB file and OOM the receiver while it tries to
/// buffer the response. If a legitimate canonical file ever needs
/// more, raise this constant — but it should be a deliberate
/// decision tied to a specific oversized artifact, not a casual
/// loosening.
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// On-the-wire request: a single 32-byte canonical hash naming the
/// bytes the caller wants. The hash itself is the authority — the
/// caller already learned this hash from the on-chain canonical-files
/// registry, so the server doesn't need to know anything else about
/// what file these bytes represent.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct FetchRequest {
	/// blake2_256 of the bytes being requested. Must match the
	/// receiver-side canonical-files registry value.
	pub canonical_hash: [u8; 32],
}

/// On-the-wire response.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum FetchResponse {
	/// Peer claims these bytes hash to the requested
	/// `canonical_hash`. Receiver MUST verify before writing them
	/// anywhere.
	Bytes(Vec<u8>),
	/// Peer does not have bytes matching the requested hash. Lets
	/// the caller fail fast and try another peer instead of timing
	/// out.
	NotAvailable,
}

/// Errors returned by [`fetch_and_verify`] and [`verify_response_bytes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchError {
	/// Peer responded `NotAvailable`. Try another peer.
	NotAvailable,
	/// Peer-supplied bytes hashed to a different value than the
	/// request's canonical hash. Hash is authority — reject and
	/// don't ask this peer again for this hash.
	HashMismatch { expected: [u8; 32], got: [u8; 32] },
	/// Response payload exceeded [`MAX_RESPONSE_BYTES`].
	ResponseTooLarge { len: usize },
	/// Underlying transport returned an error.
	Transport,
}

/// Hash a byte slice with blake2_256, the same algorithm the on-chain
/// canonical-files registry stores. Re-exported so callers don't need
/// to depend on `sp-crypto-hashing` directly just to compute the same
/// hash they're about to compare against.
pub fn blake2_256_of(bytes: &[u8]) -> [u8; 32] {
	blake2_256(bytes)
}

/// Verify the bytes from a `FetchResponse::Bytes(...)` against a
/// `FetchRequest`'s `canonical_hash`. Returns the bytes on success.
///
/// Two failure modes:
///
/// - Bytes are larger than [`MAX_RESPONSE_BYTES`]: rejected without
///   hashing (don't burn CPU on hostile-large payloads).
/// - Bytes hash to a different value than `canonical_hash`: rejected
///   with [`FetchError::HashMismatch`].
pub fn verify_response_bytes(
	request: &FetchRequest,
	bytes: Vec<u8>,
) -> Result<Vec<u8>, FetchError> {
	if bytes.len() > MAX_RESPONSE_BYTES {
		return Err(FetchError::ResponseTooLarge { len: bytes.len() });
	}
	let actual = blake2_256_of(&bytes);
	if actual != request.canonical_hash {
		return Err(FetchError::HashMismatch {
			expected: request.canonical_hash,
			got: actual,
		});
	}
	Ok(bytes)
}

/// Server-side abstraction: a source of canonical files indexed by
/// their blake2_256 hash. The actual implementation walks the local
/// install directory (or maintains an in-memory map in tests).
pub trait CanonicalFileSource {
	/// Return the bytes whose blake2_256 hash equals `hash`, or
	/// `None` if no such file is locally available.
	fn read_by_hash(&self, hash: &[u8; 32]) -> Option<Vec<u8>>;
}

/// Server-side request handler. Looks up the requested hash in the
/// local source, returns the bytes if found and not too large to
/// ship, otherwise `NotAvailable`.
///
/// The server does NOT need to verify the hash before responding —
/// the client always verifies — but a defensive double-check
/// implementation is reasonable in production to catch local-source
/// corruption before it propagates out.
pub fn handle_request<S: CanonicalFileSource + ?Sized>(
	source: &S,
	request: &FetchRequest,
) -> FetchResponse {
	match source.read_by_hash(&request.canonical_hash) {
		Some(bytes) if bytes.len() <= MAX_RESPONSE_BYTES => FetchResponse::Bytes(bytes),
		// Local source has bytes that are too big to ship under the
		// protocol cap. Should never happen for legitimate canonical
		// files, but prefer an honest "I can't serve this" over
		// truncation.
		Some(_) => FetchResponse::NotAvailable,
		None => FetchResponse::NotAvailable,
	}
}

/// Client-side abstraction: a thing that turns a request into a
/// response. Implementors plug in their own peer-routing,
/// timeout, retry semantics; this crate stays transport-agnostic.
pub trait FetchTransport {
	type Error;

	/// Send the request, await the response.
	fn send_request(&mut self, request: FetchRequest) -> Result<FetchResponse, Self::Error>;
}

/// Client-side helper: issue a request, verify the response,
/// return the verified bytes. The standard heal-flow entry point.
pub fn fetch_and_verify<T: FetchTransport>(
	transport: &mut T,
	canonical_hash: [u8; 32],
) -> Result<Vec<u8>, FetchError> {
	let request = FetchRequest { canonical_hash };
	let response = transport
		.send_request(request.clone())
		.map_err(|_| FetchError::Transport)?;
	match response {
		FetchResponse::Bytes(bytes) => verify_response_bytes(&request, bytes),
		FetchResponse::NotAvailable => Err(FetchError::NotAvailable),
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloc::collections::BTreeMap;
	use alloc::vec;

	/// Test source backed by a `BTreeMap<hash, bytes>`. Caller seeds
	/// it with files; the source hashes once at insert time so the
	/// lookup matches a real-source's behavior.
	struct MapSource {
		by_hash: BTreeMap<[u8; 32], Vec<u8>>,
	}

	impl MapSource {
		fn new() -> Self {
			Self { by_hash: BTreeMap::new() }
		}

		fn insert(&mut self, bytes: Vec<u8>) {
			let h = blake2_256_of(&bytes);
			self.by_hash.insert(h, bytes);
		}
	}

	impl CanonicalFileSource for MapSource {
		fn read_by_hash(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
			self.by_hash.get(hash).cloned()
		}
	}

	/// Honest transport: looks the request up against an in-memory
	/// source, builds the canonical handler response.
	struct HonestTransport<'a> {
		source: &'a MapSource,
	}

	impl<'a> FetchTransport for HonestTransport<'a> {
		type Error = ();
		fn send_request(&mut self, request: FetchRequest) -> Result<FetchResponse, ()> {
			Ok(handle_request(self.source, &request))
		}
	}

	/// Dishonest transport that always returns the same wrong bytes,
	/// regardless of what was asked for. Models a peer trying to
	/// poison the heal flow.
	struct LyingTransport {
		wrong_bytes: Vec<u8>,
	}

	impl FetchTransport for LyingTransport {
		type Error = ();
		fn send_request(&mut self, _request: FetchRequest) -> Result<FetchResponse, ()> {
			Ok(FetchResponse::Bytes(self.wrong_bytes.clone()))
		}
	}

	/// Transport that always errors out (network failure / peer gone).
	struct BrokenTransport;

	impl FetchTransport for BrokenTransport {
		type Error = ();
		fn send_request(&mut self, _request: FetchRequest) -> Result<FetchResponse, ()> {
			Err(())
		}
	}

	/// Transport that returns oversized bytes.
	struct OversizedTransport;

	impl FetchTransport for OversizedTransport {
		type Error = ();
		fn send_request(&mut self, _request: FetchRequest) -> Result<FetchResponse, ()> {
			let too_big = vec![0u8; MAX_RESPONSE_BYTES + 1];
			Ok(FetchResponse::Bytes(too_big))
		}
	}

	#[test]
	fn fetch_request_scale_roundtrip() {
		let req = FetchRequest { canonical_hash: [0x77; 32] };
		let encoded = req.encode();
		let decoded = FetchRequest::decode(&mut &encoded[..]).unwrap();
		assert_eq!(req, decoded);
	}

	#[test]
	fn fetch_response_bytes_scale_roundtrip() {
		let r = FetchResponse::Bytes(vec![1, 2, 3, 4]);
		let encoded = r.encode();
		let decoded = FetchResponse::decode(&mut &encoded[..]).unwrap();
		assert_eq!(r, decoded);
	}

	#[test]
	fn fetch_response_not_available_scale_roundtrip() {
		let r = FetchResponse::NotAvailable;
		let encoded = r.encode();
		let decoded = FetchResponse::decode(&mut &encoded[..]).unwrap();
		assert_eq!(r, decoded);
	}

	#[test]
	fn handle_request_returns_bytes_when_source_has_them() {
		let mut source = MapSource::new();
		let payload = b"canonical foundation file".to_vec();
		let h = blake2_256_of(&payload);
		source.insert(payload.clone());

		let resp = handle_request(&source, &FetchRequest { canonical_hash: h });
		assert_eq!(resp, FetchResponse::Bytes(payload));
	}

	#[test]
	fn handle_request_returns_not_available_when_source_lacks_them() {
		let source = MapSource::new();
		let resp = handle_request(&source, &FetchRequest { canonical_hash: [0xAB; 32] });
		assert_eq!(resp, FetchResponse::NotAvailable);
	}

	#[test]
	fn verify_response_accepts_matching_bytes() {
		let payload = b"the bytes".to_vec();
		let h = blake2_256_of(&payload);
		let req = FetchRequest { canonical_hash: h };
		let verified = verify_response_bytes(&req, payload.clone()).unwrap();
		assert_eq!(verified, payload);
	}

	#[test]
	fn verify_response_rejects_mismatched_bytes() {
		let req = FetchRequest { canonical_hash: [0xAB; 32] };
		let bad = b"definitely not the bytes whose hash is 0xAB...".to_vec();
		match verify_response_bytes(&req, bad) {
			Err(FetchError::HashMismatch { expected, got }) => {
				assert_eq!(expected, [0xAB; 32]);
				assert_ne!(got, [0xAB; 32]);
			},
			other => panic!("expected HashMismatch, got {:?}", other),
		}
	}

	#[test]
	fn verify_response_rejects_oversized_payload() {
		let req = FetchRequest { canonical_hash: [0xAB; 32] };
		let huge = vec![0u8; MAX_RESPONSE_BYTES + 1];
		match verify_response_bytes(&req, huge) {
			Err(FetchError::ResponseTooLarge { len }) => {
				assert_eq!(len, MAX_RESPONSE_BYTES + 1);
			},
			other => panic!("expected ResponseTooLarge, got {:?}", other),
		}
	}

	#[test]
	fn fetch_and_verify_returns_bytes_via_honest_peer() {
		let mut source = MapSource::new();
		let payload = b"gemini-node v1 binary bytes".to_vec();
		let h = blake2_256_of(&payload);
		source.insert(payload.clone());

		let mut transport = HonestTransport { source: &source };
		let bytes = fetch_and_verify(&mut transport, h).unwrap();
		assert_eq!(bytes, payload);
	}

	#[test]
	fn fetch_and_verify_rejects_lying_peer() {
		// Peer claims to serve bytes for hash H, but actually
		// returns unrelated content. Hash check on the receiver
		// must catch this.
		let mut transport = LyingTransport {
			wrong_bytes: b"malicious payload".to_vec(),
		};
		let target_hash = blake2_256_of(b"the real canonical bytes");

		match fetch_and_verify(&mut transport, target_hash) {
			Err(FetchError::HashMismatch { expected, got }) => {
				assert_eq!(expected, target_hash);
				assert_eq!(got, blake2_256_of(b"malicious payload"));
			},
			other => panic!("expected HashMismatch, got {:?}", other),
		}
	}

	#[test]
	fn fetch_and_verify_propagates_not_available() {
		struct EmptyTransport;
		impl FetchTransport for EmptyTransport {
			type Error = ();
			fn send_request(
				&mut self,
				_request: FetchRequest,
			) -> Result<FetchResponse, ()> {
				Ok(FetchResponse::NotAvailable)
			}
		}
		let mut transport = EmptyTransport;
		assert_eq!(
			fetch_and_verify(&mut transport, [0xAB; 32]),
			Err(FetchError::NotAvailable),
		);
	}

	#[test]
	fn fetch_and_verify_maps_transport_error() {
		let mut transport = BrokenTransport;
		assert_eq!(
			fetch_and_verify(&mut transport, [0xAB; 32]),
			Err(FetchError::Transport),
		);
	}

	#[test]
	fn fetch_and_verify_rejects_oversized_response() {
		let mut transport = OversizedTransport;
		match fetch_and_verify(&mut transport, [0xAB; 32]) {
			Err(FetchError::ResponseTooLarge { len }) => {
				assert_eq!(len, MAX_RESPONSE_BYTES + 1);
			},
			other => panic!("expected ResponseTooLarge, got {:?}", other),
		}
	}

	#[test]
	fn handle_request_skips_oversized_local_files() {
		// Edge case: local source has a file whose hash matches the
		// request, but its size exceeds the protocol cap. Server
		// should refuse to ship rather than truncating.
		struct OversizedSource {
			hash: [u8; 32],
			bytes: Vec<u8>,
		}
		impl CanonicalFileSource for OversizedSource {
			fn read_by_hash(&self, h: &[u8; 32]) -> Option<Vec<u8>> {
				if h == &self.hash {
					Some(self.bytes.clone())
				} else {
					None
				}
			}
		}
		let source = OversizedSource {
			hash: [0xCC; 32],
			bytes: vec![0u8; MAX_RESPONSE_BYTES + 1],
		};
		let resp = handle_request(&source, &FetchRequest { canonical_hash: [0xCC; 32] });
		assert_eq!(resp, FetchResponse::NotAvailable);
	}
}
