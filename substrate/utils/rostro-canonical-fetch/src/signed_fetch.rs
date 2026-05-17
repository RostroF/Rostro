// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Signed-attestation variant of the canonical-file fetch protocol.
//!
//! Phase 7 v2: the heal-fetch flow used to be single-source (a peer
//! sends back bytes, we trust them because the hash matches). This
//! module adds a parallel protocol where each peer's response is
//! cryptographically signed under its libp2p node-identity key, with
//! the signature anchored to the chain's current block number / hash
//! and a wall-clock timestamp. Multiple peers reply; the caller
//! aggregates K-of-N independently-verified responses before
//! installing the bytes.
//!
//! ## Why two protocols and not one
//!
//! The unsigned [`crate::FetchResponse`] still serves a real use
//! case: trusted in-process transports (e.g.
//! [`crate::local_dir::LocalDirectoryFetchTransport`] reading from a
//! local cache an operator put there). The signature would add no
//! information in that path. The signed protocol is for the
//! network-broadcast case — "any reachable peer can answer" — where
//! aggregating attestations is the only sane trust model.
//!
//! ## What `verify_signed_response` proves
//!
//! 1. `blake2_256(bytes) == claimed_hash` — bytes match the claim.
//! 2. `claimed_hash == request_hash` — answers the question we asked.
//! 3. `nonce` echoes the request — defeats replayed cached responses.
//! 4. Response size is under [`crate::MAX_RESPONSE_BYTES`] — bounded
//!    OOM surface from hostile peers.
//! 5. `sig` is a valid Ed25519 signature, by `signer_pubkey`, over
//!    the canonical preimage (`hash || nonce || block_number_le ||
//!    block_hash || timestamp_le`, prefixed with the
//!    [`SIGNED_FETCH_PREIMAGE_DOMAIN`] domain-separation tag).
//!
//! It does NOT prove freshness in wall-clock terms — the timestamp
//! is a hint, not a freshness guarantee. The caller can reject stale
//! responses by inspecting [`SignedFetchResponse::timestamp_unix_secs`]
//! against its own clock. Same for block-number staleness: the caller
//! decides whether `block_number` is "current enough" vs. its own
//! chain view.
//!
//! ## Trust quorum (K-of-N) lives one level up
//!
//! This module models ONE signed response. The broadcast client
//! collects K verified responses agreeing on the same `(hash, bytes)`
//! before installing — see Piece 2c. Setting K=1 is acceptable in a
//! trusted lab (single peer is enough); mainnet operations bump K up
//! per policy. The wire format is identical regardless of K.

use alloc::vec::Vec;
use codec::{Decode, Encode};

use crate::{blake2_256_of, CanonicalFileSource, MAX_RESPONSE_BYTES};

/// On-the-wire signed-fetch request. Same shape as the unsigned
/// [`crate::FetchRequest`] but carries a per-request nonce that the
/// signer must echo in [`SignedFetchResponse::nonce`]. The nonce is
/// the cryptographic replay defense.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct SignedFetchRequest {
	/// blake2_256 of the bytes being requested. Must match the
	/// receiver-side canonical-files registry value.
	pub canonical_hash: [u8; 32],
	/// Fresh per-request nonce. The signer echoes this in
	/// [`SignedFetchResponse::nonce`]; mismatches indicate replay.
	pub nonce: [u8; 32],
}

/// On-the-wire reply. Either a signed response payload or an
/// explicit "I don't have this hash" so the asker can fail fast
/// without waiting for the request timeout.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum SignedFetchReply {
	/// Signer has bytes matching the requested hash. Receiver must
	/// run [`verify_signed_response`] before trusting.
	Signed(SignedFetchResponse),
	/// Signer does not have bytes for this hash. No signature
	/// required — the absence claim isn't load-bearing for trust.
	NotAvailable,
}

/// Domain-separation tag prefixed to the signature preimage. Bumped
/// (e.g. `/v2`) if the preimage layout ever changes incompatibly,
/// guaranteeing that a v1 signature cannot be replayed against a v2
/// verifier even if all other bits align.
pub const SIGNED_FETCH_PREIMAGE_DOMAIN: &[u8] = b"rostro/canonical-fetch-attested/v1";

/// On-the-wire signed fetch response. Carries everything the asker
/// needs to verify a peer's claim, including the peer's Ed25519
/// pubkey + signature.
///
/// The receiver MUST call [`verify_signed_response`] before treating
/// `bytes` as canonical. Verification is per-response; trust
/// aggregation across multiple signers is the caller's job.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct SignedFetchResponse {
	/// Peer-supplied bytes. Receiver re-hashes via blake2_256 and
	/// compares against [`Self::hash`] to detect tampering before
	/// trusting the payload.
	pub bytes: Vec<u8>,
	/// Signer's claim of `blake2_256(bytes)`. Verified by re-hashing
	/// on the receive side.
	pub hash: [u8; 32],
	/// Echoed from the originating request's nonce. A response whose
	/// nonce doesn't echo a known in-flight request is a replay (or
	/// a confused responder) and is rejected.
	pub nonce: [u8; 32],
	/// Block number this attestation is anchored to. Lets the caller
	/// reason about how current the attestation is — a response
	/// anchored to a block earlier than the caller's chain view is
	/// stale and may be ignored at policy discretion.
	pub block_number: u32,
	/// Block hash at [`Self::block_number`]. Disambiguates forks.
	pub block_hash: [u8; 32],
	/// Signer's wall-clock timestamp (Unix epoch seconds). Hint
	/// only — the cryptographic freshness guarantee comes from the
	/// nonce.
	pub timestamp_unix_secs: u64,
	/// Signer's Ed25519 public key. By convention the libp2p
	/// node-identity key, so the asker can correlate signer ↔
	/// PeerId.
	pub signer_pubkey: [u8; 32],
	/// Ed25519 signature over the canonical preimage.
	pub sig: [u8; 64],
}

/// Verification outcome for a single [`SignedFetchResponse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignedFetchError {
	/// Bytes hash to a value other than [`SignedFetchResponse::hash`],
	/// OR [`SignedFetchResponse::hash`] doesn't match the request's
	/// `canonical_hash`. Either way, peer-supplied bytes can't be
	/// trusted as canonical.
	HashMismatch { expected: [u8; 32], got: [u8; 32] },
	/// Response nonce doesn't echo the request's nonce. Indicates a
	/// replay or a confused responder.
	NonceMismatch { expected: [u8; 32], got: [u8; 32] },
	/// Response payload exceeded [`crate::MAX_RESPONSE_BYTES`].
	/// Rejected without hashing.
	ResponseTooLarge { len: usize },
	/// Signer's `signer_pubkey` is not a valid Ed25519 point.
	InvalidPubkey,
	/// Ed25519 verification failed: `sig` does not match the
	/// preimage under `signer_pubkey`.
	SignatureInvalid,
}

/// Build the canonical preimage that a [`SignedFetchResponse`]
/// signs over. Layout:
///
/// ```text
/// SIGNED_FETCH_PREIMAGE_DOMAIN || hash || nonce
///   || block_number.to_le_bytes()
///   || block_hash
///   || timestamp_unix_secs.to_le_bytes()
/// ```
///
/// Length: `SIGNED_FETCH_PREIMAGE_DOMAIN.len() + 32 + 32 + 4 + 32 + 8`
/// = `DOMAIN.len() + 108` bytes.
///
/// LE byte order is chosen for consistency with SCALE (which also
/// encodes integers little-endian).
pub fn build_signed_preimage(
	hash: &[u8; 32],
	nonce: &[u8; 32],
	block_number: u32,
	block_hash: &[u8; 32],
	timestamp_unix_secs: u64,
) -> Vec<u8> {
	let mut buf = Vec::with_capacity(SIGNED_FETCH_PREIMAGE_DOMAIN.len() + 108);
	buf.extend_from_slice(SIGNED_FETCH_PREIMAGE_DOMAIN);
	buf.extend_from_slice(hash);
	buf.extend_from_slice(nonce);
	buf.extend_from_slice(&block_number.to_le_bytes());
	buf.extend_from_slice(block_hash);
	buf.extend_from_slice(&timestamp_unix_secs.to_le_bytes());
	buf
}

/// Verify a single [`SignedFetchResponse`] against the request that
/// asked for it. Returns the bytes on success; never short-circuits
/// past the hash check on the optimistic path.
///
/// The caller is responsible for aggregating multiple verified
/// responses into a K-of-N quorum before installing bytes — this
/// function only models the per-response correctness check.
pub fn verify_signed_response<'r>(
	request_hash: &[u8; 32],
	request_nonce: &[u8; 32],
	response: &'r SignedFetchResponse,
) -> Result<&'r [u8], SignedFetchError> {
	// Size cap before hashing. Hostile peers shouldn't be able to
	// burn the receiver's CPU on multi-megabyte hash computations.
	if response.bytes.len() > MAX_RESPONSE_BYTES {
		return Err(SignedFetchError::ResponseTooLarge { len: response.bytes.len() });
	}

	// Bytes ↔ claimed hash, and claimed hash ↔ requested hash. Both
	// must hold: a peer can't substitute *different* canonical bytes
	// for the ones we asked for, even if its substitution
	// internally hashes correctly.
	let actual = blake2_256_of(&response.bytes);
	if actual != response.hash {
		return Err(SignedFetchError::HashMismatch {
			expected: response.hash,
			got: actual,
		});
	}
	if response.hash != *request_hash {
		return Err(SignedFetchError::HashMismatch {
			expected: *request_hash,
			got: response.hash,
		});
	}

	// Replay defense.
	if response.nonce != *request_nonce {
		return Err(SignedFetchError::NonceMismatch {
			expected: *request_nonce,
			got: response.nonce,
		});
	}

	// Signature check. Tampering with block_number / block_hash /
	// timestamp / hash / nonce all break this — every field that
	// matters is in the preimage.
	let preimage = build_signed_preimage(
		&response.hash,
		&response.nonce,
		response.block_number,
		&response.block_hash,
		response.timestamp_unix_secs,
	);
	let vk = ed25519_zebra::VerificationKey::try_from(response.signer_pubkey)
		.map_err(|_| SignedFetchError::InvalidPubkey)?;
	let sig = ed25519_zebra::Signature::from(response.sig);
	vk.verify(&sig, &preimage)
		.map_err(|_| SignedFetchError::SignatureInvalid)?;

	Ok(&response.bytes)
}

/// Server-side helper: turn a [`SignedFetchRequest`] into a
/// [`SignedFetchReply`], looking up bytes in `source` and signing the
/// response with `signing_key` if found.
///
/// The block anchor (`block_number`, `block_hash`) and `timestamp_unix_secs`
/// reflect the signer's current chain view at response-build time;
/// the caller supplies them rather than re-deriving here because the
/// trait is no-chain-dep by design.
///
/// Returns `SignedFetchReply::NotAvailable` if the source doesn't
/// have the bytes OR if the bytes are larger than
/// [`MAX_RESPONSE_BYTES`]. The size cap means an oversized canonical
/// file silently degrades to "not available" rather than being
/// truncated or panicking — operators see the absence and can
/// raise the cap deliberately.
#[cfg(feature = "std")]
pub fn handle_signed_request<S: CanonicalFileSource + ?Sized>(
	source: &S,
	request: &SignedFetchRequest,
	block_number: u32,
	block_hash: [u8; 32],
	timestamp_unix_secs: u64,
	signing_key: &ed25519_zebra::SigningKey,
) -> SignedFetchReply {
	match source.read_by_hash(&request.canonical_hash) {
		Some(bytes) if bytes.len() <= MAX_RESPONSE_BYTES => {
			let signed = sign_response(
				bytes,
				request.nonce,
				block_number,
				block_hash,
				timestamp_unix_secs,
				signing_key,
			);
			SignedFetchReply::Signed(signed)
		},
		// Oversized: same observable outcome as "missing." Operator
		// raises MAX_RESPONSE_BYTES if a legitimate canonical file
		// exceeds it.
		Some(_) => SignedFetchReply::NotAvailable,
		None => SignedFetchReply::NotAvailable,
	}
}

/// Sign a fetch response with the given Ed25519 signing key. Used by
/// the server-side handler. Std-gated because [`ed25519_zebra::SigningKey`]
/// pulls in `getrandom` for key operations; the verify path stays
/// no_std-compatible for any future no_std consumer.
///
/// Pure constructor — no I/O, no randomness on the signing operation
/// itself (Ed25519 signatures are deterministic).
#[cfg(feature = "std")]
pub fn sign_response(
	bytes: Vec<u8>,
	request_nonce: [u8; 32],
	block_number: u32,
	block_hash: [u8; 32],
	timestamp_unix_secs: u64,
	signing_key: &ed25519_zebra::SigningKey,
) -> SignedFetchResponse {
	let hash = blake2_256_of(&bytes);
	let preimage = build_signed_preimage(
		&hash,
		&request_nonce,
		block_number,
		&block_hash,
		timestamp_unix_secs,
	);
	let sig: ed25519_zebra::Signature = signing_key.sign(&preimage);
	let vk: ed25519_zebra::VerificationKey =
		ed25519_zebra::VerificationKey::from(signing_key);
	let signer_pubkey: [u8; 32] = vk.into();
	SignedFetchResponse {
		bytes,
		hash,
		nonce: request_nonce,
		block_number,
		block_hash,
		timestamp_unix_secs,
		signer_pubkey,
		sig: sig.into(),
	}
}

#[cfg(test)]
#[cfg(feature = "std")]
mod tests {
	use super::*;
	use ed25519_zebra::SigningKey;

	fn fixed_signing_key() -> SigningKey {
		// 32-byte seed pinned for reproducibility across runs.
		// Test-only; production keys come from the libp2p
		// node-identity keystore.
		let seed = [0x42u8; 32];
		SigningKey::from(seed)
	}

	fn other_signing_key() -> SigningKey {
		// Distinct fixed seed so "different signer" tests don't
		// depend on randomness.
		let seed = [0x99u8; 32];
		SigningKey::from(seed)
	}

	fn make_response(
		bytes: Vec<u8>,
		nonce: [u8; 32],
		block_number: u32,
		block_hash: [u8; 32],
		timestamp: u64,
		key: &SigningKey,
	) -> SignedFetchResponse {
		sign_response(bytes, nonce, block_number, block_hash, timestamp, key)
	}

	#[test]
	fn preimage_layout_is_stable() {
		// Pin the preimage byte layout against accidental refactors.
		// A change here breaks every previously-signed attestation.
		let p = build_signed_preimage(
			&[0xAA; 32],
			&[0xBB; 32],
			0x01020304u32,
			&[0xCC; 32],
			0x1122334455667788u64,
		);
		assert_eq!(p.len(), SIGNED_FETCH_PREIMAGE_DOMAIN.len() + 108);
		// Domain prefix
		assert_eq!(&p[..SIGNED_FETCH_PREIMAGE_DOMAIN.len()], SIGNED_FETCH_PREIMAGE_DOMAIN);
		let body_off = SIGNED_FETCH_PREIMAGE_DOMAIN.len();
		// hash
		assert_eq!(&p[body_off..body_off + 32], &[0xAA; 32]);
		// nonce
		assert_eq!(&p[body_off + 32..body_off + 64], &[0xBB; 32]);
		// block_number LE
		assert_eq!(&p[body_off + 64..body_off + 68], &[0x04, 0x03, 0x02, 0x01]);
		// block_hash
		assert_eq!(&p[body_off + 68..body_off + 100], &[0xCC; 32]);
		// timestamp LE
		assert_eq!(
			&p[body_off + 100..body_off + 108],
			&[0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
		);
	}

	#[test]
	fn signed_response_scale_roundtrip() {
		let key = fixed_signing_key();
		let resp = make_response(
			vec![1, 2, 3, 4],
			[0x55; 32],
			42,
			[0x66; 32],
			1_700_000_000,
			&key,
		);
		let bytes = resp.encode();
		let decoded = SignedFetchResponse::decode(&mut &bytes[..]).unwrap();
		assert_eq!(resp, decoded);
	}

	#[test]
	fn sign_then_verify_returns_bytes() {
		let key = fixed_signing_key();
		let payload = vec![9, 8, 7, 6, 5];
		let nonce = [0x77; 32];
		let resp = make_response(
			payload.clone(),
			nonce,
			100,
			[0x88; 32],
			1_700_000_000,
			&key,
		);
		let expected_hash = blake2_256_of(&payload);
		let bytes = verify_signed_response(&expected_hash, &nonce, &resp).unwrap();
		assert_eq!(bytes, &payload[..]);
	}

	#[test]
	fn verify_rejects_tampered_bytes() {
		let key = fixed_signing_key();
		let payload = vec![1, 1, 1, 1];
		let nonce = [0x77; 32];
		let mut resp = make_response(payload.clone(), nonce, 1, [0u8; 32], 0, &key);
		let expected_hash = blake2_256_of(&payload);
		// Flip one byte; hash + sig no longer agree.
		resp.bytes[0] ^= 0xFF;
		match verify_signed_response(&expected_hash, &nonce, &resp) {
			Err(SignedFetchError::HashMismatch { .. }) => {},
			other => panic!("expected HashMismatch, got {:?}", other),
		}
	}

	#[test]
	fn verify_rejects_wrong_request_hash() {
		let key = fixed_signing_key();
		let resp = make_response(
			vec![1, 2, 3],
			[0x77; 32],
			1,
			[0u8; 32],
			0,
			&key,
		);
		// Ask for a different hash than the signer attested to.
		let wrong_hash = [0xDE; 32];
		match verify_signed_response(&wrong_hash, &[0x77; 32], &resp) {
			Err(SignedFetchError::HashMismatch { expected, got }) => {
				assert_eq!(expected, wrong_hash);
				assert_eq!(got, resp.hash);
			},
			other => panic!("expected HashMismatch, got {:?}", other),
		}
	}

	#[test]
	fn verify_rejects_nonce_mismatch() {
		let key = fixed_signing_key();
		let payload = vec![1, 2, 3];
		let signed_nonce = [0x11; 32];
		let resp = make_response(payload.clone(), signed_nonce, 1, [0u8; 32], 0, &key);
		let expected_hash = blake2_256_of(&payload);
		// Ask under a different nonce than the one the response echoes.
		let request_nonce = [0x22; 32];
		match verify_signed_response(&expected_hash, &request_nonce, &resp) {
			Err(SignedFetchError::NonceMismatch { expected, got }) => {
				assert_eq!(expected, request_nonce);
				assert_eq!(got, signed_nonce);
			},
			other => panic!("expected NonceMismatch, got {:?}", other),
		}
	}

	#[test]
	fn verify_rejects_tampered_block_number() {
		let key = fixed_signing_key();
		let payload = vec![1, 2, 3];
		let nonce = [0x77; 32];
		let mut resp = make_response(payload.clone(), nonce, 100, [0u8; 32], 0, &key);
		let expected_hash = blake2_256_of(&payload);
		// Flip block_number after signing → preimage changes →
		// signature verify fails. The hash check still passes
		// (bytes untouched), so we get SignatureInvalid not HashMismatch.
		resp.block_number = 101;
		match verify_signed_response(&expected_hash, &nonce, &resp) {
			Err(SignedFetchError::SignatureInvalid) => {},
			other => panic!("expected SignatureInvalid, got {:?}", other),
		}
	}

	#[test]
	fn verify_rejects_tampered_timestamp() {
		let key = fixed_signing_key();
		let payload = vec![1, 2, 3];
		let nonce = [0x77; 32];
		let mut resp = make_response(payload.clone(), nonce, 1, [0u8; 32], 1_700_000_000, &key);
		let expected_hash = blake2_256_of(&payload);
		resp.timestamp_unix_secs = 1_800_000_000;
		match verify_signed_response(&expected_hash, &nonce, &resp) {
			Err(SignedFetchError::SignatureInvalid) => {},
			other => panic!("expected SignatureInvalid, got {:?}", other),
		}
	}

	#[test]
	fn verify_rejects_wrong_signer_pubkey() {
		let key_a = fixed_signing_key();
		let key_b = other_signing_key();
		let payload = vec![1, 2, 3];
		let nonce = [0x77; 32];
		let mut resp = make_response(payload.clone(), nonce, 1, [0u8; 32], 0, &key_a);
		let expected_hash = blake2_256_of(&payload);
		// Swap pubkey: sig was made by key_a, but claim it's key_b.
		let vk_b: ed25519_zebra::VerificationKey =
			ed25519_zebra::VerificationKey::from(&key_b);
		resp.signer_pubkey = vk_b.into();
		match verify_signed_response(&expected_hash, &nonce, &resp) {
			Err(SignedFetchError::SignatureInvalid) => {},
			other => panic!("expected SignatureInvalid, got {:?}", other),
		}
	}

	#[test]
	fn verify_rejects_tampered_signer_pubkey_bytes() {
		// Replace pubkey with arbitrary bytes. ed25519-zebra may
		// reject these at decode time (InvalidPubkey) or at verify
		// time (SignatureInvalid) depending on whether the bytes
		// happen to decompress to *some* curve point. Either path
		// preserves the contract: tampered pubkeys cannot pass
		// verification under a signature made by a different key.
		let key = fixed_signing_key();
		let payload = vec![1, 2, 3];
		let nonce = [0x77; 32];
		let mut resp = make_response(payload.clone(), nonce, 1, [0u8; 32], 0, &key);
		let expected_hash = blake2_256_of(&payload);
		resp.signer_pubkey = [0xFFu8; 32];
		match verify_signed_response(&expected_hash, &nonce, &resp) {
			Err(SignedFetchError::InvalidPubkey)
			| Err(SignedFetchError::SignatureInvalid) => {},
			other => panic!(
				"expected InvalidPubkey or SignatureInvalid, got {:?}",
				other,
			),
		}
	}

	#[test]
	fn verify_rejects_oversized_response() {
		let key = fixed_signing_key();
		let payload = vec![0u8; MAX_RESPONSE_BYTES + 1];
		let nonce = [0x77; 32];
		let resp = make_response(payload, nonce, 1, [0u8; 32], 0, &key);
		let expected_hash = resp.hash;
		match verify_signed_response(&expected_hash, &nonce, &resp) {
			Err(SignedFetchError::ResponseTooLarge { len }) => {
				assert_eq!(len, MAX_RESPONSE_BYTES + 1);
			},
			other => panic!("expected ResponseTooLarge, got {:?}", other),
		}
	}

	#[test]
	fn signed_fetch_request_scale_roundtrip() {
		let r = SignedFetchRequest {
			canonical_hash: [0xAA; 32],
			nonce: [0xBB; 32],
		};
		let bytes = r.encode();
		let decoded = SignedFetchRequest::decode(&mut &bytes[..]).unwrap();
		assert_eq!(r, decoded);
	}

	#[test]
	fn signed_fetch_reply_scale_roundtrip_both_variants() {
		let key = fixed_signing_key();
		let resp = make_response(vec![1, 2, 3], [0x77; 32], 1, [0u8; 32], 0, &key);
		let signed = SignedFetchReply::Signed(resp);
		let na = SignedFetchReply::NotAvailable;

		let signed_bytes = signed.encode();
		assert_eq!(
			SignedFetchReply::decode(&mut &signed_bytes[..]).unwrap(),
			signed,
		);

		let na_bytes = na.encode();
		assert_eq!(SignedFetchReply::decode(&mut &na_bytes[..]).unwrap(), na);
	}

	/// In-memory source for handler tests. No I/O, no temp dirs.
	struct MapSource {
		entries: alloc::collections::BTreeMap<[u8; 32], Vec<u8>>,
	}
	impl MapSource {
		fn insert(&mut self, bytes: Vec<u8>) -> [u8; 32] {
			let h = blake2_256_of(&bytes);
			self.entries.insert(h, bytes);
			h
		}
	}
	impl CanonicalFileSource for MapSource {
		fn read_by_hash(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
			self.entries.get(hash).cloned()
		}
	}

	#[test]
	fn handle_signed_request_returns_signed_when_source_has_bytes() {
		let key = fixed_signing_key();
		let mut source = MapSource { entries: Default::default() };
		let payload = b"canonical bytes".to_vec();
		let hash = source.insert(payload.clone());
		let req = SignedFetchRequest { canonical_hash: hash, nonce: [0x55; 32] };

		let reply = handle_signed_request(&source, &req, 7, [0xCC; 32], 1700, &key);

		match reply {
			SignedFetchReply::Signed(resp) => {
				assert_eq!(resp.bytes, payload);
				assert_eq!(resp.hash, hash);
				assert_eq!(resp.nonce, [0x55; 32]);
				assert_eq!(resp.block_number, 7);
				assert_eq!(resp.block_hash, [0xCC; 32]);
				assert_eq!(resp.timestamp_unix_secs, 1700);
				// Verification round-trips against the source's claim.
				let bytes = verify_signed_response(&hash, &[0x55; 32], &resp).unwrap();
				assert_eq!(bytes, &payload[..]);
			},
			other => panic!("expected Signed, got {:?}", other),
		}
	}

	#[test]
	fn handle_signed_request_returns_not_available_when_source_lacks_bytes() {
		let key = fixed_signing_key();
		let source = MapSource { entries: Default::default() };
		let req = SignedFetchRequest {
			canonical_hash: [0xDD; 32],
			nonce: [0x66; 32],
		};
		let reply = handle_signed_request(&source, &req, 1, [0u8; 32], 0, &key);
		assert_eq!(reply, SignedFetchReply::NotAvailable);
	}

	#[test]
	fn handle_signed_request_returns_not_available_for_oversized_payload() {
		let key = fixed_signing_key();
		let mut source = MapSource { entries: Default::default() };
		let huge = vec![0u8; MAX_RESPONSE_BYTES + 1];
		let hash = source.insert(huge);
		let req = SignedFetchRequest { canonical_hash: hash, nonce: [0u8; 32] };
		let reply = handle_signed_request(&source, &req, 1, [0u8; 32], 0, &key);
		assert_eq!(
			reply,
			SignedFetchReply::NotAvailable,
			"oversized canonical file should degrade to NotAvailable, not panic or truncate",
		);
	}

	#[test]
	fn domain_separation_breaks_cross_version_replay() {
		// Verify that flipping the domain prefix (simulating a v2
		// preimage layout) makes a v1 signature fail to verify.
		// This is purely a documentation check — there's no v2
		// today — but it pins the invariant that bumping the domain
		// breaks old signatures, which is the whole point of having
		// a domain.
		let key = fixed_signing_key();
		let payload = vec![1, 2, 3];
		let nonce = [0x77; 32];
		let resp = make_response(payload.clone(), nonce, 1, [0u8; 32], 0, &key);

		// Build a preimage that would correspond to a hypothetical
		// "v2" domain.
		let mut alt_preimage =
			Vec::with_capacity(SIGNED_FETCH_PREIMAGE_DOMAIN.len() + 1 + 108);
		alt_preimage.extend_from_slice(SIGNED_FETCH_PREIMAGE_DOMAIN);
		alt_preimage.push(b'x'); // would-be v2 marker
		alt_preimage.extend_from_slice(&resp.hash);
		alt_preimage.extend_from_slice(&resp.nonce);
		alt_preimage.extend_from_slice(&resp.block_number.to_le_bytes());
		alt_preimage.extend_from_slice(&resp.block_hash);
		alt_preimage.extend_from_slice(&resp.timestamp_unix_secs.to_le_bytes());

		let vk =
			ed25519_zebra::VerificationKey::try_from(resp.signer_pubkey).unwrap();
		let sig = ed25519_zebra::Signature::from(resp.sig);
		assert!(
			vk.verify(&sig, &alt_preimage).is_err(),
			"v1 signature must NOT verify under a different domain prefix",
		);
	}
}
