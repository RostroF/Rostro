// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! XOR-stripe split/combine primitives.
//!
//! Sender splits ciphertext into N shares such that any single relay
//! holds noise rather than partial ciphertext. Recipient reconstructs
//! by XORing all N shares together. Information-theoretic
//! confidentiality against fewer-than-N colluders: a single missing
//! share leaves the remaining N-1 shares looking like uniform random
//! bytes regardless of ciphertext content.
//!
//! ## Why XOR-stripe and not erasure coding
//!
//! Erasure codes (Reed-Solomon, RaptorQ) give availability +
//! threshold confidentiality: any K-of-N shares recover the
//! ciphertext, fewer cannot. XOR-stripe gives all-or-nothing
//! confidentiality: ALL N shares are required, any missing share =
//! unrecoverable.
//!
//! - **XOR-stripe** is information-theoretic against `<N` colluders.
//!   No future cryptographic advance breaks a single share's
//!   confidentiality because the share is literally uniform random
//!   noise. Costs availability: any single offline relay loses the
//!   message.
//! - **Erasure code (K-of-N)** is computationally bounded — K
//!   colluding relays reconstruct the ciphertext, still need to
//!   break the underlying encryption to read plaintext. Gains
//!   availability via redundancy.
//!
//! Rostro's chat layer ships XOR-stripe for the v0.1 confidentiality
//! property, with **share replication** at the relay layer for
//! availability (each of the N XOR shares replicated to a small
//! disjoint set, so any single relay going offline doesn't drop
//! the message). XOR + replication composes confidentiality with
//! availability at the cost of additional storage.
//!
//! ## Integrity: authenticated combine via per-share MAC
//!
//! A relay that corrupts its share by flipping bits will produce a
//! garbled reconstruction with no immediate way to identify which
//! share was bad. To localize tampering to a specific share, the
//! sender attaches a per-share MAC tag (see [`crate::verify::mac_share`])
//! and the recipient uses [`combine_xor_authenticated`] instead of
//! [`combine_xor`]: each share's MAC is verified before XOR-combining
//! begins, and the function returns a [`AuthCombineError::TamperedShare`]
//! variant identifying which share failed.
//!
//! Unauthenticated [`combine_xor`] is retained for callers that
//! handle integrity at a different layer (e.g., the upstream MLS/DR
//! AEAD will fail to decrypt a garbled assembly, which detects the
//! tampering but does not localize it to a specific relay).

use alloc::vec::Vec;

use crate::descriptor::ShareIndex;
use crate::verify::{verify_share_mac, ShareMacKey, ShareMacTag};

/// Minimum number of shares. `n=1` is the degenerate
/// "share = ciphertext" case that provides no stripe benefit;
/// reject explicitly so callers don't accidentally ship messages
/// with no relay-side confidentiality.
pub const MIN_SHARES: usize = 2;

/// Sanity cap on the number of shares. Practical relay counts are
/// 3-10. This cap exists to prevent accidental memory blowup from
/// uncapped caller input. Raise deliberately if a larger N is ever
/// needed.
pub const MAX_SHARES: usize = 64;

/// Errors from [`split_xor`] / [`combine_xor`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StripeError {
	/// Caller requested `n` outside `[MIN_SHARES, MAX_SHARES]`.
	InvalidN { got: usize, min: usize, max: usize },
	/// [`combine_xor`] called with an empty share slice.
	NoShares,
	/// [`combine_xor`] received shares of inconsistent length. All
	/// shares must be the same length (the ciphertext length).
	/// `index` is the position of the first mismatched share in the
	/// caller's slice.
	ShareSizeMismatch {
		expected: usize,
		got: usize,
		index: usize,
	},
}

/// Split `ciphertext` into `n` XOR shares.
///
/// Algorithm: generate `n-1` random shares of length
/// `ciphertext.len()` from `rng`, then compute the final share as
/// `ciphertext XOR share[0] XOR ... XOR share[n-2]`. Reconstruction
/// is the bitwise XOR of all `n` shares.
///
/// Each of the first `n-1` shares is filled with cryptographically
/// random bytes from `rng`. The final share is mathematically
/// determined by the previous `n-1` shares plus the ciphertext, but
/// because all previous shares are uniform random, the final share
/// is also uniform random when viewed in isolation (Vernam cipher
/// property).
///
/// Returns the `n` shares in the order they were generated. Order
/// does not affect reconstruction (XOR is commutative + associative).
///
/// # Errors
///
/// [`StripeError::InvalidN`] if `n` is outside `[MIN_SHARES, MAX_SHARES]`.
///
/// # Edge cases
///
/// * Empty `ciphertext`: returns `n` shares of length 0. Trivially
///   combinable, no information. Caller responsibility to avoid
///   sending zero-length chat messages.
pub fn split_xor<R>(
	ciphertext: &[u8],
	n: usize,
	rng: &mut R,
) -> Result<Vec<Vec<u8>>, StripeError>
where
	R: rand_core::RngCore + rand_core::CryptoRng,
{
	if !(MIN_SHARES..=MAX_SHARES).contains(&n) {
		return Err(StripeError::InvalidN {
			got: n,
			min: MIN_SHARES,
			max: MAX_SHARES,
		});
	}
	let len = ciphertext.len();
	let mut shares: Vec<Vec<u8>> = Vec::with_capacity(n);

	for _ in 0..(n - 1) {
		let mut buf = alloc::vec![0u8; len];
		rng.fill_bytes(&mut buf);
		shares.push(buf);
	}

	let mut final_share = ciphertext.to_vec();
	for s in &shares {
		for (out, &p) in final_share.iter_mut().zip(s.iter()) {
			*out ^= p;
		}
	}
	shares.push(final_share);

	Ok(shares)
}

/// Errors from [`combine_xor_authenticated`]. Adds MAC-failure
/// localization on top of the [`StripeError`] variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthCombineError {
	/// MAC verification failed on the share at position `slice_index`
	/// in the caller's input slice. `share_index` is the canonical
	/// position of that share within the message (0..N-1).
	///
	/// The caller should re-fetch this specific share from a
	/// different relay rather than abandon the entire message.
	TamperedShare { slice_index: usize, share_index: ShareIndex },
	/// Empty input slice.
	NoShares,
	/// Shares of inconsistent length. `slice_index` is the position
	/// of the first mismatched share in the caller's slice.
	ShareSizeMismatch {
		expected: usize,
		got: usize,
		slice_index: usize,
	},
}

/// MAC-authenticated combine: verifies each share's MAC tag under
/// `key` before XOR-combining. On any MAC failure, returns
/// [`AuthCombineError::TamperedShare`] with the position of the
/// failing share so the caller can re-fetch just that share rather
/// than discarding the whole message.
///
/// Each input tuple is `(share_index, share_bytes, mac_tag)`. The
/// `key` is the per-message MAC key derived via
/// [`crate::verify::derive_share_mac_key`].
///
/// On success, returns the XOR-combined ciphertext.
///
/// # Errors
///
/// * [`AuthCombineError::NoShares`] — empty slice.
/// * [`AuthCombineError::ShareSizeMismatch`] — shares of differing
///   sizes. (Caught BEFORE MAC verification; the size check is
///   cheap and avoids spending CPU on MAC-ing inputs we'll reject
///   anyway.)
/// * [`AuthCombineError::TamperedShare`] — a share's MAC tag did
///   not verify. `slice_index` + `share_index` identify the bad
///   share.
pub fn combine_xor_authenticated(
	key: &ShareMacKey,
	shares: &[(ShareIndex, &[u8], &ShareMacTag)],
) -> Result<Vec<u8>, AuthCombineError> {
	if shares.is_empty() {
		return Err(AuthCombineError::NoShares);
	}

	let expected_len = shares[0].1.len();
	for (i, (_, bytes, _)) in shares.iter().enumerate().skip(1) {
		if bytes.len() != expected_len {
			return Err(AuthCombineError::ShareSizeMismatch {
				expected: expected_len,
				got: bytes.len(),
				slice_index: i,
			});
		}
	}

	for (i, (share_index, bytes, tag)) in shares.iter().enumerate() {
		if verify_share_mac(key, bytes, *share_index, tag).is_err() {
			return Err(AuthCombineError::TamperedShare {
				slice_index: i,
				share_index: *share_index,
			});
		}
	}

	let byte_slices: Vec<&[u8]> = shares.iter().map(|(_, b, _)| *b).collect();
	combine_xor(&byte_slices).map_err(|e| match e {
		StripeError::NoShares => AuthCombineError::NoShares,
		StripeError::ShareSizeMismatch { expected, got, index } => {
			AuthCombineError::ShareSizeMismatch {
				expected,
				got,
				slice_index: index,
			}
		},
		// combine_xor doesn't return InvalidN; defensive fall-through.
		StripeError::InvalidN { .. } => AuthCombineError::NoShares,
	})
}

/// Reconstruct ciphertext from XOR shares.
///
/// XORs all shares together. With all `N` shares supplied (in any
/// order), returns the original ciphertext. With fewer than `N`,
/// returns something that looks like uniform random noise —
/// caller's upstream decryption layer (MLS/DR AEAD) will fail to
/// decrypt it. There is no way to detect "share missing" inside
/// this function; treat unknown-content reconstruction as
/// untrusted bytes until the decryption layer rules.
///
/// # Errors
///
/// * [`StripeError::NoShares`] if the input slice is empty.
/// * [`StripeError::ShareSizeMismatch`] if any share differs in
///   length from the first share.
pub fn combine_xor(shares: &[&[u8]]) -> Result<Vec<u8>, StripeError> {
	if shares.is_empty() {
		return Err(StripeError::NoShares);
	}
	let expected = shares[0].len();
	for (i, s) in shares.iter().enumerate().skip(1) {
		if s.len() != expected {
			return Err(StripeError::ShareSizeMismatch {
				expected,
				got: s.len(),
				index: i,
			});
		}
	}

	let mut out = shares[0].to_vec();
	for s in &shares[1..] {
		for (o, &b) in out.iter_mut().zip(s.iter()) {
			*o ^= b;
		}
	}
	Ok(out)
}

#[cfg(test)]
mod tests {
	use super::*;
	use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

	/// Deterministic CSPRNG for tests. Seed pinned per call so
	/// failures reproduce locally without relying on OS entropy.
	fn test_rng(seed: u8) -> ChaCha20Rng {
		ChaCha20Rng::from_seed([seed; 32])
	}

	fn share_refs(shares: &[Vec<u8>]) -> Vec<&[u8]> {
		shares.iter().map(|s| s.as_slice()).collect()
	}

	// ── basic roundtrip ───────────────────────────────────────────

	#[test]
	fn roundtrip_n_2() {
		let mut rng = test_rng(0x01);
		let ciphertext = b"hello, rostro chat layer";
		let shares = split_xor(ciphertext, 2, &mut rng).unwrap();
		assert_eq!(shares.len(), 2);
		let recovered = combine_xor(&share_refs(&shares)).unwrap();
		assert_eq!(recovered, ciphertext);
	}

	#[test]
	fn roundtrip_n_3() {
		let mut rng = test_rng(0x02);
		let ciphertext = b"three-share stripe";
		let shares = split_xor(ciphertext, 3, &mut rng).unwrap();
		assert_eq!(shares.len(), 3);
		assert_eq!(combine_xor(&share_refs(&shares)).unwrap(), ciphertext);
	}

	#[test]
	fn roundtrip_n_5() {
		let mut rng = test_rng(0x03);
		let ciphertext = b"five-share stripe carries the payload across more relays";
		let shares = split_xor(ciphertext, 5, &mut rng).unwrap();
		assert_eq!(shares.len(), 5);
		assert_eq!(combine_xor(&share_refs(&shares)).unwrap(), ciphertext);
	}

	#[test]
	fn roundtrip_n_10() {
		let mut rng = test_rng(0x04);
		let ciphertext = (0u8..=255u8).cycle().take(1024).collect::<Vec<_>>();
		let shares = split_xor(&ciphertext, 10, &mut rng).unwrap();
		assert_eq!(shares.len(), 10);
		assert_eq!(combine_xor(&share_refs(&shares)).unwrap(), ciphertext);
	}

	#[test]
	fn roundtrip_n_50() {
		let mut rng = test_rng(0x05);
		// 50 shares is well below MAX_SHARES (64); proves the cap
		// doesn't accidentally clip a legitimate N.
		let ciphertext = b"fifty-share stripe extreme scenario";
		let shares = split_xor(ciphertext, 50, &mut rng).unwrap();
		assert_eq!(shares.len(), 50);
		assert_eq!(combine_xor(&share_refs(&shares)).unwrap(), ciphertext);
	}

	// ── N boundary errors ─────────────────────────────────────────

	#[test]
	fn split_rejects_n_zero() {
		let mut rng = test_rng(0x06);
		match split_xor(b"x", 0, &mut rng) {
			Err(StripeError::InvalidN { got, min, max }) => {
				assert_eq!(got, 0);
				assert_eq!(min, MIN_SHARES);
				assert_eq!(max, MAX_SHARES);
			},
			other => panic!("expected InvalidN, got {:?}", other),
		}
	}

	#[test]
	fn split_rejects_n_one() {
		let mut rng = test_rng(0x07);
		match split_xor(b"x", 1, &mut rng) {
			Err(StripeError::InvalidN { got, .. }) => assert_eq!(got, 1),
			other => panic!("expected InvalidN, got {:?}", other),
		}
	}

	#[test]
	fn split_rejects_n_above_max() {
		let mut rng = test_rng(0x08);
		match split_xor(b"x", MAX_SHARES + 1, &mut rng) {
			Err(StripeError::InvalidN { got, max, .. }) => {
				assert_eq!(got, MAX_SHARES + 1);
				assert_eq!(max, MAX_SHARES);
			},
			other => panic!("expected InvalidN, got {:?}", other),
		}
	}

	#[test]
	fn split_accepts_n_at_max() {
		let mut rng = test_rng(0x09);
		let shares = split_xor(b"x", MAX_SHARES, &mut rng).unwrap();
		assert_eq!(shares.len(), MAX_SHARES);
	}

	// ── empty ciphertext edge case ────────────────────────────────

	#[test]
	fn empty_ciphertext_roundtrips() {
		let mut rng = test_rng(0x0A);
		let shares = split_xor(&[], 3, &mut rng).unwrap();
		assert_eq!(shares.len(), 3);
		for s in &shares {
			assert!(s.is_empty(), "share of empty ciphertext must be empty");
		}
		assert_eq!(combine_xor(&share_refs(&shares)).unwrap(), Vec::<u8>::new());
	}

	// ── combine errors ────────────────────────────────────────────

	#[test]
	fn combine_rejects_no_shares() {
		assert_eq!(combine_xor(&[]), Err(StripeError::NoShares));
	}

	#[test]
	fn combine_rejects_mismatched_sizes() {
		let a: Vec<u8> = alloc::vec![1, 2, 3, 4];
		let b: Vec<u8> = alloc::vec![1, 2, 3]; // one byte short
		let shares: Vec<&[u8]> = alloc::vec![a.as_slice(), b.as_slice()];
		match combine_xor(&shares) {
			Err(StripeError::ShareSizeMismatch { expected, got, index }) => {
				assert_eq!(expected, 4);
				assert_eq!(got, 3);
				assert_eq!(index, 1);
			},
			other => panic!("expected ShareSizeMismatch, got {:?}", other),
		}
	}

	// ── order independence ────────────────────────────────────────

	#[test]
	fn combine_order_independent() {
		let mut rng = test_rng(0x0B);
		let ciphertext = b"order should not matter";
		let shares = split_xor(ciphertext, 5, &mut rng).unwrap();

		let forward = share_refs(&shares);
		let mut reversed = forward.clone();
		reversed.reverse();

		assert_eq!(
			combine_xor(&forward).unwrap(),
			combine_xor(&reversed).unwrap(),
			"XOR is commutative; order must not affect result",
		);
	}

	// ── single missing share = unrecoverable ──────────────────────

	#[test]
	fn missing_share_produces_non_ciphertext() {
		let mut rng = test_rng(0x0C);
		let ciphertext = b"single missing share breaks reconstruction";
		let shares = split_xor(ciphertext, 4, &mut rng).unwrap();

		// Drop each share in turn; combining N-1 should never recover
		// the ciphertext.
		for drop_idx in 0..shares.len() {
			let partial: Vec<&[u8]> = shares
				.iter()
				.enumerate()
				.filter_map(|(i, s)| if i == drop_idx { None } else { Some(s.as_slice()) })
				.collect();
			let attempted = combine_xor(&partial).unwrap();
			assert_ne!(
				attempted, ciphertext,
				"combining {} of {} shares (dropped index {}) must not recover ciphertext",
				partial.len(),
				shares.len(),
				drop_idx,
			);
		}
	}

	// ── individual shares look random ─────────────────────────────

	#[test]
	fn individual_shares_are_not_ciphertext() {
		// Any single share viewed in isolation should be
		// indistinguishable from random; specifically, it should
		// NOT equal the plaintext ciphertext. (A real statistical
		// test would be too heavy for unit tests; this is the
		// minimum-bar version that catches "oops, we shipped the
		// ciphertext as share[0]".)
		let mut rng = test_rng(0x0D);
		let ciphertext = b"this is the secret payload";
		let shares = split_xor(ciphertext, 7, &mut rng).unwrap();
		for (i, s) in shares.iter().enumerate() {
			assert_ne!(
				s.as_slice(),
				ciphertext,
				"share {} must not equal ciphertext",
				i,
			);
		}
	}

	#[test]
	fn shares_differ_from_each_other() {
		// Each share should be distinct from the others (negligible
		// collision probability over 32+ bytes of random output).
		let mut rng = test_rng(0x0E);
		let ciphertext = (0u8..32u8).collect::<Vec<_>>();
		let shares = split_xor(&ciphertext, 8, &mut rng).unwrap();
		for i in 0..shares.len() {
			for j in (i + 1)..shares.len() {
				assert_ne!(
					shares[i], shares[j],
					"shares {} and {} happened to collide; this should be cryptographically improbable",
					i, j,
				);
			}
		}
	}

	// ── XOR commutativity sanity check ────────────────────────────

	#[test]
	fn xor_associativity_extended() {
		// Combine via XOR is associative as well as commutative;
		// pair-merge order shouldn't matter. We don't expose pair-
		// merge explicitly, but ensure a manual associative
		// reordering yields the same result as combine_xor.
		let mut rng = test_rng(0x0F);
		let ciphertext = b"associativity check";
		let shares = split_xor(ciphertext, 6, &mut rng).unwrap();

		// Manual left-fold matches combine_xor.
		let mut manual = shares[0].clone();
		for s in &shares[1..] {
			for (a, &b) in manual.iter_mut().zip(s.iter()) {
				*a ^= b;
			}
		}
		assert_eq!(combine_xor(&share_refs(&shares)).unwrap(), manual);
		assert_eq!(manual, ciphertext);
	}

	// ── single share combine returns share unchanged ──────────────

	#[test]
	fn combine_of_single_share_returns_share() {
		// Mathematically, XORing one buffer with nothing is identity.
		// We accept this — it's not an error condition. Caller's
		// upstream decryption layer will see uniform-random bytes
		// (since shares look random) and fail to decrypt. This is
		// fine.
		let single: Vec<u8> = alloc::vec![1, 2, 3, 4, 5];
		let combined = combine_xor(&[single.as_slice()]).unwrap();
		assert_eq!(combined, single);
	}

	// ── authenticated combine ─────────────────────────────────────

	use crate::descriptor::MessageId;
	use crate::verify::{derive_share_mac_key, mac_share};

	/// Build the canonical (share_index, share_bytes, tag) triple
	/// set for a stripe-split ciphertext under a given MAC key.
	fn tagged_shares(
		key: &ShareMacKey,
		shares: &[Vec<u8>],
	) -> Vec<(ShareIndex, Vec<u8>, ShareMacTag)> {
		shares
			.iter()
			.enumerate()
			.map(|(i, s)| {
				let idx = i as ShareIndex;
				let tag = mac_share(key, s, idx);
				(idx, s.clone(), tag)
			})
			.collect()
	}

	fn tagged_refs<'a>(
		tagged: &'a [(ShareIndex, Vec<u8>, ShareMacTag)],
	) -> Vec<(ShareIndex, &'a [u8], &'a ShareMacTag)> {
		tagged.iter().map(|(i, b, t)| (*i, b.as_slice(), t)).collect()
	}

	#[test]
	fn auth_combine_honest_path_roundtrips() {
		let mut rng = test_rng(0x20);
		let ciphertext = b"authenticated combine roundtrip";
		let shares = split_xor(ciphertext, 4, &mut rng).unwrap();
		let key = derive_share_mac_key(&[0x42; 32], &MessageId([0xAA; 32]));
		let tagged = tagged_shares(&key, &shares);
		let recovered = combine_xor_authenticated(&key, &tagged_refs(&tagged)).unwrap();
		assert_eq!(recovered, ciphertext);
	}

	#[test]
	fn auth_combine_identifies_tampered_share_bytes() {
		let mut rng = test_rng(0x21);
		let ciphertext = b"tamper detection test";
		let shares = split_xor(ciphertext, 5, &mut rng).unwrap();
		let key = derive_share_mac_key(&[0x42; 32], &MessageId([0xAA; 32]));
		let mut tagged = tagged_shares(&key, &shares);
		// Flip a byte in share at slice index 2.
		tagged[2].1[0] ^= 0xFF;
		match combine_xor_authenticated(&key, &tagged_refs(&tagged)) {
			Err(AuthCombineError::TamperedShare { slice_index, share_index }) => {
				assert_eq!(slice_index, 2, "must identify position of bad share");
				assert_eq!(share_index, 2, "must report canonical share_index");
			},
			other => panic!("expected TamperedShare, got {:?}", other),
		}
	}

	#[test]
	fn auth_combine_identifies_share_swap() {
		// Relay returns share[1]'s bytes under index 0 (or vice versa).
		// MAC binds bytes to position; mismatch is detected.
		let mut rng = test_rng(0x22);
		let ciphertext = b"swap attack detection";
		let shares = split_xor(ciphertext, 3, &mut rng).unwrap();
		let key = derive_share_mac_key(&[0x42; 32], &MessageId([0xAA; 32]));
		let tagged = tagged_shares(&key, &shares);

		// Construct a swapped triple: take share at index 1 but claim it's index 0.
		let mut bad: Vec<(ShareIndex, &[u8], &ShareMacTag)> = tagged_refs(&tagged);
		bad[0] = (0, tagged[1].1.as_slice(), &tagged[0].2); // index 0, but bytes from share 1

		match combine_xor_authenticated(&key, &bad) {
			Err(AuthCombineError::TamperedShare { slice_index, .. }) => {
				assert_eq!(slice_index, 0);
			},
			other => panic!("expected TamperedShare on swap, got {:?}", other),
		}
	}

	#[test]
	fn auth_combine_identifies_tampered_tag() {
		let mut rng = test_rng(0x23);
		let ciphertext = b"tag tamper";
		let shares = split_xor(ciphertext, 3, &mut rng).unwrap();
		let key = derive_share_mac_key(&[0x42; 32], &MessageId([0xAA; 32]));
		let mut tagged = tagged_shares(&key, &shares);
		// Flip a byte in the tag at slice index 1.
		tagged[1].2[0] ^= 0xFF;
		match combine_xor_authenticated(&key, &tagged_refs(&tagged)) {
			Err(AuthCombineError::TamperedShare { slice_index, share_index }) => {
				assert_eq!(slice_index, 1);
				assert_eq!(share_index, 1);
			},
			other => panic!("expected TamperedShare, got {:?}", other),
		}
	}

	#[test]
	fn auth_combine_rejects_wrong_key() {
		let mut rng = test_rng(0x24);
		let ciphertext = b"wrong key";
		let shares = split_xor(ciphertext, 3, &mut rng).unwrap();
		let key_real = derive_share_mac_key(&[0x42; 32], &MessageId([0xAA; 32]));
		let key_wrong = derive_share_mac_key(&[0x43; 32], &MessageId([0xAA; 32]));
		let tagged = tagged_shares(&key_real, &shares);
		// Caller uses the wrong key to verify; every MAC fails.
		match combine_xor_authenticated(&key_wrong, &tagged_refs(&tagged)) {
			Err(AuthCombineError::TamperedShare { slice_index: 0, .. }) => {},
			other => panic!("expected TamperedShare at slice_index 0, got {:?}", other),
		}
	}

	#[test]
	fn auth_combine_rejects_empty() {
		let key = derive_share_mac_key(&[0x42; 32], &MessageId([0xAA; 32]));
		assert_eq!(
			combine_xor_authenticated(&key, &[]),
			Err(AuthCombineError::NoShares),
		);
	}

	#[test]
	fn auth_combine_rejects_size_mismatch() {
		let key = derive_share_mac_key(&[0x42; 32], &MessageId([0xAA; 32]));
		// Build two shares of differing length; the size check fires
		// before MAC verification.
		let a: Vec<u8> = alloc::vec![1, 2, 3, 4];
		let b: Vec<u8> = alloc::vec![5, 6, 7]; // short
		let ta = mac_share(&key, &a, 0);
		let tb = mac_share(&key, &b, 1);
		let input: Vec<(ShareIndex, &[u8], &ShareMacTag)> = alloc::vec![
			(0, a.as_slice(), &ta),
			(1, b.as_slice(), &tb),
		];
		match combine_xor_authenticated(&key, &input) {
			Err(AuthCombineError::ShareSizeMismatch { expected, got, slice_index }) => {
				assert_eq!(expected, 4);
				assert_eq!(got, 3);
				assert_eq!(slice_index, 1);
			},
			other => panic!("expected ShareSizeMismatch, got {:?}", other),
		}
	}

	#[test]
	fn auth_combine_preserves_order_independence() {
		// XOR is commutative; auth-combine should accept shares in
		// any order (provided each (index, bytes, tag) tuple stays
		// consistent within itself).
		let mut rng = test_rng(0x25);
		let ciphertext = b"order independence in auth combine";
		let shares = split_xor(ciphertext, 5, &mut rng).unwrap();
		let key = derive_share_mac_key(&[0x42; 32], &MessageId([0xAA; 32]));
		let tagged = tagged_shares(&key, &shares);

		let mut reversed = tagged_refs(&tagged);
		reversed.reverse();
		assert_eq!(
			combine_xor_authenticated(&key, &reversed).unwrap(),
			ciphertext,
		);
	}
}
