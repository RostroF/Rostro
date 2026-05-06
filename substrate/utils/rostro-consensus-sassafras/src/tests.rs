// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! End-to-end tests for the slot-claim verifier.
//!
//! Generates real bandersnatch keypairs, signs a slot claim using the
//! same `slot_claim_sign_data` the runtime would use, runs the
//! verifier. Then tampers — wrong authority index, wrong slot, wrong
//! epoch index, wrong randomness, mutated signature — confirming each
//! mutation surfaces the right error.

use sp_consensus_sassafras::{
	digests::SlotClaim,
	vrf::{slot_claim_sign_data, VrfSignature},
	AuthorityId, AuthorityPair, Randomness, Slot,
};
use sp_core::crypto::{Pair, VrfSecret, Wraps};

use crate::{epoch::EpochContext, error::VerificationError, slot_claim::verify_slot_claim};

// ─── Test fixture ────────────────────────────────────────────────────────

const RANDOMNESS: Randomness = [0xAB; 32];
const EPOCH_INDEX: u64 = 7;
const SLOT: u64 = 42;

/// Generate `n` bandersnatch authority keypairs deterministically.
fn make_authorities(n: usize) -> Vec<AuthorityPair> {
	(0..n)
		.map(|i| {
			let seed = format!("//RostroSassafrasTest//{i}");
			AuthorityPair::from_string(&seed, None).expect("valid SURI test seed; qed")
		})
		.collect()
}

/// Build a valid SlotClaim for a given authority's keypair.
fn build_claim(
	pair: &AuthorityPair,
	authority_idx: u32,
	slot: Slot,
	randomness: &Randomness,
	epoch_index: u64,
) -> SlotClaim {
	let sign_data = slot_claim_sign_data(randomness, slot, epoch_index);
	let vrf_signature: VrfSignature = pair.as_inner_ref().vrf_sign(&sign_data);
	SlotClaim { authority_idx, slot, vrf_signature, ticket_claim: None }
}

fn pubkeys(authorities: &[AuthorityPair]) -> Vec<AuthorityId> {
	authorities.iter().map(|p| p.public()).collect()
}

// ─── Round trip ──────────────────────────────────────────────────────────

#[test]
fn valid_claim_verifies() {
	let authorities = make_authorities(4);
	let pubkeys = pubkeys(&authorities);
	let claim = build_claim(&authorities[2], 2, SLOT.into(), &RANDOMNESS, EPOCH_INDEX);

	let ctx = EpochContext {
		index: EPOCH_INDEX,
		randomness: &RANDOMNESS,
		authorities: &pubkeys,
	};
	let resolved = verify_slot_claim(&claim, ctx).expect("valid claim must verify");
	assert_eq!(resolved, &pubkeys[2], "verifier returns the authority that signed");
}

// ─── Authority-index errors ──────────────────────────────────────────────

#[test]
fn authority_index_out_of_range_is_caught() {
	let authorities = make_authorities(4);
	let pubkeys = pubkeys(&authorities);
	let mut claim = build_claim(&authorities[0], 0, SLOT.into(), &RANDOMNESS, EPOCH_INDEX);
	claim.authority_idx = 99;

	let ctx = EpochContext {
		index: EPOCH_INDEX,
		randomness: &RANDOMNESS,
		authorities: &pubkeys,
	};
	let err = verify_slot_claim(&claim, ctx).unwrap_err();
	assert!(
		matches!(err, VerificationError::AuthorityIndexOutOfRange { index: 99, set_size: 4 }),
		"got {err:?}"
	);
}

#[test]
fn wrong_authority_index_fails_signature_check() {
	// Pair index 2 signs, but the claim names index 0. Index 0's public
	// key won't verify the signature.
	let authorities = make_authorities(4);
	let pubkeys = pubkeys(&authorities);
	let mut claim = build_claim(&authorities[2], 2, SLOT.into(), &RANDOMNESS, EPOCH_INDEX);
	claim.authority_idx = 0;

	let ctx = EpochContext {
		index: EPOCH_INDEX,
		randomness: &RANDOMNESS,
		authorities: &pubkeys,
	};
	let err = verify_slot_claim(&claim, ctx).unwrap_err();
	assert!(matches!(err, VerificationError::InvalidVrfSignature { .. }));
}

// ─── Sign-data tampering ─────────────────────────────────────────────────

#[test]
fn wrong_slot_in_claim_fails() {
	// Sign for slot 42, but claim says slot 100. The sign-data
	// folds the slot in, so the signature won't match.
	let authorities = make_authorities(2);
	let pubkeys = pubkeys(&authorities);
	let mut claim = build_claim(&authorities[0], 0, SLOT.into(), &RANDOMNESS, EPOCH_INDEX);
	claim.slot = 100u64.into();

	let ctx = EpochContext {
		index: EPOCH_INDEX,
		randomness: &RANDOMNESS,
		authorities: &pubkeys,
	};
	let err = verify_slot_claim(&claim, ctx).unwrap_err();
	assert!(matches!(err, VerificationError::InvalidVrfSignature { .. }));
}

#[test]
fn wrong_epoch_randomness_fails() {
	let authorities = make_authorities(2);
	let pubkeys = pubkeys(&authorities);
	let claim = build_claim(&authorities[0], 0, SLOT.into(), &RANDOMNESS, EPOCH_INDEX);

	let bad_randomness: Randomness = [0xCD; 32];
	let ctx = EpochContext {
		index: EPOCH_INDEX,
		randomness: &bad_randomness,
		authorities: &pubkeys,
	};
	let err = verify_slot_claim(&claim, ctx).unwrap_err();
	assert!(matches!(err, VerificationError::InvalidVrfSignature { .. }));
}

#[test]
fn wrong_epoch_index_fails() {
	let authorities = make_authorities(2);
	let pubkeys = pubkeys(&authorities);
	let claim = build_claim(&authorities[0], 0, SLOT.into(), &RANDOMNESS, EPOCH_INDEX);

	let ctx = EpochContext {
		index: EPOCH_INDEX + 1, // off-by-one
		randomness: &RANDOMNESS,
		authorities: &pubkeys,
	};
	let err = verify_slot_claim(&claim, ctx).unwrap_err();
	assert!(matches!(err, VerificationError::InvalidVrfSignature { .. }));
}

// ─── Signature swap (different sign-data signed by same key) ─────────────

#[test]
fn signature_for_different_slot_swapped_in_fails() {
	// Sign for slot 42, then sign for slot 100 with the same key.
	// Build a claim that *says* slot 42 but carries the slot-100
	// signature. The verifier rebuilds sign_data from claim.slot=42
	// and the swapped signature won't match.
	let authorities = make_authorities(2);
	let pubkeys = pubkeys(&authorities);

	let claim_42 = build_claim(&authorities[0], 0, 42u64.into(), &RANDOMNESS, EPOCH_INDEX);
	let claim_100 = build_claim(&authorities[0], 0, 100u64.into(), &RANDOMNESS, EPOCH_INDEX);

	let mut spliced = claim_42.clone();
	spliced.vrf_signature = claim_100.vrf_signature;

	let ctx = EpochContext {
		index: EPOCH_INDEX,
		randomness: &RANDOMNESS,
		authorities: &pubkeys,
	};
	let err = verify_slot_claim(&spliced, ctx).unwrap_err();
	assert!(matches!(err, VerificationError::InvalidVrfSignature { .. }));
}

// ─── EpochContext helpers ────────────────────────────────────────────────

#[test]
fn slot_falls_in_epoch_boundaries() {
	let authorities = make_authorities(1);
	let pubkeys = pubkeys(&authorities);
	let ctx = EpochContext {
		index: 5,
		randomness: &RANDOMNESS,
		authorities: &pubkeys,
	};

	// Epoch [100, 110): slots 100..109 inside, 99 + 110 outside.
	assert!(ctx.slot_falls_in_epoch(100u64.into(), 100u64.into(), 10));
	assert!(ctx.slot_falls_in_epoch(109u64.into(), 100u64.into(), 10));
	assert!(!ctx.slot_falls_in_epoch(99u64.into(), 100u64.into(), 10));
	assert!(!ctx.slot_falls_in_epoch(110u64.into(), 100u64.into(), 10));
}

