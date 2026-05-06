// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! End-to-end tests for the slot-claim verifier.
//!
//! Generates real bandersnatch keypairs, signs a slot claim using the
//! same `slot_claim_sign_data` the runtime would use, runs the
//! verifier. Then tampers — wrong authority index, wrong slot, wrong
//! epoch index, wrong randomness, mutated signature — confirming each
//! mutation surfaces the right error.

use codec::Encode;
use sp_consensus_sassafras::{
	digests::{ConsensusLog, NextEpochDescriptor, SlotClaim},
	ticket::{TicketBody, TicketClaim, TicketId},
	vrf::{slot_claim_sign_data, VrfSignature},
	AuthorityId, AuthorityPair, EpochConfiguration, Randomness, Slot, SASSAFRAS_ENGINE_ID,
};
use sp_core::{
	crypto::{Pair, VrfSecret, Wraps},
	ed25519, H256,
};
use sp_runtime::{
	generic::{Digest, DigestItem, Header as GenericHeader},
	traits::BlakeTwo256,
};

use crate::{
	epoch::EpochContext,
	error::VerificationError,
	header::{extract_consensus_log, extract_next_epoch_descriptor, extract_slot_claim},
	producer::{produce_primary_slot_claim, produce_slot_claim, produce_ticket_claim},
	slot_claim::verify_slot_claim,
	ticket_claim::signed_data_for_ticket_binding,
	verifier::{verify_block, verify_header},
};

type TestHeader = GenericHeader<u32, BlakeTwo256>;

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

// ─── Header construction + extraction ────────────────────────────────────

/// Build a minimal test header carrying the supplied digest items.
/// Parent hash + state/extrinsics roots + block number are placeholders
/// — we never run a real chain through this, just verify-side cracking.
fn make_header(digest_items: Vec<DigestItem>) -> TestHeader {
	TestHeader {
		parent_hash: H256::zero(),
		number: 1,
		state_root: H256::zero(),
		extrinsics_root: H256::zero(),
		digest: Digest { logs: digest_items },
	}
}

fn pre_runtime_item(claim: &SlotClaim) -> DigestItem {
	DigestItem::from(claim)
}

fn next_epoch_consensus_item(desc: &NextEpochDescriptor) -> DigestItem {
	DigestItem::Consensus(SASSAFRAS_ENGINE_ID, ConsensusLog::NextEpochData(desc.clone()).encode())
}

fn sample_next_epoch_descriptor(authorities: &[AuthorityId]) -> NextEpochDescriptor {
	NextEpochDescriptor {
		randomness: [0xEE; 32],
		authorities: authorities.to_vec(),
		config: Some(EpochConfiguration { redundancy_factor: 2, attempts_number: 64 }),
	}
}

#[test]
fn extract_slot_claim_recovers_payload() {
	let authorities = make_authorities(2);
	let claim = build_claim(&authorities[0], 0, SLOT.into(), &RANDOMNESS, EPOCH_INDEX);
	let header = make_header(vec![pre_runtime_item(&claim)]);

	let extracted = extract_slot_claim(&header).expect("PreRuntime entry must be readable");
	assert_eq!(extracted.authority_idx, claim.authority_idx);
	assert_eq!(extracted.slot, claim.slot);
}

#[test]
fn extract_slot_claim_returns_none_for_empty_digest() {
	let header = make_header(vec![]);
	assert!(extract_slot_claim(&header).is_none());
}

#[test]
fn extract_slot_claim_returns_none_for_unrelated_engine_id() {
	// PreRuntime with a non-Sassafras engine ID — should be ignored.
	let header = make_header(vec![DigestItem::PreRuntime(*b"AURA", vec![1, 2, 3])]);
	assert!(extract_slot_claim(&header).is_none());
}

#[test]
fn extract_consensus_log_recovers_next_epoch_data() {
	let authorities = make_authorities(2);
	let pubkeys = pubkeys(&authorities);
	let desc = sample_next_epoch_descriptor(&pubkeys);
	let header = make_header(vec![next_epoch_consensus_item(&desc)]);

	let log = extract_consensus_log(&header).expect("ConsensusLog must decode");
	match log {
		ConsensusLog::NextEpochData(parsed) => {
			assert_eq!(parsed.authorities, desc.authorities);
			assert_eq!(parsed.randomness, desc.randomness);
		},
		ConsensusLog::OnDisabled(idx) => panic!("expected NextEpochData, got OnDisabled({idx})"),
	}
}

#[test]
fn extract_next_epoch_descriptor_returns_none_for_on_disabled() {
	// A different ConsensusLog variant must NOT surface as a NextEpochDescriptor.
	let payload = ConsensusLog::OnDisabled(3).encode();
	let header =
		make_header(vec![DigestItem::Consensus(SASSAFRAS_ENGINE_ID, payload)]);
	assert!(extract_next_epoch_descriptor(&header).is_none());
}

// ─── verify_header (block-level) ─────────────────────────────────────────

#[test]
fn verify_header_happy_path() {
	let authorities = make_authorities(3);
	let pubkeys = pubkeys(&authorities);
	let claim = build_claim(&authorities[1], 1, SLOT.into(), &RANDOMNESS, EPOCH_INDEX);
	let header = make_header(vec![pre_runtime_item(&claim)]);

	let ctx = EpochContext {
		index: EPOCH_INDEX,
		randomness: &RANDOMNESS,
		authorities: &pubkeys,
	};
	let verified = verify_header(&header, ctx).expect("valid header must verify");
	assert_eq!(verified.slot, Slot::from(SLOT));
	assert_eq!(verified.authority, &pubkeys[1]);
	assert!(verified.next_epoch.is_none(), "no next-epoch descriptor in this header");
}

#[test]
fn verify_header_missing_pre_runtime_is_caught() {
	let authorities = make_authorities(1);
	let pubkeys = pubkeys(&authorities);
	let header = make_header(vec![]); // no PreRuntime entry
	let ctx = EpochContext {
		index: EPOCH_INDEX,
		randomness: &RANDOMNESS,
		authorities: &pubkeys,
	};
	let err = verify_header(&header, ctx).unwrap_err();
	assert!(matches!(err, VerificationError::MissingSlotClaim));
}

#[test]
fn verify_header_propagates_signature_failure() {
	// Header carries a valid claim but the verifier supplies a
	// different epoch — the resulting sign-data mismatch surfaces as
	// InvalidVrfSignature, not as a header-extraction error.
	let authorities = make_authorities(2);
	let pubkeys = pubkeys(&authorities);
	let claim = build_claim(&authorities[0], 0, SLOT.into(), &RANDOMNESS, EPOCH_INDEX);
	let header = make_header(vec![pre_runtime_item(&claim)]);

	let ctx = EpochContext {
		index: EPOCH_INDEX + 5, // wrong
		randomness: &RANDOMNESS,
		authorities: &pubkeys,
	};
	let err = verify_header(&header, ctx).unwrap_err();
	assert!(matches!(err, VerificationError::InvalidVrfSignature { .. }));
}

#[test]
fn verify_header_surfaces_next_epoch_descriptor() {
	let authorities = make_authorities(2);
	let pubkeys = pubkeys(&authorities);
	let claim = build_claim(&authorities[0], 0, SLOT.into(), &RANDOMNESS, EPOCH_INDEX);
	let desc = sample_next_epoch_descriptor(&pubkeys);

	let header =
		make_header(vec![pre_runtime_item(&claim), next_epoch_consensus_item(&desc)]);

	let ctx = EpochContext {
		index: EPOCH_INDEX,
		randomness: &RANDOMNESS,
		authorities: &pubkeys,
	};
	let verified = verify_header(&header, ctx).expect("header must verify");
	let surfaced = verified.next_epoch.expect("next-epoch descriptor surfaced");
	assert_eq!(surfaced.randomness, desc.randomness);
	assert_eq!(surfaced.authorities, desc.authorities);
}

// ─── verify_block: ticket-binding cross-check ────────────────────────────

/// Construct a TicketBody + matching erased keypair. Returns
/// (TicketBody, erased_pair) so tests can sign with the erased secret.
fn make_ticket_body(seed: &str) -> (TicketBody, ed25519::Pair) {
	let erased_pair =
		ed25519::Pair::from_string(seed, None).expect("valid SURI test seed; qed");
	let revealed_pair =
		ed25519::Pair::from_string(&format!("{seed}//revealed"), None).expect("revealed; qed");
	let body = TicketBody {
		attempt_idx: 0,
		erased_public: erased_pair.public(),
		revealed_public: revealed_pair.public(),
	};
	(body, erased_pair)
}

/// Build a valid TicketClaim: sign the SlotClaim's expected ticket-
/// binding message with the erased secret.
fn make_ticket_claim(claim: &SlotClaim, erased_pair: &ed25519::Pair) -> TicketClaim {
	let message = signed_data_for_ticket_binding(claim);
	let erased_signature = erased_pair.sign(&message);
	TicketClaim { erased_signature }
}

#[test]
fn verify_block_happy_path_with_ticket() {
	let authorities = make_authorities(2);
	let pubkeys = pubkeys(&authorities);
	let mut claim = build_claim(&authorities[0], 0, SLOT.into(), &RANDOMNESS, EPOCH_INDEX);
	let (ticket_body, erased_pair) = make_ticket_body("//RostroTicket//A");
	claim.ticket_claim = Some(make_ticket_claim(&claim, &erased_pair));

	let header = make_header(vec![pre_runtime_item(&claim)]);
	let ctx = EpochContext {
		index: EPOCH_INDEX,
		randomness: &RANDOMNESS,
		authorities: &pubkeys,
	};
	let bound_id: TicketId = 0xCAFEBABE;
	let body_clone = ticket_body.clone();
	let lookup = |s: Slot| {
		assert_eq!(s, Slot::from(SLOT));
		Some((bound_id, body_clone.clone()))
	};
	let verified = verify_block(&header, ctx, lookup).expect("primary slot must verify");
	assert_eq!(verified.slot, Slot::from(SLOT));
}

#[test]
fn verify_block_fallback_path_no_ticket() {
	// No ticket bound to this slot. Claim has no ticket_claim. Must
	// pass — fallback / secondary slot path.
	let authorities = make_authorities(1);
	let pubkeys = pubkeys(&authorities);
	let claim = build_claim(&authorities[0], 0, SLOT.into(), &RANDOMNESS, EPOCH_INDEX);
	let header = make_header(vec![pre_runtime_item(&claim)]);
	let ctx = EpochContext {
		index: EPOCH_INDEX,
		randomness: &RANDOMNESS,
		authorities: &pubkeys,
	};
	let lookup = |_s: Slot| None;
	let verified = verify_block(&header, ctx, lookup).expect("fallback must pass");
	assert!(verified.claim.ticket_claim.is_none());
}

#[test]
fn verify_block_rejects_missing_ticket_claim_for_bound_slot() {
	let authorities = make_authorities(1);
	let pubkeys = pubkeys(&authorities);
	let claim = build_claim(&authorities[0], 0, SLOT.into(), &RANDOMNESS, EPOCH_INDEX);
	// Claim has NO ticket_claim, but the slot has a bound ticket.
	let header = make_header(vec![pre_runtime_item(&claim)]);
	let ctx = EpochContext {
		index: EPOCH_INDEX,
		randomness: &RANDOMNESS,
		authorities: &pubkeys,
	};
	let (body, _erased) = make_ticket_body("//RostroTicket//B");
	let lookup = |_s: Slot| Some((42u128, body.clone()));
	let err = verify_block(&header, ctx, lookup).unwrap_err();
	assert!(matches!(err, VerificationError::MissingTicketClaim { .. }));
}

#[test]
fn verify_block_rejects_unexpected_ticket_claim_for_unbound_slot() {
	let authorities = make_authorities(1);
	let pubkeys = pubkeys(&authorities);
	let mut claim = build_claim(&authorities[0], 0, SLOT.into(), &RANDOMNESS, EPOCH_INDEX);
	// Claim CARRIES a ticket_claim, but the slot has no bound ticket.
	let (_body, erased_pair) = make_ticket_body("//RostroTicket//C");
	claim.ticket_claim = Some(make_ticket_claim(&claim, &erased_pair));

	let header = make_header(vec![pre_runtime_item(&claim)]);
	let ctx = EpochContext {
		index: EPOCH_INDEX,
		randomness: &RANDOMNESS,
		authorities: &pubkeys,
	};
	let lookup = |_s: Slot| None;
	let err = verify_block(&header, ctx, lookup).unwrap_err();
	assert!(matches!(err, VerificationError::UnexpectedTicketClaim { .. }));
}

#[test]
fn verify_block_rejects_wrong_erased_signature() {
	// Bound ticket, claim has ticket_claim, but the erased_signature
	// was signed by a DIFFERENT erased key than the one in the body.
	let authorities = make_authorities(1);
	let pubkeys = pubkeys(&authorities);
	let mut claim = build_claim(&authorities[0], 0, SLOT.into(), &RANDOMNESS, EPOCH_INDEX);

	let (body_for_lookup, _erased_a) = make_ticket_body("//RostroTicket//KeyA");
	let (_body_b, erased_b) = make_ticket_body("//RostroTicket//KeyB");

	// Sign with erased_b but the body the lookup returns has erased_a.
	claim.ticket_claim = Some(make_ticket_claim(&claim, &erased_b));

	let header = make_header(vec![pre_runtime_item(&claim)]);
	let ctx = EpochContext {
		index: EPOCH_INDEX,
		randomness: &RANDOMNESS,
		authorities: &pubkeys,
	};
	let body_clone = body_for_lookup.clone();
	let lookup = |_s: Slot| Some((1u128, body_clone.clone()));
	let err = verify_block(&header, ctx, lookup).unwrap_err();
	assert!(matches!(err, VerificationError::TicketBindingFailed { .. }));
}

#[test]
fn verify_block_propagates_header_errors() {
	let authorities = make_authorities(1);
	let pubkeys = pubkeys(&authorities);
	let header = make_header(vec![]); // no PreRuntime entry
	let ctx = EpochContext {
		index: EPOCH_INDEX,
		randomness: &RANDOMNESS,
		authorities: &pubkeys,
	};
	let lookup = |_s: Slot| None;
	let err = verify_block(&header, ctx, lookup).unwrap_err();
	assert!(matches!(err, VerificationError::MissingSlotClaim));
}

// ─── Producer → Verifier round-trip ──────────────────────────────────────

#[test]
fn produce_then_verify_fallback_slot() {
	// Producer-side: validator at index 1 produces a fallback (no
	// ticket) slot claim. Verifier-side: rebuilds the sign-data and
	// the bandersnatch IETF VRF check passes.
	let authorities = make_authorities(3);
	let pubkeys = pubkeys(&authorities);
	let ctx = EpochContext {
		index: EPOCH_INDEX,
		randomness: &RANDOMNESS,
		authorities: &pubkeys,
	};
	let claim = produce_slot_claim(&authorities[1], 1, SLOT.into(), ctx, None);
	let resolved =
		verify_slot_claim(&claim, ctx).expect("produced fallback claim must verify");
	assert_eq!(resolved, &pubkeys[1]);
}

#[test]
fn produce_then_verify_primary_slot_with_ticket() {
	// Full primary-slot round-trip: producer signs the slot claim,
	// then signs the ticket-binding message with the erased ed25519
	// secret, attaches the ticket_claim. Verifier validates the
	// bandersnatch VRF AND the ed25519 ticket-binding.
	let authorities = make_authorities(2);
	let pubkeys = pubkeys(&authorities);
	let ctx = EpochContext {
		index: EPOCH_INDEX,
		randomness: &RANDOMNESS,
		authorities: &pubkeys,
	};
	let (ticket_body, erased_pair) = make_ticket_body("//RostroProducer//A");
	let claim = produce_primary_slot_claim(
		&authorities[0],
		0,
		SLOT.into(),
		ctx,
		&erased_pair,
	);
	assert!(claim.ticket_claim.is_some(), "primary claim must carry ticket_claim");

	// Wrap in a header and run the full verify_block path.
	let header = make_header(vec![pre_runtime_item(&claim)]);
	let body_clone = ticket_body.clone();
	let lookup = |_s: Slot| Some((1u128, body_clone.clone()));
	let verified = verify_block(&header, ctx, lookup).expect("primary round-trip must verify");
	assert_eq!(verified.authority, &pubkeys[0]);
}

#[test]
fn produce_ticket_claim_independently_then_compose() {
	// Two-step flow: produce a SlotClaim with no ticket, then derive
	// the ticket_claim, then attach. Verify the produce_ticket_claim
	// helper alone produces a valid binding.
	let authorities = make_authorities(1);
	let pubkeys = pubkeys(&authorities);
	let ctx = EpochContext {
		index: EPOCH_INDEX,
		randomness: &RANDOMNESS,
		authorities: &pubkeys,
	};
	let intermediate = produce_slot_claim(&authorities[0], 0, SLOT.into(), ctx, None);

	let (body, erased_pair) = make_ticket_body("//RostroProducer//Compose");
	let ticket_claim = produce_ticket_claim(&erased_pair, &intermediate);

	// Independent verification of just the ticket-binding step.
	crate::ticket_claim::verify_ticket_claim(&intermediate, &ticket_claim, &body)
		.expect("ticket-binding round-trip must hold");
}

#[test]
fn produced_claim_with_wrong_authority_index_fails_verification() {
	// Produce with authorities[2] but claim authority_idx = 0. The
	// verifier looks up index 0's public key; the signature was made
	// by index 2's secret. Verification fails.
	let authorities = make_authorities(3);
	let pubkeys = pubkeys(&authorities);
	let ctx = EpochContext {
		index: EPOCH_INDEX,
		randomness: &RANDOMNESS,
		authorities: &pubkeys,
	};
	let claim = produce_slot_claim(&authorities[2], 0, SLOT.into(), ctx, None);
	let err = verify_slot_claim(&claim, ctx).unwrap_err();
	assert!(matches!(err, VerificationError::InvalidVrfSignature { .. }));
}

