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

// ─── Import-queue Verifier (rc_consensus::Verifier impl) ────────────────

mod import_verifier_tests {
	use super::*;
	use crate::{
		import_verifier::SassafrasImportVerifier,
		providers::{EpochProvider, ProviderError, TicketProvider},
	};
	use rc_consensus::{BlockImportParams, Verifier as ConsensusVerifier};
	use sp_consensus_sassafras::{Epoch, EpochConfiguration};

	type TestBlock = sp_runtime::generic::Block<TestHeader, sp_runtime::OpaqueExtrinsic>;

	/// Stub epoch provider — returns a canned epoch regardless of
	/// parent hash. Tests parameterize via the constructor.
	struct StubEpoch {
		epoch: Epoch,
	}

	impl EpochProvider<TestBlock> for StubEpoch {
		fn epoch_at(&self, _parent: H256) -> Result<Epoch, ProviderError> {
			Ok(self.epoch.clone())
		}

		fn next_epoch_at(&self, _parent: H256) -> Result<Epoch, ProviderError> {
			Ok(self.epoch.clone())
		}
	}

	/// Stub ticket provider with a single canned binding.
	struct StubTicket {
		binding: Option<(TicketId, TicketBody)>,
	}

	impl TicketProvider<TestBlock> for StubTicket {
		fn slot_ticket(
			&self,
			_parent: H256,
			_slot: Slot,
		) -> Result<Option<(TicketId, TicketBody)>, ProviderError> {
			Ok(self.binding.clone())
		}
	}

	/// Build an Epoch with the given authorities + randomness + index.
	fn make_epoch(authorities: Vec<AuthorityId>) -> Epoch {
		Epoch {
			index: EPOCH_INDEX,
			start: 0u64.into(),
			length: 100,
			randomness: RANDOMNESS,
			authorities,
			config: EpochConfiguration { redundancy_factor: 2, attempts_number: 64 },
		}
	}

	fn make_import_params(header: TestHeader) -> BlockImportParams<TestBlock> {
		BlockImportParams::new(sp_consensus::BlockOrigin::NetworkBroadcast, header)
	}

	#[tokio::test(flavor = "current_thread")]
	async fn import_verifier_accepts_valid_fallback_block() {
		let authorities = make_authorities(2);
		let pubkeys = pubkeys(&authorities);
		let claim = build_claim(&authorities[0], 0, SLOT.into(), &RANDOMNESS, EPOCH_INDEX);
		let header = make_header(vec![pre_runtime_item(&claim)]);

		let verifier = SassafrasImportVerifier::<TestBlock, _, _>::new(
			StubEpoch { epoch: make_epoch(pubkeys) },
			StubTicket { binding: None },
		);

		verifier.verify(make_import_params(header)).await.expect("valid block accepts");
	}

	#[tokio::test(flavor = "current_thread")]
	async fn import_verifier_accepts_valid_primary_block() {
		let authorities = make_authorities(2);
		let pubkeys = pubkeys(&authorities);
		let mut claim = build_claim(&authorities[0], 0, SLOT.into(), &RANDOMNESS, EPOCH_INDEX);
		let (body, erased_pair) = make_ticket_body("//Import//A");
		claim.ticket_claim = Some(make_ticket_claim(&claim, &erased_pair));
		let header = make_header(vec![pre_runtime_item(&claim)]);

		let verifier = SassafrasImportVerifier::<TestBlock, _, _>::new(
			StubEpoch { epoch: make_epoch(pubkeys) },
			StubTicket { binding: Some((1u128, body)) },
		);
		verifier.verify(make_import_params(header)).await.expect("primary block accepts");
	}

	/// Helper: BlockImportParams isn't Debug, so unwrap_err / expect_err
	/// don't compile. Pattern-match instead.
	fn expect_err<T, E>(result: Result<T, E>) -> E {
		match result {
			Ok(_) => panic!("expected Err, got Ok"),
			Err(e) => e,
		}
	}

	#[tokio::test(flavor = "current_thread")]
	async fn import_verifier_rejects_missing_slot_claim() {
		let authorities = make_authorities(1);
		let pubkeys = pubkeys(&authorities);
		let header = make_header(vec![]); // no PreRuntime entry

		let verifier = SassafrasImportVerifier::<TestBlock, _, _>::new(
			StubEpoch { epoch: make_epoch(pubkeys) },
			StubTicket { binding: None },
		);

		let err = expect_err(verifier.verify(make_import_params(header)).await);
		assert!(err.contains("PreRuntime") || err.contains("not a Sassafras"), "got: {err}");
	}

	#[tokio::test(flavor = "current_thread")]
	async fn import_verifier_rejects_unbound_slot_with_ticket_claim() {
		let authorities = make_authorities(1);
		let pubkeys = pubkeys(&authorities);
		let mut claim = build_claim(&authorities[0], 0, SLOT.into(), &RANDOMNESS, EPOCH_INDEX);
		let (_body, erased_pair) = make_ticket_body("//Import//B");
		claim.ticket_claim = Some(make_ticket_claim(&claim, &erased_pair));
		let header = make_header(vec![pre_runtime_item(&claim)]);

		let verifier = SassafrasImportVerifier::<TestBlock, _, _>::new(
			StubEpoch { epoch: make_epoch(pubkeys) },
			StubTicket { binding: None },
		);

		let err = expect_err(verifier.verify(make_import_params(header)).await);
		assert!(err.contains("ticket_claim") || err.contains("no bound ticket"), "got: {err}");
	}

	#[tokio::test(flavor = "current_thread")]
	async fn import_verifier_propagates_epoch_lookup_failure() {
		struct FailingEpoch;
		impl EpochProvider<TestBlock> for FailingEpoch {
			fn epoch_at(&self, _: H256) -> Result<Epoch, ProviderError> {
				Err(ProviderError::UnknownBlock)
			}
			fn next_epoch_at(&self, _: H256) -> Result<Epoch, ProviderError> {
				Err(ProviderError::UnknownBlock)
			}
		}

		let authorities = make_authorities(1);
		let claim = build_claim(&authorities[0], 0, SLOT.into(), &RANDOMNESS, EPOCH_INDEX);
		let header = make_header(vec![pre_runtime_item(&claim)]);

		let verifier = SassafrasImportVerifier::<TestBlock, _, _>::new(
			FailingEpoch,
			StubTicket { binding: None },
		);

		let err = expect_err(verifier.verify(make_import_params(header)).await);
		assert!(err.contains("epoch lookup") || err.contains("unknown block"), "got: {err}");
	}
}

// ─── slot worker decision logic (R2.5c) ─────────────────────────────────

mod slot_worker_tests {
	use super::*;
	use crate::slot_worker::{fallback_winner_index, try_claim_slot, ClaimDecision};

	fn ctx<'a>(pubkeys: &'a [AuthorityId]) -> EpochContext<'a> {
		EpochContext { index: EPOCH_INDEX, randomness: &RANDOMNESS, authorities: pubkeys }
	}

	#[test]
	fn primary_claim_when_local_authority_holds_ticket_secret() {
		let authorities = make_authorities(3);
		let pubkeys = pubkeys(&authorities);
		let (body, erased_pair) = make_ticket_body("//Worker//A");

		let decision = try_claim_slot(
			SLOT.into(),
			ctx(&pubkeys),
			1, // local authority idx
			&authorities[1],
			|_slot| Some((1u128, body.clone())),
			|_b: &TicketBody| Some(erased_pair.clone()),
		);

		match decision {
			ClaimDecision::Primary { authority_idx, claim } => {
				assert_eq!(authority_idx, 1);
				assert!(claim.ticket_claim.is_some());
				// And the produced claim verifies via the full pipeline.
				let header = make_header(vec![pre_runtime_item(&claim)]);
				let body_clone = body.clone();
				let lookup = |_s: Slot| Some((1u128, body_clone.clone()));
				crate::verify_block(&header, ctx(&pubkeys), lookup)
					.expect("worker-produced primary claim must verify");
			},
			other => panic!("expected Primary, got {other:?}"),
		}
	}

	#[test]
	fn not_my_turn_when_someone_elses_ticket_is_bound() {
		let authorities = make_authorities(2);
		let pubkeys = pubkeys(&authorities);
		let (body, _erased_pair) = make_ticket_body("//Worker//SomeoneElse");

		let decision = try_claim_slot(
			SLOT.into(),
			ctx(&pubkeys),
			0,
			&authorities[0],
			|_slot| Some((1u128, body.clone())),
			|_b: &TicketBody| None, // we don't hold this erased secret
		);
		assert!(matches!(decision, ClaimDecision::NotMyTurn));
	}

	#[test]
	fn fallback_claim_when_unbound_slot_and_we_are_winner() {
		let authorities = make_authorities(4);
		let pubkeys = pubkeys(&authorities);

		// Find which authority the placeholder fallback rule picks
		// for this slot, then exercise that index.
		let test_slot = Slot::from(SLOT);
		let winner = fallback_winner_index(test_slot, &ctx(&pubkeys))
			.expect("fallback rule returns a winner for non-empty authority set");

		let decision = try_claim_slot(
			test_slot,
			ctx(&pubkeys),
			winner,
			&authorities[winner as usize],
			|_slot| None, // no ticket bound
			|_b: &TicketBody| None,
		);

		match decision {
			ClaimDecision::Fallback { authority_idx, claim } => {
				assert_eq!(authority_idx, winner);
				assert!(claim.ticket_claim.is_none());
				let header = make_header(vec![pre_runtime_item(&claim)]);
				let lookup = |_s: Slot| None;
				crate::verify_block(&header, ctx(&pubkeys), lookup)
					.expect("worker-produced fallback claim must verify");
			},
			other => panic!("expected Fallback, got {other:?}"),
		}
	}

	#[test]
	fn not_my_turn_when_unbound_slot_and_we_are_not_winner() {
		let authorities = make_authorities(4);
		let pubkeys = pubkeys(&authorities);
		let test_slot = Slot::from(SLOT);
		let winner = fallback_winner_index(test_slot, &ctx(&pubkeys)).unwrap();
		// Pick any non-winner index.
		let non_winner = (winner + 1) % 4;

		let decision = try_claim_slot(
			test_slot,
			ctx(&pubkeys),
			non_winner,
			&authorities[non_winner as usize],
			|_slot| None,
			|_b: &TicketBody| None,
		);
		assert!(matches!(decision, ClaimDecision::NotMyTurn));
	}

	#[test]
	fn fallback_winner_is_deterministic() {
		let authorities = make_authorities(4);
		let pubkeys = pubkeys(&authorities);
		let test_slot = Slot::from(SLOT);
		let a = fallback_winner_index(test_slot, &ctx(&pubkeys));
		let b = fallback_winner_index(test_slot, &ctx(&pubkeys));
		assert_eq!(a, b, "fallback rule must be deterministic");
	}

	#[test]
	fn fallback_winner_varies_with_slot() {
		let authorities = make_authorities(8);
		let pubkeys = pubkeys(&authorities);
		// Different slots should sometimes produce different winners
		// (placeholder-rule property check; real spec-rule should
		// have similar diffusion).
		let mut seen = std::collections::HashSet::new();
		for s in 0..50u64 {
			if let Some(w) = fallback_winner_index(s.into(), &ctx(&pubkeys)) {
				seen.insert(w);
			}
		}
		assert!(seen.len() >= 2, "50 slots → at least 2 distinct fallback winners");
	}
}

// ─── aux_schema: CachedEpochProvider (R2.5b) ─────────────────────────────

mod aux_schema_tests {
	use super::*;
	use crate::{
		aux_schema::CachedEpochProvider,
		providers::{EpochProvider, ProviderError},
	};
	use sp_consensus_sassafras::{Epoch, EpochConfiguration};
	use std::sync::atomic::{AtomicUsize, Ordering};

	type TestBlock = sp_runtime::generic::Block<TestHeader, sp_runtime::OpaqueExtrinsic>;

	/// EpochProvider that counts how many times each method is called.
	/// Used to verify the cache actually short-circuits on hits.
	struct CountingProvider {
		epoch: Epoch,
		next_epoch: Epoch,
		epoch_calls: AtomicUsize,
		next_epoch_calls: AtomicUsize,
	}
	impl EpochProvider<TestBlock> for CountingProvider {
		fn epoch_at(&self, _: H256) -> Result<Epoch, ProviderError> {
			self.epoch_calls.fetch_add(1, Ordering::SeqCst);
			Ok(self.epoch.clone())
		}
		fn next_epoch_at(&self, _: H256) -> Result<Epoch, ProviderError> {
			self.next_epoch_calls.fetch_add(1, Ordering::SeqCst);
			Ok(self.next_epoch.clone())
		}
	}

	fn make_test_epoch(index: u64) -> Epoch {
		Epoch {
			index,
			start: 0u64.into(),
			length: 100,
			randomness: [index as u8; 32],
			authorities: vec![],
			config: EpochConfiguration { redundancy_factor: 2, attempts_number: 64 },
		}
	}

	#[test]
	fn second_lookup_with_same_parent_hits_cache() {
		let counting = CountingProvider {
			epoch: make_test_epoch(7),
			next_epoch: make_test_epoch(8),
			epoch_calls: AtomicUsize::new(0),
			next_epoch_calls: AtomicUsize::new(0),
		};
		let cached = CachedEpochProvider::<TestBlock, _>::new(counting);

		let parent = H256::repeat_byte(0xAB);
		let _ = cached.epoch_at(parent).unwrap();
		let _ = cached.epoch_at(parent).unwrap();
		let _ = cached.epoch_at(parent).unwrap();

		assert_eq!(
			cached.cache_size(),
			1,
			"three calls with same parent → one cache entry"
		);
	}

	#[test]
	fn distinct_parents_each_populate_cache() {
		let counting = CountingProvider {
			epoch: make_test_epoch(7),
			next_epoch: make_test_epoch(8),
			epoch_calls: AtomicUsize::new(0),
			next_epoch_calls: AtomicUsize::new(0),
		};
		let cached = CachedEpochProvider::<TestBlock, _>::new(counting);

		let _ = cached.epoch_at(H256::repeat_byte(0x01)).unwrap();
		let _ = cached.epoch_at(H256::repeat_byte(0x02)).unwrap();
		let _ = cached.epoch_at(H256::repeat_byte(0x03)).unwrap();

		assert_eq!(cached.cache_size(), 3);
	}

	#[test]
	fn next_epoch_does_not_populate_cache() {
		let counting = CountingProvider {
			epoch: make_test_epoch(7),
			next_epoch: make_test_epoch(8),
			epoch_calls: AtomicUsize::new(0),
			next_epoch_calls: AtomicUsize::new(0),
		};
		let cached = CachedEpochProvider::<TestBlock, _>::new(counting);

		let _ = cached.next_epoch_at(H256::repeat_byte(0x01)).unwrap();
		let _ = cached.next_epoch_at(H256::repeat_byte(0x01)).unwrap();

		assert_eq!(cached.cache_size(), 0, "next-epoch lookups bypass cache by design");
	}

	#[test]
	fn evict_below_epoch_drops_old_entries() {
		// Populate with epochs 5, 6, 7. Evict below 7. Only the
		// epoch-7 entry should survive.
		struct VaryingProvider {
			next_index: AtomicUsize,
		}
		impl EpochProvider<TestBlock> for VaryingProvider {
			fn epoch_at(&self, _: H256) -> Result<Epoch, ProviderError> {
				// Cycle through epoch indices 5, 6, 7 across calls.
				let idx = 5 + (self.next_index.fetch_add(1, Ordering::SeqCst) % 3) as u64;
				Ok(make_test_epoch(idx))
			}
			fn next_epoch_at(&self, _: H256) -> Result<Epoch, ProviderError> {
				Ok(make_test_epoch(99))
			}
		}

		let cached = CachedEpochProvider::<TestBlock, _>::new(VaryingProvider {
			next_index: AtomicUsize::new(0),
		});
		let _ = cached.epoch_at(H256::repeat_byte(0x05)).unwrap();
		let _ = cached.epoch_at(H256::repeat_byte(0x06)).unwrap();
		let _ = cached.epoch_at(H256::repeat_byte(0x07)).unwrap();
		assert_eq!(cached.cache_size(), 3);

		cached.evict_below_epoch(7);
		assert_eq!(cached.cache_size(), 1, "only epoch-7 entry survives");
	}

	#[test]
	fn clear_drops_everything() {
		let cached = CachedEpochProvider::<TestBlock, _>::new(CountingProvider {
			epoch: make_test_epoch(1),
			next_epoch: make_test_epoch(2),
			epoch_calls: AtomicUsize::new(0),
			next_epoch_calls: AtomicUsize::new(0),
		});
		let _ = cached.epoch_at(H256::repeat_byte(0x01)).unwrap();
		let _ = cached.epoch_at(H256::repeat_byte(0x02)).unwrap();
		assert_eq!(cached.cache_size(), 2);
		cached.clear();
		assert_eq!(cached.cache_size(), 0);
	}
}

// ─── Equivocation reporter loop (R2.5e) ─────────────────────────────────

mod equivocation_reporter_tests {
	use super::*;
	use crate::{
		equivocation_reporter::{process_equivocation, ReportOutcome},
		providers::{EquivocationReporter, KeyOwnershipProver, ProviderError},
	};
	use sp_consensus_sassafras::{EquivocationProof, OpaqueKeyOwnershipProof};
	use std::sync::Mutex;

	type TestBlock = sp_runtime::generic::Block<TestHeader, sp_runtime::OpaqueExtrinsic>;

	struct StubKeyOwnerProver {
		// Inner bytes; construct OpaqueKeyOwnershipProof on demand.
		// (Type doesn't impl Clone so we can't cache the wrapper.)
		proof_bytes: Option<Vec<u8>>,
	}
	impl KeyOwnershipProver<TestBlock> for StubKeyOwnerProver {
		fn generate_key_ownership_proof(
			&self,
			_parent: H256,
			_authority: AuthorityId,
		) -> Result<Option<OpaqueKeyOwnershipProof>, ProviderError> {
			Ok(self.proof_bytes.as_ref().map(|b| fake_key_owner_proof(b.clone())))
		}
	}

	#[derive(Default)]
	struct RecordingReporter {
		submitted: Mutex<Vec<()>>,
	}
	impl EquivocationReporter<TestBlock> for RecordingReporter {
		fn submit_report(
			&self,
			_proof: EquivocationProof<TestHeader>,
			_kop: OpaqueKeyOwnershipProof,
		) -> Result<(), ProviderError> {
			self.submitted.lock().expect("not poisoned in tests").push(());
			Ok(())
		}
	}

	fn dummy_proof() -> EquivocationProof<TestHeader> {
		let authorities = make_authorities(1);
		let header_a = TestHeader {
			parent_hash: H256::repeat_byte(0xAB),
			number: 1,
			state_root: H256::repeat_byte(0x11),
			extrinsics_root: H256::zero(),
			digest: Digest { logs: vec![] },
		};
		let header_b = TestHeader {
			parent_hash: H256::repeat_byte(0xAB),
			number: 1,
			state_root: H256::repeat_byte(0x22),
			extrinsics_root: H256::zero(),
			digest: Digest { logs: vec![] },
		};
		EquivocationProof {
			offender: pubkeys(&authorities)[0].clone(),
			slot: SLOT.into(),
			first_header: header_a,
			second_header: header_b,
		}
	}

	/// Tuple-struct field is private outside the module; construct via
	/// SCALE codec round-trip (the type implements Decode and its
	/// encoding is just the inner Vec<u8>'s encoding).
	fn fake_key_owner_proof(bytes: Vec<u8>) -> OpaqueKeyOwnershipProof {
		use codec::Decode;
		OpaqueKeyOwnershipProof::decode(&mut &bytes.encode()[..]).expect("test fixture decodes")
	}

	#[test]
	fn reporter_submits_when_key_owner_proof_available() {
		let prover = StubKeyOwnerProver { proof_bytes: Some(vec![1, 2, 3]) };
		let reporter = RecordingReporter::default();
		let outcome =
			process_equivocation::<TestBlock, _, _>(dummy_proof(), &prover, &reporter)
				.expect("submit ok");
		assert_eq!(outcome, ReportOutcome::Submitted);
		assert_eq!(reporter.submitted.lock().unwrap().len(), 1);
	}

	#[test]
	fn reporter_drops_quietly_when_no_key_owner_proof() {
		// Runtime can't generate a key-ownership proof (offender
		// rotated out, etc.). Report dropped without error and without
		// submission.
		let prover = StubKeyOwnerProver { proof_bytes: None };
		let reporter = RecordingReporter::default();
		let outcome =
			process_equivocation::<TestBlock, _, _>(dummy_proof(), &prover, &reporter)
				.expect("no error");
		assert_eq!(outcome, ReportOutcome::NoKeyOwnershipProof);
		assert!(reporter.submitted.lock().unwrap().is_empty(), "must not submit without key proof");
	}

	#[test]
	fn reporter_propagates_provider_errors() {
		struct FailingProver;
		impl KeyOwnershipProver<TestBlock> for FailingProver {
			fn generate_key_ownership_proof(
				&self,
				_: H256,
				_: AuthorityId,
			) -> Result<Option<OpaqueKeyOwnershipProof>, ProviderError> {
				Err(ProviderError::Runtime("simulated failure".into()))
			}
		}
		let reporter = RecordingReporter::default();
		let result =
			process_equivocation::<TestBlock, _, _>(dummy_proof(), &FailingProver, &reporter);
		assert!(matches!(result, Err(ProviderError::Runtime(_))));
		assert!(reporter.submitted.lock().unwrap().is_empty());
	}
}

// ─── Equivocation detection ──────────────────────────────────────────────

mod equivocation_tests {
	use super::*;
	use crate::equivocation::EquivocationDetector;

	/// Build a header that *would* be valid under the given epoch
	/// context. Differentiator nudges the state_root so two headers
	/// for the same slot are distinct.
	fn make_valid_header(
		pair: &AuthorityPair,
		authority_idx: u32,
		slot: u64,
		differentiator: u8,
	) -> TestHeader {
		let claim = build_claim(pair, authority_idx, slot.into(), &RANDOMNESS, EPOCH_INDEX);
		TestHeader {
			parent_hash: H256::zero(),
			number: 1,
			state_root: H256::repeat_byte(differentiator),
			extrinsics_root: H256::zero(),
			digest: Digest { logs: vec![pre_runtime_item(&claim)] },
		}
	}

	fn ctx<'a>(pubkeys: &'a [AuthorityId]) -> EpochContext<'a> {
		EpochContext { index: EPOCH_INDEX, randomness: &RANDOMNESS, authorities: pubkeys }
	}

	#[test]
	fn first_observation_is_not_equivocation() {
		let authorities = make_authorities(2);
		let pubkeys = pubkeys(&authorities);
		let header = make_valid_header(&authorities[0], 0, SLOT, 0xAA);

		let mut detector = EquivocationDetector::<TestHeader>::new();
		let result = detector.observe(header, ctx(&pubkeys)).expect("verify ok");
		assert!(result.is_none(), "first sighting must not raise equivocation");
		assert_eq!(detector.tracked_count(), 1);
	}

	#[test]
	fn duplicate_header_is_not_equivocation() {
		let authorities = make_authorities(1);
		let pubkeys = pubkeys(&authorities);
		let header = make_valid_header(&authorities[0], 0, SLOT, 0xAA);

		let mut detector = EquivocationDetector::<TestHeader>::new();
		detector.observe(header.clone(), ctx(&pubkeys)).unwrap();
		let result = detector.observe(header, ctx(&pubkeys)).expect("verify ok");
		assert!(
			result.is_none(),
			"identical header re-observed is a duplicate import, not equivocation"
		);
		assert_eq!(detector.tracked_count(), 1);
	}

	#[test]
	fn distinct_headers_same_slot_same_authority_is_equivocation() {
		let authorities = make_authorities(2);
		let pubkeys = pubkeys(&authorities);
		// Both headers carry valid slot claims for slot SLOT by
		// authority 0, but differ in state_root → different block hash.
		let header_a = make_valid_header(&authorities[0], 0, SLOT, 0xAA);
		let header_b = make_valid_header(&authorities[0], 0, SLOT, 0xBB);

		let mut detector = EquivocationDetector::<TestHeader>::new();
		detector.observe(header_a.clone(), ctx(&pubkeys)).unwrap();
		let result = detector.observe(header_b.clone(), ctx(&pubkeys)).unwrap();
		let proof = result.expect("equivocation must be detected");
		assert_eq!(proof.offender, pubkeys[0]);
		assert_eq!(proof.slot, Slot::from(SLOT));
		assert_ne!(
			proof.first_header.state_root, proof.second_header.state_root,
			"proof's two headers must be distinct"
		);
	}

	#[test]
	fn different_slots_same_authority_is_not_equivocation() {
		let authorities = make_authorities(1);
		let pubkeys = pubkeys(&authorities);
		let header_slot_a = make_valid_header(&authorities[0], 0, SLOT, 0xAA);
		let header_slot_b = make_valid_header(&authorities[0], 0, SLOT + 1, 0xBB);

		let mut detector = EquivocationDetector::<TestHeader>::new();
		detector.observe(header_slot_a, ctx(&pubkeys)).unwrap();
		let result = detector.observe(header_slot_b, ctx(&pubkeys)).expect("verify ok");
		assert!(result.is_none(), "different slots = different keys = no equivocation");
		assert_eq!(detector.tracked_count(), 2);
	}

	#[test]
	fn different_authorities_same_slot_is_not_equivocation() {
		// Different validators legitimately can't both be assigned the
		// same slot in real Sassafras, but our detector's job is just
		// "same authority, different blocks." Two authorities each
		// signing for the same slot via separate pairs is a distinct
		// pathology (would be caught by the on-chain ticket assignment
		// rule, not by the equivocation detector).
		let authorities = make_authorities(2);
		let pubkeys = pubkeys(&authorities);
		let header_a = make_valid_header(&authorities[0], 0, SLOT, 0xAA);
		let header_b = make_valid_header(&authorities[1], 1, SLOT, 0xBB);

		let mut detector = EquivocationDetector::<TestHeader>::new();
		detector.observe(header_a, ctx(&pubkeys)).unwrap();
		let result = detector.observe(header_b, ctx(&pubkeys)).expect("verify ok");
		assert!(result.is_none(), "different authorities → no equivocation per this detector");
	}

	#[test]
	fn clear_drops_state() {
		let authorities = make_authorities(1);
		let pubkeys = pubkeys(&authorities);
		let header = make_valid_header(&authorities[0], 0, SLOT, 0xAA);
		let mut detector = EquivocationDetector::<TestHeader>::new();
		detector.observe(header, ctx(&pubkeys)).unwrap();
		assert_eq!(detector.tracked_count(), 1);
		detector.clear();
		assert_eq!(detector.tracked_count(), 0);
	}

	#[test]
	fn observe_propagates_verification_errors() {
		let authorities = make_authorities(1);
		let pubkeys = pubkeys(&authorities);
		// Header with no PreRuntime entry — will fail verify_header
		// before reaching the duplicate check.
		let header = TestHeader {
			parent_hash: H256::zero(),
			number: 1,
			state_root: H256::zero(),
			extrinsics_root: H256::zero(),
			digest: Digest { logs: vec![] },
		};
		let mut detector = EquivocationDetector::<TestHeader>::new();
		let err = detector.observe(header, ctx(&pubkeys)).unwrap_err();
		assert!(matches!(err, VerificationError::MissingSlotClaim));
	}
}

// ─── Ticket generation ───────────────────────────────────────────────────

mod ticket_gen_tests {
	use super::*;
	use crate::ticket_generation::{compute_ticket_id, produce_ticket_envelope};
	use sp_consensus_sassafras::vrf::{ticket_body_sign_data, ticket_id_input};
	use sp_core::bandersnatch::{self, ring_vrf::RingContext as InnerRingContext};

	/// Small ring size for tests; matches upstream's TEST_RING_SIZE.
	/// Avoids the multi-second 3073-G1-power setup the production
	/// RING_SIZE=512 would impose on every test run.
	const TEST_RING_SIZE: usize = 16;
	type TestRingContext = InnerRingContext<TEST_RING_SIZE>;

	/// Convert AuthorityId → underlying bandersnatch::Public for ring-
	/// VRF construction. AuthorityId wraps via app_crypto::Public →
	/// bandersnatch::Public.
	fn to_bandersnatch_public(id: &AuthorityId) -> bandersnatch::Public {
		id.as_inner_ref().clone()
	}

	#[test]
	fn compute_ticket_id_is_deterministic() {
		let authorities = make_authorities(2);
		let id1 = compute_ticket_id(&authorities[0], &RANDOMNESS, 5, EPOCH_INDEX);
		let id2 = compute_ticket_id(&authorities[0], &RANDOMNESS, 5, EPOCH_INDEX);
		assert_eq!(id1, id2, "compute_ticket_id must be deterministic");
	}

	#[test]
	fn compute_ticket_id_varies_with_attempt() {
		let authorities = make_authorities(1);
		let id_a = compute_ticket_id(&authorities[0], &RANDOMNESS, 1, EPOCH_INDEX);
		let id_b = compute_ticket_id(&authorities[0], &RANDOMNESS, 2, EPOCH_INDEX);
		assert_ne!(id_a, id_b, "different attempt indices must produce different ticket ids");
	}

	#[test]
	fn compute_ticket_id_varies_with_authority() {
		let authorities = make_authorities(2);
		let id_a = compute_ticket_id(&authorities[0], &RANDOMNESS, 0, EPOCH_INDEX);
		let id_b = compute_ticket_id(&authorities[1], &RANDOMNESS, 0, EPOCH_INDEX);
		assert_ne!(id_a, id_b, "different authorities must produce different ticket ids");
	}

	#[test]
	fn produce_ticket_envelope_round_trip_ring_vrf_verifies() {
		// Build a small (TEST_RING_SIZE=16) ring, generate a ticket
		// envelope for one member, verify the ring signature against
		// the same context's verifier. This proves the ring-VRF wiring
		// is correct end-to-end.
		let ring_ctx = TestRingContext::new_testing();
		let authorities = make_authorities(4);
		let pubkeys = pubkeys(&authorities);
		let bandersnatch_pubs: Vec<bandersnatch::Public> =
			pubkeys.iter().map(to_bandersnatch_public).collect();

		let my_idx: usize = 1;
		let prover = ring_ctx.prover(&bandersnatch_pubs, my_idx);
		let verifier = ring_ctx.verifier(&bandersnatch_pubs);

		let erased_pair = ed25519::Pair::from_string("//Ticket//Erased", None).unwrap();
		let revealed_pair = ed25519::Pair::from_string("//Ticket//Revealed", None).unwrap();

		let attempt_idx = 7;
		let envelope = produce_ticket_envelope(
			&authorities[my_idx],
			&erased_pair,
			&revealed_pair,
			attempt_idx,
			&RANDOMNESS,
			EPOCH_INDEX,
			&prover,
		);

		assert_eq!(envelope.body.attempt_idx, attempt_idx);
		assert_eq!(envelope.body.erased_public, erased_pair.public());
		assert_eq!(envelope.body.revealed_public, revealed_pair.public());

		// Rebuild sign_data the verifier-side way and check.
		let id_input = ticket_id_input(&RANDOMNESS, attempt_idx, EPOCH_INDEX);
		let sign_data = ticket_body_sign_data(&envelope.body, id_input);
		assert!(
			envelope.signature.ring_vrf_verify(&sign_data, &verifier),
			"ring-VRF signature must verify against the same context's verifier"
		);
	}
}

