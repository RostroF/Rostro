// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Tests for `pallet-proof-verifier`.
//!
//! First-pass tests cover the wiring: register/deregister/verify dispatch,
//! event emission, error paths. Real Plonky3 cryptographic verification
//! lands in a follow-up commit; for now `verify_proof` is a smoke-test
//! that confirms the lookup-and-dispatch path works.

use crate::{mock::*, *};
use frame_support::{assert_noop, assert_ok, pallet_prelude::ConstU32, BoundedVec};
use frame_system::RawOrigin;
use sp_runtime::traits::Hash;

fn make_key(byte: u8, len: usize) -> BoundedVec<u8, ConstU32<MAX_VERIFYING_KEY_LEN>> {
	let v = vec![byte; len];
	BoundedVec::try_from(v).expect("fits in MAX_VERIFYING_KEY_LEN")
}

fn make_family(label: &[u8]) -> BoundedVec<u8, ConstU32<64>> {
	BoundedVec::try_from(label.to_vec()).expect("fits in 64 bytes")
}

#[test]
fn register_verifier_works() {
	new_test_ext().execute_with(|| {
		let key = make_key(0xAB, 256);
		let family = make_family(b"execution-proof-v1");

		assert_ok!(ProofVerifier::register_verifier(
			RawOrigin::Root.into(),
			key.clone(),
			family.clone(),
		));

		// One VerifierRegistered event emitted.
		let events = System::events();
		assert!(events.iter().any(|r| matches!(
			r.event,
			RuntimeEvent::ProofVerifier(Event::VerifierRegistered { .. })
		)));

		// Storage now holds the verifier.
		let key_hash: [u8; 32] = <Test as frame_system::Config>::Hashing::hash(&key)
			.as_ref()
			.try_into()
			.expect("hash is 32 bytes");
		let info = ProofVerifier::verifier(key_hash).expect("registered");
		assert_eq!(info.circuit_family, family);
	});
}

#[test]
fn register_verifier_rejects_non_root() {
	new_test_ext().execute_with(|| {
		let key = make_key(0xAB, 256);
		let family = make_family(b"execution-proof-v1");

		assert_noop!(
			ProofVerifier::register_verifier(
				RawOrigin::Signed(1).into(),
				key,
				family,
			),
			frame_support::error::BadOrigin
		);
	});
}

#[test]
fn register_verifier_rejects_duplicate() {
	new_test_ext().execute_with(|| {
		let key = make_key(0xAB, 256);
		let family = make_family(b"execution-proof-v1");

		assert_ok!(ProofVerifier::register_verifier(
			RawOrigin::Root.into(),
			key.clone(),
			family.clone(),
		));
		assert_noop!(
			ProofVerifier::register_verifier(
				RawOrigin::Root.into(),
				key,
				family,
			),
			Error::<Test>::VerifierAlreadyRegistered
		);
	});
}

#[test]
fn deregister_verifier_works() {
	new_test_ext().execute_with(|| {
		let key = make_key(0xCD, 256);
		let family = make_family(b"hip-check-validator");

		assert_ok!(ProofVerifier::register_verifier(
			RawOrigin::Root.into(),
			key.clone(),
			family,
		));

		let key_hash: [u8; 32] = <Test as frame_system::Config>::Hashing::hash(&key)
			.as_ref()
			.try_into()
			.expect("hash is 32 bytes");

		assert_ok!(ProofVerifier::deregister_verifier(
			RawOrigin::Root.into(),
			key_hash,
		));
		assert!(ProofVerifier::verifier(key_hash).is_none());
	});
}

#[test]
fn deregister_unknown_verifier_fails() {
	new_test_ext().execute_with(|| {
		let bogus_hash = [0xFF; 32];
		assert_noop!(
			ProofVerifier::deregister_verifier(
				RawOrigin::Root.into(),
				bogus_hash,
			),
			Error::<Test>::VerifierNotRegistered
		);
	});
}

#[test]
fn verify_proof_fails_closed_until_plonky3_lands() {
	// Behaviour intentionally changed 2026-05-04: the previous "wiring-
	// level" assertion that `verify_proof` returns `Ok(())` against a
	// registered verifier was a security gap (any downstream code that
	// trusted the dispatch result would be silently bypassable). Until
	// real Plonky3 verification lands, the extrinsic fails closed with
	// `VerifierNotImplemented` after passing input validation and storage
	// lookup. This test asserts the new contract.
	new_test_ext().execute_with(|| {
		let key = make_key(0xEF, 256);
		let family = make_family(b"checkpoint-v1");

		assert_ok!(ProofVerifier::register_verifier(
			RawOrigin::Root.into(),
			key.clone(),
			family,
		));

		let key_hash: [u8; 32] = <Test as frame_system::Config>::Hashing::hash(&key)
			.as_ref()
			.try_into()
			.expect("hash is 32 bytes");

		let proof: BoundedVec<u8, ConstU32<MAX_PROOF_LEN>> =
			BoundedVec::try_from(vec![0xAB; 4096]).expect("fits");
		let public_inputs: BoundedVec<u8, ConstU32<MAX_PUBLIC_INPUTS_LEN>> =
			BoundedVec::try_from(vec![0u8; 256]).expect("fits");

		assert_noop!(
			ProofVerifier::verify_proof(
				RawOrigin::Signed(1).into(),
				key_hash,
				proof,
				public_inputs,
			),
			Error::<Test>::VerifierNotImplemented,
		);
	});
}

#[test]
fn verify_proof_against_unregistered_key_fails() {
	new_test_ext().execute_with(|| {
		let bogus_hash = [0xFF; 32];
		let proof: BoundedVec<u8, ConstU32<MAX_PROOF_LEN>> =
			BoundedVec::try_from(vec![0u8; 1024]).expect("fits");
		let public_inputs: BoundedVec<u8, ConstU32<MAX_PUBLIC_INPUTS_LEN>> =
			BoundedVec::try_from(vec![0u8; 64]).expect("fits");

		assert_noop!(
			ProofVerifier::verify_proof(
				RawOrigin::Signed(1).into(),
				bogus_hash,
				proof,
				public_inputs,
			),
			Error::<Test>::VerifierNotRegistered
		);
	});
}

// ─── known-invalid sentinel rejection ───────────────────────────────────────
// Per `feedback_input_validation_at_handoffs.md`: types prove shape, not
// semantics. Each boundary gets explicit rejection of the specific bit
// patterns that satisfy the type but should never act as that role.

#[test]
fn register_rejects_empty_verifying_key() {
	new_test_ext().execute_with(|| {
		let empty: BoundedVec<u8, ConstU32<MAX_VERIFYING_KEY_LEN>> = BoundedVec::default();
		let family = make_family(b"execution-proof-v1");
		assert_noop!(
			ProofVerifier::register_verifier(RawOrigin::Root.into(), empty, family),
			Error::<Test>::EmptyVerifyingKey,
		);
	});
}

#[test]
fn register_rejects_zero_verifying_key() {
	new_test_ext().execute_with(|| {
		let zero_key = make_key(0u8, 256);
		let family = make_family(b"execution-proof-v1");
		assert_noop!(
			ProofVerifier::register_verifier(RawOrigin::Root.into(), zero_key, family),
			Error::<Test>::ZeroVerifyingKey,
		);
	});
}

#[test]
fn register_rejects_empty_circuit_family() {
	new_test_ext().execute_with(|| {
		let key = make_key(0xAB, 256);
		let empty_family: BoundedVec<u8, ConstU32<64>> = BoundedVec::default();
		assert_noop!(
			ProofVerifier::register_verifier(RawOrigin::Root.into(), key, empty_family),
			Error::<Test>::EmptyCircuitFamily,
		);
	});
}

#[test]
fn deregister_rejects_zero_key_hash() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			ProofVerifier::deregister_verifier(RawOrigin::Root.into(), [0u8; 32]),
			Error::<Test>::ZeroKeyHash,
		);
	});
}

#[test]
fn verify_rejects_zero_key_hash() {
	new_test_ext().execute_with(|| {
		let proof: BoundedVec<u8, ConstU32<MAX_PROOF_LEN>> =
			BoundedVec::try_from(vec![0xAB; 1024]).expect("fits");
		let public_inputs: BoundedVec<u8, ConstU32<MAX_PUBLIC_INPUTS_LEN>> = BoundedVec::default();
		assert_noop!(
			ProofVerifier::verify_proof(
				RawOrigin::Signed(1).into(),
				[0u8; 32],
				proof,
				public_inputs,
			),
			Error::<Test>::ZeroKeyHash,
		);
	});
}

#[test]
fn register_rejects_short_verifying_key() {
	new_test_ext().execute_with(|| {
		// 8 bytes: non-empty, non-zero, but below MIN_VERIFYING_KEY_LEN=16.
		let short = make_key(0xAB, 8);
		let family = make_family(b"execution-proof-v1");
		assert_noop!(
			ProofVerifier::register_verifier(RawOrigin::Root.into(), short, family),
			Error::<Test>::VerifyingKeyTooShort,
		);
	});
}

#[test]
fn register_rejects_short_circuit_family() {
	new_test_ext().execute_with(|| {
		let key = make_key(0xAB, 256);
		// 2 bytes: non-empty but below MIN_CIRCUIT_FAMILY_LEN=3.
		let short_family = make_family(b"v1");
		assert_noop!(
			ProofVerifier::register_verifier(RawOrigin::Root.into(), key, short_family),
			Error::<Test>::CircuitFamilyTooShort,
		);
	});
}

#[test]
fn verify_rejects_short_proof() {
	new_test_ext().execute_with(|| {
		let key = make_key(0xAB, 256);
		let family = make_family(b"execution-proof-v1");
		assert_ok!(ProofVerifier::register_verifier(
			RawOrigin::Root.into(),
			key.clone(),
			family,
		));
		let key_hash: [u8; 32] = <Test as frame_system::Config>::Hashing::hash(&key)
			.as_ref()
			.try_into()
			.expect("hash is 32 bytes");

		// 8 bytes of garbage: non-empty, but below MIN_PROOF_LEN=16.
		let short_proof: BoundedVec<u8, ConstU32<MAX_PROOF_LEN>> =
			BoundedVec::try_from(vec![0xAB; 8]).expect("fits");
		let public_inputs: BoundedVec<u8, ConstU32<MAX_PUBLIC_INPUTS_LEN>> = BoundedVec::default();
		assert_noop!(
			ProofVerifier::verify_proof(
				RawOrigin::Signed(1).into(),
				key_hash,
				short_proof,
				public_inputs,
			),
			Error::<Test>::ProofTooShort,
		);
	});
}

#[test]
fn verify_rejects_empty_proof() {
	new_test_ext().execute_with(|| {
		// First register a verifier so we get past the registration check.
		let key = make_key(0xAB, 256);
		let family = make_family(b"execution-proof-v1");
		assert_ok!(ProofVerifier::register_verifier(
			RawOrigin::Root.into(),
			key.clone(),
			family,
		));
		let key_hash: [u8; 32] = <Test as frame_system::Config>::Hashing::hash(&key)
			.as_ref()
			.try_into()
			.expect("hash is 32 bytes");

		let empty_proof: BoundedVec<u8, ConstU32<MAX_PROOF_LEN>> = BoundedVec::default();
		let public_inputs: BoundedVec<u8, ConstU32<MAX_PUBLIC_INPUTS_LEN>> = BoundedVec::default();
		assert_noop!(
			ProofVerifier::verify_proof(
				RawOrigin::Signed(1).into(),
				key_hash,
				empty_proof,
				public_inputs,
			),
			Error::<Test>::EmptyProof,
		);
	});
}
