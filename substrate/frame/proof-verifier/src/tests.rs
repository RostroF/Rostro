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
fn verify_proof_against_registered_key_succeeds_at_wiring_level() {
	// Wiring-level test only: real Plonky3 verification lands in a
	// follow-up commit. This test confirms storage lookup + dispatch +
	// event emission work correctly.
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
			BoundedVec::try_from(vec![0u8; 4096]).expect("fits");
		let public_inputs: BoundedVec<u8, ConstU32<MAX_PUBLIC_INPUTS_LEN>> =
			BoundedVec::try_from(vec![0u8; 256]).expect("fits");

		assert_ok!(ProofVerifier::verify_proof(
			RawOrigin::Signed(1).into(),
			key_hash,
			proof,
			public_inputs,
		));

		// ProofVerified event emitted.
		let events = System::events();
		assert!(events.iter().any(|r| matches!(
			r.event,
			RuntimeEvent::ProofVerifier(Event::ProofVerified { .. })
		)));
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
