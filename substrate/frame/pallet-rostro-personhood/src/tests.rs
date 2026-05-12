// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Mock-runtime unit tests for `pallet-rostro-personhood`.
//!
//! Strategy: every dependency the pallet has on a sibling
//! component (zkpki, Groth16 verifier) is abstracted behind a
//! trait, so tests stub them with controllable mocks. No
//! arkworks proof generation, no zkpki state, no real
//! cryptography — pure FRAME unit tests of the pallet's logic.
//! This is what keeps tests cheap (sub-second per case, no OOM
//! risk on the dev host).
//!
//! Coverage target: every distinct rejection path through
//! `mint_pop`, plus the discard / re-mint cycle, plus all SRT
//! extrinsics including the strict-monotonic vk version
//! enforcement.

use crate as pallet_personhood;
use crate::{
	ChainAnchor, CircuitId, LivenessPublicInputs, NullifierType, PassportPublicInputs, PopCert,
	ProofVerifier, VkRecord, ZkPkiError, ZkPkiInterface, AA_CHALLENGE_DOMAIN,
	HIP_CHALLENGE_DOMAIN,
};
use codec::Encode;
use frame_support::{
	assert_noop, assert_ok, derive_impl, parameter_types,
	traits::{ConstU16, ConstU32, ConstU64},
};
use sp_core::H256;
use sp_runtime::{
	traits::{BlakeTwo256, IdentityLookup},
	BuildStorage,
};
use std::cell::RefCell;
use zk_pki_primitives::hip::CanonicalHipProof;

type Block = frame_system::mocking::MockBlock<Test>;
type AccountId = u64;

frame_support::construct_runtime!(
	pub enum Test {
		System: frame_system,
		Personhood: pallet_personhood,
	}
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
	type Block = Block;
	type AccountId = AccountId;
	type Lookup = IdentityLookup<AccountId>;
	type AccountData = ();
	type Hashing = BlakeTwo256;
	type Hash = H256;
	type Nonce = u32;
}

parameter_types! {
	pub const TestMaxProofAge: u64 = 600;
	/// Mock TTL: enough that no test runs past the cert's expiry. The
	/// chain-side semantics of `FixedPopTtl` are exercised by checking
	/// `PopCert.ttl_block == minted_at + TestFixedPopTtl`.
	pub const TestFixedPopTtl: u64 = 100_000;
}

/// Test runtime allowlist. Camino-shape (Salted + SaltedMock) so both
/// production and mock variants can be exercised through `mint_pop`.
/// Tests that need to exercise mainnet-shape rejection of NonSalted
/// rely on this list NOT containing `NonSalted` / `NonSaltedMock`.
pub struct TestAcceptedNullifierTypes;
impl frame_support::traits::Get<&'static [NullifierType]> for TestAcceptedNullifierTypes {
	fn get() -> &'static [NullifierType] {
		&[NullifierType::Salted, NullifierType::SaltedMock]
	}
}

impl pallet_personhood::Config for Test {
	type MaxProofAge = TestMaxProofAge;
	type FixedPopTtl = TestFixedPopTtl;
	type ZkPki = MockZkPki;
	type ProofVerifier = MockProofVerifier;
	type SrtOrigin = frame_system::EnsureRoot<AccountId>;
	type AcceptedNullifierTypes = TestAcceptedNullifierTypes;
}

// ─── Mock ZkPki ──────────────────────────────────────────────────────────
//
// Tests configure cert ownership + HIP behaviour via a thread-local.
// `ZkPkiState::default()` rejects with `CertNotFound` so tests that
// don't configure it explicitly hit that path first.

#[derive(Clone)]
struct ZkPkiState {
	/// Thumbprint → expected owner. If the thumbprint is absent,
	/// the mock returns `CertNotFound`.
	cert_owners: std::collections::HashMap<H256, AccountId>,
	/// Thumbprints whose certs are currently in the "not Good"
	/// state (suspended / revoked).
	bad_certs: std::collections::HashSet<H256>,
	/// If true, HIP verification fails for any thumbprint.
	hip_should_fail: bool,
}

impl Default for ZkPkiState {
	fn default() -> Self {
		Self {
			cert_owners: Default::default(),
			bad_certs: Default::default(),
			hip_should_fail: false,
		}
	}
}

thread_local! {
	static ZKPKI_STATE: RefCell<ZkPkiState> = RefCell::new(ZkPkiState::default());
}

fn with_zkpki_state<F: FnOnce(&mut ZkPkiState)>(f: F) {
	ZKPKI_STATE.with(|s| f(&mut s.borrow_mut()));
}

pub struct MockZkPki;
impl ZkPkiInterface<AccountId, u64> for MockZkPki {
	fn verify_cert_and_hip(
		thumbprint: H256,
		account: &AccountId,
		_hip_proof: &CanonicalHipProof,
		_challenge_nonce: &[u8; 32],
	) -> Result<(), ZkPkiError> {
		ZKPKI_STATE.with(|s| {
			let s = s.borrow();
			match s.cert_owners.get(&thumbprint) {
				None => Err(ZkPkiError::CertNotFound),
				Some(owner) if owner != account => Err(ZkPkiError::CertNotOwned),
				Some(_) if s.bad_certs.contains(&thumbprint) => Err(ZkPkiError::CertNotGood),
				Some(_) if s.hip_should_fail => Err(ZkPkiError::HipFailed),
				Some(_) => Ok(()),
			}
		})
	}

	fn hip_attested_at(_hip_proof: &CanonicalHipProof) -> Option<u64> {
		None
	}
}

// ─── Mock ProofVerifier ──────────────────────────────────────────────────

#[derive(Clone, Default)]
struct ProofVerifierState {
	passport_should_pass: bool,
	liveness_should_pass: bool,
}

thread_local! {
	static PROOF_STATE: RefCell<ProofVerifierState> =
		RefCell::new(ProofVerifierState::default());
}

fn with_proof_state<F: FnOnce(&mut ProofVerifierState)>(f: F) {
	PROOF_STATE.with(|s| f(&mut s.borrow_mut()));
}

pub struct MockProofVerifier;
impl ProofVerifier<AccountId, u64> for MockProofVerifier {
	fn verify_passport_attest(
		_vk_bytes: &[u8],
		_proof_bytes: &[u8],
		_inputs: &PassportPublicInputs<AccountId, u64>,
		_aa_challenge: &[u8; 32],
		_sha256_digest_of_challenge: &[u8; 32],
	) -> Result<(), ()> {
		PROOF_STATE.with(|s| {
			if s.borrow().passport_should_pass {
				Ok(())
			} else {
				Err(())
			}
		})
	}

	fn verify_liveness_facematch(
		_vk_bytes: &[u8],
		_proof_bytes: &[u8],
		_inputs: &LivenessPublicInputs<AccountId, u64>,
	) -> Result<(), ()> {
		PROOF_STATE.with(|s| {
			if s.borrow().liveness_should_pass {
				Ok(())
			} else {
				Err(())
			}
		})
	}
}

// ─── Test ext + helpers ──────────────────────────────────────────────────

fn new_test_ext() -> sp_io::TestExternalities {
	// Reset thread-local mock state.
	with_zkpki_state(|s| *s = ZkPkiState::default());
	with_proof_state(|s| *s = ProofVerifierState::default());

	let storage = frame_system::GenesisConfig::<Test>::default()
		.build_storage()
		.unwrap();
	let mut ext: sp_io::TestExternalities = storage.into();
	// Move past genesis so System::block_hash returns a stable value
	// and BlockNumber > 0 for sensible chain-anchor checks.
	ext.execute_with(|| {
		System::set_block_number(100);
	});
	ext
}

const ALICE: AccountId = 1;
const BOB: AccountId = 2;
const CHARLIE: AccountId = 3;
const HW_CERT_THUMB_1: H256 = H256([0xAA; 32]);
const HW_CERT_THUMB_2: H256 = H256([0xBB; 32]);

/// Mock scoped_nullifiers for the two ALICE/BOB test passports.
const SCOPED_NULL_1: H256 = H256([0x11; 32]);
const SCOPED_NULL_2: H256 = H256([0x22; 32]);
/// Mock comm_in values — the salted-commitment chain anchors that
/// tie passport_attest to liveness_facematch. Different per passport.
const COMM_IN_1: H256 = H256([0x33; 32]);
const COMM_IN_2: H256 = H256([0x44; 32]);
/// Mock OPRF federation pubkey hash. Same value across all tests since
/// only one federation pubkey is current at any time.
const OPRF_PK_HASH: H256 = H256([0x77; 32]);
const CSCA_ROOT_GOOD: H256 = H256([0x55; 32]);
const SEATS_ROOT_GOOD: H256 = H256([0x66; 32]);

/// A minimal valid HIP placeholder. The mock ZkPki ignores the
/// inner value so any well-formed CanonicalHipProof works.
fn dummy_hip() -> CanonicalHipProof {
	use zk_pki_primitives::hip::StrongBoxHipProof;
	CanonicalHipProof::StrongBox(StrongBoxHipProof {
		cert_ec_public: [0u8; 65],
		attest_ec_public: [0u8; 65],
		cert_ec_chain: Default::default(),
		attest_ec_chain: Default::default(),
		hmac_binding_output: [0u8; 32],
		hmac_binding_signature: Default::default(),
		binding_proof_context: Default::default(),
		integrity_blob: Default::default(),
		integrity_signature: Default::default(),
		nonce: [0u8; 32],
	})
}

fn anchor() -> ChainAnchor<u64> {
	ChainAnchor {
		block: System::block_number(),
		hash: System::block_hash(System::block_number()),
	}
}

fn passport_inputs(
	caller: AccountId,
	scoped_nullifier: H256,
	comm_in: H256,
	csca_root: H256,
	seats_root: H256,
	anchor: ChainAnchor<u64>,
) -> PassportPublicInputs<AccountId, u64> {
	PassportPublicInputs {
		comm_in,
		scoped_nullifier,
		nullifier_type: NullifierType::Salted,
		oprf_pk_hash: OPRF_PK_HASH,
		bound_account: caller,
		adult: true,
		seat_id: 42,
		anchor,
		csca_root,
		seats_root,
	}
}

fn liveness_inputs(
	caller: AccountId,
	comm_in: H256,
	anchor: ChainAnchor<u64>,
) -> LivenessPublicInputs<AccountId, u64> {
	LivenessPublicInputs {
		comm_in,
		bound_account: caller,
		liveness_passed: true,
		anchor,
	}
}

fn seed_roots_and_vks() {
	pallet_personhood::CurrentCscaRoot::<Test>::put(CSCA_ROOT_GOOD);
	pallet_personhood::CurrentSeatsRoot::<Test>::put(SEATS_ROOT_GOOD);
	pallet_personhood::CurrentOprfFederationPubkeyHash::<Test>::put(OPRF_PK_HASH);
	pallet_personhood::PassportAttestVk::<Test>::put(VkRecord {
		bytes: vec![0x01, 0x02, 0x03],
		version: 1,
		set_at: 1,
		ceremony_hash: H256::zero(),
	});
	pallet_personhood::LivenessFacematchVk::<Test>::put(VkRecord {
		bytes: vec![0x04, 0x05, 0x06],
		version: 1,
		set_at: 1,
		ceremony_hash: H256::zero(),
	});
}

fn good_setup(caller: AccountId, thumb: H256) {
	seed_roots_and_vks();
	with_zkpki_state(|s| {
		s.cert_owners.insert(thumb, caller);
	});
	with_proof_state(|s| {
		s.passport_should_pass = true;
		s.liveness_should_pass = true;
	});
}

fn submit_mint(
	caller: AccountId,
	thumb: H256,
	pinputs: PassportPublicInputs<AccountId, u64>,
	linputs: LivenessPublicInputs<AccountId, u64>,
) -> sp_runtime::DispatchResult {
	Personhood::mint_pop(
		RuntimeOrigin::signed(caller),
		vec![0xAA; 32],
		pinputs,
		vec![0xBB; 32],
		linputs,
		thumb,
		dummy_hip(),
	)
}

// ─── Tests: happy path ───────────────────────────────────────────────────

#[test]
fn mint_pop_happy_path_works() {
	new_test_ext().execute_with(|| {
		good_setup(ALICE, HW_CERT_THUMB_1);
		let a = anchor();
		let pin = passport_inputs(ALICE, SCOPED_NULL_1, COMM_IN_1, CSCA_ROOT_GOOD, SEATS_ROOT_GOOD, a.clone());
		let lin = liveness_inputs(ALICE, COMM_IN_1, a);
		assert_ok!(submit_mint(ALICE, HW_CERT_THUMB_1, pin, lin));
		// Storage post-conditions
		assert!(pallet_personhood::PopCerts::<Test>::contains_key(ALICE));
		assert!(pallet_personhood::Nullifiers::<Test>::contains_key(SCOPED_NULL_1));
		let cert = pallet_personhood::PopCerts::<Test>::get(ALICE).unwrap();
		assert_eq!(cert.scoped_nullifier, SCOPED_NULL_1);
		assert_eq!(cert.nullifier_type, NullifierType::Salted);
		assert_eq!(cert.seat_id, 42);
		assert!(cert.adult);
		// Cert TTL is chain-assigned: minted_at + FixedPopTtl.
		assert_eq!(cert.ttl_block, cert.minted_at + 100_000);
	});
}

#[test]
fn two_accounts_can_mint_with_different_passports() {
	new_test_ext().execute_with(|| {
		seed_roots_and_vks();
		with_zkpki_state(|s| {
			s.cert_owners.insert(HW_CERT_THUMB_1, ALICE);
			s.cert_owners.insert(HW_CERT_THUMB_2, BOB);
		});
		with_proof_state(|s| {
			s.passport_should_pass = true;
			s.liveness_should_pass = true;
		});
		let a = anchor();
		assert_ok!(submit_mint(
			ALICE,
			HW_CERT_THUMB_1,
			passport_inputs(ALICE, SCOPED_NULL_1, COMM_IN_1, CSCA_ROOT_GOOD, SEATS_ROOT_GOOD, a.clone()),
			liveness_inputs(ALICE, COMM_IN_1, a.clone()),
		));
		assert_ok!(submit_mint(
			BOB,
			HW_CERT_THUMB_2,
			passport_inputs(BOB, SCOPED_NULL_2, COMM_IN_2, CSCA_ROOT_GOOD, SEATS_ROOT_GOOD, a.clone()),
			liveness_inputs(BOB, COMM_IN_2, a),
		));
	});
}

// ─── Tests: rejection paths in `mint_pop` (in check order) ───────────────

#[test]
fn mint_already_has_pop_cert_rejected() {
	new_test_ext().execute_with(|| {
		good_setup(ALICE, HW_CERT_THUMB_1);
		let a = anchor();
		let pin = passport_inputs(ALICE, SCOPED_NULL_1, COMM_IN_1, CSCA_ROOT_GOOD, SEATS_ROOT_GOOD, a.clone());
		let lin = liveness_inputs(ALICE, COMM_IN_1, a.clone());
		assert_ok!(submit_mint(ALICE, HW_CERT_THUMB_1, pin.clone(), lin.clone()));
		assert_noop!(
			submit_mint(ALICE, HW_CERT_THUMB_1, pin, lin),
			pallet_personhood::Error::<Test>::AlreadyHasPopCert
		);
	});
}

#[test]
fn mint_no_zkpki_cert_rejected() {
	new_test_ext().execute_with(|| {
		seed_roots_and_vks();
		// Don't insert any cert owners — mock returns CertNotFound.
		with_proof_state(|s| {
			s.passport_should_pass = true;
			s.liveness_should_pass = true;
		});
		let a = anchor();
		assert_noop!(
			submit_mint(
				ALICE,
				HW_CERT_THUMB_1,
				passport_inputs(ALICE, SCOPED_NULL_1, COMM_IN_1, CSCA_ROOT_GOOD, SEATS_ROOT_GOOD, a.clone()),
				liveness_inputs(ALICE, COMM_IN_1, a),
			),
			pallet_personhood::Error::<Test>::HwCertNotFound
		);
	});
}

#[test]
fn mint_zkpki_cert_not_owned_rejected() {
	new_test_ext().execute_with(|| {
		seed_roots_and_vks();
		// HW cert exists but is owned by BOB, not the caller ALICE.
		with_zkpki_state(|s| {
			s.cert_owners.insert(HW_CERT_THUMB_1, BOB);
		});
		with_proof_state(|s| {
			s.passport_should_pass = true;
			s.liveness_should_pass = true;
		});
		let a = anchor();
		assert_noop!(
			submit_mint(
				ALICE,
				HW_CERT_THUMB_1,
				passport_inputs(ALICE, SCOPED_NULL_1, COMM_IN_1, CSCA_ROOT_GOOD, SEATS_ROOT_GOOD, a.clone()),
				liveness_inputs(ALICE, COMM_IN_1, a),
			),
			pallet_personhood::Error::<Test>::HwCertNotOwned
		);
	});
}

#[test]
fn mint_zkpki_cert_not_good_rejected() {
	new_test_ext().execute_with(|| {
		good_setup(ALICE, HW_CERT_THUMB_1);
		with_zkpki_state(|s| {
			s.bad_certs.insert(HW_CERT_THUMB_1);
		});
		let a = anchor();
		assert_noop!(
			submit_mint(
				ALICE,
				HW_CERT_THUMB_1,
				passport_inputs(ALICE, SCOPED_NULL_1, COMM_IN_1, CSCA_ROOT_GOOD, SEATS_ROOT_GOOD, a.clone()),
				liveness_inputs(ALICE, COMM_IN_1, a),
			),
			pallet_personhood::Error::<Test>::HwCertNotGood
		);
	});
}

#[test]
fn mint_hip_failed_rejected() {
	new_test_ext().execute_with(|| {
		good_setup(ALICE, HW_CERT_THUMB_1);
		with_zkpki_state(|s| {
			s.hip_should_fail = true;
		});
		let a = anchor();
		assert_noop!(
			submit_mint(
				ALICE,
				HW_CERT_THUMB_1,
				passport_inputs(ALICE, SCOPED_NULL_1, COMM_IN_1, CSCA_ROOT_GOOD, SEATS_ROOT_GOOD, a.clone()),
				liveness_inputs(ALICE, COMM_IN_1, a),
			),
			pallet_personhood::Error::<Test>::HipFailed
		);
	});
}

#[test]
fn mint_proof_bound_to_other_account_rejected() {
	new_test_ext().execute_with(|| {
		good_setup(ALICE, HW_CERT_THUMB_1);
		let a = anchor();
		// Passport proof bound to BOB but submitted by ALICE.
		let pin = passport_inputs(BOB, SCOPED_NULL_1, COMM_IN_1, CSCA_ROOT_GOOD, SEATS_ROOT_GOOD, a.clone());
		let lin = liveness_inputs(ALICE, COMM_IN_1, a);
		assert_noop!(
			submit_mint(ALICE, HW_CERT_THUMB_1, pin, lin),
			pallet_personhood::Error::<Test>::ProofBoundToOther
		);
	});
}

#[test]
fn mint_dg2_hash_mismatch_rejected() {
	new_test_ext().execute_with(|| {
		good_setup(ALICE, HW_CERT_THUMB_1);
		let a = anchor();
		let pin = passport_inputs(ALICE, SCOPED_NULL_1, COMM_IN_1, CSCA_ROOT_GOOD, SEATS_ROOT_GOOD, a.clone());
		// Liveness uses different DG2.
		let lin = liveness_inputs(ALICE, COMM_IN_2, a);
		assert_noop!(
			submit_mint(ALICE, HW_CERT_THUMB_1, pin, lin),
			pallet_personhood::Error::<Test>::ProofMismatch
		);
	});
}

#[test]
fn mint_anchor_mismatch_between_proofs_rejected() {
	new_test_ext().execute_with(|| {
		good_setup(ALICE, HW_CERT_THUMB_1);
		let a = anchor();
		let pin = passport_inputs(ALICE, SCOPED_NULL_1, COMM_IN_1, CSCA_ROOT_GOOD, SEATS_ROOT_GOOD, a);
		// Liveness anchored to a different block.
		let lin = liveness_inputs(
			ALICE,
			COMM_IN_1,
			ChainAnchor { block: 50, hash: System::block_hash(50) },
		);
		assert_noop!(
			submit_mint(ALICE, HW_CERT_THUMB_1, pin, lin),
			pallet_personhood::Error::<Test>::ProofMismatch
		);
	});
}

#[test]
fn mint_liveness_failed_rejected() {
	new_test_ext().execute_with(|| {
		good_setup(ALICE, HW_CERT_THUMB_1);
		let a = anchor();
		let pin = passport_inputs(ALICE, SCOPED_NULL_1, COMM_IN_1, CSCA_ROOT_GOOD, SEATS_ROOT_GOOD, a.clone());
		let mut lin = liveness_inputs(ALICE, COMM_IN_1, a);
		lin.liveness_passed = false;
		assert_noop!(
			submit_mint(ALICE, HW_CERT_THUMB_1, pin, lin),
			pallet_personhood::Error::<Test>::LivenessFailed
		);
	});
}

#[test]
fn mint_proof_too_old_rejected() {
	new_test_ext().execute_with(|| {
		good_setup(ALICE, HW_CERT_THUMB_1);
		// Move chain forward so the witnessed anchor is older
		// than MaxProofAge.
		System::set_block_number(2_000);
		let stale_anchor = ChainAnchor { block: 50, hash: System::block_hash(50) };
		let pin = passport_inputs(
			ALICE,
			SCOPED_NULL_1,
			COMM_IN_1,
			CSCA_ROOT_GOOD,
			SEATS_ROOT_GOOD,
			stale_anchor.clone(),
		);
		let lin = liveness_inputs(ALICE, COMM_IN_1, stale_anchor);
		assert_noop!(
			submit_mint(ALICE, HW_CERT_THUMB_1, pin, lin),
			pallet_personhood::Error::<Test>::ProofTooOld
		);
	});
}

#[test]
fn mint_anchor_hash_mismatch_rejected() {
	new_test_ext().execute_with(|| {
		good_setup(ALICE, HW_CERT_THUMB_1);
		let bad_anchor = ChainAnchor { block: System::block_number(), hash: H256([0xFF; 32]) };
		let pin = passport_inputs(
			ALICE,
			SCOPED_NULL_1,
			COMM_IN_1,
			CSCA_ROOT_GOOD,
			SEATS_ROOT_GOOD,
			bad_anchor.clone(),
		);
		let lin = liveness_inputs(ALICE, COMM_IN_1, bad_anchor);
		assert_noop!(
			submit_mint(ALICE, HW_CERT_THUMB_1, pin, lin),
			pallet_personhood::Error::<Test>::AnchorMismatch
		);
	});
}

#[test]
fn mint_csca_root_rotated_rejected() {
	new_test_ext().execute_with(|| {
		good_setup(ALICE, HW_CERT_THUMB_1);
		let a = anchor();
		let stale_csca = H256([0x99; 32]);
		let pin = passport_inputs(ALICE, SCOPED_NULL_1, COMM_IN_1, stale_csca, SEATS_ROOT_GOOD, a.clone());
		let lin = liveness_inputs(ALICE, COMM_IN_1, a);
		assert_noop!(
			submit_mint(ALICE, HW_CERT_THUMB_1, pin, lin),
			pallet_personhood::Error::<Test>::CscaRootRotated
		);
	});
}

#[test]
fn mint_seats_root_rotated_rejected() {
	new_test_ext().execute_with(|| {
		good_setup(ALICE, HW_CERT_THUMB_1);
		let a = anchor();
		let stale_seats = H256([0x88; 32]);
		let pin = passport_inputs(ALICE, SCOPED_NULL_1, COMM_IN_1, CSCA_ROOT_GOOD, stale_seats, a.clone());
		let lin = liveness_inputs(ALICE, COMM_IN_1, a);
		assert_noop!(
			submit_mint(ALICE, HW_CERT_THUMB_1, pin, lin),
			pallet_personhood::Error::<Test>::SeatsRootRotated
		);
	});
}

#[test]
fn mint_nullifier_type_nonsalted_rejected() {
	// Mainnet-shape policy reject: a proof committing to a government-
	// recomputable nullifier (NonSalted) is rejected even on a testnet
	// runtime whose AcceptedNullifierTypes is the broader [Salted,
	// SaltedMock]. NonSalted is not in any accept-list this codebase
	// will ship.
	new_test_ext().execute_with(|| {
		good_setup(ALICE, HW_CERT_THUMB_1);
		let a = anchor();
		let mut pin = passport_inputs(
			ALICE, SCOPED_NULL_1, COMM_IN_1, CSCA_ROOT_GOOD, SEATS_ROOT_GOOD, a.clone(),
		);
		pin.nullifier_type = NullifierType::NonSalted;
		let lin = liveness_inputs(ALICE, COMM_IN_1, a);
		assert_noop!(
			submit_mint(ALICE, HW_CERT_THUMB_1, pin, lin),
			pallet_personhood::Error::<Test>::NullifierTypeRejected
		);
	});
}

#[test]
fn mint_nullifier_type_nonsalted_mock_rejected() {
	new_test_ext().execute_with(|| {
		good_setup(ALICE, HW_CERT_THUMB_1);
		let a = anchor();
		let mut pin = passport_inputs(
			ALICE, SCOPED_NULL_1, COMM_IN_1, CSCA_ROOT_GOOD, SEATS_ROOT_GOOD, a.clone(),
		);
		pin.nullifier_type = NullifierType::NonSaltedMock;
		let lin = liveness_inputs(ALICE, COMM_IN_1, a);
		assert_noop!(
			submit_mint(ALICE, HW_CERT_THUMB_1, pin, lin),
			pallet_personhood::Error::<Test>::NullifierTypeRejected
		);
	});
}

#[test]
fn mint_nullifier_type_salted_mock_accepted_on_testnet_shape() {
	// The test runtime's AcceptedNullifierTypes includes SaltedMock
	// (Camino-shape). Confirm it mints, with the SaltedMock variant
	// preserved in the stored cert so downstream queries can
	// distinguish devnet certs.
	new_test_ext().execute_with(|| {
		good_setup(ALICE, HW_CERT_THUMB_1);
		let a = anchor();
		let mut pin = passport_inputs(
			ALICE, SCOPED_NULL_1, COMM_IN_1, CSCA_ROOT_GOOD, SEATS_ROOT_GOOD, a.clone(),
		);
		pin.nullifier_type = NullifierType::SaltedMock;
		let lin = liveness_inputs(ALICE, COMM_IN_1, a);
		assert_ok!(submit_mint(ALICE, HW_CERT_THUMB_1, pin, lin));
		assert_eq!(
			pallet_personhood::PopCerts::<Test>::get(ALICE).unwrap().nullifier_type,
			NullifierType::SaltedMock,
		);
	});
}

#[test]
fn mint_oprf_pk_hash_rotated_rejected() {
	new_test_ext().execute_with(|| {
		good_setup(ALICE, HW_CERT_THUMB_1);
		// Simulate K-era rotation: chain now expects a different
		// federation pubkey hash than the one the proof committed to.
		let rotated = H256([0xCC; 32]);
		pallet_personhood::CurrentOprfFederationPubkeyHash::<Test>::put(rotated);
		let a = anchor();
		// passport_inputs() commits to the pre-rotation OPRF_PK_HASH.
		let pin = passport_inputs(ALICE, SCOPED_NULL_1, COMM_IN_1, CSCA_ROOT_GOOD, SEATS_ROOT_GOOD, a.clone());
		let lin = liveness_inputs(ALICE, COMM_IN_1, a);
		assert_noop!(
			submit_mint(ALICE, HW_CERT_THUMB_1, pin, lin),
			pallet_personhood::Error::<Test>::OprfPubkeyHashRotated
		);
	});
}

// `mint_passport_expired_rejected` removed in the 2026-05-10 PI redesign:
// passport expiry is no longer carried as a PI (privacy: it's a quasi-
// identifier, low cardinality + correlated with date-of-birth). The chain
// uses a uniform `FixedPopTtl` per cert instead. The "PassportExpired"
// rejection path no longer exists; the cert TTL is chain-assigned and
// always equals minted_at + FixedPopTtl.

#[test]
fn mint_nullifier_consumed_rejected() {
	// One passport → one cert globally. Bob can't reuse Alice's
	// nullifier on his own SS58.
	new_test_ext().execute_with(|| {
		seed_roots_and_vks();
		with_zkpki_state(|s| {
			s.cert_owners.insert(HW_CERT_THUMB_1, ALICE);
			s.cert_owners.insert(HW_CERT_THUMB_2, BOB);
		});
		with_proof_state(|s| {
			s.passport_should_pass = true;
			s.liveness_should_pass = true;
		});
		let a = anchor();
		assert_ok!(submit_mint(
			ALICE,
			HW_CERT_THUMB_1,
			passport_inputs(ALICE, SCOPED_NULL_1, COMM_IN_1, CSCA_ROOT_GOOD, SEATS_ROOT_GOOD, a.clone()),
			liveness_inputs(ALICE, COMM_IN_1, a.clone()),
		));
		assert_noop!(
			submit_mint(
				BOB,
				HW_CERT_THUMB_2,
				// Same nullifier as Alice's mint = same passport.
				passport_inputs(BOB, SCOPED_NULL_1, COMM_IN_2, CSCA_ROOT_GOOD, SEATS_ROOT_GOOD, a.clone()),
				liveness_inputs(BOB, COMM_IN_2, a),
			),
			pallet_personhood::Error::<Test>::NullifierConsumed
		);
	});
}

#[test]
fn mint_passport_proof_invalid_rejected() {
	new_test_ext().execute_with(|| {
		good_setup(ALICE, HW_CERT_THUMB_1);
		with_proof_state(|s| s.passport_should_pass = false);
		let a = anchor();
		assert_noop!(
			submit_mint(
				ALICE,
				HW_CERT_THUMB_1,
				passport_inputs(ALICE, SCOPED_NULL_1, COMM_IN_1, CSCA_ROOT_GOOD, SEATS_ROOT_GOOD, a.clone()),
				liveness_inputs(ALICE, COMM_IN_1, a),
			),
			pallet_personhood::Error::<Test>::PassportProofInvalid
		);
	});
}

#[test]
fn mint_liveness_proof_invalid_rejected() {
	new_test_ext().execute_with(|| {
		good_setup(ALICE, HW_CERT_THUMB_1);
		with_proof_state(|s| s.liveness_should_pass = false);
		let a = anchor();
		assert_noop!(
			submit_mint(
				ALICE,
				HW_CERT_THUMB_1,
				passport_inputs(ALICE, SCOPED_NULL_1, COMM_IN_1, CSCA_ROOT_GOOD, SEATS_ROOT_GOOD, a.clone()),
				liveness_inputs(ALICE, COMM_IN_1, a),
			),
			pallet_personhood::Error::<Test>::LivenessProofInvalid
		);
	});
}

#[test]
fn mint_passport_vk_not_set_rejected() {
	new_test_ext().execute_with(|| {
		// Roots + OPRF hash set but vks not.
		pallet_personhood::CurrentCscaRoot::<Test>::put(CSCA_ROOT_GOOD);
		pallet_personhood::CurrentSeatsRoot::<Test>::put(SEATS_ROOT_GOOD);
		pallet_personhood::CurrentOprfFederationPubkeyHash::<Test>::put(OPRF_PK_HASH);
		with_zkpki_state(|s| {
			s.cert_owners.insert(HW_CERT_THUMB_1, ALICE);
		});
		with_proof_state(|s| {
			s.passport_should_pass = true;
			s.liveness_should_pass = true;
		});
		let a = anchor();
		assert_noop!(
			submit_mint(
				ALICE,
				HW_CERT_THUMB_1,
				passport_inputs(ALICE, SCOPED_NULL_1, COMM_IN_1, CSCA_ROOT_GOOD, SEATS_ROOT_GOOD, a.clone()),
				liveness_inputs(ALICE, COMM_IN_1, a),
			),
			pallet_personhood::Error::<Test>::PassportVkNotSet
		);
	});
}

#[test]
fn mint_liveness_vk_not_set_rejected() {
	new_test_ext().execute_with(|| {
		pallet_personhood::CurrentCscaRoot::<Test>::put(CSCA_ROOT_GOOD);
		pallet_personhood::CurrentSeatsRoot::<Test>::put(SEATS_ROOT_GOOD);
		pallet_personhood::CurrentOprfFederationPubkeyHash::<Test>::put(OPRF_PK_HASH);
		pallet_personhood::PassportAttestVk::<Test>::put(VkRecord {
			bytes: vec![0x01],
			version: 1,
			set_at: 1,
			ceremony_hash: H256::zero(),
		});
		with_zkpki_state(|s| {
			s.cert_owners.insert(HW_CERT_THUMB_1, ALICE);
		});
		with_proof_state(|s| {
			s.passport_should_pass = true;
			s.liveness_should_pass = true;
		});
		let a = anchor();
		assert_noop!(
			submit_mint(
				ALICE,
				HW_CERT_THUMB_1,
				passport_inputs(ALICE, SCOPED_NULL_1, COMM_IN_1, CSCA_ROOT_GOOD, SEATS_ROOT_GOOD, a.clone()),
				liveness_inputs(ALICE, COMM_IN_1, a),
			),
			pallet_personhood::Error::<Test>::LivenessVkNotSet
		);
	});
}

// ─── Tests: discard + re-mint cycle ──────────────────────────────────────

#[test]
fn discard_pop_works() {
	new_test_ext().execute_with(|| {
		good_setup(ALICE, HW_CERT_THUMB_1);
		let a = anchor();
		assert_ok!(submit_mint(
			ALICE,
			HW_CERT_THUMB_1,
			passport_inputs(ALICE, SCOPED_NULL_1, COMM_IN_1, CSCA_ROOT_GOOD, SEATS_ROOT_GOOD, a.clone()),
			liveness_inputs(ALICE, COMM_IN_1, a),
		));
		assert_ok!(Personhood::discard_pop(RuntimeOrigin::signed(ALICE)));
		assert!(!pallet_personhood::PopCerts::<Test>::contains_key(ALICE));
		assert!(!pallet_personhood::Nullifiers::<Test>::contains_key(SCOPED_NULL_1));
	});
}

#[test]
fn discard_pop_no_cert_rejected() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			Personhood::discard_pop(RuntimeOrigin::signed(ALICE)),
			pallet_personhood::Error::<Test>::AlreadyHasPopCert // shape: "no cert to discard"
		);
	});
}

#[test]
fn remint_after_discard_works() {
	// Alice mints, discards, then mints again with the same passport
	// nullifier — succeeds because discard freed the nullifier.
	new_test_ext().execute_with(|| {
		good_setup(ALICE, HW_CERT_THUMB_1);
		let a = anchor();
		let pin = passport_inputs(ALICE, SCOPED_NULL_1, COMM_IN_1, CSCA_ROOT_GOOD, SEATS_ROOT_GOOD, a.clone());
		let lin = liveness_inputs(ALICE, COMM_IN_1, a);
		assert_ok!(submit_mint(ALICE, HW_CERT_THUMB_1, pin.clone(), lin.clone()));
		assert_ok!(Personhood::discard_pop(RuntimeOrigin::signed(ALICE)));
		assert_ok!(submit_mint(ALICE, HW_CERT_THUMB_1, pin, lin));
	});
}

#[test]
fn discard_then_other_account_can_use_same_passport() {
	// Alice mints with passport X, discards. Bob has different
	// SS58 + different HW cert; can mint with same passport (e.g.,
	// Alice's husband restored Alice's seed phrase to a new
	// account is not the model — but the chain-side behaviour is:
	// once nullifier is free, any account can mint with that
	// passport). This documents that.
	new_test_ext().execute_with(|| {
		seed_roots_and_vks();
		with_zkpki_state(|s| {
			s.cert_owners.insert(HW_CERT_THUMB_1, ALICE);
			s.cert_owners.insert(HW_CERT_THUMB_2, BOB);
		});
		with_proof_state(|s| {
			s.passport_should_pass = true;
			s.liveness_should_pass = true;
		});
		let a = anchor();
		assert_ok!(submit_mint(
			ALICE,
			HW_CERT_THUMB_1,
			passport_inputs(ALICE, SCOPED_NULL_1, COMM_IN_1, CSCA_ROOT_GOOD, SEATS_ROOT_GOOD, a.clone()),
			liveness_inputs(ALICE, COMM_IN_1, a.clone()),
		));
		assert_ok!(Personhood::discard_pop(RuntimeOrigin::signed(ALICE)));
		assert_ok!(submit_mint(
			BOB,
			HW_CERT_THUMB_2,
			passport_inputs(BOB, SCOPED_NULL_1, COMM_IN_1, CSCA_ROOT_GOOD, SEATS_ROOT_GOOD, a.clone()),
			liveness_inputs(BOB, COMM_IN_1, a),
		));
	});
}

// ─── Tests: SRT extrinsics ───────────────────────────────────────────────

#[test]
fn srt_set_csca_root_works() {
	new_test_ext().execute_with(|| {
		let new = H256([0xCC; 32]);
		assert_ok!(Personhood::srt_set_csca_root(RuntimeOrigin::root(), new));
		assert_eq!(pallet_personhood::CurrentCscaRoot::<Test>::get(), Some(new));
	});
}

#[test]
fn srt_set_csca_root_rejects_non_root() {
	new_test_ext().execute_with(|| {
		let new = H256([0xCC; 32]);
		assert!(Personhood::srt_set_csca_root(RuntimeOrigin::signed(ALICE), new).is_err());
	});
}

#[test]
fn srt_set_seats_root_works() {
	new_test_ext().execute_with(|| {
		let new = H256([0xDD; 32]);
		assert_ok!(Personhood::srt_set_seats_root(RuntimeOrigin::root(), new));
		assert_eq!(pallet_personhood::CurrentSeatsRoot::<Test>::get(), Some(new));
	});
}

#[test]
fn srt_set_oprf_federation_pubkey_hash_works() {
	new_test_ext().execute_with(|| {
		let new = H256([0xEE; 32]);
		assert_ok!(Personhood::srt_set_oprf_federation_pubkey_hash(RuntimeOrigin::root(), new));
		assert_eq!(
			pallet_personhood::CurrentOprfFederationPubkeyHash::<Test>::get(),
			Some(new),
		);
	});
}

#[test]
fn srt_set_oprf_federation_pubkey_hash_rejects_non_root() {
	new_test_ext().execute_with(|| {
		let new = H256([0xEE; 32]);
		assert!(
			Personhood::srt_set_oprf_federation_pubkey_hash(RuntimeOrigin::signed(ALICE), new)
				.is_err()
		);
	});
}

// ─── Tests: pre-publication bootstrap state ──────────────────────────────
//
// Mirror what a fresh chain looks like before SRT has published any
// of the three load-bearing values (CSCA root, seats root, vks).

#[test]
fn mint_csca_root_not_set_rejected() {
	// Roots empty (nothing seeded), but vks present — isolates the
	// CscaRootNotSet path from the LivenessVkNotSet / PassportVkNotSet
	// paths that fire later.
	new_test_ext().execute_with(|| {
		pallet_personhood::PassportAttestVk::<Test>::put(VkRecord {
			bytes: vec![0x01],
			version: 1,
			set_at: 1,
			ceremony_hash: H256::zero(),
		});
		pallet_personhood::LivenessFacematchVk::<Test>::put(VkRecord {
			bytes: vec![0x02],
			version: 1,
			set_at: 1,
			ceremony_hash: H256::zero(),
		});
		with_zkpki_state(|s| {
			s.cert_owners.insert(HW_CERT_THUMB_1, ALICE);
		});
		with_proof_state(|s| {
			s.passport_should_pass = true;
			s.liveness_should_pass = true;
		});
		let a = anchor();
		assert_noop!(
			submit_mint(
				ALICE,
				HW_CERT_THUMB_1,
				passport_inputs(ALICE, SCOPED_NULL_1, COMM_IN_1, CSCA_ROOT_GOOD, SEATS_ROOT_GOOD, a.clone()),
				liveness_inputs(ALICE, COMM_IN_1, a),
			),
			pallet_personhood::Error::<Test>::CscaRootNotSet
		);
	});
}

#[test]
fn mint_seats_root_not_set_rejected() {
	new_test_ext().execute_with(|| {
		// CSCA root set, seats root not.
		pallet_personhood::CurrentCscaRoot::<Test>::put(CSCA_ROOT_GOOD);
		pallet_personhood::PassportAttestVk::<Test>::put(VkRecord {
			bytes: vec![0x01],
			version: 1,
			set_at: 1,
			ceremony_hash: H256::zero(),
		});
		pallet_personhood::LivenessFacematchVk::<Test>::put(VkRecord {
			bytes: vec![0x02],
			version: 1,
			set_at: 1,
			ceremony_hash: H256::zero(),
		});
		with_zkpki_state(|s| {
			s.cert_owners.insert(HW_CERT_THUMB_1, ALICE);
		});
		with_proof_state(|s| {
			s.passport_should_pass = true;
			s.liveness_should_pass = true;
		});
		let a = anchor();
		assert_noop!(
			submit_mint(
				ALICE,
				HW_CERT_THUMB_1,
				passport_inputs(ALICE, SCOPED_NULL_1, COMM_IN_1, CSCA_ROOT_GOOD, SEATS_ROOT_GOOD, a.clone()),
				liveness_inputs(ALICE, COMM_IN_1, a),
			),
			pallet_personhood::Error::<Test>::SeatsRootNotSet
		);
	});
}

#[test]
fn mint_oprf_pk_hash_not_set_rejected() {
	// CSCA root + seats root + vks set, OPRF pubkey hash not.
	// Isolates the OprfPubkeyHashNotSet path from the bootstrap
	// errors that fire earlier.
	new_test_ext().execute_with(|| {
		pallet_personhood::CurrentCscaRoot::<Test>::put(CSCA_ROOT_GOOD);
		pallet_personhood::CurrentSeatsRoot::<Test>::put(SEATS_ROOT_GOOD);
		pallet_personhood::PassportAttestVk::<Test>::put(VkRecord {
			bytes: vec![0x01],
			version: 1,
			set_at: 1,
			ceremony_hash: H256::zero(),
		});
		pallet_personhood::LivenessFacematchVk::<Test>::put(VkRecord {
			bytes: vec![0x02],
			version: 1,
			set_at: 1,
			ceremony_hash: H256::zero(),
		});
		with_zkpki_state(|s| {
			s.cert_owners.insert(HW_CERT_THUMB_1, ALICE);
		});
		with_proof_state(|s| {
			s.passport_should_pass = true;
			s.liveness_should_pass = true;
		});
		let a = anchor();
		assert_noop!(
			submit_mint(
				ALICE,
				HW_CERT_THUMB_1,
				passport_inputs(ALICE, SCOPED_NULL_1, COMM_IN_1, CSCA_ROOT_GOOD, SEATS_ROOT_GOOD, a.clone()),
				liveness_inputs(ALICE, COMM_IN_1, a),
			),
			pallet_personhood::Error::<Test>::OprfPubkeyHashNotSet
		);
	});
}

#[test]
fn srt_set_vk_strict_monotonic_enforced() {
	new_test_ext().execute_with(|| {
		// First publish: version 1 from nothing.
		assert_ok!(Personhood::srt_set_vk(
			RuntimeOrigin::root(),
			CircuitId::PassportAttest,
			vec![0x01],
			1,
			H256::zero(),
		));
		// Bumping to 2 ok.
		assert_ok!(Personhood::srt_set_vk(
			RuntimeOrigin::root(),
			CircuitId::PassportAttest,
			vec![0x02],
			2,
			H256::zero(),
		));
		// Skipping to 4 rejected.
		assert_noop!(
			Personhood::srt_set_vk(
				RuntimeOrigin::root(),
				CircuitId::PassportAttest,
				vec![0x03],
				4,
				H256::zero(),
			),
			pallet_personhood::Error::<Test>::VkVersionRegressed
		);
		// Going back to 2 rejected.
		assert_noop!(
			Personhood::srt_set_vk(
				RuntimeOrigin::root(),
				CircuitId::PassportAttest,
				vec![0x04],
				2,
				H256::zero(),
			),
			pallet_personhood::Error::<Test>::VkVersionRegressed
		);
	});
}

#[test]
fn srt_set_vk_per_circuit_isolated() {
	new_test_ext().execute_with(|| {
		// Bumping passport_attest doesn't bump liveness_facematch.
		assert_ok!(Personhood::srt_set_vk(
			RuntimeOrigin::root(),
			CircuitId::PassportAttest,
			vec![0x01],
			1,
			H256::zero(),
		));
		// liveness_facematch can still go from nothing to version 1.
		assert_ok!(Personhood::srt_set_vk(
			RuntimeOrigin::root(),
			CircuitId::LivenessFacematch,
			vec![0x01],
			1,
			H256::zero(),
		));
	});
}

// ─── Tests: domain-separator / sanity ────────────────────────────────────

#[test]
fn challenge_domains_are_stable() {
	// AA challenge and HIP nonce derivations both depend on these
	// constants. Changing either silently would invalidate every
	// in-the-wild proof against the corresponding subsystem — pin
	// both down so accidental edits show up in CI.
	//
	// They MUST also differ from each other so a leaked HIP attestation
	// cannot be replayed as an AA challenge or vice versa.
	assert_eq!(AA_CHALLENGE_DOMAIN, b"rostro-pop-aa-v1");
	assert_eq!(HIP_CHALLENGE_DOMAIN, b"rostro-pop-hip-v1");
	assert_ne!(AA_CHALLENGE_DOMAIN, HIP_CHALLENGE_DOMAIN);
}

#[test]
fn aa_challenge_and_hip_nonce_differ_on_same_inputs() {
	use crate::{aa_challenge, hip_challenge_nonce};
	let anchor = ChainAnchor { block: 100u64, hash: H256([0x42; 32]) };
	let bound: AccountId = 7;
	let aa = aa_challenge(&anchor, &bound);
	let hip = hip_challenge_nonce(&anchor, &bound);
	// Same anchor + same account → still distinct outputs because the
	// domain bytes differ. Without this, a leaked HIP attestation would
	// satisfy the AIR's AA-challenge PI binding.
	assert_ne!(aa, hip);
}

#[test]
fn pop_cert_round_trips_through_codec() {
	let cert = PopCert {
		scoped_nullifier: SCOPED_NULL_1,
		nullifier_type: NullifierType::Salted,
		ttl_block: 12345u64,
		adult: true,
		seat_id: 99,
		minted_at: 100u64,
	};
	let bytes = cert.encode();
	let decoded: PopCert<u64> = codec::Decode::decode(&mut &bytes[..]).unwrap();
	assert_eq!(decoded.scoped_nullifier, cert.scoped_nullifier);
	assert_eq!(decoded.nullifier_type, cert.nullifier_type);
	assert_eq!(decoded.ttl_block, cert.ttl_block);
	assert_eq!(decoded.adult, cert.adult);
	assert_eq!(decoded.seat_id, cert.seat_id);
	assert_eq!(decoded.minted_at, cert.minted_at);
}
