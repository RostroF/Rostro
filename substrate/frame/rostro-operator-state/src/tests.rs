// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Tests for `pallet-rostro-operator-state`. Mock runtime wires
//! pallet-balances for deposit reservation and a parking-lot-cell
//! `MockRns` registry that tests script directly via
//! `set_owner / clear_owner` to simulate RNS registration changes
//! (lapse, transfer, re-registration).

use crate as pallet_rostro_operator_state;
use crate::*;

use frame_support::{
	assert_noop, assert_ok, derive_impl,
	traits::ConstU128,
};
use pallet_rns_registrar::traits::NameRegistry as NameRegistryTrait;
use rns_types::DomainHash;
use sp_core::H256;
use sp_runtime::{
	traits::{BlakeTwo256, IdentityLookup},
	BuildStorage,
};

type Block = frame_system::mocking::MockBlock<Test>;
type AccountId = u64;
type Balance = u128;

frame_support::construct_runtime!(
	pub enum Test {
		System: frame_system,
		Balances: pallet_balances,
		OperatorState: pallet_rostro_operator_state,
	}
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
	type Block = Block;
	type AccountId = AccountId;
	type Lookup = IdentityLookup<AccountId>;
	type Hash = H256;
	type Hashing = BlakeTwo256;
	type AccountData = pallet_balances::AccountData<Balance>;
}

#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig)]
impl pallet_balances::Config for Test {
	type Balance = Balance;
	type ExistentialDeposit = ConstU128<1>;
	type AccountStore = System;
}

frame_support::parameter_types! {
	pub const MinObjectDeposit: Balance = 100;
}

impl pallet_rostro_operator_state::Config for Test {
	type Currency = Balances;
	type RnsRegistry = MockRns;
	type MinObjectDeposit = MinObjectDeposit;
}

// ─── Mock RNS registry ─────────────────────────────────────────────────

use core::cell::RefCell;
use std::collections::BTreeMap;

thread_local! {
	static OWNERS: RefCell<BTreeMap<DomainHash, AccountId>> = RefCell::new(BTreeMap::new());
}

/// Test-only RNS registrant store. Tests call [`set_owner`] /
/// [`clear_owner`] to simulate the various RNS lifecycle events
/// (initial registration, transfer, lapse).
pub struct MockRns;

impl NameRegistryTrait for MockRns {
	type AccountId = AccountId;
	fn canonical_name(_account: &AccountId) -> Option<DomainHash> {
		None
	}
	fn owner_of(node: DomainHash) -> Option<AccountId> {
		OWNERS.with(|o| o.borrow().get(&node).copied())
	}
	fn transfer_name(
		_from: &AccountId,
		_to: &AccountId,
		_node: DomainHash,
	) -> sp_runtime::DispatchResult {
		Ok(())
	}
	fn offer_bought_name(
		_seller: &AccountId,
		_buyer: &AccountId,
		_recipient: &AccountId,
		_node: DomainHash,
	) -> sp_runtime::DispatchResult {
		Ok(())
	}
	fn is_name_useable(_node: DomainHash) -> bool {
		true
	}
	fn charge_sale_fee(_buyer: &AccountId, _node: DomainHash) -> sp_runtime::DispatchResult {
		Ok(())
	}
}

fn set_owner(node: DomainHash, owner: AccountId) {
	OWNERS.with(|o| {
		o.borrow_mut().insert(node, owner);
	});
}

fn clear_owner(node: DomainHash) {
	OWNERS.with(|o| {
		o.borrow_mut().remove(&node);
	});
}

// ─── Test fixtures ─────────────────────────────────────────────────────

const NAMESPACE_A: DomainHash = H256(repeat_byte(0xAA));
const NAMESPACE_B: DomainHash = H256(repeat_byte(0xBB));

const fn repeat_byte(b: u8) -> [u8; 32] {
	[b; 32]
}
const ALICE: AccountId = 1;
const BOB: AccountId = 2;
const CUSTOMER: AccountId = 3;
const SNORKEL: AccountId = 4;
const STARTING_BAL: Balance = 1_000_000;

fn ext() -> sp_io::TestExternalities {
	OWNERS.with(|o| o.borrow_mut().clear());
	let mut t = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();
	pallet_balances::GenesisConfig::<Test> {
		balances: alloc::vec![
			(ALICE, STARTING_BAL),
			(BOB, STARTING_BAL),
			(CUSTOMER, STARTING_BAL),
			(SNORKEL, STARTING_BAL),
		],
		..Default::default()
	}
	.assimilate_storage(&mut t)
	.unwrap();
	let mut e = sp_io::TestExternalities::new(t);
	e.execute_with(|| System::set_block_number(1));
	e
}

fn ot() -> Vec<u8> {
	b"ticket-v1".to_vec()
}
fn oid() -> Vec<u8> {
	b"42".to_vec()
}
fn blob() -> Vec<u8> {
	b"opaque payload".to_vec()
}

// ─── mint_object ───────────────────────────────────────────────────────

#[test]
fn mint_succeeds_when_signer_is_namespace_owner() {
	ext().execute_with(|| {
		set_owner(NAMESPACE_A, ALICE);
		assert_ok!(OperatorState::mint_object(
			RuntimeOrigin::signed(ALICE),
			NAMESPACE_A,
			ot(),
			oid(),
			CUSTOMER,
			blob(),
			500,
		));
		let obj = OperatorState::get_object(NAMESPACE_A, &ALICE, &ot(), &oid()).unwrap();
		assert_eq!(obj.current_owner, CUSTOMER);
		assert_eq!(obj.deposit, 500);
		assert_eq!(Balances::reserved_balance(ALICE), 500);
	});
}

#[test]
fn mint_rejects_when_signer_is_not_namespace_owner() {
	ext().execute_with(|| {
		set_owner(NAMESPACE_A, ALICE);
		assert_noop!(
			OperatorState::mint_object(
				RuntimeOrigin::signed(BOB),
				NAMESPACE_A,
				ot(),
				oid(),
				CUSTOMER,
				blob(),
				500,
			),
			Error::<Test>::NamespaceNotOwnedBySigner,
		);
	});
}

#[test]
fn mint_rejects_when_namespace_unowned() {
	ext().execute_with(|| {
		// No owner set for NAMESPACE_A.
		assert_noop!(
			OperatorState::mint_object(
				RuntimeOrigin::signed(ALICE),
				NAMESPACE_A,
				ot(),
				oid(),
				CUSTOMER,
				blob(),
				500,
			),
			Error::<Test>::NamespaceNotOwnedBySigner,
		);
	});
}

#[test]
fn mint_rejects_deposit_below_minimum() {
	ext().execute_with(|| {
		set_owner(NAMESPACE_A, ALICE);
		assert_noop!(
			OperatorState::mint_object(
				RuntimeOrigin::signed(ALICE),
				NAMESPACE_A,
				ot(),
				oid(),
				CUSTOMER,
				blob(),
				50, // < MinObjectDeposit (100)
			),
			Error::<Test>::DepositTooSmall,
		);
	});
}

#[test]
fn mint_rejects_oversized_blob() {
	ext().execute_with(|| {
		set_owner(NAMESPACE_A, ALICE);
		let huge = alloc::vec![0u8; (MAX_BLOB_SIZE as usize) + 1];
		assert_noop!(
			OperatorState::mint_object(
				RuntimeOrigin::signed(ALICE),
				NAMESPACE_A,
				ot(),
				oid(),
				CUSTOMER,
				huge,
				500,
			),
			Error::<Test>::BlobTooLarge,
		);
	});
}

#[test]
fn mint_rejects_empty_object_type_or_id() {
	ext().execute_with(|| {
		set_owner(NAMESPACE_A, ALICE);
		assert_noop!(
			OperatorState::mint_object(
				RuntimeOrigin::signed(ALICE),
				NAMESPACE_A,
				alloc::vec![],
				oid(),
				CUSTOMER,
				blob(),
				500,
			),
			Error::<Test>::ObjectTypeEmpty,
		);
		assert_noop!(
			OperatorState::mint_object(
				RuntimeOrigin::signed(ALICE),
				NAMESPACE_A,
				ot(),
				alloc::vec![],
				CUSTOMER,
				blob(),
				500,
			),
			Error::<Test>::ObjectIdEmpty,
		);
	});
}

// ─── mutate_object_blob ────────────────────────────────────────────────

#[test]
fn mutate_succeeds_for_namespace_owner() {
	ext().execute_with(|| {
		set_owner(NAMESPACE_A, ALICE);
		assert_ok!(OperatorState::mint_object(
			RuntimeOrigin::signed(ALICE),
			NAMESPACE_A,
			ot(),
			oid(),
			CUSTOMER,
			blob(),
			500,
		));
		assert_ok!(OperatorState::mutate_object_blob(
			RuntimeOrigin::signed(ALICE),
			NAMESPACE_A,
			ALICE,
			ot(),
			oid(),
			b"new payload".to_vec(),
		));
		let obj = OperatorState::get_object(NAMESPACE_A, &ALICE, &ot(), &oid()).unwrap();
		assert_eq!(obj.blob.into_inner(), b"new payload".to_vec());
		// Owner / deposit unchanged.
		assert_eq!(obj.current_owner, CUSTOMER);
		assert_eq!(obj.deposit, 500);
	});
}

#[test]
fn mutate_rejects_when_signer_is_not_namespace_owner() {
	ext().execute_with(|| {
		set_owner(NAMESPACE_A, ALICE);
		assert_ok!(OperatorState::mint_object(
			RuntimeOrigin::signed(ALICE),
			NAMESPACE_A,
			ot(),
			oid(),
			CUSTOMER,
			blob(),
			500,
		));
		// Now namespace is transferred to BOB. ALICE is no longer
		// the namespace owner; her mutate must reject — even though
		// she's the mint_account in the storage key, the current
		// RNS registrant check fails.
		set_owner(NAMESPACE_A, BOB);
		assert_noop!(
			OperatorState::mutate_object_blob(
				RuntimeOrigin::signed(ALICE),
				NAMESPACE_A,
				ALICE,
				ot(),
				oid(),
				b"new payload".to_vec(),
			),
			Error::<Test>::NamespaceNotOwnedBySigner,
		);
	});
}

#[test]
fn mutate_rejects_when_signer_is_current_namespace_owner_but_not_mint_account() {
	// This is the killer cross-registration test. Alice mints,
	// Alice's lease lapses, Bob registers the same name, Bob tries
	// to mutate Alice's object. Bob holds the namespace currently
	// (auth check 1 passes), but Bob ≠ Alice's mint_account (auth
	// check 2 fails). Reject.
	ext().execute_with(|| {
		set_owner(NAMESPACE_A, ALICE);
		assert_ok!(OperatorState::mint_object(
			RuntimeOrigin::signed(ALICE),
			NAMESPACE_A,
			ot(),
			oid(),
			CUSTOMER,
			blob(),
			500,
		));
		// Lease transfers to BOB.
		set_owner(NAMESPACE_A, BOB);
		// BOB tries to mutate Alice's object under Alice's mint_account.
		assert_noop!(
			OperatorState::mutate_object_blob(
				RuntimeOrigin::signed(BOB),
				NAMESPACE_A,
				ALICE,
				ot(),
				oid(),
				b"hijacked".to_vec(),
			),
			Error::<Test>::MintAccountMismatch,
		);
		// Verify Alice's object is untouched.
		let obj = OperatorState::get_object(NAMESPACE_A, &ALICE, &ot(), &oid()).unwrap();
		assert_eq!(obj.blob.into_inner(), blob());
	});
}

#[test]
fn mutate_rejects_when_object_does_not_exist() {
	ext().execute_with(|| {
		set_owner(NAMESPACE_A, ALICE);
		assert_noop!(
			OperatorState::mutate_object_blob(
				RuntimeOrigin::signed(ALICE),
				NAMESPACE_A,
				ALICE,
				ot(),
				oid(),
				b"new payload".to_vec(),
			),
			Error::<Test>::ObjectNotFound,
		);
	});
}

// ─── transfer_object ───────────────────────────────────────────────────

#[test]
fn transfer_succeeds_when_signer_is_current_owner() {
	ext().execute_with(|| {
		set_owner(NAMESPACE_A, ALICE);
		assert_ok!(OperatorState::mint_object(
			RuntimeOrigin::signed(ALICE),
			NAMESPACE_A,
			ot(),
			oid(),
			CUSTOMER,
			blob(),
			500,
		));
		// Customer transfers their NFT to BOB. Namespace owner
		// (ALICE) doesn't sign; only the current_owner does.
		assert_ok!(OperatorState::transfer_object(
			RuntimeOrigin::signed(CUSTOMER),
			NAMESPACE_A,
			ALICE,
			ot(),
			oid(),
			BOB,
		));
		let obj = OperatorState::get_object(NAMESPACE_A, &ALICE, &ot(), &oid()).unwrap();
		assert_eq!(obj.current_owner, BOB);
	});
}

#[test]
fn transfer_rejects_when_signer_is_not_current_owner() {
	ext().execute_with(|| {
		set_owner(NAMESPACE_A, ALICE);
		assert_ok!(OperatorState::mint_object(
			RuntimeOrigin::signed(ALICE),
			NAMESPACE_A,
			ot(),
			oid(),
			CUSTOMER,
			blob(),
			500,
		));
		// Namespace owner ALICE tries to transfer the customer's
		// NFT — rejected because she's not the current_owner.
		assert_noop!(
			OperatorState::transfer_object(
				RuntimeOrigin::signed(ALICE),
				NAMESPACE_A,
				ALICE,
				ot(),
				oid(),
				BOB,
			),
			Error::<Test>::NotObjectOwner,
		);
	});
}

#[test]
fn transfer_works_after_namespace_lapse() {
	// The customer's ability to transfer their NFT must NOT depend
	// on the operator's namespace still being live. The customer
	// signature alone authorizes; storage keying by the original
	// mint_account preserves access.
	ext().execute_with(|| {
		set_owner(NAMESPACE_A, ALICE);
		assert_ok!(OperatorState::mint_object(
			RuntimeOrigin::signed(ALICE),
			NAMESPACE_A,
			ot(),
			oid(),
			CUSTOMER,
			blob(),
			500,
		));
		clear_owner(NAMESPACE_A);
		// Customer can still transfer — until cleanup is called.
		assert_ok!(OperatorState::transfer_object(
			RuntimeOrigin::signed(CUSTOMER),
			NAMESPACE_A,
			ALICE,
			ot(),
			oid(),
			BOB,
		));
		let obj = OperatorState::get_object(NAMESPACE_A, &ALICE, &ot(), &oid()).unwrap();
		assert_eq!(obj.current_owner, BOB);
	});
}

// ─── burn_object ───────────────────────────────────────────────────────

#[test]
fn burn_succeeds_and_refunds_deposit_to_namespace_owner() {
	ext().execute_with(|| {
		set_owner(NAMESPACE_A, ALICE);
		assert_ok!(OperatorState::mint_object(
			RuntimeOrigin::signed(ALICE),
			NAMESPACE_A,
			ot(),
			oid(),
			CUSTOMER,
			blob(),
			500,
		));
		assert_eq!(Balances::reserved_balance(ALICE), 500);
		assert_ok!(OperatorState::burn_object(
			RuntimeOrigin::signed(ALICE),
			NAMESPACE_A,
			ALICE,
			ot(),
			oid(),
		));
		assert_eq!(Balances::reserved_balance(ALICE), 0);
		assert_eq!(Balances::free_balance(ALICE), STARTING_BAL);
		assert!(OperatorState::get_object(NAMESPACE_A, &ALICE, &ot(), &oid()).is_none());
	});
}

#[test]
fn burn_rejects_when_signer_is_not_namespace_owner() {
	ext().execute_with(|| {
		set_owner(NAMESPACE_A, ALICE);
		assert_ok!(OperatorState::mint_object(
			RuntimeOrigin::signed(ALICE),
			NAMESPACE_A,
			ot(),
			oid(),
			CUSTOMER,
			blob(),
			500,
		));
		// Lease transfers; ALICE is no longer the namespace owner.
		set_owner(NAMESPACE_A, BOB);
		assert_noop!(
			OperatorState::burn_object(
				RuntimeOrigin::signed(ALICE),
				NAMESPACE_A,
				ALICE,
				ot(),
				oid(),
			),
			Error::<Test>::NamespaceNotOwnedBySigner,
		);
	});
}

// ─── cleanup ───────────────────────────────────────────────────────────

#[test]
fn cleanup_pays_caller_when_namespace_lapsed() {
	ext().execute_with(|| {
		set_owner(NAMESPACE_A, ALICE);
		assert_ok!(OperatorState::mint_object(
			RuntimeOrigin::signed(ALICE),
			NAMESPACE_A,
			ot(),
			oid(),
			CUSTOMER,
			blob(),
			500,
		));
		// Lease lapses entirely.
		clear_owner(NAMESPACE_A);
		// Snorkel calls cleanup. Permissionless.
		let snorkel_before = Balances::free_balance(SNORKEL);
		assert_ok!(OperatorState::cleanup(
			RuntimeOrigin::signed(SNORKEL),
			NAMESPACE_A,
			ALICE,
			ot(),
			oid(),
		));
		let snorkel_after = Balances::free_balance(SNORKEL);
		assert_eq!(snorkel_after - snorkel_before, 500);
		assert_eq!(Balances::reserved_balance(ALICE), 0);
		assert!(OperatorState::get_object(NAMESPACE_A, &ALICE, &ot(), &oid()).is_none());
	});
}

#[test]
fn cleanup_pays_caller_when_namespace_transferred_to_different_account() {
	ext().execute_with(|| {
		set_owner(NAMESPACE_A, ALICE);
		assert_ok!(OperatorState::mint_object(
			RuntimeOrigin::signed(ALICE),
			NAMESPACE_A,
			ot(),
			oid(),
			CUSTOMER,
			blob(),
			500,
		));
		// Lease transfers to BOB (different account from ALICE).
		set_owner(NAMESPACE_A, BOB);
		assert_ok!(OperatorState::cleanup(
			RuntimeOrigin::signed(SNORKEL),
			NAMESPACE_A,
			ALICE,
			ot(),
			oid(),
		));
		assert!(OperatorState::get_object(NAMESPACE_A, &ALICE, &ot(), &oid()).is_none());
	});
}

#[test]
fn cleanup_rejects_while_namespace_still_owned_by_mint_account() {
	ext().execute_with(|| {
		set_owner(NAMESPACE_A, ALICE);
		assert_ok!(OperatorState::mint_object(
			RuntimeOrigin::signed(ALICE),
			NAMESPACE_A,
			ot(),
			oid(),
			CUSTOMER,
			blob(),
			500,
		));
		// ALICE is still the namespace owner. Cleanup must reject.
		assert_noop!(
			OperatorState::cleanup(
				RuntimeOrigin::signed(SNORKEL),
				NAMESPACE_A,
				ALICE,
				ot(),
				oid(),
			),
			Error::<Test>::NotEligibleForCleanup,
		);
	});
}

#[test]
fn cleanup_works_for_alice_reclaim_does_not() {
	// Lapse-and-reclaim: Alice lapses, no one else registers, Alice
	// re-registers from the same account. Cleanup must reject because
	// the current registrant matches the mint account again — Alice's
	// objects are accessible to her once more.
	ext().execute_with(|| {
		set_owner(NAMESPACE_A, ALICE);
		assert_ok!(OperatorState::mint_object(
			RuntimeOrigin::signed(ALICE),
			NAMESPACE_A,
			ot(),
			oid(),
			CUSTOMER,
			blob(),
			500,
		));
		// Lapse.
		clear_owner(NAMESPACE_A);
		// During lapse: object is reapable. (Don't reap; just
		// confirm cleanup *would* succeed at this point.)
		assert!(OperatorState::cleanup(
			RuntimeOrigin::signed(SNORKEL),
			NAMESPACE_A,
			ALICE,
			ot(),
			oid(),
		)
		.is_ok());
		// (Object now gone; reset state for the reclaim-side
		// branch of this test.)
	});

	ext().execute_with(|| {
		set_owner(NAMESPACE_A, ALICE);
		assert_ok!(OperatorState::mint_object(
			RuntimeOrigin::signed(ALICE),
			NAMESPACE_A,
			ot(),
			oid(),
			CUSTOMER,
			blob(),
			500,
		));
		clear_owner(NAMESPACE_A);
		// Alice re-registers from same account before cleanup
		// fires.
		set_owner(NAMESPACE_A, ALICE);
		// Cleanup must reject — Alice has reclaimed.
		assert_noop!(
			OperatorState::cleanup(
				RuntimeOrigin::signed(SNORKEL),
				NAMESPACE_A,
				ALICE,
				ot(),
				oid(),
			),
			Error::<Test>::NotEligibleForCleanup,
		);
		// Object still exists, accessible by Alice.
		assert_ok!(OperatorState::burn_object(
			RuntimeOrigin::signed(ALICE),
			NAMESPACE_A,
			ALICE,
			ot(),
			oid(),
		));
	});
}

// ─── Cross-namespace isolation invariant ───────────────────────────────

#[test]
fn cross_operator_isolation_holds_under_same_object_type_and_id() {
	// Operator A under NAMESPACE_A and operator B under
	// NAMESPACE_B both mint "ticket-v1 #42". Both coexist; neither
	// can mutate the other's object.
	ext().execute_with(|| {
		set_owner(NAMESPACE_A, ALICE);
		set_owner(NAMESPACE_B, BOB);
		assert_ok!(OperatorState::mint_object(
			RuntimeOrigin::signed(ALICE),
			NAMESPACE_A,
			ot(),
			oid(),
			CUSTOMER,
			b"alice's ticket".to_vec(),
			500,
		));
		assert_ok!(OperatorState::mint_object(
			RuntimeOrigin::signed(BOB),
			NAMESPACE_B,
			ot(),
			oid(),
			CUSTOMER,
			b"bob's ticket".to_vec(),
			500,
		));
		// Both objects exist independently.
		let a_obj = OperatorState::get_object(NAMESPACE_A, &ALICE, &ot(), &oid()).unwrap();
		let b_obj = OperatorState::get_object(NAMESPACE_B, &BOB, &ot(), &oid()).unwrap();
		assert_eq!(a_obj.blob.into_inner(), b"alice's ticket".to_vec());
		assert_eq!(b_obj.blob.into_inner(), b"bob's ticket".to_vec());

		// BOB cannot mutate ALICE's object even though he holds an
		// active namespace and the same ObjectType / ObjectId.
		assert_noop!(
			OperatorState::mutate_object_blob(
				RuntimeOrigin::signed(BOB),
				NAMESPACE_A,
				ALICE,
				ot(),
				oid(),
				b"hijacked".to_vec(),
			),
			Error::<Test>::NamespaceNotOwnedBySigner,
		);
	});
}

