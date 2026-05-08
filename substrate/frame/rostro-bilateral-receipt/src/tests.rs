// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Tests for `pallet-rostro-bilateral-receipt`. Mock runtime wires
//! pallet-balances + a recording AtomicMintHook (so tests can
//! verify mint integration without depending on operator-state),
//! and uses `sp_keyring` to derive Sr25519 test keys for Alice,
//! Bob, Charlie. Signatures are produced via `MultiSignature::from
//! (pair.sign(bundle))`.

use crate as pallet_rostro_bilateral_receipt;
use crate::*;

use frame_support::{
	assert_noop, assert_ok, derive_impl,
	traits::ConstU128,
};
use sp_core::{Pair, H256};
use sp_keyring::Sr25519Keyring;
use sp_runtime::{
	traits::{BlakeTwo256, IdentityLookup},
	AccountId32, BuildStorage, MultiSignature, MultiSigner,
};

type Block = frame_system::mocking::MockBlock<Test>;
type AccountId = AccountId32;
type Balance = u128;

frame_support::construct_runtime!(
	pub enum Test {
		System: frame_system,
		Balances: pallet_balances,
		BilateralReceipt: pallet_rostro_bilateral_receipt,
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

impl pallet_rostro_bilateral_receipt::Config for Test {
	type Currency = Balances;
	type Signature = MultiSignature;
	type AccountPublic = MultiSigner;
	type AtomicMintHook = MockMintHook;
}

// ─── Mock atomic-mint hook ─────────────────────────────────────────────

use core::cell::RefCell;
use std::collections::VecDeque;

#[derive(Clone, PartialEq, Eq, Debug)]
struct MintCall {
	operator: AccountId,
	namespace: H256,
	object_type: Vec<u8>,
	object_id: Vec<u8>,
	owner: AccountId,
	blob: Vec<u8>,
	deposit: Balance,
}

thread_local! {
	/// Records every mint() invocation. Tests inspect this to
	/// confirm the hook was called with the expected parameters.
	static MINT_CALLS: RefCell<Vec<MintCall>> = RefCell::new(Vec::new());

	/// Errors to inject in upcoming hook invocations. `pop_front()`
	/// is consulted before each call; if Some(err), the hook
	/// returns that error instead of recording. Used to test the
	/// `MintHookFailed` path.
	static MINT_ERRORS: RefCell<VecDeque<DispatchError>> = RefCell::new(VecDeque::new());
}

pub struct MockMintHook;
impl AtomicMintHook<AccountId, Balance> for MockMintHook {
	fn mint(
		operator: &AccountId,
		namespace: H256,
		object_type: Vec<u8>,
		object_id: Vec<u8>,
		owner: AccountId,
		blob: Vec<u8>,
		deposit: Balance,
	) -> DispatchResult {
		if let Some(err) = MINT_ERRORS.with(|e| e.borrow_mut().pop_front()) {
			return Err(err);
		}
		MINT_CALLS.with(|c| {
			c.borrow_mut().push(MintCall {
				operator: operator.clone(),
				namespace,
				object_type,
				object_id,
				owner,
				blob,
				deposit,
			});
		});
		Ok(())
	}
}

fn reset_mocks() {
	MINT_CALLS.with(|c| c.borrow_mut().clear());
	MINT_ERRORS.with(|e| e.borrow_mut().clear());
}

// ─── Test fixtures ─────────────────────────────────────────────────────

const STARTING: Balance = 1_000_000;

fn ext() -> sp_io::TestExternalities {
	reset_mocks();
	let mut t = frame_system::GenesisConfig::<Test>::default()
		.build_storage()
		.unwrap();
	pallet_balances::GenesisConfig::<Test> {
		balances: alloc::vec![
			(Sr25519Keyring::Alice.to_account_id(), STARTING),
			(Sr25519Keyring::Bob.to_account_id(), STARTING),
			(Sr25519Keyring::Charlie.to_account_id(), STARTING),
		],
		..Default::default()
	}
	.assimilate_storage(&mut t)
	.unwrap();
	let mut e = sp_io::TestExternalities::new(t);
	e.execute_with(|| System::set_block_number(1));
	e
}

fn relayer() -> AccountId {
	Sr25519Keyring::Charlie.to_account_id()
}

fn payload(
	customer: Sr25519Keyring,
	operator: Sr25519Keyring,
	amount: Balance,
	nonce: u64,
) -> ReceiptPayload<AccountId, Balance> {
	ReceiptPayload {
		customer: customer.to_account_id(),
		operator: operator.to_account_id(),
		amount,
		trade_ref: BoundedTradeRef::try_from(b"order-42".to_vec()).unwrap(),
		fee_payer: FeePayerKind::Customer,
		nonce,
	}
}

fn sign_bundle(
	signer: Sr25519Keyring,
	payload: &ReceiptPayload<AccountId, Balance>,
	mint_along: &Option<MintAlong<AccountId, Balance>>,
) -> MultiSignature {
	let bundle = (payload.clone(), mint_along.clone()).encode();
	MultiSignature::from(signer.pair().sign(&bundle[..]))
}

// ─── Happy path ────────────────────────────────────────────────────────

#[test]
fn submit_trade_succeeds_with_valid_signatures() {
	ext().execute_with(|| {
		let p = payload(Sr25519Keyring::Alice, Sr25519Keyring::Bob, 500, 1);
		let cust_sig = sign_bundle(Sr25519Keyring::Alice, &p, &None);
		let op_sig = sign_bundle(Sr25519Keyring::Bob, &p, &None);

		assert_ok!(BilateralReceipt::submit_trade(
			RuntimeOrigin::signed(relayer()),
			p.clone(),
			cust_sig,
			op_sig,
			None,
		));
		// Funds moved.
		assert_eq!(Balances::free_balance(p.customer.clone()), STARTING - 500);
		assert_eq!(Balances::free_balance(p.operator.clone()), STARTING + 500);
		// Nonce recorded.
		assert_eq!(BilateralReceipt::last_nonce_of(&p.customer), Some(1));
	});
}

#[test]
fn submit_trade_records_receipt_keyed_by_bundle_hash() {
	ext().execute_with(|| {
		let p = payload(Sr25519Keyring::Alice, Sr25519Keyring::Bob, 500, 1);
		let cust_sig = sign_bundle(Sr25519Keyring::Alice, &p, &None);
		let op_sig = sign_bundle(Sr25519Keyring::Bob, &p, &None);

		assert_ok!(BilateralReceipt::submit_trade(
			RuntimeOrigin::signed(relayer()),
			p.clone(),
			cust_sig,
			op_sig,
			None,
		));

		let expected_hash =
			H256::from(sp_io::hashing::blake2_256(&(p.clone(), Option::<MintAlong<AccountId, Balance>>::None).encode()));
		let recorded = BilateralReceipt::receipt_of(expected_hash).unwrap();
		assert_eq!(recorded.payload, p);
		assert_eq!(recorded.block, 1);
	});
}

// ─── Signature validation ──────────────────────────────────────────────

#[test]
fn submit_trade_rejects_bad_customer_signature() {
	ext().execute_with(|| {
		let p = payload(Sr25519Keyring::Alice, Sr25519Keyring::Bob, 500, 1);
		// Charlie signs in Alice's place.
		let bad_cust = sign_bundle(Sr25519Keyring::Charlie, &p, &None);
		let op_sig = sign_bundle(Sr25519Keyring::Bob, &p, &None);

		assert_noop!(
			BilateralReceipt::submit_trade(
				RuntimeOrigin::signed(relayer()),
				p,
				bad_cust,
				op_sig,
				None,
			),
			Error::<Test>::InvalidCustomerSignature,
		);
	});
}

#[test]
fn submit_trade_rejects_bad_operator_signature() {
	ext().execute_with(|| {
		let p = payload(Sr25519Keyring::Alice, Sr25519Keyring::Bob, 500, 1);
		let cust_sig = sign_bundle(Sr25519Keyring::Alice, &p, &None);
		// Charlie signs in Bob's place.
		let bad_op = sign_bundle(Sr25519Keyring::Charlie, &p, &None);

		assert_noop!(
			BilateralReceipt::submit_trade(
				RuntimeOrigin::signed(relayer()),
				p,
				cust_sig,
				bad_op,
				None,
			),
			Error::<Test>::InvalidOperatorSignature,
		);
	});
}

#[test]
fn submit_trade_rejects_signatures_over_a_different_bundle() {
	// Customer signed payload with nonce=1; relayer submits with
	// nonce=2 (a different bundle). Verify must reject.
	ext().execute_with(|| {
		let p1 = payload(Sr25519Keyring::Alice, Sr25519Keyring::Bob, 500, 1);
		let cust_sig = sign_bundle(Sr25519Keyring::Alice, &p1, &None);
		let op_sig = sign_bundle(Sr25519Keyring::Bob, &p1, &None);

		let p2 = payload(Sr25519Keyring::Alice, Sr25519Keyring::Bob, 500, 2);
		assert_noop!(
			BilateralReceipt::submit_trade(
				RuntimeOrigin::signed(relayer()),
				p2,
				cust_sig,
				op_sig,
				None,
			),
			Error::<Test>::InvalidCustomerSignature,
		);
	});
}

// ─── Self-trade rejection ──────────────────────────────────────────────

#[test]
fn submit_trade_rejects_self_trade() {
	ext().execute_with(|| {
		let p = payload(Sr25519Keyring::Alice, Sr25519Keyring::Alice, 500, 1);
		let sig = sign_bundle(Sr25519Keyring::Alice, &p, &None);
		assert_noop!(
			BilateralReceipt::submit_trade(
				RuntimeOrigin::signed(relayer()),
				p,
				sig.clone(),
				sig,
				None,
			),
			Error::<Test>::SelfTrade,
		);
	});
}

// ─── Anti-replay ───────────────────────────────────────────────────────

#[test]
fn submit_trade_rejects_replayed_nonce() {
	ext().execute_with(|| {
		let p1 = payload(Sr25519Keyring::Alice, Sr25519Keyring::Bob, 500, 5);
		assert_ok!(BilateralReceipt::submit_trade(
			RuntimeOrigin::signed(relayer()),
			p1.clone(),
			sign_bundle(Sr25519Keyring::Alice, &p1, &None),
			sign_bundle(Sr25519Keyring::Bob, &p1, &None),
			None,
		));

		// Same nonce (5) — must reject as replay/stale.
		let p_replay = payload(Sr25519Keyring::Alice, Sr25519Keyring::Bob, 100, 5);
		assert_noop!(
			BilateralReceipt::submit_trade(
				RuntimeOrigin::signed(relayer()),
				p_replay.clone(),
				sign_bundle(Sr25519Keyring::Alice, &p_replay, &None),
				sign_bundle(Sr25519Keyring::Bob, &p_replay, &None),
				None,
			),
			Error::<Test>::ReplayedOrStaleNonce,
		);

		// Lower nonce (4) — also rejected.
		let p_stale = payload(Sr25519Keyring::Alice, Sr25519Keyring::Bob, 100, 4);
		assert_noop!(
			BilateralReceipt::submit_trade(
				RuntimeOrigin::signed(relayer()),
				p_stale.clone(),
				sign_bundle(Sr25519Keyring::Alice, &p_stale, &None),
				sign_bundle(Sr25519Keyring::Bob, &p_stale, &None),
				None,
			),
			Error::<Test>::ReplayedOrStaleNonce,
		);

		// Strictly greater nonce (6) — accepted.
		let p_next = payload(Sr25519Keyring::Alice, Sr25519Keyring::Bob, 100, 6);
		assert_ok!(BilateralReceipt::submit_trade(
			RuntimeOrigin::signed(relayer()),
			p_next.clone(),
			sign_bundle(Sr25519Keyring::Alice, &p_next, &None),
			sign_bundle(Sr25519Keyring::Bob, &p_next, &None),
			None,
		));
	});
}

#[test]
fn nonces_are_per_customer() {
	// Alice's nonce sequence is independent of Bob's (when Bob
	// is paying someone else as customer).
	ext().execute_with(|| {
		let p_alice = payload(Sr25519Keyring::Alice, Sr25519Keyring::Bob, 100, 1);
		assert_ok!(BilateralReceipt::submit_trade(
			RuntimeOrigin::signed(relayer()),
			p_alice.clone(),
			sign_bundle(Sr25519Keyring::Alice, &p_alice, &None),
			sign_bundle(Sr25519Keyring::Bob, &p_alice, &None),
			None,
		));

		// Bob (as customer) using nonce 1 must not be blocked by
		// Alice's prior nonce 1.
		let p_bob = payload(Sr25519Keyring::Bob, Sr25519Keyring::Charlie, 100, 1);
		assert_ok!(BilateralReceipt::submit_trade(
			RuntimeOrigin::signed(relayer()),
			p_bob.clone(),
			sign_bundle(Sr25519Keyring::Bob, &p_bob, &None),
			sign_bundle(Sr25519Keyring::Charlie, &p_bob, &None),
			None,
		));
	});
}

// ─── Atomic mint integration ───────────────────────────────────────────

fn make_mint_along() -> MintAlong<AccountId, Balance> {
	MintAlong {
		namespace: H256::repeat_byte(0xCC),
		object_type: BoundedVec::try_from(b"ticket-v1".to_vec()).unwrap(),
		object_id: BoundedVec::try_from(b"42".to_vec()).unwrap(),
		owner: Sr25519Keyring::Alice.to_account_id(),
		blob: BoundedVec::try_from(b"row 5 seat 12".to_vec()).unwrap(),
		deposit: 1000,
	}
}

#[test]
fn submit_trade_with_mint_along_invokes_hook() {
	ext().execute_with(|| {
		let p = payload(Sr25519Keyring::Alice, Sr25519Keyring::Bob, 500, 1);
		let mint = Some(make_mint_along());

		assert_ok!(BilateralReceipt::submit_trade(
			RuntimeOrigin::signed(relayer()),
			p.clone(),
			sign_bundle(Sr25519Keyring::Alice, &p, &mint),
			sign_bundle(Sr25519Keyring::Bob, &p, &mint),
			mint.clone(),
		));

		// Hook recorded the call.
		MINT_CALLS.with(|c| {
			let calls = c.borrow();
			assert_eq!(calls.len(), 1);
			assert_eq!(calls[0].operator, p.operator);
			assert_eq!(calls[0].namespace, H256::repeat_byte(0xCC));
			assert_eq!(calls[0].object_type, b"ticket-v1");
			assert_eq!(calls[0].object_id, b"42");
			assert_eq!(calls[0].owner, Sr25519Keyring::Alice.to_account_id());
			assert_eq!(calls[0].deposit, 1000);
		});
	});
}

#[test]
fn submit_trade_signature_covers_mint_along() {
	// Customer/operator signed the bundle with mint_along=A; if the
	// relayer submits with mint_along=B (or None), signatures must
	// reject because the bundle differs.
	ext().execute_with(|| {
		let p = payload(Sr25519Keyring::Alice, Sr25519Keyring::Bob, 500, 1);
		let mint_a = Some(make_mint_along());

		// Both parties signed mint_a — but relayer submits None.
		let cust_sig = sign_bundle(Sr25519Keyring::Alice, &p, &mint_a);
		let op_sig = sign_bundle(Sr25519Keyring::Bob, &p, &mint_a);

		assert_noop!(
			BilateralReceipt::submit_trade(
				RuntimeOrigin::signed(relayer()),
				p.clone(),
				cust_sig.clone(),
				op_sig.clone(),
				None,
			),
			Error::<Test>::InvalidCustomerSignature,
		);

		// And submitting with mint_a (the actually-signed value)
		// goes through.
		assert_ok!(BilateralReceipt::submit_trade(
			RuntimeOrigin::signed(relayer()),
			p,
			cust_sig,
			op_sig,
			mint_a,
		));
	});
}

#[test]
fn submit_trade_propagates_mint_hook_failure() {
	ext().execute_with(|| {
		MINT_ERRORS.with(|e| {
			e.borrow_mut().push_back(DispatchError::Other("operator-state rejected mint"));
		});

		let p = payload(Sr25519Keyring::Alice, Sr25519Keyring::Bob, 500, 1);
		let mint = Some(make_mint_along());

		assert_noop!(
			BilateralReceipt::submit_trade(
				RuntimeOrigin::signed(relayer()),
				p.clone(),
				sign_bundle(Sr25519Keyring::Alice, &p, &mint),
				sign_bundle(Sr25519Keyring::Bob, &p, &mint),
				mint,
			),
			Error::<Test>::MintHookFailed,
		);
	});
}

// ─── Insufficient funds ────────────────────────────────────────────────

#[test]
fn submit_trade_rejects_when_customer_balance_too_low() {
	ext().execute_with(|| {
		let p = payload(Sr25519Keyring::Alice, Sr25519Keyring::Bob, STARTING * 2, 1);
		assert_noop!(
			BilateralReceipt::submit_trade(
				RuntimeOrigin::signed(relayer()),
				p.clone(),
				sign_bundle(Sr25519Keyring::Alice, &p, &None),
				sign_bundle(Sr25519Keyring::Bob, &p, &None),
				None,
			),
			Error::<Test>::TransferFailed,
		);
	});
}

// ─── Receipt query ─────────────────────────────────────────────────────

#[test]
fn receipt_lookup_returns_none_for_unknown_hash() {
	ext().execute_with(|| {
		assert!(BilateralReceipt::receipt_of(H256::repeat_byte(0x99)).is_none());
	});
}

#[test]
fn last_nonce_returns_none_for_account_with_no_receipts() {
	ext().execute_with(|| {
		assert!(
			BilateralReceipt::last_nonce_of(&Sr25519Keyring::Eve.to_account_id())
				.is_none(),
		);
	});
}
