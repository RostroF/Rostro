// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Test runtime: system + balances + session/historical + key-lineage,
//! mirroring the gemini topology (lineage is both the session manager under
//! `NoteHistoricalRoot` and the `KeyProvenance` hook). GRANDPA itself is not
//! instantiated; its two inputs to lineage — the era clock and the current
//! set id — are thread-local mocks driven by the tests.

#![cfg(test)]

use crate as pallet_rostro_key_lineage;
use frame_support::{
	derive_impl,
	traits::{ConstU32, ConstU64, OnInitialize},
};
use pallet_session::historical as pallet_session_historical;
use sp_consensus_grandpa::AuthorityId;
use sp_core::{rostro_hybrid, Pair};
use sp_runtime::{impl_opaque_keys, BuildStorage};
use std::cell::Cell;

type Block = frame_system::mocking::MockBlock<Test>;
pub type AccountId = u64;

frame_support::construct_runtime!(
	pub enum Test
	{
		System: frame_system,
		Balances: pallet_balances,
		Session: pallet_session,
		Historical: pallet_session_historical,
		Offences: pallet_offences,
		KeyLineage: pallet_rostro_key_lineage,
	}
);

pub struct GranHandler;
impl sp_runtime::BoundToRuntimeAppPublic for GranHandler {
	type Public = AuthorityId;
}
impl frame_support::traits::OneSessionHandler<AccountId> for GranHandler {
	type Key = AuthorityId;
	fn on_genesis_session<'a, I: 'a>(_: I)
	where
		I: Iterator<Item = (&'a AccountId, AuthorityId)>,
	{
	}
	fn on_new_session<'a, I: 'a>(_: bool, _: I, _: I)
	where
		I: Iterator<Item = (&'a AccountId, AuthorityId)>,
	{
	}
	fn on_disabled(_: u32) {}
}

impl_opaque_keys! {
	pub struct MockSessionKeys {
		pub grandpa: GranHandler,
	}
}

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
	type Block = Block;
	type AccountData = pallet_balances::AccountData<u64>;
}

#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig)]
impl pallet_balances::Config for Test {
	type ExistentialDeposit = ConstU64<1>;
	type AccountStore = System;
}

impl pallet_session::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type ValidatorId = AccountId;
	type ValidatorIdOf = sp_runtime::traits::ConvertInto;
	type ShouldEndSession = pallet_session::PeriodicSessions<ConstU64<1>, ConstU64<0>>;
	type NextSessionRotation = pallet_session::PeriodicSessions<ConstU64<1>, ConstU64<0>>;
	type SessionManager = pallet_session_historical::NoteHistoricalRoot<Self, KeyLineage>;
	type SessionHandler = (GranHandler,);
	type Keys = MockSessionKeys;
	type DisablingStrategy = ();
	type WeightInfo = ();
	type Currency = Balances;
	type KeyDeposit = ();
	type KeyProvenance = KeyLineage;
}

pub struct UnitIdentificationOf;
impl sp_runtime::traits::Convert<AccountId, Option<()>> for UnitIdentificationOf {
	fn convert(_: AccountId) -> Option<()> {
		Some(())
	}
}

impl pallet_session_historical::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type FullIdentification = ();
	type FullIdentificationOf = UnitIdentificationOf;
}

thread_local! {
	static ERA: Cell<u32> = Cell::new(0);
	static SET_ID: Cell<u64> = Cell::new(0);
	static ELECTED: std::cell::RefCell<Option<Vec<AccountId>>> = std::cell::RefCell::new(None);
}

/// Stand-in for pallet-staking's session manager: yields the set primed via
/// [`prime_elected_set`] exactly once, otherwise `None` ("no new era planned
/// this session"), which is the path where lineage re-feeds the live set.
pub struct MockElectedSet;
impl pallet_session::SessionManager<AccountId> for MockElectedSet {
	fn new_session(_: sp_staking::SessionIndex) -> Option<Vec<AccountId>> {
		ELECTED.with(|e| e.borrow_mut().take())
	}
	fn new_session_genesis(_: sp_staking::SessionIndex) -> Option<Vec<AccountId>> {
		None
	}
	fn start_session(_: sp_staking::SessionIndex) {}
	fn end_session(_: sp_staking::SessionIndex) {}
}

/// Make the next session plan from `set` (a staking election result); later
/// sessions revert to `None` until primed again.
pub fn prime_elected_set(set: Vec<AccountId>) {
	ELECTED.with(|e| *e.borrow_mut() = Some(set));
}

pub struct MockEra;
impl frame_support::traits::Get<u32> for MockEra {
	fn get() -> u32 {
		ERA.with(|e| e.get())
	}
}
pub fn set_era(era: u32) {
	ERA.with(|e| e.set(era));
}

pub struct MockSetId;
impl frame_support::traits::Get<u64> for MockSetId {
	fn get() -> u64 {
		SET_ID.with(|s| s.get())
	}
}
pub fn current_mock_set_id() -> u64 {
	SET_ID.with(|s| s.get())
}

impl pallet_offences::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type IdentificationTuple = pallet_session_historical::IdentificationTuple<Self>;
	type OnOffenceHandler = KeyLineage;
}

impl pallet_rostro_key_lineage::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type CurrentEra = MockEra;
	type CurrentSetId = MockSetId;
	type MaxKeyAgeEras = ConstU32<7>;
	type MaxValidators = ConstU32<32>;
	type ReportCanary = Offences;
	type ElectedSet = MockElectedSet;
}

/// Deterministic hybrid GRANDPA key for test seed `n`.
pub fn gran_key(n: u8) -> (rostro_hybrid::Pair, AuthorityId) {
	let pair = rostro_hybrid::Pair::from_seed(&[n; 32]);
	(pair.clone(), pair.public().into())
}

pub fn keys_for(n: u8) -> MockSessionKeys {
	MockSessionKeys { grandpa: gran_key(n).1 }
}

/// Ownership proof for `set_keys`: PoP signature over `"POP_" ++ owner`.
pub fn pop_proof(n: u8, who: AccountId) -> Vec<u8> {
	use codec::Encode;
	let (pair, _) = gran_key(n);
	let statement = sp_core::proof_of_possession::statement_of_ownership(&who.encode());
	pair.sign(&statement).encode()
}

/// Genesis validators 1..=4 with grandpa key seeds 1..=4.
pub fn new_test_ext() -> sp_io::TestExternalities {
	let mut t = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();
	pallet_balances::GenesisConfig::<Test> {
		balances: (1..=10).map(|i| (i, 1_000)).collect(),
		..Default::default()
	}
	.assimilate_storage(&mut t)
	.unwrap();
	pallet_session::GenesisConfig::<Test> {
		keys: (1..=4u64).map(|i| (i, i, keys_for(i as u8))).collect(),
		..Default::default()
	}
	.assimilate_storage(&mut t)
	.unwrap();
	let mut ext = sp_io::TestExternalities::new(t);
	ext.execute_with(|| {
		System::set_block_number(1);
		set_era(0);
	});
	ext
}

/// Advance blocks; with a 1-block session period every block rotates the
/// session. Mimics GRANDPA's set-id bump: it advances iff the rotation
/// reported `changed` (which `rotate_session` reads from `QueuedChanged`
/// before overwriting it).
pub fn run_to_block(n: u64) {
	while System::block_number() < n {
		let b = System::block_number() + 1;
		System::set_block_number(b);
		let changed = pallet_session::QueuedChanged::<Test>::get();
		Session::on_initialize(b);
		if changed {
			SET_ID.with(|s| s.set(s.get() + 1));
		}
	}
}

/// Convenience: advance exactly one session (one block).
pub fn advance_session() {
	run_to_block(System::block_number() + 1);
}

pub fn active_grandpa_key(v: AccountId) -> Option<AuthorityId> {
	pallet_rostro_key_lineage::ActiveKey::<Test>::get(v)
}
