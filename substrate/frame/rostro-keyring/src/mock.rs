// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Test runtime: system + keyring only. `AccountId = AccountId32` (the
//! pallet pins it), so test accounts are real derived addresses minted
//! from real keypairs — the tests exercise actual signature verification,
//! not stand-ins.

#![cfg(test)]

use crate as pallet_rostro_keyring;
use frame_support::{derive_impl, traits::ConstU32};
use sp_core::crypto::AccountId32;
use sp_runtime::BuildStorage;

type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
	pub enum Test
	{
		System: frame_system,
		Keyring: pallet_rostro_keyring,
	}
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
	type Block = Block;
	type AccountId = AccountId32;
	type Lookup = sp_runtime::traits::IdentityLookup<AccountId32>;
}

impl pallet_rostro_keyring::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type MaxKeys = ConstU32<5>;
}

pub fn new_test_ext() -> sp_io::TestExternalities {
	let t = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();
	let mut ext = sp_io::TestExternalities::new(t);
	ext.execute_with(|| frame_system::Pallet::<Test>::set_block_number(1));
	ext
}
