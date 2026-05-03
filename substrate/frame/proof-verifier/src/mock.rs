// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Mock runtime for `pallet-proof-verifier` integration tests.

use crate as pallet_proof_verifier;
use frame_support::derive_impl;
use frame_system::EnsureRoot;
use rp_core::H256;
use rp_runtime::{
	traits::{BlakeTwo256, IdentityLookup},
	BuildStorage,
};

pub type AccountId = u64;
pub type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
	pub enum Test {
		System: frame_system,
		ProofVerifier: pallet_proof_verifier,
	}
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
	type Block = Block;
	type AccountId = AccountId;
	type Lookup = IdentityLookup<Self::AccountId>;
	type Hash = H256;
	type Hashing = BlakeTwo256;
	type AccountData = ();
}

impl pallet_proof_verifier::Config for Test {
	type RegistrarOrigin = EnsureRoot<AccountId>;
	type WeightInfo = ();
}

pub fn new_test_ext() -> rp_io::TestExternalities {
	let t = frame_system::GenesisConfig::<Test>::default()
		.build_storage()
		.unwrap();
	let mut ext = rp_io::TestExternalities::new(t);
	ext.execute_with(|| System::set_block_number(1));
	ext
}
