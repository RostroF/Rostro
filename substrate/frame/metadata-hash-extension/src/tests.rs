// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::CheckMetadataHash;
use codec::{Decode, Encode};
use frame_support::derive_impl;
use sp_runtime::{traits::TransactionExtension, transaction_validity::UnknownTransaction};

type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime! {
	pub enum Test {
		System: frame_system,
	}
}

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
	type Block = Block;
}

#[test]
fn rejects_when_no_metadata_hash_was_passed() {
	let ext = CheckMetadataHash::<Test>::decode(&mut &1u8.encode()[..]).unwrap();
	assert_eq!(Err(UnknownTransaction::CannotLookup.into()), ext.implicit());
}

#[test]
fn rejects_unknown_mode() {
	assert!(CheckMetadataHash::<Test>::decode(&mut &50u8.encode()[..]).is_err());
}

// wasm-cull W2 (per D1): `ensure_check_metadata_works_on_real_extrinsics` and
// its hash helper are culled. They exercised ENABLED-mode CheckMetadataHash
// against a hash baked in by wasm-builder's metadata-hash step, which executed
// the runtime blob through the removed WasmExecutor. Rostro ships disabled
// mode only (the tests above cover it); see docs/WASM-SURFACE-AUDIT.md.

#[allow(unused)]
mod docs {
	use super::*;

	#[docify::export]
	mod add_metadata_hash_extension {
		frame_support::construct_runtime! {
			pub enum Runtime {
				System: frame_system,
			}
		}

		/// The `TransactionExtension` to the basic transaction logic.
		pub type TxExtension = (
			frame_system::AuthorizeCall<Runtime>,
			frame_system::CheckNonZeroSender<Runtime>,
			frame_system::CheckSpecVersion<Runtime>,
			frame_system::CheckTxVersion<Runtime>,
			frame_system::CheckGenesis<Runtime>,
			frame_system::CheckMortality<Runtime>,
			frame_system::CheckNonce<Runtime>,
			frame_system::CheckWeight<Runtime>,
			// Add the `CheckMetadataHash` extension.
			// The position in this list is not important, so we could also add it to beginning.
			frame_metadata_hash_extension::CheckMetadataHash<Runtime>,
			frame_system::WeightReclaim<Runtime>,
		);

		/// In your runtime this will be your real address type.
		type Address = ();
		/// In your runtime this will be your real signature type.
		type Signature = ();

		/// Unchecked extrinsic type as expected by this runtime.
		pub type UncheckedExtrinsic =
			sp_runtime::generic::UncheckedExtrinsic<Address, RuntimeCall, Signature, TxExtension>;
	}

	// Put here to not have it in the docs as well.
	#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
	impl frame_system::Config for add_metadata_hash_extension::Runtime {
		type Block = Block;
		type RuntimeEvent = add_metadata_hash_extension::RuntimeEvent;
		type RuntimeOrigin = add_metadata_hash_extension::RuntimeOrigin;
		type RuntimeCall = add_metadata_hash_extension::RuntimeCall;
		type PalletInfo = add_metadata_hash_extension::PalletInfo;
	}


}
