// Copyright (C) Parity Technologies (UK) Ltd.
// This file is part of Polkadot.

// Polkadot is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Polkadot is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Polkadot.  If not, see <http://www.gnu.org/licenses/>.

//! SECURITY regression tests for HIGH#2:
//! `do_reserve_deposit_assets` and `do_teleport_assets` previously called
//! `reanchored_assets`, which silently dropped any asset whose id failed to
//! reanchor onto the destination. The local side debited/burned the FULL
//! `assets` (full sovereign-account credit, full `check_out`), but the
//! `ReserveAssetDeposited` / `ReceiveTeleportedAsset` instructions sent on the
//! remote side carried only the SHRUNK subset.
//!
//! Effect:
//! - reserve-deposit: difference is permanently locked in the dest's local
//!   sovereign account on this chain.
//! - teleport: difference is `check_out`'d locally and never re-minted on the
//!   destination — net issuance is reduced (true loss of value).
//!
//! Fix: both call sites now use `try_reanchored_assets`, which returns
//! `XcmError::ReanchorFailed` if any asset fails to reanchor, so the operation
//! aborts BEFORE the local debit/burn.

use frame_support::BoundedVec;
use xcm::{latest::AssetTransferFilter, prelude::*};

use super::mock::*;
use crate::{AssetsInHolding, XcmExecutor};

/// Builds a `Location` whose interior is `MAX_JUNCTIONS` (= 8) junctions deep,
/// and whose parents = 0. Reanchoring such a location against any target
/// whose `invert_target(...)` produces a non-empty interior overflows
/// `prepend_with` → reanchor fails.
fn deeply_nested_location() -> Location {
	// 8 distinct GeneralIndex junctions — fills MAX_JUNCTIONS exactly.
	let interior: Junctions = [
		GeneralIndex(0),
		GeneralIndex(1),
		GeneralIndex(2),
		GeneralIndex(3),
		GeneralIndex(4),
		GeneralIndex(5),
		GeneralIndex(6),
		GeneralIndex(7),
	]
	.into();
	Location::new(0, interior)
}

#[test]
fn try_reanchored_assets_succeeds_when_all_assets_reanchorable() {
	// A trivial fungible asset with `id = Here` reanchors fine against `Parent`.
	let mut holding = AssetsInHolding::new();
	holding.subsume_assets(crate::test_helpers::mock_asset_to_holding((Here, 100u128).into()));

	let dest: Location = Parent.into();
	let result = XcmExecutor::<XcmConfig>::try_reanchored_assets(&holding, &dest);
	assert!(result.is_ok(), "vanilla asset must reanchor fine, got {:?}", result);
	let reanchored = result.unwrap();
	assert_eq!(reanchored.inner().len(), 1, "no assets should be dropped");
}

#[test]
fn try_reanchored_assets_errors_on_overflow() {
	// Place an asset whose id is an 8-junction `Location`. Reanchoring this
	// against `Parent` requires `prepend_with` to push 1 extra junction →
	// final interior len = 9 > MAX_JUNCTIONS=8 → reanchor fails.
	let bad_asset: Asset = (deeply_nested_location(), 1_000u128).into();

	let mut holding = AssetsInHolding::new();
	holding.subsume_assets(crate::test_helpers::mock_asset_to_holding(bad_asset));

	let dest: Location = Parent.into();
	let result = XcmExecutor::<XcmConfig>::try_reanchored_assets(&holding, &dest);
	assert!(
		matches!(result, Err(XcmError::ReanchorFailed)),
		"unreanchorable asset must produce ReanchorFailed (got {:?}); the previous \
		 `reanchored_assets` impl would have silently returned an empty Assets list, \
		 which led to silent value loss in deposit/teleport.",
		result
	);
}

#[test]
fn try_reanchored_assets_errors_when_any_one_asset_fails() {
	// Mix one good asset and one whose id will fail to reanchor — the call
	// must error rather than partially succeed.
	let bad_asset: Asset = (deeply_nested_location(), 1_000u128).into();
	let good_asset: Asset = (Here, 50u128).into();

	let mut holding = AssetsInHolding::new();
	holding.subsume_assets(crate::test_helpers::mock_asset_to_holding(good_asset));
	holding.subsume_assets(crate::test_helpers::mock_asset_to_holding(bad_asset));

	let dest: Location = Parent.into();
	let result = XcmExecutor::<XcmConfig>::try_reanchored_assets(&holding, &dest);
	assert!(
		matches!(result, Err(XcmError::ReanchorFailed)),
		"any single unreanchorable asset must abort the whole call (got {:?}); \
		 silently dropping it would let the caller debit/burn locally without a \
		 matching remote credit.",
		result
	);
}

/// End-to-end: an `InitiateTransfer` whose `remote_fees` filter targets an asset
/// whose id cannot be reanchored against the destination. The executor must
/// surface the failure rather than silently shipping a shrunken
/// `ReserveAssetDeposited` instruction while having credited the full amount
/// locally.
#[test]
fn initiate_transfer_reserve_deposit_fails_loudly_on_reanchor_overflow() {
	// Fund SENDER with both a normal native fee asset and an asset whose id
	// has 8 junctions (will fail to reanchor against `Parent`).
	const SENDER: [u8; 32] = [0; 32];
	let bad_asset: Asset = (deeply_nested_location(), 1_000u128).into();
	add_asset(SENDER, (Here, 100u128));
	add_asset(SENDER, bad_asset.clone());

	// `InitiateTransfer` with remote fees as a `ReserveDeposit` filter that
	// matches the bad asset. This drives `do_reserve_deposit_assets` with the
	// bad asset, hitting the reanchor failure path.
	let xcm_on_dest = Xcm(vec![RefundSurplus]);
	let xcm = Xcm::<TestCall>(vec![
		WithdrawAsset(vec![(Here, 100u128).into(), bad_asset.clone()].into()),
		PayFees { asset: (Here, 10u128).into() },
		InitiateTransfer {
			destination: Parent.into(),
			remote_fees: Some(AssetTransferFilter::ReserveDeposit(Definite(
				vec![bad_asset].into(),
			))),
			preserve_origin: false,
			assets: BoundedVec::new(),
			remote_xcm: xcm_on_dest,
		},
	]);

	let (mut vm, _) = instantiate_executor(SENDER, xcm.clone());
	let result = vm.bench_process(xcm);
	assert!(
		result.is_err(),
		"InitiateTransfer with unreanchorable ReserveDeposit fees must fail loudly, \
		 not silently send a shrunken ReserveAssetDeposited. Got: {:?}",
		result
	);
}

#[test]
fn initiate_transfer_teleport_fails_loudly_on_reanchor_overflow() {
	// Same shape, but Teleport instead of ReserveDeposit. Pre-fix this would
	// have `check_out`'d the bad asset locally (burning it from issuance
	// accounting) without ever minting it on dest — a net issuance break.
	const SENDER: [u8; 32] = [0; 32];
	let bad_asset: Asset = (deeply_nested_location(), 1_000u128).into();
	add_asset(SENDER, (Here, 100u128));
	add_asset(SENDER, bad_asset.clone());

	let xcm_on_dest = Xcm(vec![RefundSurplus]);
	let xcm = Xcm::<TestCall>(vec![
		WithdrawAsset(vec![(Here, 100u128).into(), bad_asset.clone()].into()),
		PayFees { asset: (Here, 10u128).into() },
		InitiateTransfer {
			destination: Parent.into(),
			remote_fees: Some(AssetTransferFilter::Teleport(Definite(vec![bad_asset].into()))),
			preserve_origin: false,
			assets: BoundedVec::new(),
			remote_xcm: xcm_on_dest,
		},
	]);

	let (mut vm, _) = instantiate_executor(SENDER, xcm.clone());
	let result = vm.bench_process(xcm);
	assert!(
		result.is_err(),
		"InitiateTransfer with unreanchorable Teleport fees must fail loudly. Got: {:?}",
		result
	);
}
