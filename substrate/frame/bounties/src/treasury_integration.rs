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

//! Treasury integration for the bounties pallet.
//!
//! This file contains the `pallet_treasury::SpendFunds` impl that lets pallet-treasury
//! drive bounty funding during its spend periods. It is intentionally separated from
//! `lib.rs` so bounties' core logic stays decoupled from `pallet_treasury::Config` —
//! the integration lives behind one explicit `mod` line.
//!
//! For this impl to type-check, the runtime must wire the same `Currency` to
//! `<T as pallet_bounties::Config<I>>::Currency` as it does to
//! `<T as pallet_treasury::Config<I>>::Currency`. All current Substrate runtimes do this.

use crate::{pallet, Bounties, BountyApprovals, BountyStatus, Config, Event, Pallet, WeightInfo};
use frame_support::weights::Weight;
use sp_runtime::traits::Zero;

impl<T, I: 'static> pallet_treasury::SpendFunds<T, I> for Pallet<T, I>
where
	T: Config<
			I,
			Currency = <T as pallet_treasury::Config<I>>::Currency,
		> + pallet_treasury::Config<I>,
{
	fn spend_funds(
		budget_remaining: &mut pallet_treasury::BalanceOf<T, I>,
		imbalance: &mut pallet_treasury::PositiveImbalanceOf<T, I>,
		total_weight: &mut Weight,
		missed_any: &mut bool,
	) {
		use frame_support::traits::{Currency, Imbalance, ReservableCurrency};
		let bounties_len = BountyApprovals::<T, I>::mutate(|v| {
			let bounties_approval_len = v.len() as u32;
			v.retain(|&index| {
				Bounties::<T, I>::mutate(index, |bounty| {
					if let Some(bounty) = bounty {
						if bounty.value <= *budget_remaining {
							*budget_remaining -= bounty.value;

							if let BountyStatus::ApprovedWithCurator { curator } = &bounty.status {
								bounty.status =
									BountyStatus::CuratorProposed { curator: curator.clone() };
							} else {
								bounty.status = BountyStatus::Funded;
							}

							let err_amount =
								<T as Config<I>>::Currency::unreserve(&bounty.proposer, bounty.bond);
							debug_assert!(err_amount.is_zero());

							imbalance.subsume(<T as Config<I>>::Currency::deposit_creating(
								&Pallet::<T, I>::bounty_account_id(index),
								bounty.value,
							));

							Pallet::<T, I>::deposit_event(Event::<T, I>::BountyBecameActive {
								index,
							});
							false
						} else {
							*missed_any = true;
							true
						}
					} else {
						false
					}
				})
			});
			bounties_approval_len
		});

		*total_weight += <T as pallet::Config<I>>::WeightInfo::spend_funds(bounties_len);
	}
}
