// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023 Snowfork <hello@snowfork.com>
use super::Pallet;
use codec::{Decode, Encode, MaxEncodedLen};
use frame_support::traits::ProcessMessage;
use scale_info::TypeInfo;
pub use snowbridge_merkle_tree::MerkleProof;
use sp_core::H256;
use sp_std::prelude::*;
use Debug;

pub type ProcessMessageOriginOf<T> = <Pallet<T> as ProcessMessage>::Origin;

/// Pending order.
///
/// Records the locally-known facts about an outbound message that we will later cross-check
/// against the `InboundMessageDispatched` log emitted by the Ethereum gateway. `topic` is
/// load-bearing for delivery-receipt validation: without it, a relayer could redeem a
/// receipt for nonce `N` against an unrelated message that happened to use the same nonce
/// — this is the missing-binding half of the Hyperbridge bug class. See
/// [`Pallet::process_delivery_receipt`] for the verification.
#[derive(Encode, Decode, TypeInfo, Clone, Eq, PartialEq, Debug, MaxEncodedLen)]
pub struct PendingOrder<BlockNumber> {
	/// The nonce used to identify the message
	pub nonce: u64,
	/// The block number in which the message was committed
	pub block_number: BlockNumber,
	/// The fee in Ether provided by the user to incentivize message delivery
	#[codec(compact)]
	pub fee: u128,
	/// The topic of the outbound message. Pinned at submission time and compared against
	/// the topic in the `InboundMessageDispatched` event when a delivery receipt is
	/// processed; a mismatch rejects the receipt.
	pub topic: H256,
}

/// Hook that will be called when a new message commitment is constructed.
pub trait OnNewCommitment {
	fn on_new_commitment(commitment: H256);
}

impl OnNewCommitment for () {
	fn on_new_commitment(_commitment: H256) {}
}
