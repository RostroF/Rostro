// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Substrate-side ticket submission via the local transaction pool.
//!
//! ## Why this exists
//!
//! The `TicketSubmitter` impl in
//! `rostro-consensus-sassafras::client_providers::ClientProviders`
//! routes tickets through the runtime API
//! (`SassafrasApi::submit_tickets_unsigned_extrinsic`). That path
//! works for an offchain worker because the offchain extension is
//! registered in the WASM execution context — the pallet's call to
//! `sp_io::offchain::submit_transaction` succeeds.
//!
//! Our ticket-generation worker runs **host-side** (Phase Ring R3.5
//! step 2). Host-side runtime API calls do not register an offchain
//! extension, so the same submission path returns an error which the
//! runtime maps to `false`. End-to-end smoke proved this: 32/32
//! envelopes failed per epoch.
//!
//! This module provides the host-side equivalent: construct the
//! `UncheckedExtrinsic` directly, push it to substrate's transaction
//! pool with `TransactionSource::Local`. The pallet's
//! `validate_unsigned` accepts Local and InBlock sources, so the
//! ticket lands in the local mempool and gets included in a
//! subsequent block.
//!
//! ## Why it's gemini-node-specific (lives here, not in
//! rostro-consensus-sassafras)
//!
//! Constructing the extrinsic requires `gemini_runtime::RuntimeCall`,
//! `UncheckedExtrinsic`, and `Runtime` — types that exist in the
//! specific runtime, not in the generic consensus client crate. A
//! different runtime (camino-runtime, rostro-runtime, …) would need
//! its own equivalent. The Apache-2.0 `TicketSubmitter` trait stays
//! generic; this is the gemini-runtime concrete impl.

use std::sync::Arc;

use async_trait::async_trait;
use codec::Encode;
use frame_support::pallet_prelude::ConstU32;
use frame_support::BoundedVec;
use rc_transaction_pool_api::{TransactionPool, TransactionSource};
use rostro_consensus_sassafras::providers::ProviderError;
use rostro_consensus_sassafras::ticket_submission::TicketSubmitter;
use sp_blockchain::HeaderBackend;
use sp_consensus_sassafras::ticket::TicketEnvelope;
use sp_runtime::OpaqueExtrinsic;

use gemini_runtime::{opaque::Block as OpaqueBlock, Runtime, RuntimeCall, UncheckedExtrinsic};

/// `TicketSubmitter` impl that pushes envelopes directly to the
/// substrate transaction pool. Compose with the gemini-node's running
/// `TransactionPoolHandle` and a `Client` (for `best_hash`).
pub struct PoolTicketSubmitter<Pool, Client> {
	pool: Arc<Pool>,
	client: Arc<Client>,
}

impl<Pool, Client> PoolTicketSubmitter<Pool, Client> {
	pub fn new(pool: Arc<Pool>, client: Arc<Client>) -> Self {
		Self { pool, client }
	}
}

#[async_trait]
impl<Pool, Client> TicketSubmitter<OpaqueBlock> for PoolTicketSubmitter<Pool, Client>
where
	Pool: TransactionPool<Block = OpaqueBlock> + 'static,
	Client: HeaderBackend<OpaqueBlock> + Send + Sync + 'static,
{
	async fn submit_ticket(&self, envelope: TicketEnvelope) -> Result<(), ProviderError> {
		// Wrap the single envelope in the bounded vec the pallet expects.
		// pallet-sassafras's `submit_tickets` takes
		// `BoundedVec<TicketEnvelope, EpochLengthFor<T>>`. EpochLength
		// in gemini-runtime is the number of slots per epoch — well
		// above 1, so a single-entry batch always fits. We keep the
		// batch size at 1 for simplicity; a future iteration can
		// coalesce multiple envelopes per submission to amortize the
		// per-extrinsic dispatch cost.
		//
		// We use a generous ConstU32 here rather than the runtime's
		// EpochLengthFor associated type because BoundedVec's bound is
		// only used for length-checking on insertion; the runtime
		// recomputes the bound on decode anyway.
		let tickets: BoundedVec<TicketEnvelope, ConstU32<1024>> =
			BoundedVec::try_from(alloc::vec![envelope])
				.map_err(|_| ProviderError::Runtime("ticket batch overflow".into()))?;

		// Construct the unsigned extrinsic. `submit_tickets` takes
		// `BoundedVec<_, EpochLengthFor<T>>`; we convert via decode/encode
		// at the call site to satisfy the type bounds without naming
		// the runtime's exact EpochLength constant here.
		//
		// Encode our unbounded-typed batch as bytes, decode as the
		// runtime's exact-bounded type. Both encodings are identical
		// — `BoundedVec<T, B>::encode == Vec<T>::encode` — so this is
		// just a typecheck dance at the codec layer.
		let encoded_tickets = tickets.encode();
		let runtime_tickets = codec::Decode::decode(&mut &encoded_tickets[..])
			.map_err(|e| ProviderError::Runtime(format!("ticket bound decode: {e}")))?;

		let call: RuntimeCall = pallet_sassafras::Call::<Runtime>::submit_tickets {
			tickets: runtime_tickets,
		}
		.into();
		let xt = UncheckedExtrinsic::new_bare(call);

		// The pool's Block type is `opaque::Block`, whose Extrinsic is
		// `OpaqueExtrinsic` (just SCALE-encoded bytes). Round-trip the
		// runtime's `UncheckedExtrinsic` through SCALE → OpaqueExtrinsic
		// to satisfy the type. The pool's validate_unsigned dispatches
		// it back through the runtime, which decodes from these bytes
		// using the same `UncheckedExtrinsic` type — so the round-trip
		// is lossless.
		let bytes = xt.encode();
		let opaque_xt = OpaqueExtrinsic::from_bytes(&bytes)
			.map_err(|e| ProviderError::Runtime(format!("opaque encode: {e}")))?;

		let best = self.client.info().best_hash;
		self.pool
			.submit_one(best, TransactionSource::Local, opaque_xt)
			.await
			.map(|_| ())
			.map_err(|e| ProviderError::Runtime(format!("pool submit: {e:?}")))
	}
}

extern crate alloc;
