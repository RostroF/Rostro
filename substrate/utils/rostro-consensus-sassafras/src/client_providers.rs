// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Client-backed implementations of the provider traits.
//!
//! Production wiring binds [`crate::EpochProvider`],
//! [`crate::TicketProvider`], [`crate::KeyOwnershipProver`],
//! [`crate::EquivocationReporter`], and [`crate::TicketSubmitter`] to
//! a real `Arc<Client>` that implements
//! `sp_api::ProvideRuntimeApi<Block>` with a runtime exposing
//! `SassafrasApi`. Tests use the trait-stub variants.
//!
//! ## Usage
//!
//! ```ignore
//! let client_providers = ClientProviders::<Block, _>::new(client.clone());
//!
//! // Plug into the import-queue verifier:
//! let verifier = SassafrasImportVerifier::new(
//!     client_providers.clone(),  // EpochProvider
//!     client_providers.clone(),  // TicketProvider
//! );
//!
//! // Plug into the ticket-submission worker:
//! let stats = submit_batch::<Block, _>(envelopes, &client_providers).await;
//!
//! // Plug into the equivocation reporter:
//! let outcome = process_equivocation::<Block, _, _>(
//!     proof,
//!     &client_providers,  // KeyOwnershipProver
//!     &client_providers,  // EquivocationReporter
//! )?;
//! ```
//!
//! One struct, all five traits — production calls fan out to the same
//! runtime API client from a single shared handle.
//!
//! ## Why this is a thin file
//!
//! Each impl is a one-line forward to the runtime API. The semantic
//! work — what counts as "valid epoch context", what the ticket
//! cross-check enforces — lives in the trait abstractions and the
//! pure-crypto verifier. This file is the integration boundary
//! between them and the live chain.

use std::{marker::PhantomData, sync::Arc};

use sp_api::ProvideRuntimeApi;
use sp_consensus_sassafras::{
	ticket::{TicketBody, TicketEnvelope, TicketId},
	AuthorityId, Epoch, EquivocationProof, OpaqueKeyOwnershipProof, SassafrasApi, Slot,
};
use sp_runtime::traits::Block as BlockT;

use crate::providers::{
	EpochProvider, EquivocationReporter, KeyOwnershipProver, ProviderError, TicketProvider,
};
use crate::ticket_submission::TicketSubmitter;

/// Aggregate provider implementation backed by a substrate `Client`
/// with `SassafrasApi` runtime API access. One struct implements all
/// five provider traits the rest of the crate consumes.
///
/// `Cheap to clone` (just an Arc bump), so the typical pattern is to
/// construct once at service startup and clone it into each consumer
/// (the verifier, the slot worker, the equivocation reporter, the
/// ticket submitter).
pub struct ClientProviders<Block: BlockT, Client> {
	client: Arc<Client>,
	_phantom: PhantomData<Block>,
}

impl<Block: BlockT, Client> Clone for ClientProviders<Block, Client> {
	fn clone(&self) -> Self {
		Self { client: self.client.clone(), _phantom: PhantomData }
	}
}

impl<Block: BlockT, Client> ClientProviders<Block, Client> {
	/// Construct from a shared `Arc<Client>`. The arc is cheap to
	/// share across all five trait consumers.
	pub fn new(client: Arc<Client>) -> Self {
		Self { client, _phantom: PhantomData }
	}
}

// Map any sp-api / runtime error into our ProviderError shape with a
// uniform error message format.
fn map_runtime_err<E: core::fmt::Debug>(at: &str, err: E) -> ProviderError {
	ProviderError::Runtime(format!("SassafrasApi::{at}: {err:?}"))
}

impl<Block, Client> EpochProvider<Block> for ClientProviders<Block, Client>
where
	Block: BlockT,
	Client: ProvideRuntimeApi<Block> + Send + Sync + 'static,
	Client::Api: SassafrasApi<Block>,
{
	fn epoch_at(&self, parent: Block::Hash) -> Result<Epoch, ProviderError> {
		self.client
			.runtime_api()
			.current_epoch(parent)
			.map_err(|e| map_runtime_err("current_epoch", e))
	}

	fn next_epoch_at(&self, parent: Block::Hash) -> Result<Epoch, ProviderError> {
		self.client
			.runtime_api()
			.next_epoch(parent)
			.map_err(|e| map_runtime_err("next_epoch", e))
	}
}

impl<Block, Client> TicketProvider<Block> for ClientProviders<Block, Client>
where
	Block: BlockT,
	Client: ProvideRuntimeApi<Block> + Send + Sync + 'static,
	Client::Api: SassafrasApi<Block>,
{
	fn slot_ticket(
		&self,
		parent: Block::Hash,
		slot: Slot,
	) -> Result<Option<(TicketId, TicketBody)>, ProviderError> {
		self.client
			.runtime_api()
			.slot_ticket(parent, slot)
			.map_err(|e| map_runtime_err("slot_ticket", e))
	}
}

impl<Block, Client> KeyOwnershipProver<Block> for ClientProviders<Block, Client>
where
	Block: BlockT,
	Client: ProvideRuntimeApi<Block> + Send + Sync + 'static,
	Client::Api: SassafrasApi<Block>,
{
	fn generate_key_ownership_proof(
		&self,
		parent: Block::Hash,
		authority: AuthorityId,
	) -> Result<Option<OpaqueKeyOwnershipProof>, ProviderError> {
		self.client
			.runtime_api()
			.generate_key_ownership_proof(parent, authority)
			.map_err(|e| map_runtime_err("generate_key_ownership_proof", e))
	}
}

impl<Block, Client> EquivocationReporter<Block> for ClientProviders<Block, Client>
where
	Block: BlockT,
	Client: ProvideRuntimeApi<Block> + Send + Sync + 'static,
	Client::Api: SassafrasApi<Block>,
{
	fn submit_report(
		&self,
		proof: EquivocationProof<Block::Header>,
		key_owner_proof: OpaqueKeyOwnershipProof,
	) -> Result<(), ProviderError> {
		// Submit at the best chain head — equivocation reports are
		// not bound to a specific parent state since they're against
		// a session-historical authority. Caller's job to ensure the
		// best-block runtime can validate the proof.
		let best = self.client.runtime_api();
		// `parent` for the runtime API call: callers using this for
		// reports typically don't have a specific parent in mind, so
		// we use a sensible default by following ProvideRuntimeApi's
		// usage pattern — pass the proof's first_header.parent_hash.
		let parent = *sp_runtime::traits::Header::parent_hash(&proof.first_header);
		let submitted = best
			.submit_report_equivocation_unsigned_extrinsic(parent, proof, key_owner_proof)
			.map_err(|e| map_runtime_err("submit_report_equivocation_unsigned_extrinsic", e))?;
		if !submitted {
			return Err(ProviderError::Runtime(
				"submit_report_equivocation_unsigned_extrinsic returned false".into(),
			));
		}
		Ok(())
	}
}

#[async_trait::async_trait]
impl<Block, Client> TicketSubmitter<Block> for ClientProviders<Block, Client>
where
	Block: BlockT,
	Client: ProvideRuntimeApi<Block> + sp_blockchain::HeaderBackend<Block> + Send + Sync + 'static,
	Client::Api: SassafrasApi<Block>,
{
	async fn submit_ticket(&self, envelope: TicketEnvelope) -> Result<(), ProviderError> {
		// Submit via the runtime API at the current best hash. The
		// pallet's validate_unsigned only accepts Local + InBlock
		// sources; when called via the runtime API from our own node,
		// the resulting extrinsic is treated as Local.
		//
		// NOTE: this submission path traverses pallet-sassafras's
		// `submit_tickets_unsigned_extrinsic`, which internally calls
		// `sp_io::offchain::submit_transaction`. From a host-side
		// runtime API call there is no offchain extension registered,
		// so the host fn returns an error which the runtime maps to
		// `false`. R3.5 step 2 will replace this submission path with
		// direct transaction-pool insertion (bypassing the runtime API),
		// which is the substrate idiom for host-side validators
		// submitting their own unsigned extrinsics. For now this stub
		// returns Err on every call; the cryptographic core (envelope
		// generation) is correct and the full pipeline lights up once
		// the submitter is rewired.
		use sp_blockchain::HeaderBackend;
		let best = self.client.info().best_hash;
		let info = self.client.runtime_api();
		let submitted = info
			.submit_tickets_unsigned_extrinsic(best, vec![envelope])
			.map_err(|e| map_runtime_err("submit_tickets_unsigned_extrinsic", e))?;
		if !submitted {
			return Err(ProviderError::Runtime(
				"submit_tickets_unsigned_extrinsic returned false".into(),
			));
		}
		Ok(())
	}
}
