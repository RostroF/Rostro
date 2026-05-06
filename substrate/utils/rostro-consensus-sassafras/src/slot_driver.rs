// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Async slot worker — the substrate-side block production driver.
//!
//! Wraps R2.5c's pure-logic [`crate::try_claim_slot`] in an
//! [`rc_consensus_slots::SimpleSlotWorker`] implementation that
//! integrates with substrate's slot-tracking, proposer, and
//! block-import infrastructure. Drop-in replacement for
//! `rc_consensus_aura::start_aura` in a node service that wants
//! Sassafras consensus.
//!
//! ## What [`start_sassafras`] does
//!
//! 1. Spawns a slot-driving loop that fires once per slot duration.
//! 2. Per slot, calls [`SimpleSlotWorker::aux_data`] to fetch the
//!    epoch via `SassafrasApi::current_epoch` runtime call.
//! 3. Calls [`SimpleSlotWorker::claim_slot`] which:
//!    a. finds the local authority's bandersnatch key in the keystore
//!    b. queries `SassafrasApi::slot_ticket(slot)` for the bound ticket
//!    c. calls [`crate::try_claim_slot`] with all of the above
//!    d. returns `Some(SassafrasClaim)` if the local authority is the
//!       primary or fallback producer for this slot, else `None`
//! 4. If claimed, drives the [`Proposer`] to build a block with the
//!    SlotClaim attached as a `PreRuntime(SASS, _)` digest.
//! 5. Signs the block hash with the bandersnatch key for the
//!    `Seal(SASS, _)` digest, imports the block.
//!
//! ## Authority key lookup
//!
//! Validators store their bandersnatch keypair in the substrate
//! keystore under [`sp_consensus_sassafras::KEY_TYPE`]. On every
//! slot, [`find_local_authority`] walks the epoch's authority list
//! and asks the keystore "do you have any of these?" — the first
//! match becomes the local authority for that slot.
//!
//! ## Erased-secret lookup (ticket binding)
//!
//! Ticket-bound primary slots require the validator to also hold the
//! erased ed25519 ephemeral secret matching the bound ticket's
//! `erased_public`. v1 of this driver returns `None` from the
//! erased-secret lookup, which means primary-ticket claims never fire
//! and validators only claim slots via the fallback rule. Wiring
//! erased-secret persistence is R3.5's job (the ticket-generation
//! worker generates the ephemeral pairs at epoch start and stashes
//! them locally).

use std::{marker::PhantomData, pin::Pin, sync::Arc, time::Duration};

use codec::Encode;
use futures::{future::Future, FutureExt, TryFutureExt};
use rc_client_api::backend::AuxStore;
use rc_consensus::{
	BlockImport, BlockImportParams, ForkChoiceStrategy, JustificationSyncLink, StateAction,
	StorageChanges,
};
use rc_consensus_slots::{
	BackoffAuthoringBlocksStrategy, InherentDataProviderExt, SimpleSlotWorker, SlotInfo,
	SlotProportion, StorageChanges as SlotStorageChanges,
};
use sp_consensus_slots::SlotDuration;
use rc_telemetry::TelemetryHandle;
use sp_api::ProvideRuntimeApi;
use sp_application_crypto::AppCrypto;
use sp_blockchain::HeaderBackend;
use sp_consensus::{Environment, Error as ConsensusError, Proposer, SelectChain, SyncOracle};
use sp_consensus_sassafras::{
	digests::SlotClaim, AuthorityId, AuthorityIndex, AuthoritySignature, Epoch, SassafrasApi,
	Slot, SASSAFRAS_ENGINE_ID,
};
use sp_core::crypto::ByteArray;
use sp_inherents::CreateInherentDataProviders;
use sp_keystore::{Keystore, KeystorePtr};
use sp_runtime::{
	traits::{Block as BlockT, Header as HeaderT, NumberFor},
	DigestItem,
};

use crate::{epoch::EpochContext, signer::KeystoreSigner, slot_worker::ClaimDecision};

const LOG_TARGET: &str = "sassafras";

// ─── Claim type ────────────────────────────────────────────────────────────

/// Bundle returned by `claim_slot` when the local authority is the
/// chosen producer for a slot.
#[derive(Clone, Debug)]
pub struct SassafrasClaim {
	/// Local authority's index in the epoch's authority list.
	pub authority_idx: AuthorityIndex,
	/// Pre-runtime digest payload attached to the produced block.
	pub slot_claim: SlotClaim,
	/// The local authority's bandersnatch public — used for the
	/// keystore `sign_with` lookup at seal time.
	pub local_authority: AuthorityId,
}

// ─── Worker struct ─────────────────────────────────────────────────────────

/// Sassafras consensus slot worker. Constructed via [`start_sassafras`];
/// the struct itself isn't directly exported because its type
/// parameters get unwieldy.
struct SassafrasWorker<B: BlockT, C, E, I, SO, L, BS> {
	client: Arc<C>,
	block_import: I,
	env: E,
	keystore: KeystorePtr,
	sync_oracle: SO,
	justification_sync_link: L,
	force_authoring: bool,
	backoff_authoring_blocks: Option<BS>,
	block_proposal_slot_portion: SlotProportion,
	max_block_proposal_slot_portion: Option<SlotProportion>,
	telemetry: Option<TelemetryHandle>,
	_phantom: PhantomData<B>,
}

// ─── Public entry point ────────────────────────────────────────────────────

/// Configuration for [`start_sassafras`].
pub struct StartSassafrasParams<B: BlockT, C, SC, I, PF, SO, L, CIDP, BS> {
	/// The slot duration (constant per chain).
	pub slot_duration: SlotDuration,
	/// Substrate client handle (provides runtime API access).
	pub client: Arc<C>,
	/// Chain selector, supplies the head block to author atop.
	pub select_chain: SC,
	/// Block import pipeline.
	pub block_import: I,
	/// Proposer factory.
	pub proposer_factory: PF,
	/// Sync oracle — pauses authoring while the node is still syncing.
	pub sync_oracle: SO,
	/// Justification-sync hook for GRANDPA integration.
	pub justification_sync_link: L,
	/// Inherent data provider factory; produces timestamp + slot for each block.
	pub create_inherent_data_providers: CIDP,
	/// Force authoring even when the node thinks it's offline (testbed only).
	pub force_authoring: bool,
	/// Optional backoff strategy when finalization is lagging.
	pub backoff_authoring_blocks: Option<BS>,
	/// Substrate keystore for the bandersnatch authority key.
	pub keystore: KeystorePtr,
	/// Fraction of slot duration allocated to block proposal.
	pub block_proposal_slot_portion: SlotProportion,
	/// Optional cap on block-proposal duration extension.
	pub max_block_proposal_slot_portion: Option<SlotProportion>,
	/// Telemetry handle.
	pub telemetry: Option<TelemetryHandle>,
	/// Phantom marker for the block type (B is otherwise unused at the
	/// struct level; it's reified by the worker constructed inside).
	pub _phantom: PhantomData<B>,
}

/// Start the Sassafras consensus worker. Returns a future that runs
/// until the slot stream ends.
///
/// `Error` is the proposer-factory's error type. Substrate's standard
/// `BasicAuthorship` factory uses `sp_blockchain::Error`; the worker
/// internally maps any such error into [`sp_consensus::Error`] for
/// the SimpleSlotWorker contract. The `From<ConsensusError>` bound
/// gives us a clean conversion path without the caller having to
/// fight type aliases.
pub fn start_sassafras<B, C, SC, I, PF, SO, L, CIDP, BS, Error>(
	params: StartSassafrasParams<B, C, SC, I, PF, SO, L, CIDP, BS>,
) -> Result<impl Future<Output = ()> + Send, ConsensusError>
where
	B: BlockT,
	C: ProvideRuntimeApi<B> + AuxStore + HeaderBackend<B> + Send + Sync + 'static,
	C::Api: SassafrasApi<B>,
	SC: SelectChain<B>,
	I: BlockImport<B> + Send + Sync + 'static,
	PF: Environment<B, Error = Error> + Send + Sync + 'static,
	PF::Proposer: Proposer<B, Error = Error>,
	SO: SyncOracle + Send + Sync + Clone,
	L: JustificationSyncLink<B>,
	CIDP: CreateInherentDataProviders<B, ()> + Send + Sync + 'static,
	CIDP::InherentDataProviders: InherentDataProviderExt + Send,
	BS: BackoffAuthoringBlocksStrategy<NumberFor<B>> + Send + Sync + 'static,
	Error: std::error::Error + Send + From<ConsensusError> + 'static,
{
	let StartSassafrasParams {
		slot_duration,
		client,
		select_chain,
		block_import,
		proposer_factory,
		sync_oracle,
		justification_sync_link,
		create_inherent_data_providers,
		force_authoring,
		backoff_authoring_blocks,
		keystore,
		block_proposal_slot_portion,
		max_block_proposal_slot_portion,
		telemetry,
		_phantom,
	} = params;
	let _ = _phantom;

	let worker = SassafrasWorker::<B, _, _, _, _, _, _> {
		client: client.clone(),
		block_import,
		env: proposer_factory,
		keystore,
		sync_oracle: sync_oracle.clone(),
		justification_sync_link,
		force_authoring,
		backoff_authoring_blocks,
		block_proposal_slot_portion,
		max_block_proposal_slot_portion,
		telemetry,
		_phantom: PhantomData,
	};

	Ok(rc_consensus_slots::start_slot_worker(
		slot_duration,
		select_chain,
		rc_consensus_slots::SimpleSlotWorkerToSlotWorker(worker),
		sync_oracle,
		create_inherent_data_providers,
	))
}

// ─── SimpleSlotWorker impl ─────────────────────────────────────────────────

#[async_trait::async_trait]
impl<B, C, E, I, SO, L, BS, Error> SimpleSlotWorker<B>
	for SassafrasWorker<B, C, E, I, SO, L, BS>
where
	B: BlockT,
	C: ProvideRuntimeApi<B> + HeaderBackend<B> + Send + Sync,
	C::Api: SassafrasApi<B>,
	E: Environment<B, Error = Error> + Send + Sync,
	E::Proposer: Proposer<B, Error = Error>,
	I: BlockImport<B> + Send + Sync + 'static,
	SO: SyncOracle + Send + Clone + Sync,
	L: JustificationSyncLink<B>,
	BS: BackoffAuthoringBlocksStrategy<NumberFor<B>> + Send + Sync + 'static,
	Error: std::error::Error + Send + From<ConsensusError> + 'static,
{
	type BlockImport = I;
	type SyncOracle = SO;
	type JustificationSyncLink = L;
	type CreateProposer =
		Pin<Box<dyn Future<Output = Result<E::Proposer, ConsensusError>> + Send + 'static>>;
	type Proposer = E::Proposer;
	type Claim = SassafrasClaim;
	type AuxData = Epoch;

	fn logging_target(&self) -> &'static str {
		LOG_TARGET
	}

	fn block_import(&mut self) -> &mut Self::BlockImport {
		&mut self.block_import
	}

	fn aux_data(
		&self,
		header: &B::Header,
		_slot: Slot,
	) -> Result<Self::AuxData, ConsensusError> {
		let parent = header.hash();
		self.client
			.runtime_api()
			.current_epoch(parent)
			.map_err(|e| ConsensusError::ChainLookup(format!("SassafrasApi::current_epoch: {e:?}")))
	}

	fn authorities_len(&self, epoch: &Self::AuxData) -> Option<usize> {
		Some(epoch.authorities.len())
	}

	async fn claim_slot(
		&mut self,
		header: &B::Header,
		slot: Slot,
		epoch: &Self::AuxData,
	) -> Option<Self::Claim> {
		let (authority_idx, authority_pub) =
			find_local_authority(&self.keystore, &epoch.authorities)?;

		let parent = header.hash();
		let client = self.client.clone();

		let ticket_lookup = |s: Slot| client.runtime_api().slot_ticket(parent, s).ok().flatten();

		// v1: erased secrets are not yet persisted by R3.5's ticket-generation
		// worker, so primary-ticket claims never fire — only fallback path.
		let erased_lookup = |_body: &sp_consensus_sassafras::TicketBody| None;

		let ctx = EpochContext {
			index: epoch.index,
			randomness: &epoch.randomness,
			authorities: &epoch.authorities,
		};

		let signer = KeystoreSigner { keystore: &self.keystore, authority: &authority_pub };

		let decision = crate::slot_worker::try_claim_slot(
			slot,
			ctx,
			authority_idx,
			&signer,
			ticket_lookup,
			erased_lookup,
		);

		match decision {
			ClaimDecision::Primary { authority_idx, claim } |
			ClaimDecision::Fallback { authority_idx, claim } => {
				log::debug!(
					target: LOG_TARGET,
					"local authority {} claimed slot {}",
					authority_idx,
					slot
				);
				Some(SassafrasClaim {
					authority_idx,
					slot_claim: claim,
					local_authority: authority_pub,
				})
			},
			ClaimDecision::NotMyTurn => None,
		}
	}

	fn pre_digest_data(&self, _slot: Slot, claim: &Self::Claim) -> Vec<DigestItem> {
		vec![DigestItem::from(&claim.slot_claim)]
	}

	async fn block_import_params(
		&self,
		header: B::Header,
		header_hash: &B::Hash,
		body: Vec<B::Extrinsic>,
		storage_changes: SlotStorageChanges<B>,
		claim: Self::Claim,
		_aux: Self::AuxData,
	) -> Result<BlockImportParams<B>, ConsensusError> {
		// Sign the block hash with the local authority's bandersnatch key
		// to produce the SASS Seal digest.
		let seal = sign_seal(&self.keystore, header_hash, &claim.local_authority)?;

		let mut params = BlockImportParams::new(sp_consensus::BlockOrigin::Own, header);
		params.post_digests.push(seal);
		params.body = Some(body);
		params.state_action =
			StateAction::ApplyChanges(StorageChanges::Changes(storage_changes));
		params.fork_choice = Some(ForkChoiceStrategy::LongestChain);
		Ok(params)
	}

	fn force_authoring(&self) -> bool {
		self.force_authoring
	}

	fn should_backoff(&self, slot: Slot, chain_head: &B::Header) -> bool {
		if let Some(ref strategy) = self.backoff_authoring_blocks {
			// We can't recover the chain-head's slot cheaply (would need
			// to decode the SASS pre-digest); pass the requested slot
			// twice as both a "current slot" and a "head slot" hint.
			// Backoff strategies that care will re-derive head slot
			// from the header digest.
			return strategy.should_backoff(
				*chain_head.number(),
				slot,
				self.client.info().finalized_number,
				slot,
				self.logging_target(),
			);
		}
		false
	}

	fn sync_oracle(&mut self) -> &mut Self::SyncOracle {
		&mut self.sync_oracle
	}

	fn justification_sync_link(&mut self) -> &mut Self::JustificationSyncLink {
		&mut self.justification_sync_link
	}

	fn proposer(&mut self, block: &B::Header) -> Self::CreateProposer {
		self.env
			.init(block)
			.map_err(|e| ConsensusError::ClientImport(format!("{e:?}")))
			.boxed()
	}

	fn telemetry(&self) -> Option<TelemetryHandle> {
		self.telemetry.clone()
	}

	fn proposing_remaining_duration(&self, slot_info: &SlotInfo<B>) -> Duration {
		rc_consensus_slots::proposing_remaining_duration(
			None,
			slot_info,
			&self.block_proposal_slot_portion,
			self.max_block_proposal_slot_portion.as_ref(),
			rc_consensus_slots::SlotLenienceType::Exponential,
			self.logging_target(),
		)
	}
}

// ─── Helpers ───────────────────────────────────────────────────────────────

/// Walk the epoch's authority list and find the first one whose
/// bandersnatch key is present in the local keystore. Returns the
/// authority's index in the list and its public key — both fed into
/// the keystore-backed signer for VRF signing and into the seal-
/// signing helper.
fn find_local_authority(
	keystore: &KeystorePtr,
	authorities: &[AuthorityId],
) -> Option<(AuthorityIndex, AuthorityId)> {
	for (idx, candidate) in authorities.iter().enumerate() {
		if Keystore::has_keys(
			keystore.as_ref(),
			&[(candidate.to_raw_vec(), <AuthorityId as AppCrypto>::ID)],
		) {
			return Some((idx as AuthorityIndex, candidate.clone()));
		}
	}
	None
}

/// Sign the block hash with the local authority's bandersnatch key
/// for the SASS Seal digest item. Returns a `DigestItem::Seal(SASS,
/// signature_bytes)`.
fn sign_seal<Hash>(
	keystore: &KeystorePtr,
	header_hash: &Hash,
	authority: &AuthorityId,
) -> Result<DigestItem, ConsensusError>
where
	Hash: AsRef<[u8]>,
{
	let raw = Keystore::sign_with(
		keystore.as_ref(),
		<AuthorityId as AppCrypto>::ID,
		<AuthorityId as AppCrypto>::CRYPTO_ID,
		authority.as_slice(),
		header_hash.as_ref(),
	)
	.map_err(|e| ConsensusError::CannotSign(format!("keystore sign: {e:?}")))?
	.ok_or_else(|| {
		ConsensusError::CannotSign(format!(
			"keystore returned no signature for authority {authority:?}"
		))
	})?;

	let signature = AuthoritySignature::try_from(raw)
		.map_err(|_| ConsensusError::InvalidAuthoritiesSet)?;

	Ok(DigestItem::Seal(SASSAFRAS_ENGINE_ID, signature.encode()))
}
