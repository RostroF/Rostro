// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Phase Ring R3.5: epoch-boundary ticket-generation orchestrator.
//!
//! Sassafras's anonymous slot-assignment story rests on validators
//! contributing tickets at the start of each epoch. Tickets are
//! ring-VRF signatures over `(randomness, attempt_idx, epoch_index)`,
//! produced under the validator's bandersnatch key, blinded by the
//! ring of all current epoch authorities. The chain sorts surviving
//! tickets by their VRF-derived id and assigns them to slots.
//!
//! A node without ticket generation falls back to deterministic
//! round-robin slot assignment from the active authority set — block
//! production works, but the anonymity guarantee Sassafras was
//! designed for evaporates. R3.5 closes that gap.
//!
//! ## What this module does
//!
//! Spawns a long-lived async task that:
//!
//! 1. Watches for epoch transitions on each new finalized block.
//! 2. On a new epoch, fetches `current_epoch` (authorities + randomness
//!    + length + config) and `ring_context` from the runtime API.
//! 3. Identifies the operator's bandersnatch authority key (looks up
//!    the keystore for a key in `current_epoch.authorities`).
//! 4. Computes the ticket-id threshold from epoch parameters.
//! 5. For each attempt index in `0..attempts_number`:
//!    - Cheap VRF pre-output (via keystore) to compute the candidate
//!      ticket id.
//!    - If id < threshold, produce a full envelope (ephemeral
//!      ed25519 keypairs + ring-VRF signature via keystore + ring prover).
//! 6. Submits the surviving envelopes through the supplied
//!    [`TicketSubmitter`].
//!
//! ## What this module deliberately doesn't do
//!
//! - **Ephemeral key persistence.** Each attempt gets fresh random
//!   ed25519 erased + revealed keypairs. The erased private key needs
//!   to reappear at slot-claim time to produce the binding signature
//!   — that persistence layer lives separately (next R3.5 follow-up,
//!   tied to slot_claim.rs's signing path).
//! - **Peer-relay anonymity submission.** The trait is generic over
//!   [`TicketSubmitter`]; the local-mempool implementation in
//!   `client_providers::ClientProviders` is what we wire in v0. The
//!   peer-relay path (rostro-ratchet authenticated channel to a
//!   peer's mempool, preserving the (validator, ticket-source) cut)
//!   plugs in via the same trait — its own session.
//! - **Per-block ticket-claim verification.** That's the import-queue's
//!   responsibility (`import_verifier.rs`). This module is producer-side
//!   only.

use std::sync::Arc;
use std::time::Duration;

use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_consensus_sassafras::{
	ticket::{TicketBody, TicketEnvelope},
	vrf::{make_ticket_id, ticket_body_sign_data, ticket_id_input},
	AuthorityId, Epoch, SassafrasApi,
};
use sp_core::{bandersnatch, ed25519, Pair};
use sp_keystore::{Keystore, KeystorePtr};
use sp_runtime::traits::Block as BlockT;

use crate::ticket_submission::{
	ticket_threshold, SubmissionStats, TicketSubmitter, TicketThresholdParams,
};

/// How often the worker re-checks for epoch transitions. Faster than
/// the slot duration so we don't miss the epoch-boundary window in
/// which tickets are useful — the chain accepts tickets only during a
/// portion of each epoch (per pallet-sassafras's
/// `submit_tickets_period`). 6s matches the chain's slot duration; one
/// poll per slot is sufficient and cheap.
const POLL_INTERVAL: Duration = Duration::from_secs(6);

/// Build the ticket-generation worker as a future. The caller spawns
/// it onto its own task runtime — typically `task_manager.spawn_handle()`
/// in gemini-node. We don't take a `SpawnTaskHandle` directly because
/// that would pull `rc-service` (GPL-3.0) into this Apache-2.0 crate's
/// dependency tree.
///
/// Returns a future that runs forever (loops until the runtime drops
/// it). Generic over the substrate Client (for the runtime API), the
/// Block type, and a `TicketSubmitter` impl.
pub async fn run<Client, Block, Submitter>(
	client: Arc<Client>,
	keystore: KeystorePtr,
	submitter: Arc<Submitter>,
) where
	Block: BlockT,
	Client: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
	Client::Api: SassafrasApi<Block>,
	Submitter: TicketSubmitter<Block> + 'static,
{
	let mut last_epoch_index: Option<u64> = None;
	loop {
		match try_round(&*client, &keystore, &*submitter, last_epoch_index).await {
			Ok(EpochOutcome::SkippedSameEpoch) => {}
			Ok(EpochOutcome::Generated { epoch_index, stats }) => {
				last_epoch_index = Some(epoch_index);
				log::info!(
					target: "rostro-sassafras-ticket-worker",
					"epoch {epoch_index}: generated {stats:?}",
				);
			}
			Ok(EpochOutcome::NotAuthority) => {
				// We hold no key matching the active authority set.
				// Nothing to do until either we install a matching key
				// OR the active set rotates to one of ours.
			}
			Err(err) => {
				log::warn!(
					target: "rostro-sassafras-ticket-worker",
					"round error: {err}; will retry in {POLL_INTERVAL:?}",
				);
			}
		}
		tokio::time::sleep(POLL_INTERVAL).await;
	}
}

#[derive(Debug)]
enum EpochOutcome {
	SkippedSameEpoch,
	NotAuthority,
	Generated { epoch_index: u64, stats: SubmissionStats },
}

/// Single poll iteration. Returns immediately if epoch hasn't changed
/// or if the operator isn't in the active set. On a new epoch where the
/// operator IS an authority, generates + submits tickets.
async fn try_round<Client, Block, Submitter>(
	client: &Client,
	keystore: &KeystorePtr,
	submitter: &Submitter,
	last_epoch_index: Option<u64>,
) -> Result<EpochOutcome, String>
where
	Block: BlockT,
	Client: ProvideRuntimeApi<Block> + HeaderBackend<Block>,
	Client::Api: SassafrasApi<Block>,
	Submitter: TicketSubmitter<Block>,
{
	let best = client.info().best_hash;
	let api = client.runtime_api();

	let epoch: Epoch = api
		.current_epoch(best)
		.map_err(|e| format!("current_epoch: {e:?}"))?;
	let epoch_index = epoch_index_from(&epoch);

	if last_epoch_index == Some(epoch_index) {
		return Ok(EpochOutcome::SkippedSameEpoch);
	}

	// Find which authority slot we hold a key for. The keystore's
	// bandersnatch_public_keys returns raw bandersnatch::Public; the
	// epoch's authorities list returns the wrapped app::Public. Compare
	// by 32-byte representation.
	let local_keys = keystore.bandersnatch_public_keys(sp_consensus_sassafras::KEY_TYPE);
	let our_idx_pub = match find_authority(&epoch.authorities, &local_keys) {
		Some(p) => p,
		None => return Ok(EpochOutcome::NotAuthority),
	};

	// Compute threshold from epoch parameters.
	let threshold_params = TicketThresholdParams {
		redundancy_factor: epoch.config.redundancy_factor,
		attempts_number: epoch.config.attempts_number,
		epoch_length: epoch.length,
		validator_count: epoch.authorities.len() as u32,
	};
	let threshold = ticket_threshold(&threshold_params);

	// Fetch ring context. Required to construct the RingProver that
	// blinds our ring-VRF signature behind the full authority set.
	let ring_context = api
		.ring_context(best)
		.map_err(|e| format!("ring_context: {e:?}"))?
		.ok_or_else(|| "ring_context returned None".to_string())?;

	// Build the prover. The unwrapped bandersnatch::Public list is what
	// the prover wants — convert from app::Public via byte ref.
	let public_keys: Vec<bandersnatch::Public> = epoch
		.authorities
		.iter()
		.map(authority_to_bandersnatch)
		.collect();
	let our_idx = public_keys
		.iter()
		.position(|k| k == &our_idx_pub)
		.ok_or_else(|| "internal: our key not in derived public_keys".to_string())?;
	let ring_prover = ring_context.prover(&public_keys, our_idx);

	// Iterate attempts, filter by threshold, build envelopes for survivors.
	let mut envelopes = Vec::new();
	for attempt_idx in 0..epoch.config.attempts_number {
		let id_input = ticket_id_input(&epoch.randomness, attempt_idx, epoch_index);
		let pre_output = match keystore
			.bandersnatch_vrf_pre_output(
				sp_consensus_sassafras::KEY_TYPE,
				&our_idx_pub,
				&id_input,
			)
			.map_err(|e| format!("vrf_pre_output: {e:?}"))?
		{
			Some(o) => o,
			None => {
				return Err("keystore had key public but couldn't sign — race?".into());
			}
		};
		let candidate_id = make_ticket_id(&pre_output);
		if candidate_id >= threshold {
			continue;
		}

		// Survives the threshold filter. Build the full envelope.
		let erased_pair = ed25519::Pair::generate().0;
		let revealed_pair = ed25519::Pair::generate().0;
		let body = TicketBody {
			attempt_idx,
			erased_public: erased_pair.public(),
			revealed_public: revealed_pair.public(),
		};
		let sign_data = ticket_body_sign_data(&body, id_input);
		let signature = match keystore
			.bandersnatch_ring_vrf_sign(
				sp_consensus_sassafras::KEY_TYPE,
				&our_idx_pub,
				&sign_data,
				&ring_prover,
			)
			.map_err(|e| format!("ring_vrf_sign: {e:?}"))?
		{
			Some(sig) => sig,
			None => return Err("ring_vrf_sign: keystore returned None".into()),
		};
		envelopes.push(TicketEnvelope { body, signature });
	}

	// Submit the batch. submit_batch's stats let us telemetry-log
	// per-epoch effort vs. effective contribution.
	let stats = crate::ticket_submission::submit_batch::<Block, _>(envelopes, submitter).await;
	Ok(EpochOutcome::Generated { epoch_index, stats })
}

/// Convert an app-wrapped Sassafras `AuthorityId` to the raw
/// `bandersnatch::Public`. They share byte representation; this just
/// re-types.
fn authority_to_bandersnatch(auth: &AuthorityId) -> bandersnatch::Public {
	let bytes: [u8; 32] = AsRef::<[u8]>::as_ref(auth)
		.try_into()
		.expect("AuthorityId is 32 bytes; qed");
	bandersnatch::Public::from_raw(bytes)
}

/// Compare local bandersnatch keys against the epoch's authority list.
/// Returns the matching `bandersnatch::Public` if exactly one of our
/// local keys is in the active set; `None` if no match.
fn find_authority(
	authorities: &[AuthorityId],
	local_keys: &[bandersnatch::Public],
) -> Option<bandersnatch::Public> {
	for auth in authorities {
		let auth_bytes: &[u8] = auth.as_ref();
		for local in local_keys {
			let local_bytes: &[u8] = local.as_ref();
			if auth_bytes == local_bytes {
				return Some(*local);
			}
		}
	}
	None
}

/// The chain encodes "epoch index" as start_slot / epoch_length. We
/// reproduce that derivation here rather than asking the runtime API
/// for it explicitly (the API exposes the parts but not the index).
fn epoch_index_from(epoch: &Epoch) -> u64 {
	let start: u64 = (*epoch.start).into();
	let length = epoch.length as u64;
	if length == 0 {
		// Defensive: a zero-length epoch is malformed but shouldn't
		// crash the worker. Treat as "no epoch index"; caller sees a
		// fresh epoch each round and re-submits tickets, which is
		// wasteful but not unsafe.
		return 0;
	}
	start / length
}
