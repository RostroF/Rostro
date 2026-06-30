// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! `/rostro/chat-spend/1` — anti-entropy reconciliation of the per-epoch
//! witnessed-spend set (chat-spend-witness Phase 3).
//!
//! Each node holds a [`SpendStore`] of the witnessed [`SpendRecord`]s for the
//! current membership epoch, plus the accumulator root over them. This protocol
//! keeps those stores convergent across the chat fabric so every node's spent-set
//! is globally visible (the basis for the round-robin defence; the round-robin
//! *block* itself is the deterministic committee, wired in Phase 4).
//!
//! Modelled on `/rostro/chat-anti-entropy/1`: request carries `(epoch, root)`,
//! the responder answers `Match`, `Mismatch { records }`, or `EpochSkew`. On a
//! mismatch the initiator validates each unseen record against the epoch's RNS
//! guard set ([`verify_record`]) before merging, so a forged or malformed record
//! never enters the store.

use std::sync::Arc;
use std::time::Duration;

use codec::{Decode, Encode};
use futures::StreamExt;
use parking_lot::Mutex;
use rand_core::{OsRng, RngCore};
use rc_network::{
	request_responses::{IncomingRequest, OutgoingResponse},
	service::traits::NetworkService,
	types::ProtocolName,
	IfDisconnected, NetworkBackend,
};
use rostro_chat_membership_auth::spend::{
	verify_record, SpendSigVerify, SpendStore, SpendSyncRequest, SpendSyncResponse,
	MAX_SPEND_RECORDS_PER_RESPONSE,
};
use rostro_node_identity::NodeIdentity;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_runtime::traits::Block as BlockT;

use gemini_runtime::{opaque::Block, AccountId, Balance};
use rns_runtime_api::PnsStorageApi;
use zk_pki_primitives::runtime_api::ZkPkiApi;

use crate::chat_admission::is_chat_admitted;
use crate::chat_bucket_cache::BucketCache;
use crate::spend_committee;
use crate::validator_channel::SharedSessions;

/// libp2p protocol name. Distinct from the chat-bucket protocols.
pub const CHAT_SPEND_PROTOCOL_NAME: &str = "/rostro/chat-spend/1";

/// How often the initiator reconciles with a peer. 20s: fast enough that a
/// fresh spend is globally visible within a couple of ticks, sparse enough to
/// stay cheap.
pub const SPEND_SYNC_TICK_INTERVAL_SECS: u64 = 20;

/// Committee parameters (must match the witnessed-spend policy: 2-of-3).
const COMMITTEE_K: usize = 3;
const COMMITTEE_T: usize = 2;

const INBOUND_QUEUE_CAPACITY: usize = 16;
/// `epoch(8) + root(32)` plus SCALE framing; 128 is generous headroom.
const MAX_REQUEST_SIZE: u64 = 128;
/// Bounded by `MAX_SPEND_RECORDS_PER_RESPONSE` records of a few hundred bytes.
const MAX_RESPONSE_SIZE: u64 = MAX_SPEND_RECORDS_PER_RESPONSE as u64 * 512 + 4096;
const REQUEST_TIMEOUT_SECS: u64 = 60;

/// The shared per-epoch spend store: reconciled here, and (Phase 4) written by
/// the verifier/recorder path.
pub type SharedSpendStore = Arc<Mutex<SpendStore>>;

/// A fresh empty shared store. Epoch 0 until the initiator's first tick rolls it
/// to the chain's current membership epoch.
pub fn new_shared_store() -> SharedSpendStore {
	Arc::new(Mutex::new(SpendStore::default()))
}

/// ed25519 signature verification over libp2p node keys: the committee identity
/// published in RNS is the node's ed25519 key, and records are signed with it.
struct NodeSigVerify;

impl SpendSigVerify for NodeSigVerify {
	fn verify(&self, signer: &[u8], msg: &[u8], sig: &[u8]) -> bool {
		let key: [u8; 32] = match signer.try_into() {
			Ok(k) => k,
			Err(_) => return false,
		};
		let sig: [u8; 64] = match sig.try_into() {
			Ok(s) => s,
			Err(_) => return false,
		};
		NodeIdentity::from_ed25519_pubkey(key).verify(msg, &sig)
	}
}

/// Decide the response to a sync request against the local store. Pure, so the
/// match/mismatch/skew logic is unit-testable without networking.
fn decide_response(store: &SpendStore, req: &SpendSyncRequest) -> SpendSyncResponse {
	if req.epoch != store.epoch() {
		return SpendSyncResponse::EpochSkew { epoch: store.epoch() };
	}
	if store.root_cached() == req.root {
		SpendSyncResponse::Match
	} else {
		SpendSyncResponse::Mismatch { records: store.records_for_sync(MAX_SPEND_RECORDS_PER_RESPONSE) }
	}
}

/// Build the responder protocol config + handler future. Caller registers the
/// config into `net_config` and spawns the handler.
pub fn build_spend_sync_protocol<N, B>(
	store: SharedSpendStore,
	validator_sessions: SharedSessions,
) -> (N::RequestResponseProtocolConfig, impl std::future::Future<Output = ()>)
where
	N: NetworkBackend<B, <B as BlockT>::Hash>,
	B: BlockT,
{
	let (tx, rx) = async_channel::bounded::<IncomingRequest>(INBOUND_QUEUE_CAPACITY);

	let config = N::request_response_config(
		ProtocolName::from(CHAT_SPEND_PROTOCOL_NAME),
		Vec::new(),
		MAX_REQUEST_SIZE,
		MAX_RESPONSE_SIZE,
		Duration::from_secs(REQUEST_TIMEOUT_SECS),
		Some(tx),
	);

	(config, run_spend_sync_server(store, validator_sessions, rx))
}

/// Inbound responder: decode `SpendSyncRequest`, answer from the local store.
async fn run_spend_sync_server(
	store: SharedSpendStore,
	validator_sessions: SharedSessions,
	mut rx: async_channel::Receiver<IncomingRequest>,
) {
	while let Some(IncomingRequest { peer, payload, pending_response }) = rx.next().await {
		if !is_chat_admitted(&validator_sessions, &peer) {
			let _ = pending_response.send(OutgoingResponse {
				result: Err(()),
				reputation_changes: Vec::new(),
				sent_feedback: None,
			});
			continue;
		}

		let req = match SpendSyncRequest::decode(&mut &payload[..]) {
			Ok(r) => r,
			Err(_) => {
				log::debug!(target: "rostro-chat-spend", "undecodable sync request from {peer}");
				let _ = pending_response.send(OutgoingResponse {
					result: Err(()),
					reputation_changes: Vec::new(),
					sent_feedback: None,
				});
				continue;
			}
		};

		let resp = decide_response(&store.lock(), &req);
		let _ = pending_response.send(OutgoingResponse {
			result: Ok(resp.encode()),
			reputation_changes: Vec::new(),
			sent_feedback: None,
		});
	}
}

/// Periodic initiator. Each tick: roll the store to the chain's current epoch,
/// read that epoch's RNS guard set, reconcile with one random peer, and merge
/// any unseen records that validate against the guard set.
pub async fn run_spend_sync_initiator<Client>(
	network: Arc<dyn NetworkService>,
	store: SharedSpendStore,
	bucket_cache: BucketCache,
	client: Arc<Client>,
) where
	Client: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
	Client::Api: ZkPkiApi<Block, AccountId> + PnsStorageApi<Block, u64, Balance, AccountId>,
{
	let mut ticker = tokio::time::interval(Duration::from_secs(SPEND_SYNC_TICK_INTERVAL_SECS));
	ticker.tick().await; // skip the immediate first tick

	loop {
		ticker.tick().await;

		// 1. Current epoch + its anchor block, and the guard set as of that
		//    anchor. Roll the store so it tracks the chain epoch (self-pruning).
		let (epoch, anchor) = match spend_committee::epoch_anchor(&client) {
			Ok(v) => v,
			Err(e) => {
				log::debug!(target: "rostro-chat-spend", "epoch anchor unavailable: {e}");
				continue;
			}
		};
		store.lock().roll_to(epoch);
		let guard_set = match spend_committee::fetch_guard_set(&client, anchor) {
			Ok(g) => g,
			Err(e) => {
				log::debug!(target: "rostro-chat-spend", "guard set unavailable: {e}");
				continue;
			}
		};

		// 2. Pick a random chat-fabric peer.
		let all_peers = bucket_cache.all_peers();
		if all_peers.is_empty() {
			continue;
		}
		let peer = all_peers[(OsRng.next_u64() as usize) % all_peers.len()].0;

		// 3. Exchange roots.
		let (req_epoch, root) = {
			let s = store.lock();
			(s.epoch(), s.root_cached())
		};
		let req = SpendSyncRequest { epoch: req_epoch, root };
		let resp_bytes = match network
			.request(
				peer,
				ProtocolName::from(CHAT_SPEND_PROTOCOL_NAME),
				req.encode(),
				None,
				IfDisconnected::ImmediateError,
			)
			.await
		{
			Ok((b, _)) => b,
			Err(e) => {
				log::debug!(target: "rostro-chat-spend", "sync request to {peer} failed: {e:?}");
				continue;
			}
		};
		let resp = match SpendSyncResponse::decode(&mut &resp_bytes[..]) {
			Ok(r) => r,
			Err(_) => {
				log::debug!(target: "rostro-chat-spend", "undecodable sync response from {peer}");
				continue;
			}
		};

		// 4. Merge unseen records that validate against the guard set.
		match resp {
			SpendSyncResponse::Match | SpendSyncResponse::EpochSkew { .. } => {}
			SpendSyncResponse::Mismatch { records } => {
				let sigv = NodeSigVerify;
				let mut merged = 0usize;
				let mut rejected = 0usize;
				for rec in records {
					if rec.epoch != epoch || store.lock().contains(&rec.nullifier) {
						continue;
					}
					if verify_record(&rec, &guard_set, COMMITTEE_K, COMMITTEE_T, &sigv).is_ok() {
						if store.lock().insert(rec).unwrap_or(false) {
							merged += 1;
						}
					} else {
						rejected += 1;
					}
				}
				if merged > 0 || rejected > 0 {
					log::debug!(
						target: "rostro-chat-spend",
						"sync with {peer}: merged {merged}, rejected {rejected}",
					);
				}
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use rostro_chat_membership_auth::spend::{RecorderSig, SpendRecord};
	use rostro_node_identity::NodeSecret;

	fn canon(x: u8) -> [u8; 32] {
		// High bytes zero => below the BN254 modulus => a canonical nullifier.
		let mut b = [0u8; 32];
		b[0] = x;
		b
	}

	fn record(nullifier: [u8; 32], epoch: u64) -> SpendRecord {
		SpendRecord {
			nullifier,
			epoch,
			membership_root: [7u8; 32],
			verifier: b"node-0".to_vec(),
			verifier_sig: vec![1, 2, 3],
			recorders: vec![RecorderSig { recorder: b"node-1".to_vec(), sig: vec![4, 5, 6] }],
		}
	}

	#[test]
	fn protocol_name_is_versioned() {
		assert_eq!(CHAT_SPEND_PROTOCOL_NAME, "/rostro/chat-spend/1");
	}

	#[test]
	fn decide_response_reports_epoch_skew() {
		let store = SpendStore::new(5);
		let req = SpendSyncRequest { epoch: 6, root: [0u8; 32] };
		assert_eq!(decide_response(&store, &req), SpendSyncResponse::EpochSkew { epoch: 5 });
	}

	#[test]
	fn decide_response_matches_on_equal_root() {
		let store = SpendStore::new(5);
		let req = SpendSyncRequest { epoch: 5, root: store.root_cached() };
		assert_eq!(decide_response(&store, &req), SpendSyncResponse::Match);
	}

	#[test]
	fn decide_response_mismatch_serves_records() {
		let mut store = SpendStore::new(5);
		store.insert(record(canon(1), 5)).unwrap();
		store.insert(record(canon(2), 5)).unwrap();
		let req = SpendSyncRequest { epoch: 5, root: [0xFFu8; 32] };
		match decide_response(&store, &req) {
			SpendSyncResponse::Mismatch { records } => assert_eq!(records.len(), 2),
			other => panic!("expected mismatch, got {other:?}"),
		}
	}

	#[test]
	fn node_sig_verify_accepts_genuine_and_rejects_forged() {
		let secret = NodeSecret::from_seed([0x33u8; 32]);
		let key = secret.identity().ed25519_pubkey();
		let msg = b"witnessed-spend payload";
		let sig = secret.sign(msg);

		let v = NodeSigVerify;
		assert!(v.verify(&key, msg, &sig));
		// Wrong key.
		let other = NodeSecret::from_seed([0x44u8; 32]).identity().ed25519_pubkey();
		assert!(!v.verify(&other, msg, &sig));
		// Tampered signature.
		let mut bad = sig;
		bad[0] ^= 0xFF;
		assert!(!v.verify(&key, msg, &bad));
		// Malformed lengths.
		assert!(!v.verify(&key[..31], msg, &sig));
		assert!(!v.verify(&key, msg, &sig[..63]));
	}
}
