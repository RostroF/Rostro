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
	IfDisconnected, NetworkBackend, PeerId,
};
use rostro_chat_membership_auth::spend::{
	equivocators, recorder_sig_payload, validate_witness, verifier_sig_payload, verify_record,
	QuarantineSet, RecorderSig, RecorderState, SpendRecord, SpendSigVerify, SpendStore,
	SpendSyncRequest, SpendSyncResponse, WitnessRefusal, WitnessRequest, WitnessResponse,
	MAX_SPEND_RECORDS_PER_RESPONSE,
};
use rostro_chat_membership_auth::{verify_handshake_proof, Bn254, HandshakeRequest, VerifyingKey};
use rostro_node_identity::{NodeIdentity, NodeSecret};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_runtime::traits::Block as BlockT;
use sp_runtime::SaturatedConversion;

use gemini_runtime::{opaque::Block, AccountId, Balance};
use rns_runtime_api::PnsStorageApi;
use zk_pki_primitives::runtime_api::ZkPkiApi;

use crate::chat_admission::is_chat_admitted;
use crate::chat_bucket_cache::BucketCache;
use crate::chat_rpc::RuntimeChainView;
use crate::spend_committee;
use crate::validator_channel::SharedSessions;

/// libp2p protocol name. Distinct from the chat-bucket protocols.
pub const CHAT_SPEND_PROTOCOL_NAME: &str = "/rostro/chat-spend/1";

/// libp2p protocol name for the verifier->recorder witness handshake.
pub const CHAT_SPEND_WITNESS_PROTOCOL_NAME: &str = "/rostro/chat-spend-witness/1";

/// How often the initiator reconciles with a peer. 20s: fast enough that a
/// fresh spend is globally visible within a couple of ticks, sparse enough to
/// stay cheap.
pub const SPEND_SYNC_TICK_INTERVAL_SECS: u64 = 20;

/// Committee parameters (must match the witnessed-spend policy: 2-of-3).
const COMMITTEE_K: usize = 3;
const COMMITTEE_T: usize = 2;

/// Bogus (proof-invalid) requests from one verifier within an epoch before it is
/// quarantined for flooding.
const FLOOD_THRESHOLD: usize = 10;

const INBOUND_QUEUE_CAPACITY: usize = 16;
/// `epoch(8) + root(32)` plus SCALE framing; 128 is generous headroom.
const MAX_REQUEST_SIZE: u64 = 128;
/// Bounded by `MAX_SPEND_RECORDS_PER_RESPONSE` records of a few hundred bytes.
const MAX_RESPONSE_SIZE: u64 = MAX_SPEND_RECORDS_PER_RESPONSE as u64 * 512 + 4096;
const REQUEST_TIMEOUT_SECS: u64 = 60;
/// A WitnessRequest is `nullifier(32) + epoch(8) + root(32) + verifier(~33) +
/// verifier_sig(~65)` plus framing; 512 is generous.
const MAX_WITNESS_REQUEST_SIZE: u64 = 512;
/// A WitnessResponse is `recorder(~33) + recorder_sig(~65)` plus framing.
const MAX_WITNESS_RESPONSE_SIZE: u64 = 256;

/// The shared per-epoch spend store: reconciled here, and (Phase 4) written by
/// the verifier/recorder path.
pub type SharedSpendStore = Arc<Mutex<SpendStore>>;

/// A fresh empty shared store. Epoch 0 until the initiator's first tick rolls it
/// to the chain's current membership epoch.
pub fn new_shared_store() -> SharedSpendStore {
	Arc::new(Mutex::new(SpendStore::default()))
}

/// The recorder's per-epoch witnessed-nullifier set, shared with whatever needs
/// to inspect it (Phase 5 quarantine).
pub type SharedRecorderState = Arc<Mutex<RecorderState>>;

/// A fresh recorder state. Epoch 0 until the first witness request rolls it to
/// the chain's current membership epoch.
pub fn new_shared_recorder_state() -> SharedRecorderState {
	Arc::new(Mutex::new(RecorderState::default()))
}

/// Per-epoch quarantine set, shared across the spend protocols: detection writes
/// it (reconciliation), enforcement reads it (merge, peering, committee).
pub type SharedQuarantineSet = Arc<Mutex<QuarantineSet>>;

/// A fresh quarantine set. Epoch 0 until rolled to the chain epoch.
pub fn new_shared_quarantine_set() -> SharedQuarantineSet {
	Arc::new(Mutex::new(QuarantineSet::default()))
}

/// Whether `peer`'s node identity is quarantined (its messages are dropped).
fn peer_quarantined(quarantine: &SharedQuarantineSet, peer: &PeerId) -> bool {
	match peer.clone().into_ed25519() {
		Some(key) => quarantine.lock().is_quarantined(&key),
		None => false,
	}
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
	quarantine: SharedQuarantineSet,
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

	(config, run_spend_sync_server(store, quarantine, validator_sessions, rx))
}

/// Inbound responder: decode `SpendSyncRequest`, answer from the local store.
async fn run_spend_sync_server(
	store: SharedSpendStore,
	quarantine: SharedQuarantineSet,
	validator_sessions: SharedSessions,
	mut rx: async_channel::Receiver<IncomingRequest>,
) {
	while let Some(IncomingRequest { peer, payload, pending_response }) = rx.next().await {
		if !is_chat_admitted(&validator_sessions, &peer) || peer_quarantined(&quarantine, &peer) {
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
	quarantine: SharedQuarantineSet,
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

		// 1. Current epoch + finalized head, and the guard set at that head. Roll
		//    the store so it tracks the chain epoch (self-pruning).
		let (epoch, head) = match spend_committee::epoch_and_head(&client) {
			Ok(v) => v,
			Err(e) => {
				log::debug!(target: "rostro-chat-spend", "epoch/head unavailable: {e}");
				continue;
			}
		};
		store.lock().roll_to(epoch);
		quarantine.lock().roll_to(epoch);
		let guard_set = match spend_committee::fetch_guard_set(&client, head) {
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
					if rec.epoch != epoch {
						continue;
					}
					// Equivocation detection: a different record already stored for
					// this nullifier means someone double-signed. Quarantine the
					// recorders that signed for both (different) verifiers.
					if let Some(existing) = store.lock().conflict(&rec) {
						let bad = equivocators(&existing, &rec);
						if !bad.is_empty() {
							let mut q = quarantine.lock();
							for n in bad {
								if q.quarantine(n.clone()) {
									log::warn!(
										target: "rostro-chat-spend",
										"quarantined equivocator {} (double-signed a nullifier)",
										hex::encode(&n[..n.len().min(8)]),
									);
								}
							}
						}
						continue;
					}
					if store.lock().contains(&rec.nullifier) {
						continue;
					}
					// Merge only records that verify AND remain admissible after
					// discarding any quarantined signer (>= t honest sigs).
					if verify_record(&rec, &guard_set, COMMITTEE_K, COMMITTEE_T, &sigv).is_ok()
						&& quarantine.lock().admits(&rec, COMMITTEE_T)
					{
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

/// Build the witness-protocol responder *config* and its inbound channel. The
/// config must register into `net_config` before `build_network`; the handler is
/// spawned later (it needs the node identity, available post-build_network).
pub fn build_witness_protocol_config<N>(
) -> (N::RequestResponseProtocolConfig, async_channel::Receiver<IncomingRequest>)
where
	N: NetworkBackend<Block, <Block as BlockT>::Hash>,
{
	let (tx, rx) = async_channel::bounded::<IncomingRequest>(INBOUND_QUEUE_CAPACITY);
	let config = N::request_response_config(
		ProtocolName::from(CHAT_SPEND_WITNESS_PROTOCOL_NAME),
		Vec::new(),
		MAX_WITNESS_REQUEST_SIZE,
		MAX_WITNESS_RESPONSE_SIZE,
		Duration::from_secs(REQUEST_TIMEOUT_SECS),
		Some(tx),
	);
	(config, rx)
}

fn reject() -> OutgoingResponse {
	OutgoingResponse { result: Err(()), reputation_changes: Vec::new(), sent_feedback: None }
}

/// Recorder side of the witness handshake. For each `WitnessRequest`: roll the
/// recorder state to the chain epoch, check the membership root is recent, and
/// validate committee membership + the verifier signature + that the nullifier is
/// unseen this epoch. On success, mark it witnessed and counter-sign; otherwise
/// refuse with a reason. Marking-witnessed before signing is the double-sign
/// refusal that makes the committee a single serialisation point per nullifier.
pub async fn run_witness_server<Client>(
	node_seed: [u8; 32],
	node_pubkey: [u8; 32],
	membership_vk: Option<VerifyingKey<Bn254>>,
	client: Arc<Client>,
	recorder_state: SharedRecorderState,
	quarantine: SharedQuarantineSet,
	validator_sessions: SharedSessions,
	mut rx: async_channel::Receiver<IncomingRequest>,
) where
	Client: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
	Client::Api: ZkPkiApi<Block, AccountId> + PnsStorageApi<Block, u64, Balance, AccountId>,
{
	let node_secret = NodeSecret::from_seed(node_seed);
	let sigv = NodeSigVerify;

	while let Some(IncomingRequest { peer, payload, pending_response }) = rx.next().await {
		if !is_chat_admitted(&validator_sessions, &peer) || peer_quarantined(&quarantine, &peer) {
			let _ = pending_response.send(reject());
			continue;
		}
		let req = match WitnessRequest::decode(&mut &payload[..]) {
			Ok(r) => r,
			Err(_) => {
				log::debug!(target: "rostro-chat-spend", "undecodable witness request from {peer}");
				let _ = pending_response.send(reject());
				continue;
			}
		};

		// Chain context: current epoch + finalized head, the guard set at that
		// head, and whether the claimed membership root is recent. (Runtime calls
		// outside the recorder-state lock.)
		let (epoch, head) = match spend_committee::epoch_and_head(&client) {
			Ok(v) => v,
			Err(e) => {
				log::debug!(target: "rostro-chat-spend", "witness: epoch/head unavailable: {e}");
				let _ = pending_response.send(reject());
				continue;
			}
		};
		let guard_set = match spend_committee::fetch_guard_set(&client, head) {
			Ok(g) => g,
			Err(e) => {
				log::debug!(target: "rostro-chat-spend", "witness: guard set unavailable: {e}");
				let _ = pending_response.send(reject());
				continue;
			}
		};
		let root_recent = client
			.runtime_api()
			.membership_root_recent(client.info().best_hash, req.membership_root)
			.unwrap_or(false);

		let (resp, flood_verifier) = {
			let mut rs = recorder_state.lock();
			rs.roll_to(epoch);
			if !root_recent {
				(WitnessResponse::Refused { reason: WitnessRefusal::StaleRoot }, None)
			} else {
				match validate_witness(&req, &node_pubkey, &guard_set, COMMITTEE_K, &sigv, &rs) {
					Err(reason) => (WitnessResponse::Refused { reason }, None),
					Ok(()) => {
						// Genuine-request filter: re-verify the membership proof with
						// the verifier as guard id. A bogus proof is counted against
						// the verifier; enough this epoch quarantine it for flooding.
						if verify_witnessed_proof(&membership_vk, &client, &req) {
							rs.mark_witnessed(req.nullifier);
							let payload = recorder_sig_payload(
								&req.nullifier,
								req.epoch,
								&req.membership_root,
								&req.verifier,
							);
							let sig = node_secret.sign(&payload);
							(
								WitnessResponse::Accepted {
									recorder: node_pubkey.to_vec(),
									recorder_sig: sig.to_vec(),
								},
								None,
							)
						} else {
							let n = rs.record_bad_request(&req.verifier) as usize;
							let flood = (n >= FLOOD_THRESHOLD).then(|| req.verifier.clone());
							(WitnessResponse::Refused { reason: WitnessRefusal::BadProof }, flood)
						}
					}
				}
			}
		};

		// Quarantine a flooding verifier outside the recorder-state lock.
		if let Some(v) = flood_verifier {
			if quarantine.lock().quarantine(v.clone()) {
				log::warn!(
					target: "rostro-chat-spend",
					"quarantined flooding verifier {} ({}+ bogus proofs this epoch)",
					hex::encode(&v[..v.len().min(8)]),
					FLOOD_THRESHOLD,
				);
			}
		}

		let _ = pending_response.send(OutgoingResponse {
			result: Ok(resp.encode()),
			reputation_changes: Vec::new(),
			sent_feedback: None,
		});
	}
}

/// Re-verify a witnessed membership proof against the recorder's chain view, with
/// the request's verifier as the guard id (the guard the proof's challenge is
/// bound to). Returns true when no vk is pinned, so a node without the vk falls
/// back to trusting the verifier signature (Phase 4a posture).
fn verify_witnessed_proof<Client>(
	membership_vk: &Option<VerifyingKey<Bn254>>,
	client: &Arc<Client>,
	req: &WitnessRequest,
) -> bool
where
	Client: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
	Client::Api: ZkPkiApi<Block, AccountId>,
{
	let vk = match membership_vk {
		Some(vk) => vk,
		None => return true,
	};
	let info = client.info();
	let chain = RuntimeChainView {
		client: client.as_ref(),
		best: info.best_hash,
		best_number: info.best_number.saturated_into::<u64>(),
	};
	verify_handshake_proof(vk, &req.handshake_request(), &req.verifier, &chain).is_ok()
}

/// Why the verifier could not produce a witnessed spend.
#[derive(Debug)]
pub enum VerifierError {
	/// The nullifier is already spent this epoch (seen in the local store).
	AlreadySpent,
	/// The guard set / committee could not be computed (runtime read failed).
	Committee(String),
	/// Fewer than `t` committee members counter-signed.
	InsufficientWitnesses { got: usize, need: usize },
}

/// Verifier side of the witnessed spend. After the proof is verified (caller's
/// job), compute the committee for `(nullifier, epoch)`, collect `t` recorder
/// counter-signatures over `/rostro/chat-spend-witness/1`, assemble the
/// `SpendRecord`, write it to the local store, and return it. The committee is a
/// single serialisation point per nullifier (every verifier maps to the same
/// members), so a round-robining member cannot collect a second quorum.
pub async fn run_verifier<Client>(
	network: &Arc<dyn NetworkService>,
	client: &Arc<Client>,
	node_secret: &NodeSecret,
	node_pubkey: [u8; 32],
	spend_store: &SharedSpendStore,
	quarantine: &SharedQuarantineSet,
	req: &HandshakeRequest,
) -> Result<SpendRecord, VerifierError>
where
	Client: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
	Client::Api: ZkPkiApi<Block, AccountId> + PnsStorageApi<Block, u64, Balance, AccountId>,
{
	let nullifier = req.nullifier;
	let epoch = req.current_epoch;
	let membership_root = req.membership_root;

	// Cheap early reject if a completed record is already in the local store.
	if spend_store.lock().contains(&nullifier) {
		return Err(VerifierError::AlreadySpent);
	}

	let committee = spend_committee::committee_at_epoch(client, &nullifier, COMMITTEE_K, &node_pubkey)
		.map_err(VerifierError::Committee)?;

	let verifier_sig = node_secret
		.sign(&verifier_sig_payload(&nullifier, epoch, &membership_root))
		.to_vec();
	let wreq = WitnessRequest {
		nullifier,
		epoch,
		membership_root,
		verifier: node_pubkey.to_vec(),
		verifier_sig: verifier_sig.clone(),
		proof: req.proof.clone(),
		freshness_root: req.freshness_root,
		anchor_block: req.anchor_block,
		session_pubkey: req.session_pubkey.clone(),
	};
	let wbytes = wreq.encode();

	let mut recorders: Vec<RecorderSig> = Vec::new();
	for member in &committee {
		// Skip a quarantined committee member: its counter-signature is worthless
		// (rejected network-wide), so don't waste a round-trip on it.
		if quarantine.lock().is_quarantined(member) {
			continue;
		}
		let key: [u8; 32] = match member.as_slice().try_into() {
			Ok(k) => k,
			Err(_) => continue,
		};
		let peer = match PeerId::from_ed25519(&key) {
			Some(p) => p,
			None => continue,
		};
		match network
			.request(
				peer,
				ProtocolName::from(CHAT_SPEND_WITNESS_PROTOCOL_NAME),
				wbytes.clone(),
				None,
				IfDisconnected::ImmediateError,
			)
			.await
		{
			Ok((b, _)) => {
				if let Ok(WitnessResponse::Accepted { recorder, recorder_sig }) =
					WitnessResponse::decode(&mut &b[..])
				{
					recorders.push(RecorderSig { recorder, sig: recorder_sig });
					if recorders.len() >= COMMITTEE_T {
						break;
					}
				}
			}
			Err(e) => {
				log::debug!(target: "rostro-chat-spend", "witness request to {peer} failed: {e:?}");
			}
		}
	}

	if recorders.len() < COMMITTEE_T {
		return Err(VerifierError::InsufficientWitnesses {
			got: recorders.len(),
			need: COMMITTEE_T,
		});
	}

	let record = SpendRecord {
		nullifier,
		epoch,
		membership_root,
		verifier: node_pubkey.to_vec(),
		verifier_sig,
		recorders,
	};
	// Make it locally visible immediately; anti-entropy spreads it network-wide.
	let _ = spend_store.lock().insert(record.clone());
	Ok(record)
}

#[cfg(test)]
mod tests {
	use super::*;
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
