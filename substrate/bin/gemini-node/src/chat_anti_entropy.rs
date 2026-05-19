// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! `/rostro/chat-anti-entropy/1` — periodic gap-filling sync
//! between bucket-subscribed peers.
//!
//! Push gossip (Commit B) delivers shards from sender → R bucket
//! peers at send time. If one of those R was briefly offline, or
//! a network partition delayed delivery, that peer ends up with
//! a gap until either (a) a recipient hits its RPC and triggers
//! the Commit C fallback fetch from another peer, or (b)
//! anti-entropy fills the gap proactively.
//!
//! This module is (b).
//!
//! ## Wire shape
//!
//! Request-response on `/rostro/chat-anti-entropy/1`. One bucket
//! per request. See [`rostro_chat_primitives::anti_entropy`] for
//! the wire types.
//!
//! ## Periodic initiator
//!
//! [`run_anti_entropy_task`] runs forever:
//!
//! 1. Sleeps [`AE_TICK_INTERVAL_SECS`].
//! 2. Picks a random bucket the local node subscribes to.
//! 3. Picks a random peer from the bucket cache for that bucket.
//! 4. Computes the local digest for that bucket
//!    ([`compute_bucket_digest`] over the store's entries).
//! 5. Sends [`AeRequest`] via outbound request-response.
//! 6. On [`AeResponse::Match`] — done, in sync.
//! 7. On [`AeResponse::Mismatch`] — diffs against local set; for
//!    each entry the peer has that we don't, issues an outbound
//!    `/rostro/chat-fetch/1` keyed on the pickup_key. The fetch
//!    handler returns the share bytes + descriptor + MAC, which
//!    we then insert into the local store.
//!
//! No persistent state per peer — each tick is independent. If
//! the peer disconnects mid-exchange, the response just fails;
//! the next tick picks a different peer.
//!
//! ## Server (responder)
//!
//! [`run_anti_entropy_server`] accepts inbound `AeRequest`s,
//! computes the local digest for the requested bucket, and
//! responds Match or Mismatch+entries. Channel-split admission
//! gates the substream open just like chat-stripe / chat-fetch
//! — validators are rejected because they shouldn't be carrying
//! chat-bucket data anyway.

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
use rostro_chat_primitives::{
	anti_entropy::{
		compute_bucket_digest, to_ae_entries, AeEntry, AeRequest, AeResponse,
		MAX_AE_ENTRIES_PER_RESPONSE,
	},
	descriptor::{MessageId, PickupKey, ShareIndex},
	fetch_protocol::{FetchRequest, FetchResponse},
	store_protocol::ShareStore,
};
use sp_runtime::traits::Block as BlockT;

use crate::chat_admission::is_chat_admitted;
use crate::chat_bucket_cache::BucketCache;
use crate::chat_fetch_protocol::CHAT_FETCH_PROTOCOL_NAME;
use crate::chat_gossip_protocol::LocalSubscriptionState;
use crate::validator_channel::SharedSessions;

/// libp2p protocol name. Distinct from `/rostro/chat-stripe/1`,
/// `/rostro/chat-fetch/1`, `/rostro/chat-gossip/1`.
pub const CHAT_ANTI_ENTROPY_PROTOCOL_NAME: &str = "/rostro/chat-anti-entropy/1";

/// How often the periodic initiator fires. 30 seconds — frequent
/// enough to converge churn-affected nodes quickly, sparse enough
/// that the bandwidth bill stays bounded (refrigerators not subway
/// stations per the design discussion).
pub const AE_TICK_INTERVAL_SECS: u64 = 30;

/// Inbound queue capacity for the responder.
const INBOUND_QUEUE_CAPACITY: usize = 16;

/// Maximum request payload size: AeRequest is `bucket(1) +
/// digest(32)` = ~33 bytes plus SCALE framing. 128 is overkill
/// headroom.
const MAX_REQUEST_SIZE: u64 = 128;

/// Maximum response payload size. Mismatch responses cap at
/// MAX_AE_ENTRIES_PER_RESPONSE × (32+32+1) bytes plus framing.
const MAX_RESPONSE_SIZE: u64 =
	(MAX_AE_ENTRIES_PER_RESPONSE as u64) * 65 + 1024;

/// Request/response timeout. Generous for large mismatch dumps
/// over slow links.
const REQUEST_TIMEOUT_SECS: u64 = 60;

/// Build the responder protocol config + handler future. Caller
/// (service.rs) registers the config and spawns the handler.
pub fn build_anti_entropy_protocol<N, S, Block>(
	store: Arc<S>,
	validator_sessions: SharedSessions,
) -> (N::RequestResponseProtocolConfig, impl std::future::Future<Output = ()>)
where
	N: NetworkBackend<Block, <Block as BlockT>::Hash>,
	Block: BlockT,
	S: ShareStore + Send + Sync + 'static,
{
	let (tx, rx) = async_channel::bounded::<IncomingRequest>(INBOUND_QUEUE_CAPACITY);

	let config = N::request_response_config(
		ProtocolName::from(CHAT_ANTI_ENTROPY_PROTOCOL_NAME),
		Vec::new(),
		MAX_REQUEST_SIZE,
		MAX_RESPONSE_SIZE,
		Duration::from_secs(REQUEST_TIMEOUT_SECS),
		Some(tx),
	);

	(config, run_anti_entropy_server::<S>(store, validator_sessions, rx))
}

/// Inbound responder: pull `AeRequest`s off the rc-network channel,
/// compute the local digest for the requested bucket, respond
/// Match or Mismatch+entries.
async fn run_anti_entropy_server<S>(
	store: Arc<S>,
	validator_sessions: SharedSessions,
	mut rx: async_channel::Receiver<IncomingRequest>,
) where
	S: ShareStore + Send + Sync + 'static,
{
	while let Some(IncomingRequest { peer, payload, pending_response }) = rx.next().await {
		if !is_chat_admitted(&validator_sessions, &peer) {
			log::debug!(
				target: "rostro-chat-anti-entropy",
				"rejecting AE request from {} — validator-channel session",
				peer,
			);
			let _ = pending_response.send(OutgoingResponse {
				result: Err(()),
				reputation_changes: Vec::new(),
				sent_feedback: None,
			});
			continue;
		}

		let req = match AeRequest::decode(&mut &payload[..]) {
			Ok(r) => r,
			Err(_) => {
				log::debug!(
					target: "rostro-chat-anti-entropy",
					"undecodable AE request from {}",
					peer,
				);
				let _ = pending_response.send(OutgoingResponse {
					result: Err(()),
					reputation_changes: Vec::new(),
					sent_feedback: None,
				});
				continue;
			}
		};

		let local_entries: Vec<(PickupKey, MessageId, ShareIndex)> =
			store.entries_for_bucket(req.bucket);
		let local_digest = compute_bucket_digest(&local_entries);

		let resp = if local_digest == req.digest {
			AeResponse::Match
		} else {
			let entries = to_ae_entries(&local_entries);
			let entries = if entries.len() > MAX_AE_ENTRIES_PER_RESPONSE {
				log::warn!(
					target: "rostro-chat-anti-entropy",
					"bucket {} has {} entries; truncating mismatch response \
					 to {}",
					req.bucket,
					entries.len(),
					MAX_AE_ENTRIES_PER_RESPONSE,
				);
				entries.into_iter().take(MAX_AE_ENTRIES_PER_RESPONSE).collect()
			} else {
				entries
			};
			log::debug!(
				target: "rostro-chat-anti-entropy",
				"AE mismatch for bucket {} with {}: serving {} entries",
				req.bucket,
				peer,
				entries.len(),
			);
			AeResponse::Mismatch { entries }
		};

		let _ = pending_response.send(OutgoingResponse {
			result: Ok(resp.encode()),
			reputation_changes: Vec::new(),
			sent_feedback: None,
		});
	}
}

/// Periodic initiator. Runs forever; spawn on the task manager.
///
/// One tick = one bucket × one peer × one AeRequest. If the peer
/// responds Match, we're done. If Mismatch, we diff and fetch
/// what's missing via existing `/rostro/chat-fetch/1`.
pub async fn run_anti_entropy_task<S>(
	network: Arc<dyn NetworkService>,
	store: Arc<S>,
	bucket_cache: BucketCache,
	local_state: LocalSubscriptionState,
) where
	S: ShareStore + Send + Sync + 'static,
{
	// Light per-task RNG state; we use OsRng for randomness and a
	// Mutex-wrapped counter only to avoid OsRng calls on the hot
	// path (none here — periodic).
	let _seed_anchor = Arc::new(Mutex::new(0u64));

	let mut ticker = tokio::time::interval(Duration::from_secs(AE_TICK_INTERVAL_SECS));
	// First tick returns immediately; skip it so the node settles
	// gossip advertisements before initiating AE.
	ticker.tick().await;

	loop {
		ticker.tick().await;

		// Pick a random peer from the cache. We sync the full
		// bucket-overlap with that peer in this tick, not just a
		// single bucket — at default all-256 subscription this is
		// 256 AE requests, bounded but covers everything.
		let our_bitmap = local_state.current_bitmap();
		let all_peers = bucket_cache.all_peers();
		if all_peers.is_empty() {
			log::trace!(
				target: "rostro-chat-anti-entropy",
				"bucket cache empty; skipping AE tick",
			);
			continue;
		}
		let peer_idx = (OsRng.next_u64() as usize) % all_peers.len();
		let (peer, peer_sub) = &all_peers[peer_idx];
		let peer = *peer;

		// Compute bucket overlap = intersection of our subscription
		// and the peer's. For default all-256 networks this is just
		// 256 buckets; for dialed-down networks it's the intersection.
		let mut overlap: Vec<u8> = our_bitmap
			.iter_set()
			.filter(|b| peer_sub.bitmap.contains(*b))
			.collect();

		if overlap.is_empty() {
			log::trace!(
				target: "rostro-chat-anti-entropy",
				"no bucket overlap with peer {}; skipping",
				peer,
			);
			continue;
		}

		// Randomize iteration order so two tick cycles don't always
		// hit the same buckets first (small load-spreading + churn
		// recovery niceness).
		let n = overlap.len();
		for i in (1..n).rev() {
			let j = (OsRng.next_u64() as usize) % (i + 1);
			overlap.swap(i, j);
		}

		log::debug!(
			target: "rostro-chat-anti-entropy",
			"AE tick: peer={} syncing {} bucket(s) of overlap",
			peer,
			overlap.len(),
		);

		let mut total_mismatches = 0usize;
		let mut total_fetched = 0usize;

		for bucket in overlap {
			// Compute local digest for this bucket.
			let local_entries = store.entries_for_bucket(bucket);
			let digest = compute_bucket_digest(&local_entries);
			let local_set: std::collections::HashSet<(MessageId, ShareIndex)> =
				local_entries.iter().map(|(_, mid, si)| (*mid, *si)).collect();

			// Send AeRequest.
			let req = AeRequest { bucket, digest };
			let req_bytes = req.encode();
			let resp_bytes = match network
				.request(
					peer,
					ProtocolName::from(CHAT_ANTI_ENTROPY_PROTOCOL_NAME),
					req_bytes,
					None,
					IfDisconnected::ImmediateError,
				)
				.await
			{
				Ok((b, _)) => b,
				Err(e) => {
					log::debug!(
						target: "rostro-chat-anti-entropy",
						"AE bucket={} req to {} failed: {:?}",
						bucket, peer, e,
					);
					// Peer probably disconnected mid-tick; abandon
					// this peer for the remainder of this tick and
					// pick a new one next time.
					break;
				}
			};

			let resp = match AeResponse::decode(&mut &resp_bytes[..]) {
				Ok(r) => r,
				Err(_) => {
					log::debug!(
						target: "rostro-chat-anti-entropy",
						"AE bucket={} response from {} undecodable",
						bucket, peer,
					);
					continue;
				}
			};

			match resp {
				AeResponse::Match => {
					// Quiet: in-sync is the common case.
				}
				AeResponse::Mismatch { entries } => {
					total_mismatches += 1;
					let missing: Vec<&AeEntry> = entries
						.iter()
						.filter(|e| {
							!local_set.contains(&(e.message_id, e.share_index))
						})
						.collect();
					if missing.is_empty() {
						continue;
					}

					let mut needed_pickups: std::collections::HashSet<PickupKey> =
						std::collections::HashSet::new();
					for entry in &missing {
						needed_pickups.insert(entry.pickup_key);
					}

					for pickup in needed_pickups {
						let fetch_req = FetchRequest { pickup_key: pickup };
						let fetch_bytes = fetch_req.encode();
						match network
							.request(
								peer,
								ProtocolName::from(CHAT_FETCH_PROTOCOL_NAME),
								fetch_bytes,
								None,
								IfDisconnected::ImmediateError,
							)
							.await
						{
							Ok((rb, _)) => {
								if let Ok(fresp) =
									FetchResponse::decode(&mut &rb[..])
								{
									for fs in fresp.shares {
										if store
											.insert(
												fs.descriptor,
												fs.share_bytes,
												fs.mac_tag,
											)
											.is_ok()
										{
											total_fetched += 1;
										}
									}
								}
							}
							Err(e) => {
								log::debug!(
									target: "rostro-chat-anti-entropy",
									"AE fetch (pickup {}) to {} failed: {:?}",
									hex_short(&pickup.0),
									peer,
									e,
								);
							}
						}
					}
				}
			}
		}

		if total_mismatches > 0 || total_fetched > 0 {
			log::info!(
				target: "rostro-chat-anti-entropy",
				"AE tick with {}: {} mismatches, {} shares fetched",
				peer,
				total_mismatches,
				total_fetched,
			);
		}
	}
}

/// Short hex prefix for logging.
fn hex_short(bytes: &[u8]) -> String {
	let n = bytes.len().min(8);
	let mut s = String::with_capacity(n * 2);
	for b in &bytes[..n] {
		s.push_str(&format!("{:02x}", b));
	}
	s
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn protocol_name_is_versioned() {
		assert_eq!(CHAT_ANTI_ENTROPY_PROTOCOL_NAME, "/rostro/chat-anti-entropy/1");
	}

	#[test]
	fn tick_interval_is_30s() {
		assert_eq!(AE_TICK_INTERVAL_SECS, 30);
	}

	#[test]
	fn hex_short_pads_short_input() {
		assert_eq!(hex_short(&[0xAB, 0xCD]), "abcd");
		assert_eq!(hex_short(&[0xAB, 0xCD, 0xEF]), "abcdef");
	}

	#[test]
	fn hex_short_caps_at_eight_bytes() {
		let many = [0xFFu8; 32];
		assert_eq!(hex_short(&many).len(), 16);
	}
}
