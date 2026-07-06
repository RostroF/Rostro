// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Gemini service: Sassafras block authoring + GRANDPA finality.
//!
//! Modeled on rostro-node's service.rs; the consensus-specific
//! difference is that the import queue uses [`SassafrasImportVerifier`]
//! and the slot worker is [`start_sassafras`] from
//! `rostro-consensus-sassafras`. The rostro-trace observer / inherent
//! data provider is dropped — Phase Trace is a rostro-runtime feature
//! and lives in that node binary.

use futures::FutureExt;
use gemini_runtime::{self, opaque::Block, RuntimeApi};
use rc_client_api::{Backend, BlockBackend};
use rc_consensus::BasicQueue;
use rc_consensus_grandpa::{GrandpaPruningFilter, SharedVoterState};
use rc_consensus_slots::SlotProportion;
use rc_service::{error::Error as ServiceError, Configuration, TaskManager, WarpSyncConfig};
use rc_telemetry::{Telemetry, TelemetryWorker};
use rc_transaction_pool_api::OffchainTransactionPoolFactory;
use rostro_consensus_sassafras::{
	start_sassafras, ticket_worker, ClientProviders, SassafrasImportVerifier, StartSassafrasParams,
};
use sp_consensus_slots::SlotDuration;
use std::{marker::PhantomData, sync::Arc, time::Duration};

pub(crate) type FullClient = rc_service::TFullClient<
	Block,
	RuntimeApi,
	rostro_executor::RostroCodeExecutor<sp_io::SubstrateHostFunctions>,
>;
type FullBackend = rc_service::TFullBackend<Block>;
type FullSelectChain = rc_consensus::LongestChain<FullBackend, Block>;

const GRANDPA_JUSTIFICATION_PERIOD: u32 = 512;

/// Sassafras slot duration. Mirrors `gemini_runtime::MILLISECS_PER_BLOCK`.
const SLOT_DURATION_MILLIS: u64 = 6_000;

pub type Service = rc_service::PartialComponents<
	FullClient,
	FullBackend,
	FullSelectChain,
	rc_consensus::DefaultImportQueue<Block>,
	rc_transaction_pool::TransactionPoolHandle<Block, FullClient>,
	(
		rc_consensus_grandpa::GrandpaBlockImport<FullBackend, Block, FullClient, FullSelectChain>,
		rc_consensus_grandpa::LinkHalf<Block, FullClient, FullSelectChain>,
		Option<Telemetry>,
	),
>;

pub fn new_partial(config: &Configuration) -> Result<Service, ServiceError> {
	let telemetry = config
		.telemetry_endpoints
		.clone()
		.filter(|x| !x.is_empty())
		.map(|endpoints| -> Result<_, rc_telemetry::Error> {
			let worker = TelemetryWorker::new(16)?;
			let telemetry = worker.handle().new_telemetry(endpoints);
			Ok((worker, telemetry))
		})
		.transpose()?;

	// Phase Star B8: type-swapped from `rc_service::new_wasm_executor`
	// (same swap as rostro-node in B7). `config.executor` knobs are
	// wasmtime-specific; `RostroCodeExecutor::new()` reads `POLKAVM_*`
	// env vars + workspace defaults instead.
	let executor = rostro_executor::RostroCodeExecutor::<sp_io::SubstrateHostFunctions>::new()
		.map_err(|e| ServiceError::Other(format!("rostro-executor init: {e}")))?;

	let (client, backend, keystore_container, task_manager) =
		rc_service::new_full_parts::<Block, RuntimeApi, _>(
			config,
			telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
			executor,
			vec![Arc::new(GrandpaPruningFilter)],
		)?;
	let client = Arc::new(client);

	let telemetry = telemetry.map(|(worker, telemetry)| {
		task_manager.spawn_handle().spawn("telemetry", None, worker.run());
		telemetry
	});

	let select_chain = rc_consensus::LongestChain::new(backend.clone());

	let transaction_pool = Arc::from(
		rc_transaction_pool::Builder::new(
			task_manager.spawn_essential_handle(),
			client.clone(),
			config.role.is_authority().into(),
		)
		.with_options(config.transaction_pool.clone())
		.with_prometheus(config.prometheus_registry())
		.build(),
	);

	let (grandpa_block_import, grandpa_link) = rc_consensus_grandpa::block_import(
		client.clone(),
		GRANDPA_JUSTIFICATION_PERIOD,
		&client,
		select_chain.clone(),
		telemetry.as_ref().map(|x| x.handle()),
	)?;

	// Sassafras-side import-queue construction. ClientProviders<Block, _>
	// implements both EpochProvider and TicketProvider, so we hand it to
	// SassafrasImportVerifier twice (once for each role).
	let providers = ClientProviders::<Block, _>::new(client.clone());
	let verifier = SassafrasImportVerifier::<Block, _, _>::new(
		providers.clone(),
		providers.clone(),
	);
	let import_queue = BasicQueue::new(
		verifier,
		Box::new(grandpa_block_import.clone()),
		Some(Box::new(grandpa_block_import.clone())),
		&task_manager.spawn_essential_handle(),
		config.prometheus_registry(),
	);

	Ok(rc_service::PartialComponents {
		client,
		backend,
		task_manager,
		import_queue,
		keystore_container,
		select_chain,
		transaction_pool,
		other: (grandpa_block_import, grandpa_link, telemetry),
	})
}

/// Builds a new service for a full client.
///
/// `canonical_files_dir` (Phase 7b): when `Some(dir)`, the boot-time
/// file verifier uses a `LocalDirectoryFetchTransport` rooted at
/// `dir` as its heal source. On hash mismatch, the verifier fetches
/// canonical bytes from there, stages them (see `canonical_staging_dir`
/// below), and exits code 90 for the heal pipeline to finalize. When
/// `None`, hash mismatch is fail-stop.
///
/// `canonical_staging_dir`: directory the heal pipeline writes
/// `<basename>.new` + `<basename>.new.expected_hash` into. The watchdog
/// (outside Cannae) inotifies this directory; on a closed-write of a
/// `*.new` file it re-hashes the staged bytes, compares against the
/// sidecar hash, and renames the bytes into the canonical dir on match.
/// When `None`, the verifier stages adjacent to the canonical file (dev
/// fallback; fails under Cannae because the canonical dir is sandbox-ro).
pub fn new_full<
	N: rc_network::NetworkBackend<Block, <Block as sp_runtime::traits::Block>::Hash>,
>(
	config: Configuration,
	canonical_files_dir: Option<std::path::PathBuf>,
	canonical_staging_dir: Option<std::path::PathBuf>,
	chat_membership_vk: Option<std::path::PathBuf>,
) -> Result<TaskManager, ServiceError> {
	// Load the anonymous-membership verifying key once at startup, if a path
	// was given. A read error is fatal (the operator explicitly asked for it);
	// undecodable bytes are caught later in ChatRpc::new (auth stays off).
	let chat_membership_vk_bytes: Option<Vec<u8>> = match chat_membership_vk {
		Some(path) => Some(std::fs::read(&path).map_err(|e| {
			ServiceError::Other(format!(
				"failed to read --chat-membership-vk {}: {e}",
				path.display()
			))
		})?),
		None => None,
	};
	let rc_service::PartialComponents {
		client,
		backend,
		mut task_manager,
		import_queue,
		keystore_container,
		select_chain,
		transaction_pool,
		other: (block_import, grandpa_link, mut telemetry),
	} = new_partial(&config)?;

	let mut net_config = rc_network::config::FullNetworkConfiguration::<
		Block,
		<Block as sp_runtime::traits::Block>::Hash,
		N,
	>::new(&config.network, config.prometheus_registry().cloned());
	let metrics = N::register_notification_metrics(config.prometheus_registry());

	let peer_store_handle = net_config.peer_store_handle();
	let grandpa_protocol_name = rc_consensus_grandpa::protocol_standard_name(
		&client.block_hash(0).ok().flatten().expect("Genesis block exists; qed"),
		&config.chain_spec,
	);
	let (grandpa_protocol_config, grandpa_notification_service) =
		rc_consensus_grandpa::grandpa_peers_set_config::<_, N>(
			grandpa_protocol_name.clone(),
			metrics.clone(),
			peer_store_handle.clone(),
		);
	net_config.add_notification_protocol(grandpa_protocol_config);

	// Phase Z4: validator-channel protocols. Register BEFORE
	// build_network consumes net_config. Both protocols are
	// registered unconditionally; the handshake-server side
	// rejects requests from non-validators, and the asker only
	// initiates when this node has a local GRANDPA key (i.e. is
	// a validator itself). NotificationService is held aside; the
	// task that owns it is spawned after build_network.
	let validator_channel_sessions: crate::validator_channel::SharedSessions =
		Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new()));
	// Channel identity (GRANDPA authority + delegated `chnl` key). The
	// per-epoch cert and current epoch are published by the cert-issuer
	// task and read by both handshake sign paths; the GRANDPA key itself
	// is never used by the handshake code, only by cert issuance.
	let local_channel_identity =
		crate::validator_channel::LocalChannelIdentity::from_keystore(
			&keystore_container.keystore(),
		);
	let validator_channel_cert: crate::validator_channel::SharedCert =
		Arc::new(parking_lot::Mutex::new(None));
	let validator_channel_epoch: crate::validator_channel::SharedEpoch =
		Arc::new(std::sync::atomic::AtomicU64::new(0));
	let (vc_notification_config, vc_notification_service) =
		crate::validator_channel::build_notification_protocol::<N, _>(
			metrics.clone(),
			peer_store_handle.clone(),
		);
	net_config.add_notification_protocol(vc_notification_config);
	if let Some(identity) = local_channel_identity.clone() {
		let (vc_handshake_config, vc_handshake_handler) =
			crate::validator_channel::build_handshake_server::<N, _, _>(
				client.clone(),
				keystore_container.keystore(),
				identity.clone(),
				validator_channel_cert.clone(),
				validator_channel_epoch.clone(),
				validator_channel_sessions.clone(),
			);
		net_config.add_request_response_protocol(vc_handshake_config);
		task_manager.spawn_handle().spawn(
			"rostro-validator-channel-handshake-server",
			Some("rostro"),
			vc_handshake_handler,
		);
		// Cert-issuer: keeps the shared cert + epoch fresh, signing with
		// the GRANDPA key at most once per 24h epoch.
		task_manager.spawn_handle().spawn(
			"rostro-validator-channel-cert-issuer",
			Some("rostro"),
			crate::validator_channel::run_cert_issuer(
				client.clone(),
				keystore_container.keystore(),
				identity,
				validator_channel_cert.clone(),
				validator_channel_epoch.clone(),
			),
		);
		log::info!(
			target: "rostro-validator-channel",
			"validator-channel handshake server + cert issuer registered (we are a validator)",
		);

		// Retired-key reaper: the destruction half of the key double
		// ratchet. Destroys local GRANDPA keys the FINALIZED chain has
		// permanently retired, provided a live successor key exists.
		task_manager.spawn_handle().spawn(
			"rostro-retired-key-reaper",
			Some("rostro"),
			crate::retired_key_reaper::run_retired_key_reaper(
				client.clone(),
				keystore_container.keystore(),
				config.keystore.path().map(|p| p.to_path_buf()),
				std::sync::Arc::new(crate::retired_key_reaper::NoSealHook),
			),
		);
	} else {
		log::info!(
			target: "rostro-validator-channel",
			"validator-channel handshake server NOT registered (no local GRANDPA key)",
		);
	}

	// Commit A: chat-gossip notification protocol. Carries bucket
	// subscription advertisements between non-validator peers so
	// each node can answer "which peers carry bucket X?" for the
	// distribution layer landing in Commit B. The protocol is
	// registered here (BEFORE build_network) and the task is
	// spawned after build_network gives us a NetworkService handle.
	//
	// The BucketCache is created unconditionally (so the rest of
	// the chat stack can hold a handle), but the gossip task is
	// only spawned if we can load a persistent libp2p node-identity
	// signing key — without one, this node can RECEIVE advertisements
	// at the libp2p layer but can't sign its own outbound
	// advertisement, so it would just be a leech. Operators wanting
	// chat-gossip participation set `--node-key` / `--node-key-file`.
	let chat_bucket_cache = crate::chat_bucket_cache::BucketCache::new();
	let chat_gossip_state_and_service = match crate::canonical_fetch_protocol::load_node_identity_signing_key(
		&config.network.node_key,
	) {
		Ok(signing_key) => {
			let now_unix_s = std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH)
				.map(|d| d.as_secs())
				.unwrap_or(0);
			let local_state = crate::chat_gossip_protocol::LocalSubscriptionState::new(
				signing_key,
				rostro_chat_primitives::bucket::BucketBitmap::all(),
				now_unix_s,
			);
			let (gossip_config, gossip_service) =
				crate::chat_gossip_protocol::build_chat_gossip_protocol::<N, _>(
					metrics.clone(),
					peer_store_handle.clone(),
				);
			net_config.add_notification_protocol(gossip_config);
			log::info!(
				target: "rostro-chat-gossip",
				"chat-gossip notification protocol registered on `{}` \
				 (initial subscription: all 256 buckets)",
				crate::chat_gossip_protocol::CHAT_GOSSIP_PROTOCOL_NAME,
			);
			Some((local_state, gossip_service))
		}
		Err(e) => {
			log::warn!(
				target: "rostro-chat-gossip",
				"chat-gossip protocol NOT registered: {e}. This node can \
				 still receive advertisements at libp2p layer but cannot \
				 sign its own outbound. Set --node-key or --node-key-file \
				 to enable full participation.",
			);
			None
		}
	};

	// Phase 7 v2 Piece 3a/3b: per-peer rate limiter shared between
	// the attest server (drops over-limit incoming requests) and the
	// asker side (Piece 3c). 2 requests / 5-min window / 300s
	// cooldown per peer — see `canonical_files_gate_grief_defense`.
	let attest_rate_limiter: crate::attest_protocol::SharedRateLimiter =
		Arc::new(parking_lot::Mutex::new(
			crate::connect_gate::RateLimiter::with_defaults(),
		));

	// Phase 7b step 5: server-side handler for canonical-root
	// attestation. Peers can query us with a nonce; we reply with our
	// locally-computed `CanonicalFilesApi::canonical_root()` value
	// echoing the nonce and our role hint. Over-limit requests are
	// silently dropped via the rate limiter. Active mutual attestation
	// on connect lands in Piece 3c.
	let (attest_protocol_config, attest_handler) =
		crate::attest_protocol::build_attest_protocol::<N, _, _>(
			client.clone(),
			config.role.is_authority(),
			attest_rate_limiter.clone(),
		);
	net_config.add_request_response_protocol(attest_protocol_config);
	task_manager.spawn_handle().spawn(
		"rostro-attest-server",
		Some("rostro"),
		attest_handler,
	);

	// Phase 7 v2 step 2c: signed canonical-fetch server. Built
	// EARLY because the protocol must register into `net_config`
	// before it's consumed by `build_network` below — same lifecycle
	// constraint as the attest protocol above. The shared
	// `Arc<LocalDirectoryFetchTransport>` is reused inside
	// `verify_at_boot` further down so the same in-memory hash
	// index serves both the heal client and the libp2p server.
	let heal_source = build_heal_source(canonical_files_dir.as_deref())?;
	if let Some(source) = heal_source.as_ref() {
		match crate::canonical_fetch_protocol::load_node_identity_signing_key(
			&config.network.node_key,
		) {
			Ok(signing_key) => {
				let (fetch_protocol_config, fetch_handler) =
					crate::canonical_fetch_protocol::build_canonical_fetch_protocol::<
						N,
						_,
						_,
						_,
					>(client.clone(), source.clone(), signing_key);
				net_config.add_request_response_protocol(fetch_protocol_config);
				task_manager.spawn_handle().spawn(
					"rostro-canonical-fetch-server",
					Some("rostro"),
					fetch_handler,
				);
				log::info!(
					target: "rostro-canonical-fetch",
					"signed canonical-fetch protocol registered on `{}` \
					 ({} canonical file(s) servable)",
					crate::canonical_fetch_protocol::CANONICAL_FETCH_PROTOCOL_NAME,
					source.len(),
				);
			},
			Err(e) => {
				log::warn!(
					target: "rostro-canonical-fetch",
					"signed canonical-fetch server NOT registered: {e}. \
					 This node can still receive heal bytes but cannot \
					 serve them. Set --node-key or --node-key-file to \
					 enable server-side participation.",
				);
			},
		}
	}

	// Phase B6b: ephemeral chat-share store + the two libp2p
	// request-response protocols that read/write it.
	//
	//   * `/rostro/chat-chunk/1` — distributors deposit prepared chunk
	//     shares for the recipient's pickup key
	//   * `/rostro/chat-fetch/1` — recipients query for shares
	//     stored under their pickup key
	//
	// Same store instance backs both protocols. The store is
	// in-process, capacity-bounded, mlock'd where the OS permits,
	// TTL-swept at block boundaries (sweep wiring lands when the
	// block-import hook is added in a follow-up). All shares die
	// when the node restarts — recipients compensate via
	// replication across multiple relays.
	let chat_share_store: Arc<
		rostro_chat_ephemeral_store::EphemeralShareStore,
	> = Arc::new(
		rostro_chat_ephemeral_store::EphemeralShareStore::with_default_config(),
	);

	// Privacy-critical retention bound: a dead-drop / chunk share
	// must not outlive its TTL in RAM. `sweep_expired` deletes entries
	// whose wall-clock expiry has passed; without this task the only
	// reclaim paths are 64 MiB capacity pressure and node restart, so
	// on a low-traffic guard a share (payload bytes + pickup-key
	// metadata) would linger far past its intended life. Local-clock
	// only, no chain involvement (see GUARD-PRIVACY-AUDIT G1). 30 s
	// cadence bounds over-retention to at most one tick.
	{
		const SWEEP_INTERVAL_SECS: u64 = 30;
		let sweep_store = chat_share_store.clone();
		task_manager.spawn_handle().spawn(
			"rostro-chat-share-sweep",
			Some("rostro"),
			async move {
				let mut ticker =
					tokio::time::interval(Duration::from_secs(SWEEP_INTERVAL_SECS));
				ticker.tick().await; // immediate first tick, skip
				loop {
					ticker.tick().await;
					let now = std::time::SystemTime::now()
						.duration_since(std::time::UNIX_EPOCH)
						.map(|d| d.as_secs())
						.unwrap_or(0);
					sweep_store.sweep_expired(now);
				}
			},
		);
	}

	let (chat_chunk_config, chat_chunk_handler) =
		crate::chat_chunk_protocol::build_chat_chunk_protocol::<N, _, _>(
			chat_share_store.clone(),
			validator_channel_sessions.clone(),
		);
	net_config.add_request_response_protocol(chat_chunk_config);
	task_manager.spawn_handle().spawn(
		"rostro-chat-chunk-server",
		Some("rostro"),
		chat_chunk_handler,
	);

	let (chat_fetch_config, chat_fetch_handler) =
		crate::chat_fetch_protocol::build_chat_fetch_protocol::<N, _, _>(
			chat_share_store.clone(),
			validator_channel_sessions.clone(),
		);
	net_config.add_request_response_protocol(chat_fetch_config);
	task_manager.spawn_handle().spawn(
		"rostro-chat-fetch-server",
		Some("rostro"),
		chat_fetch_handler,
	);

	// Commit D: anti-entropy responder. Server side of
	// /rostro/chat-anti-entropy/1. Accepts AeRequest, compares
	// per-bucket digest, responds Match or Mismatch+entries.
	// Validator peers rejected at admission (channel-split).
	let (chat_ae_config, chat_ae_handler) =
		crate::chat_anti_entropy::build_anti_entropy_protocol::<N, _, _>(
			chat_share_store.clone(),
			validator_channel_sessions.clone(),
		);
	net_config.add_request_response_protocol(chat_ae_config);

		// chat-spend-witness Phase 3: /rostro/chat-spend/1 responder. Answers
		// SpendSyncRequest(epoch, root) against the shared per-epoch spend store
		// with Match / Mismatch+records / EpochSkew. Reconciled by the initiator
		// (spawned post-build_network) and written by the verifier/recorder path
		// in Phase 4.
		let chat_spend_store = crate::chat_spend_protocol::new_shared_store();
		let chat_quarantine = crate::chat_spend_protocol::new_shared_quarantine_set();
		let (chat_spend_config, chat_spend_handler) =
			crate::chat_spend_protocol::build_spend_sync_protocol::<N, _>(
				chat_spend_store.clone(),
				chat_quarantine.clone(),
				validator_channel_sessions.clone(),
			);
		net_config.add_request_response_protocol(chat_spend_config);

		// chat-spend-witness Phase 4a: register the witness-handshake responder
		// config (verifier -> recorder). Its handler needs this node's identity
		// seed, so it is spawned later in the onion block; the config + recorder
		// state are created here.
		let chat_recorder_state = crate::chat_spend_protocol::new_shared_recorder_state();
		let (chat_witness_config, chat_witness_rx) =
			crate::chat_spend_protocol::build_witness_protocol_config::<N>();
		net_config.add_request_response_protocol(chat_witness_config);
		task_manager.spawn_handle().spawn(
			"rostro-chat-spend-server",
			Some("rostro"),
			chat_spend_handler,
		);
	task_manager.spawn_handle().spawn(
		"rostro-chat-anti-entropy-server",
		Some("rostro"),
		chat_ae_handler,
	);

	// Phase 4 slice 2: register the onion-forward protocol config now
	// (before build_network). Its handler is spawned later — unlike the
	// other chat handlers it makes OUTBOUND store requests on Deliver,
	// so it needs the post-build_network NetworkService handle.
	let (chat_onion_forward_config, chat_onion_forward_rx) =
		crate::chat_onion_forward_protocol::build_chat_onion_forward_config::<N, _>();
	net_config.add_request_response_protocol(chat_onion_forward_config);

	log::info!(
		target: "rostro-chat",
		"chat-chunk + chat-fetch protocols registered on `{}` / `{}`",
		crate::chat_chunk_protocol::CHAT_CHUNK_PROTOCOL_NAME,
		crate::chat_fetch_protocol::CHAT_FETCH_PROTOCOL_NAME,
	);

	let warp_sync = Arc::new(rc_consensus_grandpa::warp_proof::NetworkProvider::new(
		backend.clone(),
		grandpa_link.shared_authority_set().clone(),
		Vec::default(),
	));

	let (network, system_rpc_tx, tx_handler_controller, sync_service) =
		rc_service::build_network(rc_service::BuildNetworkParams {
			config: &config,
			net_config,
			client: client.clone(),
			transaction_pool: transaction_pool.clone(),
			spawn_handle: task_manager.spawn_handle(),
			spawn_essential_handle: task_manager.spawn_essential_handle(),
			import_queue,
			block_announce_validator_builder: None,
			warp_sync_config: Some(WarpSyncConfig::WithProvider(warp_sync)),
			block_relay: None,
			metrics,
		})?;

	// Phase Z4 + Phase 7 v2 fix (2026-05-17): single broadcast
	// channel for peer-presence events. The validator-channel
	// notification task is the only thing in our tree that
	// reliably sees `NotificationStreamOpened`/`Closed` events
	// (sc-network's `NetworkService::event_stream` no longer
	// emits them — see
	// `substrate/client/network/src/service.rs:1664-1672`).
	// Subscribers like the canonical-files attest asker consume
	// from this channel instead.
	let (presence_tx, _presence_rx_seed) =
		tokio::sync::broadcast::channel::<crate::validator_channel::PeerPresenceEvent>(256);

	// Phase 7 v2 Piece 3c/3d: connect-time canonical-files attest
	// asker. Consumes peer-connect events from `presence_tx`
	// (sourced by the validator-channel notification task).
	// State recorded in the drift ledger so a future strict-drop
	// filter (channel-split workstream) can consult per-peer status.
	let drift_ledger: crate::attest_asker::SharedDriftLedger = Arc::new(
		parking_lot::Mutex::new(crate::connect_gate::DriftLedger::new()),
	);
	// Phase 4 slice 2: the onion-forward handler consults the same drift
	// ledger to admit forwards only from canonical-gated peer relays.
	let drift_ledger_for_onion = drift_ledger.clone();
	let attest_presence_rx = presence_tx.subscribe();
	task_manager.spawn_handle().spawn(
		"rostro-attest-asker",
		Some("rostro"),
		crate::attest_asker::run_attest_asker(
			network.clone(),
			client.clone(),
			drift_ledger,
			attest_presence_rx,
		),
	);

	// Phase Z4: validator-channel notification task. Owns the
	// validator-channel notification protocol's NotificationService.
	// Handles in one `tokio::select!`: handshake initiation +
	// inbound decrypt + inbound-substream validation + periodic
	// heartbeat send + peer-presence broadcast.
	//
	// **Always spawned**, regardless of validator status. When
	// `local_channel_identity` is `None` the handshake-init
	// branch is skipped but the task still publishes peer-presence
	// events that downstream tasks (attest_asker) depend on.
	task_manager.spawn_handle().spawn(
		"rostro-validator-channel-notifications",
		Some("rostro"),
		crate::validator_channel::run_notification_task(
			vc_notification_service,
			network.clone(),
			keystore_container.keystore(),
			local_channel_identity.clone(),
			validator_channel_cert.clone(),
			validator_channel_epoch.clone(),
			validator_channel_sessions.clone(),
			presence_tx,
		),
	);

	// Commit A: spawn the chat-gossip notification task. Owns the
	// NotificationService for /rostro/chat-gossip/1; populates
	// `chat_bucket_cache` from inbound advertisements; broadcasts
	// our own subscription to newly-opened peer streams.
	//
	// Extract a clone of the `LocalSubscriptionState` (if any)
	// for the RPC layer. Cheap — the struct is Arc-shared inside.
	let chat_local_subscription = chat_gossip_state_and_service
		.as_ref()
		.map(|(state, _)| state.clone());

	// Only spawned if `chat_gossip_state_and_service` was built
	// (requires a loadable persistent libp2p node-identity key).
	if let Some((local_state, gossip_service)) = chat_gossip_state_and_service {
		// Commit A.1: signal channel between rebalance and gossip
		// tasks. When the rebalance task updates LocalSubscriptionState's
		// bitmap, it sends () on this channel; the gossip task
		// re-broadcasts the new advertisement to all cached peers.
		let (rebalance_signal_tx, rebalance_signal_rx) =
			tokio::sync::mpsc::unbounded_channel::<()>();

		task_manager.spawn_handle().spawn(
			"rostro-chat-gossip",
			Some("rostro"),
			crate::chat_gossip_protocol::run_chat_gossip_task(
				gossip_service,
				chat_bucket_cache.clone(),
				local_state.clone(),
				rebalance_signal_rx,
			),
		);

		// Commit D: anti-entropy periodic initiator. Every
		// AE_TICK_INTERVAL_SECS, picks a random subscribed bucket
		// + random bucket-peer, exchanges digests, fetches missing
		// entries via existing /rostro/chat-fetch/1. Spawned only
		// when we have a chat-gossip LocalSubscriptionState (i.e.,
		// the node has a persistent libp2p identity key); without
		// that we'd have no bitmap to know which buckets to sync.
		let ae_network: Arc<dyn rc_network::service::traits::NetworkService> =
			Arc::new(network.clone());
		task_manager.spawn_handle().spawn(
			"rostro-chat-anti-entropy",
			Some("rostro"),
			crate::chat_anti_entropy::run_anti_entropy_task(
				ae_network,
				chat_share_store.clone(),
				chat_bucket_cache.clone(),
				local_state.clone(),
			),
		);

		// chat-spend-witness Phase 3: spend-set reconciliation initiator. Each
			// tick rolls the store to the chain epoch, reads that epoch's RNS
			// guard set, reconciles with one random peer, and merges records
			// that validate against the guard set.
			let spend_network: Arc<dyn rc_network::service::traits::NetworkService> =
				Arc::new(network.clone());
			task_manager.spawn_handle().spawn(
				"rostro-chat-spend",
				Some("rostro"),
				crate::chat_spend_protocol::run_spend_sync_initiator(
					spend_network,
					chat_spend_store.clone(),
					chat_quarantine.clone(),
					chat_bucket_cache.clone(),
					client.clone(),
				),
			);

			// Commit A.1: weekly rebalance task. Reads CHAT_BUCKET_TARGET_COUNT
		// from env (default = BUCKET_COUNT, i.e., no rebalance). At
		// dialed-down target counts, fires once per ISO week at this
		// node's deterministic-random time within the Tuesday
		// 06:00-18:00 UTC window. CHAT_REBALANCE_AT_STARTUP=1
		// triggers an immediate one-shot rebalance after the gossip
		// cache populates (test-mode override).
		let target_count = crate::chat_rebalance::read_target_count_from_env();
		task_manager.spawn_handle().spawn(
			"rostro-chat-rebalance",
			Some("rostro"),
			crate::chat_rebalance::run_rebalance_task(
				local_state,
				chat_bucket_cache.clone(),
				chat_share_store.clone(),
				target_count,
				rebalance_signal_tx,
			),
		);
	}

	if config.offchain_worker.enabled {
		let offchain_workers =
			rc_offchain::OffchainWorkers::new(rc_offchain::OffchainWorkerOptions {
				runtime_api_provider: client.clone(),
				is_validator: config.role.is_authority(),
				keystore: Some(keystore_container.keystore()),
				offchain_db: backend.offchain_storage(),
				transaction_pool: Some(OffchainTransactionPoolFactory::new(
					transaction_pool.clone(),
				)),
				network_provider: Arc::new(network.clone()),
				enable_http_requests: true,
				custom_extensions: |_| vec![],
			})?;
		task_manager.spawn_handle().spawn(
			"offchain-workers-runner",
			"offchain-worker",
			offchain_workers.run(client.clone(), task_manager.spawn_handle()).boxed(),
		);
	}

	let role = config.role;

	// Phase 7a + 7b: foundation-file verification, with optional
	// heal-from-local-directory on mismatch. The heal source `Arc`
	// was built up-stack (alongside the libp2p server registration);
	// here it's adapted into the verifier's HealFetcher trait. When
	// unset, mismatch is fail-stop.
	let heal_fetcher = heal_source.clone().map(heal_fetcher_from_source);
	crate::file_check::verify_at_boot(client.clone(), heal_fetcher, canonical_staging_dir.clone())
		.map_err(ServiceError::Other)?;

	// Phase 6 Layer 3: chain-state self-check. Reconciles the local
	// bandersnatch keystore against the on-chain authority set.
	// Critical case: operator has been elected but binary isn't
	// running as --validator → fail-stop.
	crate::role::spawn_chain_state_self_check(
		role,
		client.clone(),
		keystore_container.keystore(),
		&task_manager.spawn_handle(),
	);

	// Phase 6 Layer 4: spawn the validator self-audit task.
	// No-op for non-validator roles. Defense in depth against any path
	// (current or future) that might bind a non-loopback listener
	// while the node is acting as a validator.
	crate::role::spawn_self_audit_if_validator(role, &task_manager.spawn_handle());

	// Phase 6.1c: refresh the rostro-rpc-shield's policy cache from
	// the on-chain `pallet-rostro-rpc-method-policy` registry. No-op
	// when the shield is disabled (ROSTRO_RPC_SHIELD env var unset).
	let shield_layer = rc_rpc_server::middleware::RostroShieldLayer::from_env();
	crate::policy_refresh::spawn(
		&shield_layer,
		client.clone(),
		&task_manager.spawn_handle(),
	);

	// Phase Ring R3.5: ticket-generation worker. Validators only.
	// Polls for epoch transitions and submits ring-VRF tickets to the
	// pallet's `UnsortedSegments`. Without this the chain falls back
	// to deterministic round-robin slot assignment from the active
	// authority set — block production works, but Sassafras's
	// anonymous-slot guarantee evaporates.
	//
	// Submission goes through `PoolTicketSubmitter` (push the
	// `UncheckedExtrinsic` straight into the local transaction pool
	// with `TransactionSource::Local`) rather than
	// `ClientProviders::submit_ticket` (which routes through the
	// runtime API and panics host-side because no offchain extension
	// is registered). The pallet's `validate_unsigned` accepts Local
	// + InBlock sources, so the local-mempool path lands.
	if role.is_authority() {
		let ticket_submitter = Arc::new(
			crate::ticket_submitter::PoolTicketSubmitter::new(
				transaction_pool.clone(),
				client.clone(),
			),
		);
		task_manager.spawn_handle().spawn(
			"sassafras-ticket-worker",
			Some("rostro-consensus"),
			ticket_worker::run::<_, Block, _>(
				client.clone(),
				keystore_container.keystore(),
				ticket_submitter,
			),
		);
	}

	let force_authoring = config.force_authoring;
	let backoff_authoring_blocks: Option<()> = None;
	let name = config.network.node_name.clone();
	let enable_grandpa = !config.disable_grandpa;
	let prometheus_registry = config.prometheus_registry().cloned();

	// Derive the node's libp2p Ed25519 identity pubkey. This is
	// the NODE's identity (not a user's chat identity) — used as
	// the `relay_pubkey` field on share descriptors and exposed
	// via `chat_nodeInfo` so demo scripts know where to route.
	// The node does NOT hold any USER chat-identity secret — those live
	// on end-user devices. It does hold its OWN node-key seed, used
	// only by the isolated onion peeler (Phase 4) to peel layers
	// addressed to this node's identity and to sign relay replies. The
	// seed never enters the secret-free gossipsub routing/sharding
	// layer; see docs/NODE-IDENTITY.md + docs/DOTWAVE-CHAT-METADATA-ANONYMITY.md.
	let (chat_node_pubkey_ed25519, chat_node_seed): ([u8; 32], Option<[u8; 32]>) =
		match crate::canonical_fetch_protocol::load_node_identity_seed_bytes(
			&config.network.node_key,
		) {
			Ok(seed) => {
				let sk = ed25519_zebra::SigningKey::from(seed);
				let vk: ed25519_zebra::VerificationKey =
					ed25519_zebra::VerificationKey::from(&sk);
				(vk.into(), Some(seed))
			},
			Err(e) => {
				log::warn!(
					target: "rostro-chat",
					"chat RPC: node identity unavailable ({e}); chat_nodeInfo \
					 will return zeros and onion relaying is disabled. Set \
					 --node-key or --node-key-file for a persistent libp2p identity.",
				);
				([0u8; 32], None)
			},
		};

	let network_arc: Arc<dyn rc_network::service::traits::NetworkService> =
		Arc::new(network.clone());

	// Phase 4 slice 2: spawn the onion-forward handler (relay-2 side). It
	// owns its own OnionPeelCtx built from this node's key — peels a
	// forwarded onion and, on Deliver, injects the recipient message into
	// the chunk path. Only spawned when this node has a persistent
	// identity (onion relaying requires the node key).
	if let Some(onion_seed) = chat_node_seed {
		// chat-spend-witness Phase 4a: recorder side of
		// /rostro/chat-spend-witness/1. Spawned here because it needs this node's
		// identity seed (to counter-sign), available only after build_network.
		task_manager.spawn_handle().spawn(
			"rostro-chat-spend-witness-server",
			Some("rostro"),
			crate::chat_spend_protocol::run_witness_server(
				onion_seed,
				chat_node_pubkey_ed25519,
				chat_membership_vk_bytes
					.as_deref()
					.and_then(rostro_chat_membership_auth::deserialize_vk),
				client.clone(),
				chat_recorder_state.clone(),
				chat_quarantine.clone(),
				validator_channel_sessions.clone(),
				chat_witness_rx,
			),
		);

		let onion_peel_ctx = Arc::new(crate::chat_rpc::OnionPeelCtx::new(
			onion_seed,
			chat_node_pubkey_ed25519,
			chat_bucket_cache.clone(),
			network_arc.clone(),
		));
		task_manager.spawn_handle().spawn(
			"rostro-chat-onion-forward-server",
			Some("rostro"),
			crate::chat_onion_forward_protocol::run_onion_forward_handler(
				onion_peel_ctx,
				validator_channel_sessions.clone(),
				drift_ledger_for_onion,
				chat_onion_forward_rx,
			),
		);
	}

	let rpc_builder = {
		let client = client.clone();
		let pool = transaction_pool.clone();
		let chat_share_store = chat_share_store.clone();
		let network_arc = network_arc.clone();
		let chat_membership_vk_bytes = chat_membership_vk_bytes.clone();
		let chat_spend_store = chat_spend_store.clone();
		let chat_quarantine = chat_quarantine.clone();
		Box::new(move |_| {
			let deps = crate::rpc::FullDeps {
				client: client.clone(),
				pool: pool.clone(),
				chat: crate::rpc::ChatRpcDeps {
					node_pubkey_ed25519: chat_node_pubkey_ed25519,
					node_seed: chat_node_seed,
					share_store: chat_share_store.clone(),
					network: network_arc.clone(),
					bucket_cache: chat_bucket_cache.clone(),
					local_subscription: chat_local_subscription.clone(),
					membership_vk_bytes: chat_membership_vk_bytes.clone(),
					spend_store: chat_spend_store.clone(),
					quarantine: chat_quarantine.clone(),
				},
			};
			crate::rpc::create_full(deps).map_err(Into::into)
		})
	};

	let _rpc_handlers = rc_service::spawn_tasks(rc_service::SpawnTasksParams {
		network: Arc::new(network.clone()),
		client: client.clone(),
		keystore: keystore_container.keystore(),
		task_manager: &mut task_manager,
		transaction_pool: transaction_pool.clone(),
		rpc_builder,
		backend,
		system_rpc_tx,
		tx_handler_controller,
		sync_service: sync_service.clone(),
		config,
		telemetry: telemetry.as_mut(),
		tracing_execute_block: None,
	})?;

	if role.is_authority() {
		let proposer_factory = rc_basic_authorship::ProposerFactory::new(
			task_manager.spawn_handle(),
			client.clone(),
			transaction_pool.clone(),
			prometheus_registry.as_ref(),
			telemetry.as_ref().map(|x| x.handle()),
		);

		let slot_duration = SlotDuration::from_millis(SLOT_DURATION_MILLIS);

		let create_inherent_data_providers = move |_, ()| async move {
			let timestamp = sp_timestamp::InherentDataProvider::from_system_time();
			// First element of the tuple must Deref<Target = Slot> per
			// rc_consensus_slots::InherentDataProviderExt's blanket
			// impl. We reuse sp_consensus_aura::inherents — the
			// provider is generic slot timing despite the crate name;
			// it has no Aura-specific behaviour, just (timestamp +
			// slot_duration) → Slot. Sassafras's actual slot identity
			// rides in the SlotClaim digest, not the inherent.
			let slot =
				sp_consensus_aura::inherents::InherentDataProvider::from_timestamp_and_slot_duration(
					*timestamp,
					slot_duration,
				);
			Ok::<_, Box<dyn std::error::Error + Send + Sync>>((slot, timestamp))
		};

		let sassafras = start_sassafras(StartSassafrasParams {
			slot_duration,
			client: client.clone(),
			select_chain,
			block_import,
			proposer_factory,
			create_inherent_data_providers,
			sync_oracle: sync_service.clone(),
			justification_sync_link: sync_service.clone(),
			force_authoring,
			backoff_authoring_blocks,
			keystore: keystore_container.keystore(),
			block_proposal_slot_portion: SlotProportion::new(2f32 / 3f32),
			max_block_proposal_slot_portion: None,
			telemetry: telemetry.as_ref().map(|x| x.handle()),
			_phantom: PhantomData,
		})?;

		task_manager
			.spawn_essential_handle()
			.spawn_blocking("sassafras", Some("block-authoring"), sassafras);
	}

	if enable_grandpa {
		let keystore =
			if role.is_authority() { Some(keystore_container.keystore()) } else { None };

		let grandpa_config = rc_consensus_grandpa::Config {
			gossip_duration: Duration::from_millis(333),
			justification_generation_period: GRANDPA_JUSTIFICATION_PERIOD,
			name: Some(name),
			observer_enabled: false,
			keystore,
			local_role: role,
			telemetry: telemetry.as_ref().map(|x| x.handle()),
			protocol_name: grandpa_protocol_name,
		};

		let grandpa_config = rc_consensus_grandpa::GrandpaParams {
			config: grandpa_config,
			link: grandpa_link,
			network,
			sync: Arc::new(sync_service),
			notification_service: grandpa_notification_service,
			voting_rule: rc_consensus_grandpa::VotingRulesBuilder::default().build(),
			prometheus_registry,
			shared_voter_state: SharedVoterState::empty(),
			telemetry: telemetry.as_ref().map(|x| x.handle()),
			offchain_tx_pool_factory: OffchainTransactionPoolFactory::new(transaction_pool),
		};

		task_manager.spawn_essential_handle().spawn_blocking(
			"grandpa-voter",
			None,
			rc_consensus_grandpa::run_grandpa_voter(grandpa_config)?,
		);
	}

	Ok(task_manager)
}

/// Scan `--canonical-files-dir` into a shared, hash-indexed
/// [`LocalDirectoryFetchTransport`]. Returns `Ok(None)` when no
/// directory was supplied. The returned `Arc` is consumed by both
/// the heal-on-mismatch client (via [`heal_fetcher_from_source`])
/// and the libp2p server-side fetch handler (via
/// [`crate::canonical_fetch_protocol::build_canonical_fetch_protocol`])
/// so a single scan populates both surfaces.
fn build_heal_source(
	dir: Option<&std::path::Path>,
) -> Result<
	Option<Arc<rostro_canonical_fetch::local_dir::LocalDirectoryFetchTransport>>,
	ServiceError,
> {
	let Some(dir) = dir else { return Ok(None) };
	let transport =
		rostro_canonical_fetch::local_dir::LocalDirectoryFetchTransport::scan(dir)
			.map_err(|e| {
				ServiceError::Other(format!(
					"scanning --canonical-files-dir {}: {e}",
					dir.display(),
				))
			})?;
	log::info!(
		target: "rostro-file-check",
		"heal source ready: {} canonical file(s) indexed at {}",
		transport.len(),
		dir.display(),
	);
	Ok(Some(Arc::new(transport)))
}

/// Adapt a shared [`rostro_canonical_fetch::CanonicalFileSource`]
/// (typically the `Arc<LocalDirectoryFetchTransport>` from
/// [`build_heal_source`]) into the
/// [`crate::file_check::HealFetcher`] trait that the verifier
/// consumes. Uses [`rostro_canonical_fetch::CanonicalFileSource::read_by_hash`]
/// so the same `Arc` can power both the heal client and the libp2p
/// server-side handler without contention or duplicate scans.
fn heal_fetcher_from_source<S>(source: Arc<S>) -> Box<dyn crate::file_check::HealFetcher>
where
	S: rostro_canonical_fetch::CanonicalFileSource + Send + Sync + 'static,
{
	struct Adapter<S> {
		source: Arc<S>,
	}
	impl<S> crate::file_check::HealFetcher for Adapter<S>
	where
		S: rostro_canonical_fetch::CanonicalFileSource + Send + Sync,
	{
		fn fetch(&mut self, hash: [u8; 32]) -> Result<Vec<u8>, String> {
			self.source
				.read_by_hash(&hash)
				.ok_or_else(|| "canonical bytes not in local heal source".to_string())
		}
	}
	Box::new(Adapter { source })
}
