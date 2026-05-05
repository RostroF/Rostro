// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Rostro solochain service: Aura block authoring + GRANDPA finality.
//!
//! Modeled directly on `paseo-node` (which is a known-working solochain
//! reference) with `sp_*`/`sc_*` renamed to `rp_*`/`rc_*` per Rostro's
//! pallet-boundary refactor.

use futures::{FutureExt, StreamExt};
use rc_client_api::{Backend, BlockBackend, BlockchainEvents};
use rc_consensus_aura::{ImportQueueParams, SlotProportion, StartAuraParams};
use rc_consensus_grandpa::{GrandpaPruningFilter, SharedVoterState};
use rc_service::{error::Error as ServiceError, Configuration, TaskManager, WarpSyncConfig};
use rc_telemetry::{Telemetry, TelemetryWorker};
use rc_transaction_pool_api::OffchainTransactionPoolFactory;
use rostro_runtime::{self, opaque::Block, RuntimeApi};
use rostro_trace::{prove_chain_window, verify_chain_window, BlockTraceRow};
use sp_consensus_aura::sr25519::AuthorityPair as AuraPair;
use sp_runtime::traits::Header as HeaderT;
use std::{sync::Arc, time::Duration};

pub(crate) type FullClient = rc_service::TFullClient<
	Block,
	RuntimeApi,
	rc_executor::WasmExecutor<sp_io::SubstrateHostFunctions>,
>;
type FullBackend = rc_service::TFullBackend<Block>;
type FullSelectChain = rc_consensus::LongestChain<FullBackend, Block>;

const GRANDPA_JUSTIFICATION_PERIOD: u32 = 512;

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

	let executor =
		rc_service::new_wasm_executor::<sp_io::SubstrateHostFunctions>(&config.executor);

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

	let cidp_client = client.clone();
	let import_queue =
		rc_consensus_aura::import_queue::<AuraPair, _, _, _, _, _>(ImportQueueParams {
			block_import: grandpa_block_import.clone(),
			justification_import: Some(Box::new(grandpa_block_import.clone())),
			client: client.clone(),
			create_inherent_data_providers: move |parent_hash, _| {
				let cidp_client = cidp_client.clone();
				async move {
					let slot_duration =
						rc_consensus_aura::standalone::slot_duration_at(&*cidp_client, parent_hash)?;
					let timestamp = sp_timestamp::InherentDataProvider::from_system_time();
					let slot =
						sp_consensus_aura::inherents::InherentDataProvider::from_timestamp_and_slot_duration(
							*timestamp,
							slot_duration,
						);
					Ok((slot, timestamp))
				}
			},
			spawner: &task_manager.spawn_essential_handle(),
			registry: config.prometheus_registry(),
			check_for_equivocation: Default::default(),
			telemetry: telemetry.as_ref().map(|x| x.handle()),
			compatibility_mode: Default::default(),
		})?;

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
pub fn new_full<
	N: rc_network::NetworkBackend<Block, <Block as sp_runtime::traits::Block>::Hash>,
>(
	config: Configuration,
) -> Result<TaskManager, ServiceError> {
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
			peer_store_handle,
		);
	net_config.add_notification_protocol(grandpa_protocol_config);

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
	let force_authoring = config.force_authoring;
	let backoff_authoring_blocks: Option<()> = None;
	let name = config.network.node_name.clone();
	let enable_grandpa = !config.disable_grandpa;
	let prometheus_registry = config.prometheus_registry().cloned();

	let rpc_builder = {
		let client = client.clone();
		let pool = transaction_pool.clone();
		Box::new(move |_| {
			let deps = crate::rpc::FullDeps { client: client.clone(), pool: pool.clone() };
			crate::rpc::create_full(deps).map_err(Into::into)
		})
	};

	// Capture base_path before `spawn_tasks` moves `config`. Used by the
	// trace observer below for proof persistence.
	let proofs_dir = config.base_path.path().join("proofs");

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

	// ── Trace observer + per-block prover (advisory) ───────────────────────
	// Subscribes to block-import notifications, emits a `BlockTraceRow`
	// per imported block, runs the Plonky3 prover over each 8-block
	// window, self-verifies, and persists the proof to
	// `<base-path>/proofs/`. Advisory only — no header digest, no
	// consensus gating. Disk persistence makes the artifact available to
	// downstream tooling (light clients, audit, RPC) without touching
	// consensus.
	task_manager.spawn_handle().spawn(
		"rostro-trace-observer",
		Some("rostro-trace"),
		spawn_trace_observer(client.clone(), proofs_dir).boxed(),
	);

	if role.is_authority() {
		let proposer_factory = rc_basic_authorship::ProposerFactory::new(
			task_manager.spawn_handle(),
			client.clone(),
			transaction_pool.clone(),
			prometheus_registry.as_ref(),
			telemetry.as_ref().map(|x| x.handle()),
		);

		let slot_duration = rc_consensus_aura::slot_duration(&*client)?;

		let aura = rc_consensus_aura::start_aura::<AuraPair, _, _, _, _, _, _, _, _, _, _>(
			StartAuraParams {
				slot_duration,
				client: client.clone(),
				select_chain,
				block_import,
				proposer_factory,
				create_inherent_data_providers: move |_, ()| async move {
					let timestamp = sp_timestamp::InherentDataProvider::from_system_time();
					let slot =
						sp_consensus_aura::inherents::InherentDataProvider::from_timestamp_and_slot_duration(
							*timestamp,
							slot_duration,
						);
					Ok((slot, timestamp))
				},
				force_authoring,
				backoff_authoring_blocks,
				keystore: keystore_container.keystore(),
				sync_oracle: sync_service.clone(),
				justification_sync_link: sync_service.clone(),
				block_proposal_slot_portion: SlotProportion::new(2f32 / 3f32),
				max_block_proposal_slot_portion: None,
				telemetry: telemetry.as_ref().map(|x| x.handle()),
				compatibility_mode: Default::default(),
			},
		)?;

		task_manager
			.spawn_essential_handle()
			.spawn_blocking("aura", Some("block-authoring"), aura);
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

/// Window size for the per-block prover loop. Plonky3 uni-stark requires
/// `log_min_height > log_final_poly_len + log_blowup`; with the v0
/// `create_test_fri_params(_, 2)` setup (log_blowup=2, log_final_poly_len=2),
/// the smallest viable trace is 8 rows (log_min_height after blowup = 5,
/// 5 > 4 ✓). 8 rows ≈ 48 seconds of chain at the 6-second slot budget.
/// Tunable upward as we benchmark; v1 may bump to 64 to amortize prover cost.
const PROVE_WINDOW_ROWS: usize = 8;

/// Subscribe to block-import notifications, build a `BlockTraceRow` per
/// imported block, accumulate them into a window, generate a STARK proof
/// every `PROVE_WINDOW_ROWS` blocks, and persist each proof to disk.
///
/// v0 is **advisory**: proofs are generated, re-verified locally, written
/// to `<base_path>/proofs/window_<start>-<end>.proof.postcard`, and logged
/// via `tracing`. They are NOT attached to block headers, NOT gossiped,
/// NOT enforced. Disk persistence makes the artifact exfiltrate-able for
/// downstream tooling (light clients, audit logs, RPC endpoints) without
/// touching consensus. Real header-digest attachment is a follow-up phase.
///
/// Errors during row construction, prove/verify, or persistence are logged
/// at warn level and do not break the observer loop — the chain keeps
/// producing blocks regardless of advisory proof health.
async fn spawn_trace_observer(client: Arc<FullClient>, proofs_dir: std::path::PathBuf) {
	if let Err(e) = std::fs::create_dir_all(&proofs_dir) {
		tracing::warn!(
			target: "rostro-trace",
			path = ?proofs_dir,
			error = %e,
			"failed to create proofs directory; disk persistence disabled",
		);
	}

	let mut stream = client.import_notification_stream();
	let mut window: Vec<BlockTraceRow> = Vec::with_capacity(PROVE_WINDOW_ROWS);

	while let Some(notification) = stream.next().await {
		let row = match build_trace_row(&client, &notification) {
			Ok(row) => row,
			Err(e) => {
				tracing::warn!(
					target: "rostro-trace",
					block_hash = ?notification.hash,
					error = %e,
					"failed to build trace row",
				);
				continue;
			},
		};

		tracing::info!(
			target: "rostro-trace",
			block_number = row.block_number,
			extrinsic_count = row.extrinsic_count,
			block_hash = ?notification.hash,
			"trace row emitted",
		);

		window.push(row);

		if window.len() >= PROVE_WINDOW_ROWS {
			let drained: Vec<BlockTraceRow> = window.drain(..).collect();
			let first = drained.first().expect("non-empty").block_number;
			let last = drained.last().expect("non-empty").block_number;

			let prove_start = std::time::Instant::now();
			match prove_chain_window(&drained) {
				Ok((proof, meta)) => {
					let prove_elapsed = prove_start.elapsed();
					let verify_start = std::time::Instant::now();
					match verify_chain_window(&proof) {
						Ok(()) => {
							let verify_elapsed = verify_start.elapsed();
							let persisted = persist_proof(&proofs_dir, first, last, &proof);
							tracing::info!(
								target: "rostro-trace",
								window_first_block = first,
								window_last_block = last,
								trace_rows = meta.trace_rows,
								proof_bytes = meta.proof_bytes,
								prove_ms = prove_elapsed.as_millis() as u64,
								verify_ms = verify_elapsed.as_millis() as u64,
								persisted = ?persisted,
								"chain-window proof generated, self-verified, persisted",
							);
						},
						Err(e) => {
							tracing::warn!(
								target: "rostro-trace",
								window_first_block = first,
								window_last_block = last,
								error = ?e,
								"chain-window proof failed self-verify",
							);
						},
					}
				},
				Err(e) => {
					tracing::warn!(
						target: "rostro-trace",
						window_first_block = first,
						window_last_block = last,
						error = ?e,
						"chain-window prove failed",
					);
				},
			}
		}
	}
}

/// Persist a STARK proof to disk under `<proofs_dir>/window_<start>-<end>.proof.postcard`.
/// Returns the path on success or an error string on failure.
fn persist_proof(
	proofs_dir: &std::path::Path,
	first_block: u32,
	last_block: u32,
	proof: &rostro_trace::Proof,
) -> Result<std::path::PathBuf, String> {
	let file_name = format!("window_{:010}-{:010}.proof.postcard", first_block, last_block);
	let path = proofs_dir.join(&file_name);
	let bytes = postcard::to_allocvec(proof)
		.map_err(|e| format!("postcard encode failed: {}", e))?;
	std::fs::write(&path, &bytes)
		.map_err(|e| format!("write to {}: {}", path.display(), e))?;
	Ok(path)
}

fn build_trace_row(
	client: &Arc<FullClient>,
	notification: &rc_client_api::BlockImportNotification<Block>,
) -> Result<BlockTraceRow, String> {
	let header = &notification.header;
	let post_state_root: [u8; 32] = (*header.state_root()).into();
	let block_hash: [u8; 32] = notification.hash.into();
	let block_number: u32 = (*header.number())
		.try_into()
		.map_err(|_| "block_number does not fit in u32".to_string())?;

	// Look up the parent header to recover its post-state-root, which is
	// our pre-state-root. Genesis has no parent — fall back to all zeros.
	let pre_state_root: [u8; 32] = if block_number == 0 {
		[0u8; 32]
	} else {
		let parent_hash = *header.parent_hash();
		(*client
			.header(parent_hash)
			.map_err(|e| format!("parent header lookup failed: {}", e))?
			.ok_or_else(|| "parent header missing".to_string())?
			.state_root())
			.into()
	};

	// Body fetch is best-effort. If the block body is unavailable locally
	// (some prune configurations), we record extrinsic_count = 0 rather
	// than failing the whole observation.
	let extrinsic_count: u32 = client
		.block_body(notification.hash)
		.ok()
		.flatten()
		.map(|body| body.len() as u32)
		.unwrap_or(0);

	Ok(BlockTraceRow {
		block_number,
		extrinsic_count,
		pre_state_root,
		post_state_root,
		block_hash,
	})
}
