// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0
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
	start_sassafras, ClientProviders, SassafrasImportVerifier, StartSassafrasParams,
};
use sp_consensus_slots::SlotDuration;
use std::{marker::PhantomData, sync::Arc, time::Duration};

pub(crate) type FullClient = rc_service::TFullClient<
	Block,
	RuntimeApi,
	rc_executor::WasmExecutor<sp_io::SubstrateHostFunctions>,
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
