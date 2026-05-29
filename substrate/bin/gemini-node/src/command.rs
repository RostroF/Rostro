// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

use crate::{
	chain_spec,
	cli::{Cli, Subcommand},
	service,
};
use gemini_runtime::Block;
use rc_cli::SubstrateCli;
use rc_service::PartialComponents;

impl SubstrateCli for Cli {
	fn impl_name() -> String {
		"Gemini Node".into()
	}

	fn impl_version() -> String {
		env!("SUBSTRATE_CLI_IMPL_VERSION").into()
	}

	fn description() -> String {
		env!("CARGO_PKG_DESCRIPTION").into()
	}

	fn author() -> String {
		env!("CARGO_PKG_AUTHORS").into()
	}

	fn support_url() -> String {
		"https://github.com/RostroF/Rostro/issues".into()
	}

	fn copyright_start_year() -> i32 {
		2026
	}

	fn load_spec(&self, id: &str) -> Result<Box<dyn rc_service::ChainSpec>, String> {
		Ok(match id {
			"" | "dev" | "gemini-dev" => Box::new(chain_spec::development_config()?),
			"local" | "gemini-local" => Box::new(chain_spec::local_config()?),
			"star" | "gemini-star" => Box::new(chain_spec::star_config()?),
			path => Box::new(chain_spec::ChainSpec::from_json_file(
				std::path::PathBuf::from(path),
			)?),
		})
	}
}

/// Parse and run command line arguments.
pub fn run() -> rc_cli::Result<()> {
	let cli = Cli::from_args();

	match &cli.subcommand {
		Some(Subcommand::Key(cmd)) => cmd.run(&cli),
		Some(Subcommand::BuildSpec(cmd)) => {
			let runner = cli.create_runner(cmd)?;
			runner.sync_run(|config| cmd.run(config.chain_spec, config.network))
		},
		Some(Subcommand::CheckBlock(cmd)) => {
			let runner = cli.create_runner(cmd)?;
			runner.async_run(|config| {
				let PartialComponents { client, task_manager, import_queue, .. } =
					service::new_partial(&config)?;
				Ok((cmd.run(client, import_queue), task_manager))
			})
		},
		Some(Subcommand::ExportBlocks(cmd)) => {
			let runner = cli.create_runner(cmd)?;
			runner.async_run(|config| {
				let PartialComponents { client, task_manager, .. } =
					service::new_partial(&config)?;
				Ok((cmd.run(client, config.database), task_manager))
			})
		},
		Some(Subcommand::ExportState(cmd)) => {
			let runner = cli.create_runner(cmd)?;
			runner.async_run(|config| {
				let PartialComponents { client, task_manager, .. } =
					service::new_partial(&config)?;
				Ok((cmd.run(client, config.chain_spec), task_manager))
			})
		},
		Some(Subcommand::ImportBlocks(cmd)) => {
			let runner = cli.create_runner(cmd)?;
			runner.async_run(|config| {
				let PartialComponents { client, task_manager, import_queue, .. } =
					service::new_partial(&config)?;
				Ok((cmd.run(client, import_queue), task_manager))
			})
		},
		Some(Subcommand::PurgeChain(cmd)) => {
			let runner = cli.create_runner(cmd)?;
			runner.sync_run(|config| cmd.run(config.database))
		},
		Some(Subcommand::Revert(cmd)) => {
			let runner = cli.create_runner(cmd)?;
			runner.async_run(|config| {
				let PartialComponents { client, task_manager, backend, .. } =
					service::new_partial(&config)?;
				let aux_revert = Box::new(|client, _, blocks| {
					rc_consensus_grandpa::revert(client, blocks)?;
					Ok(())
				});
				Ok((cmd.run(client, backend, Some(aux_revert)), task_manager))
			})
		},
		Some(Subcommand::ChainInfo(cmd)) => {
			let runner = cli.create_runner(cmd)?;
			runner.sync_run(|config| cmd.run::<Block>(&config))
		},
		Some(Subcommand::InsertSassafrasKey(cmd)) => {
			use sp_core::{bandersnatch, crypto::Pair as PairT};
			use sp_keystore::Keystore;
			let keystore_path =
				cmd.base_path.join("chains").join(&cmd.chain_id).join("keystore");
			std::fs::create_dir_all(&keystore_path)
				.map_err(|e| format!("create keystore dir: {e}"))?;

			// Use sp-keystore's LocalKeystore (file-backed) to insert.
			let keystore = rc_keystore::LocalKeystore::open(&keystore_path, None)
				.map_err(|e| format!("open LocalKeystore: {e}"))?;

			// Derive the bandersnatch keypair from the SURI seed.
			let pair = bandersnatch::Pair::from_string(&cmd.suri, None)
				.map_err(|e| format!("derive pair from SURI: {e:?}"))?;
			let public = pair.public();

			Keystore::insert(
				&keystore,
				sp_consensus_sassafras::KEY_TYPE,
				&cmd.suri,
				public.as_ref(),
			)
			.map_err(|e| format!("Keystore::insert: {e:?}"))?;

			let public_bytes: &[u8] = public.as_ref();
			println!("Inserted Sassafras key for {} → public {}", cmd.suri, hex::encode(public_bytes));
			Ok(())
		},
		None => {
			let canonical_files_dir = cli.canonical_files_dir.clone();
			let canonical_staging_dir = cli.canonical_staging_dir.clone();
			let runner = cli.create_runner(&cli.run)?;
			runner.run_node_until_exit(move |config| {
				let canonical_files_dir = canonical_files_dir.clone();
				let canonical_staging_dir = canonical_staging_dir.clone();
				async move {
					// Phase 6 Layer 2: enforce role-based invariants
					// before service construction. Validator role rejects
					// non-loopback RPC bindings and the unsafe method set,
					// no escape hatch.
					crate::role::validate(&config).map_err(rc_cli::Error::Input)?;
					service::new_full::<rc_network::NetworkWorker<_, _>>(
						config,
						canonical_files_dir,
						canonical_staging_dir,
					)
					.map_err(rc_cli::Error::Service)
				}
			})
		},
	}
}
