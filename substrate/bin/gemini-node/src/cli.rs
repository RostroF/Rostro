// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! CLI surface for the gemini node. Mirrors the rostro-node CLI; the
//! consensus difference (Aura vs Sassafras) is invisible at this level.

use rc_cli::RunCmd;

#[derive(Debug, clap::Parser)]
pub struct Cli {
	#[command(subcommand)]
	pub subcommand: Option<Subcommand>,

	/// Directory containing locally-available canonical foundation
	/// files, indexed by the blake2_256 of each file's contents.
	/// When set, the Phase 7b heal flow consults this directory on
	/// boot-time hash mismatch: if the directory contains bytes
	/// matching the canonical hash from the on-chain registry, the
	/// node stages those bytes at `<exe>.new` and exits with code 90
	/// for `rostro-supervisor` to swap and restart. When unset, a
	/// hash mismatch is fail-stop (Phase 7a behavior).
	#[arg(long)]
	pub canonical_files_dir: Option<std::path::PathBuf>,

	#[clap(flatten)]
	pub run: RunCmd,
}

#[derive(Debug, clap::Subcommand)]
pub enum Subcommand {
	/// Key management cli utilities
	#[command(subcommand)]
	Key(rc_cli::KeySubcommand),

	/// Build a chain specification.
	BuildSpec(rc_cli::BuildSpecCmd),

	/// Validate blocks.
	CheckBlock(rc_cli::CheckBlockCmd),

	/// Export blocks.
	ExportBlocks(rc_cli::ExportBlocksCmd),

	/// Export the state of a given block into a chain spec.
	ExportState(rc_cli::ExportStateCmd),

	/// Import blocks.
	ImportBlocks(rc_cli::ImportBlocksCmd),

	/// Remove the whole chain.
	PurgeChain(rc_cli::PurgeChainCmd),

	/// Revert the chain to a previous state.
	Revert(rc_cli::RevertCmd),

	/// Db meta columns information.
	ChainInfo(rc_cli::ChainInfoCmd),

	/// Insert a Sassafras (bandersnatch) authority key into the local
	/// keystore for the running node. `rc-cli`'s `key insert` only
	/// supports ed25519/sr25519/ecdsa; bandersnatch (the Sassafras
	/// authority scheme) needs this side path.
	InsertSassafrasKey(InsertSassafrasKeyCmd),
}

/// Insert a bandersnatch authority key derived from a SURI seed
/// directly into the keystore at `<base-path>/chains/<chain-id>/keystore/`.
#[derive(Debug, clap::Parser)]
pub struct InsertSassafrasKeyCmd {
	/// Secret URI (e.g. `//Alice`).
	#[arg(long, required = true)]
	pub suri: String,

	/// Base path of the running node's data directory. The key gets
	/// written under `<base-path>/chains/<chain-spec-id>/keystore/`.
	#[arg(long, required = true)]
	pub base_path: std::path::PathBuf,

	/// Chain spec identifier (matches the directory name under chains/).
	#[arg(long, default_value = "gemini-local")]
	pub chain_id: String,
}

