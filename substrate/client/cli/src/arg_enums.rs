// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Definitions of [`ValueEnum`] types.

use clap::ValueEnum;
use std::str::FromStr;

// wasm-cull W4: `WasmExecutionMethod`, `WasmtimeInstantiationStrategy`,
// `ExecutionStrategy` and `execution_method_from_cli` were deleted with the
// wasm executors. Old command lines passing `--wasm-execution`,
// `--wasmtime-instantiation-strategy`, `--wasm-runtime-overrides` or the
// deprecated `--execution*` strategy flags now fail with a clear clap error
// (hard cutover, no grace window).

#[allow(missing_docs)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum TracingReceiver {
	/// Output the tracing records using the log.
	Log,
}

impl Into<rc_tracing::TracingReceiver> for TracingReceiver {
	fn into(self) -> rc_tracing::TracingReceiver {
		match self {
			TracingReceiver::Log => rc_tracing::TracingReceiver::Log,
		}
	}
}

/// The type of the node key.
#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum NodeKeyType {
	/// Use ed25519.
	Ed25519,
}

/// The crypto scheme to use.
#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum CryptoScheme {
	/// The Rostro hybrid consensus scheme (ed25519 + SLH-DSA-SHA2-128s).
	/// The default. `key insert` derives the scheme from well-known key
	/// types, so consensus keys never need this flag at all.
	RostroHybrid,
	/// ed25519 — account keys.
	Ed25519,
	/// sr25519 — account keys.
	Sr25519,
	/// ecdsa (secp256k1) — the attestor-quorum session key (`atte`), signed
	/// bytes verifiable by a foreign Ethereum contract via `ecrecover`.
	Ecdsa,
}

impl CryptoScheme {
	/// The kebab-case CLI name of the scheme, for error messages.
	pub fn cli_name(&self) -> &'static str {
		match self {
			CryptoScheme::RostroHybrid => "rostro-hybrid",
			CryptoScheme::Ed25519 => "ed25519",
			CryptoScheme::Sr25519 => "sr25519",
			CryptoScheme::Ecdsa => "ecdsa",
		}
	}
}

/// The type of the output format.
#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum OutputType {
	/// Output as json.
	Json,
	/// Output as text.
	Text,
}

/// Available RPC methods.
#[allow(missing_docs)]
#[derive(Debug, Copy, Clone, PartialEq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum RpcMethods {
	/// Expose every RPC method only when RPC is listening on `localhost`,
	/// otherwise serve only safe RPC methods.
	Auto,
	/// Allow only a safe subset of RPC methods.
	Safe,
	/// Expose every RPC method (even potentially unsafe ones).
	Unsafe,
}

impl FromStr for RpcMethods {
	type Err = String;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"safe" => Ok(RpcMethods::Safe),
			"unsafe" => Ok(RpcMethods::Unsafe),
			"auto" => Ok(RpcMethods::Auto),
			invalid => Err(format!("Invalid rpc methods {invalid}")),
		}
	}
}

impl Into<rc_service::config::RpcMethods> for RpcMethods {
	fn into(self) -> rc_service::config::RpcMethods {
		match self {
			RpcMethods::Auto => rc_service::config::RpcMethods::Auto,
			RpcMethods::Safe => rc_service::config::RpcMethods::Safe,
			RpcMethods::Unsafe => rc_service::config::RpcMethods::Unsafe,
		}
	}
}

/// CORS setting
///
/// The type is introduced to overcome `Option<Option<T>>` handling of `clap`.
#[derive(Clone, Debug)]
pub enum Cors {
	/// All hosts allowed.
	All,
	/// Only hosts on the list are allowed.
	List(Vec<String>),
}

impl From<Cors> for Option<Vec<String>> {
	fn from(cors: Cors) -> Self {
		match cors {
			Cors::All => None,
			Cors::List(list) => Some(list),
		}
	}
}

impl FromStr for Cors {
	type Err = crate::Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let mut is_all = false;
		let mut origins = Vec::new();
		for part in s.split(',') {
			match part {
				"all" | "*" => {
					is_all = true;
					break;
				},
				other => origins.push(other.to_owned()),
			}
		}

		if is_all {
			Ok(Cors::All)
		} else {
			Ok(Cors::List(origins))
		}
	}
}

/// Database backend.
///
/// RocksDB and the `Auto` detect-existing-rocksdb-or-create-paritydb path
/// were stripped after the paritydb-torture evaluation
/// (docs/PARITYDB-EVALUATION.md): ParityDb is the only chain-runtime
/// backend now. `paritydb-experimental` stays as a CLI alias for
/// operators with older scripts.
#[derive(Debug, Clone, PartialEq, Copy, clap::ValueEnum)]
#[value(rename_all = "lower")]
pub enum Database {
	/// ParityDb. <https://github.com/paritytech/parity-db/>
	ParityDb,
	/// ParityDb (deprecated alias).
	#[value(name = "paritydb-experimental")]
	ParityDbDeprecated,
}

impl Database {
	/// Returns all the variants of this enum to be shown in the cli.
	pub const fn variants() -> &'static [&'static str] {
		&["paritydb", "paritydb-experimental"]
	}
}

/// Whether off-chain workers are enabled.
#[allow(missing_docs)]
#[derive(Debug, Clone, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum OffchainWorkerEnabled {
	/// Always have offchain worker enabled.
	Always,
	/// Never enable the offchain worker.
	Never,
	/// Only enable the offchain worker when running as a validator (or collator, if this is a
	/// parachain node).
	WhenAuthority,
}

/// Syncing mode.
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]
#[value(rename_all = "kebab-case")]
pub enum SyncMode {
	/// Full sync. Download and verify all blocks.
	Full,
	/// Download blocks without executing them. Download latest state with proofs.
	Fast,
	/// Download blocks without executing them. Download latest state without proofs.
	FastUnsafe,
	/// Prove finality and download the latest state.
	/// After warp sync completes, the node will have block headers but not bodies for historical
	/// blocks (unless `blocks-pruning` is set to archive mode). This saves bandwidth while still
	/// allowing the node to serve as a warp sync source for other nodes.
	Warp,
}

impl Into<rc_network::config::SyncMode> for SyncMode {
	fn into(self) -> rc_network::config::SyncMode {
		match self {
			SyncMode::Full => rc_network::config::SyncMode::Full,
			SyncMode::Fast => rc_network::config::SyncMode::LightState {
				skip_proofs: false,
				storage_chain_mode: false,
			},
			SyncMode::FastUnsafe => rc_network::config::SyncMode::LightState {
				skip_proofs: true,
				storage_chain_mode: false,
			},
			SyncMode::Warp => rc_network::config::SyncMode::Warp,
		}
	}
}

/// Network backend type.
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]
#[value(rename_all = "lower")]
pub enum NetworkBackendType {
	/// Use libp2p for P2P networking.
	Libp2p,

	/// Use litep2p for P2P networking.
	Litep2p,
}

impl Into<rc_network::config::NetworkBackendType> for NetworkBackendType {
	fn into(self) -> rc_network::config::NetworkBackendType {
		match self {
			Self::Libp2p => rc_network::config::NetworkBackendType::Libp2p,
			Self::Litep2p => rc_network::config::NetworkBackendType::Litep2p,
		}
	}
}
