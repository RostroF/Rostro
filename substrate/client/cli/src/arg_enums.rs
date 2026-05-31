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

/// The instantiation strategy to use in compiled mode.
#[derive(Debug, Clone, Copy, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum WasmtimeInstantiationStrategy {
	/// Pool the instances to avoid initializing everything from scratch
	/// on each instantiation. Use copy-on-write memory when possible.
	PoolingCopyOnWrite,

	/// Recreate the instance from scratch on every instantiation.
	/// Use copy-on-write memory when possible.
	RecreateInstanceCopyOnWrite,

	/// Pool the instances to avoid initializing everything from scratch
	/// on each instantiation.
	Pooling,

	/// Recreate the instance from scratch on every instantiation. Very slow.
	RecreateInstance,
}

/// The default [`WasmtimeInstantiationStrategy`].
pub const DEFAULT_WASMTIME_INSTANTIATION_STRATEGY: WasmtimeInstantiationStrategy =
	WasmtimeInstantiationStrategy::PoolingCopyOnWrite;

/// How to execute Wasm runtime code.
#[derive(Debug, Clone, Copy, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum WasmExecutionMethod {
	/// Uses an interpreter which now is deprecated.
	#[clap(name = "interpreted-i-know-what-i-do")]
	Interpreted,
	/// Uses a compiled runtime.
	Compiled,
}

impl std::fmt::Display for WasmExecutionMethod {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Interpreted => write!(f, "Interpreted"),
			Self::Compiled => write!(f, "Compiled"),
		}
	}
}

/// Converts the execution method and instantiation strategy command line arguments
/// into an execution method which can be used internally.
///
/// Phase H probe (2026-05-25): when the `wasmtime-backend` feature is off,
/// every CLI choice collapses to `WasmExecutionMethod::Disabled`. gemini-node
/// never reaches a code path that instantiates this value (it uses
/// `RostroCodeExecutor` directly), so the CLI args are accepted but inert.
#[cfg(feature = "wasmtime-backend")]
pub fn execution_method_from_cli(
	execution_method: WasmExecutionMethod,
	instantiation_strategy: WasmtimeInstantiationStrategy,
) -> rc_service::config::WasmExecutionMethod {
	if let WasmExecutionMethod::Interpreted = execution_method {
		log::warn!(
			"`interpreted-i-know-what-i-do` is deprecated and will be removed in the future. Defaults to `compiled` execution mode."
		);
	}

	rc_service::config::WasmExecutionMethod::Compiled {
		instantiation_strategy: match instantiation_strategy {
			WasmtimeInstantiationStrategy::PoolingCopyOnWrite => {
				rc_service::config::WasmtimeInstantiationStrategy::PoolingCopyOnWrite
			},
			WasmtimeInstantiationStrategy::RecreateInstanceCopyOnWrite => {
				rc_service::config::WasmtimeInstantiationStrategy::RecreateInstanceCopyOnWrite
			},
			WasmtimeInstantiationStrategy::Pooling => {
				rc_service::config::WasmtimeInstantiationStrategy::Pooling
			},
			WasmtimeInstantiationStrategy::RecreateInstance => {
				rc_service::config::WasmtimeInstantiationStrategy::RecreateInstance
			},
		},
	}
}

#[cfg(not(feature = "wasmtime-backend"))]
pub fn execution_method_from_cli(
	_execution_method: WasmExecutionMethod,
	_instantiation_strategy: WasmtimeInstantiationStrategy,
) -> rc_service::config::WasmExecutionMethod {
	// Phase H probe: wasmtime backend disabled in this build.
	rc_service::config::WasmExecutionMethod::default()
}

/// The default [`WasmExecutionMethod`].
pub const DEFAULT_WASM_EXECUTION_METHOD: WasmExecutionMethod = WasmExecutionMethod::Compiled;

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
	/// Use ed25519.
	Ed25519,
	/// Use sr25519.
	Sr25519,
	/// Use ecdsa.
	Ecdsa,
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

/// How to execute blocks
#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum ExecutionStrategy {
	/// Execute with native build (if available, WebAssembly otherwise).
	Native,
	/// Only execute with the WebAssembly build.
	Wasm,
	/// Execute with both native (where available) and WebAssembly builds.
	Both,
	/// Execute with the native build if possible; if it fails, then execute with WebAssembly.
	NativeElseWasm,
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
