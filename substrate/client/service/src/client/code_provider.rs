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

use super::{client::ClientConfig, wasm_substitutes::WasmSubstitutes};
use rc_client_api::{backend, TrieCacheContext};
use rc_executor::{RuntimeVersion, RuntimeVersionOf};
use sp_core::traits::{FetchRuntimeCode, RuntimeCode};
use sp_runtime::traits::Block as BlockT;
use sp_state_machine::{backend::TryPendingCode, Ext, OverlayedChanges};
use std::sync::Arc;

/// Provider for fetching `:code` of a block.
///
/// As a node can run with code substitutes, this will ensure that these are
/// taken into account before returning the actual `code` for a block.
/// (wasm-cull W4: the local `--wasm-runtime-override` directory mechanism was
/// deleted — a node substituting its own runtime contradicts the
/// canonical-files posture. Chain-spec `codeSubstitutes` remain.)
pub struct CodeProvider<Block: BlockT, Backend, Executor> {
	backend: Arc<Backend>,
	executor: Arc<Executor>,
	wasm_substitutes: WasmSubstitutes<Block, Executor, Backend>,
}

impl<Block: BlockT, Backend, Executor: Clone> Clone for CodeProvider<Block, Backend, Executor> {
	fn clone(&self) -> Self {
		Self {
			backend: self.backend.clone(),
			executor: self.executor.clone(),
			wasm_substitutes: self.wasm_substitutes.clone(),
		}
	}
}

impl<Block, Backend, Executor> CodeProvider<Block, Backend, Executor>
where
	Block: BlockT,
	Backend: backend::Backend<Block>,
	Executor: RuntimeVersionOf,
{
	/// Create a new instance.
	pub fn new(
		client_config: &ClientConfig<Block>,
		executor: Executor,
		backend: Arc<Backend>,
	) -> sp_blockchain::Result<Self> {
		let executor = Arc::new(executor);

		let wasm_substitutes = WasmSubstitutes::new(
			client_config.wasm_runtime_substitutes.clone(),
			executor.clone(),
			backend.clone(),
		)?;

		Ok(Self { backend, executor, wasm_substitutes })
	}

	/// Returns the `:code` (or `:pending_code`) for the given `block`.
	///
	/// This takes into account potential substitutes.
	pub fn code_at_ignoring_overrides(&self, block: Block::Hash) -> sp_blockchain::Result<Vec<u8>> {
		let state = self.backend.state_at(block, TrieCacheContext::Untrusted)?;

		let state_runtime_code =
			sp_state_machine::backend::BackendRuntimeCode::new(&state, TryPendingCode::Yes);
		let runtime_code =
			state_runtime_code.runtime_code().map_err(sp_blockchain::Error::RuntimeCode)?;

		self.maybe_override_code_internal(runtime_code, &state, block)
			.and_then(|r| {
				r.0.fetch_runtime_code().map(Into::into).ok_or_else(|| {
					sp_blockchain::Error::Backend("Could not find `:code` in backend.".into())
				})
			})
	}

	/// Maybe override the given `onchain_code` with a chain-spec substitute.
	pub fn maybe_override_code<'a>(
		&'a self,
		onchain_code: RuntimeCode<'a>,
		state: &Backend::State,
		hash: Block::Hash,
	) -> sp_blockchain::Result<(RuntimeCode<'a>, RuntimeVersion)> {
		self.maybe_override_code_internal(onchain_code, state, hash)
	}

	/// Maybe override the given `onchain_code` with a chain-spec substitute.
	fn maybe_override_code_internal<'a>(
		&'a self,
		onchain_code: RuntimeCode<'a>,
		state: &Backend::State,
		hash: Block::Hash,
	) -> sp_blockchain::Result<(RuntimeCode<'a>, RuntimeVersion)> {
		let on_chain_version = self.on_chain_runtime_version(&onchain_code, state)?;
		let code_and_version = if let Some(s) =
			self.wasm_substitutes
				.get(on_chain_version.spec_version, onchain_code.heap_pages, hash)
		{
			tracing::debug!(target: "code-provider::substitutes", block = ?hash, "Using runtime substitute");
			s
		} else {
			tracing::debug!(
				target: "code-provider",
				block = ?hash,
				"No runtime substitute available, using onchain code",
			);
			(onchain_code, on_chain_version)
		};

		Ok(code_and_version)
	}

	/// Returns the on chain runtime version.
	fn on_chain_runtime_version(
		&self,
		code: &RuntimeCode,
		state: &Backend::State,
	) -> sp_blockchain::Result<RuntimeVersion> {
		let mut overlay = OverlayedChanges::default();

		let mut ext = Ext::new(&mut overlay, state, None);

		self.executor
			.runtime_version(&mut ext, code)
			.map_err(|e| sp_blockchain::Error::VersionInvalid(e.to_string()))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use backend::Backend;
	use rc_client_api::{in_mem, HeaderBackend};
	use sp_core::{
		testing::TaskExecutor,
		traits::{FetchRuntimeCode, WrappedRuntimeCode},
	};
	use std::collections::HashMap;
	use substrate_test_runtime_client::{new_test_executor, runtime, GenesisInit};

	#[test]
	fn no_substitutes_work() {
		let executor = new_test_executor();

		let code_fetcher = WrappedRuntimeCode(substrate_test_runtime::wasm_binary_unwrap().into());
		let onchain_code = RuntimeCode {
			code_fetcher: &code_fetcher,
			heap_pages: Some(128),
			hash: vec![0, 0, 0, 0],
		};

		let backend = Arc::new(in_mem::Backend::<runtime::Block>::new());

		// wasm_runtime_overrides is `None` here because we construct the
		// LocalCallExecutor directly later on
		let client_config = ClientConfig::default();

		let genesis_block_builder = crate::GenesisBlockBuilder::new(
			&substrate_test_runtime_client::GenesisParameters::default().genesis_storage(),
			!client_config.no_genesis,
			backend.clone(),
			executor.clone(),
		)
		.expect("Creates genesis block builder");

		// client is used for the convenience of creating and inserting the genesis block.
		let _client =
			crate::client::new_with_backend::<_, _, runtime::Block, _, runtime::RuntimeApi>(
				backend.clone(),
				executor.clone(),
				genesis_block_builder,
				Box::new(TaskExecutor::new()),
				None,
				None,
				client_config.clone(),
			)
			.expect("Creates a client");

		let executor = Arc::new(executor);

		let code_provider = CodeProvider {
			backend: backend.clone(),
			executor: executor.clone(),
			wasm_substitutes: WasmSubstitutes::new(Default::default(), executor, backend.clone())
				.unwrap(),
		};

		let check = code_provider
			.maybe_override_code(
				onchain_code,
				&backend
					.state_at(backend.blockchain().info().genesis_hash, TrieCacheContext::Untrusted)
					.unwrap(),
				backend.blockchain().info().genesis_hash,
			)
			.expect("RuntimeCode override")
			.0;

		assert_eq!(code_fetcher.fetch_runtime_code(), check.fetch_runtime_code());
	}

	// wasm-cull W4: `should_get_override_if_exists` deleted with the
	// `--wasm-runtime-override` machinery it tested.

	#[test]
	fn returns_code_from_substitute() {
		let executor = new_test_executor();

		let backend = Arc::new(in_mem::Backend::<runtime::Block>::new());

		// wasm-cull W4: substitutes are same-version hotfixes — they only
		// apply when the substitute blob reports the SAME spec_version as
		// the on-chain code. The wasm-era test proved selection by
		// rewriting the blob's spec_name section (`sp_version::embed`),
		// impossible on a PVM blob. Use the logging-disabled fixture blob
		// instead: identical VERSION, different bytes — and assert the
		// provider serves the substitute's bytes rather than `:code`.
		let substitute = substrate_test_runtime::wasm_binary_logging_disabled_unwrap().to_vec();
		assert_ne!(substitute, substrate_test_runtime::wasm_binary_unwrap().to_vec());

		let client_config = crate::client::ClientConfig {
			wasm_runtime_substitutes: vec![(0, substitute.clone())]
				.into_iter()
				.collect::<HashMap<_, _>>(),
			..Default::default()
		};

		let genesis_block_builder = crate::GenesisBlockBuilder::new(
			&substrate_test_runtime_client::GenesisParameters::default().genesis_storage(),
			!client_config.no_genesis,
			backend.clone(),
			executor.clone(),
		)
		.expect("Creates genesis block builder");

		// client is used for the convenience of creating and inserting the genesis block.
		let client =
			crate::client::new_with_backend::<_, _, runtime::Block, _, runtime::RuntimeApi>(
				backend.clone(),
				executor.clone(),
				genesis_block_builder,
				Box::new(TaskExecutor::new()),
				None,
				None,
				client_config.clone(),
			)
			.expect("Creates a client");

		let code_provider = CodeProvider::new(&client_config, executor, backend.clone())
			.expect("Creates a code provider");

		let genesis_hash = client.chain_info().genesis_hash;
		let code = code_provider
			.code_at_ignoring_overrides(genesis_hash)
			.expect("Fetches code with substitutes applied");

		assert_eq!(substitute, code);
	}
}
