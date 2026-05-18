// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! RPC extensions for gemini: System + TransactionPayment + Chat
//! diagnostic surface.

#![warn(missing_docs)]

use std::sync::Arc;

use gemini_runtime::{opaque::Block, AccountId, Balance, Nonce};
use jsonrpsee::RpcModule;
use rc_transaction_pool_api::TransactionPool;
use sp_api::ProvideRuntimeApi;
use sp_block_builder::BlockBuilder;
use sp_blockchain::{Error as BlockChainError, HeaderBackend, HeaderMetadata};

use crate::chat_rpc::ChatRpc;

/// Full client dependencies.
pub struct FullDeps<C, P> {
	/// The client instance to use.
	pub client: Arc<C>,
	/// Transaction pool instance.
	pub pool: Arc<P>,
	/// Chat-layer state: the running node's libp2p Ed25519
	/// identity bytes + a handle to the shared
	/// [`rostro_chat_ephemeral_store::EphemeralShareStore`]. Used
	/// to back the `chat_*` JSON-RPC diagnostics.
	pub chat: ChatRpcDeps,
}

/// Subset of [`FullDeps`] dedicated to the chat-RPC surface.
pub struct ChatRpcDeps {
	/// Raw 32-byte Ed25519 identity pubkey of the running node
	/// (the libp2p node-identity key).
	pub identity_pubkey_ed25519: [u8; 32],
	/// Raw 32-byte Ed25519 seed for the same identity. Used to
	/// derive the X25519 static secret (XEdDSA) at fetch time so
	/// we can unseal sealed-sender envelopes addressed to this
	/// node. Zero-array if no persistent key was configured —
	/// fetch will return an error in that case.
	pub identity_seed_ed25519: [u8; 32],
	/// Shared chat-share store. Lives inside the service for the
	/// lifetime of the node; cloned into the RPC layer so the
	/// chat-fetch path can read pickup-keyed entries.
	pub share_store: Arc<rostro_chat_ephemeral_store::EphemeralShareStore>,
}

/// Instantiate all full RPC extensions.
pub fn create_full<C, P>(
	deps: FullDeps<C, P>,
) -> Result<RpcModule<()>, Box<dyn std::error::Error + Send + Sync>>
where
	C: ProvideRuntimeApi<Block>,
	C: HeaderBackend<Block> + HeaderMetadata<Block, Error = BlockChainError> + 'static,
	C: Send + Sync + 'static,
	C::Api: substrate_frame_rpc_system::AccountNonceApi<Block, AccountId, Nonce>,
	C::Api: pallet_transaction_payment_rpc::TransactionPaymentRuntimeApi<Block, Balance>,
	C::Api: BlockBuilder<Block>,
	P: TransactionPool + 'static,
{
	use crate::chat_rpc::ChatRpcApiServer;
	use pallet_transaction_payment_rpc::{TransactionPayment, TransactionPaymentApiServer};
	use substrate_frame_rpc_system::{System, SystemApiServer};

	let mut module = RpcModule::new(());
	let FullDeps { client, pool, chat } = deps;

	module.merge(System::new(client.clone(), pool).into_rpc())?;
	module.merge(TransactionPayment::new(client).into_rpc())?;
	module.merge(
		ChatRpc::new(
			chat.identity_pubkey_ed25519,
			chat.identity_seed_ed25519,
			chat.share_store,
		)
		.into_rpc(),
	)?;

	Ok(module)
}
