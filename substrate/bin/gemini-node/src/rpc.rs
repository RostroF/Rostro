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
use zk_pki_primitives::runtime_api::ZkPkiApi;

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
/// Does NOT carry any user chat-identity secret — those stay on
/// end-user devices. The node only knows:
///   - its own libp2p Ed25519 pubkey (for relay-descriptor minting
///     + node-info diagnostics)
///   - the shared share-store handle
///   - the networking service handle (for outbound remote-relay
///     fetches)
pub struct ChatRpcDeps {
	/// Raw 32-byte Ed25519 pubkey of this NODE (libp2p
	/// node-identity). Used as the `relay_pubkey` field in share
	/// descriptors the node mints when accepting `chat_send_envelope`
	/// calls. Distinct from any user chat-identity.
	pub node_pubkey_ed25519: [u8; 32],
	/// Shared chat-share store. Lives inside the service for the
	/// lifetime of the node; cloned into the RPC layer.
	pub share_store: Arc<rostro_chat_ephemeral_store::EphemeralShareStore>,
	/// Handle to the running node's networking service. Used by
	/// `chat_fetch_shares` to query remote relays via the outbound
	/// `/rostro/chat-fetch/1` libp2p protocol when the caller
	/// supplies `relay_peer_id_hex`.
	pub network: Arc<dyn rc_network::service::traits::NetworkService>,
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
	C::Api: ZkPkiApi<Block, AccountId>,
	P: TransactionPool + 'static,
{
	use crate::chat_rpc::ChatRpcApiServer;
	use pallet_transaction_payment_rpc::{TransactionPayment, TransactionPaymentApiServer};
	use substrate_frame_rpc_system::{System, SystemApiServer};

	let mut module = RpcModule::new(());
	let FullDeps { client, pool, chat } = deps;

	module.merge(System::new(client.clone(), pool).into_rpc())?;
	module.merge(TransactionPayment::new(client.clone()).into_rpc())?;
	module.merge(
		ChatRpc::new(
			chat.node_pubkey_ed25519,
			chat.share_store,
			chat.network,
			client,
		)
		.into_rpc(),
	)?;

	Ok(module)
}
