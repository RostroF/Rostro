//! JSON-RPC node extension for ZK-PKI.
//!
//! Exposes the eight query endpoints of
//! [`zk_pki_primitives::runtime_api::ZkPkiApi`] under the `zkpki_`
//! JSON-RPC namespace. Node operators mount [`ZkPkiRpc`] on their
//! node binary's RPC server; relying parties call the methods via
//! standard JSON-RPC.
//!
//! All method names lower-camelCase per JSON-RPC convention. The
//! response types are the same [`CertStatusResponse`] /
//! [`CertSummary`] / [`EntityStatusResponse`] the runtime API
//! returns, serialised with serde under the `std` feature.

use std::sync::Arc;

use codec::Codec;
use jsonrpsee::{
    core::RpcResult,
    proc_macros::rpc,
    types::ErrorObjectOwned,
};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_runtime::traits::Block as BlockT;

use zk_pki_primitives::runtime_api::{
    CertStatusResponse, CertSummary, EntityStatusResponse, ZkPkiApi,
};

/// Map a runtime-api error to a JSON-RPC error object.
fn rpc_err(e: impl core::fmt::Display) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(1, e.to_string(), None::<()>)
}

/// JSON-RPC method surface. Each method forwards to the corresponding
/// [`ZkPkiApi`] runtime-api call at the caller-supplied block, or the
/// best block if `at` is `None`.
#[rpc(server)]
pub trait ZkPkiRpcApi<BlockHash, AccountId> {
    #[method(name = "zkpki_certStatus")]
    fn cert_status(
        &self,
        thumbprint: [u8; 32],
        at: Option<BlockHash>,
    ) -> RpcResult<Option<CertStatusResponse<AccountId>>>;

    #[method(name = "zkpki_certsByIssuer")]
    fn certs_by_issuer(
        &self,
        issuer: AccountId,
        at: Option<BlockHash>,
    ) -> RpcResult<Vec<CertSummary>>;

    #[method(name = "zkpki_certsByUser")]
    fn certs_by_user(
        &self,
        user: AccountId,
        at: Option<BlockHash>,
    ) -> RpcResult<Vec<CertSummary>>;

    #[method(name = "zkpki_certsByRoot")]
    fn certs_by_root(
        &self,
        root: AccountId,
        at: Option<BlockHash>,
    ) -> RpcResult<Vec<CertSummary>>;

    #[method(name = "zkpki_entityStatus")]
    fn entity_status(
        &self,
        address: AccountId,
        at: Option<BlockHash>,
    ) -> RpcResult<Option<EntityStatusResponse<AccountId>>>;

    #[method(name = "zkpki_ekLookup")]
    fn ek_lookup(
        &self,
        root: AccountId,
        ek_hash: [u8; 32],
        at: Option<BlockHash>,
    ) -> RpcResult<Option<[u8; 32]>>;

    #[method(name = "zkpki_chainValidAt")]
    fn chain_valid_at(
        &self,
        thumbprint: [u8; 32],
        block_number: u64,
        at: Option<BlockHash>,
    ) -> RpcResult<bool>;
}

/// RPC handler implementation. Generic over the client + block so any
/// Substrate node that implements [`ZkPkiApi`] in its runtime can
/// mount this.
pub struct ZkPkiRpc<C, Block> {
    client: Arc<C>,
    _marker: std::marker::PhantomData<Block>,
}

impl<C, Block> ZkPkiRpc<C, Block> {
    pub fn new(client: Arc<C>) -> Self {
        Self {
            client,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<C, Block, AccountId> ZkPkiRpcApiServer<<Block as BlockT>::Hash, AccountId>
    for ZkPkiRpc<C, Block>
where
    Block: BlockT,
    C: Send + Sync + 'static + ProvideRuntimeApi<Block> + HeaderBackend<Block>,
    C::Api: ZkPkiApi<Block, AccountId>,
    AccountId: Codec + Send + Sync + 'static,
{
    fn cert_status(
        &self,
        thumbprint: [u8; 32],
        at: Option<<Block as BlockT>::Hash>,
    ) -> RpcResult<Option<CertStatusResponse<AccountId>>> {
        let api = self.client.runtime_api();
        let at_hash = at.unwrap_or_else(|| self.client.info().best_hash);
        api.cert_status(at_hash, thumbprint).map_err(rpc_err)
    }

    fn certs_by_issuer(
        &self,
        issuer: AccountId,
        at: Option<<Block as BlockT>::Hash>,
    ) -> RpcResult<Vec<CertSummary>> {
        let api = self.client.runtime_api();
        let at_hash = at.unwrap_or_else(|| self.client.info().best_hash);
        api.certs_by_issuer(at_hash, issuer).map_err(rpc_err)
    }

    fn certs_by_user(
        &self,
        user: AccountId,
        at: Option<<Block as BlockT>::Hash>,
    ) -> RpcResult<Vec<CertSummary>> {
        let api = self.client.runtime_api();
        let at_hash = at.unwrap_or_else(|| self.client.info().best_hash);
        api.certs_by_user(at_hash, user).map_err(rpc_err)
    }

    fn certs_by_root(
        &self,
        root: AccountId,
        at: Option<<Block as BlockT>::Hash>,
    ) -> RpcResult<Vec<CertSummary>> {
        let api = self.client.runtime_api();
        let at_hash = at.unwrap_or_else(|| self.client.info().best_hash);
        api.certs_by_root(at_hash, root).map_err(rpc_err)
    }

    fn entity_status(
        &self,
        address: AccountId,
        at: Option<<Block as BlockT>::Hash>,
    ) -> RpcResult<Option<EntityStatusResponse<AccountId>>> {
        let api = self.client.runtime_api();
        let at_hash = at.unwrap_or_else(|| self.client.info().best_hash);
        api.entity_status(at_hash, address).map_err(rpc_err)
    }

    fn ek_lookup(
        &self,
        root: AccountId,
        ek_hash: [u8; 32],
        at: Option<<Block as BlockT>::Hash>,
    ) -> RpcResult<Option<[u8; 32]>> {
        let api = self.client.runtime_api();
        let at_hash = at.unwrap_or_else(|| self.client.info().best_hash);
        api.ek_lookup(at_hash, root, ek_hash).map_err(rpc_err)
    }

    fn chain_valid_at(
        &self,
        thumbprint: [u8; 32],
        block_number: u64,
        at: Option<<Block as BlockT>::Hash>,
    ) -> RpcResult<bool> {
        let api = self.client.runtime_api();
        let at_hash = at.unwrap_or_else(|| self.client.info().best_hash);
        api.chain_valid_at(at_hash, thumbprint, block_number)
            .map_err(rpc_err)
    }
}
