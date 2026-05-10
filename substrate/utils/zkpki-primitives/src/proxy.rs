//! Proxy-relationship validation trait + helpers.
//!
//! `register_root` and `issue_issuer_cert` require that the caller's
//! account has a pre-existing proxy relationship (in Substrate's
//! `pallet_proxy`) with the proxy account they name in the call.
//! The pallet expresses that requirement through the
//! [`ValidateProxy`] trait, wired via `T::ProxyValidator` in the
//! pallet's Config. Production runtimes bind a real implementation
//! (`PalletProxyValidator` in `zk-pki-runtime/src/proxy_validator.rs`
//! — reads `pallet_proxy::Proxies` directly); the integration-test
//! runtime binds [`NoopProxyValidator`] to keep existing tests
//! green. Negative tests can bind [`RejectAllProxyValidator`].

/// Validates that a proxy relationship exists between `delegator`
/// and `delegatee`. The delegatee acts on behalf of the delegator.
///
/// In ZK-PKI: the proxy account acts on behalf of the root/issuer
/// identity registered on-chain.
pub trait ValidateProxy<AccountId> {
    fn has_proxy(delegator: &AccountId, delegatee: &AccountId) -> bool;
}

/// No-op implementation — accepts any pair. Used by the
/// integration-test runtime so existing tests that don't care about
/// proxy validation continue to pass. NEVER wire this in production.
pub struct NoopProxyValidator;
impl<AccountId> ValidateProxy<AccountId> for NoopProxyValidator {
    fn has_proxy(_delegator: &AccountId, _delegatee: &AccountId) -> bool {
        true
    }
}

/// Always-rejects implementation — used only by negative tests to
/// exercise the `ProxyNotFound` error branch without needing to
/// simulate a real proxy-pallet absence.
pub struct RejectAllProxyValidator;
impl<AccountId> ValidateProxy<AccountId> for RejectAllProxyValidator {
    fn has_proxy(_delegator: &AccountId, _delegatee: &AccountId) -> bool {
        false
    }
}
