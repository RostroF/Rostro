//! Reference production implementation of the ZK-PKI
//! [`ValidateProxy`] trait, backed by `pallet_proxy`.
//!
//! Reads `pallet_proxy::Proxies::<T>` directly: the storage map
//! from delegator → `(BoundedVec<ProxyDefinition, MaxProxies>,
//! BalanceOf<T>)`. A proxy relationship exists iff any
//! `ProxyDefinition.delegate` in the delegator's list matches the
//! named delegatee.
//!
//! `zk-pki-runtime` does NOT bind this as the default
//! `T::ProxyValidator` for the ZK-PKI pallet — it binds
//! [`zk_pki_primitives::proxy::NoopProxyValidator`] so the existing
//! integration test corpus keeps passing without wiring a real
//! proxy record for every mint fixture. This type is provided as
//! the canonical production pattern; a downstream node runtime
//! that actually wants the invariant-#12 check should bind it via
//! `type ProxyValidator = PalletProxyValidator<Runtime>;`.

use core::marker::PhantomData;
use zk_pki_primitives::proxy::ValidateProxy;

pub struct PalletProxyValidator<T>(PhantomData<T>);

impl<T> ValidateProxy<T::AccountId> for PalletProxyValidator<T>
where
    T: pallet_proxy::Config,
{
    fn has_proxy(delegator: &T::AccountId, delegatee: &T::AccountId) -> bool {
        let (proxies, _deposit) = pallet_proxy::Proxies::<T>::get(delegator);
        proxies.iter().any(|def| &def.delegate == delegatee)
    }
}
