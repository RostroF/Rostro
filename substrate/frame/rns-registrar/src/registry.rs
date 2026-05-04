//! # Registry
//!
//! This module is a high-level abstraction of the NFT module,
//! and provides `PnsOfficial` storage.
//!
//!
//! ## Introduction
//!
//! Most of the methods of this module are abstracted to higher-level
//! domain name distribution calls (pns-registrar).
//! But there are still some methods for domain authority management.
//!
//! ### Module functions
//!
//! - `burn` - destroy a domain name, requires the domain's operational privileges
//! - `set_official` - Set official account, needs manager privileges
use sp_weights::Weight;

pub use pallet::*;
use sp_runtime::DispatchError;
use sp_std::vec::Vec;

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use crate::{nft, traits::{OriginRecorder, Registrar, RecordCleaner, Ss58Updater}};
    use frame_support::pallet_prelude::*;
    use frame_support::traits::EnsureOrigin;
    use frame_system::pallet_prelude::*;
    use rns_types::{DomainHash, DomainTracing, Record};
    use sp_runtime::traits::Zero;
    use sp_std::vec::Vec;

    #[pallet::config]
    pub trait Config:
        frame_system::Config
        + crate::nft::Config<ClassData = (), TokenData = Record, TokenId = DomainHash>
    {

        type WeightInfo: WeightInfo;

        type Registrar: Registrar<AccountId = Self::AccountId>;

        type ManagerOrigin: EnsureOrigin<Self::RuntimeOrigin, Success = Self::AccountId>;

        /// Writes the SS58 record when a name is transferred.
        type Ss58Updater: Ss58Updater<AccountId = Self::AccountId>;

        /// Clears non-SS58 DNS records when a name changes hands.
        type RecordCleaner: RecordCleaner;

        /// Writes the ORIGIN record (block hash) when ownership changes.
        type OriginRecorder: OriginRecorder;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    /// `name_hash` -> (`origin`,`parent`) or `origin`
    #[pallet::storage]
    pub type RuntimeOrigin<T: Config> = StorageMap<_, Twox64Concat, DomainHash, DomainTracing>;

    /// (`root_node`, `child_node`) — index of all subnames under a root domain.
    ///
    /// All subdomains at any depth are stored under their root (top-level) domain hash.
    /// Used to enumerate and bulk-delete subnames when a root domain is transferred,
    /// released, or sold.
    #[pallet::storage]
    pub type SubNames<T: Config> =
        StorageDoubleMap<_, Twox64Concat, DomainHash, Twox64Concat, DomainHash, ()>;

    /// (`owner`, `subname_hash`) — index of all subnames currently held by an account.
    ///
    /// Updated atomically on subname mint, transfer, and burn.
    /// Enables reverse lookup: given an account, enumerate every subname they hold.
    #[pallet::storage]
    pub type AccountToSubnames<T: Config> =
        StorageDoubleMap<_, Twox64Concat, T::AccountId, Twox64Concat, DomainHash, ()>;

    /// `subname_hash` → SubnameRecord — authoritative record for each subdomain delegation.
    /// Present for all states (Offered, Active, Rejected). Deleted on revoke or release.
    #[pallet::storage]
    pub type SubnameRecords<T: Config> =
        StorageMap<_, Blake2_128Concat, DomainHash, rns_types::SubnameRecord<T::AccountId>>;

    /// (`target_account`, `subname_hash`) — pending-offer index.
    /// Inserted on offer, removed on accept/reject/revoke.
    #[pallet::storage]
    pub type OfferedToAccount<T: Config> =
        StorageDoubleMap<_, Twox64Concat, T::AccountId, Twox64Concat, DomainHash, ()>;

    /// `official`
    #[pallet::storage]
    pub type Official<T: Config> = StorageValue<_, T::AccountId>;

    #[pallet::genesis_config]
    pub struct GenesisConfig<T: Config> {
        pub origin: Vec<(DomainHash, DomainTracing)>,
        pub official: Option<T::AccountId>,
    }

    impl<T: Config> Default for GenesisConfig<T> {
        fn default() -> Self {
            GenesisConfig {
                origin: Vec::with_capacity(0),
                official: None,
            }
        }
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            for (node, origin) in self.origin.iter() {
                RuntimeOrigin::<T>::insert(node, origin);
            }
            if let Some(official) = &self.official {
                Official::<T>::put(official);
            }
        }
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Logged when a node is traded.
        Transferred {
            from: T::AccountId,
            to: T::AccountId,
            class_id: T::ClassId,
            token_id: T::TokenId,
        },
        /// Logged when a node is minted.
        TokenMinted {
            class_id: T::ClassId,
            token_id: T::TokenId,
            node: DomainHash,
            owner: T::AccountId,
        },
        /// Logged when a node is burned.
        TokenBurned {
            class_id: T::ClassId,
            token_id: T::TokenId,
            node: DomainHash,
            owner: T::AccountId,
            caller: T::AccountId,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// Not enough permissions to call functions.
        NoPermission,
        /// Not exist
        NotExist,
        /// Capacity is not enough to add new child nodes.
        CapacityNotEnough,
        /// You must clear all subdomains before burning a domain name.
        SubnodeNotClear,
        /// You may be burning a root node or an unknown node?
        BanBurnBaseNode,
        /// Pns official account is not initialized, please feedback to the official.
        OfficialNotInitiated,
        /// The name string you provided is invalid (illegal characters or wrong length).
        /// Use "sub.domain" for subdomains or "domain" for top-level names.
        InvalidName,
        /// The recipient is the owner of the root canonical name.
        /// A canonical name owner cannot hold a subname under their own domain.
        CannotOwnSubnameUnderOwnDomain,
        /// A SubnameRecord already exists for this label (offered, active, or rejected).
        SubnameAlreadyExists,
        /// No SubnameRecord found for this subname hash.
        SubnameNotFound,
        /// Offer cannot be accepted or rejected — it is not in the Offered state.
        SubnameNotOffered,
        /// Subname cannot be released — it is not in the Active state.
        SubnameNotActive,
        /// Caller is not the target of this subdomain offer or active record.
        NotSubnameTarget,
        /// Caller is not the parent domain owner for this subdomain.
        NotSubnameOfferer,
        /// Subnames cannot be created under another subname — depth is limited to one level.
        SubnameDepthExceeded,
        /// The offer target already holds a name (canonical or subdomain).
        /// An account may hold at most one name at a time.
        TargetAlreadyOwnsName,
        InternalHashConversion,
    }

    // helper
    impl<T: Config> Pallet<T> {
        #[inline]
        pub fn verify(caller: &T::AccountId, node: DomainHash) -> DispatchResult {
            let owner = &nft::Pallet::<T>::tokens(T::ClassId::zero(), node)
                .ok_or(Error::<T>::NotExist)?
                .owner;

            Self::verify_with_owner(caller, node, owner)?;

            Ok(())
        }

        #[inline]
        pub fn verify_with_owner(
            caller: &T::AccountId,
            _node: DomainHash,
            owner: &T::AccountId,
        ) -> DispatchResult {
            ensure!(caller == owner, Error::<T>::NoPermission);

            Ok(())
        }
    }
    impl<T: Config> Pallet<T> {
        pub(crate) fn do_burn(caller: T::AccountId, token: T::TokenId) -> DispatchResult {
            let class_id = T::ClassId::zero();
            let Some(token_info) = nft::Pallet::<T>::tokens(class_id, token) else {
                return Err(Error::<T>::NotExist.into())
            };

            let token_owner = token_info.owner;

            Self::verify_with_owner(&caller, token, &token_owner)?;

            let Some(origin) = RuntimeOrigin::<T>::get(token) else {
                return Err(Error::<T>::BanBurnBaseNode.into())
            };

            match origin {
                DomainTracing::RuntimeOrigin(origin) => {
                    // Subnames must have no children before they can be manually burned.
                    ensure!(token_info.data.children == 0, Error::<T>::SubnodeNotClear);
                    Self::sub_children(origin, class_id)?;
                    SubNames::<T>::remove(origin, token);
                    AccountToSubnames::<T>::remove(&token_owner, token);
                }
                DomainTracing::Root => {
                    // Auto-clear all subnames so callers don't need to do it manually.
                    Self::clear_subnames(token);
                    T::Registrar::clear_registrar_info(token, &token_owner)?;
                    // Canonical names are inserted into AccountToSubnames at mint time;
                    // remove that entry so the former owner can register again.
                    AccountToSubnames::<T>::remove(&token_owner, token);
                }
            }

            // Remove domain-keyed metadata that would otherwise leak after burn.
            RuntimeOrigin::<T>::remove(token);

            // Clear all DNS records for the node itself (SS58, ORIGIN, etc.).
            T::RecordCleaner::clear_all_records(token);

            nft::Pallet::<T>::burn(&token_owner, (class_id, token))?;

            Self::deposit_event(Event::<T>::TokenBurned {
                class_id,
                token_id: token,
                node: token,
                owner: token_owner,
                caller,
            });
            Ok(())
        }

        /// Delete a root-level name record from storage without ownership
        /// checks. Clears subnames, RegistrarInfo, DNS records, and the
        /// NFT token. No funds are touched — caller handles deposits.
        pub(crate) fn do_force_delete(token: T::TokenId) -> DispatchResult {
            let class_id = T::ClassId::zero();
            let Some(token_info) = nft::Pallet::<T>::tokens(class_id, token) else {
                return Err(Error::<T>::NotExist.into())
            };
            let token_owner = token_info.owner;

            // Only root-level names can be cleaned up this way.
            let Some(origin) = RuntimeOrigin::<T>::get(token) else {
                return Err(Error::<T>::BanBurnBaseNode.into())
            };
            match origin {
                DomainTracing::Root => {
                    Self::clear_subnames(token);
                    T::Registrar::clear_registrar_info(token, &token_owner)?;
                    AccountToSubnames::<T>::remove(&token_owner, token);
                }
                _ => return Err(Error::<T>::NotExist.into()),
            }

            RuntimeOrigin::<T>::remove(token);
            T::RecordCleaner::clear_all_records(token);
            nft::Pallet::<T>::burn(&token_owner, (class_id, token))?;

            Self::deposit_event(Event::<T>::TokenBurned {
                class_id,
                token_id: token,
                node: token,
                owner: token_owner.clone(),
                caller: token_owner,
            });
            Ok(())
        }

        #[cfg_attr(
            not(feature = "runtime-benchmarks"),
            frame_support::require_transactional
        )]
        pub(crate) fn mint_subname(
            owner: &T::AccountId,
            metadata: Vec<u8>,
            node: DomainHash,
            label_node: DomainHash,
            to: T::AccountId,
            capacity: u32,
            // `[maybe_pre_owner]`
            do_payments: impl FnOnce(Option<&T::AccountId>) -> DispatchResult,
        ) -> DispatchResult {
            let class_id = T::ClassId::zero();
            // dot: hash 0xce159cf34380757d1932a8e4a74e85e85957b0a7a52d9c566c0a3c8d6133d0f7
            // [206, 21, 156, 243, 67, 128, 117, 125, 25, 50, 168, 228, 167, 78, 133, 232, 89, 87,
            // 176, 167, 165, 45, 156, 86, 108, 10, 60, 141, 97, 51, 208, 247]
            let Some(node_info) = nft::Pallet::<T>::tokens(class_id, node) else {
                return Err(Error::<T>::NotExist.into());
            };

            let node_owner = node_info.owner;

            Self::verify_with_owner(owner, node, &node_owner)?;

            // Determine the root canonical name for this subname tree.
            let root_node = match RuntimeOrigin::<T>::get(node) {
                Some(DomainTracing::RuntimeOrigin(root)) => root,
                _ => node,
            };
            // The owner of the root canonical name cannot receive a subname under
            // their own domain — they would be vouching for themselves.
            if let Some(root_info) = nft::Tokens::<T>::get(class_id, root_node) {
                ensure!(to != root_info.owner, Error::<T>::CannotOwnSubnameUnderOwnDomain);
            }

            if let Some(info) = nft::Tokens::<T>::get(class_id, label_node) {
                T::Registrar::check_expires_registrable(label_node)?;

                let from = info.owner;

                do_payments(Some(&from))?;

                // Clear all subdomains and the root node's own DNS records before
                // handing the name to the new owner. This resets the children counter,
                // removes all SubnameRecords/SubNames/OfferedToAccount/AccountToSubnames
                // entries for every child, and wipes the root's own stale DNS data
                // (RPC, VALIDATOR, AVATAR, etc.) so the new owner starts with a clean slate.
                Self::clear_subnames(label_node);
                T::RecordCleaner::clear_all_records(label_node);

                AccountToSubnames::<T>::remove(&from, label_node);
                nft::Pallet::<T>::transfer(&from, &to, (class_id, label_node))?;
                AccountToSubnames::<T>::insert(&to, label_node, ());
            } else {
                do_payments(None)?;

                nft::Pallet::<T>::mint(&to, (class_id, label_node), metadata, Default::default())?;
                AccountToSubnames::<T>::insert(&to, label_node, ());

                if let Some(origin) = RuntimeOrigin::<T>::get(node) {
                    match origin {
                        DomainTracing::RuntimeOrigin(origin) => {
                            T::Registrar::check_expires_useable(origin)?;

                            Self::add_children_with_check(origin, class_id, capacity)?;

                            Self::add_children(node, class_id)?;

                            RuntimeOrigin::<T>::insert(
                                label_node,
                                DomainTracing::RuntimeOrigin(origin),
                            );
                            SubNames::<T>::insert(origin, label_node, ());
                        }
                        DomainTracing::Root => {
                            Self::add_children_with_check(node, class_id, capacity)?;

                            RuntimeOrigin::<T>::insert(
                                label_node,
                                DomainTracing::RuntimeOrigin(node),
                            );
                            SubNames::<T>::insert(node, label_node, ());
                        }
                    }
                } else {
                    Self::add_children(node, class_id)?;

                    RuntimeOrigin::<T>::insert(label_node, DomainTracing::Root);
                }
            }
            Self::deposit_event(Event::<T>::TokenMinted {
                class_id,
                token_id: label_node,
                node,
                owner: to,
            });

            Ok(())
        }
        pub(crate) fn add_children(node: DomainHash, class_id: T::ClassId) -> DispatchResult {
            nft::Tokens::<T>::mutate(class_id, node, |data| -> DispatchResult {
                let Some(info) = data else {
                    return Err(Error::<T>::NotExist.into())
                };

                let node_children = info.data.children;
                info.data.children = node_children
                    .checked_add(1)
                    .ok_or(sp_runtime::ArithmeticError::Overflow)?;
                Ok(())
            })
        }
        pub(crate) fn add_children_with_check(
            node: DomainHash,
            class_id: T::ClassId,
            capacity: u32,
        ) -> DispatchResult {
            nft::Tokens::<T>::mutate(class_id, node, |data| -> DispatchResult {
                let Some(info) = data else {
                    return Err(Error::<T>::NotExist.into())
                };
                let node_children = info.data.children;
                ensure!(node_children < capacity, Error::<T>::CapacityNotEnough);
                info.data.children = node_children
                    .checked_add(1)
                    .ok_or(sp_runtime::ArithmeticError::Overflow)?;
                Ok(())
            })
        }
        /// Ensure `from` is a caller.
        #[cfg_attr(
            not(feature = "runtime-benchmarks"),
            frame_support::require_transactional
        )]
        pub fn do_transfer(
            from: &T::AccountId,
            to: &T::AccountId,
            token: T::TokenId,
        ) -> DispatchResult {
            let class_id = T::ClassId::zero();
            let token_info =
                nft::Pallet::<T>::tokens(class_id, token).ok_or(Error::<T>::NotExist)?;

            let owner = token_info.owner;

            Self::verify_with_owner(from, token, &owner)?;

            let Some(origin) = RuntimeOrigin::<T>::get(token) else {
                return Err(Error::<T>::NotExist.into())
            };

            match origin {
                DomainTracing::RuntimeOrigin(root) => {
                    T::Registrar::check_expires_renewable(root)?;
                    // The recipient cannot be the owner of the root canonical name.
                    if let Some(root_info) = nft::Tokens::<T>::get(class_id, root) {
                        ensure!(to != &root_info.owner, Error::<T>::CannotOwnSubnameUnderOwnDomain);
                    }
                    AccountToSubnames::<T>::remove(&owner, token);
                    AccountToSubnames::<T>::insert(to, token, ());
                }
                DomainTracing::Root => {
                    T::Registrar::check_expires_renewable(token)?;
                    // Clear all subnames so the new owner receives a clean domain.
                    Self::clear_subnames(token);
                }
            }

            nft::Pallet::<T>::transfer(&owner, to, (class_id, token))?;

            // Clear stale DNS records from the previous owner, then update SS58.
            // ORIGIN is intentionally NOT rewritten here — it pins the initial
            // registration block and must survive ownership changes (trait doc at
            // `traits.rs:OriginRecorder`). Overwriting on transfer would forge
            // "proof of registration block" for any consumer of `pns_getInfo`.
            T::RecordCleaner::clear_records_except_ss58(token);
            T::Ss58Updater::update_ss58(token, to)?;

            Self::deposit_event(Event::<T>::Transferred {
                from: owner,
                to: to.clone(),
                class_id,
                token_id: token,
            });

            Ok(())
        }

        pub(crate) fn sub_children(node: DomainHash, class_id: T::ClassId) -> DispatchResult {
            nft::Tokens::<T>::mutate(class_id, node, |data| -> DispatchResult {
                let Some(info) = data else {
                    return  Err(Error::<T>::NotExist.into())
                };

                let node_children = info.data.children;
                info.data.children = node_children
                    .checked_sub(1)
                    .ok_or(sp_runtime::ArithmeticError::Overflow)?;
                Ok(())
            })
        }

        /// Bulk-delete all subnames registered under `root_node`.
        ///
        /// For each child:
        /// - All DNS records (Records, Accounts, Texts) are wiped.
        /// - The NFT is burned (removes from Tokens and TokensByOwner).
        /// - The RuntimeOrigin entry is removed.
        ///
        /// After all children are removed the SubNames prefix is cleared and
        /// the root's children counter is reset to zero.
        fn clear_subnames(root_node: DomainHash) {
            let class_id = T::ClassId::zero();
            const MAX_CHILDREN_PER_CLEANUP: usize = 100;
            let children: sp_std::vec::Vec<DomainHash> =
                SubNames::<T>::iter_prefix(root_node)
                    .take(MAX_CHILDREN_PER_CLEANUP)
                    .map(|(child, _)| child)
                    .collect();
            for child in children {
                T::RecordCleaner::clear_all_records(child);
                RuntimeOrigin::<T>::remove(child);
                // Clear new-style SubnameRecord delegation.
                if let Some(record) = SubnameRecords::<T>::take(child) {
                    match record.state {
                        rns_types::SubnameState::Offered | rns_types::SubnameState::Rejected => {
                            OfferedToAccount::<T>::remove(&record.target, child);
                        }
                        rns_types::SubnameState::Active => {
                            AccountToSubnames::<T>::remove(&record.target, child);
                        }
                    }
                }
                // Clear old-style NFT subname (legacy path).
                if let Some(info) = nft::Tokens::<T>::get(class_id, child) {
                    AccountToSubnames::<T>::remove(&info.owner, child);
                    let _ = nft::Pallet::<T>::burn(&info.owner, (class_id, child));
                }
            }
            let _ = SubNames::<T>::clear_prefix(root_node, MAX_CHILDREN_PER_CLEANUP as u32, None);
            nft::Tokens::<T>::mutate(class_id, root_node, |data| {
                if let Some(info) = data {
                    info.data.children = 0;
                }
            });
        }
    }
    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(3)]
        #[pallet::weight(T::WeightInfo::set_official())]
        #[frame_support::transactional]
        pub fn set_official(origin: OriginFor<T>, official: T::AccountId) -> DispatchResult {
            let _who = T::ManagerOrigin::ensure_origin(origin)?;
            let old_official = Official::<T>::take();

            Official::<T>::put(&official);

            if let Some(old_official) = old_official {
                nft::Pallet::<T>::transfer(
                    &old_official,
                    &official,
                    (T::ClassId::zero(), T::Registrar::basenode()),
                )?;
            }

            nft::Classes::<T>::mutate(T::ClassId::zero(), |info| {
                if let Some(info) = info {
                    info.owner = official;
                }
            });

            Ok(())
        }
    }
}

use crate::traits::{RecordCleaner as _, Registrar as _};
use frame_support::{
    dispatch::DispatchResult,
    ensure,
};
use rns_types::DomainHash;
pub trait WeightInfo {
    fn set_official() -> Weight;
}
// TODO: replace litentry
impl<T: pallet::Config> crate::traits::NFT<T::AccountId> for pallet::Pallet<T> {
    type ClassId = T::ClassId;

    type TokenId = T::TokenId;

    type Balance = u128;

    fn balance(who: &T::AccountId) -> Self::Balance {
        const MAX_COUNT: usize = 10;
        crate::nft::TokensByOwner::<T>::iter_prefix((who,)).take(MAX_COUNT).count() as u128
    }

    fn owner(token: (Self::ClassId, Self::TokenId)) -> Option<T::AccountId> {
        crate::nft::Pallet::<T>::tokens(token.0, token.1).map(|t| t.owner)
    }
    #[cfg_attr(
        not(feature = "runtime-benchmarks"),
        frame_support::require_transactional
    )]
    fn transfer(
        from: &T::AccountId,
        to: &T::AccountId,
        token: (Self::ClassId, Self::TokenId),
    ) -> DispatchResult {
        use sp_runtime::traits::Zero;
        ensure!(token.0 == T::ClassId::zero(), Error::<T>::NotExist);

        Self::do_transfer(from, to, token.1)
    }
}

impl<T: pallet::Config> crate::traits::Registry for pallet::Pallet<T> {
    type AccountId = T::AccountId;

    #[cfg_attr(
        not(feature = "runtime-benchmarks"),
        frame_support::require_transactional
    )]
    fn mint_subname(
        node_owner: &Self::AccountId,
        node: DomainHash,
        label_node: DomainHash,
        to: Self::AccountId,
        capacity: u32,
        do_payments: impl FnOnce(Option<&T::AccountId>) -> DispatchResult,
    ) -> DispatchResult {
        let metadata = Vec::with_capacity(0);
        Self::mint_subname(
            node_owner,
            metadata,
            node,
            label_node,
            to,
            capacity,
            do_payments,
        )
    }

    fn available(caller: &Self::AccountId, node: DomainHash) -> DispatchResult {
        pallet::Pallet::<T>::verify(caller, node)
    }

    fn owner_of(node: DomainHash) -> Option<Self::AccountId> {
        crate::nft::Pallet::<T>::tokens(T::ClassId::default(), node).map(|t| t.owner)
    }

    #[frame_support::require_transactional]
    fn transfer(from: &Self::AccountId, to: &Self::AccountId, node: DomainHash) -> DispatchResult {
        Self::do_transfer(from, to, node)
    }

    #[frame_support::require_transactional]
    fn burn(caller: Self::AccountId, node: DomainHash) -> DispatchResult {
        Self::do_burn(caller, node)
    }

    #[frame_support::require_transactional]
    fn force_delete(node: DomainHash) -> DispatchResult {
        Self::do_force_delete(node)
    }

    fn has_active_subname(account: &Self::AccountId) -> bool {
        pallet::AccountToSubnames::<T>::iter_prefix(account).next().is_some()
    }

    fn offer_subname(
        parent: DomainHash,
        label_node: DomainHash,
        label_bytes: frame_support::BoundedVec<u8, sp_core::ConstU32<63>>,
        to: Self::AccountId,
        capacity: u32,
    ) -> DispatchResult {
        use sp_runtime::traits::Zero;
        // Depth check: parent must be a root domain (.dot name), not a subname.
        match pallet::RuntimeOrigin::<T>::get(parent) {
            Some(rns_types::DomainTracing::Root) => {}
            _ => return Err(pallet::Error::<T>::SubnameDepthExceeded.into()),
        }
        // The target cannot be the parent domain's NFT owner.
        let class_id = T::ClassId::zero();
        if let Some(parent_token) = crate::nft::Tokens::<T>::get(class_id, parent) {
            ensure!(to != parent_token.owner, pallet::Error::<T>::CannotOwnSubnameUnderOwnDomain);
        }
        // No duplicate record in any state.
        ensure!(
            !pallet::SubnameRecords::<T>::contains_key(label_node),
            pallet::Error::<T>::SubnameAlreadyExists
        );
        // Reserve capacity slot (children counter on parent NFT token data).
        Self::add_children_with_check(parent, class_id, capacity)?;
        pallet::SubnameRecords::<T>::insert(
            label_node,
            rns_types::SubnameRecord {
                parent,
                label: label_bytes,
                target: to.clone(),
                state: rns_types::SubnameState::Offered,
            },
        );
        pallet::OfferedToAccount::<T>::insert(&to, label_node, ());
        pallet::SubNames::<T>::insert(parent, label_node, ());
        Ok(())
    }

    fn accept_subname_offer(
        label_node: DomainHash,
        acceptor: &Self::AccountId,
    ) -> Result<DomainHash, DispatchError> {
        // An account may hold at most one name. Block if the acceptor already holds
        // a canonical name or any other active subdomain.
        ensure!(
            !T::Registrar::has_valid_canonical_name(acceptor),
            pallet::Error::<T>::TargetAlreadyOwnsName
        );
        ensure!(
            pallet::AccountToSubnames::<T>::iter_prefix(acceptor).next().is_none(),
            pallet::Error::<T>::TargetAlreadyOwnsName
        );
        let mut parent = DomainHash::default();
        pallet::SubnameRecords::<T>::try_mutate(label_node, |maybe_record| -> DispatchResult {
            let record = maybe_record.as_mut().ok_or(pallet::Error::<T>::SubnameNotFound)?;
            ensure!(
                record.state == rns_types::SubnameState::Offered,
                pallet::Error::<T>::SubnameNotOffered
            );
            ensure!(record.target == *acceptor, pallet::Error::<T>::NotSubnameTarget);
            parent = record.parent;
            record.state = rns_types::SubnameState::Active;
            pallet::OfferedToAccount::<T>::remove(acceptor, label_node);
            pallet::AccountToSubnames::<T>::insert(acceptor, label_node, ());
            Ok(())
        })?;

        // Mint the canonical NFT to the acceptor. The resolver's ownership gate
        // (`RegistryChecker::check_node_useable` → `registry::Pallet::verify` →
        // `nft::Pallet::tokens(0, node)`) requires an NFT entry; without this
        // the acceptor holds a subname record but cannot call `set_record` /
        // `set_text` etc. — the feature was unreachable before this fix. NFTs
        // remain the canonical ownership token everywhere in PNS.
        use sp_runtime::traits::Zero;
        let class_id = T::ClassId::zero();
        crate::nft::Pallet::<T>::mint(
            acceptor,
            (class_id, label_node),
            sp_std::vec::Vec::new(),
            Default::default(),
        )?;
        // Track the subname's domain origin as rooted at the parent so
        // downstream lookups (chain walks, cleanup on root release) can
        // resolve the lineage.
        pallet::RuntimeOrigin::<T>::insert(
            label_node,
            rns_types::DomainTracing::RuntimeOrigin(parent),
        );
        Ok(parent)
    }

    fn reject_subname_offer(
        label_node: DomainHash,
        caller: &Self::AccountId,
    ) -> DispatchResult {
        pallet::SubnameRecords::<T>::try_mutate(label_node, |maybe_record| -> DispatchResult {
            let record = maybe_record.as_mut().ok_or(pallet::Error::<T>::SubnameNotFound)?;
            ensure!(
                record.state == rns_types::SubnameState::Offered,
                pallet::Error::<T>::SubnameNotOffered
            );
            ensure!(record.target == *caller, pallet::Error::<T>::NotSubnameTarget);
            record.state = rns_types::SubnameState::Rejected;
            pallet::OfferedToAccount::<T>::remove(caller, label_node);
            Ok(())
        })
    }

    fn revoke_subname(parent: DomainHash, label_node: DomainHash) -> DispatchResult {
        use sp_runtime::traits::Zero;
        let record = pallet::SubnameRecords::<T>::take(label_node)
            .ok_or(pallet::Error::<T>::SubnameNotFound)?;
        ensure!(record.parent == parent, pallet::Error::<T>::NotSubnameOfferer);
        let class_id = T::ClassId::zero();
        match record.state {
            rns_types::SubnameState::Offered | rns_types::SubnameState::Rejected => {
                pallet::OfferedToAccount::<T>::remove(&record.target, label_node);
            }
            rns_types::SubnameState::Active => {
                pallet::AccountToSubnames::<T>::remove(&record.target, label_node);
                T::RecordCleaner::clear_all_records(label_node);
                // Burn the canonical NFT minted at accept-time (M1
                // fix). Without this, the NFT leaks on revoke — the
                // subname is removed from every tracking index but
                // `nft::Tokens[0, label_node]` would still show the
                // old holder as owner. Also cleans up RuntimeOrigin.
                let _ = crate::nft::Pallet::<T>::burn(&record.target, (class_id, label_node));
                pallet::RuntimeOrigin::<T>::remove(label_node);
            }
        }
        pallet::SubNames::<T>::remove(parent, label_node);
        Self::sub_children(parent, class_id)?;
        Ok(())
    }

    fn release_subname(
        label_node: DomainHash,
        by: &Self::AccountId,
    ) -> Result<DomainHash, DispatchError> {
        use sp_runtime::traits::Zero;
        let record = pallet::SubnameRecords::<T>::take(label_node)
            .ok_or(pallet::Error::<T>::SubnameNotFound)?;
        ensure!(
            record.state == rns_types::SubnameState::Active,
            pallet::Error::<T>::SubnameNotActive
        );
        ensure!(record.target == *by, pallet::Error::<T>::NotSubnameTarget);
        pallet::AccountToSubnames::<T>::remove(by, label_node);
        pallet::SubNames::<T>::remove(record.parent, label_node);
        let class_id = T::ClassId::zero();
        Self::sub_children(record.parent, class_id)?;
        T::RecordCleaner::clear_all_records(label_node);
        // Burn the canonical NFT minted at accept-time (M1 fix).
        // Without this the NFT leaks on voluntary release.
        let _ = crate::nft::Pallet::<T>::burn(by, (class_id, label_node));
        pallet::RuntimeOrigin::<T>::remove(label_node);
        Ok(record.parent)
    }

    fn revoke_pending_offer_for_target(
        label_node: DomainHash,
        target: &Self::AccountId,
    ) -> DispatchResult {
        let record = pallet::SubnameRecords::<T>::get(label_node)
            .ok_or(pallet::Error::<T>::SubnameNotFound)?;
        ensure!(
            record.state == rns_types::SubnameState::Offered,
            pallet::Error::<T>::SubnameNotOffered
        );
        ensure!(record.target == *target, pallet::Error::<T>::NotSubnameTarget);
        // Delegate full cleanup to revoke_subname (removes record, SubNames entry,
        // OfferedToAccount entry, and decrements the parent's children counter).
        Self::revoke_subname(record.parent, label_node)
    }
}

impl<T: Config> crate::traits::Official for pallet::Pallet<T> {
    type AccountId = T::AccountId;

    fn get_official_account() -> Result<Self::AccountId, DispatchError> {
        Official::<T>::get().ok_or_else(|| Error::<T>::OfficialNotInitiated.into())
    }
}

impl WeightInfo for () {
    fn set_official() -> Weight { Weight::from_parts(150_000_000, 500) }
}

#[cfg(feature = "runtime-benchmarks")]
#[frame_benchmarking::v2::benchmarks]
mod benchmarks {
    use super::*;
    use frame_benchmarking::v2::*;
    use frame_system::RawOrigin;
    use crate::traits::Registrar;

    #[benchmark]
    fn set_official() {
        // The dev chain genesis seeds the basenode NFT to the initial
        // official (Alice) and the `Official` storage slot. This
        // benchmark hands the role off to a fresh account, exercising
        // both the storage swap and the NFT transfer in the extrinsic.
        // Running under runtime-benchmarks with the test-attestation
        // feature picks up the paseo dev genesis state.
        let new_official: T::AccountId = whitelisted_caller();
        let basenode = <T as pallet::Config>::Registrar::basenode();
        // Precondition sanity: if genesis hasn't seeded Official (e.g. a
        // runtime without PNS dev genesis), install the current owner
        // from NFT state so the transfer branch still executes.
        if pallet::Official::<T>::get().is_none() {
            use sp_runtime::traits::Zero;
            let class_id = T::ClassId::zero();
            if let Some(token) = crate::nft::Tokens::<T>::get(class_id, basenode) {
                pallet::Official::<T>::put(&token.owner);
            }
        }

        #[extrinsic_call]
        _(RawOrigin::Root, new_official.clone());

        assert_eq!(pallet::Official::<T>::get(), Some(new_official));
    }
}
