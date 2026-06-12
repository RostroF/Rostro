/*!
# Resolvers
This module provides functionality for domain name resolution. Most of these interfaces are interfaces provided for subsequent cooperation with wallets.

### Module functions
- `set_text` - set text parsing, requires domain ownership and the domain to not be expired
- `set_record` - set a DNS record, same requirements as above
!*/

use codec::{Encode, MaxEncodedLen, DecodeWithMemTracking};

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::{dispatch::DispatchResult, pallet_prelude::*};
    use frame_system::pallet_prelude::*;
    use rns_types::ddns::codec_type::RecordType;
    use scale_info::TypeInfo;

    use super::RegistryChecker;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        const OFFCHAIN_PREFIX: &'static [u8];

        type WeightInfo: WeightInfo;

        type MaxContentLen: Get<u32>;

        type RegistryChecker: RegistryChecker<AccountId = Self::AccountId>;
    }

    pub type Content<T> = BoundedVec<u8, <T as Config>::MaxContentLen>;

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[derive(Encode, Decode, Clone, Eq, PartialEq, MaxEncodedLen, Debug, TypeInfo, DecodeWithMemTracking)]
    #[derive(serde::Serialize, serde::Deserialize)]
    pub enum TextKind {
        Email,
        Url,
        Avatar,
        Description,
        Notice,
        Keywords,
        Twitter,
        Github,
        Ipfs,
    }

    /// text mapping
    #[pallet::storage]
    pub type Texts<T: Config> = StorageDoubleMap<
        _,
        Twox64Concat,
        rns_types::DomainHash,
        Twox64Concat,
        TextKind,
        Content<T>,
        ValueQuery,
    >;

    #[pallet::storage]
    pub type RecordCount<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        rns_types::DomainHash,
        u32,
        ValueQuery,
    >;

    /// ddns record
    #[pallet::storage]
    pub type Records<T: Config> = StorageDoubleMap<
        _,
        Twox64Concat,
        rns_types::DomainHash,
        Twox64Concat,
        rns_types::ddns::codec_type::RecordType,
        Content<T>,
        ValueQuery,
    >;

    #[pallet::genesis_config]
    pub struct GenesisConfig<T: Config> {
        pub texts: Vec<(rns_types::DomainHash, TextKind, Content<T>)>,
    }

    impl<T: Config> Default for GenesisConfig<T> {
        fn default() -> Self {
            GenesisConfig {
                texts: Vec::new(),
            }
        }
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            for (node, text_kind, text) in self.texts.iter().cloned() {
                Texts::<T>::insert(node, text_kind, text);
            }
        }
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        TextsChanged {
            node: rns_types::DomainHash,
            kind: TextKind,
            content: Content<T>,
        },
        RecordsChanged {
            node: rns_types::DomainHash,
            kind: RecordType,
            content: Content<T>,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        InvalidPermission,
        /// The SS58 record is managed by the chain (set on register/transfer/buy).
        /// Owners may not edit it directly via `set_record`.
        Ss58RecordProtected,
        /// The name string you provided is invalid (illegal characters, wrong length,
        /// or unsupported format).  Use `"sub.domain"` for subdomains or `"domain"`
        /// for top-level names.
        InvalidName,
        /// The record type is not in the set of user-settable types.
        /// Only declared RNS attribute types are accepted.
        InvalidRecordType,
    }

    impl<T: Config> Pallet<T> {
        /// Resolve a human-readable name string to a [`DomainHash`].
        ///
        /// - `"sub.domain"` → namehash of subdomain `sub` under `domain.<tld>`.
        /// - `"domain"` (no dot) → namehash of the top-level `domain.<tld>`.
        fn name_to_node(name: &[u8]) -> Result<rns_types::DomainHash, sp_runtime::DispatchError> {
            rns_types::parse_name_to_node(name, &T::RegistryChecker::base_node())
                .ok_or(Error::<T>::InvalidName.into())
        }
    }

    #[pallet::view_functions]
    impl<T: Config> Pallet<T> {
        /// Return DNS records for a domain namehash.
        ///
        /// SS58 (65280) and ORIGIN (65290) are always included in the response as
        /// proof anchors — they are chain-managed and not caller-controlled.
        /// Additional types are fetched only if explicitly listed in `record_types`.
        ///
        /// The following types are blocked from `record_types` and silently dropped
        /// if present — they are chain-managed proof anchors that are auto-included
        /// in every response and cannot be set by users:
        ///   SS58, ORIGIN
        pub fn lookup(node: rns_types::DomainHash, record_types: Vec<RecordType>) -> Vec<(RecordType, Vec<u8>)> {
            const MAX_QUERY_TYPES: usize = 3;
            let record_types: Vec<RecordType> = record_types.into_iter().take(MAX_QUERY_TYPES).collect();
            const BLOCKED: &[RecordType] = &[
                RecordType::SS58,   // chain-managed, always returned unconditionally
                RecordType::ORIGIN, // chain-managed, always returned unconditionally
            ];

            let mut results = Vec::new();

            // SS58 and ORIGIN are proof anchors — included unconditionally.
            let ss58 = Records::<T>::get(node, RecordType::SS58);
            if !ss58.is_empty() {
                results.push((RecordType::SS58, ss58.to_vec()));
            }
            let origin = Records::<T>::get(node, RecordType::ORIGIN);
            if !origin.is_empty() {
                results.push((RecordType::ORIGIN, origin.to_vec()));
            }

            for rt in record_types {
                if BLOCKED.contains(&rt) {
                    continue;
                }
                let content = Records::<T>::get(node, rt);
                if !content.is_empty() {
                    results.push((rt, content.to_vec()));
                }
            }
            results
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Set a DNS record for a domain.
        ///
        /// `name` accepts two forms:
        /// - `"sub.domain"` — targets the subdomain `sub.domain.<tld>`.
        /// - `"domain"` (no dot) — targets the top-level domain `domain.<tld>`.
        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::set_record(content.len() as u32))]
        pub fn set_record(
            origin: OriginFor<T>,
            name: Vec<u8>,
            record_type: RecordType,
            content: Content<T>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            const USER_SETTABLE: &[RecordType] = &[
                RecordType::A, RecordType::AAAA, RecordType::CNAME, RecordType::TXT,
                RecordType::RPC, RecordType::VALIDATOR,
                RecordType::PUBKEY1, RecordType::PUBKEY2, RecordType::PUBKEY3,
                RecordType::AVATAR, RecordType::CONTRACT,
                RecordType::IPFS, RecordType::CONTENT,
            ];
            ensure!(
                USER_SETTABLE.contains(&record_type),
                Error::<T>::InvalidRecordType
            );
            let node = Self::name_to_node(&name)?;
            ensure!(
                T::RegistryChecker::check_node_useable(node, &who),
                Error::<T>::InvalidPermission
            );
            const MAX_RECORDS_PER_NAME: u32 = 20;
            let is_update = Records::<T>::contains_key(node, record_type);
            if !is_update {
                let count = RecordCount::<T>::get(node);
                ensure!(count < MAX_RECORDS_PER_NAME, Error::<T>::InvalidPermission);
                RecordCount::<T>::insert(node, count.saturating_add(1));
            }
            Records::<T>::insert(node, &record_type, &content);
            Self::deposit_event(Event::<T>::RecordsChanged {
                node,
                kind: record_type,
                content,
            });
            Ok(())
        }

        /// Set a text record for a domain.
        ///
        /// `name` accepts two forms:
        /// - `"sub.domain"` — targets the subdomain `sub.domain.<tld>`.
        /// - `"domain"` (no dot) — targets the top-level domain `domain.<tld>`.
        #[pallet::call_index(3)]
        #[pallet::weight(T::WeightInfo::set_text(content.len() as u32))]
        pub fn set_text(
            origin: OriginFor<T>,
            name: Vec<u8>,
            kind: TextKind,
            content: Content<T>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let node = Self::name_to_node(&name)?;
            ensure!(
                T::RegistryChecker::check_node_useable(node, &who),
                Error::<T>::InvalidPermission
            );
            Texts::<T>::insert(node, &kind, &content);
            Self::deposit_event(Event::<T>::TextsChanged { node, kind, content });
            Ok(())
        }

    }
}

use frame_support::dispatch::DispatchResult;
use sp_weights::Weight;
use rns_types::{ddns::codec_type::RecordType, DomainHash};
use sp_std::vec::Vec;

pub trait WeightInfo {
    fn set_text(content_len: u32) -> Weight;
    fn set_record(content_len: u32) -> Weight;
}

pub trait RegistryChecker {
    type AccountId;
    fn check_node_useable(node: rns_types::DomainHash, owner: &Self::AccountId) -> bool;
    /// Returns the TLD base node used by the chain (e.g. `RST_BASENODE`).
    /// Required so the resolver pallet can compute domain hashes from name strings.
    fn base_node() -> rns_types::DomainHash;
}

impl WeightInfo for () {
    fn set_text(_content_len: u32) -> Weight { Weight::from_parts(200_000_000, 2_000) }
    fn set_record(_content_len: u32) -> Weight { Weight::from_parts(200_000_000, 2_000) }
}

#[cfg(feature = "runtime-benchmarks")]
#[frame_benchmarking::v2::benchmarks(
    where T: pallet_rns_registrar::registrar::Config,
)]
mod benchmarks {
    use super::*;
    use frame_benchmarking::v2::*;
    use frame_support::{traits::Currency, BoundedVec};
    use frame_system::RawOrigin;
    use sp_runtime::SaturatedConversion;
    use sp_std::vec;
    use super::pallet::TextKind;

    const BENCH_NAME: &[u8] = b"benchresolver";

    /// Fund + register a canonical name for the caller so the
    /// resolver's `check_node_useable` gate passes.
    fn setup_owned_name<T>(caller: &T::AccountId)
    where
        T: pallet_rns_registrar::registrar::Config,
    {
        let big: pallet_rns_registrar::registrar::BalanceOf<T> =
            (u128::MAX / 2).saturated_into();
        <T as pallet_rns_registrar::registrar::Config>::Currency::make_free_balance_be(caller, big);
        pallet_rns_registrar::registrar::Pallet::<T>::register(
            RawOrigin::Signed(caller.clone()).into(),
            BENCH_NAME.to_vec(),
            None,
        )
        .expect("register_root bench setup");
    }

    #[benchmark]
    fn set_record(s: Linear<0, 1024>) {
        let caller: T::AccountId = whitelisted_caller();
        setup_owned_name::<T>(&caller);
        let content: Content<T> = BoundedVec::try_from(vec![0u8; s as usize])
            .unwrap_or_else(|_| BoundedVec::try_from(vec![0u8; 1024]).unwrap());

        #[extrinsic_call]
        _(
            RawOrigin::Signed(caller),
            BENCH_NAME.to_vec(),
            RecordType::TXT,
            content,
        );
    }

    #[benchmark]
    fn set_text(s: Linear<0, 1024>) {
        let caller: T::AccountId = whitelisted_caller();
        setup_owned_name::<T>(&caller);
        let content: Content<T> = BoundedVec::try_from(vec![0u8; s as usize])
            .unwrap_or_else(|_| BoundedVec::try_from(vec![0u8; 1024]).unwrap());

        #[extrinsic_call]
        _(
            RawOrigin::Signed(caller),
            BENCH_NAME.to_vec(),
            TextKind::Email,
            content,
        );
    }
}

impl<C: Config> Pallet<C> {
    /// Write the SS58 record for `node` from the owner's encoded account bytes.
    ///
    /// This is an internal privileged path: it bypasses the normal user-facing
    /// permission check and is intended to be called only by trusted pallets
    /// (registrar on registration, registry on transfer, marketplace on buy).
    pub fn set_ss58_record(node: DomainHash, owner: &C::AccountId) -> DispatchResult
    where
        C::AccountId: codec::Encode,
    {
        use codec::Encode;
        let bytes = owner.encode();
        let content = pallet::Content::<C>::try_from(bytes)
            .map_err(|_| pallet::Error::<C>::InvalidPermission)?;
        pallet::Records::<C>::insert(node, RecordType::SS58, content);
        Ok(())
    }

    /// Write the ORIGIN record for `node` — the block hash of the block in which
    /// the name was originally registered. Used as on-chain proof of purchase.
    ///
    /// Like `set_ss58_record`, this is an internal privileged path called only
    /// by the registrar on registration.
    pub fn set_origin_record(node: DomainHash, block_hash: [u8; 32]) -> DispatchResult {
        let content = pallet::Content::<C>::try_from(block_hash.to_vec())
            .map_err(|_| pallet::Error::<C>::InvalidPermission)?;
        pallet::Records::<C>::insert(node, RecordType::ORIGIN, content);
        Ok(())
    }

    /// Remove all DNS records for `node` except the SS58 record.
    ///
    /// Called on ownership transfers so the new owner does not inherit stale
    /// DNS data (RPC endpoints, validator stash, parachain IDs, etc.) from
    /// the previous owner.  `Texts` are intentionally left
    /// untouched — only `Records` entries are cleared here.
    ///
    /// `SS58` is preserved because the transfer path writes the new owner's
    /// SS58 immediately after, and `ORIGIN` is preserved because it pins
    /// the initial registration block of the name — proof-of-registration
    /// attestations (reputation scoring, seniority, etc.) depend on ORIGIN
    /// surviving ownership changes. Overwriting or wiping ORIGIN on transfer
    /// would let a round-trip sale forge "proof of registration block" for
    /// any `pns_getInfo` consumer.
    pub fn clear_records_except_ss58(node: DomainHash) {
        const MAX_CLEANUP: usize = 100;
        let to_remove: Vec<RecordType> = pallet::Records::<C>::iter_prefix(node)
            .filter(|(rt, _)| *rt != RecordType::SS58 && *rt != RecordType::ORIGIN)
            .take(MAX_CLEANUP)
            .map(|(rt, _)| rt)
            .collect();
        let removed = to_remove.len() as u32;
        for rt in to_remove {
            pallet::Records::<C>::remove(node, rt);
        }
        let current = pallet::RecordCount::<C>::get(node);
        pallet::RecordCount::<C>::insert(node, current.saturating_sub(removed));
    }

    /// Remove ALL DNS records for `node` (Records and Texts).
    ///
    /// Called when a domain is completely destroyed (e.g. a subname that is
    /// auto-cleared when its parent is transferred, released, or sold).
    pub fn clear_all_records(node: DomainHash) {
        const MAX_CLEANUP: u32 = 100;
        let _ = pallet::Records::<C>::clear_prefix(node, MAX_CLEANUP, None);
        let _ = pallet::Texts::<C>::clear_prefix(node, MAX_CLEANUP, None);
        pallet::RecordCount::<C>::remove(node);
    }
}
