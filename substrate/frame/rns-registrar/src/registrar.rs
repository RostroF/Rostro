//! # Registrar
//! This module is the registration center for domain names,
//! and it also records some important information about domain name registration:
//!
//! ```rust
//!     pub struct RegistrarInfo<Duration, Balance> {
//!         /// Expiration time
//!         pub expire: Duration,
//!         /// Capacity of subdomains that can be created
//!         pub capacity: u32,
//!         /// Registration fee paid at registration time
//!         pub register_fee: Balance,
//!     }
//! ```
//! ## Introduction
//! Some of the methods in this module involve the transfer of money,
//! so you need to be as careful as possible when reviewing them.
//!
//! 5% of the registration fee is held on the registrant's account as a
//! cleanup deposit (pallet-scoped hold). The remaining 95% is withdrawn
//! and split: 40% to the block author, 55% to PnsCustodian.
//!
//! ### Module functions
//! - `add_reserved` - adds a pre-reserved domain name (pre-reserved domains cannot be registered), requires manager privileges
//! - `remove_reserved` - removes a reserved domain name, requires manager privileges
//! - `register` - register a domain name
//! - `renew` - renew a domain name, requires caller to own the canonical name
//! - `transfer` - transfer a domain name, requires the caller to own the canonical name
//! - `release_name` - burn the caller's canonical name, returning it to the open pool
//! - `mint_subname` - create a subdomain, requires the caller to have permission to operate the domain

pub use pallet::*;
use rns_types::DomainHash;

pub type BalanceOf<T> = <<T as Config>::Currency as frame_support::traits::Currency<
    <T as frame_system::Config>::AccountId,
>>::Balance;

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use crate::traits::{BlockAuthor, IsRegistrarOpen, Label, Official, OriginRecorder, PriceOracle, RecordCleaner, Registry, Ss58Updater};
    use frame_support::{
        pallet_prelude::*,
        traits::{
            Currency, EnsureOrigin, ExistenceRequirement, Time,
            tokens::fungible::hold::Mutate as HoldMutate,
        },
        Twox64Concat,
    };
    use frame_system::{ensure_signed, pallet_prelude::*};
    use rns_types::{DomainHash, RegistrarInfo};
    use rp_runtime::traits::{AtLeast32Bit, CheckedAdd, MaybeSerializeDeserialize, Saturating, StaticLookup, Zero};
    use rp_runtime::{ArithmeticError, SaturatedConversion};
    use rp_std::vec::Vec;

    #[pallet::config]
    pub trait Config: frame_system::Config {

        type Registry: Registry<AccountId = Self::AccountId, Balance = BalanceOf<Self>>;

        type Currency: Currency<Self::AccountId>;

        /// Composite hold reason. Must include this pallet's `HoldReason`.
        type RuntimeHoldReason: From<HoldReason>;

        /// Fungible hold interface — used to place pallet-scoped holds on
        /// the registrant's balance. Only this pallet can release them.
        type Fungible: HoldMutate<
            Self::AccountId,
            Reason = Self::RuntimeHoldReason,
            Balance = BalanceOf<Self>,
        >;

        type NowProvider: Time<Moment = Self::Moment>;

        type Moment: AtLeast32Bit
            + Parameter
            + Default
            + Copy
            + MaxEncodedLen
            + MaybeSerializeDeserialize;

        #[pallet::constant]
        type GracePeriod: Get<Self::Moment>;

        #[pallet::constant]
        type DefaultCapacity: Get<u32>;

        #[pallet::constant]
        type BaseNode: Get<DomainHash>;

        #[pallet::constant]
        type MinRegistrationDuration: Get<Self::Moment>;

        #[pallet::constant]
        type MaxRegistrationDuration: Get<Self::Moment>;

        /// How long a gift-purchased name remains in "offered" state before the
        /// offer expires and the name becomes re-registrable (90 days).
        #[pallet::constant]
        type OfferWindow: Get<Self::Moment>;

        type WeightInfo: WeightInfo;

        type PriceOracle: PriceOracle<Moment = Self::Moment, Balance = BalanceOf<Self>>;

        type ManagerOrigin: EnsureOrigin<Self::RuntimeOrigin, Success = Self::AccountId>;

        type PnsCustodian: Get<Self::AccountId>;


        type BlockAuthor: crate::traits::BlockAuthor<AccountId = Self::AccountId>;

        type IsOpen: IsRegistrarOpen;

        type Official: Official<AccountId = Self::AccountId>;

        /// Writes the SS58 record when a name is registered.
        type Ss58Updater: Ss58Updater<AccountId = Self::AccountId>;

        /// Writes the ORIGIN record (parent block hash) on initial registration.
        type OriginRecorder: OriginRecorder;

        /// Clears DNS records when a subdomain is revoked or released.
        type RecordCleaner: RecordCleaner;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    /// Hold reasons scoped to this pallet. Only PnsRegistrar can release these.
    #[pallet::composite_enum]
    pub enum HoldReason {
        /// 5% of the registration fee, held on the registrant's account
        /// until the expired name is cleaned up.
        #[codec(index = 0)]
        CleanupDeposit,
    }

    /// 5% of the registration fee, held on the registrant's SS58 via
    /// a pallet-scoped hold (`HoldReason::CleanupDeposit`). Only this
    /// pallet can release it. Tracks (depositor, amount) per name.
    /// Released and paid to the cleanup() caller after expiry.
    #[pallet::storage]
    pub type CleanupDeposit<T: Config> =
        StorageMap<_, Blake2_128Concat, DomainHash, (T::AccountId, BalanceOf<T>)>;

    /// `name_hash` -> Info{ `expire`, `capacity`, `register_fee`, `label_len` }
    #[pallet::storage]
    pub type RegistrarInfos<T: Config> =
        StorageMap<_, Blake2_128Concat, DomainHash, RegistrarInfoOf<T>>;

    /// Reverse index: cleanup-eligible deadline (`expire + grace`) → name hashes.
    /// The deadline is deterministic and computed at register/renew time.
    /// cleanup() reads entries where the key ≤ now — no filtering needed.
    #[pallet::storage]
    pub type ExpiryIndex<T: Config> = StorageDoubleMap<
        _,
        Twox64Concat,
        T::Moment,
        Twox64Concat,
        DomainHash,
        (),
        ValueQuery,
    >;

    /// `name_hash` if in `reserved_list` -> ()
    #[pallet::storage]
    pub type ReservedList<T: Config> = StorageMap<_, Twox64Concat, DomainHash, (), ValueQuery>;

    /// `owner` -> their single canonical `name_hash`
    /// Each address may hold at most one canonical (top-level) name at a time.
    #[pallet::storage]
    pub type OwnerToPrimaryName<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, DomainHash>;

    /// `name_hash` → OfferedNameRecord — top-level names purchased as gifts, pending acceptance.
    ///
    /// While this entry exists, DNS lookups for the name return `null`.
    /// Cleared when the recipient calls `accept_offered_name` or rejects via `register`.
    #[pallet::storage]
    pub type OfferedNames<T: Config> =
        StorageMap<_, Blake2_128Concat, DomainHash, rns_types::OfferedNameRecord<T::AccountId, T::Moment>>;

    pub type RegistrarInfoOf<T> = RegistrarInfo<<T as Config>::Moment, BalanceOf<T>>;

    #[pallet::genesis_config]
    pub struct GenesisConfig<T: Config> {
        pub infos: Vec<(DomainHash, RegistrarInfoOf<T>)>,
        /// Pre-computed namehashes to reserve. Use `reserved_names` for human-readable names instead.
        pub reserved_list: rp_std::collections::btree_set::BTreeSet<DomainHash>,
        /// Plain-text labels (e.g. b"polkadot") to reserve at genesis.
        /// Each is hashed against the runtime's BaseNode at build time.
        /// Invalid or unrecognised labels are silently skipped.
        /// The `add_reserved` / `remove_reserved` extrinsics can extend or shrink
        /// the reserved set at any time after genesis.
        pub reserved_names: rp_std::vec::Vec<rp_std::vec::Vec<u8>>,
    }

    impl<T: Config> Default for GenesisConfig<T> {
        fn default() -> Self {
            GenesisConfig {
                infos: Vec::with_capacity(0),
                reserved_list: rp_std::collections::btree_set::BTreeSet::new(),
                reserved_names: rp_std::vec::Vec::new(),
            }
        }
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            for (node, info) in self.infos.iter() {
                RegistrarInfos::<T>::insert(node, info);
            }

            // Raw namehash entries (e.g. from an older chainspec or programmatic use).
            for node in self.reserved_list.iter() {
                ReservedList::<T>::insert(node, ());
            }

            // Human-readable labels resolved at genesis time.
            let base_node = T::BaseNode::get();
            for name in self.reserved_names.iter() {
                if let Some(node) = rns_types::parse_name_to_node(name, &base_node) {
                    ReservedList::<T>::insert(node, ());
                }
            }
        }
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// When a domain name is successfully registered, this moment will be logged.
        NameRegistered {
            name: Vec<u8>,
            node: DomainHash,
            owner: T::AccountId,
            expire: T::Moment,
            fee: BalanceOf<T>,
        },
        // to frontend call
        /// When a domain name is successfully renewed, this moment will be logged.
        NameRenewed {
            node: DomainHash,
            owner: T::AccountId,
            expire: T::Moment,
            fee: BalanceOf<T>,
        },
        SubnameOffered {
            parent: DomainHash,
            subnode: DomainHash,
            label: Vec<u8>,
            target: T::AccountId,
        },
        SubnameAccepted {
            subnode: DomainHash,
            target: T::AccountId,
        },
        SubnameRejected {
            subnode: DomainHash,
            target: T::AccountId,
        },
        SubnameRevoked {
            subnode: DomainHash,
            parent: DomainHash,
        },
        SubnameReleased {
            subnode: DomainHash,
            parent: DomainHash,
        },
        /// Reserve a domain name.
        NameReserved { node: DomainHash },
        /// Cancel a reserved domain name.
        NameUnReserved { node: DomainHash },
        /// A top-level name was purchased as a gift and is awaiting acceptance by the recipient.
        NameBoughtForRecipient {
            node: DomainHash,
            buyer: T::AccountId,
            recipient: T::AccountId,
        },
        /// The recipient accepted a name that was gifted to them.
        OfferedNameAccepted {
            node: DomainHash,
            recipient: T::AccountId,
        },
        /// A pending offered name was rejected by the recipient.
        OfferedNameRejected {
            node: DomainHash,
            by: T::AccountId,
        },
        /// Expired names were cleaned up. Deposits released from original
        /// registrants and paid to the cleanup caller.
        NamesCleaned {
            count: u32,
            caller: T::AccountId,
            payout: BalanceOf<T>,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// You are not in possession of the term.
        NotOwned,
        /// The node is still occupied and cannot be registered.
        Occupied,
        /// You are processing a subdomain or the domain which does not exist.
        /// Or you are registering an occupied subdomain.
        NotExistOrOccupied,
        /// This domain name is temporarily frozen, if you are the authority of the
        /// country (region) or organization, you can contact the official to get
        /// this domain name for you.
        Frozen,
        /// The label you entered is not parsed properly, maybe there are illegal characters in your label.
        ParseLabelFailed,
        /// The length of the label you entered does not correspond to the requirement.
        ///
        /// The length of the label is calculated according to bytes.
        LabelInvalid,
        /// The domain name has exceeded its trial period, please renew or re-register.
        NotUseable,
        /// The domain name has exceeded the renewal period, please re-register.
        NotRenewable,
        /// You want to register in less time than the minimum time we set.
        RegistryDurationInvalid,
        /// Sorry, the registration center is currently closed, please pay attention to the official message and wait for the registration to open.
        RegistrarClosed,
        /// This address already owns a canonical name. Release the current name before registering a new one.
        AlreadyHasCanonicalName,
        /// This address already holds an active subdomain. Release it before acquiring a canonical name.
        AlreadyHoldsSubdomain,
        /// This address has no canonical name registered.
        NoCanonicalName,
        /// Subdomain label could not be converted to a bounded vector (too long).
        LabelTooLong,
        /// This name is already in the offered state (purchased as a gift, pending acceptance).
        NameAlreadyOffered,
        /// No offered name record found for this name.
        OfferedNameNotFound,
        /// Caller is not the intended recipient of this name offer.
        NotOfferedNameRecipient,
        /// The 90-day offer window has expired. The name is now re-registrable.
        OfferExpired,
        /// This name is in an active offered state and cannot be registered until
        /// the recipient accepts, rejects, or the 90-day offer window expires.
        NameInOfferedState,
        InternalHashConversion,
        /// Caller does not have enough free balance to cover the registration
        /// fee plus the 5% cleanup deposit.
        InsufficientBalance,
        /// No names have expired past the grace period yet.
        NotExpired,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Add a domain name to the reserved list by name string (e.g. b"alice").
        ///
        /// Reserved names cannot be registered by anyone until removed.
        /// Only callable by the manager origin.
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::add_reserved())]
        pub fn add_reserved(origin: OriginFor<T>, name: Vec<u8>) -> DispatchResult {
            let _who = T::ManagerOrigin::ensure_origin(origin)?;

            let (label, _) = Label::new_with_len(&name).ok_or(Error::<T>::ParseLabelFailed)?;
            let node = label.encode_with_node(&T::BaseNode::get());

            ReservedList::<T>::insert(node, ());

            Self::deposit_event(Event::<T>::NameReserved { node });
            Ok(())
        }
        /// Remove a domain name from the reserved list by name string (e.g. b"alice").
        ///
        /// Only callable by the manager origin.
        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::remove_reserved())]
        pub fn remove_reserved(origin: OriginFor<T>, name: Vec<u8>) -> DispatchResult {
            let _who = T::ManagerOrigin::ensure_origin(origin)?;

            let (label, _) = Label::new_with_len(&name).ok_or(Error::<T>::ParseLabelFailed)?;
            let node = label.encode_with_node(&T::BaseNode::get());

            ReservedList::<T>::remove(node);

            Self::deposit_event(Event::<T>::NameUnReserved { node });
            Ok(())
        }
        /// Register a domain name for the caller.
        ///
        /// Note: The domain name must conform to the rules,
        /// while the interface is only responsible for
        /// registering domain names greater than 10 in length.
        ///
        /// Ensure: The name must be unoccupied.
        ///
        /// The registrant is always the signing caller. To gift a name to another
        /// account, purchase via the marketplace's buy-for-recipient path or use
        /// the subdomain offer flow — both feed into `OfferedNames` /
        /// `accept_offered_name`, which validates recipient consent.
        ///
        /// `reject_offer`: Optional — reject a pending offered name (top-level or subdomain) before
        /// registering. Pass the plain label (e.g. `b"bob"` or `b"sub.parent"`) of the name to
        /// reject. The caller must be the intended recipient of the offer. For top-level offered
        /// names the NFT is burned (non-refundable). For subdomain offers the record is fully
        /// revoked.
        #[pallet::call_index(2)]
        #[pallet::weight(T::WeightInfo::register(name.len() as u32))]
        #[frame_support::transactional]
        pub fn register(
            origin: OriginFor<T>,
            name: Vec<u8>,
            reject_offer: Option<Vec<u8>>,
        ) -> DispatchResult {
            let caller = ensure_signed(origin)?;

            // Reject a pending offered name before registering, if requested.
            if let Some(ref reject_name) = reject_offer {
                let rej_node = rns_types::parse_name_to_node(reject_name, &T::BaseNode::get())
                    .ok_or(Error::<T>::ParseLabelFailed)?;

                if let Some(offer) = OfferedNames::<T>::take(rej_node) {
                    // Top-level name offered via marketplace gift purchase.
                    ensure!(offer.recipient == caller, Error::<T>::NotOfferedNameRecipient);
                    // The recipient currently holds the NFT — burn it, freeing the slot.
                    T::Registry::burn(caller.clone(), rej_node)?;
                    Self::deposit_event(Event::<T>::OfferedNameRejected { node: rej_node, by: caller.clone() });
                } else {
                    // Try as a subdomain offer addressed to the caller.
                    T::Registry::revoke_pending_offer_for_target(rej_node, &caller)
                        .map_err(|_| Error::<T>::OfferedNameNotFound)?;
                    Self::deposit_event(Event::<T>::OfferedNameRejected { node: rej_node, by: caller.clone() });
                }
            }

            ensure!(!name.is_empty(), Error::<T>::LabelInvalid);
            ensure!(T::IsOpen::is_open(), Error::<T>::RegistrarClosed);

            let (label, label_len) =
                Label::new_with_len(&name).ok_or(Error::<T>::ParseLabelFailed)?;

            use crate::traits::Available;

            ensure!(label_len.is_registrable(), Error::<T>::LabelInvalid);

            let official = T::Official::get_official_account()?;

            let now = T::NowProvider::now();
            let duration = T::MaxRegistrationDuration::get();
            let expire = now
                .checked_add(&duration)
                .ok_or(ArithmeticError::Overflow)?;

            let base_node = T::BaseNode::get();
            let label_node = label.encode_with_node(&base_node);

            ensure!(
                !ReservedList::<T>::contains_key(label_node),
                Error::<T>::Frozen
            );

            // Block registration if name is in an active (non-expired) offered state.
            // If the offer window has expired, clean up the stale entry.
            if let Some(offer) = OfferedNames::<T>::get(label_node) {
                if offer.offered_at.checked_add(&T::OfferWindow::get()).map_or(false, |d| now < d) {
                    return Err(Error::<T>::NameInOfferedState.into());
                }
                // Offer expired — clean up stale entry so registration can proceed.
                OfferedNames::<T>::remove(label_node);
            }

            // Enforce one name per address: no canonical name and no active subdomain.
            if let Some(existing_node) = OwnerToPrimaryName::<T>::get(&caller) {
                let still_valid = RegistrarInfos::<T>::get(existing_node)
                    .map(|info| info.expire.checked_add(&T::GracePeriod::get()).map_or(false, |d| now <= d))
                    .unwrap_or(false);
                if still_valid {
                    return Err(Error::<T>::AlreadyHasCanonicalName.into());
                }
                // Expired canonical name – remove the stale entry so the caller can register anew.
                OwnerToPrimaryName::<T>::remove(&caller);
            }
            ensure!(!T::Registry::has_active_subname(&caller), Error::<T>::AlreadyHoldsSubdomain);

            let fee = T::PriceOracle::registration_fee(label_len)
                .ok_or(ArithmeticError::Overflow)?;

            T::Registry::mint_subname(
                &official,
                base_node,
                label_node,
                caller.clone(),
                0,
                |maybe_pre_owner| -> DispatchResult {
                    // If this name was previously owned by someone else, remove their
                    // canonical name record so they are free to register again.
                    if let Some(pre_owner) = maybe_pre_owner {
                        if OwnerToPrimaryName::<T>::get(pre_owner) == Some(label_node) {
                            OwnerToPrimaryName::<T>::remove(pre_owner);
                        }
                    }
                    let deposit = fee / 20u32.into(); // 5% — held on registrant
                    let spendable = fee - deposit;
                    // Release any prior registrant's cleanup hold before placing the new one.
                    // Without this, a re-registration after the prior holder's grace period
                    // ends (without anyone calling `cleanup()`) strands the prior deposit —
                    // `HoldReason::CleanupDeposit` is releasable only by this pallet, and
                    // the storage row we're about to overwrite was the only index pointing
                    // to the prior holder's held funds. Mirrors `renew` and `transfer`.
                    if let Some((old_depositor, old_amount)) = CleanupDeposit::<T>::take(label_node) {
                        let _ = Self::release_cleanup_hold(&old_depositor, old_amount, ReleaseReason::Replaced);
                    }
                    // Place a pallet-scoped hold on the registrant's account.
                    T::Fungible::hold(
                        &HoldReason::CleanupDeposit.into(),
                        &caller,
                        deposit,
                    ).map_err(|_| Error::<T>::InsufficientBalance)?;
                    CleanupDeposit::<T>::insert(label_node, (caller.clone(), deposit));
                    // Withdraw the remaining 95% and split: 40% author, 55% custodian.
                    use frame_support::traits::Imbalance;
                    let imbalance = T::Currency::withdraw(
                        &caller,
                        spendable,
                        frame_support::traits::WithdrawReasons::FEE,
                        ExistenceRequirement::KeepAlive,
                    )?;
                    // 40/95 of the spendable goes to block author, remainder to custodian.
                    use rp_runtime::Perbill;
                    let author_share = Perbill::from_rational(40u32, 95u32) * spendable;
                    let (author_imbalance, org_imbalance) = imbalance.split(author_share);
                    T::Currency::resolve_creating(&T::PnsCustodian::get(), org_imbalance);
                    if let Some(author) = T::BlockAuthor::author() {
                        T::Currency::resolve_creating(&author, author_imbalance);
                    } else {
                        T::Currency::resolve_creating(&T::PnsCustodian::get(), author_imbalance);
                    }
                    let current_block = frame_system::Pallet::<T>::block_number().saturated_into::<u32>();
                    let deadline = expire
                        .checked_add(&T::GracePeriod::get())
                        .ok_or(ArithmeticError::Overflow)?;
                    RegistrarInfos::<T>::mutate(label_node, |info| -> DispatchResult {
                        if let Some(old) = info.as_ref() {
                            // Re-registration: remove stale expiry index entry.
                            let old_deadline = old.expire
                                .checked_add(&T::GracePeriod::get())
                                .unwrap_or(old.expire);
                            ExpiryIndex::<T>::remove(old_deadline, label_node);
                        }
                        if let Some(info) = info.as_mut() {
                            info.register_fee = fee;
                            info.expire = expire;
                            info.label_len = label_len as u32;
                            info.last_block = current_block;
                        } else {
                            let _ = info.insert(RegistrarInfoOf::<T> {
                                register_fee: fee,
                                expire,
                                capacity: T::DefaultCapacity::get(),
                                label_len: label_len as u32,
                                last_block: current_block,
                            });
                        }
                        Ok(())
                    })?;
                    ExpiryIndex::<T>::insert(deadline, label_node, ());
                    Ok(())
                },
            )?;

            // Record this as the caller's canonical name.
            OwnerToPrimaryName::<T>::insert(&caller, label_node);

            // Write the SS58 record so DNS lookups immediately resolve to the new owner.
            T::Ss58Updater::update_ss58(label_node, &caller)?;

            // Write the ORIGIN record — parent block hash as proof of registration block.
            let parent_hash: [u8; 32] = frame_system::Pallet::<T>::parent_hash()
                .as_ref()
                .try_into()
                .map_err(|_| Error::<T>::InternalHashConversion)?;
            T::OriginRecorder::record_origin(label_node, parent_hash)?;

            Self::deposit_event(Event::<T>::NameRegistered {
                name,
                node: label_node,
                owner: caller,
                expire,
                fee,
            });

            Ok(())
        }
        /// Renew the caller's canonical domain name.
        ///
        /// Only the current owner of a name may renew it. Renewal resets expiry to
        /// `MaxRegistrationDuration` from now (not additive) and charges the renewal
        /// fee to the caller.
        ///
        /// Ensure: Caller must own a canonical name that is within the renewable period.
        #[pallet::call_index(3)]
        #[pallet::weight(T::WeightInfo::renew())]
        #[frame_support::transactional]
        pub fn renew(origin: OriginFor<T>) -> DispatchResult {
            let caller = ensure_signed(origin)?;

            ensure!(T::IsOpen::is_open(), Error::<T>::RegistrarClosed);

            let label_node = OwnerToPrimaryName::<T>::get(&caller)
                .ok_or(Error::<T>::NoCanonicalName)?;

            RegistrarInfos::<T>::mutate(label_node, |info| -> DispatchResult {
                let info = info.as_mut().ok_or(Error::<T>::NotExistOrOccupied)?;
                let now = T::NowProvider::now();
                let grace_period = T::GracePeriod::get();
                ensure!(now <= info.expire + grace_period, Error::<T>::NotRenewable);
                let price = T::PriceOracle::registration_fee(info.label_len as usize)
                    .ok_or(ArithmeticError::Overflow)?;
                let deposit = price / 20u32.into(); // 5%
                let spendable = price - deposit;
                // Release old hold before placing the new one.
                if let Some((old_depositor, old_amount)) = CleanupDeposit::<T>::take(label_node) {
                    let _ = Self::release_cleanup_hold(&old_depositor, old_amount, ReleaseReason::Replaced);
                }
                T::Fungible::hold(
                    &HoldReason::CleanupDeposit.into(),
                    &caller,
                    deposit,
                ).map_err(|_| Error::<T>::InsufficientBalance)?;
                CleanupDeposit::<T>::insert(label_node, (caller.clone(), deposit));
                use frame_support::traits::Imbalance;
                let imbalance = T::Currency::withdraw(
                    &caller,
                    spendable,
                    frame_support::traits::WithdrawReasons::FEE,
                    ExistenceRequirement::KeepAlive,
                )?;
                // 40/95 of the spendable goes to block author, remainder to custodian.
                use rp_runtime::Perbill;
                let author_share = Perbill::from_rational(40u32, 95u32) * spendable;
                let (author_imbalance, org_imbalance) = imbalance.split(author_share);
                T::Currency::resolve_creating(&T::PnsCustodian::get(), org_imbalance);
                if let Some(author) = T::BlockAuthor::author() {
                    T::Currency::resolve_creating(&author, author_imbalance);
                } else {
                    T::Currency::resolve_creating(&T::PnsCustodian::get(), author_imbalance);
                }
                let old_deadline = info.expire
                    .checked_add(&grace_period)
                    .unwrap_or(info.expire);
                info.expire = now
                    .checked_add(&T::MaxRegistrationDuration::get())
                    .ok_or(ArithmeticError::Overflow)?;
                let new_deadline = info.expire
                    .checked_add(&grace_period)
                    .ok_or(ArithmeticError::Overflow)?;
                ExpiryIndex::<T>::remove(old_deadline, label_node);
                ExpiryIndex::<T>::insert(new_deadline, label_node, ());
                Self::deposit_event(Event::<T>::NameRenewed {
                    node: label_node,
                    owner: caller.clone(),
                    expire: info.expire,
                    fee: price,
                });
                Ok(())
            })
        }
        /// Transfer the caller's canonical name to another account.
        ///
        /// Ensure: The recipient must not already hold a valid canonical name.
        #[pallet::call_index(4)]
        #[pallet::weight(T::WeightInfo::transfer())]
        #[frame_support::transactional]
        pub fn transfer(
            origin: OriginFor<T>,
            to: <T::Lookup as StaticLookup>::Source,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let to = T::Lookup::lookup(to)?;

            ensure!(T::IsOpen::is_open(), Error::<T>::RegistrarClosed);

            // Derive the node from the caller's canonical name — only their registered
            // name is transferable through this extrinsic.
            let node = OwnerToPrimaryName::<T>::get(&who)
                .ok_or(Error::<T>::NoCanonicalName)?;

            if let Some(info) = RegistrarInfos::<T>::get(node) {
                let now = T::NowProvider::now();
                ensure!(
                    info.expire.checked_add(&T::GracePeriod::get()).map_or(false, |d| d > now),
                    Error::<T>::NotOwned
                );
            }
            // Prevent transfer to an account that already holds any name.
            if let Some(existing) = OwnerToPrimaryName::<T>::get(&to) {
                let now = T::NowProvider::now();
                let still_valid = RegistrarInfos::<T>::get(existing)
                    .map(|info| info.expire.checked_add(&T::GracePeriod::get()).map_or(false, |d| now <= d))
                    .unwrap_or(false);
                if still_valid {
                    return Err(Error::<T>::AlreadyHasCanonicalName.into());
                }
                OwnerToPrimaryName::<T>::remove(&to);
            }
            ensure!(!T::Registry::has_active_subname(&to), Error::<T>::AlreadyHoldsSubdomain);

            // Move the cleanup deposit from the old owner to the new owner.
            if let Some((old_depositor, old_amount)) = CleanupDeposit::<T>::take(node) {
                let _ = Self::release_cleanup_hold(&old_depositor, old_amount, ReleaseReason::Replaced);
                T::Fungible::hold(
                    &HoldReason::CleanupDeposit.into(),
                    &to,
                    old_amount,
                ).map_err(|_| Error::<T>::InsufficientBalance)?;
                CleanupDeposit::<T>::insert(node, (to.clone(), old_amount));
            }

            T::Registry::transfer(&who, &to, node)?;

            OwnerToPrimaryName::<T>::remove(&who);
            OwnerToPrimaryName::<T>::insert(&to, node);

            Ok(())
        }
        /// Release the caller's canonical name back to the pool.
        ///
        /// The name NFT is burned and the name becomes available for registration again.
        /// After releasing, the caller may register a new canonical name.
        ///
        /// Ensure: The caller must currently own the canonical name being released,
        /// and the name must have no active subdomains.
        #[pallet::call_index(6)]
        #[pallet::weight(T::WeightInfo::release_name())]
        #[frame_support::transactional]
        pub fn release_name(origin: OriginFor<T>) -> DispatchResult {
            let caller = ensure_signed(origin)?;

            // Derive the node from the caller's canonical name — only their registered
            // name can be released through this extrinsic.
            let node = OwnerToPrimaryName::<T>::get(&caller)
                .ok_or(Error::<T>::NoCanonicalName)?;

            // Release the cleanup deposit back to the owner.
            if let Some((depositor, amount)) = CleanupDeposit::<T>::take(node) {
                let _ = Self::release_cleanup_hold(&depositor, amount, ReleaseReason::Released);
            }

            // Remove the expiry index entry.
            if let Some(info) = RegistrarInfos::<T>::get(node) {
                let deadline = info.expire
                    .checked_add(&T::GracePeriod::get())
                    .unwrap_or(info.expire);
                ExpiryIndex::<T>::remove(deadline, node);
            }

            OwnerToPrimaryName::<T>::remove(&caller);
            T::Registry::burn(caller, node)?;

            Ok(())
        }

        /// Offer a subdomain to a specific account.
        ///
        /// Callable only by the owner of the canonical parent name.
        /// Creates a SubnameRecord in the `Offered` state addressed to `target`.
        /// The target must call `accept_subdomain` or `reject_subdomain` to act on it.
        #[pallet::call_index(5)]
        #[pallet::weight(T::WeightInfo::offer_subdomain(label.len() as u32))]
        #[frame_support::transactional]
        pub fn offer_subdomain(
            origin: OriginFor<T>,
            label: Vec<u8>,
            target: <T::Lookup as StaticLookup>::Source,
        ) -> DispatchResult {
            let caller = ensure_signed(origin)?;
            let target = T::Lookup::lookup(target)?;

            ensure!(T::IsOpen::is_open(), Error::<T>::RegistrarClosed);

            let parent_node = OwnerToPrimaryName::<T>::get(&caller)
                .ok_or(Error::<T>::NoCanonicalName)?;

            // Parent must be live (not expired).
            let now = T::NowProvider::now();
            let info = RegistrarInfos::<T>::get(parent_node)
                .ok_or(Error::<T>::NotExistOrOccupied)?;
            ensure!(now < info.expire, Error::<T>::NotUseable);

            let (sub_label, _) = Label::new_with_len(&label).ok_or(Error::<T>::ParseLabelFailed)?;
            let label_node = sub_label.encode_with_node(&parent_node);

            let bounded_label: frame_support::BoundedVec<
                u8,
                rp_core::ConstU32<63>,
            > = label.clone().try_into().map_err(|_| Error::<T>::LabelTooLong)?;

            T::Registry::offer_subname(parent_node, label_node, bounded_label, target.clone(), info.capacity)?;

            Self::deposit_event(Event::<T>::SubnameOffered {
                parent: parent_node,
                subnode: label_node,
                label,
                target,
            });

            Ok(())
        }

        /// Accept a pending subdomain offer.
        ///
        /// Callable only by the account that was specified as the target in the offer.
        /// Flips state from `Offered` to `Active` and writes the SS58 record.
        #[pallet::call_index(7)]
        #[pallet::weight(T::WeightInfo::accept_subdomain())]
        #[frame_support::transactional]
        pub fn accept_subdomain(
            origin: OriginFor<T>,
            parent: Vec<u8>,
            label: Vec<u8>,
        ) -> DispatchResult {
            let caller = ensure_signed(origin)?;

            let (parent_label, _) =
                Label::new_with_len(&parent).ok_or(Error::<T>::ParseLabelFailed)?;
            let parent_node = parent_label.encode_with_node(&T::BaseNode::get());

            let (sub_label, _) =
                Label::new_with_len(&label).ok_or(Error::<T>::ParseLabelFailed)?;
            let label_node = sub_label.encode_with_node(&parent_node);

            // Parent must still be live.
            let now = T::NowProvider::now();
            let info = RegistrarInfos::<T>::get(parent_node)
                .ok_or(Error::<T>::NotExistOrOccupied)?;
            ensure!(now < info.expire, Error::<T>::NotUseable);

            T::Registry::accept_subname_offer(label_node, &caller)?;

            T::Ss58Updater::update_ss58(label_node, &caller)?;

            Self::deposit_event(Event::<T>::SubnameAccepted {
                subnode: label_node,
                target: caller,
            });

            Ok(())
        }

        /// Reject a pending subdomain offer.
        ///
        /// Callable only by the account that was specified as the target in the offer.
        /// Flips state from `Offered` to `Rejected` so the offerer can see the outcome.
        /// The offerer must call `revoke_subdomain` to clean up the record.
        #[pallet::call_index(8)]
        #[pallet::weight(T::WeightInfo::reject_subdomain())]
        pub fn reject_subdomain(
            origin: OriginFor<T>,
            parent: Vec<u8>,
            label: Vec<u8>,
        ) -> DispatchResult {
            let caller = ensure_signed(origin)?;

            let (parent_label, _) =
                Label::new_with_len(&parent).ok_or(Error::<T>::ParseLabelFailed)?;
            let parent_node = parent_label.encode_with_node(&T::BaseNode::get());

            let (sub_label, _) =
                Label::new_with_len(&label).ok_or(Error::<T>::ParseLabelFailed)?;
            let label_node = sub_label.encode_with_node(&parent_node);

            T::Registry::reject_subname_offer(label_node, &caller)?;

            Self::deposit_event(Event::<T>::SubnameRejected {
                subnode: label_node,
                target: caller,
            });

            Ok(())
        }

        /// Revoke a subdomain (Offered, Rejected, or Active) created under the caller's canonical name.
        ///
        /// Callable only by the parent domain owner (the original offerer).
        /// Deletes the SubnameRecord entirely and decrements the parent's children counter.
        #[pallet::call_index(9)]
        #[pallet::weight(T::WeightInfo::revoke_subdomain())]
        #[frame_support::transactional]
        pub fn revoke_subdomain(
            origin: OriginFor<T>,
            label: Vec<u8>,
        ) -> DispatchResult {
            let caller = ensure_signed(origin)?;

            let parent_node = OwnerToPrimaryName::<T>::get(&caller)
                .ok_or(Error::<T>::NoCanonicalName)?;

            let (sub_label, _) =
                Label::new_with_len(&label).ok_or(Error::<T>::ParseLabelFailed)?;
            let label_node = sub_label.encode_with_node(&parent_node);

            T::Registry::revoke_subname(parent_node, label_node)?;

            Self::deposit_event(Event::<T>::SubnameRevoked {
                subnode: label_node,
                parent: parent_node,
            });

            Ok(())
        }

        /// Release an active subdomain voluntarily.
        ///
        /// Accept a top-level name that was purchased as a gift for the caller.
        ///
        /// Callable only by the account designated as `recipient` when the name was bought.
        /// Sets the caller as the canonical name owner, writes SS58 and ORIGIN records,
        /// and removes the offered state so lookups begin resolving normally.
        ///
        /// The caller must not already hold a valid canonical name or an active subdomain.
        #[pallet::call_index(11)]
        #[pallet::weight(T::WeightInfo::accept_offered_name())]
        #[frame_support::transactional]
        pub fn accept_offered_name(origin: OriginFor<T>, name: Vec<u8>) -> DispatchResult {
            let caller = ensure_signed(origin)?;

            let (label, _) = Label::new_with_len(&name).ok_or(Error::<T>::ParseLabelFailed)?;
            let node = label.encode_with_node(&T::BaseNode::get());

            let offer = OfferedNames::<T>::take(node).ok_or(Error::<T>::OfferedNameNotFound)?;
            ensure!(offer.recipient == caller, Error::<T>::NotOfferedNameRecipient);

            let now = T::NowProvider::now();

            // The 90-day offer window must not have expired.
            ensure!(
                offer.offered_at.checked_add(&T::OfferWindow::get()).map_or(false, |d| now < d),
                Error::<T>::OfferExpired
            );

            // The RegistrarInfo must still be valid.
            let info = RegistrarInfos::<T>::get(node).ok_or(Error::<T>::NotExistOrOccupied)?;
            ensure!(now < info.expire, Error::<T>::NotUseable);

            // Caller must not already hold another canonical name.
            if let Some(existing_node) = OwnerToPrimaryName::<T>::get(&caller) {
                let still_valid = RegistrarInfos::<T>::get(existing_node)
                    .map(|i| i.expire.checked_add(&T::GracePeriod::get()).map_or(false, |d| now <= d))
                    .unwrap_or(false);
                if still_valid {
                    return Err(Error::<T>::AlreadyHasCanonicalName.into());
                }
                OwnerToPrimaryName::<T>::remove(&caller);
            }
            ensure!(!T::Registry::has_active_subname(&caller), Error::<T>::AlreadyHoldsSubdomain);

            // Activate the name for the recipient.
            OwnerToPrimaryName::<T>::insert(&caller, node);
            T::Ss58Updater::update_ss58(node, &caller)?;
            let parent_hash: [u8; 32] = frame_system::Pallet::<T>::parent_hash()
                .as_ref()
                .try_into()
                .map_err(|_| Error::<T>::InternalHashConversion)?;
            T::OriginRecorder::record_origin(node, parent_hash)?;

            Self::deposit_event(Event::<T>::OfferedNameAccepted { node, recipient: caller });
            Ok(())
        }

        /// Release an active subdomain voluntarily.
        ///
        /// Callable only by the current holder (the account that accepted the offer).
        /// Deletes the SubnameRecord and decrements the parent's children counter.
        #[pallet::call_index(10)]
        #[pallet::weight(T::WeightInfo::release_subdomain())]
        #[frame_support::transactional]
        pub fn release_subdomain(
            origin: OriginFor<T>,
            parent: Vec<u8>,
            label: Vec<u8>,
        ) -> DispatchResult {
            let caller = ensure_signed(origin)?;

            let (parent_label, _) =
                Label::new_with_len(&parent).ok_or(Error::<T>::ParseLabelFailed)?;
            let parent_node = parent_label.encode_with_node(&T::BaseNode::get());

            let (sub_label, _) =
                Label::new_with_len(&label).ok_or(Error::<T>::ParseLabelFailed)?;
            let label_node = sub_label.encode_with_node(&parent_node);

            let parent_from_record = T::Registry::release_subname(label_node, &caller)?;

            Self::deposit_event(Event::<T>::SubnameReleased {
                subnode: label_node,
                parent: parent_from_record,
            });

            Ok(())
        }

        /// Clean up expired name registrations at a specific deadline.
        /// Anyone can call this.
        ///
        /// The caller provides the `deadline` (expire + grace) they want to
        /// clean up. This value is deterministic — emitted in registration
        /// events and computable from on-chain data. The pallet validates
        /// `deadline ≤ now`, then uses `iter_prefix(deadline)` to read only
        /// the names at that deadline — O(batch size), not O(total names).
        ///
        /// Processes up to 5 entries per call. Releases the pallet-scoped
        /// hold from each original registrant and transfers the freed funds
        /// to the caller.
        #[pallet::call_index(12)]
        #[pallet::weight(T::WeightInfo::cleanup())]
        #[frame_support::transactional]
        pub fn cleanup(origin: OriginFor<T>, deadline: T::Moment) -> DispatchResult {
            let caller = ensure_signed(origin)?;
            const MAX_CLEANUP_PER_CALL: usize = 5;

            let now = T::NowProvider::now();
            ensure!(deadline <= now, Error::<T>::NotExpired);

            // Read only entries at this specific deadline — no full scan.
            let expired: Vec<DomainHash> = ExpiryIndex::<T>::iter_prefix(deadline)
                .take(MAX_CLEANUP_PER_CALL)
                .map(|(node, _)| node)
                .collect();

            ensure!(!expired.is_empty(), Error::<T>::NotExpired);

            let mut total_payout = BalanceOf::<T>::default();

            for node in &expired {
                if let Some((depositor, deposit_amount)) = CleanupDeposit::<T>::take(node) {
                    let released = Self::release_cleanup_hold(
                        &depositor, deposit_amount, ReleaseReason::Expired,
                    );

                    if !released.is_zero() {
                        T::Currency::transfer(
                            &depositor,
                            &caller,
                            released,
                            ExistenceRequirement::AllowDeath,
                        )?;
                        total_payout = total_payout.saturating_add(released);
                    }
                }

                if let Some(owner) = T::Registry::owner_of(*node) {
                    if OwnerToPrimaryName::<T>::get(&owner) == Some(*node) {
                        OwnerToPrimaryName::<T>::remove(&owner);
                    }
                }

                let _ = T::Registry::force_delete(*node);
                ExpiryIndex::<T>::remove(deadline, node);
            }

            Self::deposit_event(Event::<T>::NamesCleaned {
                count: expired.len() as u32,
                caller,
                payout: total_payout,
            });

            Ok(())
        }
    }
}

use crate::traits::Registry;
use frame_support::{
    dispatch::DispatchResult,
    traits::{Get, Time},
};
use rp_runtime::traits::CheckedAdd;
use rp_weights::Weight;

pub trait WeightInfo {
    fn offer_subdomain(len: u32) -> Weight;
    fn accept_subdomain() -> Weight;
    fn reject_subdomain() -> Weight;
    fn revoke_subdomain() -> Weight;
    fn release_subdomain() -> Weight;
    fn accept_offered_name() -> Weight;
    fn register(len: u32) -> Weight;
    fn renew() -> Weight;
    fn transfer() -> Weight;
    fn add_reserved() -> Weight;
    fn remove_reserved() -> Weight;
    fn release_name() -> Weight;
    fn cleanup() -> Weight;
}

impl<T: Config> crate::traits::Registrar for Pallet<T> {
    type Balance = BalanceOf<T>;
    type AccountId = T::AccountId;
    type Moment = T::Moment;

    fn check_expires_registrable(node: DomainHash) -> rp_runtime::DispatchResult {
        let now = T::NowProvider::now();

        let expire = RegistrarInfos::<T>::get(node)
            .ok_or(Error::<T>::NotExistOrOccupied)?
            .expire;

        frame_support::ensure!(expire.checked_add(&T::GracePeriod::get()).map_or(true, |d| now > d), Error::<T>::Occupied);

        Ok(())
    }

    fn check_expires_renewable(node: DomainHash) -> rp_runtime::DispatchResult {
        let now = T::NowProvider::now();

        let expire = RegistrarInfos::<T>::get(node)
            .ok_or(Error::<T>::NotExistOrOccupied)?
            .expire;

        frame_support::ensure!(
            expire.checked_add(&T::GracePeriod::get()).map_or(false, |d| now < d),
            Error::<T>::NotRenewable
        );

        Ok(())
    }

    fn check_expires_useable(node: DomainHash) -> rp_runtime::DispatchResult {
        let now = T::NowProvider::now();

        let expire = RegistrarInfos::<T>::get(node)
            .ok_or(Error::<T>::NotExistOrOccupied)?
            .expire;

        frame_support::ensure!(now < expire, Error::<T>::NotUseable);

        Ok(())
    }

    fn clear_registrar_info(
        node: DomainHash,
        _owner: &Self::AccountId,
    ) -> rp_runtime::DispatchResult {
        RegistrarInfos::<T>::try_mutate_exists(node, |maybe_info| -> DispatchResult {
            *maybe_info = None;
            Ok(())
        })
    }

    fn basenode() -> DomainHash {
        T::BaseNode::get()
    }

    fn has_valid_canonical_name(account: &Self::AccountId) -> bool {
        let Some(node) = OwnerToPrimaryName::<T>::get(account) else { return false };
        let now = T::NowProvider::now();
        RegistrarInfos::<T>::get(node)
            .map(|info| info.expire.checked_add(&T::GracePeriod::get()).map_or(false, |d| now <= d))
            .unwrap_or(false)
    }
}

impl WeightInfo for () {
    fn offer_subdomain(_len: u32) -> Weight { Weight::from_parts(500_000_000, 5_000) }
    fn accept_subdomain() -> Weight { Weight::from_parts(500_000_000, 5_000) }
    fn reject_subdomain() -> Weight { Weight::from_parts(200_000_000, 2_000) }
    fn revoke_subdomain() -> Weight { Weight::from_parts(200_000_000, 2_000) }
    fn release_subdomain() -> Weight { Weight::from_parts(200_000_000, 2_000) }
    fn accept_offered_name() -> Weight { Weight::from_parts(500_000_000, 5_000) }
    fn register(_len: u32) -> Weight { Weight::from_parts(500_000_000, 5_000) }
    fn renew() -> Weight { Weight::from_parts(500_000_000, 5_000) }
    fn transfer() -> Weight { Weight::from_parts(500_000_000, 5_000) }
    fn add_reserved() -> Weight { Weight::from_parts(150_000_000, 500) }
    fn remove_reserved() -> Weight { Weight::from_parts(150_000_000, 500) }
    fn release_name() -> Weight { Weight::from_parts(500_000_000, 5_000) }
    fn cleanup() -> Weight { Weight::from_parts(500_000_000, 5_000) }
}

impl<T: Config> Pallet<T> {
    pub fn get_info(id: DomainHash) -> Option<RegistrarInfoOf<T>> {
        RegistrarInfos::<T>::get(id)
    }

    /// Release a `CleanupDeposit` hold. Two permitted reasons:
    ///
    /// - `Expired`: the name is past expiry + grace. Used by cleanup().
    /// - `Replaced`: the hold is being swapped for a fresh one during renew.
    ///
    /// Any other call path is a bug — this function is the single gate.
    fn release_cleanup_hold(
        depositor: &T::AccountId,
        amount: BalanceOf<T>,
        reason: ReleaseReason,
    ) -> BalanceOf<T> {
        use frame_support::traits::tokens::{fungible::hold::Mutate, Precision};
        match reason {
            ReleaseReason::Expired | ReleaseReason::Replaced | ReleaseReason::Released => {
                T::Fungible::release(
                    &pallet::HoldReason::CleanupDeposit.into(),
                    depositor,
                    amount,
                    Precision::BestEffort,
                ).unwrap_or_default()
            }
        }
    }
}

/// Why the pallet is releasing a cleanup hold.
enum ReleaseReason {
    /// Name expired past grace — cleanup() is paying out to caller.
    Expired,
    /// Hold is being swapped: renew (new hold on same owner),
    /// transfer (new hold on recipient), or marketplace sale.
    Replaced,
    /// Owner voluntarily released or burned the name. Deposit returned.
    Released,
}

impl<T: Config> crate::traits::NameRegistry for Pallet<T> {
    type AccountId = T::AccountId;

    fn canonical_name(account: &T::AccountId) -> Option<DomainHash> {
        OwnerToPrimaryName::<T>::get(account)
    }

    fn owner_of(node: DomainHash) -> Option<T::AccountId> {
        T::Registry::owner_of(node)
    }

    fn transfer_name(from: &T::AccountId, to: &T::AccountId, node: DomainHash) -> rp_runtime::DispatchResult {
        // Prevent transfer to an account that already holds any name.
        if let Some(existing) = OwnerToPrimaryName::<T>::get(to) {
            let now = T::NowProvider::now();
            let still_valid = RegistrarInfos::<T>::get(existing)
                .map(|info| info.expire.checked_add(&T::GracePeriod::get()).map_or(false, |d| now <= d))
                .unwrap_or(false);
            if still_valid {
                return Err(Error::<T>::AlreadyHasCanonicalName.into());
            }
            OwnerToPrimaryName::<T>::remove(to);
        }
        frame_support::ensure!(
            !T::Registry::has_active_subname(to),
            Error::<T>::AlreadyHoldsSubdomain
        );
        T::Registry::transfer(from, to, node)?;
        if OwnerToPrimaryName::<T>::get(from) == Some(node) {
            OwnerToPrimaryName::<T>::remove(from);
        }
        OwnerToPrimaryName::<T>::insert(to, node);
        Ok(())
    }

    fn is_name_useable(node: DomainHash) -> bool {
        <Self as crate::traits::Registrar>::check_expires_useable(node).is_ok()
    }

    fn offer_bought_name(
        seller: &T::AccountId,
        buyer: &T::AccountId,
        recipient: &T::AccountId,
        node: DomainHash,
    ) -> rp_runtime::DispatchResult {
        // The name must not already be in offered state.
        frame_support::ensure!(
            !OfferedNames::<T>::contains_key(node),
            Error::<T>::NameAlreadyOffered
        );
        // The recipient must not already hold any name.
        if let Some(existing) = OwnerToPrimaryName::<T>::get(recipient) {
            let now = T::NowProvider::now();
            let still_valid = RegistrarInfos::<T>::get(existing)
                .map(|info| info.expire.checked_add(&T::GracePeriod::get()).map_or(false, |d| now <= d))
                .unwrap_or(false);
            frame_support::ensure!(
                !still_valid,
                Error::<T>::AlreadyHasCanonicalName
            );
        }
        frame_support::ensure!(
            !T::Registry::has_active_subname(recipient),
            Error::<T>::AlreadyHoldsSubdomain
        );

        // Transfer the NFT from seller to recipient.
        // do_transfer clears seller's subnames/DNS records and writes SS58/ORIGIN for recipient.
        // These will be overwritten when the recipient calls accept_offered_name.
        T::Registry::transfer(seller, recipient, node)?;

        // Remove the seller's canonical name entry.
        if OwnerToPrimaryName::<T>::get(seller) == Some(node) {
            OwnerToPrimaryName::<T>::remove(seller);
        }
        // Do NOT set recipient's OwnerToPrimaryName — that happens on acceptance.

        // Record the pending offer with a 90-day acceptance window.
        let offered_at = T::NowProvider::now();
        OfferedNames::<T>::insert(
            node,
            rns_types::OfferedNameRecord {
                buyer: buyer.clone(),
                recipient: recipient.clone(),
                offered_at,
            },
        );

        Self::deposit_event(Event::<T>::NameBoughtForRecipient {
            node,
            buyer: buyer.clone(),
            recipient: recipient.clone(),
        });

        Ok(())
    }

    fn charge_sale_fee(
        buyer: &T::AccountId,
        node: DomainHash,
    ) -> rp_runtime::DispatchResult {
        use crate::traits::{BlockAuthor, PriceOracle};
        use frame_support::traits::{
            Currency, Imbalance, ExistenceRequirement, WithdrawReasons,
            tokens::fungible::hold::Mutate as HoldMutate,
        };

        let info = RegistrarInfos::<T>::get(node)
            .ok_or(Error::<T>::NotExistOrOccupied)?;
        let fee = T::PriceOracle::registration_fee(info.label_len as usize)
            .ok_or(rp_runtime::ArithmeticError::Overflow)?;

        // Release the seller's old cleanup deposit back to them.
        if let Some((old_depositor, old_amount)) = pallet::CleanupDeposit::<T>::take(node) {
            let _ = Self::release_cleanup_hold(&old_depositor, old_amount, ReleaseReason::Replaced);
        }

        // Hold 5% on the buyer as the new cleanup deposit.
        let deposit = fee / 20u32.into();
        let spendable = fee - deposit;
        T::Fungible::hold(
            &pallet::HoldReason::CleanupDeposit.into(),
            buyer,
            deposit,
        ).map_err(|_| Error::<T>::InsufficientBalance)?;
        pallet::CleanupDeposit::<T>::insert(node, (buyer.clone(), deposit));

        // Withdraw the remaining 95% and split.
        let imbalance = T::Currency::withdraw(
            buyer,
            spendable,
            WithdrawReasons::FEE,
            ExistenceRequirement::KeepAlive,
        )?;
        use rp_runtime::Perbill;
        let author_share = Perbill::from_rational(40u32, 95u32) * spendable;
        let (author_imbalance, org_imbalance) = imbalance.split(author_share);
        T::Currency::resolve_creating(&T::PnsCustodian::get(), org_imbalance);
        if let Some(author) = T::BlockAuthor::author() {
            T::Currency::resolve_creating(&author, author_imbalance);
        } else {
            T::Currency::resolve_creating(&T::PnsCustodian::get(), author_imbalance);
        }

        Ok(())
    }
}

#[cfg(feature = "runtime-benchmarks")]
#[frame_benchmarking::v2::benchmarks(
    where
        T: pallet::Config
            + crate::price_oracle::Config
            + crate::registry::Config
            + crate::nft::Config
            + pallet_timestamp::Config<Moment = <T as pallet::Config>::Moment>,
)]
mod benchmarks {
    use super::*;
    use super::pallet::{
        OfferedNames, RegistrarInfoOf, RegistrarInfos,
    };
    use frame_benchmarking::v2::*;
    use frame_support::traits::{Currency, Get};
    use frame_system::RawOrigin;
    use rp_runtime::traits::{SaturatedConversion, StaticLookup, Zero};
    use rp_std::vec::Vec;
    use crate::traits::Label;
    use rns_types::{DomainHash, OfferedNameRecord};

    fn seed_prices<T>()
    where
        T: pallet::Config + crate::price_oracle::Config,
    {
        type PriceBalanceOf<T> = <<T as crate::price_oracle::Config>::Currency
            as Currency<<T as frame_system::Config>::AccountId>>::Balance;
        let unit: PriceBalanceOf<T> = 1_000_000_000_000u128.saturated_into();
        let zero: PriceBalanceOf<T> = 0u32.into();
        let one: PriceBalanceOf<T> = 1u32.into();
        crate::price_oracle::BasePrice::<T>::put([unit; 11]);
        crate::price_oracle::RentPrice::<T>::put([zero; 11]);
        crate::price_oracle::ExchangeRate::<T>::put(one);
    }

    fn seed_basenode<T>(owner: &T::AccountId)
    where
        T: pallet::Config + crate::nft::Config + crate::registry::Config,
    {
        let class_id = <T as crate::nft::Config>::ClassId::zero();
        let basenode = <T as pallet::Config>::BaseNode::get();

        if crate::nft::Classes::<T>::get(class_id).is_none() {
            let info = crate::nft::ClassInfo {
                metadata: Default::default(),
                total_issuance: Default::default(),
                owner: owner.clone(),
                data: Default::default(),
            };
            crate::nft::Classes::<T>::insert(class_id, info);
        }

        let tinfo = crate::nft::TokenInfo {
            metadata: Default::default(),
            owner: owner.clone(),
            data: Default::default(),
        };
        crate::nft::Tokens::<T>::insert(class_id, basenode, tinfo);
        crate::nft::TokensByOwner::<T>::insert((owner.clone(), class_id, basenode), ());

        crate::registry::Official::<T>::put(owner);
    }

    fn seed_now<T>(t: <T as pallet::Config>::Moment)
    where
        T: pallet::Config
            + pallet_timestamp::Config<Moment = <T as pallet::Config>::Moment>,
    {
        pallet_timestamp::Now::<T>::put(t);
    }

    fn fund<T: pallet::Config>(who: &T::AccountId) {
        let big: BalanceOf<T> = (u128::MAX / 2).saturated_into();
        T::Currency::make_free_balance_be(who, big);
    }

    fn setup_base<T>(official: &T::AccountId)
    where
        T: pallet::Config
            + crate::price_oracle::Config
            + crate::registry::Config
            + crate::nft::Config
            + pallet_timestamp::Config<Moment = <T as pallet::Config>::Moment>,
    {
        seed_prices::<T>();
        seed_basenode::<T>(official);
        fund::<T>(official);
        seed_now::<T>(1u32.into());
    }

    fn register_name<T>(caller: T::AccountId, name: &[u8]) -> DomainHash
    where
        T: pallet::Config
            + crate::price_oracle::Config
            + crate::registry::Config
            + crate::nft::Config
            + pallet_timestamp::Config<Moment = <T as pallet::Config>::Moment>,
    {
        fund::<T>(&caller);
        Pallet::<T>::register(
            RawOrigin::Signed(caller).into(),
            name.to_vec(),
            None,
        )
        .expect("register bench setup");
        let (label, _) = Label::new_with_len(name).expect("valid label");
        label.encode_with_node(&<T as pallet::Config>::BaseNode::get())
    }

    #[benchmark]
    fn add_reserved() {
        let official: T::AccountId = account("official", 0, 0);
        setup_base::<T>(&official);

        #[extrinsic_call]
        _(RawOrigin::Root, b"reserved1".to_vec());
    }

    #[benchmark]
    fn remove_reserved() {
        let official: T::AccountId = account("official", 0, 0);
        setup_base::<T>(&official);
        Pallet::<T>::add_reserved(RawOrigin::Root.into(), b"reserved1".to_vec())
            .expect("add_reserved setup");

        #[extrinsic_call]
        _(RawOrigin::Root, b"reserved1".to_vec());
    }

    #[benchmark]
    fn register(s: Linear<1, 10>) {
        let official: T::AccountId = account("official", 0, 0);
        setup_base::<T>(&official);
        let caller: T::AccountId = whitelisted_caller();
        fund::<T>(&caller);
        let name: Vec<u8> = (0..s).map(|i| b'a' + (i as u8 % 26)).collect();

        #[extrinsic_call]
        _(RawOrigin::Signed(caller), name, None);
    }

    #[benchmark]
    fn renew() {
        let official: T::AccountId = account("official", 0, 0);
        setup_base::<T>(&official);
        let caller: T::AccountId = whitelisted_caller();
        let _ = register_name::<T>(caller.clone(), b"renewbench");

        #[extrinsic_call]
        _(RawOrigin::Signed(caller));
    }

    #[benchmark]
    fn transfer() {
        let official: T::AccountId = account("official", 0, 0);
        setup_base::<T>(&official);
        let caller: T::AccountId = whitelisted_caller();
        let _ = register_name::<T>(caller.clone(), b"xferbench");
        let dest: T::AccountId = account("dest", 0, 0);
        fund::<T>(&dest);
        let dest_src = T::Lookup::unlookup(dest);

        #[extrinsic_call]
        _(RawOrigin::Signed(caller), dest_src);
    }

    #[benchmark]
    fn release_name() {
        let official: T::AccountId = account("official", 0, 0);
        setup_base::<T>(&official);
        let caller: T::AccountId = whitelisted_caller();
        let _ = register_name::<T>(caller.clone(), b"releasebench");

        #[extrinsic_call]
        _(RawOrigin::Signed(caller));
    }

    #[benchmark]
    fn offer_subdomain(s: Linear<1, 32>) {
        let official: T::AccountId = account("official", 0, 0);
        setup_base::<T>(&official);
        let parent_owner: T::AccountId = whitelisted_caller();
        let _ = register_name::<T>(parent_owner.clone(), b"parentoffer");
        let target: T::AccountId = account("target", 0, 0);
        let target_src = T::Lookup::unlookup(target);
        let label: Vec<u8> = (0..s).map(|i| b'a' + (i as u8 % 26)).collect();

        #[extrinsic_call]
        _(RawOrigin::Signed(parent_owner), label, target_src);
    }

    #[benchmark]
    fn accept_subdomain() {
        let official: T::AccountId = account("official", 0, 0);
        setup_base::<T>(&official);
        let parent_owner: T::AccountId = whitelisted_caller();
        let _ = register_name::<T>(parent_owner.clone(), b"parentaccept");
        let target: T::AccountId = account("target", 0, 0);
        let target_src = T::Lookup::unlookup(target.clone());
        Pallet::<T>::offer_subdomain(
            RawOrigin::Signed(parent_owner).into(),
            b"sub".to_vec(),
            target_src,
        )
        .expect("offer subdomain setup");

        #[extrinsic_call]
        _(RawOrigin::Signed(target), b"parentaccept".to_vec(), b"sub".to_vec());
    }

    #[benchmark]
    fn reject_subdomain() {
        let official: T::AccountId = account("official", 0, 0);
        setup_base::<T>(&official);
        let parent_owner: T::AccountId = whitelisted_caller();
        let _ = register_name::<T>(parent_owner.clone(), b"parentreject");
        let target: T::AccountId = account("target", 0, 0);
        let target_src = T::Lookup::unlookup(target.clone());
        Pallet::<T>::offer_subdomain(
            RawOrigin::Signed(parent_owner).into(),
            b"sub".to_vec(),
            target_src,
        )
        .expect("offer subdomain setup");

        #[extrinsic_call]
        _(RawOrigin::Signed(target), b"parentreject".to_vec(), b"sub".to_vec());
    }

    #[benchmark]
    fn revoke_subdomain() {
        let official: T::AccountId = account("official", 0, 0);
        setup_base::<T>(&official);
        let parent_owner: T::AccountId = whitelisted_caller();
        let _ = register_name::<T>(parent_owner.clone(), b"parentrevoke");
        let target: T::AccountId = account("target", 0, 0);
        let target_src = T::Lookup::unlookup(target);
        Pallet::<T>::offer_subdomain(
            RawOrigin::Signed(parent_owner.clone()).into(),
            b"sub".to_vec(),
            target_src,
        )
        .expect("offer subdomain setup");

        #[extrinsic_call]
        _(RawOrigin::Signed(parent_owner), b"sub".to_vec());
    }

    #[benchmark]
    fn release_subdomain() {
        let official: T::AccountId = account("official", 0, 0);
        setup_base::<T>(&official);
        let parent_owner: T::AccountId = whitelisted_caller();
        let _ = register_name::<T>(parent_owner.clone(), b"parentrelease");
        let target: T::AccountId = account("target", 0, 0);
        let target_src = T::Lookup::unlookup(target.clone());
        Pallet::<T>::offer_subdomain(
            RawOrigin::Signed(parent_owner).into(),
            b"sub".to_vec(),
            target_src,
        )
        .expect("offer subdomain setup");
        Pallet::<T>::accept_subdomain(
            RawOrigin::Signed(target.clone()).into(),
            b"parentrelease".to_vec(),
            b"sub".to_vec(),
        )
        .expect("accept subdomain setup");

        #[extrinsic_call]
        _(RawOrigin::Signed(target), b"parentrelease".to_vec(), b"sub".to_vec());
    }

    #[benchmark]
    fn accept_offered_name() {
        let official: T::AccountId = account("official", 0, 0);
        setup_base::<T>(&official);
        let buyer: T::AccountId = account("buyer", 0, 0);
        let recipient: T::AccountId = whitelisted_caller();
        fund::<T>(&recipient);

        let name = b"gifted".to_vec();
        let (label, label_len) = Label::new_with_len(&name).expect("valid label");
        let node = label.encode_with_node(&<T as pallet::Config>::BaseNode::get());

        let class_id = <T as crate::nft::Config>::ClassId::zero();
        let tinfo = crate::nft::TokenInfo {
            metadata: Default::default(),
            owner: recipient.clone(),
            data: Default::default(),
        };
        crate::nft::Tokens::<T>::insert(class_id, node, tinfo);
        crate::nft::TokensByOwner::<T>::insert((recipient.clone(), class_id, node), ());

        let now = <T as pallet::Config>::NowProvider::now();
        let max_dur = <T as pallet::Config>::MaxRegistrationDuration::get();
        let expire = now.checked_add(&max_dur).expect("expire fits");
        let register_fee: BalanceOf<T> = 1_000_000_000_000u128.saturated_into();
        RegistrarInfos::<T>::insert(
            node,
            RegistrarInfoOf::<T> {
                register_fee,
                expire,
                capacity: <T as pallet::Config>::DefaultCapacity::get(),
                label_len: label_len as u32,
                last_block: 0u32,
            },
        );

        let offered: OfferedNameRecord<T::AccountId, <T as pallet::Config>::Moment> =
            OfferedNameRecord {
                buyer,
                recipient: recipient.clone(),
                offered_at: now,
            };
        OfferedNames::<T>::insert(node, offered);

        #[extrinsic_call]
        _(RawOrigin::Signed(recipient), name);
    }

    #[benchmark]
    fn cleanup() {
        let official: T::AccountId = account("official", 0, 0);
        setup_base::<T>(&official);
        let caller: T::AccountId = whitelisted_caller();
        fund::<T>(&caller);
        let registrant: T::AccountId = account("reg", 0, 0);
        let _ = register_name::<T>(registrant, b"cleanbench");

        let one: <T as pallet::Config>::Moment = 1u32.into();
        let max_dur = <T as pallet::Config>::MaxRegistrationDuration::get();
        let grace = <T as pallet::Config>::GracePeriod::get();
        let expire = one + max_dur;
        let deadline = expire + grace;
        let advanced = deadline + one;
        seed_now::<T>(advanced);

        #[extrinsic_call]
        _(RawOrigin::Signed(caller), deadline);
    }
}
