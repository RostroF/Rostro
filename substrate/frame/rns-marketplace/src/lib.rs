#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

pub mod marketplace_weights;

#[frame_support::pallet]
pub mod pallet {
    use codec::{DecodeWithMemTracking, Encode, Decode, MaxEncodedLen};
    use frame_support::{
        pallet_prelude::*,
        traits::{Currency, ExistenceRequirement, Time,
                 tokens::fungible::hold::Mutate as HoldMutate},
    };
    use frame_system::{ensure_signed, pallet_prelude::*};
    use sp_runtime::traits::{AtLeast32Bit, MaybeSerializeDeserialize, Zero};
    use rns_types::DomainHash;
    use pallet_rns_registrar::traits::{Label, NameRegistry, OriginRecorder, RecordCleaner, Ss58Updater};
    use sp_std::vec::Vec;
    use crate::WeightInfo;
    use scale_info::TypeInfo;

    pub type BalanceOf<T> =
        <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type Currency: Currency<Self::AccountId>;

        /// Composite hold reason. Must include this pallet's `HoldReason`.
        type RuntimeHoldReason: From<HoldReason>;

        /// Fungible hold interface for listing deposits.
        type Fungible: HoldMutate<
            Self::AccountId,
            Reason = Self::RuntimeHoldReason,
            Balance = BalanceOf<Self>,
        >;

        /// Amount held from the seller when creating a listing.
        #[pallet::constant]
        type ListingDeposit: Get<BalanceOf<Self>>;

        /// How long after a listing expires before it becomes claimable
        /// by anyone via `cleanup_listing()`. During this window only the
        /// seller can reclaim via `cancel_listing()`.
        #[pallet::constant]
        type ListingGracePeriod: Get<Self::Moment>;

        type Moment: AtLeast32Bit
            + Parameter
            + Default
            + Copy
            + MaxEncodedLen
            + MaybeSerializeDeserialize;

        /// Provider of the current on-chain time.
        type NowProvider: Time<Moment = Self::Moment>;

        /// Access to name ownership and transfer operations.
        type NameRegistry: pallet_rns_registrar::traits::NameRegistry<AccountId = Self::AccountId>;

        /// Writes the SS58 (owner account) record after a name is purchased.
        type Ss58Updater: Ss58Updater<AccountId = Self::AccountId>;

        /// Clears non-SS58 DNS records when a name is purchased.
        type RecordCleaner: RecordCleaner;

        /// Writes the ORIGIN record (block hash) when a name is purchased.
        type OriginRecorder: OriginRecorder;

        /// The base namehash for the TLD (e.g. the namehash of "rst").
        #[pallet::constant]
        type BaseNode: Get<DomainHash>;

        type WeightInfo: WeightInfo;
    }

    /// An active sale listing.
    #[derive(Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, MaxEncodedLen, TypeInfo)]
    #[derive(serde::Serialize, serde::Deserialize)]
    pub struct Listing<AccountId, Balance, Moment> {
        /// Account that created the listing and will receive the proceeds.
        pub seller: AccountId,
        /// Asking price in the native currency.
        pub price: Balance,
        /// Millisecond timestamp after which this listing is no longer valid.
        pub expires_at: Moment,
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    /// Hold reasons scoped to this pallet.
    #[pallet::composite_enum]
    pub enum HoldReason {
        /// Deposit held on the seller when creating a listing.
        #[codec(index = 0)]
        ListingDeposit,
    }

    /// Active listings indexed by the name's namehash.
    #[pallet::storage]
    pub type Listings<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        DomainHash,
        Listing<T::AccountId, BalanceOf<T>, T::Moment>,
    >;

    /// Listing deposit held on the seller. Tracks (seller, amount) per node.
    /// Released on buy or cancel. Claimable by anyone after listing expiry
    /// + grace period via `cleanup_listing()`.
    #[pallet::storage]
    pub type ListingDeposits<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        DomainHash,
        (T::AccountId, BalanceOf<T>),
    >;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A name was listed for sale.
        Listed {
            node: DomainHash,
            seller: T::AccountId,
            price: BalanceOf<T>,
            expires_at: T::Moment,
        },
        /// A listing was cancelled by the owner.
        Delisted {
            node: DomainHash,
            seller: T::AccountId,
        },
        /// A name was sold. Buyer paid the seller's asking price plus the
        /// registration fee (charged separately by the registrar).
        Sold {
            node: DomainHash,
            seller: T::AccountId,
            buyer: T::AccountId,
            price: BalanceOf<T>,
        },
        /// An expired listing was cleaned up and its deposit paid to the caller.
        ListingCleaned {
            node: DomainHash,
            caller: T::AccountId,
            payout: BalanceOf<T>,
        },
        /// A name was purchased as a gift for `recipient` and is awaiting their acceptance.
        NameBoughtForRecipient {
            node: DomainHash,
            seller: T::AccountId,
            buyer: T::AccountId,
            recipient: T::AccountId,
            price: BalanceOf<T>,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// Caller has no canonical name registered.
        NoCanonicalName,
        /// This name is already listed for sale.
        AlreadyListed,
        /// No active listing found for this name.
        NotListed,
        /// The listing's expiry time is in the past.
        ListingExpired,
        /// The listed seller no longer owns this name.
        SellerNoLongerOwns,
        /// Expiry must be in the future.
        ExpiryNotInFuture,
        /// The provided name label is invalid (empty, too long, or contains illegal characters).
        InvalidName,
        /// The buyer and the seller cannot be the same account.
        BuyerIsSeller,
        /// The buyer cannot also be the intended gift recipient.
        BuyerIsRecipient,
        /// The seller cannot be the gift recipient (no self-gifting).
        SellerIsRecipient,
        InternalHashConversion,
        /// Seller does not have enough free balance for the listing deposit.
        InsufficientDeposit,
        /// The listing has not expired past its grace period yet.
        ListingNotExpired,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// List the caller's canonical name for sale at `price`, expiring at `expires_at`.
        ///
        /// The name remains usable by the owner while listed — there is no escrow lock.
        /// If the owner transfers or releases the name before a buyer appears, the listing
        /// becomes stale and any `buy_name` attempt will fail.
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::create_listing())]
        pub fn create_listing(
            origin: OriginFor<T>,
            price: BalanceOf<T>,
            expires_at: T::Moment,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let now = T::NowProvider::now();
            ensure!(expires_at > now, Error::<T>::ExpiryNotInFuture);
            let node = T::NameRegistry::canonical_name(&who)
                .ok_or(Error::<T>::NoCanonicalName)?;
            // Auto-clean stale listings where the previous seller no longer owns the name.
            if let Some(existing) = Listings::<T>::get(node) {
                if Some(existing.seller.clone()) == T::NameRegistry::owner_of(node) {
                    return Err(Error::<T>::AlreadyListed.into());
                }
                // Stale listing — release old deposit if any.
                if let Some((old_seller, old_deposit)) = ListingDeposits::<T>::take(node) {
                    use frame_support::traits::tokens::Precision;
                    let _ = T::Fungible::release(
                        &HoldReason::ListingDeposit.into(),
                        &old_seller,
                        old_deposit,
                        Precision::BestEffort,
                    );
                }
                Listings::<T>::remove(node);
            }
            // Hold listing deposit on the seller.
            let deposit = T::ListingDeposit::get();
            T::Fungible::hold(
                &HoldReason::ListingDeposit.into(),
                &who,
                deposit,
            ).map_err(|_| Error::<T>::InsufficientDeposit)?;
            ListingDeposits::<T>::insert(node, (who.clone(), deposit));
            Listings::<T>::insert(node, Listing { seller: who.clone(), price, expires_at });
            Self::deposit_event(Event::<T>::Listed { node, seller: who, price, expires_at });
            Ok(())
        }

        /// Cancel the caller's active listing.
        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::cancel_listing())]
        pub fn cancel_listing(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let node = T::NameRegistry::canonical_name(&who)
                .ok_or(Error::<T>::NoCanonicalName)?;
            ensure!(Listings::<T>::contains_key(node), Error::<T>::NotListed);
            // Release the listing deposit back to the seller.
            if let Some((seller, deposit)) = ListingDeposits::<T>::take(node) {
                use frame_support::traits::tokens::Precision;
                let _ = T::Fungible::release(
                    &HoldReason::ListingDeposit.into(),
                    &seller,
                    deposit,
                    Precision::BestEffort,
                );
            }
            Listings::<T>::remove(node);
            Self::deposit_event(Event::<T>::Delisted { node, seller: who });
            Ok(())
        }

        /// Purchase a listed name. The buyer pays the seller's asking price
        /// PLUS the full registration fee (based on label length). The
        /// registration fee prevents hot-potato flipping to circumvent
        /// short-name pricing — every transfer costs the same as a fresh
        /// registration.
        ///
        /// Pass `recipient = Some(account)` to buy the name as a gift.
        /// The name enters an "offered" state until the recipient accepts.
        #[pallet::call_index(2)]
        #[pallet::weight(T::WeightInfo::buy_name())]
        #[frame_support::transactional]
        pub fn buy_name(origin: OriginFor<T>, name: Vec<u8>, recipient: Option<T::AccountId>) -> DispatchResult {
            let buyer = ensure_signed(origin)?;
            let label = Label::new(&name).ok_or(Error::<T>::InvalidName)?;
            let node = label.encode_with_node(&T::BaseNode::get());
            let listing = Listings::<T>::get(node).ok_or(Error::<T>::NotListed)?;
            ensure!(buyer != listing.seller, Error::<T>::BuyerIsSeller);
            ensure!(listing.expires_at > T::NowProvider::now(), Error::<T>::ListingExpired);
            if Some(listing.seller.clone()) != T::NameRegistry::owner_of(node) {
                // Stale listing — release the deposit back to the original seller.
                if let Some((seller, deposit)) = ListingDeposits::<T>::take(node) {
                    use frame_support::traits::tokens::Precision;
                    let _ = T::Fungible::release(
                        &HoldReason::ListingDeposit.into(),
                        &seller,
                        deposit,
                        Precision::BestEffort,
                    );
                }
                Listings::<T>::remove(node);
                return Err(Error::<T>::SellerNoLongerOwns.into());
            }

            ensure!(
                T::NameRegistry::is_name_useable(node),
                Error::<T>::ListingExpired
            );

            if let Some(ref recip) = recipient {
                ensure!(*recip != buyer, Error::<T>::BuyerIsRecipient);
                ensure!(*recip != listing.seller, Error::<T>::SellerIsRecipient);
            }

            // Pay the seller's asking price.
            T::Currency::transfer(
                &buyer,
                &listing.seller,
                listing.price,
                ExistenceRequirement::KeepAlive,
            )?;

            // Charge the buyer the registration fee (5% hold + 40% author + 55% custodian).
            // Releases the seller's old cleanup deposit back to them.
            T::NameRegistry::charge_sale_fee(&buyer, node)?;

            // Release the listing deposit back to the seller.
            if let Some((seller, deposit)) = ListingDeposits::<T>::take(node) {
                use frame_support::traits::tokens::Precision;
                let _ = T::Fungible::release(
                    &HoldReason::ListingDeposit.into(),
                    &seller,
                    deposit,
                    Precision::BestEffort,
                );
            }

            Listings::<T>::remove(node);

            if let Some(recip) = recipient {
                T::NameRegistry::offer_bought_name(&listing.seller, &buyer, &recip, node)?;

                Self::deposit_event(Event::<T>::NameBoughtForRecipient {
                    node,
                    seller: listing.seller,
                    buyer,
                    recipient: recip,
                    price: listing.price,
                });
            } else {
                T::NameRegistry::transfer_name(&listing.seller, &buyer, node)?;

                // ORIGIN is intentionally NOT rewritten on marketplace sale —
                // it pins the initial registration block of the name, which must
                // survive ownership changes so off-chain reputation / seniority
                // consumers can trust `pns_getInfo`'s ORIGIN record.
                T::RecordCleaner::clear_records_except_ss58(node);
                T::Ss58Updater::update_ss58(node, &buyer)?;

                Self::deposit_event(Event::<T>::Sold {
                    node,
                    seller: listing.seller,
                    buyer,
                    price: listing.price,
                });
            }
            Ok(())
        }

        /// Clean up an expired listing whose grace period has passed.
        /// Anyone can call this. The listing deposit is released from the
        /// seller and transferred to the caller.
        #[pallet::call_index(3)]
        #[pallet::weight(T::WeightInfo::cleanup_listing())]
        #[frame_support::transactional]
        pub fn cleanup_listing(origin: OriginFor<T>, name: Vec<u8>) -> DispatchResult {
            let caller = ensure_signed(origin)?;
            let label = Label::new(&name).ok_or(Error::<T>::InvalidName)?;
            let node = label.encode_with_node(&T::BaseNode::get());

            let listing = Listings::<T>::get(node).ok_or(Error::<T>::NotListed)?;
            let now = T::NowProvider::now();

            // Must be past listing expiry + grace period.
            use sp_runtime::traits::CheckedAdd;
            let deadline = listing.expires_at
                .checked_add(&T::ListingGracePeriod::get())
                .unwrap_or(listing.expires_at);
            ensure!(now > deadline, Error::<T>::ListingNotExpired);

            // Release the deposit and pay the cleanup caller.
            if let Some((seller, deposit)) = ListingDeposits::<T>::take(node) {
                use frame_support::traits::tokens::Precision;
                let released = T::Fungible::release(
                    &HoldReason::ListingDeposit.into(),
                    &seller,
                    deposit,
                    Precision::BestEffort,
                ).unwrap_or_default();

                if !released.is_zero() {
                    T::Currency::transfer(
                        &seller,
                        &caller,
                        released,
                        ExistenceRequirement::AllowDeath,
                    )?;
                }

                Self::deposit_event(Event::<T>::ListingCleaned {
                    node,
                    caller,
                    payout: released,
                });
            }

            Listings::<T>::remove(node);
            Ok(())
        }
    }
}

use sp_weights::Weight;
use rns_types::DomainHash;

pub trait WeightInfo {
    fn create_listing() -> Weight;
    fn cancel_listing() -> Weight;
    fn buy_name() -> Weight;
    fn cleanup_listing() -> Weight;
}

impl WeightInfo for () {
    fn create_listing() -> Weight { Weight::from_parts(200_000_000, 2_000) }
    fn cancel_listing() -> Weight { Weight::from_parts(200_000_000, 2_000) }
    fn buy_name() -> Weight { Weight::from_parts(500_000_000, 5_000) }
    fn cleanup_listing() -> Weight { Weight::from_parts(500_000_000, 5_000) }
}

impl<T: Config> Pallet<T> {
    /// Returns the active listing for `node`, if any.
    pub fn listing(node: DomainHash) -> Option<Listing<T::AccountId, BalanceOf<T>, T::Moment>> {
        pallet::Listings::<T>::get(node)
    }
}

#[cfg(feature = "runtime-benchmarks")]
#[frame_benchmarking::v2::benchmarks(
    where T: pallet_rns_registrar::registrar::Config + pallet_timestamp::Config<Moment = <T as pallet::Config>::Moment>,
)]
mod benchmarks {
    use super::*;
    use frame_benchmarking::v2::*;
    use frame_support::traits::{Currency, Get};
    use frame_system::RawOrigin;
    use sp_runtime::{traits::SaturatedConversion, traits::One};

    /// Fund + register a canonical name for the caller.
    fn setup_owner<T>(caller: &T::AccountId, name: &[u8])
    where
        T: pallet_rns_registrar::registrar::Config,
    {
        let big: pallet_rns_registrar::registrar::BalanceOf<T> =
            (u128::MAX / 2).saturated_into();
        <T as pallet_rns_registrar::registrar::Config>::Currency::make_free_balance_be(caller, big);
        pallet_rns_registrar::registrar::Pallet::<T>::register(
            RawOrigin::Signed(caller.clone()).into(),
            name.to_vec(),
            None,
        )
        .expect("register bench setup");
    }

    fn bench_price<T: pallet::Config>() -> BalanceOf<T> {
        1_000_000_000_000u128.saturated_into()
    }

    /// Moment 10 days from now — comfortably inside the listing window
    /// but also past any `now == expires_at` boundary checks in tests.
    fn future_moment<T>() -> <T as pallet::Config>::Moment
    where
        T: pallet::Config + pallet_timestamp::Config<Moment = <T as pallet::Config>::Moment>,
    {
        let now = pallet_timestamp::Now::<T>::get();
        let ten_days: u64 = 10 * 86_400_000;
        now + ten_days.saturated_into()
    }

    #[benchmark]
    fn create_listing() {
        let caller: T::AccountId = whitelisted_caller();
        setup_owner::<T>(&caller, b"listbench");

        let price = bench_price::<T>();
        let exp = future_moment::<T>();

        #[extrinsic_call]
        _(RawOrigin::Signed(caller), price, exp);
    }

    #[benchmark]
    fn cancel_listing() {
        let caller: T::AccountId = whitelisted_caller();
        setup_owner::<T>(&caller, b"cancelbench");
        let price = bench_price::<T>();
        let exp = future_moment::<T>();
        Pallet::<T>::create_listing(
            RawOrigin::Signed(caller.clone()).into(),
            price,
            exp,
        )
        .expect("create_listing bench setup");

        #[extrinsic_call]
        _(RawOrigin::Signed(caller));
    }

    #[benchmark]
    fn buy_name() {
        let seller: T::AccountId = whitelisted_caller();
        setup_owner::<T>(&seller, b"buybench");
        let price = bench_price::<T>();
        let exp = future_moment::<T>();
        Pallet::<T>::create_listing(
            RawOrigin::Signed(seller.clone()).into(),
            price,
            exp,
        )
        .expect("create_listing bench setup");

        let buyer: T::AccountId = account("buyer", 0, 0);
        let big: pallet_rns_registrar::registrar::BalanceOf<T> =
            (u128::MAX / 2).saturated_into();
        <T as pallet_rns_registrar::registrar::Config>::Currency::make_free_balance_be(&buyer, big);

        #[extrinsic_call]
        _(RawOrigin::Signed(buyer), b"buybench".to_vec(), None);
    }

    #[benchmark]
    fn cleanup_listing() {
        let seller: T::AccountId = whitelisted_caller();
        setup_owner::<T>(&seller, b"cleanbench");

        // Short listing window — 1 ms past `now` — so advancing time
        // past grace is cheap.
        let now = pallet_timestamp::Now::<T>::get();
        let short_exp: <T as pallet::Config>::Moment =
            now + <<T as pallet::Config>::Moment as One>::one();
        Pallet::<T>::create_listing(
            RawOrigin::Signed(seller.clone()).into(),
            bench_price::<T>(),
            short_exp,
        )
        .expect("create_listing bench setup");

        // Advance past expires_at + ListingGracePeriod.
        let grace = <T as pallet::Config>::ListingGracePeriod::get();
        let advanced: <T as pallet_timestamp::Config>::Moment = short_exp
            + grace
            + <<T as pallet::Config>::Moment as One>::one();
        pallet_timestamp::Now::<T>::put(advanced);

        let caller: T::AccountId = account("reaper", 0, 0);

        #[extrinsic_call]
        _(RawOrigin::Signed(caller), b"cleanbench".to_vec());
    }
}
