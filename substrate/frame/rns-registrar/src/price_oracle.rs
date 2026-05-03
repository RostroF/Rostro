//! # Price Oracle
//!
//! This module is responsible for providing a price list
//! that can be set dynamically, but it is not intelligent
//! and the base price can only be set manually by the manager.
//! (A more intelligent approach, such as an off-chain worker,
//!  is being considered)
//!
//! ## Introduction
//!
//! This module is used to calculate the parameters required
//! for the base price of domain name registrations and auctions.
//!
//! ### Module functions
//!
//! - `set_exchange_rate` - sets the local rate
//! - `set_base_price` - sets the base price
//! - `set_rent_price` - sets the price used for time growth
//!
//! All the above methods require manager privileges in `pnsOrigin`.
//!
//! Note that the `trait` of `ExchangeRate` is to conveniently follow
//! if the parallel chain itself provides price oracle related functions,
//! and can be directly replaced.
//!
use rp_weights::Weight;
pub use pallet::*;

type BalanceOf<T> = <<T as Config>::Currency as frame_support::traits::Currency<
    <T as frame_system::Config>::AccountId,
>>::Balance;

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use crate::traits::ExchangeRate as ExchangeRateT;
    use frame_support::traits::{Currency, EnsureOrigin};
    use frame_support::{dispatch::DispatchResult, pallet_prelude::*};
    use frame_system::pallet_prelude::*;
    use scale_info::TypeInfo;
    use rp_runtime::traits::AtLeast32BitUnsigned;

    #[pallet::config]
    pub trait Config: frame_system::Config {

        type Currency: Currency<Self::AccountId>;

        type Moment: Clone
            + Copy
            + Decode
            + Encode
            + Eq
            + PartialEq
            + core::fmt::Debug
            + Default
            + TypeInfo
            + AtLeast32BitUnsigned
            + MaybeSerializeDeserialize;

        type ExchangeRate: ExchangeRateT<Balance = BalanceOf<Self>>;

        type WeightInfo: WeightInfo;

        type ManagerOrigin: EnsureOrigin<Self::RuntimeOrigin, Success = Self::AccountId>;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    // 11 price tiers, tier selection keyed by domain name length.
    #[pallet::storage]
    pub type BasePrice<T: Config> = StorageValue<_, [BalanceOf<T>; 11], ValueQuery>;

    #[pallet::storage]
    pub type RentPrice<T: Config> = StorageValue<_, [BalanceOf<T>; 11], ValueQuery>;

    #[pallet::storage]
    pub type ExchangeRate<T: Config> = StorageValue<_, BalanceOf<T>, ValueQuery>;

    #[pallet::genesis_config]
    pub struct GenesisConfig<T: Config> {
        pub base_prices: [BalanceOf<T>; 11],
        pub rent_prices: [BalanceOf<T>; 11],
        pub init_rate: BalanceOf<T>,
    }

    impl<T: Config> Default for GenesisConfig<T> {
        fn default() -> Self {
            GenesisConfig {
                base_prices: [Default::default(); 11],
                rent_prices: [Default::default(); 11],
                init_rate: Default::default(),
            }
        }
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            <BasePrice<T>>::put(self.base_prices);
            <RentPrice<T>>::put(self.rent_prices);
            <ExchangeRate<T>>::put(self.init_rate);
        }
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Base praice changed
        /// `[base_prices]`
        BasePriceChanged([BalanceOf<T>; 11]),
        /// Rent price changed
        /// `[rent_prices]`
        RentPriceChanged([BalanceOf<T>; 11]),
        /// Exchange rate changed
        /// `[who, rate]`
        ExchangeRateChanged(T::AccountId, BalanceOf<T>),
    }

    #[pallet::error]
    pub enum Error<T> {}

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::set_exchange_rate())]
        pub fn set_exchange_rate(
            origin: OriginFor<T>,
            exchange_rate: BalanceOf<T>,
        ) -> DispatchResult {
            let who = T::ManagerOrigin::ensure_origin(origin)?;

            <ExchangeRate<T>>::put(exchange_rate);

            Self::deposit_event(Event::ExchangeRateChanged(who, exchange_rate));

            Ok(())
        }
        /// Internal root method.
        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::set_base_price())]
        pub fn set_base_price(origin: OriginFor<T>, prices: [BalanceOf<T>; 11]) -> DispatchResult {
            let _who = T::ManagerOrigin::ensure_origin(origin)?;

            <BasePrice<T>>::put(prices);

            Self::deposit_event(Event::BasePriceChanged(prices));

            Ok(())
        }
        /// Internal root method.
        #[pallet::call_index(2)]
        #[pallet::weight(T::WeightInfo::set_rent_price())]
        pub fn set_rent_price(origin: OriginFor<T>, prices: [BalanceOf<T>; 11]) -> DispatchResult {
            let _who = T::ManagerOrigin::ensure_origin(origin)?;

            <RentPrice<T>>::put(prices);

            Self::deposit_event(Event::RentPriceChanged(prices));

            Ok(())
        }
    }
}
use crate::traits::{ExchangeRate as ExchangeRateT, PriceOracle};

#[cfg(feature = "runtime-benchmarks")]
#[frame_benchmarking::v2::benchmarks]
mod benchmarks {
    use super::*;
    use frame_benchmarking::v2::*;
    use frame_system::RawOrigin;

    fn price_array<T: Config>() -> [BalanceOf<T>; 11] {
        let one: BalanceOf<T> = 1_000_000u32.into();
        [one; 11]
    }

    #[benchmark]
    fn set_exchange_rate() {
        let rate: BalanceOf<T> = 42_000_000u32.into();
        #[extrinsic_call]
        _(RawOrigin::Root, rate);
        assert_eq!(ExchangeRate::<T>::get(), rate);
    }

    #[benchmark]
    fn set_base_price() {
        let prices = price_array::<T>();
        #[extrinsic_call]
        _(RawOrigin::Root, prices);
        assert_eq!(BasePrice::<T>::get(), prices);
    }

    #[benchmark]
    fn set_rent_price() {
        let prices = price_array::<T>();
        #[extrinsic_call]
        _(RawOrigin::Root, prices);
        assert_eq!(RentPrice::<T>::get(), prices);
    }
}

pub trait WeightInfo {
    fn set_exchange_rate() -> Weight;
    fn set_base_price() -> Weight;
    fn set_rent_price() -> Weight;
}

impl<T: Config> PriceOracle for Pallet<T> {
    type Moment = T::Moment;

    type Balance = BalanceOf<T>;

    fn registration_fee(name_len: usize) -> Option<Self::Balance> {
        if name_len == 0 {
            return None;
        }
        let base_prices = BasePrice::<T>::get();
        let idx = (name_len - 1).min(base_prices.len() - 1);
        Some(base_prices[idx])
    }

    fn register_fee(name_len: usize, _duration: Self::Moment) -> Option<Self::Balance> {
        Self::registration_fee(name_len)
    }

    fn renew_fee(name_len: usize, _duration: Self::Moment) -> Option<Self::Balance> {
        Self::registration_fee(name_len)
    }
}

impl<T: Config> ExchangeRateT for Pallet<T> {
    type Balance = BalanceOf<T>;

    fn get_exchange_rate() -> Self::Balance {
        ExchangeRate::<T>::get()
    }
}

impl WeightInfo for () {
    fn set_exchange_rate() -> Weight { Weight::from_parts(150_000_000, 500) }
    fn set_base_price() -> Weight { Weight::from_parts(150_000_000, 500) }
    fn set_rent_price() -> Weight { Weight::from_parts(150_000_000, 500) }
}
