//! `WeightInfo` trait + two implementations for `zk-pki-pallet`.
//!
//! # ⚠️ Placeholder weights
//!
//! [`SubstrateWeight`] below contains **conservative placeholder
//! estimates** derived from per-extrinsic storage read/write counts.
//! They are NOT measured on reference hardware — the Substrate
//! benchmark CLI has not been run against this pallet yet.
//!
//! These placeholders are sufficient for Paseo testnet deployment
//! where block-weight ceilings are generous and exact weight
//! accuracy doesn't gate block production. Before Kusama or mainnet
//! submission, run the real benchmark:
//!
//! ```bash
//! cargo bench --features runtime-benchmarks \
//!   --package zk-pki-pallet \
//!   -- --pallet zk-pki-pallet --extrinsic '*'
//! ```
//!
//! and replace each `Weight::from_parts(...)` body with the
//! measured values.
//!
//! [`UnitTestWeight`] returns `Weight::zero()` for every extrinsic.
//! Used by the `zk-pki-runtime` integration test harness so test
//! outcomes are unaffected by weight changes.

#![allow(clippy::unnecessary_cast)]

use core::marker::PhantomData;
use frame_support::{traits::Get, weights::Weight};

/// Weight interface for every extrinsic in `zk-pki-pallet`.
pub trait WeightInfo {
    fn register_root() -> Weight;
    fn issue_issuer_cert() -> Weight;
    fn offer_contract() -> Weight;
    fn mint_cert() -> Weight;
    fn suspend_cert() -> Weight;
    fn reactivate_cert() -> Weight;
    fn invalidate_cert() -> Weight;
    fn self_discard_cert() -> Weight;
    fn invalidate_issuer() -> Weight;
    fn flag_root_compromised() -> Weight;
    fn reissue_cert() -> Weight;
    fn renew_cert() -> Weight;
    fn deregister_root() -> Weight;
    fn cleanup() -> Weight;
    fn challenge_compromise() -> Weight;
    fn resolve_challenge() -> Weight;
    fn create_cert_template() -> Weight;
    fn deactivate_cert_template() -> Weight;
    fn discard_cert_template() -> Weight;
    fn set_mime_wrap_vk() -> Weight;
}

/// Placeholder production weights. Must be replaced with measured
/// values before Kusama / mainnet — see module docstring.
pub struct SubstrateWeight<T>(PhantomData<T>);

/// Measured weights from `./target/release/paseo-node benchmark pallet
/// --chain=dev --pallet=zk_pki_pallet --extrinsic='*'
/// --exclude-extrinsics=zk_pki_pallet::renew_cert --steps=20 --repeat=5`
/// on 2026-04-21 (AMD Ryzen 9 5900HX). `renew_cert` is excluded — its
/// benchmark requires a real P-256 successor signature which would
/// pull signing deps into the benchmark crate; placeholder retained.
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
	/// Storage: `ZkPki::Roots` (r:1 w:1)
	/// Proof: `ZkPki::Roots` (`max_values`: None, `max_size`: Some(159), added: 2634, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::Issuers` (r:1 w:0)
	/// Proof: `ZkPki::Issuers` (`max_values`: None, `max_size`: Some(191), added: 2666, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::DeregisteredRoots` (r:1 w:0)
	/// Proof: `ZkPki::DeregisteredRoots` (`max_values`: None, `max_size`: Some(53), added: 2528, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::EkRegistry` (r:1 w:1)
	/// Proof: `ZkPki::EkRegistry` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::CertLookupHot` (r:1 w:1)
	/// Proof: `ZkPki::CertLookupHot` (`max_values`: None, `max_size`: Some(305), added: 2780, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Holds` (r:1 w:1)
	/// Proof: `Balances::Holds` (`max_values`: None, `max_size`: Some(103), added: 2578, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::ExpiryIndex` (r:1 w:1)
	/// Proof: `ZkPki::ExpiryIndex` (`max_values`: None, `max_size`: Some(8214), added: 10689, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::CertsByUser` (r:0 w:1)
	/// Proof: `ZkPki::CertsByUser` (`max_values`: None, `max_size`: Some(96), added: 2571, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::CertsByRoot` (r:0 w:1)
	/// Proof: `ZkPki::CertsByRoot` (`max_values`: None, `max_size`: Some(96), added: 2571, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::CertLookupCold` (r:0 w:1)
	/// Proof: `ZkPki::CertLookupCold` (`max_values`: None, `max_size`: Some(5079), added: 7554, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::CertsByIssuer` (r:0 w:1)
	/// Proof: `ZkPki::CertsByIssuer` (`max_values`: None, `max_size`: Some(96), added: 2571, mode: `MaxEncodedLen`)
	fn register_root() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `6`
		//  Estimated: `11679`
		// Minimum execution time: 78_132_000 picoseconds.
		Weight::from_parts(84_668_000, 0)
			.saturating_add(Weight::from_parts(0, 11679))
			.saturating_add(T::DbWeight::get().reads(7))
			.saturating_add(T::DbWeight::get().writes(9))
	}
	/// Storage: `ZkPki::Roots` (r:2 w:1)
	/// Proof: `ZkPki::Roots` (`max_values`: None, `max_size`: Some(159), added: 2634, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::Issuers` (r:1 w:1)
	/// Proof: `ZkPki::Issuers` (`max_values`: None, `max_size`: Some(191), added: 2666, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::IssuerCountPerRoot` (r:1 w:1)
	/// Proof: `ZkPki::IssuerCountPerRoot` (`max_values`: None, `max_size`: Some(52), added: 2527, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::EkRegistry` (r:1 w:1)
	/// Proof: `ZkPki::EkRegistry` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::CertLookupHot` (r:2 w:1)
	/// Proof: `ZkPki::CertLookupHot` (`max_values`: None, `max_size`: Some(305), added: 2780, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Holds` (r:1 w:1)
	/// Proof: `Balances::Holds` (`max_values`: None, `max_size`: Some(103), added: 2578, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::ExpiryIndex` (r:1 w:1)
	/// Proof: `ZkPki::ExpiryIndex` (`max_values`: None, `max_size`: Some(8214), added: 10689, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::RootIssuers` (r:1 w:1)
	/// Proof: `ZkPki::RootIssuers` (`max_values`: None, `max_size`: Some(209), added: 2684, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::CertsByUser` (r:0 w:1)
	/// Proof: `ZkPki::CertsByUser` (`max_values`: None, `max_size`: Some(96), added: 2571, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::CertsByRoot` (r:0 w:1)
	/// Proof: `ZkPki::CertsByRoot` (`max_values`: None, `max_size`: Some(96), added: 2571, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::CertLookupCold` (r:0 w:1)
	/// Proof: `ZkPki::CertLookupCold` (`max_values`: None, `max_size`: Some(5079), added: 7554, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::CertsByIssuer` (r:0 w:1)
	/// Proof: `ZkPki::CertsByIssuer` (`max_values`: None, `max_size`: Some(96), added: 2571, mode: `MaxEncodedLen`)
	fn issue_issuer_cert() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `898`
		//  Estimated: `11679`
		// Minimum execution time: 104_508_000 picoseconds.
		Weight::from_parts(110_844_000, 0)
			.saturating_add(Weight::from_parts(0, 11679))
			.saturating_add(T::DbWeight::get().reads(10))
			.saturating_add(T::DbWeight::get().writes(12))
	}
	/// Storage: `ZkPki::Issuers` (r:1 w:1)
	/// Proof: `ZkPki::Issuers` (`max_values`: None, `max_size`: Some(191), added: 2666, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::UserIssuerIndex` (r:1 w:0)
	/// Proof: `ZkPki::UserIssuerIndex` (`max_values`: None, `max_size`: Some(112), added: 2587, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::CertLookupHot` (r:2 w:0)
	/// Proof: `ZkPki::CertLookupHot` (`max_values`: None, `max_size`: Some(305), added: 2780, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::Roots` (r:1 w:1)
	/// Proof: `ZkPki::Roots` (`max_values`: None, `max_size`: Some(159), added: 2634, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::CertTemplates` (r:1 w:0)
	/// Proof: `ZkPki::CertTemplates` (`max_values`: None, `max_size`: Some(1319), added: 3794, mode: `MaxEncodedLen`)
	/// Storage: `System::ParentHash` (r:1 w:0)
	/// Proof: `System::ParentHash` (`max_values`: Some(1), `max_size`: Some(32), added: 527, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::OfferIndex` (r:1 w:1)
	/// Proof: `ZkPki::OfferIndex` (`max_values`: None, `max_size`: Some(112), added: 2587, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::OfferExpiryIndex` (r:1 w:1)
	/// Proof: `ZkPki::OfferExpiryIndex` (`max_values`: None, `max_size`: Some(8206), added: 10681, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::ContractOffers` (r:0 w:1)
	/// Proof: `ZkPki::ContractOffers` (`max_values`: None, `max_size`: Some(1264), added: 3739, mode: `MaxEncodedLen`)
	fn offer_contract() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1340`
		//  Estimated: `11671`
		// Minimum execution time: 63_419_000 picoseconds.
		Weight::from_parts(68_255_000, 0)
			.saturating_add(Weight::from_parts(0, 11671))
			.saturating_add(T::DbWeight::get().reads(9))
			.saturating_add(T::DbWeight::get().writes(5))
	}
	/// Storage: `ZkPki::ContractOffers` (r:1 w:1)
	/// Proof: `ZkPki::ContractOffers` (`max_values`: None, `max_size`: Some(1264), added: 3739, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::UserIssuerIndex` (r:1 w:1)
	/// Proof: `ZkPki::UserIssuerIndex` (`max_values`: None, `max_size`: Some(112), added: 2587, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::Issuers` (r:1 w:1)
	/// Proof: `ZkPki::Issuers` (`max_values`: None, `max_size`: Some(191), added: 2666, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::CertLookupHot` (r:3 w:1)
	/// Proof: `ZkPki::CertLookupHot` (`max_values`: None, `max_size`: Some(305), added: 2780, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::Roots` (r:1 w:1)
	/// Proof: `ZkPki::Roots` (`max_values`: None, `max_size`: Some(159), added: 2634, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::CertTemplates` (r:1 w:1)
	/// Proof: `ZkPki::CertTemplates` (`max_values`: None, `max_size`: Some(1319), added: 3794, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::EkRegistry` (r:1 w:1)
	/// Proof: `ZkPki::EkRegistry` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	/// Storage: `System::Account` (r:2 w:2)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Holds` (r:1 w:1)
	/// Proof: `Balances::Holds` (`max_values`: None, `max_size`: Some(103), added: 2578, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::ExpiryIndex` (r:1 w:1)
	/// Proof: `ZkPki::ExpiryIndex` (`max_values`: None, `max_size`: Some(8214), added: 10689, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::OfferExpiryIndex` (r:1 w:1)
	/// Proof: `ZkPki::OfferExpiryIndex` (`max_values`: None, `max_size`: Some(8206), added: 10681, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::TemplateActiveCertCount` (r:1 w:1)
	/// Proof: `ZkPki::TemplateActiveCertCount` (`max_values`: None, `max_size`: Some(134), added: 2609, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::CertsByUser` (r:0 w:1)
	/// Proof: `ZkPki::CertsByUser` (`max_values`: None, `max_size`: Some(96), added: 2571, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::OfferIndex` (r:0 w:1)
	/// Proof: `ZkPki::OfferIndex` (`max_values`: None, `max_size`: Some(112), added: 2587, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::CertsByRoot` (r:0 w:1)
	/// Proof: `ZkPki::CertsByRoot` (`max_values`: None, `max_size`: Some(96), added: 2571, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::CertLookupCold` (r:0 w:1)
	/// Proof: `ZkPki::CertLookupCold` (`max_values`: None, `max_size`: Some(5079), added: 7554, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::CertsByIssuer` (r:0 w:1)
	/// Proof: `ZkPki::CertsByIssuer` (`max_values`: None, `max_size`: Some(96), added: 2571, mode: `MaxEncodedLen`)
	fn mint_cert() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1964`
		//  Estimated: `11679`
		// Minimum execution time: 213_193_000 picoseconds.
		Weight::from_parts(227_832_000, 0)
			.saturating_add(Weight::from_parts(0, 11679))
			.saturating_add(T::DbWeight::get().reads(15))
			.saturating_add(T::DbWeight::get().writes(18))
	}
	/// Storage: `ZkPki::CertLookupHot` (r:1 w:1)
	/// Proof: `ZkPki::CertLookupHot` (`max_values`: None, `max_size`: Some(305), added: 2780, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::Issuers` (r:1 w:0)
	/// Proof: `ZkPki::Issuers` (`max_values`: None, `max_size`: Some(191), added: 2666, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::CertLookupCold` (r:1 w:1)
	/// Proof: `ZkPki::CertLookupCold` (`max_values`: None, `max_size`: Some(5079), added: 7554, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::PurgeIndex` (r:1 w:1)
	/// Proof: `ZkPki::PurgeIndex` (`max_values`: None, `max_size`: Some(8206), added: 10681, mode: `MaxEncodedLen`)
	fn suspend_cert() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1019`
		//  Estimated: `11671`
		// Minimum execution time: 30_869_000 picoseconds.
		Weight::from_parts(33_570_000, 0)
			.saturating_add(Weight::from_parts(0, 11671))
			.saturating_add(T::DbWeight::get().reads(4))
			.saturating_add(T::DbWeight::get().writes(3))
	}
	/// Storage: `ZkPki::CertLookupCold` (r:1 w:1)
	/// Proof: `ZkPki::CertLookupCold` (`max_values`: None, `max_size`: Some(5079), added: 7554, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::CertLookupHot` (r:1 w:1)
	/// Proof: `ZkPki::CertLookupHot` (`max_values`: None, `max_size`: Some(305), added: 2780, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::PurgeIndex` (r:1 w:1)
	/// Proof: `ZkPki::PurgeIndex` (`max_values`: None, `max_size`: Some(8206), added: 10681, mode: `MaxEncodedLen`)
	fn reactivate_cert() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1016`
		//  Estimated: `11671`
		// Minimum execution time: 28_768_000 picoseconds.
		Weight::from_parts(31_168_000, 0)
			.saturating_add(Weight::from_parts(0, 11671))
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().writes(3))
	}
	/// Storage: `ZkPki::CertLookupHot` (r:1 w:1)
	/// Proof: `ZkPki::CertLookupHot` (`max_values`: None, `max_size`: Some(305), added: 2780, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::CertLookupCold` (r:1 w:1)
	/// Proof: `ZkPki::CertLookupCold` (`max_values`: None, `max_size`: Some(5079), added: 7554, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::ExpiryIndex` (r:1 w:1)
	/// Proof: `ZkPki::ExpiryIndex` (`max_values`: None, `max_size`: Some(8214), added: 10689, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::TemplateActiveCertCount` (r:1 w:1)
	/// Proof: `ZkPki::TemplateActiveCertCount` (`max_values`: None, `max_size`: Some(134), added: 2609, mode: `MaxEncodedLen`)
	/// Storage: `System::Account` (r:1 w:1)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Holds` (r:1 w:1)
	/// Proof: `Balances::Holds` (`max_values`: None, `max_size`: Some(103), added: 2578, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::CertsByUser` (r:0 w:1)
	/// Proof: `ZkPki::CertsByUser` (`max_values`: None, `max_size`: Some(96), added: 2571, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::CertsByRoot` (r:0 w:1)
	/// Proof: `ZkPki::CertsByRoot` (`max_values`: None, `max_size`: Some(96), added: 2571, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::CertsByIssuer` (r:0 w:1)
	/// Proof: `ZkPki::CertsByIssuer` (`max_values`: None, `max_size`: Some(96), added: 2571, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::UserIssuerIndex` (r:0 w:1)
	/// Proof: `ZkPki::UserIssuerIndex` (`max_values`: None, `max_size`: Some(112), added: 2587, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::EkRegistry` (r:0 w:1)
	/// Proof: `ZkPki::EkRegistry` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	fn invalidate_cert() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1355`
		//  Estimated: `11679`
		// Minimum execution time: 80_918_000 picoseconds.
		Weight::from_parts(85_560_000, 0)
			.saturating_add(Weight::from_parts(0, 11679))
			.saturating_add(T::DbWeight::get().reads(6))
			.saturating_add(T::DbWeight::get().writes(11))
	}
	/// Storage: `ZkPki::CertLookupHot` (r:1 w:1)
	/// Proof: `ZkPki::CertLookupHot` (`max_values`: None, `max_size`: Some(305), added: 2780, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::CertLookupCold` (r:1 w:1)
	/// Proof: `ZkPki::CertLookupCold` (`max_values`: None, `max_size`: Some(5079), added: 7554, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::ExpiryIndex` (r:1 w:1)
	/// Proof: `ZkPki::ExpiryIndex` (`max_values`: None, `max_size`: Some(8214), added: 10689, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::TemplateActiveCertCount` (r:1 w:1)
	/// Proof: `ZkPki::TemplateActiveCertCount` (`max_values`: None, `max_size`: Some(134), added: 2609, mode: `MaxEncodedLen`)
	/// Storage: `System::Account` (r:1 w:1)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Holds` (r:1 w:1)
	/// Proof: `Balances::Holds` (`max_values`: None, `max_size`: Some(103), added: 2578, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::CertsByUser` (r:0 w:1)
	/// Proof: `ZkPki::CertsByUser` (`max_values`: None, `max_size`: Some(96), added: 2571, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::CertsByRoot` (r:0 w:1)
	/// Proof: `ZkPki::CertsByRoot` (`max_values`: None, `max_size`: Some(96), added: 2571, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::CertsByIssuer` (r:0 w:1)
	/// Proof: `ZkPki::CertsByIssuer` (`max_values`: None, `max_size`: Some(96), added: 2571, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::UserIssuerIndex` (r:0 w:1)
	/// Proof: `ZkPki::UserIssuerIndex` (`max_values`: None, `max_size`: Some(112), added: 2587, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::EkRegistry` (r:0 w:1)
	/// Proof: `ZkPki::EkRegistry` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	fn self_discard_cert() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `1359`
		//  Estimated: `11679`
		// Minimum execution time: 83_087_000 picoseconds.
		Weight::from_parts(89_859_000, 0)
			.saturating_add(Weight::from_parts(0, 11679))
			.saturating_add(T::DbWeight::get().reads(6))
			.saturating_add(T::DbWeight::get().writes(11))
	}
	/// Storage: `ZkPki::Roots` (r:1 w:0)
	/// Proof: `ZkPki::Roots` (`max_values`: None, `max_size`: Some(159), added: 2634, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::Issuers` (r:1 w:1)
	/// Proof: `ZkPki::Issuers` (`max_values`: None, `max_size`: Some(191), added: 2666, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::IssuerCountPerRoot` (r:1 w:1)
	/// Proof: `ZkPki::IssuerCountPerRoot` (`max_values`: None, `max_size`: Some(52), added: 2527, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::RootIssuers` (r:1 w:1)
	/// Proof: `ZkPki::RootIssuers` (`max_values`: None, `max_size`: Some(209), added: 2684, mode: `MaxEncodedLen`)
	fn invalidate_issuer() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `747`
		//  Estimated: `3674`
		// Minimum execution time: 27_808_000 picoseconds.
		Weight::from_parts(30_480_000, 0)
			.saturating_add(Weight::from_parts(0, 3674))
			.saturating_add(T::DbWeight::get().reads(4))
			.saturating_add(T::DbWeight::get().writes(3))
	}
	/// Storage: `ZkPki::Roots` (r:1 w:1)
	/// Proof: `ZkPki::Roots` (`max_values`: None, `max_size`: Some(159), added: 2634, mode: `MaxEncodedLen`)
	fn flag_root_compromised() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `385`
		//  Estimated: `3624`
		// Minimum execution time: 14_080_000 picoseconds.
		Weight::from_parts(15_526_000, 0)
			.saturating_add(Weight::from_parts(0, 3624))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `ZkPki::Issuers` (r:1 w:1)
	/// Proof: `ZkPki::Issuers` (`max_values`: None, `max_size`: Some(191), added: 2666, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::CertLookupHot` (r:4 w:2)
	/// Proof: `ZkPki::CertLookupHot` (`max_values`: None, `max_size`: Some(305), added: 2780, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::Roots` (r:1 w:1)
	/// Proof: `ZkPki::Roots` (`max_values`: None, `max_size`: Some(159), added: 2634, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::EkRegistry` (r:1 w:2)
	/// Proof: `ZkPki::EkRegistry` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	/// Storage: `System::Account` (r:2 w:2)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Holds` (r:2 w:2)
	/// Proof: `Balances::Holds` (`max_values`: None, `max_size`: Some(103), added: 2578, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::CertLookupCold` (r:1 w:2)
	/// Proof: `ZkPki::CertLookupCold` (`max_values`: None, `max_size`: Some(5079), added: 7554, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::ExpiryIndex` (r:2 w:2)
	/// Proof: `ZkPki::ExpiryIndex` (`max_values`: None, `max_size`: Some(8214), added: 10689, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::TemplateActiveCertCount` (r:1 w:1)
	/// Proof: `ZkPki::TemplateActiveCertCount` (`max_values`: None, `max_size`: Some(134), added: 2609, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::CertsByUser` (r:0 w:2)
	/// Proof: `ZkPki::CertsByUser` (`max_values`: None, `max_size`: Some(96), added: 2571, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::CertsByRoot` (r:0 w:2)
	/// Proof: `ZkPki::CertsByRoot` (`max_values`: None, `max_size`: Some(96), added: 2571, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::CertsByIssuer` (r:0 w:2)
	/// Proof: `ZkPki::CertsByIssuer` (`max_values`: None, `max_size`: Some(96), added: 2571, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::UserIssuerIndex` (r:0 w:1)
	/// Proof: `ZkPki::UserIssuerIndex` (`max_values`: None, `max_size`: Some(112), added: 2587, mode: `MaxEncodedLen`)
	fn reissue_cert() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `2319`
		//  Estimated: `22368`
		// Minimum execution time: 171_726_000 picoseconds.
		Weight::from_parts(184_424_000, 0)
			.saturating_add(Weight::from_parts(0, 22368))
			.saturating_add(T::DbWeight::get().reads(15))
			.saturating_add(T::DbWeight::get().writes(22))
	}
	/// Storage: `ZkPki::Roots` (r:1 w:1)
	/// Proof: `ZkPki::Roots` (`max_values`: None, `max_size`: Some(159), added: 2634, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::RootIssuers` (r:1 w:0)
	/// Proof: `ZkPki::RootIssuers` (`max_values`: None, `max_size`: Some(209), added: 2684, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::CertLookupHot` (r:1 w:1)
	/// Proof: `ZkPki::CertLookupHot` (`max_values`: None, `max_size`: Some(305), added: 2780, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::CertLookupCold` (r:1 w:1)
	/// Proof: `ZkPki::CertLookupCold` (`max_values`: None, `max_size`: Some(5079), added: 7554, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::ExpiryIndex` (r:1 w:1)
	/// Proof: `ZkPki::ExpiryIndex` (`max_values`: None, `max_size`: Some(8214), added: 10689, mode: `MaxEncodedLen`)
	/// Storage: `Balances::Holds` (r:1 w:1)
	/// Proof: `Balances::Holds` (`max_values`: None, `max_size`: Some(103), added: 2578, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::DeregisteredRoots` (r:0 w:1)
	/// Proof: `ZkPki::DeregisteredRoots` (`max_values`: None, `max_size`: Some(53), added: 2528, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::CertsByUser` (r:0 w:1)
	/// Proof: `ZkPki::CertsByUser` (`max_values`: None, `max_size`: Some(96), added: 2571, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::CertsByRoot` (r:0 w:1)
	/// Proof: `ZkPki::CertsByRoot` (`max_values`: None, `max_size`: Some(96), added: 2571, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::IssuerCountPerRoot` (r:0 w:1)
	/// Proof: `ZkPki::IssuerCountPerRoot` (`max_values`: None, `max_size`: Some(52), added: 2527, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::CertsByIssuer` (r:0 w:1)
	/// Proof: `ZkPki::CertsByIssuer` (`max_values`: None, `max_size`: Some(96), added: 2571, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::UserIssuerIndex` (r:0 w:1)
	/// Proof: `ZkPki::UserIssuerIndex` (`max_values`: None, `max_size`: Some(112), added: 2587, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::EkRegistry` (r:0 w:1)
	/// Proof: `ZkPki::EkRegistry` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	fn deregister_root() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `863`
		//  Estimated: `11679`
		// Minimum execution time: 77_861_000 picoseconds.
		Weight::from_parts(82_995_000, 0)
			.saturating_add(Weight::from_parts(0, 11679))
			.saturating_add(T::DbWeight::get().reads(6))
			.saturating_add(T::DbWeight::get().writes(12))
	}
	/// Storage: `ZkPki::CertLookupHot` (r:1 w:0)
	/// Proof: `ZkPki::CertLookupHot` (`max_values`: None, `max_size`: Some(305), added: 2780, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::CertLookupCold` (r:1 w:1)
	/// Proof: `ZkPki::CertLookupCold` (`max_values`: None, `max_size`: Some(5079), added: 7554, mode: `MaxEncodedLen`)
	fn cleanup() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `708`
		//  Estimated: `8544`
		// Minimum execution time: 21_100_000 picoseconds.
		Weight::from_parts(22_856_000, 0)
			.saturating_add(Weight::from_parts(0, 8544))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `ZkPki::Roots` (r:1 w:1)
	/// Proof: `ZkPki::Roots` (`max_values`: None, `max_size`: Some(159), added: 2634, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::Issuers` (r:1 w:0)
	/// Proof: `ZkPki::Issuers` (`max_values`: None, `max_size`: Some(191), added: 2666, mode: `MaxEncodedLen`)
	fn challenge_compromise() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `389`
		//  Estimated: `3656`
		// Minimum execution time: 17_804_000 picoseconds.
		Weight::from_parts(19_630_000, 0)
			.saturating_add(Weight::from_parts(0, 3656))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `ZkPki::Roots` (r:1 w:1)
	/// Proof: `ZkPki::Roots` (`max_values`: None, `max_size`: Some(159), added: 2634, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::Issuers` (r:1 w:0)
	/// Proof: `ZkPki::Issuers` (`max_values`: None, `max_size`: Some(191), added: 2666, mode: `MaxEncodedLen`)
	fn resolve_challenge() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `393`
		//  Estimated: `3656`
		// Minimum execution time: 17_866_000 picoseconds.
		Weight::from_parts(19_552_000, 0)
			.saturating_add(Weight::from_parts(0, 3656))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `ZkPki::Issuers` (r:1 w:1)
	/// Proof: `ZkPki::Issuers` (`max_values`: None, `max_size`: Some(191), added: 2666, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::CertTemplates` (r:1 w:1)
	/// Proof: `ZkPki::CertTemplates` (`max_values`: None, `max_size`: Some(1319), added: 3794, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::CertLookupHot` (r:1 w:0)
	/// Proof: `ZkPki::CertLookupHot` (`max_values`: None, `max_size`: Some(305), added: 2780, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::IssuerTemplateNames` (r:1 w:1)
	/// Proof: `ZkPki::IssuerTemplateNames` (`max_values`: None, `max_size`: Some(16946), added: 19421, mode: `MaxEncodedLen`)
	fn create_cert_template() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `715`
		//  Estimated: `20411`
		// Minimum execution time: 43_812_000 picoseconds.
		Weight::from_parts(47_037_000, 0)
			.saturating_add(Weight::from_parts(0, 20411))
			.saturating_add(T::DbWeight::get().reads(4))
			.saturating_add(T::DbWeight::get().writes(3))
	}
	/// Storage: `ZkPki::CertTemplates` (r:1 w:1)
	/// Proof: `ZkPki::CertTemplates` (`max_values`: None, `max_size`: Some(1319), added: 3794, mode: `MaxEncodedLen`)
	fn deactivate_cert_template() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `530`
		//  Estimated: `4784`
		// Minimum execution time: 15_413_000 picoseconds.
		Weight::from_parts(17_113_000, 0)
			.saturating_add(Weight::from_parts(0, 4784))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `ZkPki::CertTemplates` (r:1 w:1)
	/// Proof: `ZkPki::CertTemplates` (`max_values`: None, `max_size`: Some(1319), added: 3794, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::TemplateActiveCertCount` (r:1 w:1)
	/// Proof: `ZkPki::TemplateActiveCertCount` (`max_values`: None, `max_size`: Some(134), added: 2609, mode: `MaxEncodedLen`)
	/// Storage: `ZkPki::IssuerTemplateNames` (r:1 w:1)
	/// Proof: `ZkPki::IssuerTemplateNames` (`max_values`: None, `max_size`: Some(16946), added: 19421, mode: `MaxEncodedLen`)
	fn discard_cert_template() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `678`
		//  Estimated: `20411`
		// Minimum execution time: 39_880_000 picoseconds.
		Weight::from_parts(43_145_000, 0)
			.saturating_add(Weight::from_parts(0, 20411))
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().writes(3))
	}
	/// PLACEHOLDER — bench excluded (successor-signature requirement).
	/// Regenerate once benchmarking.rs can construct a valid signature.
	fn renew_cert() -> Weight {
		Weight::from_parts(80_000_000, 0)
			.saturating_add(T::DbWeight::get().reads(4))
			.saturating_add(T::DbWeight::get().writes(8))
	}

	/// PLACEHOLDER — Stage 5b. The benchmark in `benchmarking.rs`
	/// pins this to the size of the largest VK we accept
	/// (`MAX_MIME_WRAP_VK_BYTES = 32_768`); regenerate before
	/// Kusama. Storage layout is one read + one write of
	/// `MimeWrapVk` plus the bounded-vec decode of the input.
	///
	/// Storage: `ZkPki::MimeWrapVk` (r:0 w:1)
	/// Proof: `ZkPki::MimeWrapVk` (`max_values`: Some(1), `max_size`: Some(32773), added: 33268, mode: `MaxEncodedLen`)
	fn set_mime_wrap_vk() -> Weight {
		Weight::from_parts(50_000_000, 0)
			.saturating_add(Weight::from_parts(0, 33_268))
			.saturating_add(T::DbWeight::get().writes(1))
	}
}

/// Zero-cost weights for the integration-test runtime. Preserves
/// existing test behaviour — the test harness uses these so weight
/// changes don't perturb test outcomes.
pub struct UnitTestWeight;

impl WeightInfo for UnitTestWeight {
    fn register_root() -> Weight { Weight::zero() }
    fn issue_issuer_cert() -> Weight { Weight::zero() }
    fn offer_contract() -> Weight { Weight::zero() }
    fn mint_cert() -> Weight { Weight::zero() }
    fn suspend_cert() -> Weight { Weight::zero() }
    fn reactivate_cert() -> Weight { Weight::zero() }
    fn invalidate_cert() -> Weight { Weight::zero() }
    fn self_discard_cert() -> Weight { Weight::zero() }
    fn invalidate_issuer() -> Weight { Weight::zero() }
    fn flag_root_compromised() -> Weight { Weight::zero() }
    fn reissue_cert() -> Weight { Weight::zero() }
    fn renew_cert() -> Weight { Weight::zero() }
    fn deregister_root() -> Weight { Weight::zero() }
    fn cleanup() -> Weight { Weight::zero() }
    fn challenge_compromise() -> Weight { Weight::zero() }
    fn resolve_challenge() -> Weight { Weight::zero() }
    fn create_cert_template() -> Weight { Weight::zero() }
    fn deactivate_cert_template() -> Weight { Weight::zero() }
    fn discard_cert_template() -> Weight { Weight::zero() }
    fn set_mime_wrap_vk() -> Weight { Weight::zero() }
}
