// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Per-pallet `Config` implementations for the Rostro Phase 1 solochain runtime.
//!
//! Pallets included here intentionally exclude the RNS family — those land
//! in the next commit on this branch, after gates 1-5 pass with the base
//! template.

use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use frame_support::{
	derive_impl,
	dispatch::DispatchClass,
	parameter_types,
	traits::{
		ConstBool, ConstU128, ConstU32, ConstU64, ConstU8, FindAuthor, InstanceFilter,
		VariantCountOf,
	},
	weights::{
		constants::{RocksDbWeight, WEIGHT_REF_TIME_PER_SECOND},
		IdentityFee, Weight,
	},
};
use frame_system::limits::{BlockLength, BlockWeights};
use pallet_transaction_payment::{ConstFeeMultiplier, FungibleAdapter, Multiplier};
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_runtime::{traits::ConvertInto, ConsensusEngineId, Perbill};
use sp_version::RuntimeVersion;
use scale_info::TypeInfo;

use super::{
	opaque, AccountId, Aura, Balance, Balances, Block, BlockNumber, Hash, Nonce, OriginCaller,
	PalletInfo, Runtime, RuntimeCall, RuntimeEvent, RuntimeFreezeReason, RuntimeHoldReason,
	RuntimeOrigin, RuntimeTask, System, Timestamp, EXISTENTIAL_DEPOSIT, ROSTO, SLOT_DURATION,
	VERSION,
};

const NORMAL_DISPATCH_RATIO: Perbill = Perbill::from_percent(75);

parameter_types! {
	pub const BlockHashCount: BlockNumber = 2400;
	pub const Version: RuntimeVersion = VERSION;

	/// 2 seconds of compute per 6-second block.
	pub RuntimeBlockWeights: BlockWeights = BlockWeights::with_sensible_defaults(
		Weight::from_parts(2u64 * WEIGHT_REF_TIME_PER_SECOND, u64::MAX),
		NORMAL_DISPATCH_RATIO,
	);
	pub RuntimeBlockLength: BlockLength = BlockLength::builder()
		.max_length(5 * 1024 * 1024)
		.modify_max_length_for_class(DispatchClass::Normal, |m| *m = NORMAL_DISPATCH_RATIO * *m)
		.build();
	/// SS58 prefix 137 reserved for Rostro (placeholder; final assignment is a
	/// prelaunch concern). 42 is the generic substrate dev prefix.
	pub const SS58Prefix: u8 = 42;
}

/// Runtime-upgrade migrations. The type-registry gate runs last so any
/// SRT-approved fingerprint updates earlier in the tuple have already landed
/// before we assert the post-upgrade invariant.
#[allow(unused_parens)]
type SingleBlockMigrations =
	(pallet_rostro_type_registry::migrations::EnforceWellKnownFingerprints<Runtime>,);

// ─── frame_system ───────────────────────────────────────────────────────────

#[derive_impl(frame_system::config_preludes::SolochainDefaultConfig)]
impl frame_system::Config for Runtime {
	type Block = Block;
	type BlockWeights = RuntimeBlockWeights;
	type BlockLength = RuntimeBlockLength;
	type AccountId = AccountId;
	type Nonce = Nonce;
	type Hash = Hash;
	type BlockHashCount = BlockHashCount;
	type DbWeight = RocksDbWeight;
	type Version = Version;
	type AccountData = pallet_balances::AccountData<Balance>;
	type SS58Prefix = SS58Prefix;
	type MaxConsumers = ConstU32<16>;
	type SingleBlockMigrations = SingleBlockMigrations;
}

// ─── pallet_timestamp ───────────────────────────────────────────────────────

impl pallet_timestamp::Config for Runtime {
	type Moment = u64;
	type OnTimestampSet = Aura;
	type MinimumPeriod = ConstU64<{ SLOT_DURATION / 2 }>;
	type WeightInfo = ();
}

// ─── pallet_aura ────────────────────────────────────────────────────────────

impl pallet_aura::Config for Runtime {
	type Moment = u64;
	type Time = Timestamp;
	type AuthorityId = AuraId;
	type DisabledValidators = ();
	type MaxAuthorities = ConstU32<32>;
	type AllowMultipleBlocksPerSlot = ConstBool<false>;
	type SlotDuration = ConstU64<SLOT_DURATION>;
}

// ─── pallet_session ─────────────────────────────────────────────────────────
// Required as a supertrait of `pallet_grandpa::Config` in this tree. NOT used
// for validator rotation in dev solochain — Period/Offset are nominal, the
// SessionManager is unit (existing validators stay forever).

parameter_types! {
	pub const SessionPeriod: BlockNumber = u32::MAX;
	pub const SessionOffset: BlockNumber = 0;
}

impl pallet_session::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type ValidatorId = AccountId;
	type ValidatorIdOf = ConvertInto;
	type ShouldEndSession = pallet_session::PeriodicSessions<SessionPeriod, SessionOffset>;
	type NextSessionRotation = pallet_session::PeriodicSessions<SessionPeriod, SessionOffset>;
	type SessionManager = ();
	type SessionHandler = <opaque::SessionKeys as sp_runtime::traits::OpaqueKeys>::KeyTypeIdProviders;
	type Keys = opaque::SessionKeys;
	type DisablingStrategy = ();
	type Currency = Balances;
	type KeyDeposit = ConstU128<{ ROSTO / 10 }>;
	type WeightInfo = ();
}

// ─── pallet_grandpa ─────────────────────────────────────────────────────────

impl pallet_grandpa::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type WeightInfo = ();
	type MaxAuthorities = ConstU32<32>;
	type MaxNominators = ConstU32<0>;
	type MaxSetIdSessionEntries = ConstU64<0>;
	type KeyOwnerProof = sp_core::Void;
	type EquivocationReportSystem = ();
}

// ─── pallet_authorship ──────────────────────────────────────────────────────

/// Maps Aura's slot-author index back to an `AccountId`. With pallet_session
/// absent, we look up the current `Aura::Authorities` list and decode the
/// raw 32-byte sr25519 key as an `AccountId32`.
pub struct AuraAuthorAdapter;
impl FindAuthor<AccountId> for AuraAuthorAdapter {
	fn find_author<'a, I>(digests: I) -> Option<AccountId>
	where
		I: 'a + IntoIterator<Item = (ConsensusEngineId, &'a [u8])>,
	{
		let index = pallet_aura::Pallet::<Runtime>::find_author(digests)?;
		let authorities = pallet_aura::Authorities::<Runtime>::get();
		let aura_id = authorities.get(index as usize)?.clone();
		let raw: [u8; 32] = aura_id.into_inner().0;
		Some(AccountId::new(raw))
	}
}

impl pallet_authorship::Config for Runtime {
	type FindAuthor = AuraAuthorAdapter;
	type EventHandler = ();
}

// ─── pallet_balances ────────────────────────────────────────────────────────

impl pallet_balances::Config for Runtime {
	type MaxLocks = ConstU32<50>;
	type MaxReserves = ();
	type ReserveIdentifier = [u8; 8];
	type Balance = Balance;
	type RuntimeEvent = RuntimeEvent;
	type DustRemoval = ();
	type ExistentialDeposit = ConstU128<EXISTENTIAL_DEPOSIT>;
	type AccountStore = System;
	type WeightInfo = pallet_balances::weights::SubstrateWeight<Runtime>;
	type FreezeIdentifier = RuntimeFreezeReason;
	type MaxFreezes = VariantCountOf<RuntimeFreezeReason>;
	type RuntimeHoldReason = RuntimeHoldReason;
	type RuntimeFreezeReason = RuntimeFreezeReason;
	type DoneSlashHandler = ();
}

// ─── pallet_transaction_payment ─────────────────────────────────────────────

parameter_types! {
	pub FeeMultiplier: Multiplier = Multiplier::from_u32(1);
}

impl pallet_transaction_payment::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	// Fees are deducted from the sender and dropped (no treasury wired in
	// Phase 1; spec explicitly defers economic distribution).
	type OnChargeTransaction = FungibleAdapter<Balances, ()>;
	type OperationalFeeMultiplier = ConstU8<5>;
	type WeightToFee = IdentityFee<Balance>;
	type LengthToFee = IdentityFee<Balance>;
	type FeeMultiplierUpdate = ConstFeeMultiplier<FeeMultiplier>;
	type WeightInfo = pallet_transaction_payment::weights::SubstrateWeight<Runtime>;
}

// ─── pallet_sudo ────────────────────────────────────────────────────────────

impl pallet_sudo::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type RuntimeCall = RuntimeCall;
	type WeightInfo = pallet_sudo::weights::SubstrateWeight<Runtime>;
}

// ─── pallet_multisig ────────────────────────────────────────────────────────

parameter_types! {
	// One ROS as the base deposit; per-signatory slot is a tenth of that.
	pub const MultisigDepositBase: Balance = ROSTO;
	pub const MultisigDepositFactor: Balance = ROSTO / 10;
}

impl pallet_multisig::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type RuntimeCall = RuntimeCall;
	type Currency = Balances;
	type DepositBase = MultisigDepositBase;
	type DepositFactor = MultisigDepositFactor;
	type MaxSignatories = ConstU32<100>;
	type WeightInfo = pallet_multisig::weights::SubstrateWeight<Runtime>;
	type BlockNumberProvider = System;
}

// ─── pallet_proxy ───────────────────────────────────────────────────────────

#[derive(
	Copy,
	Clone,
	Eq,
	PartialEq,
	Ord,
	PartialOrd,
	Encode,
	Decode,
	DecodeWithMemTracking,
	MaxEncodedLen,
	TypeInfo,
	Debug,
)]
pub enum ProxyType {
	Any,
	NonTransfer,
}

impl Default for ProxyType {
	fn default() -> Self {
		Self::Any
	}
}

impl InstanceFilter<RuntimeCall> for ProxyType {
	fn filter(&self, c: &RuntimeCall) -> bool {
		match self {
			ProxyType::Any => true,
			ProxyType::NonTransfer => !matches!(
				c,
				RuntimeCall::Balances(..)
			),
		}
	}

	fn is_superset(&self, other: &Self) -> bool {
		match (self, other) {
			(x, y) if x == y => true,
			(ProxyType::Any, _) => true,
			_ => false,
		}
	}
}

parameter_types! {
	pub const ProxyDepositBase: Balance = ROSTO;
	pub const ProxyDepositFactor: Balance = ROSTO / 100;
	pub const AnnouncementDepositBase: Balance = ROSTO;
	pub const AnnouncementDepositFactor: Balance = ROSTO / 100;
}

impl pallet_proxy::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type RuntimeCall = RuntimeCall;
	type Currency = Balances;
	type ProxyType = ProxyType;
	type ProxyDepositBase = ProxyDepositBase;
	type ProxyDepositFactor = ProxyDepositFactor;
	type MaxProxies = ConstU32<32>;
	type MaxPending = ConstU32<32>;
	type CallHasher = sp_runtime::traits::BlakeTwo256;
	type AnnouncementDepositBase = AnnouncementDepositBase;
	type AnnouncementDepositFactor = AnnouncementDepositFactor;
	type WeightInfo = pallet_proxy::weights::SubstrateWeight<Runtime>;
	type BlockNumberProvider = System;
}

// ─── pallet_utility ─────────────────────────────────────────────────────────

impl pallet_utility::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type RuntimeCall = RuntimeCall;
	type PalletsOrigin = OriginCaller;
	type WeightInfo = pallet_utility::weights::SubstrateWeight<Runtime>;
}

// ─── pallet_proof_verifier ──────────────────────────────────────────────────

impl pallet_proof_verifier::Config for Runtime {
	type RegistrarOrigin = frame_system::EnsureRoot<AccountId>;
	type WeightInfo = ();
}

// ─── pallet_rostro_type_registry ────────────────────────────────────────────

impl pallet_rostro_type_registry::Config for Runtime {
	// TODO(srt): retarget at `pallet-rostro-security-response-team` when it lands.
	type SecurityResponseTeamOrigin = frame_system::EnsureRoot<AccountId>;
}

// ─── pallet_rostro_proof_anchor ─────────────────────────────────────────────

impl pallet_rostro_proof_anchor::Config for Runtime {}

// ───────────────────────────────────────────────────────────────────────────
//                              RNS
// ───────────────────────────────────────────────────────────────────────────
//
// Wiring for the Rostro Name Service. Modeled on paseo-node's working PNS
// runtime (its older Config trait surface) and extended for the LeanPNS
// additions: RuntimeHoldReason / Fungible (deposit holds), OfferWindow,
// PnsCustodian, BlockAuthor, SecurityResponseTeamOrigin.

use rns_types::DomainHash;
use frame_support::traits::Get;

const DAYS_MS: u64 = 24 * 60 * 60 * 1000;

parameter_types! {
	pub const RnsBaseNode: DomainHash = rns_types::RST_BASENODE;
	pub const RnsGracePeriod: u64 = 30 * DAYS_MS;
	pub const RnsOfferWindow: u64 = 90 * DAYS_MS;
	pub const RnsDefaultCapacity: u32 = 100;
	pub const RnsMinRegistrationDuration: u64 = 28 * DAYS_MS;
	pub const RnsMaxRegistrationDuration: u64 = 365 * DAYS_MS;
	pub const RnsMaxContentLen: u32 = 1024;
	pub const RnsListingDeposit: Balance = 10 * ROSTO;
	pub const RnsListingGracePeriod: u64 = 7 * DAYS_MS;
	pub PnsCustodianAccount: AccountId = AccountId::new([0u8; 32]);
}

/// `EnsureRoot`-equivalent that satisfies `Success = AccountId`.
/// Returns the all-zero address; the caller is still gated behind Root.
pub struct EnsureRootAsAccountId;
impl frame_support::traits::EnsureOrigin<RuntimeOrigin> for EnsureRootAsAccountId {
	type Success = AccountId;

	fn try_origin(o: RuntimeOrigin) -> Result<Self::Success, RuntimeOrigin> {
		frame_system::EnsureRoot::<AccountId>::try_origin(o).map(|_| AccountId::new([0u8; 32]))
	}

	#[cfg(feature = "runtime-benchmarks")]
	fn try_successful_origin() -> Result<RuntimeOrigin, ()> {
		Ok(frame_system::RawOrigin::Root.into())
	}
}

pub struct RnsIsOpen;
impl pallet_rns_registrar::traits::IsRegistrarOpen for RnsIsOpen {
	fn is_open() -> bool {
		true
	}
}

pub struct RnsSs58Updater;
impl pallet_rns_registrar::traits::Ss58Updater for RnsSs58Updater {
	type AccountId = AccountId;
	fn update_ss58(node: DomainHash, owner: &AccountId) -> sp_runtime::DispatchResult {
		pallet_rns_resolvers::resolvers::Pallet::<Runtime>::set_ss58_record(node, owner)
	}
}

pub struct RnsOriginRecorder;
impl pallet_rns_registrar::traits::OriginRecorder for RnsOriginRecorder {
	fn record_origin(node: DomainHash, block_hash: [u8; 32]) -> sp_runtime::DispatchResult {
		pallet_rns_resolvers::resolvers::Pallet::<Runtime>::set_origin_record(node, block_hash)
	}
}

pub struct RnsRecordCleaner;
impl pallet_rns_registrar::traits::RecordCleaner for RnsRecordCleaner {
	fn clear_records_except_ss58(node: DomainHash) {
		pallet_rns_resolvers::resolvers::Pallet::<Runtime>::clear_records_except_ss58(node)
	}
	fn clear_all_records(node: DomainHash) {
		pallet_rns_resolvers::resolvers::Pallet::<Runtime>::clear_all_records(node)
	}
}

pub struct RnsBlockAuthor;
impl pallet_rns_registrar::traits::BlockAuthor for RnsBlockAuthor {
	type AccountId = AccountId;
	fn author() -> Option<Self::AccountId> {
		pallet_authorship::Pallet::<Runtime>::author()
	}
}

pub struct RnsRegistryChecker;
impl pallet_rns_resolvers::resolvers::RegistryChecker for RnsRegistryChecker {
	type AccountId = AccountId;
	fn check_node_useable(node: DomainHash, owner: &AccountId) -> bool {
		use pallet_rns_registrar::traits::Registrar as _;
		if pallet_rns_registrar::registry::Pallet::<Runtime>::verify(owner, node).is_err() {
			return false;
		}
		pallet_rns_registrar::registrar::Pallet::<Runtime>::get_info(node)
			.map(|_| {
				<pallet_rns_registrar::registrar::Pallet<Runtime> as pallet_rns_registrar::traits::Registrar>::check_expires_useable(node).is_ok()
			})
			.unwrap_or(true)
	}
	fn base_node() -> DomainHash {
		<RnsBaseNode as Get<DomainHash>>::get()
	}
}

// rns-registrar's NFT sub-pallet: tracks domain ownership.
impl pallet_rns_registrar::nft::Config for Runtime {
	type ClassId = u32;
	type TotalId = u128;
	type TokenId = DomainHash;
	type ClassData = ();
	type TokenData = rns_types::Record;
	type MaxClassMetadata = ConstU32<0>;
	type MaxTokenMetadata = ConstU32<0>;
}

// rns-registrar's price oracle sub-pallet: governance-managed pricing curve.
impl pallet_rns_registrar::price_oracle::Config for Runtime {
	type Currency = Balances;
	type Moment = u64;
	type ExchangeRate = pallet_rns_registrar::price_oracle::Pallet<Runtime>;
	type WeightInfo = ();
	type ManagerOrigin = EnsureRootAsAccountId;
}

// rns-registrar's registry sub-pallet: NFT-backed name ownership.
impl pallet_rns_registrar::registry::Config for Runtime {
	type WeightInfo = ();
	type Registrar = pallet_rns_registrar::registrar::Pallet<Runtime>;
	type ManagerOrigin = EnsureRootAsAccountId;
	type Ss58Updater = RnsSs58Updater;
	type RecordCleaner = RnsRecordCleaner;
	type OriginRecorder = RnsOriginRecorder;
}

// rns-registrar's main registrar sub-pallet: register/renew/transfer/subdomain.
impl pallet_rns_registrar::registrar::Config for Runtime {
	type Registry = pallet_rns_registrar::registry::Pallet<Runtime>;
	type Currency = Balances;
	type RuntimeHoldReason = RuntimeHoldReason;
	type Fungible = Balances;
	type NowProvider = Timestamp;
	type Moment = u64;
	type GracePeriod = RnsGracePeriod;
	type DefaultCapacity = RnsDefaultCapacity;
	type BaseNode = RnsBaseNode;
	type MinRegistrationDuration = RnsMinRegistrationDuration;
	type MaxRegistrationDuration = RnsMaxRegistrationDuration;
	type OfferWindow = RnsOfferWindow;
	type WeightInfo = ();
	type PriceOracle = pallet_rns_registrar::price_oracle::Pallet<Runtime>;
	type ManagerOrigin = EnsureRootAsAccountId;
	// TODO(srt): retarget at `pallet-rostro-security-response-team`
	type SecurityResponseTeamOrigin = frame_system::EnsureRoot<AccountId>;
	type PnsCustodian = PnsCustodianAccount;
	type BlockAuthor = RnsBlockAuthor;
	type IsOpen = RnsIsOpen;
	type Official = pallet_rns_registrar::registry::Pallet<Runtime>;
	type Ss58Updater = RnsSs58Updater;
	type OriginRecorder = RnsOriginRecorder;
	type RecordCleaner = RnsRecordCleaner;
}

impl pallet_rns_resolvers::resolvers::Config for Runtime {
	const OFFCHAIN_PREFIX: &'static [u8] = b"rns/";
	type WeightInfo = ();
	type MaxContentLen = RnsMaxContentLen;
	type RegistryChecker = RnsRegistryChecker;
}

impl pallet_rns_marketplace::Config for Runtime {
	type Currency = Balances;
	type RuntimeHoldReason = RuntimeHoldReason;
	type Fungible = Balances;
	type ListingDeposit = RnsListingDeposit;
	type ListingGracePeriod = RnsListingGracePeriod;
	type Moment = u64;
	type NowProvider = Timestamp;
	type NameRegistry = pallet_rns_registrar::registrar::Pallet<Runtime>;
	type Ss58Updater = RnsSs58Updater;
	type RecordCleaner = RnsRecordCleaner;
	type OriginRecorder = RnsOriginRecorder;
	type BaseNode = RnsBaseNode;
	type WeightInfo = ();
}
