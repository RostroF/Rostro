// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # Gemini Runtime — Phase Ring R3.2/R3.3
//!
//! Sassafras-flavoured Rostro testbed. Strips the rostro-runtime down
//! to the minimum needed to prove the Sassafras consensus mechanism
//! end-to-end on twin-node bringup; once that lands (R3.6) and the
//! twin-node test verifies block production + finalization, this
//! runtime is the basis for retiring Aura from the production rostro
//! runtime (R4).
//!
//! ## Pallet set
//!
//! Mandatory:
//!   - `frame_system`
//!   - `pallet_timestamp`
//!   - `pallet_sassafras` — block production
//!   - `pallet_grandpa` — finality
//!   - `pallet_balances` + `pallet_transaction_payment` — for any
//!     extrinsic submission to work
//!   - `pallet_sudo` — privileged ops on the testbed
//!   - `pallet_authorship` — identifies the block author
//!   - `pallet_session` — supertrait of `pallet_grandpa::Config` in
//!     this tree, even though we don't use periodic rotation in the
//!     dev solochain shape
//!
//! Deferred to follow-up commits: RNS family, ProofVerifier,
//! RostroProofAnchor, RostroTypeRegistry, Multisig, Proxy, Utility.
//! Each can be ported from rostro-runtime when needed; the
//! configuration shape doesn't change.
//!
//! ## URS at v1
//!
//! `pallet-sassafras` is built with the `construct-dummy-ring-context`
//! feature, so genesis populates `RingContext` with
//! `RingProofParams::from_seed(R, [0; 32])` — a deterministic dummy
//! that's NOT cryptographically secure (the trapdoor is the zero
//! seed). This is for testbed bringup only; production gemini should
//! replace it with the real EIP-4844-derived URS via
//! `rostro_kzg_srs::build_ring_context_bytes_for_genesis` once R3.6
//! validates the consensus mechanism end-to-end. **Do not deploy the
//! dummy URS to a chain that has any economic value.**

#![cfg_attr(not(feature = "std"), no_std)]
#![recursion_limit = "256"]

#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

extern crate alloc;

use alloc::{borrow::Cow, vec, vec::Vec};
use codec::Encode;
use sp_api::impl_runtime_apis;
use sp_core::{crypto::KeyTypeId, OpaqueMetadata};
use sp_runtime::{
	generic, impl_opaque_keys,
	traits::{
		BlakeTwo256, Block as BlockT, ConvertInto, IdentifyAccount, NumberFor, Verify,
	},
	transaction_validity::{TransactionSource, TransactionValidity},
	ApplyExtrinsicResult, MultiSignature,
};
#[cfg(feature = "std")]
use sp_version::NativeVersion;
use sp_version::RuntimeVersion;

pub use frame_support::{
	construct_runtime, derive_impl, parameter_types,
	traits::{
		ConstBool, ConstU128, ConstU32, ConstU64, ConstU8, FindAuthor, KeyOwnerProofSystem,
		Randomness, VariantCountOf,
	},
	weights::{
		constants::{RocksDbWeight, WEIGHT_REF_TIME_PER_SECOND},
		IdentityFee, Weight,
	},
	StorageValue,
};
pub use frame_system::Call as SystemCall;
pub use pallet_balances::Call as BalancesCall;
pub use pallet_timestamp::Call as TimestampCall;
pub use sp_runtime::{Perbill, Permill};

// ─── Type aliases ───────────────────────────────────────────────────────────

pub type Signature = MultiSignature;
pub type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;
pub type Nonce = u32;
pub type Balance = u128;
pub type BlockNumber = u32;
pub type Hash = sp_core::H256;
pub type Address = sp_runtime::MultiAddress<AccountId, ()>;
pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
pub type Block = generic::Block<Header, UncheckedExtrinsic>;
pub type SignedBlock = generic::SignedBlock<Block>;
pub type BlockId = generic::BlockId<Block>;

pub type SignedExtra = (
	frame_system::CheckNonZeroSender<Runtime>,
	frame_system::CheckSpecVersion<Runtime>,
	frame_system::CheckTxVersion<Runtime>,
	frame_system::CheckGenesis<Runtime>,
	frame_system::CheckEra<Runtime>,
	frame_system::CheckNonce<Runtime>,
	frame_system::CheckWeight<Runtime>,
	pallet_transaction_payment::ChargeTransactionPayment<Runtime>,
	frame_metadata_hash_extension::CheckMetadataHash<Runtime>,
);

pub type UncheckedExtrinsic =
	generic::UncheckedExtrinsic<Address, RuntimeCall, Signature, SignedExtra>;
pub type CheckedExtrinsic = generic::CheckedExtrinsic<AccountId, RuntimeCall, SignedExtra>;

pub type Executive = frame_executive::Executive<
	Runtime,
	Block,
	frame_system::ChainContext<Runtime>,
	Runtime,
	AllPalletsWithSystem,
>;

// ─── Opaque types (CLI / node service) ──────────────────────────────────────

pub mod opaque {
	use super::*;

	pub use sp_runtime::OpaqueExtrinsic as UncheckedExtrinsic;

	pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
	pub type Block = generic::Block<Header, UncheckedExtrinsic>;
	pub type BlockId = generic::BlockId<Block>;

	// pallet-sassafras manages its own authority rotation via
	// EpochChangeInternalTrigger and doesn't implement
	// OneSessionHandler, so we don't register a sassafras key with
	// pallet-session. Bandersnatch authorities are set at genesis;
	// rotating them is its own follow-up (would require either a
	// session-historical integration or a custom rotation extrinsic).
	// Grandpa keys still flow through session because pallet-grandpa
	// requires the supertrait.
	impl_opaque_keys! {
		pub struct SessionKeys {
			pub grandpa: Grandpa,
		}
	}
}

// ─── ROST denominations ────────────────────────────────────────────────────

pub const ROSTO: Balance = 1_000_000_000_000;
pub const MILLI_ROS: Balance = ROSTO / 1_000;
pub const EXISTENTIAL_DEPOSIT: Balance = MILLI_ROS;

// ─── Block timing ──────────────────────────────────────────────────────────

/// 6-second slot — matches rostro-runtime's spec.
pub const MILLISECS_PER_BLOCK: u64 = 6_000;
pub const SLOT_DURATION: u64 = MILLISECS_PER_BLOCK;
pub const MINUTES: BlockNumber = 60_000 / (MILLISECS_PER_BLOCK as BlockNumber);
pub const HOURS: BlockNumber = MINUTES * 60;

/// Sassafras epoch length in slots. 600 slots × 6s = 60 minutes.
pub const EPOCH_LENGTH_IN_SLOTS: u32 = 600;

// ─── Runtime version ───────────────────────────────────────────────────────

#[sp_version::runtime_version]
pub const VERSION: RuntimeVersion = RuntimeVersion {
	spec_name: Cow::Borrowed("gemini"),
	impl_name: Cow::Borrowed("gemini-runtime"),
	authoring_version: 1,
	spec_version: 100,
	impl_version: 1,
	apis: RUNTIME_API_VERSIONS,
	transaction_version: 1,
	system_version: 1,
};

#[cfg(feature = "std")]
pub fn native_version() -> NativeVersion {
	NativeVersion { runtime_version: VERSION, can_author_with: Default::default() }
}

// ─── frame_system ──────────────────────────────────────────────────────────

parameter_types! {
	pub const BlockHashCount: BlockNumber = 2400;
	pub const Version: RuntimeVersion = VERSION;
	pub const SS58Prefix: u8 = 42;
}

#[derive_impl(frame_system::config_preludes::SolochainDefaultConfig)]
impl frame_system::Config for Runtime {
	type Block = Block;
	type BlockHashCount = BlockHashCount;
	type DbWeight = RocksDbWeight;
	type Version = Version;
	type AccountData = pallet_balances::AccountData<Balance>;
	type SS58Prefix = SS58Prefix;
	type MaxConsumers = ConstU32<16>;
}

// pallet-sassafras uses unsigned extrinsics for ticket + equivocation
// submission. The pallet's CreateBare bound requires the runtime to
// expose how to construct an unsigned extrinsic carrying a Call.
impl<C> frame_system::offchain::CreateTransactionBase<C> for Runtime
where
	RuntimeCall: From<C>,
{
	type RuntimeCall = RuntimeCall;
	type Extrinsic = UncheckedExtrinsic;
}

impl<C> frame_system::offchain::CreateBare<C> for Runtime
where
	RuntimeCall: From<C>,
{
	fn create_bare(call: Self::RuntimeCall) -> Self::Extrinsic {
		UncheckedExtrinsic::new_bare(call)
	}
}

// ─── pallet_timestamp ──────────────────────────────────────────────────────

impl pallet_timestamp::Config for Runtime {
	type Moment = u64;
	type OnTimestampSet = ();
	type MinimumPeriod = ConstU64<{ SLOT_DURATION / 2 }>;
	type WeightInfo = ();
}

// ─── pallet_sassafras ──────────────────────────────────────────────────────

impl pallet_sassafras::Config for Runtime {
	type EpochLength = ConstU32<EPOCH_LENGTH_IN_SLOTS>;
	type MaxAuthorities = ConstU32<32>;
	type EpochChangeTrigger = pallet_sassafras::EpochChangeInternalTrigger;
	type WeightInfo = ();
}

// ─── pallet_session ────────────────────────────────────────────────────────
// Required as `pallet_grandpa::Config` supertrait. No periodic rotation —
// the validator set is fixed for the testbed lifetime.

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

// ─── pallet_grandpa ────────────────────────────────────────────────────────

impl pallet_grandpa::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type WeightInfo = ();
	type MaxAuthorities = ConstU32<32>;
	type MaxNominators = ConstU32<0>;
	type MaxSetIdSessionEntries = ConstU64<0>;
	type KeyOwnerProof = sp_core::Void;
	type EquivocationReportSystem = ();
}

// ─── pallet_authorship ─────────────────────────────────────────────────────
// FindAuthor reads the current SlotClaim's authority_idx from the digest log
// and looks up that index in pallet_sassafras::Authorities.

pub struct SassafrasAuthorAdapter;
impl FindAuthor<AccountId> for SassafrasAuthorAdapter {
	fn find_author<'a, I>(digests: I) -> Option<AccountId>
	where
		I: 'a + IntoIterator<Item = (sp_runtime::ConsensusEngineId, &'a [u8])>,
	{
		use codec::Decode;
		use sp_consensus_sassafras::{digests::SlotClaim, SASSAFRAS_ENGINE_ID};

		for (engine_id, mut data) in digests {
			if engine_id == SASSAFRAS_ENGINE_ID {
				if let Ok(claim) = SlotClaim::decode(&mut data) {
					let authorities = pallet_sassafras::Authorities::<Runtime>::get();
					let id = authorities.get(claim.authority_idx as usize)?.clone();
					// AuthorityId wraps bandersnatch::Public(Vec/[u8;33] internally).
					// We surface the first 32 bytes as the AccountId — same pattern
					// rostro-runtime uses for AuraAuthorAdapter, just sourced from a
					// different authority type.
					let raw: [u8; 32] = id.encode().get(..32)?.try_into().ok()?;
					return Some(AccountId::new(raw));
				}
			}
		}
		None
	}
}

impl pallet_authorship::Config for Runtime {
	type FindAuthor = SassafrasAuthorAdapter;
	type EventHandler = ();
}

// ─── pallet_balances ───────────────────────────────────────────────────────

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

// ─── pallet_transaction_payment ────────────────────────────────────────────

parameter_types! {
	pub FeeMultiplier: pallet_transaction_payment::Multiplier =
		pallet_transaction_payment::Multiplier::from_u32(1);
}

impl pallet_transaction_payment::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type OnChargeTransaction = pallet_transaction_payment::FungibleAdapter<Balances, ()>;
	type OperationalFeeMultiplier = ConstU8<5>;
	type WeightToFee = IdentityFee<Balance>;
	type LengthToFee = IdentityFee<Balance>;
	type FeeMultiplierUpdate = pallet_transaction_payment::ConstFeeMultiplier<FeeMultiplier>;
	type WeightInfo = pallet_transaction_payment::weights::SubstrateWeight<Runtime>;
}

// ─── pallet_sudo ───────────────────────────────────────────────────────────

impl pallet_sudo::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type RuntimeCall = RuntimeCall;
	type WeightInfo = pallet_sudo::weights::SubstrateWeight<Runtime>;
}

// ─── pallet_rostro_rpc_method_policy ───────────────────────────────────────
//
// On-chain registry consumed by `rostro-rpc-shield` to know which RPC
// methods to admit / gate / refuse. Origin stubbed at `EnsureRoot` until
// `pallet-rostro-security-response-team` (prelaunch item) lands.

impl pallet_rostro_rpc_method_policy::Config for Runtime {
	type SecurityResponseTeamOrigin = frame_system::EnsureRoot<AccountId>;
}

// ─── pallet_rostro_canonical_files ─────────────────────────────────────────
//
// On-chain registry of canonical foundation-file hashes. Native node
// verifier reads at boot, fail-stops on mismatch (Phase 7a). Origin
// stubbed at `EnsureRoot` until SRT lands.

impl pallet_rostro_canonical_files::Config for Runtime {
	type SecurityResponseTeamOrigin = frame_system::EnsureRoot<AccountId>;
}

// ─── construct_runtime ─────────────────────────────────────────────────────

construct_runtime!(
	pub enum Runtime {
		// System
		System: frame_system,
		Timestamp: pallet_timestamp,
		Sudo: pallet_sudo,

		// Consensus — Sassafras (block production) + GRANDPA (finality)
		Sassafras: pallet_sassafras,
		Grandpa: pallet_grandpa,
		Authorship: pallet_authorship,
		Session: pallet_session,

		// Economic
		Balances: pallet_balances,
		TransactionPayment: pallet_transaction_payment,

		// Operational — on-chain RPC method access policy registry,
		// consumed by the native rostro-rpc-shield middleware.
		RpcMethodPolicy: pallet_rostro_rpc_method_policy,

		// Operational — on-chain registry of canonical foundation
		// file hashes; native verifier reads at boot.
		CanonicalFiles: pallet_rostro_canonical_files,
	}
);

// ─── Re-exports for downstream code ────────────────────────────────────────

pub use pallet_grandpa::AuthorityId as GrandpaId;
pub use sp_consensus_sassafras::AuthorityId as SassafrasId;

// ─── Runtime APIs ──────────────────────────────────────────────────────────

impl_runtime_apis! {
	impl sp_api::Core<Block> for Runtime {
		fn version() -> RuntimeVersion {
			VERSION
		}

		fn execute_block(block: <Block as BlockT>::LazyBlock) {
			Executive::execute_block(block.into());
		}

		fn initialize_block(header: &<Block as BlockT>::Header) -> sp_runtime::ExtrinsicInclusionMode {
			Executive::initialize_block(header)
		}
	}

	impl sp_api::Metadata<Block> for Runtime {
		fn metadata() -> OpaqueMetadata {
			OpaqueMetadata::new(Runtime::metadata().into())
		}

		fn metadata_at_version(version: u32) -> Option<OpaqueMetadata> {
			Runtime::metadata_at_version(version)
		}

		fn metadata_versions() -> Vec<u32> {
			Runtime::metadata_versions()
		}
	}

	impl sp_block_builder::BlockBuilder<Block> for Runtime {
		fn apply_extrinsic(extrinsic: <Block as BlockT>::Extrinsic) -> ApplyExtrinsicResult {
			Executive::apply_extrinsic(extrinsic)
		}

		fn finalize_block() -> <Block as BlockT>::Header {
			Executive::finalize_block()
		}

		fn inherent_extrinsics(data: sp_inherents::InherentData) -> Vec<<Block as BlockT>::Extrinsic> {
			data.create_extrinsics()
		}

		fn check_inherents(
			block: <Block as BlockT>::LazyBlock,
			data: sp_inherents::InherentData,
		) -> sp_inherents::CheckInherentsResult {
			data.check_extrinsics(&block.into())
		}
	}

	impl sp_transaction_pool::runtime_api::TaggedTransactionQueue<Block> for Runtime {
		fn validate_transaction(
			source: TransactionSource,
			tx: <Block as BlockT>::Extrinsic,
			block_hash: <Block as BlockT>::Hash,
		) -> TransactionValidity {
			Executive::validate_transaction(source, tx, block_hash)
		}
	}

	impl sp_offchain::OffchainWorkerApi<Block> for Runtime {
		fn offchain_worker(header: &<Block as BlockT>::Header) {
			Executive::offchain_worker(header)
		}
	}

	// Sassafras consensus runtime API — the load-bearing piece for
	// rostro-consensus-sassafras's ClientProviders to bind against.
	//
	// Earlier commits hardened ring_context() and
	// submit_tickets_unsigned_extrinsic() at the runtime level (Phase 5):
	// they returned None / false to block F-NEW-2 + F-NEW-1 vectors. With
	// Phase 6.1 the rostro-rpc-shield now reads the on-chain
	// `pallet-rostro-rpc-method-policy` registry which classifies both
	// methods as Deny — external state_call is rejected at the RPC
	// middleware, before the runtime sees the call. The runtime stubs
	// were redundant defense-in-depth that broke the LEGITIMATE
	// offchain-context callers (ticket generation worker reads
	// ring_context to build RingProver; the worker submits tickets via
	// submit_tickets_unsigned_extrinsic). Reverted to upstream behaviour
	// as part of Phase Ring R3.5 to unblock the offchain ticket worker.
	// External callers remain shut out by the shield.
	impl sp_consensus_sassafras::SassafrasApi<Block> for Runtime {
		fn ring_context() -> Option<sp_consensus_sassafras::vrf::RingContext> {
			pallet_sassafras::RingContext::<Runtime>::get()
		}

		fn submit_tickets_unsigned_extrinsic(
			tickets: Vec<sp_consensus_sassafras::TicketEnvelope>,
		) -> bool {
			Sassafras::submit_tickets_unsigned_extrinsic(tickets)
		}

		fn slot_ticket_id(slot: sp_consensus_sassafras::Slot) -> Option<sp_consensus_sassafras::TicketId> {
			Sassafras::slot_ticket_id(slot)
		}

		fn slot_ticket(
			slot: sp_consensus_sassafras::Slot,
		) -> Option<(sp_consensus_sassafras::TicketId, sp_consensus_sassafras::TicketBody)> {
			Sassafras::slot_ticket(slot)
		}

		fn current_epoch() -> sp_consensus_sassafras::Epoch {
			Sassafras::current_epoch()
		}

		fn next_epoch() -> sp_consensus_sassafras::Epoch {
			Sassafras::next_epoch()
		}

		fn generate_key_ownership_proof(
			_authority_id: sp_consensus_sassafras::AuthorityId,
		) -> Option<sp_consensus_sassafras::OpaqueKeyOwnershipProof> {
			// No session-historical infrastructure in the v1 testbed runtime.
			// Equivocation reporting is structurally available via the
			// trait, but production reporting requires session-historical
			// proof generation that's its own follow-up commit.
			None
		}

		fn submit_report_equivocation_unsigned_extrinsic(
			_equivocation_proof: sp_consensus_sassafras::EquivocationProof<<Block as BlockT>::Header>,
			_key_owner_proof: sp_consensus_sassafras::OpaqueKeyOwnershipProof,
		) -> bool {
			// Same as above — wired to a stub until session-historical
			// infrastructure lands. Returning false signals "report
			// dropped" to the off-chain reporter.
			false
		}
	}

	impl sp_session::SessionKeys<Block> for Runtime {
		fn generate_session_keys(
			owner: Vec<u8>,
			seed: Option<Vec<u8>>,
		) -> sp_session::OpaqueGeneratedSessionKeys {
			opaque::SessionKeys::generate(&owner, seed).into()
		}

		fn decode_session_keys(encoded: Vec<u8>) -> Option<Vec<(Vec<u8>, KeyTypeId)>> {
			opaque::SessionKeys::decode_into_raw_public_keys(&encoded)
		}
	}

	impl sp_consensus_grandpa::GrandpaApi<Block> for Runtime {
		fn grandpa_authorities() -> sp_consensus_grandpa::AuthorityList {
			Grandpa::grandpa_authorities()
		}

		fn current_set_id() -> sp_consensus_grandpa::SetId {
			Grandpa::current_set_id()
		}

		fn submit_report_equivocation_unsigned_extrinsic(
			_equivocation_proof: sp_consensus_grandpa::EquivocationProof<
				<Block as BlockT>::Hash,
				NumberFor<Block>,
			>,
			_key_owner_proof: sp_consensus_grandpa::OpaqueKeyOwnershipProof,
		) -> Option<()> {
			None
		}

		fn generate_key_ownership_proof(
			_set_id: sp_consensus_grandpa::SetId,
			_authority_id: sp_consensus_grandpa::AuthorityId,
		) -> Option<sp_consensus_grandpa::OpaqueKeyOwnershipProof> {
			None
		}
	}

	impl frame_system_rpc_runtime_api::AccountNonceApi<Block, AccountId, Nonce> for Runtime {
		fn account_nonce(account: AccountId) -> Nonce {
			System::account_nonce(account)
		}
	}

	impl pallet_transaction_payment_rpc_runtime_api::TransactionPaymentApi<Block, Balance> for Runtime {
		fn query_info(
			uxt: <Block as BlockT>::Extrinsic,
			len: u32,
		) -> pallet_transaction_payment_rpc_runtime_api::RuntimeDispatchInfo<Balance> {
			TransactionPayment::query_info(uxt, len)
		}

		fn query_fee_details(
			uxt: <Block as BlockT>::Extrinsic,
			len: u32,
		) -> pallet_transaction_payment::FeeDetails<Balance> {
			TransactionPayment::query_fee_details(uxt, len)
		}

		fn query_weight_to_fee(weight: Weight) -> Balance {
			TransactionPayment::weight_to_fee(weight)
		}

		fn query_length_to_fee(length: u32) -> Balance {
			TransactionPayment::length_to_fee(length)
		}
	}

	impl sp_genesis_builder::GenesisBuilder<Block> for Runtime {
		fn build_state(config: Vec<u8>) -> sp_genesis_builder::Result {
			frame_support::genesis_builder_helper::build_state::<RuntimeGenesisConfig>(config)
		}

		fn get_preset(id: &Option<sp_genesis_builder::PresetId>) -> Option<Vec<u8>> {
			frame_support::genesis_builder_helper::get_preset::<RuntimeGenesisConfig>(id, |_| None)
		}

		fn preset_names() -> Vec<sp_genesis_builder::PresetId> {
			vec![]
		}
	}

	// On-chain RPC method-policy registry surface, queried by the
	// native `rostro-rpc-shield` middleware to bridge the native +
	// WASM trust domains. See `pallet-rostro-rpc-method-policy` for
	// the design rationale.
	impl pallet_rostro_rpc_method_policy::RpcMethodPolicyApi<Block> for Runtime {
		fn policy_for(method: Vec<u8>) -> Option<pallet_rostro_rpc_method_policy::MethodPolicy> {
			pallet_rostro_rpc_method_policy::Pallet::<Runtime>::policy_for(&method)
		}

		fn all_policies() -> Vec<(Vec<u8>, pallet_rostro_rpc_method_policy::MethodPolicy)> {
			pallet_rostro_rpc_method_policy::Pallet::<Runtime>::all_policies()
		}
	}

	// Canonical foundation-file registry surface, queried by the
	// native node-side verifier at boot. See
	// `pallet-rostro-canonical-files` for design rationale.
	impl pallet_rostro_canonical_files::CanonicalFilesApi<Block> for Runtime {
		fn hash_for(path: Vec<u8>) -> Option<[u8; 32]> {
			pallet_rostro_canonical_files::Pallet::<Runtime>::hash_for(&path)
		}

		fn all_files() -> Vec<(Vec<u8>, [u8; 32])> {
			pallet_rostro_canonical_files::Pallet::<Runtime>::all_files()
		}
	}
}

