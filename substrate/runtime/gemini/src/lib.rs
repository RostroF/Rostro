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

// Phase Star B8: declare a 512 KiB minimum stack to the polkavm linker.
// The polkavm-linker default is 8 KiB (`VM_MIN_PAGE_SIZE * 2`), which
// the typed `serde_json::from_slice::<RuntimeGenesisConfig>` path blows
// during `GenesisBuilder_build_state`. Same fix as rostro-runtime (B7);
// gated to PVM target only.
#[cfg(all(any(target_arch = "riscv32", target_arch = "riscv64"), target_feature = "e"))]
polkavm_derive::min_stack_size!(512 * 1024);

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
	ApplyExtrinsicResult,
};
use pallet_session::historical as pallet_session_historical;
use rostro_multi_key::{RostroSignature, RostroSigner};

mod keyring_signature;
pub use keyring_signature::KeyringSignature;
#[cfg(feature = "std")]
use sp_version::NativeVersion;
use sp_version::RuntimeVersion;

pub use frame_support::{
	construct_runtime, derive_impl, parameter_types,
	traits::{
		ConstBool, ConstU128, ConstU32, ConstU64, ConstU8, FindAuthor, Get, KeyOwnerProofSystem,
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

// Multi-scheme signature primitive — see `rostro-multi-key` crate docs.
// Sr25519 + Ed25519 + Ecdsa, all raw-pubkey-as-address (variant order +
// wire format mirror substrate's MultiSignature):
// Sr25519 raw-pubkey — byte-identical to Polkadot, so a DOT holder's
//   account is unchanged on Rostro (modulo SS58 prefix),
// Ed25519 source-matches Solana/Aptos/Sui/Cosmos/Ledger (raw pubkey),
// Ecdsa source-matches Ethereum (last-20 of keccak256(uncompressed)).
pub type Signature = RostroSignature;
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

// The extrinsic signature type is the keyring-aware wrapper, NOT the
// bare `Signature` alias: SCALE-identical on the wire, but `Checkable`
// consults the account keyring (docs/KEYRING.md) during verification.
pub type UncheckedExtrinsic =
	generic::UncheckedExtrinsic<Address, RuntimeCall, KeyringSignature, SignedExtra>;
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

	// Both consensus keys flow through pallet-session: sassafras
	// (bandersnatch, block production) rotates via its
	// OneSessionHandler + EpochChangeExternalTrigger — sessions ARE
	// sassafras epochs — and grandpa (finality) schedules its
	// authority-set change each session. The validator set behind
	// both is produced by pallet-staking's NPoS election, filtered
	// through KeyLineage.
	// The attestor secp256k1 key (Attestor pallet) also rides SessionKeys so it
	// rotates with the consensus keys and is vetted through the same set_keys
	// path (KeyLineage::note_set_keys sees the full bundle). The Attestor pallet
	// is its OneSessionHandler: each session it caches the validators' derived
	// Ethereum addresses as the attestor set. Adding a field is a SessionKeys
	// wire-format change (genesis-breaking, like the sassafras add at spec 106);
	// it lands via chain reset, not set_code.
	impl_opaque_keys! {
		pub struct SessionKeys {
			pub sassafras: Sassafras,
			pub grandpa: Grandpa,
			pub attestor: Attestor,
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
pub const DAYS: BlockNumber = HOURS * 24;

/// Sassafras epoch length in slots. 600 slots × 6s = 60 minutes.
/// Sessions are epoch-driven (`ShouldEndSession = Sassafras`), so this is
/// also the session length: the epoch arithmetic is slot-based and fixed
/// -length, exactly like BABE, which is why sessions must follow the epoch
/// clock rather than a block-counting `PeriodicSessions`.
#[cfg(not(feature = "lab-fast-lifecycle"))]
pub const EPOCH_LENGTH_IN_SLOTS: u32 = 600;

/// Scenario-only lifecycle compression (star proofs; see
/// scripts/star-scenarios/): 25-slot epochs make a session rotation — and
/// with it a staking era — observable in minutes instead of hours. NEVER
/// ship a lab-fast binary to the lab cluster or beyond: it changes
/// consensus timing without changing spec_version, so it would fork any
/// chain whose peers run the canonical build.
#[cfg(feature = "lab-fast-lifecycle")]
pub const EPOCH_LENGTH_IN_SLOTS: u32 = 25;

// ─── Runtime version ───────────────────────────────────────────────────────

// Bumped per forkless set_code upgrade — Substrate requires strict
// increase. 101 = first live upgrade (dev chain, 2026-07-02);
// 102 = first 3-node lab-cluster upgrade (2026-07-02);
// 103 = consensus-key lifecycle workstream 1 (session rotation,
// key lineage, offences; docs/CONSENSUS-KEY-LIFECYCLE.md);
// 104 = history anchor (dual-hash sealing of session-boundary
// headers under Keccak-512);
// 105 = pq-chat P3b prekey record home (PREKEY/SEAL typed
// records, RnsMaxContentLen 1024 -> 1536; docs/PQ-CHAT.md);
// 106 = NPoS: pallet-staking + onchain phragmen election drive
// the validator set; sassafras keys join SessionKeys and epochs
// become session-driven. Genesis-breaking (SessionKeys wire
// format + pallet reorder) — lands via chain reset, not set_code.
// 107 = KeyLineage::plan_next_set returns None on no-op sessions, so
// GRANDPA set_id stops bumping every session on a stable validator set.
// Root cause of a finality-wedge amplifier found on the NPoS VM farm
// (2026-07-13): pallet_session treats ANY Some(_) as changed=true, and
// this pallet planned every session for enforcement, so the authority
// set rotated every session even when membership was unchanged — turning
// any finality lag into a queued-set-change backlog / voter wedge.
// Proven: set_code across the fix is finality-clean at 2- and 5-validator
// scale; set_id then bumps ONLY on real membership changes. Ships via
// set_code (genesis-compatible).
// 108 = account keyring: revocable multi-key authority overlay
// (pallet-rostro-keyring + KeyringSignature stateful verify;
// docs/KEYRING.md), riding with the EcdsaP256 extrinsic-signing variant.
// Signed extrinsics wire-identical; pure set_code, no new host fns. (107
// belongs to the set_id fix on main; keyring took 108 to avoid a
// duplicate-107 collision.)
// 111 = attestor quorum: pallet-rostro-attestor + a secp256k1 ATTESTOR key
// added to SessionKeys, so a validator subset signs the zkpki RootOfRoots
// checkpoint for a foreign Ethereum contract to verify via ecrecover
// (docs/ATTESTOR-QUORUM.md). SessionKeys wire-format change =>
// GENESIS-BREAKING (like the sassafras add at 106); lands via chain reset,
// NOT set_code. Also carries ZkPkiApi v4 (signed_checkpoint / issuer_branch).
// 112 = ZkPkiApi v5: witness_branch(thumbprint) serves the customer's keccak
// leaf branch within an issuer's witness tree (RWA presentation Phase 3),
// completing signed_checkpoint -> issuer_branch -> witness_branch. Additive
// runtime-API method; pure set_code (no wire/genesis change).
//
// lab-fast-lifecycle keeps the SAME spec_version but cfg-gates
// BondingDuration (28→1) + the membership-epoch clock (block/25→block/
// 10000) for scenario runs. It shares the number by design — the two
// builds are never on one chain (operational "never mix lab-fast with a
// canonical cluster" rule), and sp_version::runtime_version needs a
// numeric literal so it cannot branch on the feature.
#[sp_version::runtime_version]
pub const VERSION: RuntimeVersion = RuntimeVersion {
	spec_name: Cow::Borrowed("gemini"),
	impl_name: Cow::Borrowed("gemini-runtime"),
	authoring_version: 1,
	spec_version: 112,
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
	// Epoch changes are session-driven: pallet-session ends a session
	// exactly when `should_end_epoch` fires (`ShouldEndSession =
	// Sassafras`) and the OneSessionHandler enacts the change with the
	// staking-elected authority set.
	type EpochChangeTrigger = pallet_sassafras::EpochChangeExternalTrigger;
	type WeightInfo = ();
}

// ─── pallet_session ────────────────────────────────────────────────────────
// Sessions are sassafras epochs (~1h): the epoch arithmetic is slot-based, so
// sassafras itself decides when sessions end (the BABE pattern). Each session
// the manager chain runs: staking plans the elected set at era boundaries,
// KeyLineage filters it (offence-disabled + deadline-missed excluded) and
// records key lineage, historical notes the key-ownership root. Session KEYS
// registered via `set_keys` activate at the next session boundary and GRANDPA
// schedules the authority-set change (set_id advances every session).
// KeyLineage vets every `set_keys` (a GRANDPA key is accepted exactly once in
// chain history) and enforces the forced-rotation deadline by excluding
// non-compliant validators from the next set.
// docs/CONSENSUS-KEY-LIFECYCLE.md, workstream 1 P0+P1.

impl pallet_session::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type ValidatorId = AccountId;
	type ValidatorIdOf = ConvertInto;
	type ShouldEndSession = Sassafras;
	type NextSessionRotation = Sassafras;
	type SessionManager = pallet_session::historical::NoteHistoricalRoot<Runtime, KeyLineage>;
	type SessionHandler = <opaque::SessionKeys as sp_runtime::traits::OpaqueKeys>::KeyTypeIdProviders;
	type Keys = opaque::SessionKeys;
	// In-session disabling for offenders (staking routes offence severity
	// here via its SessionInterface): disable up to 1/3 of the set, re-enable
	// when a worse offender needs the slot. The cross-session consequence
	// stays with KeyLineage (roster exclusion, heal on fresh key).
	type DisablingStrategy =
		pallet_session::disabling::UpToLimitWithReEnablingDisablingStrategy;
	type Currency = Balances;
	type KeyDeposit = ConstU128<{ ROSTO / 10 }>;
	type WeightInfo = ();
	type KeyProvenance = KeyLineage;
}

// Session-historical: stores a merkle root of each session's (validator,
// session-keys) mapping so equivocation key-ownership proofs stay checkable
// after the session that the offence occurred in has ended.
impl pallet_session::historical::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type FullIdentification = ();
	type FullIdentificationOf = UnitIdentificationOf;
}

/// Unit identification: no economic data to attach until NPoS staking lands.
pub struct UnitIdentificationOf;
impl sp_runtime::traits::Convert<AccountId, Option<()>> for UnitIdentificationOf {
	fn convert(_: AccountId) -> Option<()> {
		Some(())
	}
}

// ─── pallet_rostro_key_lineage ─────────────────────────────────────────────
// Permanent GRANDPA-key lineage + fresh-key primitive + forced-rotation
// deadline. As the inner session manager under `NoteHistoricalRoot` it
// re-feeds the (filtered) roster every session, so the historical trie root
// is regenerated from the keys actually active in that session — a rotated
// GRANDPA key stays provable for exactly the sessions it was live — and every
// session is marked `changed`, which is what makes GRANDPA schedule the
// authority-set change that activates rotated keys.

/// Era clock for key lineage: the zkpki 24h membership epoch, so "era" means
/// one thing chain-wide. Under `lab-fast-lifecycle` (star scenarios only)
/// the lineage era runs off a compressed 25-block clock instead, so the
/// K=7-era forced-rotation deadline is provable inside a scenario window;
/// the zkpki epoch itself is untouched (chat freshness keeps its real
/// clock).
pub struct MembershipEpochEra;
impl Get<u32> for MembershipEpochEra {
	fn get() -> u32 {
		#[cfg(feature = "lab-fast-lifecycle")]
		{
			// The forced-rotation deadline (MaxKeyAgeEras=7) counts THIS
			// clock, not the staking era. At block/25 (= one epoch) a
			// membership era was 2.5 min, so K=7 fired every ~17 min and
			// culled every validator that hadn't just rotated — a farm
			// treadmill that inverted the production ordering (membership
			// epoch 24h ≫ staking era). block/10000 = ~16.7h per era, so
			// K=7 ≈ 4.9 days: outlasts a multi-day churn run + the 72h
			// traffic window while staying compressed vs the 7-day prod
			// deadline. The deadline itself was already proven live (farm
			// churn 2026-07-12) — this stops it firing UNintentionally.
			(frame_system::Pallet::<Runtime>::block_number() / 10000) as u32
		}
		#[cfg(not(feature = "lab-fast-lifecycle"))]
		{
			zk_pki_pallet::Pallet::<Runtime>::current_epoch()
		}
	}
}

/// Live GRANDPA set id for lineage lifecycle points.
pub struct GrandpaCurrentSetId;
impl Get<u64> for GrandpaCurrentSetId {
	fn get() -> u64 {
		Grandpa::current_set_id()
	}
}

impl pallet_rostro_key_lineage::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type CurrentEra = MembershipEpochEra;
	type CurrentSetId = GrandpaCurrentSetId;
	// Forced-rotation deadline K = 7 eras (7 days): a next-session GRANDPA
	// key strictly older than this excludes its validator from the next set.
	type MaxKeyAgeEras = ConstU32<7>;
	type MaxValidators = ConstU32<32>;
	type ReportCanary = Offences;
	// The roster source: staking's NPoS election. KeyLineage filters what
	// staking elects; on `None` sessions (mid-era) it re-feeds its
	// `PlannedSet` so enforcement runs every session.
	type ElectedSet = Staking;
}

// ─── pallet_offences ───────────────────────────────────────────────────────
// The offence sink for GRANDPA equivocations and retired-key canary reports.
// Reports are stored permanently; the consequence fans out to both sinks:
// staking applies the economics (slash by fraction, era accounting,
// in-session disabling via its SessionInterface) and KeyLineage applies the
// roster consequence (disable-and-record, heal on fresh keys).

/// Route every offence to staking (slash) AND key-lineage (disable-and-
/// record). Both handlers are idempotent per offence; weights add.
pub struct OffenceFanout;
impl
	sp_staking::offence::OnOffenceHandler<
		AccountId,
		pallet_session_historical::IdentificationTuple<Runtime>,
		Weight,
	> for OffenceFanout
{
	fn on_offence(
		offenders: &[sp_staking::offence::OffenceDetails<
			AccountId,
			pallet_session_historical::IdentificationTuple<Runtime>,
		>],
		slash_fractions: &[Perbill],
		slash_session: sp_staking::SessionIndex,
	) -> Weight {
		use sp_staking::offence::OnOffenceHandler;
		let staking_weight = <Staking as OnOffenceHandler<
			AccountId,
			pallet_session_historical::IdentificationTuple<Runtime>,
			Weight,
		>>::on_offence(offenders, slash_fractions, slash_session);
		let lineage_weight = <KeyLineage as OnOffenceHandler<
			AccountId,
			pallet_session_historical::IdentificationTuple<Runtime>,
			Weight,
		>>::on_offence(offenders, slash_fractions, slash_session);
		staking_weight.saturating_add(lineage_weight)
	}
}

impl pallet_offences::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type IdentificationTuple = pallet_session_historical::IdentificationTuple<Self>;
	type OnOffenceHandler = OffenceFanout;
}

// ─── pallet_grandpa ────────────────────────────────────────────────────────

impl pallet_grandpa::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type WeightInfo = ();
	type MaxAuthorities = ConstU32<32>;
	type MaxNominators = ConstU32<0>;
	// set_id → session mappings retained for validating equivocation proofs
	// against past authority sets. One entry per session: 2048 ≈ 341 days.
	type MaxSetIdSessionEntries = ConstU64<2048>;
	type KeyOwnerProof = sp_session::MembershipProof;
	// Equivocation reports flow into pallet_offences (filtered so offences
	// older than the current bonding window are politely discarded instead
	// of failing inside staking) and from there fan out to staking (slash)
	// and KeyLineage (disable-and-record).
	type EquivocationReportSystem = pallet_grandpa::EquivocationReportSystem<
		Self,
		pallet_staking::FilterHistoricalOffences<Staking, Offences>,
		Historical,
		ReportLongevity,
	>;
}

parameter_types! {
	// Unsigned-report transaction validity window: the bonding period in
	// blocks (a report older than that could not slash anything anyway).
	pub ReportLongevity: u64 = BondingDuration::get() as u64 *
		SessionsPerEra::get() as u64 *
		EPOCH_LENGTH_IN_SLOTS as u64;
}

// ─── pallet_authorship ─────────────────────────────────────────────────────
// The author is the session validator ACCOUNT: pallet-sassafras recovers the
// SlotClaim's authority_idx from the digest log, FindAccountFromAuthorIndex
// maps that index into pallet-session's validator list (sassafras authorities
// are built from session validators in order, so the index is shared). This
// is what lets staking credit era reward points — and RNS route its author
// fee share — to the validator's real stash account.

pub type SassafrasAuthor = pallet_session::FindAccountFromAuthorIndex<Runtime, Sassafras>;

impl pallet_authorship::Config for Runtime {
	type FindAuthor = SassafrasAuthor;
	// 20 era reward points per authored block.
	type EventHandler = Staking;
}

// ─── NPoS: pallet_staking + onchain phragmen election ──────────────────────
// Upstream-vanilla NPoS, lean shape: the election runs on-chain (sequential
// phragmen via `OnChainExecution` — this fork culled the multi-phase
// provider; multi-block is the scale-up path if on-chain solving ever
// outgrows the block budget), the voter list is staking's own unsorted map
// (no bags-list pallet), rewards follow the standard inflation curve, and
// slashes/remainders burn (no treasury yet). Roster delivery to
// pallet-session goes through KeyLineage (`ElectedSet = Staking`), which
// filters offence-disabled and rotation-deadline-missed validators.

/// Bonded funds unlock this many eras after unbonding. Canonical: 28
/// (~7 days). Under lab-fast-lifecycle (scenario builds only) bonding
/// compresses to 1 era so a farm churn run can watch withdraw_unbonded
/// complete in minutes instead of hours.
#[cfg(not(feature = "lab-fast-lifecycle"))]
pub const BONDING_DURATION_ERAS: sp_staking::EraIndex = 28;
#[cfg(feature = "lab-fast-lifecycle")]
pub const BONDING_DURATION_ERAS: sp_staking::EraIndex = 1;

/// Slash deferral must stay strictly below BondingDuration
/// (cancel_deferred_slash window); with 1-era lab bonding it drops to 0
/// (slashes apply immediately).
#[cfg(not(feature = "lab-fast-lifecycle"))]
pub const SLASH_DEFER_ERAS: sp_staking::EraIndex = 27;
#[cfg(feature = "lab-fast-lifecycle")]
pub const SLASH_DEFER_ERAS: sp_staking::EraIndex = 0;

parameter_types! {
	// 6 sassafras-epoch sessions (~1h each) per era: ~6h eras, Kusama-style.
	pub const SessionsPerEra: sp_staking::SessionIndex = 6;
	// See BONDING_DURATION_ERAS / SLASH_DEFER_ERAS above (lab-fast-gated).
	pub const BondingDuration: sp_staking::EraIndex = BONDING_DURATION_ERAS;
	pub const SlashDeferDuration: sp_staking::EraIndex = SLASH_DEFER_ERAS;
	// Aligned with sassafras/grandpa MaxAuthorities and KeyLineage
	// MaxValidators: one bound chain-wide.
	pub const MaxValidatorSet: u32 = 32;
	pub ElectionBoundsOnChain: frame_election_provider_support::bounds::ElectionBounds =
		frame_election_provider_support::bounds::ElectionBoundsBuilder::default()
			.voters_count(2048.into())
			.targets_count(256.into())
			.build();
}

pallet_staking_reward_curve::build! {
	// Standard substrate inflation curve: 2.5% at zero stake, 10% at the
	// 50% ideal staking rate, exponential falloff past it.
	const REWARD_CURVE: sp_runtime::curve::PiecewiseLinear<'static> = curve!(
		min_inflation: 0_025_000,
		max_inflation: 0_100_000,
		ideal_stake: 0_500_000,
		falloff: 0_050_000,
		max_piece_count: 40,
		test_precision: 0_005_000,
	);
}

parameter_types! {
	pub RewardCurve: &'static sp_runtime::curve::PiecewiseLinear<'static> = &REWARD_CURVE;
}

/// On-chain sequential-phragmen election, used both at genesis and every era.
pub struct OnChainSeqPhragmen;
impl frame_election_provider_support::onchain::Config for OnChainSeqPhragmen {
	type Sort = ConstBool<true>;
	type System = Runtime;
	type Solver = frame_election_provider_support::SequentialPhragmen<AccountId, Perbill>;
	type DataProvider = Staking;
	type WeightInfo = frame_election_provider_support::weights::SubstrateWeight<Runtime>;
	type MaxWinnersPerPage = MaxValidatorSet;
	type MaxBackersPerWinner = ConstU32<256>;
	type Bounds = ElectionBoundsOnChain;
}

pub struct StakingBenchmarkingConfig;
impl pallet_staking::BenchmarkingConfig for StakingBenchmarkingConfig {
	type MaxValidators = ConstU32<1000>;
	type MaxNominators = ConstU32<1000>;
}

impl pallet_staking::Config for Runtime {
	type OldCurrency = Balances;
	type Currency = Balances;
	type RuntimeHoldReason = RuntimeHoldReason;
	type CurrencyBalance = Balance;
	type UnixTime = Timestamp;
	type CurrencyToVote = sp_staking::currency_to_vote::U128CurrencyToVote;
	type ElectionProvider =
		frame_election_provider_support::onchain::OnChainExecution<OnChainSeqPhragmen>;
	type GenesisElectionProvider = Self::ElectionProvider;
	type NominationsQuota = pallet_staking::FixedNominationsQuota<16>;
	type HistoryDepth = ConstU32<84>;
	// No treasury yet: the non-staker share of inflation burns.
	type RewardRemainder = ();
	type RuntimeEvent = RuntimeEvent;
	// Slashed funds burn.
	type Slash = ();
	type Reward = ();
	type SessionsPerEra = SessionsPerEra;
	type BondingDuration = BondingDuration;
	type SlashDeferDuration = SlashDeferDuration;
	// Sudo chain: root manages the less-critical staking knobs too.
	type AdminOrigin = frame_system::EnsureRoot<AccountId>;
	type SessionInterface = Self;
	type EraPayout = pallet_staking::ConvertCurve<RewardCurve>;
	type NextNewSession = Session;
	type MaxExposurePageSize = ConstU32<64>;
	type MaxValidatorSet = MaxValidatorSet;
	// Staking's own unsorted maps — sufficient at testnet scale; bags-list
	// is the upgrade path when nominator counts demand a sorted list.
	type VoterList = pallet_staking::UseNominatorsAndValidatorsMap<Self>;
	type TargetList = pallet_staking::UseValidatorsMap<Self>;
	type MaxUnlockingChunks = ConstU32<32>;
	type MaxControllersInDeprecationBatch = ConstU32<100>;
	type EventListeners = ();
	type Filter = frame_support::traits::Nothing;
	type BenchmarkingConfig = StakingBenchmarkingConfig;
	type WeightInfo = pallet_staking::weights::SubstrateWeight<Runtime>;
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

// ─── pallet_rostro_history_anchor ──────────────────────────────────────────
//
// Dual-hash anchoring: the first block of each new session seals the
// outgoing set's final header into a running Keccak-512 chain (bind while
// fresh; forging anchored history requires simultaneous structural breaks
// of BLAKE2-256 and Keccak).
//
// The era clock is the SESSION INDEX, deliberately not pallet-staking's
// era: the epoch/era mechanism on this chain is orthogonal to NPoS, and
// era-less deployments (the lab cluster) must anchor too. When NPoS lands,
// staking eras are session multiples, so session-boundary seals subsume
// era-boundary seals.

/// Session index as the history-anchor era clock.
pub struct SessionIndexProvider;
impl Get<Option<u32>> for SessionIndexProvider {
	fn get() -> Option<u32> {
		Some(pallet_session::Pallet::<Runtime>::current_index())
	}
}

impl pallet_rostro_history_anchor::Config for Runtime {
	type EraProvider = SessionIndexProvider;
	// Weight guard only, deliberately generous: a legitimate header
	// failing this bound would make the scheduled block unbuildable.
	type MaxHeaderBytes = ConstU32<65536>;
}

// ─── RNS — full wiring (registrar + registry + nft + price oracle ──────────
//      + resolvers + marketplace) ────────────────────────────────────────
//
// Identity primitive. Names live on chain, owned by AccountIds,
// 1-year max lease (renewals top up to "1 year from now," cannot
// exceed). Reserved-list seeded from
// `pallet_rns_registrar::genesis_reserved::SEED_RESERVED` at chain
// spec build time.
//
// PnsCustodian: temporary placeholder pointing at the sudo account.
// The 50/50 treasury+burn split is a follow-up that requires
// migrating PnsCustodian's Config item from `Get<AccountId>` to
// `OnUnbalanced<NegativeImbalanceOf<...>>` and wiring a Treasury
// pallet — tracked separately.

parameter_types! {
	/// Floor on per-object operator-state deposits.
	pub const MinOperatorObjectDeposit: Balance = ROSTO;

	/// RNS post-expiry grace period — name can be reclaimed by the
	/// previous owner during this window before becoming
	/// re-registrable by anyone.
	pub const RnsGracePeriod: u64 = 30 * (DAYS as u64) * MILLISECS_PER_BLOCK;

	/// RNS gift-name "offered" expiration. After this, an unaccepted
	/// gift returns to the seller.
	pub const RnsOfferWindow: u64 = 90 * (DAYS as u64) * MILLISECS_PER_BLOCK;

	/// Subdomains per registered name.
	pub const RnsDefaultCapacity: u32 = 10;

	/// No meaningful minimum registration duration on Rostro — set
	/// to 1 day, low enough that the parameter is effectively
	/// non-binding without inviting millisecond-grade spam. Rostro
	/// policy: max 365 days, renewal tops up to "365 days from
	/// now," there is no real floor.
	pub const RnsMinRegistrationDuration: u64 = (DAYS as u64) * MILLISECS_PER_BLOCK;

	/// Rostro names cap at 1-year leases. Renewals top up the
	/// remaining duration to a 365-days-from-now ceiling, never
	/// exceed it.
	pub const RnsMaxRegistrationDuration: u64 = 365 * (DAYS as u64) * MILLISECS_PER_BLOCK;

	/// Maximum bytes per resolver record (TXT, AVATAR CID, RPC
	/// endpoint, etc.). 1536: fits the largest typed record, a
	/// PQSPK/SEAL prekey record (1184-byte ML-KEM-768 ek + 64-byte
	/// sig = 1248; docs/PQ-CHAT.md).
	pub const RnsMaxContentLen: u32 = 1536;

	/// Marketplace listing deposit — held on the seller while a
	/// listing is active, refunded on cancellation, paid to the
	/// cleanup caller after expiry-past-grace.
	pub const RnsListingDeposit: Balance = ROSTO;

	/// Marketplace listing grace period before cleanup eligibility.
	pub const RnsListingGracePeriod: u64 = 7 * (DAYS as u64) * MILLISECS_PER_BLOCK;

	/// Base namehash for Rostro (mainnet `rst` TLD). Gemini is the
	/// testbed for this exact stack so it uses the production
	/// basenode by design.
	pub const RnsBaseNode: rns_types::DomainHash = rns_types::RST_BASENODE;
}

/// `EnsureRoot`-equivalent that satisfies `Success = AccountId`.
/// RNS Config items expect this signature for their ManagerOrigin.
pub struct EnsureRootAsAccountId;
impl frame_support::traits::EnsureOrigin<RuntimeOrigin> for EnsureRootAsAccountId {
	type Success = AccountId;
	fn try_origin(o: RuntimeOrigin) -> Result<Self::Success, RuntimeOrigin> {
		match <frame_system::EnsureRoot<AccountId>>::try_origin(o) {
			Ok(_) => Ok(AccountId::new([0u8; 32])),
			Err(o) => Err(o),
		}
	}
	#[cfg(feature = "runtime-benchmarks")]
	fn try_successful_origin() -> Result<RuntimeOrigin, ()> {
		Ok(RuntimeOrigin::root())
	}
}

/// PnsCustodian funding placeholder — receives the protocol-share
/// of registration / renewal fees. Currently routes to whoever
/// holds the sudo key. The proper 50% treasury / 50% burn split
/// requires the rns-registrar pallet to migrate this Config item
/// from `Get<AccountId>` to `OnUnbalanced<NegativeImbalance>` —
/// tracked as a follow-up.
pub struct PnsCustodianAccount;
impl frame_support::traits::Get<AccountId> for PnsCustodianAccount {
	fn get() -> AccountId {
		pallet_sudo::Key::<Runtime>::get().unwrap_or_else(|| AccountId::new([0u8; 32]))
	}
}

/// Block author for RNS fee distribution (40% of registration fee
/// per the registrar's price oracle). Reads from
/// `pallet_authorship::Author`, which is populated each block by
/// the `SassafrasAuthor::find_author` lookup (the validator's
/// session account, i.e. the stash).
pub struct PnsBlockAuthor;
impl pallet_rns_registrar::traits::BlockAuthor for PnsBlockAuthor {
	type AccountId = AccountId;
	fn author() -> Option<AccountId> {
		pallet_authorship::Pallet::<Runtime>::author()
	}
}

/// Always-open registrar. Rostro doesn't shut people out of name
/// registration. Could be governance-gated in a future revision
/// if a registration-pause emergency action is ever needed.
pub struct PnsIsOpen;
impl pallet_rns_registrar::traits::IsRegistrarOpen for PnsIsOpen {
	fn is_open() -> bool {
		true
	}
}

/// Bridge `registrar`/`marketplace` → `resolvers` for SS58 record
/// updates. The registrar/marketplace mint or transfer a name; we
/// echo the new owner into the resolvers' SS58 record so DNS-style
/// lookups always reflect the current owner.
pub struct RnsSs58Updater;
impl pallet_rns_registrar::traits::Ss58Updater for RnsSs58Updater {
	type AccountId = AccountId;
	fn update_ss58(
		node: rns_types::DomainHash,
		owner: &AccountId,
	) -> sp_runtime::DispatchResult {
		pallet_rns_resolvers::resolvers::Pallet::<Runtime>::set_ss58_record(node, owner)
	}
}

/// Bridge `registrar` → `resolvers` for ORIGIN record (block hash
/// of the registration block). Pinned at initial registration,
/// preserved across renewals.
pub struct PnsOriginRecorder;
impl pallet_rns_registrar::traits::OriginRecorder for PnsOriginRecorder {
	fn record_origin(
		node: rns_types::DomainHash,
		block_hash: [u8; 32],
	) -> sp_runtime::DispatchResult {
		pallet_rns_resolvers::resolvers::Pallet::<Runtime>::set_origin_record(node, block_hash)
	}
}

/// Bridge `registrar`/`marketplace` → `resolvers` for record
/// cleanup on transfer/burn. SS58 update is paired separately so
/// the new owner's SS58 lands before non-SS58 records get cleared.
pub struct PnsRecordCleaner;
impl pallet_rns_registrar::traits::RecordCleaner for PnsRecordCleaner {
	fn clear_records_except_ss58(node: rns_types::DomainHash) {
		pallet_rns_resolvers::resolvers::Pallet::<Runtime>::clear_records_except_ss58(node)
	}
	fn clear_all_records(node: rns_types::DomainHash) {
		pallet_rns_resolvers::resolvers::Pallet::<Runtime>::clear_all_records(node)
	}
}

/// Resolvers consult this when validating that a record-write
/// targets a registered + useable name owned by the caller.
pub struct PnsRegistryChecker;
impl pallet_rns_resolvers::resolvers::RegistryChecker for PnsRegistryChecker {
	type AccountId = AccountId;
	fn check_node_useable(node: rns_types::DomainHash, owner: &AccountId) -> bool {
		use pallet_rns_registrar::traits::Registrar as _;
		if pallet_rns_registrar::registry::Pallet::<Runtime>::verify(owner, node).is_err() {
			return false;
		}
		pallet_rns_registrar::registrar::Pallet::<Runtime>::get_info(node)
			.map(|_| {
				pallet_rns_registrar::registrar::Pallet::<Runtime>::check_expires_useable(node)
					.is_ok()
			})
			.unwrap_or(true)
	}
	fn base_node() -> rns_types::DomainHash {
		<RnsBaseNode as frame_support::traits::Get<rns_types::DomainHash>>::get()
	}
}

impl pallet_rns_registrar::nft::Config for Runtime {
	type ClassId = u32;
	type TotalId = u128;
	type TokenId = rns_types::DomainHash;
	type ClassData = ();
	type TokenData = rns_types::Record;
	type MaxClassMetadata = ConstU32<0>;
	type MaxTokenMetadata = ConstU32<0>;
}

impl pallet_rns_registrar::price_oracle::Config for Runtime {
	type Currency = Balances;
	type Moment = u64;
	type ExchangeRate = pallet_rns_registrar::price_oracle::Pallet<Runtime>;
	type WeightInfo = ();
	type ManagerOrigin = EnsureRootAsAccountId;
}

impl pallet_rns_registrar::registry::Config for Runtime {
	type WeightInfo = ();
	type Registrar = pallet_rns_registrar::registrar::Pallet<Runtime>;
	type ManagerOrigin = EnsureRootAsAccountId;
	type Ss58Updater = RnsSs58Updater;
	type RecordCleaner = PnsRecordCleaner;
	type OriginRecorder = PnsOriginRecorder;
}

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
	// when SRT lands. Stubbed to root until then.
	type SecurityResponseTeamOrigin = frame_system::EnsureRoot<AccountId>;
	type PnsCustodian = PnsCustodianAccount;
	type BlockAuthor = PnsBlockAuthor;
	type IsOpen = PnsIsOpen;
	type Official = pallet_rns_registrar::registry::Pallet<Runtime>;
	type Ss58Updater = RnsSs58Updater;
	type OriginRecorder = PnsOriginRecorder;
	type RecordCleaner = PnsRecordCleaner;
}

impl pallet_rns_resolvers::resolvers::Config for Runtime {
	const OFFCHAIN_PREFIX: &'static [u8] = b"rns/";
	type WeightInfo = ();
	type MaxContentLen = RnsMaxContentLen;
	type RegistryChecker = PnsRegistryChecker;
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
	type RecordCleaner = PnsRecordCleaner;
	type OriginRecorder = PnsOriginRecorder;
	type BaseNode = RnsBaseNode;
	type WeightInfo = ();
}

// ─── pallet_rostro_operator_state ──────────────────────────────────────────
//
// RNS-rooted operator-private object storage. RnsRegistry now
// points at the real `pallet_rns_registrar::registrar::Pallet` —
// `mint_object` enforces real namespace ownership.

impl pallet_rostro_operator_state::Config for Runtime {
	type Currency = Balances;
	type RnsRegistry = pallet_rns_registrar::registrar::Pallet<Runtime>;
	type MinObjectDeposit = MinOperatorObjectDeposit;
}

// ─── pallet_rostro_bilateral_receipt ───────────────────────────────────────
//
// Customer↔operator non-repudiation receipts + atomic operator-state
// mint via the [`OperatorStateMintAdapter`]. The adapter calls
// operator-state's `mint_object` extrinsic with a synthesized
// `Signed(operator)` origin — the operator's signature on the
// bilateral receipt bundle (which includes the mint parameters)
// is what authorizes both the trade AND the mint atomically.

pub struct OperatorStateMintAdapter;
impl pallet_rostro_bilateral_receipt::AtomicMintHook<AccountId, Balance>
	for OperatorStateMintAdapter
{
	fn mint(
		operator: &AccountId,
		namespace: sp_core::H256,
		object_type: alloc::vec::Vec<u8>,
		object_id: alloc::vec::Vec<u8>,
		owner: AccountId,
		blob: alloc::vec::Vec<u8>,
		deposit: Balance,
	) -> sp_runtime::DispatchResult {
		pallet_rostro_operator_state::Pallet::<Runtime>::mint_object(
			frame_system::RawOrigin::Signed(operator.clone()).into(),
			namespace,
			object_type,
			object_id,
			owner,
			blob,
			deposit,
		)
	}
}

impl pallet_rostro_bilateral_receipt::Config for Runtime {
	type Currency = Balances;
	type Signature = Signature;
	type AccountPublic = RostroSigner;
	type AtomicMintHook = OperatorStateMintAdapter;
}

// ─── zk-pki Configuration ─────────────────────────────────────────────────
// Hardware-attestation primitive. Binds a device's TPM EK / Strongbox
// key to an on-chain commitment, then verifies mime_wrap Groth16 proofs
// against that commitment. The same primitive carries every PoP cert.
//
// Constants tracked from paseo's posture: 30-day grace, 5-year root TTL,
// 90-day min root, 45-day challenge window, fee tiers PoP/Packed/None.
// Block cadence is the gemini value (DAYS = 24h of HOURS-of-MINUTES at
// MILLISECS_PER_BLOCK), so day counts translate directly.
parameter_types! {
	pub const PkiInactivePurgePeriod: BlockNumber    = 30 * DAYS;
	pub const PkiContractOfferTtlBlocks: BlockNumber = DAYS;
	pub const PkiMaxRootTtlBlocks: BlockNumber       = 5 * 365 * DAYS;
	pub const PkiMaxIssuersPerRoot: u32              = 5;
	pub const PkiChallengeWindowBlocks: BlockNumber  = 45 * DAYS;
	pub const PkiCertDeposit: Balance                = ROSTO;
	pub const PkiOfferDeposit: Balance               = ROSTO / 10;
	pub const PkiMinRootTtlBlocks: BlockNumber       = 90 * DAYS;
	pub const PkiMinIssuerTtlBlocks: BlockNumber     = 30 * DAYS;
	pub const PkiTtlCheckInterval: BlockNumber       = DAYS;
	pub const PkiTemplateDeposit: Balance            = 10 * ROSTO;
	pub const PkiMaxTemplatesPerIssuer: u32          = 256;
	pub const PkiProtocolFeeBasisPoints: u32         = 1_000;
	pub const PkiBlockCreatorCapBasisPoints: u32     = 4_000;
	pub const PkiDepositBasisPoints: u32             = 500;
	pub const PkiMinDeposit: Balance                 = ROSTO / 10;
	pub const PkiMintFeePoP: Balance                 = ROSTO;
	pub const PkiMintFeePacked: Balance              = ROSTO + ROSTO / 2;
	pub const PkiMintFeeNone: Balance                = 2 * ROSTO;
	// Burn-hole until treasury wires up — same posture as
	// `PnsCustodianAccount`. Swap to a real treasury sink once
	// `pallet-treasury` lands.
	pub PkiProtocolFeeRecipient: AccountId = AccountId::new([0u8; 32]);
}

impl zk_pki_pallet::Config for Runtime {
	type InactivePurgePeriod = PkiInactivePurgePeriod;
	type ContractOfferTtlBlocks = PkiContractOfferTtlBlocks;
	type MaxRootTtlBlocks = PkiMaxRootTtlBlocks;
	type MaxIssuersPerRoot = PkiMaxIssuersPerRoot;
	type ChallengeWindowBlocks = PkiChallengeWindowBlocks;
	type CertDeposit = PkiCertDeposit;
	type OfferDeposit = PkiOfferDeposit;
	type MinRootTtlBlocks = PkiMinRootTtlBlocks;
	type MinIssuerTtlBlocks = PkiMinIssuerTtlBlocks;
	type TtlCheckInterval = PkiTtlCheckInterval;
	type TemplateDeposit = PkiTemplateDeposit;
	type MaxTemplatesPerIssuer = PkiMaxTemplatesPerIssuer;
	type RuntimeHoldReason = RuntimeHoldReason;
	type Currency = Balances;
	type FindAuthor = SassafrasAuthor;
	type ProtocolFeeRecipient = PkiProtocolFeeRecipient;
	type ProtocolFeeBasisPoints = PkiProtocolFeeBasisPoints;
	type BlockCreatorCapBasisPoints = PkiBlockCreatorCapBasisPoints;
	type DepositBasisPoints = PkiDepositBasisPoints;
	type MinDeposit = PkiMinDeposit;
	type MintFeePoP = PkiMintFeePoP;
	type MintFeePacked = PkiMintFeePacked;
	type MintFeeNone = PkiMintFeeNone;
	// Per-call-unique EK-hash test verifier. Production must swap
	// to the real `TpmAttestationVerifier` once mainnet is staffing
	// the manufacturer-intermediate whitelist.
	type Attestation = zk_pki_primitives::traits::TpmTestAttestationVerifier;
	// Production hardware-attestation verifier: full chain signature walk +
	// Google root (legacy + 2026) + manufacturer-intermediate pinning + StrongBox/
	// origin/RootOfTrust extraction. The `mock-attestation` feature swaps in the
	// bypass-crypto `NoopBindingProofVerifier` for lab/mock-mint flows only.
	// (App-signing-cert identity auto-enforces once `DOTWAVE_SIGNING_CERT_HASH`
	// is grounded; hardware/root/package checks are strict now — see the
	// fail-forward sentinel in `zk-pki-integrity`.)
	#[cfg(not(feature = "mock-attestation"))]
	type BindingProofVerifier = zk_pki_tpm::ProductionBindingProofVerifier;
	#[cfg(feature = "mock-attestation")]
	type BindingProofVerifier =
		zk_pki_tpm::test_mock_verifier::NoopBindingProofVerifier;
	// Placeholder weights — replace with `--pallet zk-pki-pallet
	// --extrinsic '*'` benchmark output before mainnet.
	type WeightInfo = zk_pki_pallet::weights::SubstrateWeight<Runtime>;
	// pallet_proxy is not in gemini-runtime — we use Noop. Operator
	// authorization on Rostro is RNS-rooted, not proxy-rooted.
	type ProxyValidator = zk_pki_primitives::proxy::NoopProxyValidator;
}

// ─── Attestor Quorum Configuration ─────────────────────────────────────────
// A subset of validators (v0 = all active validators) signs the zkpki
// RootOfRoots checkpoint with a secp256k1 ATTESTOR session key, landed as
// unsigned txs the mempool aggregates. A foreign Ethereum contract verifies the
// quorum via `ecrecover`. The pallet is its own OneSessionHandler (caches the
// session's attestor eth-addresses) and its own AttestorRegistry, so `Attestors`
// binds back to the pallet. `Checkpoint` reads zkpki's root-of-roots getter.
// See docs/ATTESTOR-QUORUM.md, docs/HANDOFF-RWA-CREDENTIAL.md.

/// The value the quorum signs: zkpki's root-of-roots over every issuer's witness
/// + freshness roots, recomputed on each witness-tree change.
pub struct RootOfRootsCheckpoint;
impl pallet_rostro_attestor::CheckpointProvider for RootOfRootsCheckpoint {
	fn root() -> [u8; 32] {
		ZkPki::root_of_roots()
	}
}

impl pallet_rostro_attestor::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type Checkpoint = RootOfRootsCheckpoint;
	// The pallet caches each session's validators (their ATTESTOR keys) as the
	// attestor set and computes the ⌈2/3⌉ threshold — so it is its own registry.
	type Attestors = Attestor;
	// Chain-wide validator cap (matches Staking's elected-set bound).
	type MaxAttestors = ConstU32<32>;
	// Retain ~10 minutes of (height → root) so a late-landing attestation still
	// validates against the root the chain had at its height (6s blocks).
	type RecentWindow = ConstU32<100>;
}

// ─── Personhood (PoP) Configuration ───────────────────────────────────────
// Proof-of-personhood layer above zkpki. mint_pop verifies a
// passport_attest + liveness_facematch Groth16 pair (BN254) bound to
// the caller's active zkpki HW cert via a fresh HIP. Single passport
// = single cert globally (deterministic nullifier). PoP cert bound
// to SS58, so multi-device users (one SS58 spans devices via
// restored seed) still vote once.
//
// MaxProofAge=600 blocks (~1 hour at 6s/block) — locked §1.

parameter_types! {
	pub const PopMaxProofAge: BlockNumber = 600;
	/// PoP cert TTL: 5 years aligned with the OPRF K rotation cycle per
	/// `pop_design_section1c_oprf_nullifier.md`. Computed as
	/// `5 years * 365 days * 24 hours * 60 minutes * 10 blocks/min`
	/// at 6s block time = 5 * 365 * 24 * 600 = 26_280_000 blocks.
	pub const PopFixedTtl: BlockNumber = 26_280_000;
	/// Per the pallet docstring: 256 KB upper bound for STARK proofs.
	/// Matches the mainnet recommendation; safe for the gemini testbed.
	pub const PopMaxProofBytes: u32 = 262_144;
}

/// Camino testnet shape — both production and mock variants allowed
/// so PoP minting can be exercised end-to-end on the testbed without
/// requiring real OPRF federation infrastructure. Mainnet narrows to
/// `&[NullifierType::Salted]`.
pub struct PopAcceptedNullifierTypes;
impl frame_support::traits::Get<&'static [pallet_rostro_personhood::NullifierType]>
	for PopAcceptedNullifierTypes
{
	fn get() -> &'static [pallet_rostro_personhood::NullifierType] {
		&[
			pallet_rostro_personhood::NullifierType::Salted,
			pallet_rostro_personhood::NullifierType::SaltedMock,
		]
	}
}

/// Testbed sentinel fingerprints — no SRT VK ceremony has been run for
/// this binary. `srt_set_vk` will reject every publication with
/// `VkFingerprintMismatch` until real circuit-family fingerprints are
/// wired here, which is the safe default for a testbed.
pub struct PopExpectedVkFingerprints;
impl frame_support::traits::Get<&'static [(pallet_rostro_personhood::CircuitId, sp_core::H256)]>
	for PopExpectedVkFingerprints
{
	fn get() -> &'static [(pallet_rostro_personhood::CircuitId, sp_core::H256)] {
		&[
			(pallet_rostro_personhood::CircuitId::PassportAttest, sp_core::H256([0xF1; 32])),
			(pallet_rostro_personhood::CircuitId::LivenessFacematch, sp_core::H256([0xF2; 32])),
		]
	}
}

/// Adapter that delegates `pallet_rostro_personhood::ZkPkiInterface`
/// calls to the local zkpki pallet. The interface keeps the
/// personhood pallet decoupled from a hard `T: zk_pki_pallet::Config`
/// bound — gemini-runtime is the only crate that knows about both.
pub struct ZkPkiPersonhoodAdapter;

impl pallet_rostro_personhood::ZkPkiInterface<AccountId, BlockNumber>
	for ZkPkiPersonhoodAdapter
{
	fn verify_cert_and_hip(
		thumbprint: sp_core::H256,
		account: &AccountId,
		hip_proof: &zk_pki_primitives::hip::CanonicalHipProof,
		challenge_nonce: &[u8; 32],
	) -> Result<(), pallet_rostro_personhood::ZkPkiError> {
		let result = zk_pki_pallet::Pallet::<Runtime>::verify_active_cert_and_hip(
			thumbprint.0,
			account,
			hip_proof,
			challenge_nonce,
		);
		// Translate zkpki's pallet errors into the small enum
		// personhood understands. Anything other than the four
		// listed reasons is funnelled into HipFailed — those are
		// the only paths `verify_active_cert_and_hip` returns.
		result.map_err(|e| {
			use pallet_rostro_personhood::ZkPkiError;
			let ev: zk_pki_pallet::Error<Runtime> = e;
			match ev {
				zk_pki_pallet::Error::<Runtime>::CertNotFound => ZkPkiError::CertNotFound,
				zk_pki_pallet::Error::<Runtime>::NotCertHolder => ZkPkiError::CertNotOwned,
				zk_pki_pallet::Error::<Runtime>::CertNotActive
				| zk_pki_pallet::Error::<Runtime>::CertExpired => ZkPkiError::CertNotGood,
				_ => ZkPkiError::HipFailed,
			}
		})
	}

	fn hip_attested_at(
		_hip_proof: &zk_pki_primitives::hip::CanonicalHipProof,
	) -> Option<BlockNumber> {
		// CanonicalHipProof's freshness comes from the
		// challenge_nonce being bound to a recent chain anchor
		// (which the personhood circuit enforces). The proof
		// itself doesn't carry a chain block number, so report
		// None — personhood's mint_pop already handles that
		// case (anchor-binding is the freshness mechanism).
		None
	}
}

impl pallet_rostro_personhood::Config for Runtime {
	type MaxProofAge = PopMaxProofAge;
	type FixedPopTtl = PopFixedTtl;
	type MaxProofBytes = PopMaxProofBytes;
	type ExpectedVkFingerprints = PopExpectedVkFingerprints;
	type AcceptedNullifierTypes = PopAcceptedNullifierTypes;
	type ZkPki = ZkPkiPersonhoodAdapter;
	// Production Groth16 verifier (ark-groth16 over BN254). Same
	// stack zk-pki uses for mime_wrap.
	type ProofVerifier = pallet_rostro_personhood::ArkProofVerifier;
	// SrtOrigin stubbed at EnsureRoot until the SecurityResponseTeam
	// pallet lands. Same posture as RNS reserved-list and other
	// SRT-gated extrinsics in this runtime.
	type SrtOrigin = frame_system::EnsureRoot<AccountId>;
}

// ─── pallet_rostro_keyring ─────────────────────────────────────────────────
// Account keyring: revocable multi-key authority overlay
// (docs/KEYRING.md). Consulted once per signed extrinsic via
// KeyringSignature's Verify impl.

impl pallet_rostro_keyring::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type MaxKeys = ConstU32<5>;
}

// ─── construct_runtime ─────────────────────────────────────────────────────

construct_runtime!(
	pub enum Runtime {
		// System
		System: frame_system,
		Timestamp: pallet_timestamp,
		Sudo: pallet_sudo,

		// Consensus — Sassafras (block production) + GRANDPA (finality).
		// Sassafras MUST precede Session: its on_initialize reads the slot
		// claim digest and updates CurrentSlot before Session's
		// on_initialize consults ShouldEndSession (= Sassafras).
		Sassafras: pallet_sassafras,
		Grandpa: pallet_grandpa,
		Authorship: pallet_authorship,

		// Economic. Declared before Staking: staking's genesis bonds the
		// genesis stakers, so balances genesis must build first.
		Balances: pallet_balances,
		TransactionPayment: pallet_transaction_payment,

		// NPoS. Staking MUST precede Session: session's genesis asks the
		// session manager (KeyLineage → Staking) for the elected set, so
		// staking's genesis (stakers bonded, prefs set) must build first.
		// This reorder renumbered Session and everything after it — a
		// genesis-breaking change that rode the spec-106 chain reset.
		Staking: pallet_staking,
		Session: pallet_session,

		// Operational — on-chain RPC method access policy registry,
		// consumed by the native rostro-rpc-shield middleware.
		RpcMethodPolicy: pallet_rostro_rpc_method_policy,

		// Operational — on-chain registry of canonical foundation
		// file hashes; native verifier reads at boot.
		CanonicalFiles: pallet_rostro_canonical_files,

		// RNS — Rostro's identity primitive. Six pallets cooperate:
		// nft (NFT-backed name ownership), price_oracle (registration
		// fee curve), registry (per-name records, transfers),
		// registrar (registration / renewal / reserved-list, the
		// outward-facing entry point), resolvers (DNS-style record
		// reads + writes), marketplace (name listings + sales).
		RnsNft: pallet_rns_registrar::nft,
		RnsPriceOracle: pallet_rns_registrar::price_oracle,
		RnsRegistry: pallet_rns_registrar::registry,
		RnsRegistrar: pallet_rns_registrar::registrar,
		RnsResolvers: pallet_rns_resolvers::resolvers,
		RnsMarketplace: pallet_rns_marketplace,

		// Operator state — RNS-rooted per-operator object storage
		// (NFTs, tickets, custom records).
		OperatorState: pallet_rostro_operator_state,

		// Bilateral receipts — customer↔operator non-repudiation +
		// atomic operator-state mint via OperatorStateMintAdapter.
		BilateralReceipt: pallet_rostro_bilateral_receipt,

		// zk-pki — hardware-attestation primitive. Binds device EK/
		// Strongbox key to on-chain commitment; verifies mime_wrap
		// Groth16 proofs. Foundation for personhood (8e) and
		// validator slash-on-rejoin attestations (7b step 6).
		ZkPki: zk_pki_pallet,

		// Personhood (PoP) — verifies a passport_attest +
		// liveness_facematch Groth16 pair bound to an active zkpki
		// cert via a fresh HIP. One passport → one cert
		// (deterministic nullifier). One SS58 → one PoP cert. The
		// personhood layer mime_wrap is orthogonal to (HW
		// attestation), bound only via the SS58 holder.
		Personhood: pallet_rostro_personhood,

		// Session-historical — per-session key-ownership trie roots
		// (equivocation proofs against past sessions). Appended at the
		// END on purpose: pallet indices are positional and this runtime
		// is live; inserting next to Session would renumber every pallet
		// after it and break encoded-call compatibility.
		Historical: pallet_session_historical,

		// GRANDPA-key lineage: fresh-key primitive, permanent key records,
		// forced-rotation deadline (docs/CONSENSUS-KEY-LIFECYCLE.md, P1).
		// Appended at the END: pallet indices are positional and this
		// runtime is live.
		KeyLineage: pallet_rostro_key_lineage,

		// Offence sink: permanent reports for equivocation + retired-key
		// canary, consequence routed to KeyLineage (P2). Positional append,
		// same as above.
		Offences: pallet_offences,

		// History anchor: dual-hash (Keccak-512) sealing of session-
		// boundary headers. Positional append, same as above. Hook order
		// matters and is satisfied here: Session's on_initialize rotates
		// the session BEFORE this pallet's on_initialize latches the seal
		// schedule, so the incoming set seals the outgoing set's final
		// header in the rotation block itself.
		HistoryAnchor: pallet_rostro_history_anchor,

		// Account keyring: revocable multi-key authority overlay
		// consulted by extrinsic signature verification
		// (docs/KEYRING.md). Positional append, same as above.
		Keyring: pallet_rostro_keyring,
		// Attestor Quorum: validators sign the zkpki RootOfRoots checkpoint with
		// a secp256k1 ATTESTOR session key so a foreign contract verifies it via
		// ecrecover. Rides SessionKeys (genesis-breaking, spec 111). Positional
		// append. See docs/ATTESTOR-QUORUM.md.
		Attestor: pallet_rostro_attestor,
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
			equivocation_proof: sp_consensus_grandpa::EquivocationProof<
				<Block as BlockT>::Hash,
				NumberFor<Block>,
			>,
			key_owner_proof: sp_consensus_grandpa::OpaqueKeyOwnershipProof,
		) -> Option<()> {
			let key_owner_proof = key_owner_proof.decode()?;
			Grandpa::submit_unsigned_equivocation_report(equivocation_proof, key_owner_proof)
		}

		fn generate_key_ownership_proof(
			_set_id: sp_consensus_grandpa::SetId,
			authority_id: sp_consensus_grandpa::AuthorityId,
		) -> Option<sp_consensus_grandpa::OpaqueKeyOwnershipProof> {
			Historical::prove((sp_consensus_grandpa::KEY_TYPE, authority_id))
				.map(|p| p.encode())
				.map(sp_consensus_grandpa::OpaqueKeyOwnershipProof::new)
		}
	}

	impl pallet_rostro_key_lineage::KeyLineageApi<Block> for Runtime {
		fn is_retired_grandpa_key(key: sp_consensus_grandpa::AuthorityId) -> bool {
			KeyLineage::is_retired(&key)
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

		fn canonical_root() -> [u8; 32] {
			pallet_rostro_canonical_files::Pallet::<Runtime>::canonical_root()
		}

		fn release_pubkey() -> Option<[u8; 32]> {
			pallet_rostro_canonical_files::Pallet::<Runtime>::release_pubkey()
		}
	}

	// RNS storage API surface — used by the snorkel and any
	// external client doing name lookups over `state_call`. Each
	// method has a corresponding entry in
	// `V0_WELL_KNOWN_POLICIES` classified `PublicGated`, so the
	// rostro-rpc-shield rate-limits queries but doesn't deny them.
	impl rns_runtime_api::PnsStorageApi<Block, u64, Balance, AccountId> for Runtime {
		fn get_info(
			id: rns_types::DomainHash,
		) -> Option<rns_types::NameRecord<AccountId, u64, Balance>> {
			use frame_support::traits::Time;
			let info = pallet_rns_registrar::registrar::Pallet::<Runtime>::get_info(id)?;
			if pallet_timestamp::Pallet::<Runtime>::now() >= info.expire {
				return None;
			}
			let token = pallet_rns_registrar::nft::Pallet::<Runtime>::tokens(0u32, id)?;
			let for_sale = pallet_rns_marketplace::Listings::<Runtime>::contains_key(id);
			Some(rns_types::NameRecord {
				owner: token.owner,
				expire: info.expire,
				capacity: info.capacity,
				register_fee: info.register_fee,
				for_sale,
				last_block: info.last_block,
				read_block_number: 0,
				read_block_hash: Default::default(),
			})
		}

		fn lookup(
			id: rns_types::DomainHash,
			record_types: Vec<rns_types::ddns::codec_type::RecordType>,
		) -> Vec<(rns_types::ddns::codec_type::RecordType, Vec<u8>)> {
			pallet_rns_resolvers::resolvers::Pallet::<Runtime>::lookup(id, record_types)
		}

		fn resolve_name(
			name: Vec<u8>,
		) -> Option<rns_types::NameRecord<AccountId, u64, Balance>> {
			use frame_support::traits::Time;
			use pallet_rns_registrar::traits::Label;
			let (label, _) = Label::new_with_len(&name)?;
			let base_node = <RnsBaseNode as frame_support::traits::Get<rns_types::DomainHash>>::get();
			let node = label.encode_with_node(&base_node);
			let info = pallet_rns_registrar::registrar::Pallet::<Runtime>::get_info(node)?;
			if pallet_timestamp::Pallet::<Runtime>::now() >= info.expire {
				return None;
			}
			let token = pallet_rns_registrar::nft::Pallet::<Runtime>::tokens(0u32, node)?;
			let for_sale = pallet_rns_marketplace::Listings::<Runtime>::contains_key(node);
			Some(rns_types::NameRecord {
				owner: token.owner,
				expire: info.expire,
				capacity: info.capacity,
				register_fee: info.register_fee,
				for_sale,
				last_block: info.last_block,
				read_block_number: 0,
				read_block_hash: Default::default(),
			})
		}

		fn get_listing(
			name: Vec<u8>,
		) -> Option<rns_types::ListingInfo<AccountId, Balance, u64>> {
			use pallet_rns_registrar::traits::Label;
			let (label, _) = Label::new_with_len(&name)?;
			let base_node = <RnsBaseNode as frame_support::traits::Get<rns_types::DomainHash>>::get();
			let node = label.encode_with_node(&base_node);
			let l = pallet_rns_marketplace::Listings::<Runtime>::get(node)?;
			Some(rns_types::ListingInfo {
				seller: l.seller,
				price: l.price,
				expires_at: l.expires_at,
				read_block_number: 0,
				read_block_hash: Default::default(),
			})
		}

		fn lookup_by_name(
			name: Vec<u8>,
			record_types: Vec<rns_types::ddns::codec_type::RecordType>,
		) -> Vec<(rns_types::ddns::codec_type::RecordType, Vec<u8>)> {
			let base_node = <RnsBaseNode as frame_support::traits::Get<rns_types::DomainHash>>::get();
			let node = rns_types::parse_name_to_node(&name, &base_node).unwrap_or_default();
			pallet_rns_resolvers::resolvers::Pallet::<Runtime>::lookup(node, record_types)
		}

		fn account_dashboard(owner: AccountId) -> rns_types::AccountDashboard {
			let primary_name =
				pallet_rns_registrar::registrar::OwnerToPrimaryName::<Runtime>::get(&owner);
			let subnames =
				pallet_rns_registrar::registry::AccountToSubnames::<Runtime>::iter_prefix(&owner)
					.map(|(hash, _)| hash)
					.collect();
			let pending_subname_offers =
				pallet_rns_registrar::registry::OfferedToAccount::<Runtime>::iter_prefix(&owner)
					.map(|(hash, _)| hash)
					.collect();
			let pending_name_offers = pallet_rns_registrar::registrar::OfferedNames::<Runtime>::iter()
				.filter_map(|(node, record)| {
					if record.recipient == owner { Some(node) } else { None }
				})
				.collect();
			rns_types::AccountDashboard {
				primary_name,
				subnames,
				pending_subname_offers,
				pending_name_offers,
			}
		}

		fn guard_set() -> Vec<[u8; 32]> {
			pallet_rns_resolvers::resolvers::Pallet::<Runtime>::guard_set()
		}
	}

	// zk-pki runtime API — cert / EK / chain-validity queries. Each
	// method forwards to a `pallet::Pallet::<Runtime>::query_*`
	// function. Exposed via `state_call`; corresponding entries in
	// `V0_WELL_KNOWN_POLICIES` classify them as `PublicGated` so
	// rostro-rpc-shield rate-limits but does not deny.
	impl zk_pki_primitives::runtime_api::ZkPkiApi<Block, AccountId> for Runtime {
		fn cert_status(
			thumbprint: [u8; 32],
		) -> Option<zk_pki_primitives::runtime_api::CertStatusResponse<AccountId>> {
			zk_pki_pallet::Pallet::<Runtime>::query_cert_status(thumbprint)
		}

		fn certs_by_issuer(
			issuer: AccountId,
		) -> Vec<zk_pki_primitives::runtime_api::CertSummary> {
			zk_pki_pallet::Pallet::<Runtime>::query_certs_by_issuer(issuer)
		}

		fn certs_by_user(
			user: AccountId,
		) -> Vec<zk_pki_primitives::runtime_api::CertSummary> {
			zk_pki_pallet::Pallet::<Runtime>::query_certs_by_user(user)
		}

		fn certs_by_root(
			root: AccountId,
		) -> Vec<zk_pki_primitives::runtime_api::CertSummary> {
			zk_pki_pallet::Pallet::<Runtime>::query_certs_by_root(root)
		}

		fn entity_status(
			address: AccountId,
		) -> Option<zk_pki_primitives::runtime_api::EntityStatusResponse<AccountId>> {
			zk_pki_pallet::Pallet::<Runtime>::query_entity_status(address)
		}

		fn ek_lookup(root: AccountId, ek_hash: [u8; 32]) -> Option<[u8; 32]> {
			zk_pki_pallet::Pallet::<Runtime>::query_ek_lookup(root, ek_hash)
		}

		fn certs_by_device_key(key_hash: [u8; 32]) -> sp_std::vec::Vec<[u8; 32]> {
			zk_pki_pallet::Pallet::<Runtime>::query_certs_by_device_key(key_hash)
		}

		fn chain_valid_at(thumbprint: [u8; 32], block_number: u64) -> bool {
			zk_pki_pallet::Pallet::<Runtime>::query_chain_valid_at(thumbprint, block_number)
		}

		fn cert_authentication(
			thumbprint: [u8; 32],
		) -> Option<zk_pki_primitives::runtime_api::CertAuthInfo<AccountId>> {
			zk_pki_pallet::Pallet::<Runtime>::query_cert_authentication(thumbprint)
		}

		fn cert_hip_genesis(
			thumbprint: [u8; 32],
		) -> Option<zk_pki_primitives::hip::GenesisHardwareFingerprint> {
			zk_pki_pallet::Pallet::<Runtime>::query_cert_hip_genesis(thumbprint)
		}

		fn membership_root() -> [u8; 32] {
			zk_pki_pallet::Pallet::<Runtime>::membership_root()
		}

		fn membership_root_recent(root: [u8; 32]) -> bool {
			zk_pki_pallet::Pallet::<Runtime>::membership_root_recent(&root)
		}

		fn freshness_root() -> [u8; 32] {
			zk_pki_pallet::Pallet::<Runtime>::freshness_root()
		}

		fn freshness_root_recent(root: [u8; 32]) -> bool {
			zk_pki_pallet::Pallet::<Runtime>::freshness_root_recent(&root)
		}

		fn membership_epoch() -> u32 {
			zk_pki_pallet::Pallet::<Runtime>::current_epoch()
		}

		fn membership_scope() -> u64 {
			zk_pki_pallet::Pallet::<Runtime>::membership_scope()
		}

		fn membership_witness(
			thumbprint: [u8; 32],
		) -> Option<zk_pki_primitives::runtime_api::MembershipWitnessData> {
			zk_pki_pallet::Pallet::<Runtime>::membership_witness(thumbprint)
		}

		// ── RWA witness-credential serving (v4) ──────────────────────────

		fn root_of_roots() -> [u8; 32] {
			ZkPki::root_of_roots()
		}

		fn issuer_branch(
			issuer: AccountId,
		) -> Option<zk_pki_primitives::runtime_api::IssuerRoots> {
			ZkPki::root_of_roots_witness(&issuer).map(|(index, witness_root, freshness_root, path)| {
				zk_pki_primitives::runtime_api::IssuerRoots {
					index,
					witness_root,
					freshness_root,
					path,
				}
			})
		}

		fn signed_checkpoint() -> Option<zk_pki_primitives::runtime_api::WitnessCheckpoint> {
			pallet_rostro_attestor::Pallet::<Runtime>::latest_checkpoint().map(|cp| {
				zk_pki_primitives::runtime_api::WitnessCheckpoint {
					root: cp.root,
					height: cp.height,
					sigs: cp
						.sigs
						.into_iter()
						.map(sp_core::ecdsa::Signature::from_raw)
						.collect(),
				}
			})
		}

		fn attestor_set() -> Vec<[u8; 20]> {
			pallet_rostro_attestor::Pallet::<Runtime>::attestor_addresses()
		}

		fn witness_branch(
			thumbprint: [u8; 32],
		) -> Option<zk_pki_primitives::runtime_api::WitnessBranchData<AccountId>> {
			ZkPki::witness_branch(thumbprint)
		}
	}
}

