#![cfg_attr(not(feature = "std"), no_std)]

//! Reference runtime for ZK-PKI integration testing.
//! Wires zk-pki-pallet into a minimal solochain runtime.
//! Not intended for production deployment.

pub mod proxy_validator;

use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use frame_support::{
    derive_impl,
    parameter_types,
    traits::{ConstU128, ConstU32, InstanceFilter},
};
use scale_info::TypeInfo;
use sp_runtime::traits::{BlakeTwo256, IdentityLookup};

pub type AccountId = sp_runtime::AccountId32;
pub type Balance = u128;
pub type BlockNumber = u32;

parameter_types! {
    pub const BlockHashCount: BlockNumber = 2400;
    pub const ExistentialDeposit: Balance = 1;
    // ZK-PKI pallet constants
    pub const InactivePurgePeriod: BlockNumber = 432_000; // 30 days at 6s blocks — grace period
    pub const ContractOfferTtlBlocks: BlockNumber = 7_200; // ~1 day
    pub const MaxRootTtlBlocks: BlockNumber = 13_140_000; // ~5 years at 12s blocks
    pub const MaxIssuersPerRoot: u32 = 5;
    pub const ChallengeWindowBlocks: BlockNumber = 324_000; // ~45 days
    pub const CertDeposit: Balance = 1_000_000_000_000; // 1 DOT, covers hot + cold
    pub const OfferDeposit: Balance = 100_000_000_000; // 0.1 DOT
    pub const MinRootTtlBlocks: BlockNumber = 648_000; // ~90 days at 12s blocks
    pub const MinIssuerTtlBlocks: BlockNumber = 216_000; // ~30 days at 12s blocks
    pub const TtlCheckInterval: BlockNumber = 7_200; // ~1 day — how often RPC consumers should re-query
    pub const TemplateDeposit: Balance = 10_000_000_000_000; // 10 DOT-equivalent on testnet
    pub const MaxTemplatesPerIssuer: u32 = 256;
    // Fee system constants.
    pub const ProtocolFeeBasisPoints: u32 = 1_000; // 10%
    pub const BlockCreatorCapBasisPoints: u32 = 4_000; // 40% cap on block-author tip
    pub const DepositBasisPoints: u32 = 500; // 5% of mint fee
    pub const MinDeposit: Balance = 100_000_000_000; // 0.1 DOT floor
    pub const MintFeePoP: Balance = 1_000_000_000_000; // 1 DOT
    pub const MintFeePacked: Balance = 1_500_000_000_000; // 1.5 DOT
    pub const MintFeeNone: Balance = 2_000_000_000_000; // 2 DOT
    // Integration-test runtime: protocol fees sink to a fixed
    // placeholder account — no governance controller wired in.
    // Real runtimes point this at a sovereign account.
    pub ProtocolFeeRecipient: AccountId = AccountId::new([0xFEu8; 32]);
}

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Runtime {
    type Block = frame_system::mocking::MockBlock<Runtime>;
    type AccountId = AccountId;
    type Lookup = IdentityLookup<AccountId>;
    type AccountData = pallet_balances::AccountData<Balance>;
}

/// Filter type for `pallet_proxy`. We accept any proxy — the
/// integration-test runtime doesn't restrict delegated calls by
/// category. A real node runtime would enumerate allowed call
/// categories here (balances-only, governance-only, etc.).
#[derive(
    Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Encode, Decode, DecodeWithMemTracking,
    MaxEncodedLen, TypeInfo, Debug, Default,
)]
pub enum ProxyType {
    #[default]
    Any,
}

impl InstanceFilter<RuntimeCall> for ProxyType {
    fn filter(&self, _call: &RuntimeCall) -> bool {
        match self {
            ProxyType::Any => true,
        }
    }
}

impl pallet_proxy::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type RuntimeCall = RuntimeCall;
    type Currency = Balances;
    type ProxyType = ProxyType;
    type ProxyDepositBase = ConstU128<0>;
    type ProxyDepositFactor = ConstU128<0>;
    type MaxProxies = ConstU32<32>;
    type WeightInfo = ();
    type MaxPending = ConstU32<32>;
    type CallHasher = BlakeTwo256;
    type AnnouncementDepositBase = ConstU128<0>;
    type AnnouncementDepositFactor = ConstU128<0>;
    type BlockNumberProvider = frame_system::Pallet<Runtime>;
}

impl pallet_balances::Config for Runtime {
    type Balance = Balance;
    type DustRemoval = ();
    type RuntimeEvent = RuntimeEvent;
    type ExistentialDeposit = ExistentialDeposit;
    type AccountStore = System;
    type WeightInfo = ();
    type MaxLocks = ConstU32<50>;
    type MaxReserves = ConstU32<50>;
    type ReserveIdentifier = [u8; 8];
    type RuntimeHoldReason = RuntimeHoldReason;
    type RuntimeFreezeReason = ();
    type FreezeIdentifier = ();
    type MaxFreezes = ConstU32<0>;
    type DoneSlashHandler = ();
}

impl zk_pki_pallet::Config for Runtime {
    type InactivePurgePeriod = InactivePurgePeriod;
    type ContractOfferTtlBlocks = ContractOfferTtlBlocks;
    type MaxRootTtlBlocks = MaxRootTtlBlocks;
    type MaxIssuersPerRoot = MaxIssuersPerRoot;
    type ChallengeWindowBlocks = ChallengeWindowBlocks;
    type CertDeposit = CertDeposit;
    type OfferDeposit = OfferDeposit;
    type MinRootTtlBlocks = MinRootTtlBlocks;
    type MinIssuerTtlBlocks = MinIssuerTtlBlocks;
    type TtlCheckInterval = TtlCheckInterval;
    type RuntimeHoldReason = RuntimeHoldReason;
    type Currency = Balances;
    type FindAuthor = (); // Test runtime: no block author → tip rolls to protocol recipient.
    type ProtocolFeeRecipient = ProtocolFeeRecipient;
    type ProtocolFeeBasisPoints = ProtocolFeeBasisPoints;
    type BlockCreatorCapBasisPoints = BlockCreatorCapBasisPoints;
    type DepositBasisPoints = DepositBasisPoints;
    type MinDeposit = MinDeposit;
    type MintFeePoP = MintFeePoP;
    type MintFeePacked = MintFeePacked;
    type MintFeeNone = MintFeeNone;
    // Integration-test runtime: wire the Tpm-returning test verifier
    // so PoP-capability tests on `register_root` /
    // `issue_issuer_cert` can exercise the happy path. The verifier
    // derives a per-call-unique EK hash from `(pubkey, challenge)`,
    // so multiple registrations in one test do not collide at the EK
    // dedup gate. Production runtime uses a real TPM verifier.
    type Attestation = zk_pki_primitives::traits::TpmTestAttestationVerifier;
    // Integration-test runtime: wire the bypass-crypto verifier so
    // pallet tests can exercise `mint_cert`'s Ok path without being
    // blocked by the placeholder `DOTWAVE_SIGNING_CERT_HASH`
    // constant. Mainnet runtime uses
    // `zk_pki_tpm::ProductionBindingProofVerifier`.
    type BindingProofVerifier = zk_pki_tpm::test_mock_verifier::NoopBindingProofVerifier;
    type TemplateDeposit = TemplateDeposit;
    type MaxTemplatesPerIssuer = MaxTemplatesPerIssuer;
    // Zero-cost weights for the integration-test runtime — test
    // behaviour must stay decoupled from the placeholder production
    // weights in `zk_pki_pallet::weights::SubstrateWeight`.
    type WeightInfo = zk_pki_pallet::weights::UnitTestWeight;
    // Integration-test runtime wires the no-op validator so existing
    // tests (which don't configure real `pallet_proxy::Proxies`
    // entries) keep passing. Production runtimes should bind
    // `proxy_validator::PalletProxyValidator<Runtime>` instead.
    type ProxyValidator = zk_pki_primitives::proxy::NoopProxyValidator;
}

frame_support::construct_runtime!(
    pub enum Runtime {
        System: frame_system,
        Balances: pallet_balances,
        Proxy: pallet_proxy,
        ZkPki: zk_pki_pallet,
    }
);
