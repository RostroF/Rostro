//! Proxy-validation integration tests.
//!
//! Exercises two paths:
//!
//! - **Positive** against the production `zk_pki_runtime::Runtime`
//!   (which binds `NoopProxyValidator`) — `register_root` and
//!   `issue_issuer_cert` succeed when the validator returns true.
//! - **Negative** against a local mock runtime (`RejectTest`) that
//!   rebinds `type ProxyValidator = RejectAllProxyValidator` —
//!   same extrinsics fail with `ProxyNotFound`.
//!
//! The mock runtime duplicates the pallet Config wiring so the
//! validator swap is the only axis of difference. Every other type
//! mirrors `zk_pki_runtime::Runtime`.

use codec::Encode;
use frame_support::{
    assert_noop, assert_ok, construct_runtime, derive_impl, parameter_types,
    traits::ConstU32, BoundedVec,
};
use sp_core::crypto::AccountId32;
use sp_runtime::{traits::IdentityLookup, BuildStorage};
use zk_pki_primitives::crypto::DevicePublicKey;
use zk_pki_primitives::eku::Eku;
use zk_pki_runtime::test_serial;

// ──────────────────────────────────────────────────────────────────────
// Fixtures shared across both runtimes
// ──────────────────────────────────────────────────────────────────────

const ROOT_ACCOUNT: [u8; 32] = [0xA1; 32];
const ISSUER_ACCOUNT: [u8; 32] = [0xB2; 32];
const ROOT_PROXY: [u8; 32] = [0xD4; 32];
const ISSUER_PROXY: [u8; 32] = [0xE5; 32];
const INITIAL_BALANCE: u128 = 100_000_000_000_000;

fn account(seed: [u8; 32]) -> AccountId32 {
    AccountId32::from(seed)
}

fn test_cert_ec_pubkey() -> Vec<u8> {
    use p256::ecdsa::{SigningKey, VerifyingKey};
    let sk = SigningKey::from_slice(&[7u8; 32]).expect("valid P-256 scalar");
    let vk: VerifyingKey = *sk.verifying_key();
    vk.to_encoded_point(false).as_bytes().to_vec()
}

// ──────────────────────────────────────────────────────────────────────
// Positive path — against the production runtime (NoopProxyValidator)
// ──────────────────────────────────────────────────────────────────────

mod positive {
    use super::*;
    use zk_pki_runtime::{Runtime, RuntimeOrigin, ZkPki, test_serial};

    fn new_test_ext() -> sp_io::TestExternalities {
        let mut t = frame_system::GenesisConfig::<Runtime>::default()
            .build_storage()
            .unwrap();
        pallet_balances::GenesisConfig::<Runtime> {
            balances: vec![
                (account(ROOT_ACCOUNT), INITIAL_BALANCE),
                (account(ROOT_PROXY), INITIAL_BALANCE),
                (account(ISSUER_ACCOUNT), INITIAL_BALANCE),
                (account(ISSUER_PROXY), INITIAL_BALANCE),
            ],
            dev_accounts: None,
        }
        .assimilate_storage(&mut t)
        .unwrap();
        t.into()
    }

    fn run<R>(f: impl FnOnce() -> R) -> R {
        new_test_ext().execute_with(|| {
            frame_system::Pallet::<Runtime>::set_block_number(1);
            f()
        })
    }

    #[test]
    fn register_root_valid_proxy_succeeds() {
        run(|| {
            let pubkey =
                DevicePublicKey::new_p256(&test_cert_ec_pubkey()).unwrap();
            let empty_att: BoundedVec<_, _> = BoundedVec::try_from(vec![]).unwrap();
            let empty_ekus: BoundedVec<Eku, ConstU32<8>> =
                BoundedVec::try_from(vec![]).unwrap();
            assert_ok!(ZkPki::register_root(
                RuntimeOrigin::signed(account(ROOT_ACCOUNT)),
                account(ROOT_PROXY),
                pubkey,
                empty_att,
                1_000_000u64,
                empty_ekus,
            
                test_serial(1),
            ));
        });
    }

    #[test]
    fn issue_issuer_cert_valid_proxy_succeeds() {
        run(|| {
            let pubkey =
                DevicePublicKey::new_p256(&test_cert_ec_pubkey()).unwrap();
            let empty_att: BoundedVec<_, _> = BoundedVec::try_from(vec![]).unwrap();
            let empty_ekus: BoundedVec<Eku, ConstU32<8>> =
                BoundedVec::try_from(vec![]).unwrap();
            assert_ok!(ZkPki::register_root(
                RuntimeOrigin::signed(account(ROOT_ACCOUNT)),
                account(ROOT_PROXY),
                pubkey.clone(),
                empty_att.clone(),
                1_000_000u64,
                empty_ekus.clone(),
            
                test_serial(2),
            ));
            assert_ok!(ZkPki::issue_issuer_cert(
                RuntimeOrigin::signed(account(ROOT_ACCOUNT)),
                account(ISSUER_ACCOUNT),
                account(ISSUER_PROXY),
                pubkey,
                empty_att,
                500_000u64,
                empty_ekus,
            
                test_serial(3),
            ));
        });
    }
}

// ──────────────────────────────────────────────────────────────────────
// Negative path — local mock runtime with RejectAllProxyValidator
// ──────────────────────────────────────────────────────────────────────

mod negative {
    use super::*;

    pub type AccountId = AccountId32;
    pub type Balance = u128;
    pub type BlockNumber = u64;

    parameter_types! {
        pub const BlockHashCount: BlockNumber = 2400;
        pub const ExistentialDeposit: Balance = 1;
        pub const InactivePurgePeriod: BlockNumber = 432_000;
        pub const ContractOfferTtlBlocks: BlockNumber = 7_200;
        pub const MaxRootTtlBlocks: BlockNumber = 13_140_000;
        pub const MaxIssuersPerRoot: u32 = 5;
        pub const ChallengeWindowBlocks: BlockNumber = 324_000;
        pub const CertDeposit: Balance = 1_000_000_000_000;
        pub const OfferDeposit: Balance = 100_000_000_000;
        pub const MinRootTtlBlocks: BlockNumber = 648_000;
        pub const MinIssuerTtlBlocks: BlockNumber = 216_000;
        pub const TtlCheckInterval: BlockNumber = 7_200;
        pub const TemplateDeposit: Balance = 10_000_000_000_000;
        pub const MaxTemplatesPerIssuer: u32 = 256;
        pub const ProtocolFeeBasisPoints: u32 = 1_000;
        pub const BlockCreatorCapBasisPoints: u32 = 4_000;
        pub const DepositBasisPoints: u32 = 500;
        pub const MinDeposit: Balance = 100_000_000_000;
        pub const MintFeePoP: Balance = 1_000_000_000_000;
        pub const MintFeePacked: Balance = 1_500_000_000_000;
        pub const MintFeeNone: Balance = 2_000_000_000_000;
        pub ProtocolFeeRecipient: AccountId = AccountId::new([0xFEu8; 32]);
    }

    #[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
    impl frame_system::Config for RejectTest {
        type Block = frame_system::mocking::MockBlock<RejectTest>;
        type AccountId = AccountId;
        type Lookup = IdentityLookup<AccountId>;
        type AccountData = pallet_balances::AccountData<Balance>;
    }

    impl pallet_balances::Config for RejectTest {
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

    impl zk_pki_pallet::Config for RejectTest {
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
        type FindAuthor = ();
        type ProtocolFeeRecipient = ProtocolFeeRecipient;
        type ProtocolFeeBasisPoints = ProtocolFeeBasisPoints;
        type BlockCreatorCapBasisPoints = BlockCreatorCapBasisPoints;
        type DepositBasisPoints = DepositBasisPoints;
        type MinDeposit = MinDeposit;
        type MintFeePoP = MintFeePoP;
        type MintFeePacked = MintFeePacked;
        type MintFeeNone = MintFeeNone;
        type Attestation = zk_pki_primitives::traits::TpmTestAttestationVerifier;
        type BindingProofVerifier =
            zk_pki_tpm::test_mock_verifier::NoopBindingProofVerifier;
        type TemplateDeposit = TemplateDeposit;
        type MaxTemplatesPerIssuer = MaxTemplatesPerIssuer;
        type WeightInfo = zk_pki_pallet::weights::UnitTestWeight;
        // The one axis this mock exists to exercise: reject all.
        type ProxyValidator = zk_pki_primitives::proxy::RejectAllProxyValidator;
    }

    construct_runtime!(
        pub enum RejectTest {
            System: frame_system,
            Balances: pallet_balances,
            ZkPki: zk_pki_pallet,
        }
    );

    fn new_test_ext() -> sp_io::TestExternalities {
        let mut t = frame_system::GenesisConfig::<RejectTest>::default()
            .build_storage()
            .unwrap();
        pallet_balances::GenesisConfig::<RejectTest> {
            balances: vec![
                (account(ROOT_ACCOUNT), INITIAL_BALANCE),
                (account(ROOT_PROXY), INITIAL_BALANCE),
                (account(ISSUER_ACCOUNT), INITIAL_BALANCE),
                (account(ISSUER_PROXY), INITIAL_BALANCE),
            ],
            dev_accounts: None,
        }
        .assimilate_storage(&mut t)
        .unwrap();
        t.into()
    }

    fn run<R>(f: impl FnOnce() -> R) -> R {
        new_test_ext().execute_with(|| {
            frame_system::Pallet::<RejectTest>::set_block_number(1);
            f()
        })
    }

    #[test]
    fn register_root_invalid_proxy_rejected() {
        run(|| {
            let pubkey =
                DevicePublicKey::new_p256(&test_cert_ec_pubkey()).unwrap();
            let empty_att: BoundedVec<_, _> = BoundedVec::try_from(vec![]).unwrap();
            let empty_ekus: BoundedVec<Eku, ConstU32<8>> =
                BoundedVec::try_from(vec![]).unwrap();
            assert_noop!(
                ZkPki::register_root(
                    RuntimeOrigin::signed(account(ROOT_ACCOUNT)),
                    account(ROOT_PROXY),
                    pubkey,
                    empty_att,
                    1_000_000u64,
                    empty_ekus,
                
                    test_serial(4),
                ),
                zk_pki_pallet::Error::<RejectTest>::ProxyNotFound,
            );
        });
    }

    #[test]
    fn issue_issuer_cert_invalid_proxy_rejected() {
        run(|| {
            // To reach `issue_issuer_cert`'s proxy check we first need
            // a successfully-registered root — but the RejectAll
            // validator refuses register_root too. Seed `Roots`
            // storage directly to bypass that and target the
            // issue_issuer_cert check specifically.
            //
            // This mirrors how FRAME benchmarks seed precondition
            // state via direct storage writes.
            use zk_pki_pallet::Roots;
            use zk_pki_primitives::issuer::{EntityState, RootRecord};
            // Also seed the root's cert so `issue_issuer_cert`'s
            // parent-cert lookup succeeds before it reaches the proxy
            // check. A minimal hot record suffices for the reach.
            use zk_pki_pallet::CertLookupHot;
            use zk_pki_primitives::cert::{
                CertState, CURRENT_SCHEMA_VERSION,
            };
            use zk_pki_primitives::tpm::AttestationType;
            let root_thumb = [0x11u8; 32];
            CertLookupHot::<RejectTest>::insert(
                root_thumb,
                zk_pki_pallet::CertRecordHot {
                    schema_version: CURRENT_SCHEMA_VERSION,
                    thumbprint: root_thumb,
                    root: account(ROOT_ACCOUNT),
                    issuer: account(ROOT_ACCOUNT),
                    user: account(ROOT_ACCOUNT),
                    mint_block: 1u64,
                    expiry_block: 10_000_000u64,
                    state: CertState::Active,
                    ek_hash: None,
                    attestation_type: AttestationType::None,
                    manufacturer_verified: false,
                    template_name: BoundedVec::default(),
                    ekus: BoundedVec::default(),
                    pop_mechanism: None,
                },
            );
            Roots::<RejectTest>::insert(
                account(ROOT_ACCOUNT),
                RootRecord {
                    proxy: account(ROOT_PROXY),
                    cert_thumbprint: root_thumb,
                    registered_at: 1u64,
                    state: EntityState::Active,
                    challenge_used: false,
                    capability_ekus: BoundedVec::default(),
                },
            );
            let pubkey =
                DevicePublicKey::new_p256(&test_cert_ec_pubkey()).unwrap();
            let empty_att: BoundedVec<_, _> = BoundedVec::try_from(vec![]).unwrap();
            let empty_ekus: BoundedVec<Eku, ConstU32<8>> =
                BoundedVec::try_from(vec![]).unwrap();
            assert_noop!(
                ZkPki::issue_issuer_cert(
                    RuntimeOrigin::signed(account(ROOT_ACCOUNT)),
                    account(ISSUER_ACCOUNT),
                    account(ISSUER_PROXY),
                    pubkey,
                    empty_att,
                    500_000u64,
                    empty_ekus,
                
                    test_serial(5),
                ),
                zk_pki_pallet::Error::<RejectTest>::ProxyNotFound,
            );
        });
    }

    #[test]
    fn reject_all_validator_unit_test() {
        use zk_pki_primitives::proxy::{RejectAllProxyValidator, ValidateProxy};
        let a = account([0u8; 32]);
        let b = account([1u8; 32]);
        assert!(!RejectAllProxyValidator::has_proxy(&a, &b));
    }
}

// Suppress unused-Encode warning on the import — `Encode` is pulled
// in via `DevicePublicKey` / EKU serialization paths in some fixture
// helpers the compiler doesn't always see through.
#[allow(dead_code)]
fn _unused_encode() {
    let _ = [0u8; 32].encode();
}
