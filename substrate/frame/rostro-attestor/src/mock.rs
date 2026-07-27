//! Mock runtime for the attestor pallet. The `CheckpointProvider` and
//! `AttestorRegistry` are backed by thread-locals so tests can set the current
//! root, attestor set, and threshold.

use crate as pallet_rostro_attestor;
use crate::{AttestorRegistry, CheckpointProvider, EthAddress};
use frame_support::{derive_impl, traits::ConstU32};
use sp_runtime::BuildStorage;
use std::cell::RefCell;

type Block = frame_system::mocking::MockBlock<Test>;
/// Extrinsic type for the offchain unsigned-tx submission path (the pallet's
/// `CreateBare` supertrait requires it; the offchain-worker test decodes it).
pub type Extrinsic = sp_runtime::testing::TestXt<RuntimeCall, ()>;

frame_support::construct_runtime!(
    pub enum Test {
        System: frame_system,
        Attestor: pallet_rostro_attestor,
    }
);

impl<LocalCall> frame_system::offchain::CreateTransactionBase<LocalCall> for Test
where
    RuntimeCall: From<LocalCall>,
{
    type RuntimeCall = RuntimeCall;
    type Extrinsic = Extrinsic;
}

impl<LocalCall> frame_system::offchain::CreateBare<LocalCall> for Test
where
    RuntimeCall: From<LocalCall>,
{
    fn create_bare(call: Self::RuntimeCall) -> Self::Extrinsic {
        Extrinsic::new_bare(call)
    }
}

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
}

impl pallet_rostro_attestor::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type Checkpoint = MockCheckpoint;
    type Attestors = MockAttestors;
    type MaxAttestors = ConstU32<32>;
    type RecentWindow = ConstU32<10>;
}

thread_local! {
    static TEST_ROOT: RefCell<[u8; 32]> = const { RefCell::new([0u8; 32]) };
    static TEST_ATTESTORS: RefCell<Vec<EthAddress>> = const { RefCell::new(Vec::new()) };
    static TEST_THRESHOLD: RefCell<u32> = const { RefCell::new(1) };
}

pub fn set_root(r: [u8; 32]) {
    TEST_ROOT.with(|x| *x.borrow_mut() = r);
}
pub fn set_attestors(a: Vec<EthAddress>) {
    TEST_ATTESTORS.with(|x| *x.borrow_mut() = a);
}
pub fn set_threshold(t: u32) {
    TEST_THRESHOLD.with(|x| *x.borrow_mut() = t);
}

pub struct MockCheckpoint;
impl CheckpointProvider for MockCheckpoint {
    fn root() -> [u8; 32] {
        TEST_ROOT.with(|r| *r.borrow())
    }
}

pub struct MockAttestors;
impl AttestorRegistry for MockAttestors {
    fn attestors() -> Vec<EthAddress> {
        TEST_ATTESTORS.with(|a| a.borrow().clone())
    }
    fn threshold() -> u32 {
        TEST_THRESHOLD.with(|t| *t.borrow())
    }
}

pub fn new_test_ext() -> sp_io::TestExternalities {
    let t = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();
    let mut ext: sp_io::TestExternalities = t.into();
    ext.execute_with(|| System::set_block_number(1));
    ext
}

/// Advance to block `n`, running `on_finalize` for each block so `RecentRoots`
/// records the checkpoint root at each height.
pub fn run_to_block(n: u64) {
    use frame_support::traits::OnFinalize;
    while System::block_number() < n {
        let b = System::block_number();
        Attestor::on_finalize(b);
        System::on_finalize(b);
        System::set_block_number(b + 1);
    }
}
