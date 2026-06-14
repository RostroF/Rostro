//! Minimal mock runtime for `pallet-rns-resolvers` tests — the first test
//! harness for the RNS pallets. Permissive ownership (any signer may edit any
//! node) and the real `RST_BASENODE`, so `parse_name_to_node` matches the
//! production runtime.

use crate as pallet_rns_resolvers;
use frame_support::{derive_impl, traits::ConstU32};
use sp_runtime::BuildStorage;

type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
    pub enum Test {
        System: frame_system,
        RnsResolvers: pallet_rns_resolvers::resolvers,
    }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
}

/// Any signer may edit any node; base node is the real RST base node so name
/// hashing is identical to the runtime.
pub struct MockRegistryChecker;
impl pallet_rns_resolvers::resolvers::RegistryChecker for MockRegistryChecker {
    type AccountId = u64;
    fn check_node_useable(_node: rns_types::DomainHash, _owner: &u64) -> bool {
        true
    }
    fn base_node() -> rns_types::DomainHash {
        rns_types::RST_BASENODE
    }
}

impl pallet_rns_resolvers::resolvers::Config for Test {
    const OFFCHAIN_PREFIX: &'static [u8] = b"rns/";
    type WeightInfo = ();
    type MaxContentLen = ConstU32<1024>;
    type RegistryChecker = MockRegistryChecker;
}

pub fn new_test_ext() -> sp_io::TestExternalities {
    frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .expect("system genesis builds")
        .into()
}
