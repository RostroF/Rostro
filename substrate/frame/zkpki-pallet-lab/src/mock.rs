//! Minimal mock runtime for Stage 4a pallet integration tests.
//!
//! Provides a single-pallet runtime (zkpki-pallet-lab only), a test
//! externality builder, and a helper to construct an origin for the
//! "root" user (needed for `set_verifying_key`).

use crate as pallet_zkpki;
use frame_support::{derive_impl, parameter_types};
use sp_core::H256;
use sp_runtime::{BuildStorage, traits::IdentityLookup};

type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
    pub enum Test {
        System: frame_system,
        ZkPki: pallet_zkpki,
    }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
    type AccountId = u64;
    type Lookup = IdentityLookup<Self::AccountId>;
    type AccountData = ();
    type Hash = H256;
}

parameter_types! {
    pub const MaxConsumedNonces: u32 = 10_000;
}

impl pallet_zkpki::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type MaxConsumedNonces = MaxConsumedNonces;
}

/// Build a new test externality with empty storage. Tests that need
/// a preloaded VK call `install_vk(&mut t, vk_bytes)` after this.
pub fn new_test_ext() -> sp_io::TestExternalities {
    frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap()
        .into()
}

/// Convenience: fixed test account id used across tests.
pub const ALICE: u64 = 1;

/// Deterministic 32-byte ec_key_pub for fixture tests. Not a real
/// P-256 pubkey — we don't need cryptographic correctness of the
/// ec_key value, just consistent bytes to feed into the circuit.
pub fn fixture_ec_key_pub() -> [u8; 32] {
    let mut buf = [0u8; 32];
    for (i, b) in buf.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(13);
    }
    buf
}

/// Deterministic 32-byte seed for fixture tests.
pub fn fixture_seed() -> [u8; 32] {
    let mut buf = [0u8; 32];
    for (i, b) in buf.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(11).wrapping_add(47);
    }
    buf
}

/// Produce the sha256 commitment used by the circuit's C1 constraint.
pub fn compute_commitment(ec_key_pub: &[u8; 32], seed: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(ec_key_pub);
    h.update(seed);
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// Compute the 24-bit user_otp that C2 expects for a given (seed, bucket).
pub fn compute_user_otp(seed: &[u8; 32], bucket: u64) -> u32 {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(seed);
    h.update(bucket.to_be_bytes());
    let d = h.finalize();
    // OTP is the last 24 bits of the 256-bit digest, big-endian —
    // i.e., bytes [29, 30, 31] packed MSB-first into a u32's low-24.
    ((d[29] as u32) << 16) | ((d[30] as u32) << 8) | (d[31] as u32)
}

