//! TEST-ONLY trusted-setup harness: emit a matched (pk, vk) pair for the
//! membership circuit so the smoke test can pin a vk in the node and ship the
//! pk to the phone prover.
//!
//! This is NOT the mainnet ceremony. `setup_test_keys` uses a deterministic
//! single-party RNG; the toxic waste is not destroyed, so a holder of these
//! keys could forge proofs. Acceptable for a dev/testnet smoke test where the
//! membership trie is open during collection (D10), never for mainnet.
//!
//! Usage:
//!   cargo run -p rostro-membership-circuit --features groth16 \
//!     --example setup_test_keys -- <out_dir>
//!
//! Writes `<out_dir>/membership_vk.bin` and `<out_dir>/membership_pk.bin`.

use std::path::PathBuf;

use rostro_membership_circuit::groth16::setup_test_keys;

fn main() {
    let out_dir = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    std::fs::create_dir_all(&out_dir).expect("create out dir");

    let (pk_bytes, vk_bytes) = setup_test_keys();

    let vk_path = out_dir.join("membership_vk.bin");
    let pk_path = out_dir.join("membership_pk.bin");
    std::fs::write(&vk_path, &vk_bytes).expect("write vk");
    std::fs::write(&pk_path, &pk_bytes).expect("write pk");

    eprintln!("TEST-ONLY keys (deterministic; NOT a production ceremony):");
    eprintln!("  vk: {} ({} bytes)", vk_path.display(), vk_bytes.len());
    eprintln!("  pk: {} ({} bytes)", pk_path.display(), pk_bytes.len());
}
