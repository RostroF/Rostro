use super::*;
use ark_relations::r1cs::ConstraintSystem;
use rostro_membership_tree::{authentication_path, empty_roots, update, MemoryStore};
use rostro_poseidon_bn254::{hash_leaf, id_commitment, nullifier, params, PoseidonField};

type F = PoseidonField;

fn index_to_bits(index: u64) -> Vec<bool> {
    (0..DEPTH).map(|i| (index >> i) & 1 == 1).collect()
}

/// Build a fully-consistent valid witness: a cert enrolled at `index` with a
/// membership leaf in R_m, a freshness leaf in R_f, fresh through epoch 20,
/// expiring at block 5000, proven at epoch 15 / anchor block 4000.
fn valid_circuit() -> MembershipCircuit {
    let p = params();
    let empties = empty_roots(&p);
    let index = 5u64;

    let s = F::from(987_654_321u64);
    let expiry_block = F::from(5000u64);
    let scope = F::from(1u64);
    let idc = id_commitment(&p, s);
    let m_leaf = hash_leaf(&p, idc, expiry_block, scope);

    let mut m_store = MemoryStore::new();
    let m_root = update(&mut m_store, &p, &empties, index, m_leaf);
    let m_path = authentication_path(&m_store, &empties, index).to_vec();

    let fresh_until = F::from(20u64);
    let mut f_store = MemoryStore::new();
    let f_root = update(&mut f_store, &p, &empties, index, fresh_until);
    let f_path = authentication_path(&f_store, &empties, index).to_vec();

    let current_epoch = F::from(15u64);
    let anchor_block = F::from(4000u64);
    let n = nullifier(&p, s, current_epoch);

    MembershipCircuit {
        membership_root: Some(m_root),
        freshness_root: Some(f_root),
        nullifier: Some(n),
        current_epoch: Some(current_epoch),
        anchor_block: Some(anchor_block),
        scope: Some(scope),
        challenge: Some(F::from(0xCAFEu64)),
        session_pubkey: Some(F::from(0xBEEFu64)),
        s: Some(s),
        expiry_block: Some(expiry_block),
        fresh_until_epoch: Some(fresh_until),
        index_bits: Some(index_to_bits(index)),
        membership_path: Some(m_path),
        freshness_path: Some(f_path),
    }
}

fn satisfied(c: MembershipCircuit) -> bool {
    let cs = ConstraintSystem::<F>::new_ref();
    c.generate_constraints(cs.clone()).unwrap();
    cs.is_satisfied().unwrap()
}

#[test]
fn valid_proof_satisfies() {
    let c = valid_circuit();
    let cs = ConstraintSystem::<F>::new_ref();
    c.generate_constraints(cs.clone()).unwrap();
    assert!(cs.is_satisfied().unwrap());
    // 8 public inputs + the constant `1`.
    assert_eq!(cs.num_instance_variables(), 9);
}

#[test]
fn wrong_secret_fails() {
    // A different `s` breaks both id_commitment→membership and the nullifier.
    let mut c = valid_circuit();
    c.s = Some(F::from(111u64));
    assert!(!satisfied(c));
}

#[test]
fn tampered_membership_path_fails() {
    let mut c = valid_circuit();
    let mut path = c.membership_path.take().unwrap();
    path[0] += F::from(1u64);
    c.membership_path = Some(path);
    assert!(!satisfied(c));
}

#[test]
fn wrong_membership_root_fails() {
    let mut c = valid_circuit();
    c.membership_root = Some(F::from(12345u64));
    assert!(!satisfied(c));
}

#[test]
fn tampered_freshness_path_fails() {
    let mut c = valid_circuit();
    let mut path = c.freshness_path.take().unwrap();
    path[0] += F::from(1u64);
    c.freshness_path = Some(path);
    assert!(!satisfied(c));
}

#[test]
fn nullifier_mismatch_fails() {
    let mut c = valid_circuit();
    c.nullifier = Some(F::from(999u64));
    assert!(!satisfied(c));
}

#[test]
fn stale_freshness_fails() {
    // current_epoch (25) > fresh_until (20): stale. Recompute the nullifier
    // for the new epoch so the ONLY failing constraint is the freshness check.
    let p = params();
    let mut c = valid_circuit();
    let new_epoch = F::from(25u64);
    c.current_epoch = Some(new_epoch);
    c.nullifier = Some(nullifier(&p, c.s.unwrap(), new_epoch));
    assert!(!satisfied(c));
}

#[test]
fn fresh_exactly_at_current_epoch_ok() {
    // fresh_until == current_epoch is still fresh (inclusive). Rebuild the
    // freshness tree so the leaf equals current_epoch (15).
    let p = params();
    let empties = empty_roots(&p);
    let index = 5u64;
    let mut c = valid_circuit();
    let fresh = F::from(15u64);
    let mut f_store = MemoryStore::new();
    let f_root = update(&mut f_store, &p, &empties, index, fresh);
    c.fresh_until_epoch = Some(fresh);
    c.freshness_root = Some(f_root);
    c.freshness_path = Some(authentication_path(&f_store, &empties, index).to_vec());
    assert!(satisfied(c));
}

#[test]
fn expired_cert_fails() {
    // anchor_block (6000) >= expiry_block (5000): expired. anchor_block feeds
    // only the expiry check, so this isolates it.
    let mut c = valid_circuit();
    c.anchor_block = Some(F::from(6000u64));
    assert!(!satisfied(c));
}

#[test]
fn anchor_just_below_expiry_ok() {
    // anchor 4999 < expiry 5000: still valid (strict <).
    let mut c = valid_circuit();
    c.anchor_block = Some(F::from(4999u64));
    assert!(satisfied(c));
}

#[test]
fn anchor_equal_expiry_fails() {
    // anchor == expiry is expired (strict <).
    let mut c = valid_circuit();
    c.anchor_block = Some(F::from(5000u64));
    assert!(!satisfied(c));
}

#[test]
fn wrong_index_fails() {
    // Proving the leaf at a different index than where it sits breaks both
    // Merkle paths against their roots.
    let mut c = valid_circuit();
    c.index_bits = Some(index_to_bits(6));
    assert!(!satisfied(c));
}

#[cfg(feature = "groth16")]
#[test]
fn groth16_roundtrip_and_measure() {
    use crate::groth16;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use std::time::Instant;

    // Constraint count (proving cost driver).
    let cs = ConstraintSystem::<F>::new_ref();
    valid_circuit().generate_constraints(cs.clone()).unwrap();
    let n_constraints = cs.num_constraints();

    let mut rng = StdRng::seed_from_u64(42);

    let t = Instant::now();
    let (pk, vk) = groth16::setup(&mut rng);
    let setup_ms = t.elapsed().as_millis();

    // Prove (single-threaded; a per-session phone-cost proxy). Average a few.
    let runs = 5u32;
    let t = Instant::now();
    let mut last = None;
    for _ in 0..runs {
        last = groth16::prove(&pk, valid_circuit(), &mut rng);
    }
    let prove_ms = t.elapsed().as_millis() as f64 / runs as f64;
    let proof = last.expect("proof");

    let inputs = groth16::public_inputs(&valid_circuit()).unwrap();
    let t = Instant::now();
    let ok = groth16::verify(&vk, &inputs, &proof);
    let verify_us = t.elapsed().as_micros();
    assert!(ok, "valid proof must verify");

    // A tampered public input (wrong nullifier) must fail.
    let mut bad = inputs;
    bad[2] += F::from(1u64);
    assert!(!groth16::verify(&vk, &bad, &proof), "tampered input must fail");

    // Serialization roundtrips (wire proof + pinned vk).
    let proof_bytes = groth16::serialize_proof(&proof);
    let vk_bytes = groth16::serialize_vk(&vk);
    let proof2 = groth16::deserialize_proof(&proof_bytes).expect("proof roundtrip");
    let vk2 = groth16::deserialize_vk(&vk_bytes).expect("vk roundtrip");
    assert!(groth16::verify(&vk2, &inputs, &proof2), "roundtripped proof verifies");

    println!("\n=== MEMBERSHIP CIRCUIT — Groth16 / BN254 (single-threaded) ===");
    println!("  constraints : {n_constraints}");
    println!("  setup       : {setup_ms} ms");
    println!("  prove       : {prove_ms:.1} ms  (avg of {runs})");
    println!("  verify      : {verify_us} us");
    println!("  proof size  : {} bytes", proof_bytes.len());
    println!("  vk size     : {} bytes", vk_bytes.len());
    println!("==============================================================\n");
}
