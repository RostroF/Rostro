//! Stage 3 smoke test — end-to-end proof generation and verification.
//!
//! Produces a valid proof via ark-circom, verifies it via the
//! production-shaped `verify_proof` function, and sanity-checks
//! tamper rejection by mutating public inputs.
//!
//! If this test passes, the `verify_proof` API is correct and
//! ready to be extracted into a Substrate pallet.

use std::path::PathBuf;

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use zkpki_verifier_lab::{
    deserialize_vk, generate_sample_proof, prepare_vk, serialize_vk, verify_proof,
};

fn fixture(name: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("fixtures");
    p.push(name);
    p
}

#[test]
fn mime_wrap_round_trip() {
    let sample = generate_sample_proof(
        fixture("mime_wrap.wasm"),
        fixture("mime_wrap.r1cs"),
        fixture("mime_wrap_final.zkey"),
    )
    .expect("sample proof generation failed");

    println!("[diag] proof_bytes.len() = {}", sample.proof_bytes.len());
    println!("[diag] public_inputs.len() = {}", sample.public_inputs.len());
    println!("[diag] vk.gamma_abc_g1.len() = {}", sample.vk.gamma_abc_g1.len());
    println!(
        "[diag] constraints_satisfied = {} ({} constraints total)",
        sample.constraints_satisfied, sample.num_constraints
    );
    println!(
        "[diag] first 8 public inputs = {:?}",
        sample
            .public_inputs
            .iter()
            .take(8)
            .map(|f| format!("{f:?}"))
            .collect::<Vec<_>>()
    );

    let pvk = prepare_vk(&sample.vk);

    // ── Try three verify paths to narrow down where it fails ─────
    // Path A: the production-shaped verify_proof (deserialize + processed vk)
    let a_ok = verify_proof(&sample.proof_bytes, &sample.public_inputs, &pvk)
        .expect("Path A verify returned Err for a well-formed proof");
    println!("[diag] Path A (verify_proof with pvk): {a_ok}");

    // Path B: Groth16::verify_with_processed_vk directly on in-memory Proof
    let proof_inmem =
        Proof::<Bn254>::deserialize_compressed(sample.proof_bytes.as_slice()).unwrap();
    let b_ok = Groth16::<Bn254>::verify_with_processed_vk(
        &pvk,
        &sample.public_inputs,
        &proof_inmem,
    )
    .unwrap();
    println!("[diag] Path B (verify_with_processed_vk, inmem): {b_ok}");

    // Path C: full Groth16::verify (non-prepared). If this gives a different
    // answer than Path A/B, the issue is in prepare_verifying_key.
    let c_ok = Groth16::<Bn254>::verify(&sample.vk, &sample.public_inputs, &proof_inmem)
        .unwrap();
    println!("[diag] Path C (Groth16::verify raw): {c_ok}");

    assert!(a_ok, "valid proof failed to verify (Path A)");
    assert!(b_ok, "valid proof failed to verify (Path B)");
    assert!(c_ok, "valid proof failed to verify (Path C)");

    // ── Tampered public input rejected ───────────────────────────
    let mut tampered = sample.public_inputs.clone();
    tampered[0] += Fr::from(1u64);
    let ok = verify_proof(&sample.proof_bytes, &tampered, &pvk)
        .expect("verify_proof returned Err for a tampered-but-well-formed call");
    assert!(!ok, "tampered public input was accepted as valid");

    // ── VK serialize round-trip ──────────────────────────────────
    let vk_bytes = serialize_vk(&sample.vk).unwrap();
    let vk_back = deserialize_vk(&vk_bytes).unwrap();
    let pvk2 = prepare_vk(&vk_back);
    let ok = verify_proof(&sample.proof_bytes, &sample.public_inputs, &pvk2).unwrap();
    assert!(ok, "proof verification failed after VK round-trip");
}
