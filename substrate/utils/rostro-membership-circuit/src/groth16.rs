//! Groth16 setup / prove / verify for the membership circuit.
//!
//! Feature-gated (`groth16`): pulls the BN254 pairing proving machinery the
//! constraint system itself does not need. `verify`, `public_inputs`, and the
//! (de)serialization helpers are production paths (the guard verifies, the
//! runtime/guard pin the vk, the phone ships a proof). `setup` and `prove` are
//! here for the harness and a future ceremony.
//!
//! SECURITY: the single-party `setup` is TEST-ONLY. Production verifying keys
//! require a multi-party trusted-setup ceremony so the toxic waste is
//! destroyed by at least one honest participant.

use ark_bn254::{Bn254, Fr};
use ark_ff::Zero;
use ark_groth16::{prepare_verifying_key, Groth16, Proof, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};
use ark_std::{vec, vec::Vec};
use rostro_membership_tree::DEPTH;

use crate::MembershipCircuit;

/// The 8 public inputs, in the exact order the circuit allocates them. `None`
/// if any public field is unset.
pub fn public_inputs(c: &MembershipCircuit) -> Option<[Fr; 8]> {
    Some([
        c.membership_root?,
        c.freshness_root?,
        c.nullifier?,
        c.current_epoch?,
        c.anchor_block?,
        c.scope?,
        c.challenge?,
        c.session_pubkey?,
    ])
}

/// A structurally-complete, fully-assigned dummy circuit used only to drive
/// setup (which reads the constraint *shape*, not the values).
fn setup_shape() -> MembershipCircuit {
    let z = Some(Fr::zero());
    MembershipCircuit {
        membership_root: z,
        freshness_root: z,
        nullifier: z,
        current_epoch: z,
        anchor_block: z,
        scope: z,
        challenge: z,
        session_pubkey: z,
        s: z,
        expiry_block: z,
        fresh_until_epoch: z,
        index_bits: Some(vec![false; DEPTH]),
        membership_path: Some(vec![Fr::zero(); DEPTH]),
        freshness_path: Some(vec![Fr::zero(); DEPTH]),
    }
}

/// Generate proving + verifying keys for the circuit shape. TEST-ONLY RNG;
/// production needs a ceremony.
pub fn setup<R: RngCore + CryptoRng>(rng: &mut R) -> (ProvingKey<Bn254>, VerifyingKey<Bn254>) {
    Groth16::<Bn254>::circuit_specific_setup(setup_shape(), rng)
        .expect("groth16 circuit_specific_setup")
}

/// Produce a proof for a fully-assigned circuit. `None` on synthesis error.
pub fn prove<R: RngCore + CryptoRng>(
    pk: &ProvingKey<Bn254>,
    circuit: MembershipCircuit,
    rng: &mut R,
) -> Option<Proof<Bn254>> {
    Groth16::<Bn254>::prove(pk, circuit, rng).ok()
}

/// Verify a proof against its public inputs (the guard's path).
pub fn verify(vk: &VerifyingKey<Bn254>, public_inputs: &[Fr], proof: &Proof<Bn254>) -> bool {
    let pvk = prepare_verifying_key(vk);
    Groth16::<Bn254>::verify_with_processed_vk(&pvk, public_inputs, proof).unwrap_or(false)
}

/// Serialize a verifying key (compressed) for pinning.
pub fn serialize_vk(vk: &VerifyingKey<Bn254>) -> Vec<u8> {
    let mut out = Vec::new();
    vk.serialize_compressed(&mut out).expect("vk serializes");
    out
}

/// Deserialize a pinned verifying key.
pub fn deserialize_vk(bytes: &[u8]) -> Option<VerifyingKey<Bn254>> {
    VerifyingKey::<Bn254>::deserialize_compressed(bytes).ok()
}

/// Serialize a proof (compressed) for the wire.
pub fn serialize_proof(proof: &Proof<Bn254>) -> Vec<u8> {
    let mut out = Vec::new();
    proof.serialize_compressed(&mut out).expect("proof serializes");
    out
}

/// Deserialize a wire proof.
pub fn deserialize_proof(bytes: &[u8]) -> Option<Proof<Bn254>> {
    Proof::<Bn254>::deserialize_compressed(bytes).ok()
}
