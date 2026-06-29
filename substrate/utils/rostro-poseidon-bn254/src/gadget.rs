//! In-circuit (R1CS) mirror of the native role hashes.
//!
//! Built from the *same* [`PoseidonConfig`] as the native path
//! ([`crate::params`]), so the two are identical by construction. The
//! `native_matches_gadget` test in `tests.rs` proves equality for each
//! role. Enable with the `gadget` feature; the runtime and the phone do
//! not compile this module.

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar,
    poseidon::{constraints::PoseidonSpongeVar, PoseidonConfig},
};
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use crate::{DOMAIN_COMMITMENT, DOMAIN_LEAF, DOMAIN_NODE, DOMAIN_NULLIFIER};

/// Core in-circuit sponge hash: absorb the constant `domain` tag, then
/// `elems`, squeeze one element. Mirrors [`crate::hash`].
fn hash_var(
    cs: ConstraintSystemRef<Fr>,
    params: &PoseidonConfig<Fr>,
    domain: u64,
    elems: &[FpVar<Fr>],
) -> Result<FpVar<Fr>, SynthesisError> {
    let mut sponge = PoseidonSpongeVar::<Fr>::new(cs, params);
    sponge.absorb(&FpVar::Constant(Fr::from(domain)))?;
    for e in elems {
        sponge.absorb(e)?;
    }
    Ok(sponge.squeeze_field_elements(1)?[0].clone())
}

/// In-circuit [`crate::id_commitment`].
pub fn id_commitment_var(
    cs: ConstraintSystemRef<Fr>,
    params: &PoseidonConfig<Fr>,
    s: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    hash_var(cs, params, DOMAIN_COMMITMENT, core::slice::from_ref(s))
}

/// In-circuit [`crate::hash_node`].
pub fn hash_node_var(
    cs: ConstraintSystemRef<Fr>,
    params: &PoseidonConfig<Fr>,
    left: &FpVar<Fr>,
    right: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    hash_var(cs, params, DOMAIN_NODE, &[left.clone(), right.clone()])
}

/// In-circuit [`crate::hash_leaf`].
pub fn hash_leaf_var(
    cs: ConstraintSystemRef<Fr>,
    params: &PoseidonConfig<Fr>,
    id_commitment: &FpVar<Fr>,
    expiry_block: &FpVar<Fr>,
    scope: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    hash_var(
        cs,
        params,
        DOMAIN_LEAF,
        &[id_commitment.clone(), expiry_block.clone(), scope.clone()],
    )
}

/// In-circuit [`crate::nullifier`].
pub fn nullifier_var(
    cs: ConstraintSystemRef<Fr>,
    params: &PoseidonConfig<Fr>,
    s: &FpVar<Fr>,
    epoch: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    hash_var(cs, params, DOMAIN_NULLIFIER, &[s.clone(), epoch.clone()])
}
