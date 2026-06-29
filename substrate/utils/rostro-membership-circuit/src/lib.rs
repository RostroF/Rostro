//! Groth16 R1CS circuit for the dotwave chat anonymous-membership proof.
//!
//! The prover (the phone) proves, in zero knowledge, that it holds a
//! membership secret `s` whose cert is in the valid set, is not expired, and
//! is HIP-fresh, without revealing which cert. The guard verifies this once
//! per session and learns only "a valid, fresh, accountable holder, with
//! session key Y and rate tag N".
//!
//! ## Statement
//!
//! Public inputs (verifier-supplied, in this exact order):
//!   0. `membership_root`  — current/recent R_m
//!   1. `freshness_root`   — current/recent R_f
//!   2. `nullifier`        — N, the per-epoch rate tag
//!   3. `current_epoch`    — for the nullifier and the freshness check
//!   4. `anchor_block`     — a recent block, for the expiry check
//!   5. `scope`            — the anonymity-set domain
//!   6. `challenge`        — binds guard_node_id + anchor + session_pubkey
//!   7. `session_pubkey`   — the per-session key (as a field element)
//!
//! Private witnesses: `s`, `expiry_block`, `fresh_until_epoch`, the leaf
//! `index` (as bits), and the two Merkle authentication paths.
//!
//! Constraints:
//!   1. `id_commitment = Poseidon(s)`                              (possession)
//!   2. `membership_leaf = Poseidon(id_commitment, expiry, scope)` (binding)
//!   3. `membership_leaf` at `index` in `membership_root`          (membership)
//!   4. `fresh_until_epoch` at `index` in `freshness_root`         (freshness leaf)
//!   5. `nullifier = Poseidon(s, current_epoch)`                   (well-formed N)
//!   6. `fresh_until_epoch >= current_epoch`                       (HIP-fresh)
//!   7. `anchor_block < expiry_block`                              (not expired)
//!   8. `challenge`, `session_pubkey` bound into the system        (non-relayable)
//!
//! The membership and freshness leaves share one `index`, which is what ties
//! a cert's freshness to its membership entry (decisions D6).
//!
//! This crate is the constraint system plus a native-witness harness that
//! checks satisfiability directly in a `ConstraintSystem`. Groth16 setup,
//! proving, and verification are a later, separate step.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
use alloc::vec::Vec;

use ark_bn254::Fr;
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    convert::ToBitsGadget,
    eq::EqGadget,
    fields::fp::FpVar,
    select::CondSelectGadget,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use rostro_membership_tree::DEPTH;
use rostro_poseidon_bn254::{
    gadget::{hash_leaf_var, hash_node_var, id_commitment_var, nullifier_var},
    params, PoseidonConfig,
};

#[cfg(feature = "groth16")]
pub mod groth16;

/// Bit width for the `fresh_until_epoch >= current_epoch` range check.
/// Epochs are `u32`, so 33 bits is comfortable headroom.
const EPOCH_BITS: usize = 33;
/// Bit width for the `anchor_block < expiry_block` range check. Block
/// numbers are `u64`.
const BLOCK_BITS: usize = 64;

/// The membership-proof circuit. Every field is an `Option` so the same
/// type drives both Groth16 setup (all `None`, structure only) and proving
/// (all `Some`).
#[derive(Clone, Default)]
pub struct MembershipCircuit {
    // ----- public inputs -----
    pub membership_root: Option<Fr>,
    pub freshness_root: Option<Fr>,
    pub nullifier: Option<Fr>,
    pub current_epoch: Option<Fr>,
    pub anchor_block: Option<Fr>,
    pub scope: Option<Fr>,
    pub challenge: Option<Fr>,
    pub session_pubkey: Option<Fr>,
    // ----- private witnesses -----
    pub s: Option<Fr>,
    pub expiry_block: Option<Fr>,
    pub fresh_until_epoch: Option<Fr>,
    /// Leaf index as `DEPTH` little-endian bits (LSB first).
    pub index_bits: Option<Vec<bool>>,
    /// Membership authentication path: `DEPTH` siblings, bottom-up.
    pub membership_path: Option<Vec<Fr>>,
    /// Freshness authentication path: `DEPTH` siblings, bottom-up.
    pub freshness_path: Option<Vec<Fr>>,
}

/// Recompute a Merkle root in-circuit from a leaf, its index bits, and an
/// authentication path. Mirrors `rostro_membership_tree::root_from_path`:
/// bit 0 ⇒ this node is the left child, bit 1 ⇒ the right child.
fn merkle_root(
    cs: ConstraintSystemRef<Fr>,
    params: &PoseidonConfig<Fr>,
    leaf: &FpVar<Fr>,
    index_bits: &[Boolean<Fr>],
    path: &[FpVar<Fr>],
) -> Result<FpVar<Fr>, SynthesisError> {
    let mut cur = leaf.clone();
    for (bit, sibling) in index_bits.iter().zip(path.iter()) {
        // bit==1 ⇒ cur is the right child (sibling on the left).
        let left = FpVar::conditionally_select(bit, sibling, &cur)?;
        let right = FpVar::conditionally_select(bit, &cur, sibling)?;
        cur = hash_node_var(cs.clone(), params, &left, &right)?;
    }
    Ok(cur)
}

/// Enforce `larger - smaller ∈ [0, 2^bits)`, i.e. `larger >= smaller` for
/// values that genuinely fit in `bits` bits. The committed operands (epochs
/// from the freshness leaf, block numbers from the membership leaf) are real
/// small values pinned by the Merkle roots, so the range holds for honest
/// provers and wraps (failing the high-bit check) for `larger < smaller`.
fn enforce_geq(
    larger: &FpVar<Fr>,
    smaller: &FpVar<Fr>,
    bits: usize,
) -> Result<(), SynthesisError> {
    let diff = larger - smaller;
    let diff_bits = diff.to_bits_le()?;
    let zero = Boolean::constant(false);
    for b in diff_bits.iter().skip(bits) {
        b.enforce_equal(&zero)?;
    }
    Ok(())
}

impl ConstraintSynthesizer<Fr> for MembershipCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let params = params();

        // ---- public inputs (order is the verifier contract) ----
        let membership_root = FpVar::new_input(cs.clone(), || want(self.membership_root))?;
        let freshness_root = FpVar::new_input(cs.clone(), || want(self.freshness_root))?;
        let nullifier = FpVar::new_input(cs.clone(), || want(self.nullifier))?;
        let current_epoch = FpVar::new_input(cs.clone(), || want(self.current_epoch))?;
        let anchor_block = FpVar::new_input(cs.clone(), || want(self.anchor_block))?;
        let scope = FpVar::new_input(cs.clone(), || want(self.scope))?;
        let challenge = FpVar::new_input(cs.clone(), || want(self.challenge))?;
        let session_pubkey = FpVar::new_input(cs.clone(), || want(self.session_pubkey))?;

        // ---- private witnesses ----
        let s = FpVar::new_witness(cs.clone(), || want(self.s))?;
        let expiry_block = FpVar::new_witness(cs.clone(), || want(self.expiry_block))?;
        let fresh_until_epoch = FpVar::new_witness(cs.clone(), || want(self.fresh_until_epoch))?;
        let index_bits = alloc_bits(cs.clone(), self.index_bits.as_ref())?;
        let membership_path = alloc_path(cs.clone(), self.membership_path.as_ref())?;
        let freshness_path = alloc_path(cs.clone(), self.freshness_path.as_ref())?;

        // 1. Possession: id_commitment = Poseidon(s).
        let id_commitment = id_commitment_var(cs.clone(), &params, &s)?;

        // 2-3. Membership: leaf = Poseidon(id_commitment, expiry, scope), in R_m.
        let membership_leaf =
            hash_leaf_var(cs.clone(), &params, &id_commitment, &expiry_block, &scope)?;
        let computed_m =
            merkle_root(cs.clone(), &params, &membership_leaf, &index_bits, &membership_path)?;
        computed_m.enforce_equal(&membership_root)?;

        // 4. Freshness leaf is the epoch value itself, at the SAME index in R_f.
        let computed_f =
            merkle_root(cs.clone(), &params, &fresh_until_epoch, &index_bits, &freshness_path)?;
        computed_f.enforce_equal(&freshness_root)?;

        // 5. Well-formed nullifier: N = Poseidon(s, current_epoch).
        let computed_n = nullifier_var(cs.clone(), &params, &s, &current_epoch)?;
        computed_n.enforce_equal(&nullifier)?;

        // 6. HIP-fresh: fresh_until_epoch >= current_epoch.
        enforce_geq(&fresh_until_epoch, &current_epoch, EPOCH_BITS)?;

        // 7. Not expired: anchor_block < expiry_block (strict).
        let one = FpVar::Constant(Fr::from(1u64));
        let anchor_plus_one = &anchor_block + &one;
        enforce_geq(&expiry_block, &anchor_plus_one, BLOCK_BITS)?;

        // 8. Bind challenge + session_pubkey into the constraint system so the
        //    proof is non-malleable and non-relayable. They are public inputs,
        //    so the verifier fixes them; the squaring keeps them referenced.
        let _challenge_sq = &challenge * &challenge;
        let _session_sq = &session_pubkey * &session_pubkey;

        Ok(())
    }
}

/// Witness accessor: `Some(v)` during proving, `AssignmentMissing` during
/// setup.
fn want(v: Option<Fr>) -> Result<Fr, SynthesisError> {
    v.ok_or(SynthesisError::AssignmentMissing)
}

/// Allocate exactly `DEPTH` index bits (structure fixed regardless of
/// witness presence, so setup and proving see the same shape).
fn alloc_bits(
    cs: ConstraintSystemRef<Fr>,
    bits: Option<&Vec<bool>>,
) -> Result<Vec<Boolean<Fr>>, SynthesisError> {
    let mut out = Vec::with_capacity(DEPTH);
    for i in 0..DEPTH {
        out.push(Boolean::new_witness(cs.clone(), || {
            bits.and_then(|v| v.get(i).copied())
                .ok_or(SynthesisError::AssignmentMissing)
        })?);
    }
    Ok(out)
}

/// Allocate exactly `DEPTH` authentication-path siblings.
fn alloc_path(
    cs: ConstraintSystemRef<Fr>,
    path: Option<&Vec<Fr>>,
) -> Result<Vec<FpVar<Fr>>, SynthesisError> {
    let mut out = Vec::with_capacity(DEPTH);
    for i in 0..DEPTH {
        out.push(FpVar::new_witness(cs.clone(), || {
            path.and_then(|v| v.get(i).copied())
                .ok_or(SynthesisError::AssignmentMissing)
        })?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
