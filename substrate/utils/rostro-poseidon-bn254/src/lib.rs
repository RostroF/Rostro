//! Canonical Poseidon-over-BN254 instance for the dotwave chat
//! anonymous-membership scheme.
//!
//! This crate is the single source of truth for every Poseidon hash that
//! has to agree byte-for-byte across three places:
//!   * the phone (rust_core), which computes `id_commitment = H(s)` at
//!     enrollment and builds the membership-proof witness;
//!   * the runtime (`zkpki-pallet`), which recomputes leaf and Merkle-node
//!     hashes on insert / remove / root-advance; and
//!   * the Groth16 circuit, via the feature-gated [`gadget`] module.
//!
//! If any of those three disagree by a single field element, nothing
//! verifies. So the instance is pinned here and locked by the
//! known-answer tests at the bottom of this file. The `gadget` module is
//! built from the *same* [`PoseidonConfig`] as the native path, so the
//! two cannot drift; the `native_matches_gadget` test proves it.
//!
//! ## The instance (see DOTWAVE-CHAT-ANON-MEMBERSHIP-AUTH-DECISIONS D4)
//!   * field: BN254 scalar field `Fr`
//!   * S-box: `x^5` (`ALPHA = 5`)
//!   * width `t = 3` (rate 2, capacity 1), used as a sponge so each role
//!     absorbs a variable number of inputs after a domain tag
//!   * rounds: `R_F = 8` full, `R_P = 57` partial (standard BN254 t=3)
//!
//! ## Domain separation
//! Every role hash absorbs a distinct domain tag as its first field
//! element, so a value valid in one role can never be reinterpreted in
//! another (a node hash reused as a leaf, a commitment reused as a
//! nullifier, etc). The tags are [`DOMAIN_COMMITMENT`], [`DOMAIN_NODE`],
//! [`DOMAIN_LEAF`], [`DOMAIN_NULLIFIER`].

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::{
    poseidon::{find_poseidon_ark_and_mds, PoseidonSponge},
    CryptographicSponge, FieldBasedCryptographicSponge,
};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

pub use ark_bn254::Fr as PoseidonField;
/// The Poseidon configuration type, re-exported so downstream crates can
/// thread `&PoseidonConfig` through hot paths without depending on
/// ark-crypto-primitives directly.
pub use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;

#[cfg(feature = "gadget")]
pub mod gadget;

// ───────────────────────────── instance parameters ─────────────────────────

/// Full rounds (`R_F`).
pub const FULL_ROUNDS: usize = 8;
/// Partial rounds (`R_P`) for BN254, width 3.
pub const PARTIAL_ROUNDS: usize = 57;
/// S-box exponent.
pub const ALPHA: u64 = 5;
/// Sponge rate.
pub const RATE: usize = 2;
/// Sponge capacity.
pub const CAPACITY: usize = 1;
/// BN254 scalar field bit length, fed to the Grain LFSR constant
/// generator. The state width it derives is `RATE + 1`.
const PRIME_BITS: u64 = 254;

/// Build the canonical [`PoseidonConfig`] for this instance.
///
/// The round constants and MDS matrix are derived deterministically from
/// the instance parameters via the Grain LFSR generator, so this returns
/// the same configuration on every platform. It is not cheap (it runs the
/// LFSR and an MDS search), so callers that hash many times in one
/// operation (e.g. a depth-32 Merkle path) should call this once and pass
/// the `&PoseidonConfig` into the role hashes, not rebuild it per hash.
///
/// The KATs at the bottom of this file pin the outputs; a future
/// optimization may freeze `ark`/`mds` as constants, and the KATs will
/// guarantee the frozen blob matches this generator.
pub fn params() -> PoseidonConfig<Fr> {
    let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
        PRIME_BITS,
        RATE,
        FULL_ROUNDS as u64,
        PARTIAL_ROUNDS as u64,
        0,
    );
    PoseidonConfig::new(FULL_ROUNDS, PARTIAL_ROUNDS, ALPHA, mds, ark, RATE, CAPACITY)
}

// ───────────────────────────── domain tags ─────────────────────────────────

/// Domain tag for `id_commitment = H(s)`.
pub const DOMAIN_COMMITMENT: u64 = 1;
/// Domain tag for a 2-to-1 Merkle node hash.
pub const DOMAIN_NODE: u64 = 2;
/// Domain tag for the membership leaf hash.
pub const DOMAIN_LEAF: u64 = 3;
/// Domain tag for the per-epoch nullifier.
pub const DOMAIN_NULLIFIER: u64 = 4;

// ───────────────────────────── native role hashes ──────────────────────────

/// Core sponge hash: absorb `domain`, then `elems`, squeeze one element.
fn hash(params: &PoseidonConfig<Fr>, domain: u64, elems: &[Fr]) -> Fr {
    let mut sponge = PoseidonSponge::<Fr>::new(params);
    sponge.absorb(&Fr::from(domain));
    for e in elems {
        sponge.absorb(e);
    }
    sponge.squeeze_native_field_elements(1)[0]
}

/// `id_commitment = H(DOMAIN_COMMITMENT, s)`. The leaf-bound identity
/// commitment; `s` is the hardware-derived membership secret.
pub fn id_commitment(params: &PoseidonConfig<Fr>, s: Fr) -> Fr {
    hash(params, DOMAIN_COMMITMENT, &[s])
}

/// `H(DOMAIN_NODE, left, right)`: a 2-to-1 Merkle node compression.
pub fn hash_node(params: &PoseidonConfig<Fr>, left: Fr, right: Fr) -> Fr {
    hash(params, DOMAIN_NODE, &[left, right])
}

/// `leaf = H(DOMAIN_LEAF, id_commitment, expiry_block, scope)`. Static
/// membership leaf (freshness is committed separately; see decisions D6).
pub fn hash_leaf(params: &PoseidonConfig<Fr>, id_commitment: Fr, expiry_block: Fr, scope: Fr) -> Fr {
    hash(params, DOMAIN_LEAF, &[id_commitment, expiry_block, scope])
}

/// `nullifier = H(DOMAIN_NULLIFIER, s, epoch)`: one per cert per epoch.
pub fn nullifier(params: &PoseidonConfig<Fr>, s: Fr, epoch: Fr) -> Fr {
    hash(params, DOMAIN_NULLIFIER, &[s, epoch])
}

// ───────────────────────────── field <-> bytes ─────────────────────────────

/// Deserialize a 32-byte little-endian value into `Fr`, rejecting any
/// encoding that is not canonical (i.e. `>= Fr` modulus). This is the
/// validate-at-handoff check the pallet performs on `id_commitment`
/// before it ever reaches a leaf.
pub fn fr_from_canonical_bytes_le(b: &[u8; 32]) -> Option<Fr> {
    Fr::deserialize_compressed(&b[..]).ok()
}

/// Serialize `Fr` to its canonical 32-byte little-endian encoding.
pub fn fr_to_bytes_le(f: &Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    f.serialize_compressed(&mut out[..])
        .expect("Fr always serializes into 32 bytes");
    out
}

// ───────────────────────────── hash-to-field (phone) ───────────────────────

/// Domain-separation tag for [`hash_to_field_bn254`].
pub const HASH_TO_FIELD_DST: &[u8] = b"rostro-poseidon-bn254:htf:v1";

/// Reduce arbitrary bytes (the in-chip ECDH shared secret, on the phone)
/// into a uniform `Fr`. Defined as
/// `Fr::from_le_bytes_mod_order(SHA-512(DST || msg))`: 512 input bits
/// reduced modulo a ~254-bit prime leaves bias far below `2^-128`.
///
/// This runs only on the phone (the membership secret `s` is a circuit
/// *witness*, not recomputed in-circuit or on-chain). It lives here so
/// the phone uses exactly this definition and never an ad-hoc one.
pub fn hash_to_field_bn254(msg: &[u8]) -> Fr {
    use sha2::{Digest, Sha512};
    let mut h = Sha512::new();
    h.update(HASH_TO_FIELD_DST);
    h.update(msg);
    Fr::from_le_bytes_mod_order(&h.finalize())
}

#[cfg(test)]
mod tests;
