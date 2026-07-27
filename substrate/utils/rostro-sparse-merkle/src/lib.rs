//! Depth-32 sparse Merkle tree — the shared math for Rostro's identity trees.
//!
//! Previously this algorithm was copied across two crates (a Poseidon one for
//! chat, a keccak one for witness). It lives here once now, generic over a
//! [`Hasher`], with two instantiations:
//!
//! - [`poseidon::PoseidonHasher`] — BN254, SNARK-friendly. The chat
//!   anonymous-membership tree, whose authentication paths are re-verified in
//!   a Groth16 circuit, so the hashing must be circuit-cheap. Byte-identical
//!   to the prior standalone crate (same `rostro_poseidon_bn254` primitives).
//! - [`keccak::KeccakHasher`] — keccak256. The per-issuer witness trees, whose
//!   branches are walked by a foreign smart contract using the native
//!   keccak256 opcode; Poseidon would be ruinous there.
//!
//! The `2^32` address space is stored sparsely: only occupied nodes are kept;
//! a missing node at level `L` is the constant empty-subtree root
//! ([`empty_roots`]). Every lifecycle event is `O(DEPTH)` hashes. The tree
//! operates over a [`NodeStore`] the pallet backs with runtime storage; an
//! in-memory store is provided for tests and off-chain tooling.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// Tree depth: 32 levels, leaves at level 0, root at level [`DEPTH`].
pub const DEPTH: usize = 32;

/// The maximum number of leaves: `2^DEPTH`.
pub const CAPACITY: u64 = 1u64 << DEPTH;

// ───────────────────────────── hasher ──────────────────────────────────────

/// The hash the tree is built from. A `Hasher` value carries whatever
/// parameters the hash needs (Poseidon holds its round constants; keccak is a
/// unit), so the algorithm below never threads params explicitly.
pub trait Hasher {
    /// A tree node: 32-byte-ish, `Copy` and comparable so emptiness can be
    /// detected by value against the empty-subtree constants.
    type Node: Copy + PartialEq;
    /// The internal-node hash of an ordered `(left, right)` pair.
    fn hash_node(&self, left: &Self::Node, right: &Self::Node) -> Self::Node;
    /// The value of an empty leaf slot (the sparse-tree sentinel).
    fn empty_leaf(&self) -> Self::Node;
}

// ───────────────────────────── node store ──────────────────────────────────

/// Sparse storage of occupied internal nodes, keyed by `(level, index)`. A
/// missing entry means the empty-subtree root for that level. Level 0 is
/// leaves; level [`DEPTH`] is the single root.
pub trait NodeStore<N> {
    fn get(&self, level: u8, index: u64) -> Option<N>;
    fn set(&mut self, level: u8, index: u64, value: N);
    fn clear(&mut self, level: u8, index: u64);
}

/// In-memory [`NodeStore`] for tests and off-chain tooling.
#[derive(Clone)]
pub struct MemoryStore<N> {
    nodes: BTreeMap<(u8, u64), N>,
}

impl<N: Copy> MemoryStore<N> {
    pub fn new() -> Self {
        Self { nodes: BTreeMap::new() }
    }
    /// Number of occupied nodes (storage footprint).
    pub fn occupied(&self) -> usize {
        self.nodes.len()
    }
}

impl<N: Copy> Default for MemoryStore<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<N: Copy> NodeStore<N> for MemoryStore<N> {
    fn get(&self, level: u8, index: u64) -> Option<N> {
        self.nodes.get(&(level, index)).copied()
    }
    fn set(&mut self, level: u8, index: u64, value: N) {
        self.nodes.insert((level, index), value);
    }
    fn clear(&mut self, level: u8, index: u64) {
        self.nodes.remove(&(level, index));
    }
}

// ───────────────────────────── empty-subtree roots ─────────────────────────

/// `empty_roots(h)[L]` is the root of an all-empty subtree of height `L`:
/// `[0]` is `h.empty_leaf()`, `[L] = h.hash_node(e[L-1], e[L-1])`. Length
/// `DEPTH + 1`. Constant for the hasher; compute once and reuse.
pub fn empty_roots<H: Hasher>(h: &H) -> Vec<H::Node> {
    let mut e = Vec::with_capacity(DEPTH + 1);
    e.push(h.empty_leaf());
    for level in 0..DEPTH {
        let below = e[level];
        e.push(h.hash_node(&below, &below));
    }
    e
}

/// The root of a completely empty tree.
pub fn empty_root<H: Hasher>(h: &H) -> H::Node {
    empty_roots(h)[DEPTH]
}

// ───────────────────────────── core update ─────────────────────────────────

/// Set the leaf at `index` to `leaf` (use `h.empty_leaf()` to remove) and
/// recompute the path to the root, returning the new root. Nodes that fall
/// back to their empty-subtree default are cleared, keeping storage sparse.
///
/// `empties` must be [`empty_roots`] for `h`; pass it in so a caller updating
/// many leaves does not recompute it each time.
pub fn update<H: Hasher, S: NodeStore<H::Node>>(
    store: &mut S,
    h: &H,
    empties: &[H::Node],
    index: u64,
    leaf: H::Node,
) -> H::Node {
    debug_assert!(index < CAPACITY, "leaf index out of range");
    debug_assert!(empties.len() == DEPTH + 1, "empties must have DEPTH+1 entries");

    let mut idx = index;
    let mut cur = leaf;

    if cur == empties[0] {
        store.clear(0, idx);
    } else {
        store.set(0, idx, cur);
    }

    for level in 0..DEPTH {
        let sibling = store.get(level as u8, idx ^ 1).unwrap_or(empties[level]);
        let (left, right) = if idx & 1 == 0 { (cur, sibling) } else { (sibling, cur) };
        cur = h.hash_node(&left, &right);
        idx >>= 1;
        let parent_level = (level + 1) as u8;
        if cur == empties[level + 1] {
            store.clear(parent_level, idx);
        } else {
            store.set(parent_level, idx, cur);
        }
    }

    cur
}

/// The authentication path (sibling at each level, bottom-up) for `index`.
/// Missing siblings are the empty-subtree root for their level. No hasher
/// needed — this only reads the store and the precomputed empties.
pub fn authentication_path<N: Copy, S: NodeStore<N>>(
    store: &S,
    empties: &[N],
    index: u64,
) -> [N; DEPTH] {
    let mut idx = index;
    let mut path = [empties[0]; DEPTH];
    for level in 0..DEPTH {
        path[level] = store.get(level as u8, idx ^ 1).unwrap_or(empties[level]);
        idx >>= 1;
    }
    path
}

/// Recompute a root from a leaf, its `index`, and an authentication path.
/// This is exactly what a verifier does (in-circuit for Poseidon, on-chain
/// for keccak), so a path from [`authentication_path`] that recomputes the
/// current root here verifies identically there.
pub fn root_from_path<H: Hasher>(
    h: &H,
    leaf: H::Node,
    index: u64,
    path: &[H::Node; DEPTH],
) -> H::Node {
    let mut idx = index;
    let mut cur = leaf;
    for sib in path.iter().take(DEPTH) {
        let (left, right) = if idx & 1 == 0 { (cur, *sib) } else { (*sib, cur) };
        cur = h.hash_node(&left, &right);
        idx >>= 1;
    }
    cur
}

// ───────────────────────────── poseidon instantiation ──────────────────────

/// Poseidon-BN254 hasher for the chat anonymous-membership tree. SNARK-
/// friendly; authentication paths re-verify in the Groth16 circuit.
pub mod poseidon {
    use super::Hasher;
    use ark_bn254::Fr;
    use ark_ff::Zero;
    use rostro_poseidon_bn254::{hash_node as poseidon_hash_node, params, PoseidonConfig};

    /// Re-exported so a consumer can build leaves and (de)serialize field
    /// elements from the one tree crate.
    pub use rostro_poseidon_bn254::{fr_from_canonical_bytes_le, fr_to_bytes_le, hash_leaf};

    /// The BN254 scalar field element used as a tree node.
    pub type Node = Fr;

    /// A Poseidon hasher holding the one pinned parameter set.
    pub struct PoseidonHasher {
        params: PoseidonConfig<Fr>,
    }

    impl PoseidonHasher {
        pub fn new() -> Self {
            Self { params: params() }
        }
        pub fn params(&self) -> &PoseidonConfig<Fr> {
            &self.params
        }
    }

    impl Default for PoseidonHasher {
        fn default() -> Self {
            Self::new()
        }
    }

    /// `PoseidonHasher` is a newtype over the pinned `PoseidonConfig`, so it
    /// derefs to it — a caller with a hasher can pass `&hasher` anywhere a
    /// `&PoseidonConfig` is wanted (e.g. `hash_leaf`) without unwrapping.
    impl core::ops::Deref for PoseidonHasher {
        type Target = PoseidonConfig<Fr>;
        fn deref(&self) -> &Self::Target {
            &self.params
        }
    }

    impl Hasher for PoseidonHasher {
        type Node = Fr;
        fn hash_node(&self, left: &Fr, right: &Fr) -> Fr {
            poseidon_hash_node(&self.params, *left, *right)
        }
        fn empty_leaf(&self) -> Fr {
            Fr::zero()
        }
    }
}

// ───────────────────────────── keccak instantiation ────────────────────────

/// keccak256 hasher for the per-issuer witness trees. A foreign contract
/// walks the branch with the native keccak256 opcode.
pub mod keccak {
    use super::Hasher;
    use sp_crypto_hashing::keccak_256;

    /// A 32-byte keccak node (or a value leaf).
    pub type Node = [u8; 32];

    /// The keccak hasher (parameterless).
    #[derive(Clone, Copy, Default)]
    pub struct KeccakHasher;

    impl Hasher for KeccakHasher {
        type Node = [u8; 32];
        fn hash_node(&self, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(left);
            buf[32..].copy_from_slice(right);
            keccak_256(&buf)
        }
        fn empty_leaf(&self) -> [u8; 32] {
            [0u8; 32]
        }
    }

    /// The witness leaf value: `keccak256(id_commitment ++ expiry_be ++
    /// scope_be)`, with `expiry`/`scope` as 8-byte big-endian so a Solidity
    /// verifier reconstructs it with
    /// `keccak256(abi.encodePacked(idc, uint64(expiry), uint64(scope)))`.
    pub fn hash_leaf(id_commitment: &[u8; 32], expiry: u64, scope: u64) -> [u8; 32] {
        let mut buf = [0u8; 48];
        buf[..32].copy_from_slice(id_commitment);
        buf[32..40].copy_from_slice(&expiry.to_be_bytes());
        buf[40..48].copy_from_slice(&scope.to_be_bytes());
        keccak_256(&buf)
    }

    /// A `u64` as a big-endian right-aligned 32-byte value leaf (the freshness
    /// tree, whose leaf *is* `fresh_until_epoch`).
    pub fn value_leaf(value: u64) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[24..].copy_from_slice(&value.to_be_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::keccak::{hash_leaf as k_leaf, value_leaf, KeccakHasher};
    use super::poseidon::{hash_leaf as p_leaf, PoseidonHasher};
    use super::*;

    #[test]
    fn keccak_insert_remove_roundtrips() {
        let h = KeccakHasher;
        let empties = empty_roots(&h);
        let mut store = MemoryStore::<[u8; 32]>::new();
        let r0 = empty_root(&h);
        let leaf = k_leaf(&[7u8; 32], 1000, 2);
        let r1 = update(&mut store, &h, &empties, 5, leaf);
        assert_ne!(r1, r0);
        let r2 = update(&mut store, &h, &empties, 5, h.empty_leaf());
        assert_eq!(r2, r0);
        assert_eq!(store.occupied(), 0);
        // path recomputes root
        update(&mut store, &h, &empties, 3, leaf);
        let root = update(&mut store, &h, &empties, 5, leaf);
        let path = authentication_path(&store, &empties, 5);
        assert_eq!(root_from_path(&h, leaf, 5, &path), root);
    }

    #[test]
    fn poseidon_insert_remove_roundtrips() {
        let h = PoseidonHasher::new();
        let empties = empty_roots(&h);
        let mut store = MemoryStore::new();
        let r0 = empty_root(&h);
        let leaf = p_leaf(h.params(), 42u64.into(), 1000u64.into(), 1u64.into());
        let r1 = update(&mut store, &h, &empties, 5, leaf);
        assert_ne!(r1, r0);
        let r2 = update(&mut store, &h, &empties, 5, h.empty_leaf());
        assert_eq!(r2, r0);
        let root = update(&mut store, &h, &empties, 7, leaf);
        let path = authentication_path(&store, &empties, 7);
        assert_eq!(root_from_path(&h, leaf, 7, &path), root);
    }

    #[test]
    fn value_leaf_is_big_endian_right_aligned() {
        let v = value_leaf(0x0102);
        assert_eq!(v[30], 0x01);
        assert_eq!(v[31], 0x02);
        assert_eq!(v[..30], [0u8; 30]);
    }
}
