//! Depth-32 sparse Poseidon-BN254 Merkle tree for the chat
//! anonymous-membership set (see DOTWAVE-CHAT-ANON-MEMBERSHIP-AUTH-DECISIONS
//! D5).
//!
//! Inclusion-only, mutable: leaves are inserted at mint and cleared on
//! revoke / expiry. The address space is `2^32` (~4.3B leaves), far more
//! than a tree could ever materialize, so the tree is stored *sparsely*:
//! only occupied internal nodes are kept; a missing node at level `L` is
//! implicitly the root of an all-empty subtree of height `L`, which is a
//! constant ([`empty_roots`]). That keeps storage proportional to the live
//! cert set, and every lifecycle event is `O(DEPTH)` node hashes.
//!
//! This crate is the math only. It operates over a [`NodeStore`] trait so
//! the pallet can back it with runtime storage; an in-memory store is
//! provided for tests. Slot allocation (the free-list) and the
//! root-history ring are also provided as plain helpers the pallet owns.
//!
//! ## What "membership" hashes to
//! Leaves are `rostro_poseidon_bn254::hash_leaf(id_commitment, expiry,
//! scope)`; internal nodes are `hash_node(left, right)`. Both come from the
//! one pinned Poseidon instance, so an authentication path produced here
//! verifies identically in the Groth16 circuit.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use ark_bn254::Fr;
use ark_ff::Zero;
use rostro_poseidon_bn254::{hash_node, params, PoseidonConfig};

/// Tree depth: 32 levels, leaves at level 0, root at level [`DEPTH`].
pub const DEPTH: usize = 32;

/// The value of an empty leaf slot. A real leaf is a `hash_leaf` output,
/// which is `0` only with probability `2^-254`, so `0` is a safe empty
/// sentinel; emptiness is tracked structurally (store presence) regardless.
pub fn empty_leaf() -> Fr {
    Fr::zero()
}

/// The maximum number of leaves: `2^DEPTH`.
pub const CAPACITY: u64 = 1u64 << DEPTH;

// ───────────────────────────── empty-subtree roots ─────────────────────────

/// `empty_roots(params)[L]` is the root of an all-empty subtree of height
/// `L`: `[0]` is [`empty_leaf`], `[L] = hash_node(e[L-1], e[L-1])`. Length
/// `DEPTH + 1`. Compute once and reuse; it is constant for the instance.
pub fn empty_roots(params: &PoseidonConfig<Fr>) -> Vec<Fr> {
    let mut e = Vec::with_capacity(DEPTH + 1);
    e.push(empty_leaf());
    for level in 0..DEPTH {
        let below = e[level];
        e.push(hash_node(params, below, below));
    }
    e
}

/// The root of a completely empty tree.
pub fn empty_root(params: &PoseidonConfig<Fr>) -> Fr {
    empty_roots(params)[DEPTH]
}

// ───────────────────────────── node store ──────────────────────────────────

/// Sparse storage of occupied internal nodes, keyed by `(level, index)`.
/// A missing entry at `(level, index)` means the empty-subtree root for
/// that level. Level 0 is leaves; level [`DEPTH`] is the single root.
pub trait NodeStore {
    /// The stored node, or `None` if this position is an empty subtree.
    fn get(&self, level: u8, index: u64) -> Option<Fr>;
    /// Store a non-empty node.
    fn set(&mut self, level: u8, index: u64, value: Fr);
    /// Drop a node back to its empty-subtree default.
    fn clear(&mut self, level: u8, index: u64);
}

/// In-memory [`NodeStore`] for tests and off-chain tooling.
#[derive(Default, Clone)]
pub struct MemoryStore {
    nodes: BTreeMap<(u8, u64), Fr>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
    /// Number of occupied nodes (storage footprint).
    pub fn occupied(&self) -> usize {
        self.nodes.len()
    }
}

impl NodeStore for MemoryStore {
    fn get(&self, level: u8, index: u64) -> Option<Fr> {
        self.nodes.get(&(level, index)).copied()
    }
    fn set(&mut self, level: u8, index: u64, value: Fr) {
        self.nodes.insert((level, index), value);
    }
    fn clear(&mut self, level: u8, index: u64) {
        self.nodes.remove(&(level, index));
    }
}

// ───────────────────────────── core update ─────────────────────────────────

/// Set the leaf at `index` to `leaf` (use [`empty_leaf`] to remove) and
/// recompute the path to the root, returning the new root. Nodes that fall
/// back to their empty-subtree default are cleared, keeping storage sparse.
///
/// `empties` must be [`empty_roots`] for `params`; pass it in so a caller
/// updating many leaves does not recompute it each time.
pub fn update<S: NodeStore>(
    store: &mut S,
    params: &PoseidonConfig<Fr>,
    empties: &[Fr],
    index: u64,
    leaf: Fr,
) -> Fr {
    debug_assert!(index < CAPACITY, "leaf index out of range");
    debug_assert!(empties.len() == DEPTH + 1, "empties must have DEPTH+1 entries");

    let mut idx = index;
    let mut cur = leaf;

    // Level 0: place or clear the leaf.
    if cur == empties[0] {
        store.clear(0, idx);
    } else {
        store.set(0, idx, cur);
    }

    // Levels 1..=DEPTH: recompute the parent at each step.
    for level in 0..DEPTH {
        let sibling = store
            .get(level as u8, idx ^ 1)
            .unwrap_or(empties[level]);
        let (left, right) = if idx & 1 == 0 {
            (cur, sibling)
        } else {
            (sibling, cur)
        };
        cur = hash_node(params, left, right);
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
/// Missing siblings are the empty-subtree root for their level.
pub fn authentication_path<S: NodeStore>(
    store: &S,
    empties: &[Fr],
    index: u64,
) -> [Fr; DEPTH] {
    let mut idx = index;
    let mut path = [Fr::zero(); DEPTH];
    for level in 0..DEPTH {
        path[level] = store
            .get(level as u8, idx ^ 1)
            .unwrap_or(empties[level]);
        idx >>= 1;
    }
    path
}

/// Recompute a root from a leaf, its `index`, and an authentication path.
/// This is exactly what the Groth16 inclusion circuit enforces, so a path
/// from [`authentication_path`] that recomputes the current root here will
/// also verify in-circuit.
pub fn root_from_path(
    params: &PoseidonConfig<Fr>,
    leaf: Fr,
    index: u64,
    path: &[Fr; DEPTH],
) -> Fr {
    let mut idx = index;
    let mut cur = leaf;
    for level in 0..DEPTH {
        let (left, right) = if idx & 1 == 0 {
            (cur, path[level])
        } else {
            (path[level], cur)
        };
        cur = hash_node(params, left, right);
        idx >>= 1;
    }
    cur
}

// ───────────────────────────── slot allocator ──────────────────────────────

/// Dense slot allocator with free-list reuse (decisions D5). Hands out the
/// lowest available index: a removed slot is reused before `next` advances,
/// bounding the live index range to the live-set size. The pallet stores
/// `next` and `free`; this is the policy.
#[derive(Default, Clone)]
pub struct Allocator {
    next: u64,
    free: Vec<u64>,
}

impl Allocator {
    pub fn new() -> Self {
        Self::default()
    }
    /// Reserve a leaf index, reusing a freed slot if one exists.
    pub fn alloc(&mut self) -> Option<u64> {
        if let Some(i) = self.free.pop() {
            return Some(i);
        }
        if self.next >= CAPACITY {
            return None;
        }
        let i = self.next;
        self.next += 1;
        Some(i)
    }
    /// Return a slot to the free-list.
    pub fn free(&mut self, index: u64) {
        self.free.push(index);
    }
    /// Number of live (allocated and not freed) slots.
    pub fn live(&self) -> u64 {
        self.next - self.free.len() as u64
    }
}

// ───────────────────────────── root history ────────────────────────────────

/// Bounded ring of recent roots, so a proof built against a just-superseded
/// root still verifies during the window between build and submit
/// (decisions D5). The pallet owns the persisted form; this is the logic.
#[derive(Clone)]
pub struct RootHistory {
    roots: VecDeque<Fr>,
    cap: usize,
}

impl RootHistory {
    /// New ring holding up to `cap` recent roots (cap >= 1).
    pub fn new(cap: usize) -> Self {
        Self {
            roots: VecDeque::with_capacity(cap),
            cap: cap.max(1),
        }
    }
    /// Record a new root, evicting the oldest when full. A repeated root is
    /// not duplicated.
    pub fn push(&mut self, root: Fr) {
        if self.roots.back() == Some(&root) {
            return;
        }
        if self.roots.len() == self.cap {
            self.roots.pop_front();
        }
        self.roots.push_back(root);
    }
    /// Is `root` within the accepted recent-root window?
    pub fn contains(&self, root: &Fr) -> bool {
        self.roots.iter().any(|r| r == root)
    }
    /// The most recent root, if any.
    pub fn latest(&self) -> Option<Fr> {
        self.roots.back().copied()
    }
    pub fn len(&self) -> usize {
        self.roots.len()
    }
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }
}

// ───────────────────────────── bundled tree (tests/tooling) ────────────────

/// A self-contained tree bundling a [`MemoryStore`], an [`Allocator`], the
/// current root and a [`RootHistory`]. Convenience for tests and off-chain
/// tooling; the pallet composes the same pieces over runtime storage.
pub struct MembershipTree {
    params: PoseidonConfig<Fr>,
    empties: Vec<Fr>,
    store: MemoryStore,
    alloc: Allocator,
    root: Fr,
    history: RootHistory,
}

impl MembershipTree {
    pub fn new(history_cap: usize) -> Self {
        let params = params();
        let empties = empty_roots(&params);
        let root = empties[DEPTH];
        let mut history = RootHistory::new(history_cap);
        history.push(root);
        Self {
            params,
            empties,
            store: MemoryStore::new(),
            alloc: Allocator::new(),
            root,
            history,
        }
    }

    pub fn root(&self) -> Fr {
        self.root
    }
    pub fn history(&self) -> &RootHistory {
        &self.history
    }
    pub fn occupied_nodes(&self) -> usize {
        self.store.occupied()
    }

    /// Insert a leaf, returning its index. `None` if the tree is full.
    pub fn insert(&mut self, leaf: Fr) -> Option<u64> {
        let index = self.alloc.alloc()?;
        self.root = update(&mut self.store, &self.params, &self.empties, index, leaf);
        self.history.push(self.root);
        Some(index)
    }

    /// Remove the leaf at `index`, freeing the slot for reuse.
    pub fn remove(&mut self, index: u64) {
        self.root = update(
            &mut self.store,
            &self.params,
            &self.empties,
            index,
            empty_leaf(),
        );
        self.alloc.free(index);
        self.history.push(self.root);
    }

    /// Authentication path for a leaf index against the current tree.
    pub fn path(&self, index: u64) -> [Fr; DEPTH] {
        authentication_path(&self.store, &self.empties, index)
    }

    pub fn params(&self) -> &PoseidonConfig<Fr> {
        &self.params
    }
}

#[cfg(test)]
mod tests;
