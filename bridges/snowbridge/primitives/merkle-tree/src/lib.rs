// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023 Snowfork <hello@snowfork.com>
// SPDX-FileCopyrightText: 2021-2022 Parity Technologies (UK) Ltd.
#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]

//! This crate implements a simple binary Merkle Tree utilities required for inter-op with Ethereum
//! bridge & Solidity contract.
//!
//! The implementation is optimised for usage within Substrate Runtime and supports no-std
//! compilation targets.
//!
//! Merkle Tree is constructed from arbitrary-length leaves, that are initially hashed using the
//! same `\[`Hasher`\]` as the inner nodes.
//! Inner nodes are created by concatenating the left and right child hashes in **positional**
//! (`left ‖ right`) order and hashing again. The position of each leaf is therefore bound into
//! the root: a `(leaf, proof)` pair only verifies against the index it was constructed for.
//!
//! Earlier revisions of this crate hashed sibling pairs in *sorted* order (`min ‖ max`), which
//! made `leaf_index` decorative — any `(leaf, proof)` pair verified against any index in the
//! tree. That was the missing-bounds half of the Hyperbridge bug class. The current
//! implementation uses fixed (left, right) ordering driven by the bits of `leaf_index` so the
//! verifier is forced to use the position the proof was generated for. **This is a wire-format
//! change**: roots produced by this crate now differ from the upstream Snowbridge / Solidity
//! `verify` paths that still use sorted-pair hashing. Any downstream consumer
//! (Solidity gateway, runtime tests pinning hex roots) must be updated together with this crate.
//!
//! If the number of leaves is not even, last leaf (hash of) is promoted to the upper layer.

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::vec;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_core::H256;
use sp_runtime::traits::Hash;

/// Construct a root hash of a Binary Merkle Tree created from given leaves.
///
/// See crate-level docs for details about Merkle Tree construction.
///
/// In case an empty list of leaves is passed the function returns a 0-filled hash.
pub fn merkle_root<H, I>(leaves: I) -> H256
where
	H: Hash<Output = H256>,
	I: Iterator<Item = H256>,
{
	merkelize::<H, _, _>(leaves, &mut ())
}

fn merkelize<H, V, I>(leaves: I, visitor: &mut V) -> H256
where
	H: Hash<Output = H256>,
	V: Visitor,
	I: Iterator<Item = H256>,
{
	let upper = Vec::with_capacity(leaves.size_hint().0);
	let mut next = match merkelize_row::<H, _, _>(leaves, upper, visitor) {
		Ok(root) => return root,
		Err(next) if next.is_empty() => return H256::default(),
		Err(next) => next,
	};

	let mut upper = Vec::with_capacity(next.len().div_ceil(2));
	loop {
		visitor.move_up();

		match merkelize_row::<H, _, _>(next.drain(..), upper, visitor) {
			Ok(root) => return root,
			Err(t) => {
				// swap collections to avoid allocations
				upper = next;
				next = t;
			},
		};
	}
}

/// A generated merkle proof.
///
/// The structure contains all necessary data to later on verify the proof and the leaf itself.
#[derive(Encode, Decode, Debug, PartialEq, Eq, TypeInfo)]
pub struct MerkleProof {
	/// Root hash of generated merkle tree.
	pub root: H256,
	/// Proof items (does not contain the leaf hash, nor the root obviously).
	///
	/// This vec contains all inner node hashes necessary to reconstruct the root hash given the
	/// leaf hash.
	pub proof: Vec<H256>,
	/// Number of leaves in the original tree.
	///
	/// This is needed to detect a case where we have an odd number of leaves that "get promoted"
	/// to upper layers.
	pub number_of_leaves: u64,
	/// Index of the leaf the proof is for (0-based).
	pub leaf_index: u64,
	/// Leaf content (hashed).
	pub leaf: H256,
}

/// A trait of object inspecting merkle root creation.
///
/// It can be passed to [`merkelize_row`] or [`merkelize`] functions and will be notified
/// about tree traversal.
trait Visitor {
	/// We are moving one level up in the tree.
	fn move_up(&mut self);

	/// We are creating an inner node from given `left` and `right` nodes.
	///
	/// Note that in case of last odd node in the row `right` might be empty.
	/// The method will also visit the `root` hash (level 0).
	///
	/// The `index` is an index of `left` item.
	fn visit(&mut self, index: u64, left: &Option<H256>, right: &Option<H256>);
}

/// No-op implementation of the visitor.
impl Visitor for () {
	fn move_up(&mut self) {}
	fn visit(&mut self, _index: u64, _left: &Option<H256>, _right: &Option<H256>) {}
}

/// Construct a Merkle Proof for leaves given by indices.
///
/// The function constructs a (partial) Merkle Tree first and stores all elements required
/// to prove the requested item (leaf) given the root hash.
///
/// Both the Proof and the Root Hash are returned.
///
/// # Panic
///
/// The function will panic if given `leaf_index` is greater than the number of leaves.
pub fn merkle_proof<H, I>(leaves: I, leaf_index: u64) -> MerkleProof
where
	H: Hash<Output = H256>,
	I: Iterator<Item = H256>,
{
	let mut leaf = None;
	let mut hashes = vec![];
	let mut number_of_leaves = 0;
	for (idx, l) in (0u64..).zip(leaves) {
		// count the leaves
		number_of_leaves = idx + 1;
		hashes.push(l);
		// find the leaf for the proof
		if idx == leaf_index {
			leaf = Some(l);
		}
	}

	/// The struct collects a proof for single leaf.
	struct ProofCollection {
		proof: Vec<H256>,
		position: u64,
	}

	impl ProofCollection {
		fn new(position: u64) -> Self {
			ProofCollection { proof: Default::default(), position }
		}
	}

	impl Visitor for ProofCollection {
		fn move_up(&mut self) {
			self.position /= 2;
		}

		fn visit(&mut self, index: u64, left: &Option<H256>, right: &Option<H256>) {
			// we are at left branch - right goes to the proof.
			if self.position == index {
				if let Some(right) = right {
					self.proof.push(*right);
				}
			}
			// we are at right branch - left goes to the proof.
			if self.position == index + 1 {
				if let Some(left) = left {
					self.proof.push(*left);
				}
			}
		}
	}

	let mut collect_proof = ProofCollection::new(leaf_index);

	let root = merkelize::<H, _, _>(hashes.into_iter(), &mut collect_proof);
	let leaf = leaf.expect("Requested `leaf_index` is greater than number of leaves.");

	MerkleProof { root, proof: collect_proof.proof, number_of_leaves, leaf_index, leaf }
}

/// Leaf node for proof verification.
///
/// Can be either a value that needs to be hashed first,
/// or the hash itself.
#[derive(Debug, PartialEq, Eq)]
pub enum Leaf<'a> {
	/// Leaf content.
	Value(&'a [u8]),
	/// Hash of the leaf content.
	Hash(H256),
}

impl<'a, T: AsRef<[u8]>> From<&'a T> for Leaf<'a> {
	fn from(v: &'a T) -> Self {
		Leaf::Value(v.as_ref())
	}
}

impl<'a> From<H256> for Leaf<'a> {
	fn from(v: H256) -> Self {
		Leaf::Hash(v)
	}
}

/// Verify Merkle Proof correctness versus given root hash.
///
/// The proof is NOT expected to contain leaf hash as the first
/// element, but only all adjacent nodes required to eventually by process of
/// concatenating and hashing end up with given root hash.
///
/// The proof must not contain the root hash.
///
/// `leaf_index` is **load-bearing**: at each tree layer the verifier consults
/// `position & 1` of the *current* row position to decide whether the running hash sits on
/// the left (`current ‖ sibling`) or right (`sibling ‖ current`) of its parent. When the row
/// has odd width and the running hash is the trailing odd-element, that layer is *promoted*
/// (no sibling consumed, no hash performed) — exactly mirroring [`merkelize_row`]. This binds
/// the proof to a specific tree position: a proof generated for index `i` will not verify
/// against any other index `j != i`. Earlier revisions of this crate hashed sibling pairs in
/// sorted order, which made `leaf_index` decorative; see the crate-level docs for the
/// security rationale.
pub fn verify_proof<'a, H, P, L>(
	root: &'a H256,
	proof: P,
	number_of_leaves: u64,
	leaf_index: u64,
	leaf: L,
) -> bool
where
	H: Hash<Output = H256>,
	P: IntoIterator<Item = H256>,
	L: Into<Leaf<'a>>,
{
	if leaf_index >= number_of_leaves {
		return false;
	}

	let leaf_hash = match leaf.into() {
		Leaf::Value(content) => <H as Hash>::hash(content),
		Leaf::Hash(hash) => hash,
	};

	let hash_len = <H as sp_core::Hasher>::LENGTH;
	let mut combined = [0_u8; 64];
	let mut current = leaf_hash;
	let mut position = leaf_index;
	let mut row_width = number_of_leaves;
	let mut proof_iter = proof.into_iter();

	while row_width > 1 {
		// Trailing-odd-element promotion: when the current row has odd width and the running
		// hash is the last element in the row, it is simply forwarded to the next row without
		// consuming a sibling. This MUST mirror `merkelize_row`'s odd-promotion branch.
		let is_trailing_odd = (row_width % 2 == 1) && (position == row_width - 1);
		if !is_trailing_odd {
			let sibling = match proof_iter.next() {
				Some(s) => s,
				None => return false,
			};
			if position & 1 == 0 {
				combined[..hash_len].copy_from_slice(current.as_ref());
				combined[hash_len..].copy_from_slice(sibling.as_ref());
			} else {
				combined[..hash_len].copy_from_slice(sibling.as_ref());
				combined[hash_len..].copy_from_slice(current.as_ref());
			}
			current = <H as Hash>::hash(&combined);
		}
		position /= 2;
		row_width = row_width.div_ceil(2);
	}

	// Reject if the proof has unconsumed siblings; that indicates a malformed/forged proof.
	if proof_iter.next().is_some() {
		return false;
	}

	root == &current
}

/// Processes a single row (layer) of a tree by taking pairs of elements,
/// concatenating them, hashing and placing into resulting vector.
///
/// In case only one element is provided it is returned via `Ok` result, in any other case (also an
/// empty iterator) an `Err` with the inner nodes of upper layer is returned.
fn merkelize_row<H, V, I>(
	mut iter: I,
	mut next: Vec<H256>,
	visitor: &mut V,
) -> Result<H256, Vec<H256>>
where
	H: Hash<Output = H256>,
	V: Visitor,
	I: Iterator<Item = H256>,
{
	next.clear();

	let hash_len = <H as sp_core::Hasher>::LENGTH;
	let mut index = 0;
	let mut combined = vec![0_u8; hash_len * 2];
	loop {
		let a = iter.next();
		let b = iter.next();
		visitor.visit(index, &a, &b);

		index += 2;
		match (a, b) {
			(Some(a), Some(b)) => {
				// Positional `(left ‖ right)` hashing: `a` came from `iter` first and so it
				// holds the lower-index (left) sibling, `b` the higher-index (right) one. We
				// must NOT sort by hash value here — doing so would erase the position
				// information that `verify_proof` consumes via the bits of `leaf_index`.
				combined[..hash_len].copy_from_slice(a.as_ref());
				combined[hash_len..].copy_from_slice(b.as_ref());

				next.push(<H as Hash>::hash(&combined));
			},
			// Odd number of items. Promote the item to the upper layer.
			(Some(a), None) if !next.is_empty() => {
				next.push(a);
			},
			// Last item = root.
			(Some(a), None) => return Ok(a),
			// Finish up, no more items.
			_ => return Err(next),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use hex_literal::hex;
	use sp_crypto_hashing::keccak_256;
	use sp_runtime::traits::Keccak256;

	fn make_leaves(count: u64) -> Vec<H256> {
		(0..count).map(|i| keccak_256(&i.to_le_bytes()).into()).collect()
	}

	#[test]
	fn should_generate_empty_root() {
		// given
		sp_tracing::init_for_tests();
		let data = vec![];

		// when
		let out = merkle_root::<Keccak256, _>(data.into_iter());

		// then
		assert_eq!(
			hex::encode(out),
			"0000000000000000000000000000000000000000000000000000000000000000"
		);
	}

	#[test]
	fn should_generate_single_root() {
		// given
		sp_tracing::init_for_tests();
		let data = make_leaves(1);

		// when
		let out = merkle_root::<Keccak256, _>(data.into_iter());

		// then
		assert_eq!(
			hex::encode(out),
			"011b4d03dd8c01f1049143cf9c4c817e4b167f1d1b83e5c6f0f10d89ba1e7bce"
		);
	}

	#[test]
	fn should_generate_root_pow_2() {
		// given
		sp_tracing::init_for_tests();
		let data = make_leaves(2);

		// when
		let out = merkle_root::<Keccak256, _>(data.into_iter());

		// then
		assert_eq!(
			hex::encode(out),
			"e497bd1c13b13a60af56fa0d2703517c232fde213ad20d2c3dd60735c6604512"
		);
	}

	#[test]
	fn should_generate_root_complex() {
		sp_tracing::init_for_tests();
		let test = |root, data: Vec<H256>| {
			assert_eq!(
				array_bytes::bytes2hex("", merkle_root::<Keccak256, _>(data.into_iter()).as_ref()),
				root
			);
		};

		// NOTE: these roots changed from the upstream sorted-pair values when this crate switched
		// to positional `(left ‖ right)` hashing — see the crate-level docs and the security
		// rationale on `verify_proof`.
		test("9f0ed730035045c3a5bf327ad69bcbe7b97565b22508bafcfca2c143331b324a", make_leaves(3));

		test("763b4b6dc3a1c0abfe1802a0251376b9a7e20865c8dc6604c51b8607e687ddf0", make_leaves(4));

		test("3680559a0d08b50da89aeb450645af94af494a2fb196f742cba51cafd1ca6c44", make_leaves(10));
	}

	#[test]
	fn should_generate_and_verify_proof() {
		// given
		sp_tracing::init_for_tests();
		let data: Vec<H256> = make_leaves(3);

		// Note: we feed the `proof.leaf` (already-hashed) back into `verify_proof` so the
		// `Leaf::Hash` variant is used. Passing `&data[i]` would route through `Leaf::Value`
		// and re-hash, which is a different (and incorrect) usage.
		let proof0 = merkle_proof::<Keccak256, _>(data.clone().into_iter(), 0);
		assert!(verify_proof::<Keccak256, _, _>(
			&proof0.root,
			proof0.proof.clone(),
			data.len() as u64,
			proof0.leaf_index,
			proof0.leaf,
		));

		let proof1 = merkle_proof::<Keccak256, _>(data.clone().into_iter(), 1);
		assert!(verify_proof::<Keccak256, _, _>(
			&proof1.root,
			proof1.proof,
			data.len() as u64,
			proof1.leaf_index,
			proof1.leaf,
		));

		let proof2 = merkle_proof::<Keccak256, _>(data.clone().into_iter(), 2);
		assert!(verify_proof::<Keccak256, _, _>(
			&proof2.root,
			proof2.proof,
			data.len() as u64,
			proof2.leaf_index,
			proof2.leaf
		));

		// then
		assert_eq!(hex::encode(proof0.root), hex::encode(proof1.root));
		assert_eq!(hex::encode(proof2.root), hex::encode(proof1.root));

		assert!(!verify_proof::<Keccak256, _, _>(
			&H256::from_slice(&hex!(
				"fb3b3be94be9e983ba5e094c9c51a7d96a4fa2e5d8e891df00ca89ba05bb1239"
			)),
			proof0.proof,
			data.len() as u64,
			proof0.leaf_index,
			proof0.leaf
		));

		assert!(!verify_proof::<Keccak256, _, _>(
			&proof0.root,
			vec![],
			data.len() as u64,
			proof0.leaf_index,
			proof0.leaf
		));
	}

	/// Regression test for the "decorative `leaf_index`" bug class. Pre-fix, the verifier
	/// hashed sibling pairs in sorted order, so a `(leaf, proof)` pair for index `i` would
	/// verify against ANY other index `j` in `[0, number_of_leaves)`. Post-fix, the proof
	/// is bound to its position via the bits of `leaf_index`.
	#[test]
	fn verify_proof_rejects_substituted_leaf_index() {
		sp_tracing::init_for_tests();
		// 4 leaves so that all sibling positions exercise the bit logic at multiple layers.
		let data: Vec<H256> = make_leaves(4);
		let n = data.len() as u64;

		let proof0 = merkle_proof::<Keccak256, _>(data.clone().into_iter(), 0);

		// Positive control: legitimate position must verify.
		assert!(verify_proof::<Keccak256, _, _>(
			&proof0.root,
			proof0.proof.clone(),
			n,
			0,
			proof0.leaf,
		));

		// Negative: same `(leaf, proof)` payload, but claim it sits at every other index.
		// Pre-fix, all of these would have returned `true`. Post-fix, all must reject.
		for fake_index in 1..n {
			assert!(
				!verify_proof::<Keccak256, _, _>(
					&proof0.root,
					proof0.proof.clone(),
					n,
					fake_index,
					proof0.leaf,
				),
				"verify_proof must reject (leaf=0, proof=0) when claimed at index {fake_index}"
			);
		}

		// And a proof for a different index, with index 0's leaf, must also reject —
		// the proof path itself differs from index 0's path.
		let proof2 = merkle_proof::<Keccak256, _>(data.clone().into_iter(), 2);
		assert!(!verify_proof::<Keccak256, _, _>(
			&proof2.root,
			proof2.proof,
			n,
			0,
			proof0.leaf,
		));
	}

	/// Exhaustive sanity check that no `(leaf_i, proof_i)` verifies at any index `j != i`.
	/// This guards against a future regression that reintroduces sorted-pair fold logic.
	#[test]
	fn verify_proof_is_position_binding_across_all_indices() {
		sp_tracing::init_for_tests();
		let data: Vec<H256> = make_leaves(8);
		let n = data.len() as u64;

		for i in 0..n {
			let proof_i = merkle_proof::<Keccak256, _>(data.clone().into_iter(), i);
			assert!(verify_proof::<Keccak256, _, _>(
				&proof_i.root,
				proof_i.proof.clone(),
				n,
				i,
				proof_i.leaf,
			));
			for j in 0..n {
				if i == j {
					continue;
				}
				assert!(
					!verify_proof::<Keccak256, _, _>(
						&proof_i.root,
						proof_i.proof.clone(),
						n,
						j,
						proof_i.leaf,
					),
					"index {i}'s proof must not verify at index {j}"
				);
			}
		}
	}

	#[test]
	#[should_panic]
	fn should_panic_on_invalid_leaf_index() {
		sp_tracing::init_for_tests();
		merkle_proof::<Keccak256, _>(make_leaves(1).into_iter(), 5);
	}
}
