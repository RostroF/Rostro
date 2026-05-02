#![cfg_attr(not(feature = "std"), no_std)]

//! Merkle Mountain Range — Rostro hardening fork.
//!
//! Vendored fork of `polkadot-ckb-merkle-mountain-range` v0.8.1 with multi-layer
//! defense-in-depth against the Hyperbridge MMR attack class. See
//! `/tmp/security-audit-mmr-lib.md` and the inline `Rostro hardening (X)` markers
//! across `src/mmr.rs` and `src/ancestry_proof.rs` for details.
//!
//! The lib name (`mmr_lib`) and public API surface match upstream — only failure
//! modes change. Existing valid proofs still verify true; existing rejected proofs
//! still reject; the only difference is rejecting *more* malformed-input cases that
//! the upstream would have silently accepted.

pub mod ancestry_proof;
mod error;
pub mod helper;
mod merge;
mod mmr;
mod mmr_store;
#[cfg(test)]
mod tests;
pub mod util;

pub use ancestry_proof::{AncestryProof, NodeMerkleProof};
pub use error::{Error, Result};
pub use helper::{is_canonical_mmr_size, leaf_index_to_mmr_size, leaf_index_to_pos};
pub use merge::Merge;
pub use mmr::{MerkleProof, MMR};
pub use mmr_store::{MMRStoreReadOps, MMRStoreWriteOps};

cfg_if::cfg_if! {
    if #[cfg(feature = "std")] {
        use std::borrow;
        use std::collections;
        use std::vec;
        use std::string;
    } else {
        extern crate alloc;
        use alloc::borrow;
        use alloc::collections;
        use alloc::vec;
        use alloc::string;
    }
}
