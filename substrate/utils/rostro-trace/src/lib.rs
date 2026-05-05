// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # rostro-trace
//!
//! Per-block execution-trace types + minimal Plonky3 AIR for the v0
//! tensor-DA-as-PCS pipeline. v0 is **observational and advisory** — the
//! trace captures coarse-grained state-transition data, an AIR constrains
//! chain consistency, and the resulting STARK proof is generated but not
//! enforced. Enforcement comes later via a runtime upgrade once the
//! verifier host function is baked into the node binary.
//!
//! ## What v0 captures
//!
//! Each block produces one [`BlockTraceRow`]:
//! - `block_number`: u32, sequential
//! - `extrinsic_count`: u32
//! - `pre_state_root`: 32-byte hash (chunked into 8 × u32 for the trace matrix)
//! - `post_state_root`: 32-byte hash (chunked into 8 × u32)
//! - `block_hash`: 32-byte hash (chunked into 8 × u32)
//!
//! Total: **26 trace columns** in the Goldilocks field.
//!
//! ## What v0 constrains
//!
//! [`ChainConsistencyAir`] enforces:
//! - `next.block_number == local.block_number + 1` (sequential block numbers)
//! - `next.pre_state_root == local.post_state_root` (state-root chain)
//!
//! That's all. v0 is the *skeleton* — proves the wiring (trace generation,
//! Plonky3 prover, AIR evaluation) works end-to-end. Real per-extrinsic
//! constraint logic lands in v1 via a more elaborate AIR over a richer
//! trace.
//!
//! ## What's deferred
//!
//! - Per-extrinsic execution trace (register/memory ops, host function calls)
//! - Tensor-DA encoding of the trace matrix
//! - Proof attachment to block headers (digest item)
//! - Verifier host function in the node binary
//! - Runtime upgrade flipping enforcement on

mod air;
mod prover;
mod row;

#[cfg(test)]
mod tests;

pub use air::{ChainConsistencyAir, COL_BLOCK_NUMBER, COL_EXTRINSIC_COUNT, COL_PRE_STATE_ROOT, COL_POST_STATE_ROOT, COL_BLOCK_HASH, NUM_COLS};
pub use prover::{make_config, prove_chain_window, verify_chain_window, Config, Proof, ProofMeta, ProverError};
pub use row::BlockTraceRow;
