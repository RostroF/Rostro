// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # rostro-poseidon-air
//!
//! Plonky3 AIR for the Goldilocks-Poseidon2 permutation, WIDTH=8.
//! Standalone hash AIR consumed by PoP per-algorithm AIRs
//! (`passport_attest_aa_*`, `passport_attest_ca_*`, `liveness_facematch`)
//! via cross-table lookups in the multi-table PoP architecture.
//!
//! Permutation parameters mirror `p3_goldilocks::Poseidon2Goldilocks<8>`:
//! - WIDTH = 8 Goldilocks state cells
//! - HALF_FULL_ROUNDS = 4 (so 8 total external rounds: 4 initial + 4 final)
//! - PARTIAL_ROUNDS = 22 (internal)
//! - SBOX_DEGREE = 7 (`x^7`)
//! - Round constants: `p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_8_*`
//! - External MDS: 4×4 fused MDS via `p3_goldilocks::MATRIX_DIAG_8_GOLDILOCKS`-style construction
//! - Internal layer: diagonal matrix `MATRIX_DIAG_8_GOLDILOCKS`
//!
//! ## Constraint discipline
//!
//! S-box `x^7` is degree 7, which would push constraint degree above
//! the typical Plonky3 budget (degree ≤ 3 for cheap LDE blowup). To
//! keep constraints low-degree, every S-box position carries
//! intermediate witness cells:
//! - `x_squared = (state + RC)^2` (degree-2 constraint)
//! - `x_to_4 = x_squared^2` (degree-2 constraint)
//! - `x_to_7 = (state + RC) * x_squared * x_to_4` (degree-3 constraint)
//!
//! All round-transition constraints are then degree ≤ 3.
//!
//! ## Status (2026-05-10)
//!
//! - **All round-transition constraints landed.** [`ExternalRoundAir`]
//!   constrains the four-round half-block (initial OR terminal — same shape,
//!   different round-constant table); [`InternalRoundAir`] constrains the
//!   22-round partial-round block (S-box on cell 0 only, diagonal linear
//!   layer with `MATRIX_DIAG_8_GOLDILOCKS`). Both keep max constraint degree
//!   at 3 via intermediate-witness columns (`x_squared`, `x_to_4`). Round
//!   constants live in preprocessed traces.
//! - **24 unit tests pass against vendored Plonky3 master rev b638013.**
//!   Coverage: trace shape, preprocessed-table correctness, per-round Rust
//!   reference vs `p3_poseidon2`'s `external_terminal_permute_state` and
//!   `internal_permute_state`, honest-trace AIR-eval acceptance, per-witness
//!   corruption rejection, and an end-to-end composition test that proves
//!   `pre-MDS → ExternalRoundAir(Initial) → InternalRoundAir → ExternalRoundAir(Terminal)`
//!   matches `p3_goldilocks::default_goldilocks_poseidon2_8` exactly.
//! - **Pre-block "extra MDS" not modeled here.** `external_initial_permute_state`
//!   prepends one bare `mds_light_permutation` before the first round; that's a
//!   linear function of the input state cells and belongs at the call-site
//!   lookup wiring, not in this AIR.
//! - **Sponge composition: not in this crate.** Input loading, capacity init,
//!   multi-permutation absorb/squeeze belong at the call-site (the AIR that's
//!   USING this hash) not in the permutation primitive itself.
//! - **Cross-AIR bus interactions: not yet wired.** This crate compiles and
//!   tests against the vendored `p3-lookup` machinery (master rev b638013,
//!   PR #1566). The next concrete unit of work is parameterizing each AIR
//!   over a bus name and pushing row-0 receives + row-N sends in `eval`:
//!     - `ExternalRoundAir(Initial)`:  row 0 ← input bus, row 4 → stage1 bus
//!     - `InternalRoundAir`:           row 0 ← stage1 bus, row 22 → stage2 bus
//!     - `ExternalRoundAir(Terminal)`: row 0 ← stage2 bus, row 4 → output bus
//!   Bus name MUST be construction-time parameterized — caller AIRs may want
//!   the SAME pair of round AIRs on different bus instances within one batch.
//!   Widening the [`p3_air::Air`] bound to [`p3_lookup::InteractionBuilder`]
//!   is the structural change; existing test [`ExpectZeroBuilder`] gains a
//!   no-op [`InteractionBuilder`] impl.
//! - **u32 range checks: separate workstream.** All PoP-side u32 witness
//!   columns must lookup-prove `value < 2^32`. Same lookup machinery, separate
//!   table AIR (or shared-table architecture across all PoP AIRs). Sequenced
//!   after the bus-receive/send pattern lands.

#![cfg_attr(not(feature = "std"), no_std)]

mod external_round;
mod internal_round;

pub use external_round::{
	COL_STATE, COL_X_SQUARED, COL_X_TO_4, EXTERNAL_ROUND_NUM_COLS, ExternalRoundAir,
	ExternalRoundKind, HALF_FULL_ROUNDS, PREPROCESSED_NUM_COLS, TRACE_HEIGHT, WIDTH,
};
pub use internal_round::{
	COL_INT_STATE, COL_INT_X_SQUARED, COL_INT_X_TO_4, INTERNAL_ROUND_NUM_COLS, InternalRoundAir,
	PARTIAL_ROUNDS, PREPROCESSED_NUM_COLS_INTERNAL, TRACE_HEIGHT_INTERNAL,
};

#[cfg(test)]
mod tests;
