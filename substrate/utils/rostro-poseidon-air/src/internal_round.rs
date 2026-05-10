// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Internal (partial) rounds of the Goldilocks-Poseidon2 (WIDTH=8) permutation
//! as a Plonky3 AIR.
//!
//! Mirrors `p3_poseidon2::internal_permute_state` constraint-by-constraint for
//! the 22-round internal block. Per round:
//!   1. Add the round constant to `state[0]` only.
//!   2. Apply the S-box `x → x^7` to `state[0]` only.
//!   3. Apply the internal linear layer: `state ← (1 + diag(D)) · state` where
//!      `D = MATRIX_DIAG_8_GOLDILOCKS`. Concretely,
//!      `new_state[i] = D[i] · state[i] + Σ_j state[j]`.
//!
//! Note: per `p3_poseidon2`, the diagonal stored as `MATRIX_DIAG_8_GOLDILOCKS`
//! is the `D` of `M = 1 + diag(D)` (named with the `_M_1` convention there).
//! There is no off-by-one in the matmul.
//!
//! ## Trace shape
//!
//! - **Witness**: `(PARTIAL_ROUNDS + 1) = 23` rows × `INTERNAL_ROUND_NUM_COLS = 10`
//!   columns.
//!   - Rows 0..=21: state going INTO each of the 22 rounds, plus the cell-0
//!     S-box intermediate witnesses (`x_squared`, `x_to_4`).
//!   - Row 22: state coming OUT of round 21. Its intermediate-witness cells
//!     are unconstrained.
//! - **Preprocessed**: 23 rows × 1 column holding the round constant for that
//!   round (a single scalar added to cell 0). Row 22's preprocessed cell is
//!   zero (unused).
//!
//! ## Constraint discipline
//!
//! Per transition (rows 0..=21 → next), with `x := state[0] + rc`:
//!   - `x_squared == x · x`                                    (degree 2)
//!   - `x_to_4    == x_squared · x_squared`                    (degree 2)
//!   - Build `sbox_out` with `sbox_out[0] = x · x_squared · x_to_4` (= `x^7`,
//!     degree 3) and `sbox_out[i] = state[i]` for i ≥ 1.
//!   - `next.state[i] == D[i] · sbox_out[i] + Σ_j sbox_out[j]` for all i
//!     (degree 3, dominated by the cell-0 term in the sum).
//!
//! All constraints are degree ≤ 3.

extern crate alloc;

use alloc::vec::Vec;
use core::ops::{Add, Mul};

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::{
	GOLDILOCKS_POSEIDON2_RC_8_INTERNAL, Goldilocks, MATRIX_DIAG_8_GOLDILOCKS,
};
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;

use crate::external_round::WIDTH;

/// Number of partial rounds for Goldilocks-Poseidon2 WIDTH=8 (matches
/// `p3_goldilocks::GOLDILOCKS_POSEIDON2_PARTIAL_ROUNDS_8`).
pub const PARTIAL_ROUNDS: usize = 22;

/// Per-row witness column layout: state, x_squared (scalar), x_to_4 (scalar).
pub const COL_INT_STATE: usize = 0;
pub const COL_INT_X_SQUARED: usize = WIDTH;
pub const COL_INT_X_TO_4: usize = WIDTH + 1;

/// Total witness columns per row.
pub const INTERNAL_ROUND_NUM_COLS: usize = WIDTH + 2;

/// Preprocessed columns per row: 1 scalar round-constant cell.
pub const PREPROCESSED_NUM_COLS_INTERNAL: usize = 1;

/// Total trace rows. Last row holds the OUTPUT state of the internal block.
pub const TRACE_HEIGHT_INTERNAL: usize = PARTIAL_ROUNDS + 1;

/// AIR for the 22 internal (partial) rounds of Goldilocks-Poseidon2 WIDTH=8.
///
/// Each instance is bound to two named buses at construction:
/// - `bus_in`  — state[0..WIDTH] is RECEIVED from this bus on row 0.
/// - `bus_out` — state[0..WIDTH] is SENT to this bus on the last row (22).
#[derive(Clone, Debug)]
pub struct InternalRoundAir {
	pub bus_in: &'static str,
	pub bus_out: &'static str,
}

impl InternalRoundAir {
	pub const fn new(bus_in: &'static str, bus_out: &'static str) -> Self {
		Self { bus_in, bus_out }
	}

	pub const fn round_constants(&self) -> &'static [Goldilocks; PARTIAL_ROUNDS] {
		&GOLDILOCKS_POSEIDON2_RC_8_INTERNAL
	}
}

impl<F: PrimeCharacteristicRing + Send + Sync> BaseAir<F> for InternalRoundAir {
	fn width(&self) -> usize {
		INTERNAL_ROUND_NUM_COLS
	}

	fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
		let rc_table = self.round_constants();
		let mut values = Vec::with_capacity(TRACE_HEIGHT_INTERNAL * PREPROCESSED_NUM_COLS_INTERNAL);
		for round in 0..PARTIAL_ROUNDS {
			values.push(F::from_u64(rc_table[round].as_canonical_u64()));
		}
		values.push(F::ZERO);
		Some(RowMajorMatrix::new(values, PREPROCESSED_NUM_COLS_INTERNAL))
	}
}

impl<AB: InteractionBuilder> Air<AB> for InternalRoundAir
where
	AB::F: Send,
{
	fn eval(&self, builder: &mut AB) {
		let main = builder.main();
		let preprocessed = builder.preprocessed().clone();
		let is_transition = builder.is_transition();
		let is_first = builder.is_first_row();
		let is_last = builder.is_last_row();

		let local = main.current_slice();
		let next = main.next_slice();
		let pre = preprocessed.current_slice();

		let state: [AB::Var; WIDTH] = core::array::from_fn(|i| local[COL_INT_STATE + i]);
		let x_squared: AB::Var = local[COL_INT_X_SQUARED];
		let x_to_4: AB::Var = local[COL_INT_X_TO_4];
		let next_state: [AB::Var; WIDTH] = core::array::from_fn(|i| next[COL_INT_STATE + i]);
		let rc: AB::Var = pre[0];

		let x: AB::Expr = state[0] + rc;

		// Bus interactions. Row 0 receives the state coming in from upstream;
		// last row sends the state going out to downstream.
		builder.push_interaction(self.bus_in, state, -is_first, 1);
		builder.push_interaction(self.bus_out, state, is_last, 1);

		let mut tb = builder.when(is_transition);

		tb.assert_eq(x.clone() * x.clone(), x_squared);
		tb.assert_eq(x_squared * x_squared, x_to_4);

		let mut sbox_out: [AB::Expr; WIDTH] = core::array::from_fn(|i| {
			if i == 0 {
				x.clone() * x_squared * x_to_4
			} else {
				state[i].into()
			}
		});

		let diag: [AB::Expr; WIDTH] = core::array::from_fn(|i| {
			AB::Expr::from_u64(MATRIX_DIAG_8_GOLDILOCKS[i].as_canonical_u64())
		});

		internal_linear_layer_8(&mut sbox_out, &diag);

		for i in 0..WIDTH {
			tb.assert_eq(sbox_out[i].clone(), next_state[i]);
		}
	}
}

/// Apply the internal layer matrix `M = 1 + diag(D)` to `state` in place:
/// `new_state[i] = D[i] · state[i] + Σ_j state[j]`. Generic over both the
/// AB::Expr (eval) and Goldilocks (test) sides.
pub(crate) fn internal_linear_layer_8<E>(state: &mut [E; WIDTH], diag: &[E; WIDTH])
where
	E: Clone + Add<E, Output = E> + Mul<E, Output = E>,
{
	let sum: E = state[0].clone()
		+ state[1].clone()
		+ state[2].clone()
		+ state[3].clone()
		+ state[4].clone()
		+ state[5].clone()
		+ state[6].clone()
		+ state[7].clone();

	for i in 0..WIDTH {
		let new_val = state[i].clone() * diag[i].clone() + sum.clone();
		state[i] = new_val;
	}
}
