// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! External rounds of the Goldilocks-Poseidon2 (WIDTH=8) permutation as a Plonky3 AIR.
//!
//! Mirrors `p3_poseidon2::external_terminal_permute_state` constraint-by-constraint
//! for the four-round half-block (initial or terminal). The pre-block "extra MDS"
//! that `external_initial_permute_state` applies before the first round is NOT
//! constrained here; that linear step belongs at the call-site lookup wiring (it's a
//! free permutation of the input state cells from the caller's AIR).
//!
//! ## Trace shape
//!
//! - **Witness**: `(HALF_FULL_ROUNDS + 1) = 5` rows × `EXTERNAL_ROUND_NUM_COLS = 24`
//!   columns.
//!   - Rows 0..=3: state going INTO each of the 4 rounds, plus the S-box
//!     intermediate witnesses for that round.
//!   - Row 4: state coming OUT of round 3. Its intermediate-witness cells are
//!     unconstrained — no transition originates from row 4.
//! - **Preprocessed**: 5 rows × 8 columns holding the round-constant vector for
//!   each round. Row 4's preprocessed cells are zero (unused).
//!
//! ## Constraint discipline
//!
//! Per transition (rows 0..=3 → next), with `x_i := state_i + rc_i`:
//!   - `x_squared_i  == x_i * x_i`             (degree 2)
//!   - `x_to_4_i     == x_squared_i * x_squared_i`  (degree 2)
//!   - `next.state   == MDSlight( x_i * x_squared_i * x_to_4_i  for i in 0..8 )`
//!     where the right-hand side is degree 3 in trace cells.
//!
//! All constraints are degree ≤ 3.

extern crate alloc;

use alloc::vec::Vec;
use core::ops::Add;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::{
	GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL, GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL,
	Goldilocks,
};
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;

/// Width of the Poseidon2 state for Goldilocks (8 field elements).
pub const WIDTH: usize = 8;

/// Number of external rounds per half (4 initial + 4 terminal = 8 total).
pub const HALF_FULL_ROUNDS: usize = 4;

/// Per-row witness columns: state, x_squared, x_to_4 (each WIDTH cells).
pub const COL_STATE: usize = 0;
pub const COL_X_SQUARED: usize = WIDTH;
pub const COL_X_TO_4: usize = WIDTH * 2;

/// Total witness columns per row.
pub const EXTERNAL_ROUND_NUM_COLS: usize = WIDTH * 3;

/// Preprocessed columns per row: WIDTH round-constant cells.
pub const PREPROCESSED_NUM_COLS: usize = WIDTH;

/// Total trace rows. Last row holds the OUTPUT state of the half-block; rows
/// `0..HALF_FULL_ROUNDS` hold one round each.
pub const TRACE_HEIGHT: usize = HALF_FULL_ROUNDS + 1;

/// Whether this AIR instance constrains the initial (4 rounds at the start)
/// or terminal (4 rounds at the end) external block of Poseidon2.
///
/// Both share the same constraint structure but use different round-constant
/// tables.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExternalRoundKind {
	Initial,
	Terminal,
}

/// AIR for one half-block (4 external rounds) of Goldilocks-Poseidon2 WIDTH=8.
///
/// Each instance is bound to two named buses at construction:
/// - `bus_in`  — state[0..WIDTH] is RECEIVED from this bus on row 0.
/// - `bus_out` — state[0..WIDTH] is SENT to this bus on the last row.
///
/// Bus names are construction-time parameters so that one caller AIR can
/// instantiate multiple Poseidon2 invocations within a single batch each
/// with its own input/output buses.
#[derive(Clone, Debug)]
pub struct ExternalRoundAir {
	pub kind: ExternalRoundKind,
	pub bus_in: &'static str,
	pub bus_out: &'static str,
}

impl ExternalRoundAir {
	pub const fn new(
		kind: ExternalRoundKind,
		bus_in: &'static str,
		bus_out: &'static str,
	) -> Self {
		Self { kind, bus_in, bus_out }
	}

	pub const fn round_constants(&self) -> &'static [[Goldilocks; WIDTH]; HALF_FULL_ROUNDS] {
		match self.kind {
			ExternalRoundKind::Initial => &GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL,
			ExternalRoundKind::Terminal => &GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL,
		}
	}
}

impl<F: PrimeCharacteristicRing + Send + Sync> BaseAir<F> for ExternalRoundAir {
	fn width(&self) -> usize {
		EXTERNAL_ROUND_NUM_COLS
	}

	fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
		let rc_table = self.round_constants();
		let mut values = Vec::with_capacity(TRACE_HEIGHT * PREPROCESSED_NUM_COLS);
		for round in 0..HALF_FULL_ROUNDS {
			for i in 0..WIDTH {
				values.push(F::from_u64(rc_table[round][i].as_canonical_u64()));
			}
		}
		// Row HALF_FULL_ROUNDS: trailing output row, RC unused.
		for _ in 0..WIDTH {
			values.push(F::ZERO);
		}
		Some(RowMajorMatrix::new(values, PREPROCESSED_NUM_COLS))
	}
}

impl<AB: InteractionBuilder> Air<AB> for ExternalRoundAir
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

		let state: [AB::Var; WIDTH] = core::array::from_fn(|i| local[COL_STATE + i]);
		let x_squared: [AB::Var; WIDTH] = core::array::from_fn(|i| local[COL_X_SQUARED + i]);
		let x_to_4: [AB::Var; WIDTH] = core::array::from_fn(|i| local[COL_X_TO_4 + i]);
		let next_state: [AB::Var; WIDTH] = core::array::from_fn(|i| next[COL_STATE + i]);
		let rc: [AB::Var; WIDTH] = core::array::from_fn(|i| pre[i]);

		let x: [AB::Expr; WIDTH] = core::array::from_fn(|i| state[i] + rc[i]);

		// Bus interactions. Sign convention per p3-lookup: positive count =
		// send, negative = receive. State columns at row 0 carry the input
		// (received from upstream); at the last row they carry the output
		// (sent downstream). Multiplicity selects which row activates.
		builder.push_interaction(self.bus_in, state, -is_first, 1);
		builder.push_interaction(self.bus_out, state, is_last, 1);

		// Round-transition constraints (degree ≤ 3).
		let mut tb = builder.when(is_transition);

		for i in 0..WIDTH {
			tb.assert_eq(x[i].clone() * x[i].clone(), x_squared[i]);
		}

		for i in 0..WIDTH {
			tb.assert_eq(x_squared[i] * x_squared[i], x_to_4[i]);
		}

		let mut sbox_out: [AB::Expr; WIDTH] =
			core::array::from_fn(|i| x[i].clone() * x_squared[i] * x_to_4[i]);

		mds_light_permutation_8(&mut sbox_out);

		for i in 0..WIDTH {
			tb.assert_eq(sbox_out[i].clone(), next_state[i]);
		}
	}
}

/// Apply the 4×4 MDS matrix
/// ```text
///   [ 2 3 1 1 ]
///   [ 1 2 3 1 ]
///   [ 1 1 2 3 ]
///   [ 3 1 1 2 ]
/// ```
/// in place. Mirrors `apply_mat4` in `p3_poseidon2::external`.
fn apply_mat4<E>(x: &mut [E; 4])
where
	E: Clone + Add<E, Output = E>,
{
	let t01 = x[0].clone() + x[1].clone();
	let t23 = x[2].clone() + x[3].clone();
	let t0123 = t01.clone() + t23.clone();
	let t01123 = t0123.clone() + x[1].clone();
	let t01233 = t0123 + x[3].clone();
	let two_x0 = x[0].clone() + x[0].clone();
	let two_x2 = x[2].clone() + x[2].clone();
	x[3] = t01233.clone() + two_x0;
	x[1] = t01123.clone() + two_x2;
	x[0] = t01123 + t01;
	x[2] = t01233 + t23;
}

/// External-layer linear step for WIDTH=8: apply `apply_mat4` to each consecutive
/// 4-element chunk, then add the partial-sum vector to each element. Mirrors the
/// `WIDTH ∈ {4,8,12,16,20,24,32}` branch of `p3_poseidon2::mds_light_permutation`.
pub(crate) fn mds_light_permutation_8<E>(state: &mut [E; WIDTH])
where
	E: Clone + Add<E, Output = E>,
{
	{
		let (lo, hi) = state.split_at_mut(4);
		let lo: &mut [E; 4] =
			lo.try_into().expect("split_at_mut(4) of length-8 yields a 4-slice; qed");
		let hi: &mut [E; 4] =
			hi.try_into().expect("split_at_mut(4) of length-8 yields a 4-slice; qed");
		apply_mat4(lo);
		apply_mat4(hi);
	}

	let sums: [E; 4] = core::array::from_fn(|k| state[k].clone() + state[4 + k].clone());

	for i in 0..WIDTH {
		let new_val = state[i].clone() + sums[i % 4].clone();
		state[i] = new_val;
	}
}
