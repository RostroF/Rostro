// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! AIR for [`crate::hash_to_curve`].
//!
//! Single-row AIR. Pure orchestration — no in-row arithmetic. Every
//! computational step is delegated to a service AIR via a service-bus
//! query; integrity comes from LogUp balance with those upstream services.
//!
//! ## Pipeline (8 bus pushes per row)
//!
//! 1. Send `(private_nullifier, u_0[8], u_1[8])` on
//!    [`rostro_hash_to_field_air::hash_to_field_air::BUS_HASH_TO_FIELD`].
//! 2. Send `(u_0[8], P_0[32])` on
//!    [`rostro_curve25519::elligator2_air::BUS_ELLIGATOR2`].
//! 3. Send `(u_1[8], P_1[32])` on the same bus (different sponge instance
//!    in upstream batch).
//! 4. Send `(P_0[32], P_1[32], Q[32])` on
//!    [`rostro_curve25519::point_add_air::BUS_POINT_ADD`].
//! 5–7. Three sends on
//!    [`rostro_curve25519::point_double_air::BUS_POINT_DOUBLE`] with payload
//!    `(input.xyz[24], output[32])`: `(Q, 2Q)`, `(2Q, 4Q)`, `(4Q, 8Q)`.
//! 8. Receive `(private_nullifier, P_final[32])` on
//!    [`crate::BUS_HASH_TO_CURVE`] (multiplicity −1; the service-bus
//!    receive that closes the AIR).
//!
//! Each Edwards point is 32 cells: `(x[8], y[8], z[8], t[8])` extended-
//! coordinates. PointDoubleAir takes only `(x, y, z)` of its input by
//! convention (the doubling formula doesn't read `t`).
//!
//! ## Trace shape (209 columns)
//!
//! | Segment              | Width |
//! |---|---|
//! | private_nullifier    | 1     |
//! | u_0[8] / u_1[8]      | 16    |
//! | P_0[32] / P_1[32]    | 64    |
//! | Q[32]                | 32    |
//! | 2Q[32] / 4Q[32]      | 64    |
//! | 8Q[32] (= P_final)   | 32    |
//!
//! ## Soundness
//!
//! Shared witness columns appear in multiple bus payloads (e.g., `P_0`
//! appears in both BUS_ELLIGATOR2 (as output) and BUS_POINT_ADD (as input)).
//! Because we use the same trace cells in both pushes, value consistency
//! across stages is structural — no in-row constraints needed.
//!
//! Corruption rejection: any tampering with an intermediate point breaks
//! LogUp balance against at least one upstream service. The in-row
//! `ExpectZeroBuilder` cannot catch this (no in-row constraints fail);
//! coverage moves to integration time when the full Hash2Curve cluster
//! runs against a real LogUp-tracking prover.

extern crate alloc;

use alloc::vec::Vec;

use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;

use rostro_curve25519::elligator2::map_to_curve_elligator2_edwards25519;
use rostro_curve25519::elligator2_air::BUS_ELLIGATOR2;
use rostro_curve25519::field::FIELD_NUM_LIMBS;
use rostro_curve25519::point::{add as point_add, double as point_double, EdwardsPoint};
use rostro_curve25519::point_add_air::BUS_POINT_ADD;
use rostro_curve25519::point_double_air::BUS_POINT_DOUBLE;
use rostro_hash_to_field_air::hash_to_field;
use rostro_hash_to_field_air::hash_to_field_air::BUS_HASH_TO_FIELD;

use crate::BUS_HASH_TO_CURVE;

/// Cells per extended-coords Edwards point: `(x[8], y[8], z[8], t[8])`.
const POINT_CELLS: usize = 4 * FIELD_NUM_LIMBS;
/// Cells per `(x, y, z)`-only point (input shape for PointDoubleAir).
const POINT_XYZ_CELLS: usize = 3 * FIELD_NUM_LIMBS;

// ─── Column layout ────────────────────────────────────────────────────────

const COL_PRIVATE_NULLIFIER: usize = 0;
const COL_U_0: usize = COL_PRIVATE_NULLIFIER + 1;
const COL_U_1: usize = COL_U_0 + FIELD_NUM_LIMBS;
const COL_P_0: usize = COL_U_1 + FIELD_NUM_LIMBS;
const COL_P_1: usize = COL_P_0 + POINT_CELLS;
const COL_Q: usize = COL_P_1 + POINT_CELLS;
const COL_TWO_Q: usize = COL_Q + POINT_CELLS;
const COL_FOUR_Q: usize = COL_TWO_Q + POINT_CELLS;
const COL_EIGHT_Q: usize = COL_FOUR_Q + POINT_CELLS;

/// Total trace column width.
pub const HASH_TO_CURVE_AIR_NUM_COLS: usize = COL_EIGHT_Q + POINT_CELLS;

/// Single-row AIR.
pub const HASH_TO_CURVE_AIR_TRACE_HEIGHT: usize = 1;

// ─── AIR ──────────────────────────────────────────────────────────────────

/// AIR for one hash_to_curve invocation. Pure orchestration: pushes 7
/// service-bus queries (1× hash_to_field + 2× elligator2 + 1× point_add
/// + 3× point_double) and receives on `bus_query` (default
/// [`BUS_HASH_TO_CURVE`]).
#[derive(Clone, Debug)]
pub struct Hash2CurveAir {
	/// Service bus this AIR provides.
	pub bus_query: &'static str,
	/// Upstream service buses. Must match the names used by the upstream
	/// AIRs in the same batch.
	pub bus_hash_to_field: &'static str,
	pub bus_elligator2: &'static str,
	pub bus_point_add: &'static str,
	pub bus_point_double: &'static str,
}

impl Hash2CurveAir {
	pub const fn new(
		bus_query: &'static str,
		bus_hash_to_field: &'static str,
		bus_elligator2: &'static str,
		bus_point_add: &'static str,
		bus_point_double: &'static str,
	) -> Self {
		Self {
			bus_query,
			bus_hash_to_field,
			bus_elligator2,
			bus_point_add,
			bus_point_double,
		}
	}

	/// Construct with all default bus names. Convenient when there is
	/// exactly one Hash2Curve invocation per batch.
	pub const fn default_buses() -> Self {
		Self {
			bus_query: BUS_HASH_TO_CURVE,
			bus_hash_to_field: BUS_HASH_TO_FIELD,
			bus_elligator2: BUS_ELLIGATOR2,
			bus_point_add: BUS_POINT_ADD,
			bus_point_double: BUS_POINT_DOUBLE,
		}
	}
}

impl<F: PrimeCharacteristicRing + Send + Sync> BaseAir<F> for Hash2CurveAir {
	fn width(&self) -> usize {
		HASH_TO_CURVE_AIR_NUM_COLS
	}
}

impl<AB: InteractionBuilder> Air<AB> for Hash2CurveAir
where
	AB::F: Send,
{
	fn eval(&self, builder: &mut AB) {
		let main = builder.main();
		let local = main.current_slice();

		let private_nullifier: AB::Var = local[COL_PRIVATE_NULLIFIER];

		// Helper to read a contiguous run of cells as a fixed-size expr array.
		let read_field = |start: usize| -> [AB::Expr; FIELD_NUM_LIMBS] {
			core::array::from_fn(|i| local[start + i].into())
		};
		let read_point = |start: usize| -> [AB::Expr; POINT_CELLS] {
			core::array::from_fn(|i| local[start + i].into())
		};
		let read_point_xyz = |start: usize| -> [AB::Expr; POINT_XYZ_CELLS] {
			core::array::from_fn(|i| local[start + i].into())
		};

		// (1) BUS_HASH_TO_FIELD send: (private_nullifier, u_0[8], u_1[8]) = 17
		{
			const N: usize = 1 + 2 * FIELD_NUM_LIMBS;
			let payload: [AB::Expr; N] = core::array::from_fn(|i| {
				if i == 0 {
					private_nullifier.into()
				} else if i <= FIELD_NUM_LIMBS {
					local[COL_U_0 + i - 1].into()
				} else {
					local[COL_U_1 + i - 1 - FIELD_NUM_LIMBS].into()
				}
			});
			builder.push_interaction(self.bus_hash_to_field, payload, AB::Expr::ONE, 1);
		}

		// (2) BUS_ELLIGATOR2 send: (u_0[8], P_0[32]) = 40
		{
			const N: usize = FIELD_NUM_LIMBS + POINT_CELLS;
			let u_0 = read_field(COL_U_0);
			let p_0 = read_point(COL_P_0);
			let payload: [AB::Expr; N] = core::array::from_fn(|i| {
				if i < FIELD_NUM_LIMBS {
					u_0[i].clone()
				} else {
					p_0[i - FIELD_NUM_LIMBS].clone()
				}
			});
			builder.push_interaction(self.bus_elligator2, payload, AB::Expr::ONE, 1);
		}

		// (3) BUS_ELLIGATOR2 send: (u_1[8], P_1[32]) = 40
		{
			const N: usize = FIELD_NUM_LIMBS + POINT_CELLS;
			let u_1 = read_field(COL_U_1);
			let p_1 = read_point(COL_P_1);
			let payload: [AB::Expr; N] = core::array::from_fn(|i| {
				if i < FIELD_NUM_LIMBS {
					u_1[i].clone()
				} else {
					p_1[i - FIELD_NUM_LIMBS].clone()
				}
			});
			builder.push_interaction(self.bus_elligator2, payload, AB::Expr::ONE, 1);
		}

		// (4) BUS_POINT_ADD send: (P_0[32], P_1[32], Q[32]) = 96
		{
			const N: usize = 3 * POINT_CELLS;
			let p_0 = read_point(COL_P_0);
			let p_1 = read_point(COL_P_1);
			let q = read_point(COL_Q);
			let payload: [AB::Expr; N] = core::array::from_fn(|i| {
				if i < POINT_CELLS {
					p_0[i].clone()
				} else if i < 2 * POINT_CELLS {
					p_1[i - POINT_CELLS].clone()
				} else {
					q[i - 2 * POINT_CELLS].clone()
				}
			});
			builder.push_interaction(self.bus_point_add, payload, AB::Expr::ONE, 1);
		}

		// (5–7) BUS_POINT_DOUBLE sends: (Q.xyz[24], 2Q[32]), (2Q.xyz, 4Q),
		// (4Q.xyz, 8Q). Payload size 56 each.
		const DOUBLE_PAYLOAD: usize = POINT_XYZ_CELLS + POINT_CELLS;
		for (input_xyz_col, output_col) in [
			(COL_Q, COL_TWO_Q),
			(COL_TWO_Q, COL_FOUR_Q),
			(COL_FOUR_Q, COL_EIGHT_Q),
		] {
			let xyz = read_point_xyz(input_xyz_col);
			let out = read_point(output_col);
			let payload: [AB::Expr; DOUBLE_PAYLOAD] = core::array::from_fn(|i| {
				if i < POINT_XYZ_CELLS {
					xyz[i].clone()
				} else {
					out[i - POINT_XYZ_CELLS].clone()
				}
			});
			builder.push_interaction(self.bus_point_double, payload, AB::Expr::ONE, 1);
		}

		// (8) BUS_HASH_TO_CURVE receive (service-bus close): payload =
		// (private_nullifier, P_final[32]) = 33 cells.
		{
			const N: usize = 1 + POINT_CELLS;
			let p_final = read_point(COL_EIGHT_Q);
			let payload: [AB::Expr; N] = core::array::from_fn(|i| {
				if i == 0 {
					private_nullifier.into()
				} else {
					p_final[i - 1].clone()
				}
			});
			builder.push_interaction(self.bus_query, payload, -AB::Expr::ONE, 1);
		}
	}
}

// ─── Trace builder ────────────────────────────────────────────────────────

/// Build the trace row for one hash_to_curve invocation.
pub fn build_hash_to_curve_trace(
	private_nullifier: Goldilocks,
) -> RowMajorMatrix<Goldilocks> {
	let (u_0, u_1) = hash_to_field(private_nullifier);
	let p_0 = map_to_curve_elligator2_edwards25519(&u_0);
	let p_1 = map_to_curve_elligator2_edwards25519(&u_1);
	let q = point_add(&p_0, &p_1);
	let two_q = point_double(&q);
	let four_q = point_double(&two_q);
	let eight_q = point_double(&four_q);

	let mut cells = Vec::with_capacity(HASH_TO_CURVE_AIR_NUM_COLS);
	cells.push(private_nullifier);
	push_field_limbs(&mut cells, &u_0);
	push_field_limbs(&mut cells, &u_1);
	push_point(&mut cells, &p_0);
	push_point(&mut cells, &p_1);
	push_point(&mut cells, &q);
	push_point(&mut cells, &two_q);
	push_point(&mut cells, &four_q);
	push_point(&mut cells, &eight_q);

	debug_assert_eq!(cells.len(), HASH_TO_CURVE_AIR_NUM_COLS);
	RowMajorMatrix::new(cells, HASH_TO_CURVE_AIR_NUM_COLS)
}

fn push_field_limbs(cells: &mut Vec<Goldilocks>, limbs: &[u32; FIELD_NUM_LIMBS]) {
	for &v in limbs {
		cells.push(Goldilocks::from_u64(u64::from(v)));
	}
}

fn push_point(cells: &mut Vec<Goldilocks>, p: &EdwardsPoint) {
	push_field_limbs(cells, &p.x);
	push_field_limbs(cells, &p.y);
	push_field_limbs(cells, &p.z);
	push_field_limbs(cells, &p.t);
}
