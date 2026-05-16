// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! AIR for Chaum-Pedersen dlog-equality verification.
//!
//! Single-row, pure orchestration. Pushes 7 service-bus queries:
//!
//! | # | Bus           | Payload                          | Cells |
//! |---|---|---|---|
//! | 1 | BUS_SCALAR_MUL | `(s_bytes[32], G[32], s_G[32])`  | 96    |
//! | 2 | BUS_SCALAR_MUL | `(e_bytes[32], pk[32], e_pk[32])` | 96    |
//! | 3 | BUS_SCALAR_MUL | `(s_bytes[32], blinded[32], s_blinded[32])` | 96 |
//! | 4 | BUS_SCALAR_MUL | `(e_bytes[32], response[32], e_response[32])` | 96 |
//! | 5 | BUS_POINT_ADD  | `(R_pk[32], e_pk[32], s_G[32])`  | 96    |
//! | 6 | BUS_POINT_ADD  | `(R_resp[32], e_response[32], s_blinded[32])` | 96 |
//! | 7 | BUS_CP_DLOG_EQ | `(pk, blinded, response, R_pk, R_resp, e_bytes, s_bytes)` | 224 |
//!
//! Soundness comes entirely from LogUp balance with upstream services
//! (ScalarMulAir, PointAddAir). Sharing `s_G` between bus push #1 (the
//! scalar-mul output) and bus push #5 (the point-add output) makes the
//! Σ-protocol equation `s·G == R_pk + e·pk` structural — same trace
//! cells appear in both payloads, so equality is enforced by LogUp.
//! Same for `s_blinded`.
//!
//! ## Layout (352 columns)
//!
//! | Segment              | Width |
//! |---|---|
//! | pk[32]               | 32    |
//! | blinded[32]          | 32    |
//! | response[32]         | 32    |
//! | R_pk[32]             | 32    |
//! | R_resp[32]           | 32    |
//! | e_bytes[32]          | 32    |
//! | s_bytes[32]          | 32    |
//! | s_G[32]              | 32    |
//! | e_pk[32]             | 32    |
//! | s_blinded[32]        | 32    |
//! | e_response[32]       | 32    |
//!
//! ## What this AIR does NOT verify
//!
//! - That `e` was correctly derived via Fiat-Shamir from the transcript.
//!   That binding is the OUTER circuit's responsibility (see crate docs).
//! - That `s_bytes` is in the canonical scalar range `[0, ℓ)` where ℓ
//!   is the Edwards25519 prime-order subgroup order. ScalarMulAir works
//!   on raw 256-bit scalars; the OUTER circuit can range-check `s` if
//!   needed for signature-malleability defenses.

extern crate alloc;

use alloc::vec::Vec;

use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;

use rostro_curve25519::field::FIELD_NUM_LIMBS;
use rostro_curve25519::point::{add as point_add, scalar_mul, EdwardsPoint};
use rostro_curve25519::point_add_air::BUS_POINT_ADD;
use rostro_curve25519::scalar_mul_air::BUS_SCALAR_MUL;

use crate::{ed25519_basepoint, BUS_CP_DLOG_EQ};

/// Cells per Edwards point: `(x[8], y[8], z[8], t[8])`.
const POINT_CELLS: usize = 4 * FIELD_NUM_LIMBS;
/// Cells per 32-byte scalar.
const SCALAR_BYTES: usize = 32;

// ─── Column layout ────────────────────────────────────────────────────────

const COL_PK: usize = 0;
const COL_BLINDED: usize = COL_PK + POINT_CELLS;
const COL_RESPONSE: usize = COL_BLINDED + POINT_CELLS;
const COL_R_PK: usize = COL_RESPONSE + POINT_CELLS;
const COL_R_RESP: usize = COL_R_PK + POINT_CELLS;
const COL_E_BYTES: usize = COL_R_RESP + POINT_CELLS;
const COL_S_BYTES: usize = COL_E_BYTES + SCALAR_BYTES;
const COL_S_G: usize = COL_S_BYTES + SCALAR_BYTES;
const COL_E_PK: usize = COL_S_G + POINT_CELLS;
const COL_S_BLINDED: usize = COL_E_PK + POINT_CELLS;
const COL_E_RESPONSE: usize = COL_S_BLINDED + POINT_CELLS;

pub const CHAUM_PEDERSEN_AIR_NUM_COLS: usize = COL_E_RESPONSE + POINT_CELLS;
pub const CHAUM_PEDERSEN_AIR_TRACE_HEIGHT: usize = 1;

// ─── AIR ──────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct ChaumPedersenAir {
	pub bus_query: &'static str,
	pub bus_scalar_mul: &'static str,
	pub bus_point_add: &'static str,
}

impl ChaumPedersenAir {
	pub const fn new(
		bus_query: &'static str,
		bus_scalar_mul: &'static str,
		bus_point_add: &'static str,
	) -> Self {
		Self { bus_query, bus_scalar_mul, bus_point_add }
	}

	pub const fn default_buses() -> Self {
		Self {
			bus_query: BUS_CP_DLOG_EQ,
			bus_scalar_mul: BUS_SCALAR_MUL,
			bus_point_add: BUS_POINT_ADD,
		}
	}
}

impl<F: PrimeCharacteristicRing + Send + Sync> BaseAir<F> for ChaumPedersenAir {
	fn width(&self) -> usize {
		CHAUM_PEDERSEN_AIR_NUM_COLS
	}
}

impl<AB: InteractionBuilder> Air<AB> for ChaumPedersenAir
where
	AB::F: Send,
{
	fn eval(&self, builder: &mut AB) {
		let main = builder.main();
		let local = main.current_slice();

		let read_point = |start: usize| -> [AB::Expr; POINT_CELLS] {
			core::array::from_fn(|i| local[start + i].into())
		};
		let read_scalar = |start: usize| -> [AB::Expr; SCALAR_BYTES] {
			core::array::from_fn(|i| local[start + i].into())
		};

		// Load all segments once.
		let pk = read_point(COL_PK);
		let blinded = read_point(COL_BLINDED);
		let response = read_point(COL_RESPONSE);
		let r_pk = read_point(COL_R_PK);
		let r_resp = read_point(COL_R_RESP);
		let e_bytes = read_scalar(COL_E_BYTES);
		let s_bytes = read_scalar(COL_S_BYTES);
		let s_g = read_point(COL_S_G);
		let e_pk = read_point(COL_E_PK);
		let s_blinded = read_point(COL_S_BLINDED);
		let e_response = read_point(COL_E_RESPONSE);

		// Edwards25519 basepoint as a constant in the bus payload (verifier-known).
		let basepoint_expr: [AB::Expr; POINT_CELLS] = {
			let g = ed25519_basepoint();
			let mut out = [AB::Expr::ZERO; POINT_CELLS];
			for i in 0..FIELD_NUM_LIMBS {
				out[i] = AB::Expr::from_u64(u64::from(g.x[i]));
				out[FIELD_NUM_LIMBS + i] = AB::Expr::from_u64(u64::from(g.y[i]));
				out[2 * FIELD_NUM_LIMBS + i] = AB::Expr::from_u64(u64::from(g.z[i]));
				out[3 * FIELD_NUM_LIMBS + i] = AB::Expr::from_u64(u64::from(g.t[i]));
			}
			out
		};

		// Helper: BUS_SCALAR_MUL push (scalar[32], P[32], k·P[32]) = 96 cells.
		let push_scalar_mul = |
			builder: &mut AB,
			scalar: &[AB::Expr; SCALAR_BYTES],
			point: &[AB::Expr; POINT_CELLS],
			result: &[AB::Expr; POINT_CELLS],
		| {
			const N: usize = SCALAR_BYTES + 2 * POINT_CELLS;
			let payload: [AB::Expr; N] = core::array::from_fn(|i| {
				if i < SCALAR_BYTES {
					scalar[i].clone()
				} else if i < SCALAR_BYTES + POINT_CELLS {
					point[i - SCALAR_BYTES].clone()
				} else {
					result[i - SCALAR_BYTES - POINT_CELLS].clone()
				}
			});
			builder.push_interaction(self.bus_scalar_mul, payload, AB::Expr::ONE, 1);
		};

		// Helper: BUS_POINT_ADD push (P1[32], P2[32], P3[32]) = 96 cells.
		let push_point_add = |
			builder: &mut AB,
			p1: &[AB::Expr; POINT_CELLS],
			p2: &[AB::Expr; POINT_CELLS],
			p3: &[AB::Expr; POINT_CELLS],
		| {
			const N: usize = 3 * POINT_CELLS;
			let payload: [AB::Expr; N] = core::array::from_fn(|i| {
				if i < POINT_CELLS {
					p1[i].clone()
				} else if i < 2 * POINT_CELLS {
					p2[i - POINT_CELLS].clone()
				} else {
					p3[i - 2 * POINT_CELLS].clone()
				}
			});
			builder.push_interaction(self.bus_point_add, payload, AB::Expr::ONE, 1);
		};

		// (1) s · G = s_G
		push_scalar_mul(builder, &s_bytes, &basepoint_expr, &s_g);
		// (2) e · pk = e_pk
		push_scalar_mul(builder, &e_bytes, &pk, &e_pk);
		// (3) s · blinded = s_blinded
		push_scalar_mul(builder, &s_bytes, &blinded, &s_blinded);
		// (4) e · response = e_response
		push_scalar_mul(builder, &e_bytes, &response, &e_response);
		// (5) R_pk + e_pk = s_G  (same trace cells as in (1) — equality structural)
		push_point_add(builder, &r_pk, &e_pk, &s_g);
		// (6) R_resp + e_response = s_blinded
		push_point_add(builder, &r_resp, &e_response, &s_blinded);

		// (7) Service-bus close: receive (pk, blinded, response, R_pk, R_resp, e, s)
		//     = 5 × 32 + 2 × 32 = 224 cells.
		const SERVICE_PAYLOAD: usize = 5 * POINT_CELLS + 2 * SCALAR_BYTES;
		let mut service: [AB::Expr; SERVICE_PAYLOAD] =
			core::array::from_fn(|_| AB::Expr::ZERO);
		let mut cursor = 0;
		for src in [&pk, &blinded, &response, &r_pk, &r_resp] {
			for i in 0..POINT_CELLS {
				service[cursor + i] = src[i].clone();
			}
			cursor += POINT_CELLS;
		}
		for src in [&e_bytes, &s_bytes] {
			for i in 0..SCALAR_BYTES {
				service[cursor + i] = src[i].clone();
			}
			cursor += SCALAR_BYTES;
		}
		debug_assert_eq!(cursor, SERVICE_PAYLOAD);
		builder.push_interaction(self.bus_query, service, -AB::Expr::ONE, 1);
	}
}

// ─── Trace builder ────────────────────────────────────────────────────────

/// Build the trace row for one Chaum-Pedersen verification given honest
/// inputs `(pk, blinded, response, R_pk, R_resp, e_bytes, s_bytes)`.
/// Computes the four scalar-mul intermediates internally; the resulting
/// trace satisfies the AIR's bus payloads if the inputs are honest (i.e.,
/// `s·G == R_pk + e·pk` and `s·blinded == R_resp + e·response`).
pub fn build_chaum_pedersen_trace(
	pk: &EdwardsPoint,
	blinded: &EdwardsPoint,
	response: &EdwardsPoint,
	r_pk: &EdwardsPoint,
	r_resp: &EdwardsPoint,
	e_bytes: &[u8; SCALAR_BYTES],
	s_bytes: &[u8; SCALAR_BYTES],
) -> RowMajorMatrix<Goldilocks> {
	let g = ed25519_basepoint();
	let s_g = scalar_mul(s_bytes, &g);
	let e_pk = scalar_mul(e_bytes, pk);
	let s_blinded = scalar_mul(s_bytes, blinded);
	let e_response = scalar_mul(e_bytes, response);

	// Sanity: honest inputs satisfy the equations. Trace builder enforces.
	debug_assert!(
		points_equal_via_compress(&s_g, &point_add(r_pk, &e_pk)),
		"build_chaum_pedersen_trace called with non-honest inputs (eq 1 fails)",
	);
	debug_assert!(
		points_equal_via_compress(&s_blinded, &point_add(r_resp, &e_response)),
		"build_chaum_pedersen_trace called with non-honest inputs (eq 2 fails)",
	);

	let mut cells = Vec::with_capacity(CHAUM_PEDERSEN_AIR_NUM_COLS);
	push_point(&mut cells, pk);
	push_point(&mut cells, blinded);
	push_point(&mut cells, response);
	push_point(&mut cells, r_pk);
	push_point(&mut cells, r_resp);
	push_scalar(&mut cells, e_bytes);
	push_scalar(&mut cells, s_bytes);
	push_point(&mut cells, &s_g);
	push_point(&mut cells, &e_pk);
	push_point(&mut cells, &s_blinded);
	push_point(&mut cells, &e_response);

	debug_assert_eq!(cells.len(), CHAUM_PEDERSEN_AIR_NUM_COLS);
	RowMajorMatrix::new(cells, CHAUM_PEDERSEN_AIR_NUM_COLS)
}

fn push_point(cells: &mut Vec<Goldilocks>, p: &EdwardsPoint) {
	for &v in &p.x {
		cells.push(Goldilocks::from_u64(u64::from(v)));
	}
	for &v in &p.y {
		cells.push(Goldilocks::from_u64(u64::from(v)));
	}
	for &v in &p.z {
		cells.push(Goldilocks::from_u64(u64::from(v)));
	}
	for &v in &p.t {
		cells.push(Goldilocks::from_u64(u64::from(v)));
	}
}

fn push_scalar(cells: &mut Vec<Goldilocks>, s: &[u8; SCALAR_BYTES]) {
	for &b in s {
		cells.push(Goldilocks::from_u64(u64::from(b)));
	}
}

fn points_equal_via_compress(a: &EdwardsPoint, b: &EdwardsPoint) -> bool {
	use rostro_curve25519::ristretto::compress as ristretto_compress;
	ristretto_compress(a) == ristretto_compress(b)
}
