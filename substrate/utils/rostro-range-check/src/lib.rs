// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # rostro-range-check
//!
//! u16-range lookup table AIR over Goldilocks for use in Rostro's PoP path.
//!
//! Every u32-typed witness column in a PoP AIR (per
//! `pop_air_goldilocks_packing_convention.md` — one u32 per Goldilocks
//! element) must be range-proven `value < 2^32`. Without that, a malicious
//! prover can put values ≥ 2^32 in those columns and break soundness of
//! every downstream constraint that assumes u32 shape (RSA modular
//! exponentiation, SHA-256 byte arithmetic, Poseidon2 sponge state…).
//!
//! Bit-decomposition is too expensive (~5× column blowup at AA-AIR scale).
//! Lookup-table range checks are the only viable enforcement: split each
//! u32 into two u16 halves, lookup each half against a shared table that
//! carries every value in `[0, 2^16)`.
//!
//! ## What this crate provides
//!
//! [`U16RangeTableAir`] — the **table side** of the lookup. Single AIR
//! shared across all PoP AIRs in a batch:
//! - Trace height `2^16 = 65 536` rows.
//! - Preprocessed: one column, `row[i].value = i`.
//! - Witness: one column, `row[i].multiplicity = number of caller-side
//!   lookups that hit value i across the entire batch`.
//! - Bus contract: emits `table_entry(bus, [value], multiplicity)` per row.
//!
//! Caller AIRs (e.g. `passport_attest_aa_*`) speak the **lookup side** by
//! calling `lookup_key(bus, [value], +1)` for each u16 half they want
//! range-proven. The LogUp argument balances the global bus (sum of
//! receives = sum of sends) and the proof system rejects any imbalance.
//!
//! ## Bus name
//!
//! Bus identifier is a construction-time parameter — the silo principle
//! says callers picking different bus names get separate audits, even
//! when the table contents are identical. Production callers in PoP
//! converge on a single bus across the batch (one shared table = lower
//! prover cost), but this crate doesn't enforce a global convention.
//!
//! ## Status (2026-05-10)
//!
//! - Table AIR scaffolded with preprocessed-value column + multiplicity
//!   witness column.
//! - 4 unit tests: trace shape, preprocessed-table content matches
//!   `[0..2^16)`, recording-builder verifies the per-row `table_entry`
//!   call has the right bus name + sign + weight.
//! - **Caller-side helpers** (`lookup_u16`, `lookup_u32_split_into_u16s`)
//!   are deferred — they belong in the same crate as the caller AIRs
//!   (per silo: utility helpers next to the AIR that uses them, not in
//!   a separate crate that tempts cross-purpose-file violations).

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;

/// Number of distinct u16 values, sized to `2^16`. Trace height of
/// [`U16RangeTableAir`] is exactly this.
pub const U16_TABLE_HEIGHT: usize = 1 << 16;

/// Preprocessed columns: the table value at each row.
pub const PREPROCESSED_NUM_COLS: usize = 1;

/// Witness columns: the multiplicity (lookup count) per row.
pub const NUM_COLS: usize = 1;

/// Column index of the witnessed multiplicity per row.
pub const COL_MULTIPLICITY: usize = 0;

/// AIR that provides every value in `[0, 2^16)` on a named bus.
///
/// Prover responsibility: fill the multiplicity column so that for each
/// row `i`, `multiplicity[i] = (number of caller-side lookups for value
/// i across the entire batch)`. The LogUp argument verifies this balance.
#[derive(Clone, Debug)]
pub struct U16RangeTableAir {
	pub bus_name: &'static str,
}

impl U16RangeTableAir {
	pub const fn new(bus_name: &'static str) -> Self {
		Self { bus_name }
	}
}

impl<F: PrimeCharacteristicRing + Send + Sync> BaseAir<F> for U16RangeTableAir {
	fn width(&self) -> usize {
		NUM_COLS
	}

	fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
		let mut values = Vec::with_capacity(U16_TABLE_HEIGHT * PREPROCESSED_NUM_COLS);
		for i in 0..U16_TABLE_HEIGHT {
			values.push(F::from_u64(i as u64));
		}
		Some(RowMajorMatrix::new(values, PREPROCESSED_NUM_COLS))
	}
}

impl<AB: InteractionBuilder> Air<AB> for U16RangeTableAir
where
	AB::F: Send,
{
	fn eval(&self, builder: &mut AB) {
		let main = builder.main();
		let preprocessed = builder.preprocessed().clone();

		let local = main.current_slice();
		let pre = preprocessed.current_slice();

		let multiplicity: AB::Var = local[COL_MULTIPLICITY];
		let value: AB::Var = pre[0];

		// Provide one table entry per row. `count_weight = 0` per
		// p3-lookup convention for table-side entries (caller-side
		// lookups carry weight 1 toward the height-bound soundness
		// constraint `Σ weight_i * height_i < p`; the table itself
		// doesn't contribute height).
		//
		// Sign convention: negative count = receive (i.e. table entry being
		// provided). Caller-side lookups use positive count to query.
		// Negation is on Expr (Var doesn't impl Neg directly).
		let neg_multiplicity: AB::Expr = AB::Expr::ZERO - multiplicity;
		builder.push_interaction(self.bus_name, [value], neg_multiplicity, 0);
	}
}

/// Build a witness trace of [`U16_TABLE_HEIGHT`] rows from a per-value
/// multiplicity table. `multiplicities[i]` is the count of caller-side
/// lookups that should hit value `i`.
pub fn build_table_witness(multiplicities: &[u32; U16_TABLE_HEIGHT]) -> Vec<Goldilocks> {
	let mut out = Vec::with_capacity(U16_TABLE_HEIGHT);
	for &m in multiplicities.iter() {
		out.push(Goldilocks::from_u64(u64::from(m)));
	}
	out
}

#[cfg(test)]
mod tests;
