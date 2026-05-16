// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Tests for [`U16RangeTableAir`].
//!
//! These verify the table-side bus contract: each row emits a
//! `push_interaction` call with the right bus name, value, multiplicity,
//! and `count_weight = 0` (table-entry sign convention). Soundness of the
//! LogUp balance is the proof system's responsibility.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, BaseAir, RowWindow};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_lookup::InteractionBuilder;

use crate::{
	COL_MULTIPLICITY, NUM_COLS, PREPROCESSED_NUM_COLS, U16RangeTableAir, U16_TABLE_HEIGHT,
	build_table_witness,
};

#[test]
fn table_height_is_exactly_2_pow_16() {
	assert_eq!(U16_TABLE_HEIGHT, 65_536);
}

#[test]
fn preprocessed_trace_emits_every_u16_in_order() {
	let air = U16RangeTableAir::new("test-bus");
	let pp =
		<U16RangeTableAir as BaseAir<Goldilocks>>::preprocessed_trace(&air).expect("table has pp");
	assert_eq!(pp.values.len(), U16_TABLE_HEIGHT * PREPROCESSED_NUM_COLS);
	for i in 0..U16_TABLE_HEIGHT {
		assert_eq!(
			pp.values[i],
			Goldilocks::from_u64(i as u64),
			"preprocessed value at row {} should equal i",
			i,
		);
	}
}

#[test]
fn build_table_witness_sums_match_input() {
	let mut mults = [0u32; U16_TABLE_HEIGHT];
	mults[0] = 1;
	mults[42] = 7;
	mults[65_535] = 3;

	let witness = build_table_witness(&mults);
	assert_eq!(witness.len(), U16_TABLE_HEIGHT);
	assert_eq!(witness[0], Goldilocks::from_u64(1));
	assert_eq!(witness[42], Goldilocks::from_u64(7));
	assert_eq!(witness[65_535], Goldilocks::from_u64(3));
	assert_eq!(witness[1], Goldilocks::ZERO);
}

/// Recording builder: captures every push_interaction call. Used for
/// structural verification of bus contracts without running a full prover.
struct RecordingInteractionBuilder<'a> {
	main_window: RowWindow<'a, Goldilocks>,
	preprocessed_window: RowWindow<'a, Goldilocks>,
	is_first: Goldilocks,
	is_last: Goldilocks,
	is_trans: Goldilocks,
	pushed: Vec<(String, Goldilocks, Vec<Goldilocks>, u32)>,
}

impl<'a> AirBuilder for RecordingInteractionBuilder<'a> {
	type F = Goldilocks;
	type Expr = Goldilocks;
	type Var = Goldilocks;
	type MainWindow = RowWindow<'a, Goldilocks>;
	type PreprocessedWindow = RowWindow<'a, Goldilocks>;
	type PublicVar = Goldilocks;
	type PeriodicVar = Goldilocks;

	fn main(&self) -> Self::MainWindow {
		self.main_window
	}
	fn preprocessed(&self) -> &Self::PreprocessedWindow {
		&self.preprocessed_window
	}
	fn is_first_row(&self) -> Self::Expr {
		self.is_first
	}
	fn is_last_row(&self) -> Self::Expr {
		self.is_last
	}
	fn is_transition_window(&self, _: usize) -> Self::Expr {
		self.is_trans
	}
	fn assert_zero<I: Into<Self::Expr>>(&mut self, _x: I) {}
}

impl<'a> InteractionBuilder for RecordingInteractionBuilder<'a> {
	fn push_interaction<E: Into<Self::Expr>>(
		&mut self,
		bus_name: &str,
		fields: impl IntoIterator<Item = E>,
		count: impl Into<Self::Expr>,
		count_weight: u32,
	) {
		let multiplicity: Goldilocks = count.into();
		let collected: Vec<Goldilocks> = fields.into_iter().map(Into::into).collect();
		self.pushed
			.push((String::from(bus_name), multiplicity, collected, count_weight));
	}

	fn push_local_interaction(
		&mut self,
		tuples: impl IntoIterator<Item = (Vec<Self::Expr>, Self::Expr)>,
	) {
		tuples.into_iter().for_each(drop);
	}
}

/// At an arbitrary row, the table emits exactly one `push_interaction`
/// call: bus_name = construction parameter, fields = [value], count =
/// -multiplicity, weight = 0.
#[test]
fn table_emits_negative_multiplicity_for_each_row() {
	let bus = "rostro-u16-range-test";
	let air = U16RangeTableAir::new(bus);

	// Build a witness row at index 42 with multiplicity 5.
	let row_idx = 42usize;
	let mut multiplicities = [0u32; U16_TABLE_HEIGHT];
	multiplicities[row_idx] = 5;
	let witness = build_table_witness(&multiplicities);

	let main_curr = &witness[row_idx * NUM_COLS..(row_idx + 1) * NUM_COLS];
	// "next" doesn't matter for this AIR — no transition constraints, just
	// a per-row table_entry. Pass any same-shape slice.
	let main_next = main_curr;

	let pp = <U16RangeTableAir as BaseAir<Goldilocks>>::preprocessed_trace(&air).unwrap();
	let pre_curr = &pp.values[row_idx * PREPROCESSED_NUM_COLS..(row_idx + 1) * PREPROCESSED_NUM_COLS];
	let pre_next = pre_curr;

	let mut builder = RecordingInteractionBuilder {
		main_window: RowWindow::from_two_rows(main_curr, main_next),
		preprocessed_window: RowWindow::from_two_rows(pre_curr, pre_next),
		is_first: Goldilocks::ZERO,
		is_last: Goldilocks::ZERO,
		is_trans: Goldilocks::ONE,
		pushed: Vec::new(),
	};
	air.eval(&mut builder);

	assert_eq!(builder.pushed.len(), 1, "exactly 1 table_entry call expected per row");
	let (name, mult, fields, weight) = &builder.pushed[0];
	assert_eq!(name, bus);
	assert_eq!(*mult, -Goldilocks::from_u64(5), "table entry count should be -multiplicity");
	assert_eq!(fields.len(), 1);
	assert_eq!(fields[0], Goldilocks::from_u64(row_idx as u64));
	assert_eq!(*weight, 0, "table entries carry weight 0 per p3-lookup convention");
}

/// Multiple table instances on different buses are independent.
#[test]
fn distinct_bus_names_create_distinct_tables() {
	let air_a = U16RangeTableAir::new("bus-a");
	let air_b = U16RangeTableAir::new("bus-b");
	assert_ne!(air_a.bus_name, air_b.bus_name);
}

/// Width and column constants are stable surface area — break them and
/// downstream callers break.
#[test]
fn width_and_layout_constants_are_stable() {
	let air = U16RangeTableAir::new("any");
	assert_eq!(<U16RangeTableAir as BaseAir<Goldilocks>>::width(&air), NUM_COLS);
	assert_eq!(NUM_COLS, 1);
	assert_eq!(PREPROCESSED_NUM_COLS, 1);
	assert_eq!(COL_MULTIPLICITY, 0);
}
