// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # rostro-poseidon-sponge-air
//!
//! Service-bus wrapper around the Goldilocks-Poseidon2 WIDTH=8 permutation.
//!
//! Provides a single bus, [`SpongeShellAir::bus_query`], on which a consumer
//! sends a query payload `(input[8], output[8])` to assert
//! `output == Permutation(input)` where `Permutation` is the canonical
//! `default_goldilocks_poseidon2_8`.
//!
//! Realising one permutation invocation requires **four** AIRs included in
//! the same batch with consistent bus names:
//!
//! 1. [`SpongeShellAir`] — single-row shell. Carries `input`, `output`, and
//!    the post-pre-MDS state. Receives on `bus_query`, sends on `bus_init_in`,
//!    receives on `bus_term_out`. Constrains
//!    `post_mds = mds_light_permutation_8(input)` (the linear pre-block layer
//!    that `external_initial_permute_state` prepends and that
//!    [`rostro_poseidon_air::ExternalRoundAir`] does NOT cover).
//! 2. [`rostro_poseidon_air::ExternalRoundAir`] (Initial kind) — 5 rows × 4
//!    full rounds.
//! 3. [`rostro_poseidon_air::InternalRoundAir`] — 23 rows × 22 partial rounds.
//! 4. [`rostro_poseidon_air::ExternalRoundAir`] (Terminal kind) — 5 rows × 4
//!    full rounds.
//!
//! Use [`build_sponge_airs`] to construct all four with consistent
//! auto-suffixed internal bus names.
//!
//! ## Sponge usage from a consumer AIR
//!
//! ```ignore
//! // In your AIR's eval():
//! builder.push_interaction(
//!     bus_query,                     // matches the SpongeShellAir's bus_query
//!     input.iter().chain(output.iter()).copied(),  // 16 cells
//!     AB::Expr::ONE,                 // send (positive)
//!     1,
//! );
//! ```
//!
//! ## Status
//!
//! - WIDTH=8, single-permutation sponge sized for inputs that fit the full
//!   state (e.g., `private_nullifier + DST + counter` in hash_to_field).
//! - Multi-block absorption (longer inputs requiring multiple permutations
//!   chained with capacity carry) is NOT in scope here. If/when needed, add a
//!   separate AIR; do not extend this one (silo principle).

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{boxed::Box, format, string::String};

use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;

use rostro_poseidon_air::{
	mds_light_permutation_8, ExternalRoundAir, ExternalRoundKind, InternalRoundAir, WIDTH,
};

/// Number of trace columns in [`SpongeShellAir`].
pub const SPONGE_SHELL_NUM_COLS: usize = 3 * WIDTH; // input, post_mds, output
/// Single-row trace (the permutation is one-shot at this layer).
pub const SPONGE_SHELL_TRACE_HEIGHT: usize = 1;

const COL_INPUT: usize = 0;
const COL_POST_MDS: usize = WIDTH;
const COL_OUTPUT: usize = 2 * WIDTH;

/// Reference (witness-side) implementation of the WIDTH=8 sponge:
/// `output = default_goldilocks_poseidon2_8.permute(input)`.
///
/// This is the source of truth used by [`SpongeShellAir`] for trace
/// generation; it MUST stay in algebraic agreement with the AIR — the
/// `composition_matches_p3_default` test in this crate's test module is the
/// load-bearing parity check.
pub fn poseidon2_sponge_8(input: [Goldilocks; WIDTH]) -> [Goldilocks; WIDTH] {
	use p3_goldilocks::default_goldilocks_poseidon2_8;
	use p3_symmetric::Permutation;
	let perm = default_goldilocks_poseidon2_8();
	let mut state = input;
	perm.permute_mut(&mut state);
	state
}

/// Single-row shell AIR for one Poseidon2 sponge invocation.
///
/// Constraints:
/// - `post_mds[i] == mds_light_permutation_8(input)[i]` for `i ∈ 0..WIDTH`.
///
/// Bus interactions (one per row, single row):
/// - Receive on [`Self::bus_query`], payload `input || output` (16 cells),
///   multiplicity −1.
/// - Send on [`Self::bus_init_in`], payload `post_mds` (8 cells), multiplicity +1.
/// - Receive on [`Self::bus_term_out`], payload `output` (8 cells), multiplicity −1.
#[derive(Clone, Debug)]
pub struct SpongeShellAir {
	pub bus_query: &'static str,
	pub bus_init_in: &'static str,
	pub bus_term_out: &'static str,
}

impl SpongeShellAir {
	pub const fn new(
		bus_query: &'static str,
		bus_init_in: &'static str,
		bus_term_out: &'static str,
	) -> Self {
		Self { bus_query, bus_init_in, bus_term_out }
	}
}

impl<F: PrimeCharacteristicRing + Send + Sync> BaseAir<F> for SpongeShellAir {
	fn width(&self) -> usize {
		SPONGE_SHELL_NUM_COLS
	}
}

impl<AB: InteractionBuilder> Air<AB> for SpongeShellAir
where
	AB::F: Send,
{
	fn eval(&self, builder: &mut AB) {
		let main = builder.main();
		let local = main.current_slice();

		let input: [AB::Var; WIDTH] = core::array::from_fn(|i| local[COL_INPUT + i]);
		let post_mds: [AB::Var; WIDTH] = core::array::from_fn(|i| local[COL_POST_MDS + i]);
		let output: [AB::Var; WIDTH] = core::array::from_fn(|i| local[COL_OUTPUT + i]);

		// Pre-MDS linear constraint: post_mds = M · input.
		// Apply the same `mds_light_permutation_8` used on the witness side
		// to satisfy E: Clone + Add — AB::Expr meets that.
		let mut input_expr: [AB::Expr; WIDTH] =
			core::array::from_fn(|i| input[i].into());
		mds_light_permutation_8(&mut input_expr);
		for i in 0..WIDTH {
			builder.assert_zero(post_mds[i].into() - input_expr[i].clone());
		}

		// Bus glue.
		// (1) Receive query on bus_query — payload is input || output (16 cells).
		let query_payload: [AB::Expr; 2 * WIDTH] = core::array::from_fn(|i| {
			if i < WIDTH { input[i].into() } else { output[i - WIDTH].into() }
		});
		builder.push_interaction(
			self.bus_query,
			query_payload,
			-AB::Expr::ONE,
			1,
		);

		// (2) Send post-MDS state into the round chain.
		let post_mds_payload: [AB::Expr; WIDTH] = core::array::from_fn(|i| post_mds[i].into());
		builder.push_interaction(self.bus_init_in, post_mds_payload, AB::Expr::ONE, 1);

		// (3) Receive permuted output from the terminal-round AIR.
		let output_payload: [AB::Expr; WIDTH] = core::array::from_fn(|i| output[i].into());
		builder.push_interaction(self.bus_term_out, output_payload, -AB::Expr::ONE, 1);
	}
}

/// All four AIRs needed to realise one Poseidon2 sponge invocation, with
/// consistently-named internal buses.
#[derive(Clone, Debug)]
pub struct SpongeAirs {
	pub shell: SpongeShellAir,
	pub external_initial: ExternalRoundAir,
	pub internal: InternalRoundAir,
	pub external_terminal: ExternalRoundAir,
}

/// Build a complete [`SpongeAirs`] bundle with internal buses derived from
/// `bus_query`. Each call site uses a distinct `bus_query` to avoid LogUp
/// crosstalk across multiple sponge invocations in the same batch.
///
/// Internal bus names are heap-leaked at construction time. This is a one-shot
/// cost paid once per AIR instantiation (typically prover startup), not per
/// proof, so the leak is fine in production.
pub fn build_sponge_airs(bus_query: &'static str) -> SpongeAirs {
	let bus_init_in = leak_str(format!("{}-init-in", bus_query));
	let bus_init_out = leak_str(format!("{}-init-out", bus_query));
	let bus_int_out = leak_str(format!("{}-int-out", bus_query));
	let bus_term_out = leak_str(format!("{}-term-out", bus_query));
	SpongeAirs {
		shell: SpongeShellAir::new(bus_query, bus_init_in, bus_term_out),
		external_initial: ExternalRoundAir::new(
			ExternalRoundKind::Initial,
			bus_init_in,
			bus_init_out,
		),
		internal: InternalRoundAir::new(bus_init_out, bus_int_out),
		external_terminal: ExternalRoundAir::new(
			ExternalRoundKind::Terminal,
			bus_int_out,
			bus_term_out,
		),
	}
}

fn leak_str(s: String) -> &'static str {
	Box::leak(s.into_boxed_str())
}

/// Build the trace matrix for one [`SpongeShellAir`] invocation.
pub fn build_sponge_shell_trace(
	input: [Goldilocks; WIDTH],
) -> RowMajorMatrix<Goldilocks> {
	let output = poseidon2_sponge_8(input);
	let mut post_mds = input;
	mds_light_permutation_8(&mut post_mds);

	let mut values = alloc::vec::Vec::with_capacity(SPONGE_SHELL_NUM_COLS);
	values.extend_from_slice(&input);
	values.extend_from_slice(&post_mds);
	values.extend_from_slice(&output);
	RowMajorMatrix::new(values, SPONGE_SHELL_NUM_COLS)
}

#[cfg(test)]
mod tests;
