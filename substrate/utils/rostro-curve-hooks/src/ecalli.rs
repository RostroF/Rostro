// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! Pinned-index imports of the RVM curve-operation intrinsics
//! (`ROSTRO_INTRINSIC_*` in the vendored interpreter). These symbol names
//! are canonical: the executor registers stub host functions under exactly
//! these names to satisfy instantiation-time import resolution — the
//! interpreter intercepts the ecalli inline, so the stubs never execute.
//! A blob importing these does NOT instantiate on a node without the
//! intrinsics and stubs: a hard, loud cutover, never a silent slow path.
//! The verify-class imports (110-114, 123) live in rostro-guest-crypto's
//! own ecalli module; each symbol is declared in exactly one crate so a
//! linked blob never carries duplicate pinned imports.

// polkavm-derive rejects doc comments on extern import blocks — keep
// comments as `//` lines.
#[polkavm_derive::polkavm_import]
extern "C" {
	// ROSTRO_INTRINSIC_BLS381_G1_MSM (unchecked deserialization)
	#[polkavm_import(index = 115)]
	pub fn rostro_bls381_g1_msm(points_ptr: u32, scalars_ptr: u32, n: u32, out_ptr: u32) -> u32;
	// ROSTRO_INTRINSIC_BLS381_G2_MSM
	#[polkavm_import(index = 116)]
	pub fn rostro_bls381_g2_msm(points_ptr: u32, scalars_ptr: u32, n: u32, out_ptr: u32) -> u32;
	// ROSTRO_INTRINSIC_BLS381_MULTI_MILLER_LOOP
	#[polkavm_import(index = 117)]
	pub fn rostro_bls381_multi_miller_loop(pairs_ptr: u32, n_pairs: u32, out_ptr: u32) -> u32;
	// ROSTRO_INTRINSIC_BLS381_FINAL_EXP
	#[polkavm_import(index = 118)]
	pub fn rostro_bls381_final_exp(in_ptr: u32, out_ptr: u32) -> u32;
	// ROSTRO_INTRINSIC_BANDERSNATCH_TE_MSM
	#[polkavm_import(index = 119)]
	pub fn rostro_bandersnatch_te_msm(
		points_ptr: u32,
		scalars_ptr: u32,
		n: u32,
		out_ptr: u32,
	) -> u32;
	// ROSTRO_INTRINSIC_BANDERSNATCH_TE_MUL_PROJECTIVE
	#[polkavm_import(index = 124)]
	pub fn rostro_bandersnatch_te_mul_projective(
		base_ptr: u32,
		limbs_ptr: u32,
		n_limbs: u32,
		out_ptr: u32,
	) -> u32;
	// ROSTRO_INTRINSIC_BANDERSNATCH_SW_MSM (65-byte SW points)
	#[polkavm_import(index = 125)]
	pub fn rostro_bandersnatch_sw_msm(
		points_ptr: u32,
		scalars_ptr: u32,
		n: u32,
		out_ptr: u32,
	) -> u32;
	// ROSTRO_INTRINSIC_BANDERSNATCH_SW_MUL_PROJECTIVE
	#[polkavm_import(index = 126)]
	pub fn rostro_bandersnatch_sw_mul_projective(
		base_ptr: u32,
		limbs_ptr: u32,
		n_limbs: u32,
		out_ptr: u32,
	) -> u32;
	// ROSTRO_INTRINSIC_BLS381_G1_MUL_PROJECTIVE (n_limbs ≤ 4: GLV guard)
	#[polkavm_import(index = 127)]
	pub fn rostro_bls381_g1_mul_projective(
		base_ptr: u32,
		limbs_ptr: u32,
		n_limbs: u32,
		out_ptr: u32,
	) -> u32;
	// ROSTRO_INTRINSIC_BLS381_G2_MUL_PROJECTIVE
	#[polkavm_import(index = 128)]
	pub fn rostro_bls381_g2_mul_projective(
		base_ptr: u32,
		limbs_ptr: u32,
		n_limbs: u32,
		out_ptr: u32,
	) -> u32;
	// Montgomery-limb MSM variants: points/scalars travel as raw LE
	// Montgomery limbs (zero conversion multiplications on either side).
	// These are the hooks' MSM path; the byte-canonical MSMs above remain
	// the wire-facing variants.
	// ROSTRO_INTRINSIC_BLS381_G1_MSM_MONT
	#[polkavm_import(index = 131)]
	pub fn rostro_bls381_g1_msm_mont(
		points_ptr: u32,
		scalars_ptr: u32,
		n: u32,
		out_ptr: u32,
	) -> u32;
	// ROSTRO_INTRINSIC_BLS381_G2_MSM_MONT
	#[polkavm_import(index = 132)]
	pub fn rostro_bls381_g2_msm_mont(
		points_ptr: u32,
		scalars_ptr: u32,
		n: u32,
		out_ptr: u32,
	) -> u32;
	// ROSTRO_INTRINSIC_BANDERSNATCH_TE_MSM_MONT
	#[polkavm_import(index = 133)]
	pub fn rostro_bandersnatch_te_msm_mont(
		points_ptr: u32,
		scalars_ptr: u32,
		n: u32,
		out_ptr: u32,
	) -> u32;
	// ROSTRO_INTRINSIC_BANDERSNATCH_SW_MSM_MONT
	#[polkavm_import(index = 134)]
	pub fn rostro_bandersnatch_sw_msm_mont(
		points_ptr: u32,
		scalars_ptr: u32,
		n: u32,
		out_ptr: u32,
	) -> u32;
}
