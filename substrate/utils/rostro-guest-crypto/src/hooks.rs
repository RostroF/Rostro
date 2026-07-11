// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! `RostroCurveHooks`: one type implementing BOTH
//! `ark_bls12_381_ext::CurveHooks` and
//! `ark_ed_on_bls12_381_bandersnatch_ext::CurveHooks`.
//!
//! On `target_env = "polkavm"` every hooked group operation marshals to the
//! RVM ecalli intrinsics (wire format: affine uncompressed points — 96B G1,
//! 192B G2, 64B TE, 65B SW, 576B Fq12; canonical 32B Fr scalars; raw LE u64
//! limbs for `mul_projective`). Inputs beyond the intrinsic operand caps are
//! chunked (MSM is additive, the Miller loop is multiplicative over pairs —
//! chunked results are bit-identical). Natively the hooks replicate the
//! ext-crate defaults via zero-cost transmutation into plain arkworks, so
//! hooked and plain constructions are byte-equal by construction — the
//! consensus gate for the ring-VRF curve switch.
//!
//! Failure policy: intrinsic failure (A0 = 0) is unreachable for inputs this
//! module produces (it pre-validates caps and serializes its own operands),
//! so it panics — in-guest a panic is a deterministic trap, exactly what
//! plain arkworks produces on the same malformed state. `mul_projective`
//! scalars wider than the intrinsic caps fall back to in-guest plain
//! arkworks, preserving plain-ark semantics (including ark's own panic on
//! 5+ limb G1 scalars) at interpreted speed for inputs that never occur in
//! practice.

#[cfg(target_env = "polkavm")]
use alloc::vec::Vec;
use ark_ec::pairing::Pairing;
use ark_ec::CurveConfig;
#[cfg(target_env = "polkavm")]
use ark_ec::{AffineRepr, CurveGroup};
#[cfg(target_env = "polkavm")]
use ark_ff::{One, Zero};
#[cfg(target_env = "polkavm")]
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// The hooks type. Uninhabited: it exists only as a type parameter.
pub enum RostroCurveHooks {}

/// BLS12-381 with every group operation routed through the facade.
pub type Bls12_381 = ark_bls12_381_ext::Bls12_381<RostroCurveHooks>;
pub type BlsG1Affine = ark_bls12_381_ext::G1Affine<RostroCurveHooks>;
pub type BlsG1Projective = ark_bls12_381_ext::G1Projective<RostroCurveHooks>;
pub type BlsG2Affine = ark_bls12_381_ext::G2Affine<RostroCurveHooks>;
pub type BlsG2Projective = ark_bls12_381_ext::G2Projective<RostroCurveHooks>;

/// Bandersnatch (ed-on-bls12-381) with hooked group operations.
pub type EdwardsAffine = ark_ed_on_bls12_381_bandersnatch_ext::EdwardsAffine<RostroCurveHooks>;
pub type EdwardsProjective =
	ark_ed_on_bls12_381_bandersnatch_ext::EdwardsProjective<RostroCurveHooks>;
pub type SWAffine = ark_ed_on_bls12_381_bandersnatch_ext::SWAffine<RostroCurveHooks>;
pub type SWProjective = ark_ed_on_bls12_381_bandersnatch_ext::SWProjective<RostroCurveHooks>;

/// Wire sizes of the intrinsic ABI (uncompressed affine; SW bandersnatch is
/// 65B because the 2-bit SW flags overflow the 255-bit field's spare bit).
#[cfg(target_env = "polkavm")]
mod wire {
	pub const G1: usize = 96;
	pub const G2: usize = 192;
	pub const TE: usize = 64;
	pub const SW: usize = 65;
	pub const FQ12: usize = 576;
}

/// Plain-arkworks delegation, replicating the ext-crate default hook bodies
/// (zero-cost transmutation into the upstream curve configs). Natively this
/// IS the backend; in-guest it serves only as the over-cap `mul_projective`
/// fallback.
#[allow(dead_code)]
mod plain {
	use super::*;
	use ark_bls12_381::{g1::Config as ArkG1Config, g2::Config as ArkG2Config, Config as ArkBlsConfig};
	use ark_ec::bls12::Bls12Config as ArkBls12ConfigTrait;
	use ark_ec::pairing::MillerLoopOutput;
	use ark_ec::short_weierstrass::{self as sw, SWCurveConfig};
	use ark_ec::twisted_edwards::{self as te, TECurveConfig};
	use ark_ed_on_bls12_381_bandersnatch::BandersnatchConfig as ArkBanderConfig;
	use ark_models_ext::transmute::{TransmuteInto, TransmuteRef};
	use ark_models_ext::VariableBaseMSM;

	pub fn multi_miller_loop(
		g1: impl Iterator<Item = <super::Bls12_381 as Pairing>::G1Prepared>,
		g2: impl Iterator<Item = <super::Bls12_381 as Pairing>::G2Prepared>,
	) -> <super::Bls12_381 as Pairing>::TargetField {
		let g1 = g1.map(|p| {
			let affine: &sw::Affine<ArkG1Config> = p.0.transmute_ref();
			*affine
		});
		let g2 = g2.map(|q| {
			let affine: &sw::Affine<ArkG2Config> = q.0.transmute_ref();
			*affine
		});
		<ArkBlsConfig as ArkBls12ConfigTrait>::multi_miller_loop(g1, g2).0
	}

	pub fn final_exponentiation(
		target: <super::Bls12_381 as Pairing>::TargetField,
	) -> <super::Bls12_381 as Pairing>::TargetField {
		<ArkBlsConfig as ArkBls12ConfigTrait>::final_exponentiation(MillerLoopOutput(target))
			.map(|po| po.0)
			.expect("final exponentiation: non-invertible element")
	}

	pub fn msm_g1(bases: &[BlsG1Affine], scalars: &[ark_bls12_381::Fr]) -> BlsG1Projective {
		let bases: &[sw::Affine<ArkG1Config>] = bases.transmute_ref();
		<sw::Projective<ArkG1Config> as VariableBaseMSM>::msm_unchecked(bases, scalars)
			.transmute_into()
	}

	pub fn msm_g2(bases: &[BlsG2Affine], scalars: &[ark_bls12_381::Fr]) -> BlsG2Projective {
		let bases: &[sw::Affine<ArkG2Config>] = bases.transmute_ref();
		<sw::Projective<ArkG2Config> as VariableBaseMSM>::msm_unchecked(bases, scalars)
			.transmute_into()
	}

	pub fn mul_projective_g1(base: &BlsG1Projective, scalar: &[u64]) -> BlsG1Projective {
		let base: &sw::Projective<ArkG1Config> = base.transmute_ref();
		<ArkG1Config as SWCurveConfig>::mul_projective(base, scalar).transmute_into()
	}

	pub fn mul_projective_g2(base: &BlsG2Projective, scalar: &[u64]) -> BlsG2Projective {
		let base: &sw::Projective<ArkG2Config> = base.transmute_ref();
		<ArkG2Config as SWCurveConfig>::mul_projective(base, scalar).transmute_into()
	}

	pub fn msm_te(
		bases: &[super::EdwardsAffine],
		scalars: &[ark_ed_on_bls12_381_bandersnatch::Fr],
	) -> super::EdwardsProjective {
		let bases: &[te::Affine<ArkBanderConfig>] = bases.transmute_ref();
		<te::Projective<ArkBanderConfig> as VariableBaseMSM>::msm_unchecked(bases, scalars)
			.transmute_into()
	}

	pub fn mul_projective_te(
		base: &super::EdwardsProjective,
		scalar: &[u64],
	) -> super::EdwardsProjective {
		let base: &te::Projective<ArkBanderConfig> = base.transmute_ref();
		<ArkBanderConfig as TECurveConfig>::mul_projective(base, scalar).transmute_into()
	}

	pub fn msm_sw(
		bases: &[super::SWAffine],
		scalars: &[ark_ed_on_bls12_381_bandersnatch::Fr],
	) -> super::SWProjective {
		let bases: &[sw::Affine<ArkBanderConfig>] = bases.transmute_ref();
		<sw::Projective<ArkBanderConfig> as VariableBaseMSM>::msm_unchecked(bases, scalars)
			.transmute_into()
	}

	pub fn mul_projective_sw(base: &super::SWProjective, scalar: &[u64]) -> super::SWProjective {
		let base: &sw::Projective<ArkBanderConfig> = base.transmute_ref();
		<ArkBanderConfig as SWCurveConfig>::mul_projective(base, scalar).transmute_into()
	}
}

/// Guest MSM marshalling: serialize a chunk of (points, scalars), one ecalli
/// per chunk, sum the partial results (MSM is additive over input chunks).
/// Length mismatch mirrors `msm_unchecked`'s zip semantics: excess of either
/// slice is ignored.
#[cfg(target_env = "polkavm")]
macro_rules! guest_msm {
	($ecalli:path, $bases:expr, $scalars:expr, $pt_len:expr, $affine:ty, $proj:ty) => {{
		let n = core::cmp::min($bases.len(), $scalars.len());
		let mut acc = <$proj>::zero();
		let mut pbuf: Vec<u8> = Vec::new();
		let mut sbuf: Vec<u8> = Vec::new();
		let mut start = 0usize;
		while start < n {
			let end = core::cmp::min(start + crate::MAX_BLS_MSM, n);
			pbuf.clear();
			sbuf.clear();
			for p in &$bases[start..end] {
				p.serialize_uncompressed(&mut pbuf).expect("serialize into Vec cannot fail");
			}
			for s in &$scalars[start..end] {
				s.serialize_uncompressed(&mut sbuf).expect("serialize into Vec cannot fail");
			}
			let mut out = [0u8; $pt_len];
			let ok = unsafe {
				$ecalli(
					pbuf.as_ptr() as u32,
					sbuf.as_ptr() as u32,
					(end - start) as u32,
					out.as_mut_ptr() as u32,
				)
			};
			if ok != 1 {
				panic!("rostro-guest-crypto: MSM intrinsic failed");
			}
			let part = <$affine>::deserialize_uncompressed_unchecked(&out[..])
				.expect("intrinsic output is canonical");
			acc += part.into_group();
			start = end;
		}
		acc
	}};
}

/// Guest `mul_projective` marshalling. Scalars wider than the intrinsic's
/// limb cap (or empty) take the plain in-guest path, preserving plain-ark
/// semantics exactly.
#[cfg(target_env = "polkavm")]
macro_rules! guest_mul_projective {
	($ecalli:path, $base:expr, $scalar:expr, $pt_len:expr, $affine:ty, $limb_cap:expr, $plain:expr) => {{
		if $scalar.is_empty() || $scalar.len() > $limb_cap {
			$plain
		} else {
			let affine = $base.into_affine();
			let mut bbuf = [0u8; $pt_len];
			affine.serialize_uncompressed(&mut bbuf[..]).expect("fixed-size buffer");
			let mut lbuf: Vec<u8> = Vec::with_capacity($scalar.len() * 8);
			for limb in $scalar {
				lbuf.extend_from_slice(&limb.to_le_bytes());
			}
			let mut out = [0u8; $pt_len];
			let ok = unsafe {
				$ecalli(
					bbuf.as_ptr() as u32,
					lbuf.as_ptr() as u32,
					$scalar.len() as u32,
					out.as_mut_ptr() as u32,
				)
			};
			if ok != 1 {
				panic!("rostro-guest-crypto: mul_projective intrinsic failed");
			}
			<$affine>::deserialize_uncompressed_unchecked(&out[..])
				.expect("intrinsic output is canonical")
				.into_group()
		}
	}};
}

impl ark_bls12_381_ext::CurveHooks for RostroCurveHooks {
	fn multi_miller_loop(
		g1: impl Iterator<Item = <ark_bls12_381_ext::Bls12_381<Self> as Pairing>::G1Prepared>,
		g2: impl Iterator<Item = <ark_bls12_381_ext::Bls12_381<Self> as Pairing>::G2Prepared>,
	) -> <ark_bls12_381_ext::Bls12_381<Self> as Pairing>::TargetField {
		#[cfg(target_env = "polkavm")]
		{
			// The Miller loop is multiplicative over pairs: chunk at the
			// intrinsic cap and multiply the partial Fq12 outputs.
			let pairs: Vec<_> = g1.zip(g2).collect();
			let mut acc: ark_bls12_381::Fq12 = One::one();
			for chunk in pairs.chunks(crate::MAX_BLS_PAIRS) {
				let mut buf: Vec<u8> = Vec::with_capacity(chunk.len() * (wire::G1 + wire::G2));
				for (p, q) in chunk {
					p.0.serialize_uncompressed(&mut buf).expect("serialize into Vec cannot fail");
					q.0.serialize_uncompressed(&mut buf).expect("serialize into Vec cannot fail");
				}
				let mut out = [0u8; wire::FQ12];
				let ok = unsafe {
					crate::ecalli::rostro_bls381_multi_miller_loop(
						buf.as_ptr() as u32,
						chunk.len() as u32,
						out.as_mut_ptr() as u32,
					)
				};
				if ok != 1 {
					panic!("rostro-guest-crypto: multi_miller_loop intrinsic failed");
				}
				let f = ark_bls12_381::Fq12::deserialize_uncompressed_unchecked(&out[..])
					.expect("intrinsic output is canonical");
				acc *= f;
			}
			acc
		}
		#[cfg(not(target_env = "polkavm"))]
		{
			plain::multi_miller_loop(g1, g2)
		}
	}

	fn final_exponentiation(
		target: <ark_bls12_381_ext::Bls12_381<Self> as Pairing>::TargetField,
	) -> <ark_bls12_381_ext::Bls12_381<Self> as Pairing>::TargetField {
		#[cfg(target_env = "polkavm")]
		{
			let mut in_buf = [0u8; wire::FQ12];
			target.serialize_uncompressed(&mut in_buf[..]).expect("fixed-size buffer");
			let mut out = [0u8; wire::FQ12];
			let ok = unsafe {
				crate::ecalli::rostro_bls381_final_exp(
					in_buf.as_ptr() as u32,
					out.as_mut_ptr() as u32,
				)
			};
			if ok != 1 {
				// The one legitimate failure is the non-invertible zero
				// input; the ext default panics there too.
				panic!("final exponentiation: non-invertible element");
			}
			ark_bls12_381::Fq12::deserialize_uncompressed_unchecked(&out[..])
				.expect("intrinsic output is canonical")
		}
		#[cfg(not(target_env = "polkavm"))]
		{
			plain::final_exponentiation(target)
		}
	}

	fn msm_g1(
		bases: &[ark_bls12_381_ext::g1::G1Affine<Self>],
		scalars: &[<ark_bls12_381_ext::g1::Config<Self> as CurveConfig>::ScalarField],
	) -> ark_bls12_381_ext::G1Projective<Self> {
		#[cfg(target_env = "polkavm")]
		{
			guest_msm!(
				crate::ecalli::rostro_bls381_g1_msm,
				bases,
				scalars,
				wire::G1,
				BlsG1Affine,
				BlsG1Projective
			)
		}
		#[cfg(not(target_env = "polkavm"))]
		{
			plain::msm_g1(bases, scalars)
		}
	}

	fn msm_g2(
		bases: &[ark_bls12_381_ext::g2::G2Affine<Self>],
		scalars: &[<ark_bls12_381_ext::g2::Config<Self> as CurveConfig>::ScalarField],
	) -> ark_bls12_381_ext::G2Projective<Self> {
		#[cfg(target_env = "polkavm")]
		{
			guest_msm!(
				crate::ecalli::rostro_bls381_g2_msm,
				bases,
				scalars,
				wire::G2,
				BlsG2Affine,
				BlsG2Projective
			)
		}
		#[cfg(not(target_env = "polkavm"))]
		{
			plain::msm_g2(bases, scalars)
		}
	}

	fn mul_projective_g1(
		base: &ark_bls12_381_ext::G1Projective<Self>,
		scalar: &[u64],
	) -> ark_bls12_381_ext::G1Projective<Self> {
		#[cfg(target_env = "polkavm")]
		{
			guest_mul_projective!(
				crate::ecalli::rostro_bls381_g1_mul_projective,
				base,
				scalar,
				wire::G1,
				BlsG1Affine,
				crate::MAX_G1_MUL_PROJECTIVE_LIMBS,
				plain::mul_projective_g1(base, scalar)
			)
		}
		#[cfg(not(target_env = "polkavm"))]
		{
			plain::mul_projective_g1(base, scalar)
		}
	}

	fn mul_projective_g2(
		base: &ark_bls12_381_ext::G2Projective<Self>,
		scalar: &[u64],
	) -> ark_bls12_381_ext::G2Projective<Self> {
		#[cfg(target_env = "polkavm")]
		{
			guest_mul_projective!(
				crate::ecalli::rostro_bls381_g2_mul_projective,
				base,
				scalar,
				wire::G2,
				BlsG2Affine,
				crate::MAX_MUL_PROJECTIVE_LIMBS,
				plain::mul_projective_g2(base, scalar)
			)
		}
		#[cfg(not(target_env = "polkavm"))]
		{
			plain::mul_projective_g2(base, scalar)
		}
	}
}

impl ark_ed_on_bls12_381_bandersnatch_ext::CurveHooks for RostroCurveHooks {
	fn msm_te(
		bases: &[ark_ed_on_bls12_381_bandersnatch_ext::EdwardsAffine<Self>],
		scalars: &[<ark_ed_on_bls12_381_bandersnatch_ext::EdwardsConfig<Self> as CurveConfig>::ScalarField],
	) -> ark_ed_on_bls12_381_bandersnatch_ext::EdwardsProjective<Self> {
		#[cfg(target_env = "polkavm")]
		{
			guest_msm!(
				crate::ecalli::rostro_bandersnatch_te_msm,
				bases,
				scalars,
				wire::TE,
				EdwardsAffine,
				EdwardsProjective
			)
		}
		#[cfg(not(target_env = "polkavm"))]
		{
			plain::msm_te(bases, scalars)
		}
	}

	fn mul_projective_te(
		base: &ark_ed_on_bls12_381_bandersnatch_ext::EdwardsProjective<Self>,
		scalar: &[u64],
	) -> ark_ed_on_bls12_381_bandersnatch_ext::EdwardsProjective<Self> {
		#[cfg(target_env = "polkavm")]
		{
			guest_mul_projective!(
				crate::ecalli::rostro_bandersnatch_te_mul_projective,
				base,
				scalar,
				wire::TE,
				EdwardsAffine,
				crate::MAX_MUL_PROJECTIVE_LIMBS,
				plain::mul_projective_te(base, scalar)
			)
		}
		#[cfg(not(target_env = "polkavm"))]
		{
			plain::mul_projective_te(base, scalar)
		}
	}

	fn msm_sw(
		bases: &[ark_ed_on_bls12_381_bandersnatch_ext::SWAffine<Self>],
		scalars: &[<ark_ed_on_bls12_381_bandersnatch_ext::SWConfig<Self> as CurveConfig>::ScalarField],
	) -> ark_ed_on_bls12_381_bandersnatch_ext::SWProjective<Self> {
		#[cfg(target_env = "polkavm")]
		{
			guest_msm!(
				crate::ecalli::rostro_bandersnatch_sw_msm,
				bases,
				scalars,
				wire::SW,
				SWAffine,
				SWProjective
			)
		}
		#[cfg(not(target_env = "polkavm"))]
		{
			plain::msm_sw(bases, scalars)
		}
	}

	fn mul_projective_sw(
		base: &ark_ed_on_bls12_381_bandersnatch_ext::SWProjective<Self>,
		scalar: &[u64],
	) -> ark_ed_on_bls12_381_bandersnatch_ext::SWProjective<Self> {
		#[cfg(target_env = "polkavm")]
		{
			guest_mul_projective!(
				crate::ecalli::rostro_bandersnatch_sw_mul_projective,
				base,
				scalar,
				wire::SW,
				SWAffine,
				crate::MAX_MUL_PROJECTIVE_LIMBS,
				plain::mul_projective_sw(base, scalar)
			)
		}
		#[cfg(not(target_env = "polkavm"))]
		{
			plain::mul_projective_sw(base, scalar)
		}
	}
}
