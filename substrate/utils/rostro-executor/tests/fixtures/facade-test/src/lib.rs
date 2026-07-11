// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! # rostro-guest-crypto correctness fixture (RVM interpreter)
//!
//! Guest side of the facade differential battery's third leg:
//! facade-native == raw-crate is pinned in the facade's own `tests/`;
//! THIS fixture proves facade-guest == facade-native with the guest half
//! really marshalling to the RVM ecalli intrinsics.
//!
//! Every export takes `(input_ptr, input_len)` (input at `heap_base`) and
//! returns a status in `A0`: 0 ok, 1 framing error, 2 parse error,
//! 4 result mismatch / verify failure. The harness computes each expected
//! value through the facade's NATIVE backend and appends it to the input;
//! the guest recomputes through the ecalli backend and byte-compares.
//!
//! Framing (all integers LE):
//! - `ft_pairing`:       g1(96) ‖ g2(192) ‖ expected_gt(576)
//! - `ft_msm_*`:         n(u32) ‖ points(n × PT) ‖ scalars(n × 32) ‖ expected(PT)
//! - `ft_mul_*`:         n_limbs(u32) ‖ limbs(n × 8) ‖ base(PT) ‖ expected(PT)
//! - `ft_p256`:          vk(33) ‖ sig(64) ‖ prehash(32)
//! - `ft_p521`:          vk(133) ‖ sig(132) ‖ prehash(64)
//! - `ft_mldsa`:         pk(1952) ‖ sig(3309) ‖ msg(..)
//! - `ft_slhdsa`:        pk(32) ‖ sig(7856) ‖ msg(..)
//! - `ft_recover`:       hash(32) ‖ sig(65) ‖ expected_pk(64)
//! - `ft_pairing_check`: pairs(n × 288)
//! - `ft_ed25519`:       pk(32) ‖ sig(64) ‖ msg(..)
//! - `ft_sr25519`:       pk(32) ‖ sig(64) ‖ msg(..)
//! - `ft_ecdsa`:         pk(33) ‖ sig(65) ‖ hash(32)
//!
//! where PT ∈ {96 (BLS G1), 192 (BLS G2), 64 (bandersnatch TE),
//! 65 (bandersnatch SW — the 2-bit SW flags overflow the 255-bit field's
//! spare bit)}.

#![cfg_attr(not(feature = "std"), no_std)]

// Re-export the PVM blob produced by build.rs for the host-side harness.
#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

/// Returns the PVM blob bytes. Panics if `SKIP_WASM_BUILD` was set.
#[cfg(feature = "std")]
pub fn binary_unwrap() -> &'static [u8] {
	WASM_BINARY.expect(
		"rostro-executor-fixture-facade-test binary missing — build was \
		 skipped via SKIP_WASM_BUILD or substrate-wasm-builder reported failure",
	)
}

// ─── Runtime side (no_std) ─────────────────────────────────────────────────

// Deliberately NO `min_stack_size!`: the facade's guest paths must fit the
// linker's 1 MiB Rostro default, since real runtime blobs will rely on it.
#[cfg(not(feature = "std"))]
mod guest {
	extern crate alloc;
	use alloc::vec::Vec;
	use ark_ec::pairing::Pairing;
	use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
	use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
	use rostro_guest_crypto::{hooks, verify};

	fn input<'a>(ptr: u32, len: u32) -> &'a [u8] {
		unsafe { core::slice::from_raw_parts(ptr as *const u8, len as usize) }
	}

	fn read_u32(data: &[u8]) -> Option<(u32, &[u8])> {
		if data.len() < 4 {
			return None;
		}
		let n = u32::from_le_bytes(data[..4].try_into().ok()?);
		Some((n, &data[4..]))
	}

	// ── hooked-curve exports ────────────────────────────────────────────

	#[polkavm_derive::polkavm_export]
	#[no_mangle]
	pub extern "C" fn ft_pairing(ptr: u32, len: u32) -> u64 {
		let data = input(ptr, len);
		if data.len() != 96 + 192 + 576 {
			return 1;
		}
		let Ok(g1) = hooks::BlsG1Affine::deserialize_uncompressed_unchecked(&data[..96]) else {
			return 2;
		};
		let Ok(g2) =
			hooks::BlsG2Affine::deserialize_uncompressed_unchecked(&data[96..288])
		else {
			return 2;
		};
		// Full ext plumbing: Pairing::pairing → Config::multi_miller_loop →
		// hook (ecalli 117) → Config::final_exponentiation → hook (118).
		let gt = hooks::Bls12_381::pairing(g1, g2);
		let mut out = [0u8; 576];
		if gt.0.serialize_uncompressed(&mut out[..]).is_err() {
			return 2;
		}
		if out[..] == data[288..] {
			0
		} else {
			4
		}
	}

	#[polkavm_derive::polkavm_export]
	#[no_mangle]
	pub extern "C" fn ft_multi_pairing(ptr: u32, len: u32) -> u64 {
		// n(u32) ‖ n × (g1(96) ‖ g2(192)) ‖ expected_gt(576). Driven with
		// n > MAX_BLS_PAIRS by the harness to exercise the Miller-loop
		// chunking path (partial Fq12 products multiplied in-guest).
		let data = input(ptr, len);
		let Some((n, rest)) = read_u32(data) else { return 1 };
		let n = n as usize;
		if rest.len() != n * 288 + 576 {
			return 1;
		}
		let (pairs, expected) = rest.split_at(n * 288);
		let mut g1s: Vec<hooks::BlsG1Affine> = Vec::with_capacity(n);
		let mut g2s: Vec<hooks::BlsG2Affine> = Vec::with_capacity(n);
		for i in 0..n {
			let off = i * 288;
			let Ok(g1) =
				hooks::BlsG1Affine::deserialize_uncompressed_unchecked(&pairs[off..off + 96])
			else {
				return 2;
			};
			let Ok(g2) = hooks::BlsG2Affine::deserialize_uncompressed_unchecked(
				&pairs[off + 96..off + 288],
			) else {
				return 2;
			};
			g1s.push(g1);
			g2s.push(g2);
		}
		let gt = hooks::Bls12_381::multi_pairing(g1s, g2s);
		let mut out = [0u8; 576];
		if gt.0.serialize_uncompressed(&mut out[..]).is_err() {
			return 2;
		}
		if out[..] == expected[..] {
			0
		} else {
			4
		}
	}

	macro_rules! ft_msm {
		($name:ident, $pt_len:expr, $affine:ty, $proj:ty, $fr:ty) => {
			#[polkavm_derive::polkavm_export]
			#[no_mangle]
			pub extern "C" fn $name(ptr: u32, len: u32) -> u64 {
				let data = input(ptr, len);
				let Some((n, rest)) = read_u32(data) else { return 1 };
				let n = n as usize;
				if rest.len() != n * $pt_len + n * 32 + $pt_len {
					return 1;
				}
				let (pts, rest) = rest.split_at(n * $pt_len);
				let (scalars, expected) = rest.split_at(n * 32);
				let mut bases: Vec<$affine> = Vec::with_capacity(n);
				let mut ss: Vec<$fr> = Vec::with_capacity(n);
				for i in 0..n {
					let Ok(p) = <$affine>::deserialize_uncompressed_unchecked(
						&pts[i * $pt_len..(i + 1) * $pt_len],
					) else {
						return 2;
					};
					let Ok(s) = <$fr>::deserialize_uncompressed_unchecked(
						&scalars[i * 32..(i + 1) * 32],
					) else {
						return 2;
					};
					bases.push(p);
					ss.push(s);
				}
				// VariableBaseMSM::msm routes through the ext config's msm
				// override → hook (ecalli). msm_unchecked/msm_bigint would
				// NOT: ark-ec's defaults go straight to the generic
				// interpreted Pippenger, bypassing the Config seam — the
				// bench harness exists to catch exactly that.
				let Ok(acc) = <$proj>::msm(&bases, &ss) else { return 2 };
				let acc = acc.into_affine();
				let mut out = [0u8; $pt_len];
				if acc.serialize_uncompressed(&mut out[..]).is_err() {
					return 2;
				}
				if out[..] == expected[..] {
					0
				} else {
					4
				}
			}
		};
	}

	ft_msm!(ft_msm_g1, 96, hooks::BlsG1Affine, hooks::BlsG1Projective, ark_bls12_381::Fr);
	ft_msm!(ft_msm_g2, 192, hooks::BlsG2Affine, hooks::BlsG2Projective, ark_bls12_381::Fr);
	ft_msm!(
		ft_te_msm,
		64,
		hooks::EdwardsAffine,
		hooks::EdwardsProjective,
		ark_ed_on_bls12_381_bandersnatch::Fr
	);
	ft_msm!(
		ft_sw_msm,
		65,
		hooks::SWAffine,
		hooks::SWProjective,
		ark_ed_on_bls12_381_bandersnatch::Fr
	);

	macro_rules! ft_mul {
		($name:ident, $pt_len:expr, $affine:ty) => {
			#[polkavm_derive::polkavm_export]
			#[no_mangle]
			pub extern "C" fn $name(ptr: u32, len: u32) -> u64 {
				let data = input(ptr, len);
				let Some((n_limbs, rest)) = read_u32(data) else { return 1 };
				let n_limbs = n_limbs as usize;
				if rest.len() != n_limbs * 8 + 2 * $pt_len {
					return 1;
				}
				let (limb_bytes, rest) = rest.split_at(n_limbs * 8);
				let (base_bytes, expected) = rest.split_at($pt_len);
				let mut limbs: Vec<u64> = Vec::with_capacity(n_limbs);
				for chunk in limb_bytes.chunks_exact(8) {
					limbs.push(u64::from_le_bytes(chunk.try_into().expect("chunks_exact")));
				}
				let Ok(base) = <$affine>::deserialize_uncompressed_unchecked(base_bytes) else {
					return 2;
				};
				// AffineRepr::mul_bigint → Config::mul_projective → hook.
				let res = base.mul_bigint(&limbs[..]).into_affine();
				let mut out = [0u8; $pt_len];
				if res.serialize_uncompressed(&mut out[..]).is_err() {
					return 2;
				}
				if out[..] == expected[..] {
					0
				} else {
					4
				}
			}
		};
	}

	ft_mul!(ft_mul_g1, 96, hooks::BlsG1Affine);
	ft_mul!(ft_mul_g2, 192, hooks::BlsG2Affine);
	ft_mul!(ft_mul_te, 64, hooks::EdwardsAffine);
	ft_mul!(ft_mul_sw, 65, hooks::SWAffine);

	// ── verify-facade exports ───────────────────────────────────────────

	#[polkavm_derive::polkavm_export]
	#[no_mangle]
	pub extern "C" fn ft_p256(ptr: u32, len: u32) -> u64 {
		let data = input(ptr, len);
		if data.len() != 33 + 64 + 32 {
			return 1;
		}
		let vk: &[u8; 33] = data[..33].try_into().expect("split");
		let sig: &[u8; 64] = data[33..97].try_into().expect("split");
		if verify::p256_verify_prehash(vk, sig, &data[97..]) {
			0
		} else {
			4
		}
	}

	#[polkavm_derive::polkavm_export]
	#[no_mangle]
	pub extern "C" fn ft_p521(ptr: u32, len: u32) -> u64 {
		let data = input(ptr, len);
		if data.len() != 133 + 132 + 64 {
			return 1;
		}
		let vk: &[u8; 133] = data[..133].try_into().expect("split");
		let sig: &[u8; 132] = data[133..265].try_into().expect("split");
		if verify::p521_verify_prehash(vk, sig, &data[265..]) {
			0
		} else {
			4
		}
	}

	#[polkavm_derive::polkavm_export]
	#[no_mangle]
	pub extern "C" fn ft_mldsa(ptr: u32, len: u32) -> u64 {
		let data = input(ptr, len);
		if data.len() < 1952 + 3309 {
			return 1;
		}
		let pk: &[u8; 1952] = data[..1952].try_into().expect("split");
		let sig: &[u8; 3309] = data[1952..5261].try_into().expect("split");
		if verify::mldsa65_verify(pk, &data[5261..], sig, &[]) {
			0
		} else {
			4
		}
	}

	#[polkavm_derive::polkavm_export]
	#[no_mangle]
	pub extern "C" fn ft_slhdsa(ptr: u32, len: u32) -> u64 {
		let data = input(ptr, len);
		if data.len() < 32 + 7856 {
			return 1;
		}
		let pk: &[u8; 32] = data[..32].try_into().expect("split");
		let sig: &[u8; 7856] = data[32..7888].try_into().expect("split");
		if verify::slhdsa128s_verify(pk, &data[7888..], sig, &[]) {
			0
		} else {
			4
		}
	}

	#[polkavm_derive::polkavm_export]
	#[no_mangle]
	pub extern "C" fn ft_recover(ptr: u32, len: u32) -> u64 {
		let data = input(ptr, len);
		if data.len() != 32 + 65 + 64 {
			return 1;
		}
		let hash: &[u8; 32] = data[..32].try_into().expect("split");
		let sig: &[u8; 65] = data[32..97].try_into().expect("split");
		let Some(pk) = verify::secp256k1_recover(hash, sig) else { return 4 };
		if pk[..] == data[97..] {
			0
		} else {
			4
		}
	}

	#[polkavm_derive::polkavm_export]
	#[no_mangle]
	pub extern "C" fn ft_pairing_check(ptr: u32, len: u32) -> u64 {
		let data = input(ptr, len);
		if verify::bls381_pairing_check(data) {
			0
		} else {
			4
		}
	}

	#[polkavm_derive::polkavm_export]
	#[no_mangle]
	pub extern "C" fn ft_ed25519(ptr: u32, len: u32) -> u64 {
		let data = input(ptr, len);
		if data.len() < 32 + 64 {
			return 1;
		}
		let pk: &[u8; 32] = data[..32].try_into().expect("split");
		let sig: &[u8; 64] = data[32..96].try_into().expect("split");
		if verify::ed25519_verify(sig, &data[96..], pk) {
			0
		} else {
			4
		}
	}

	#[polkavm_derive::polkavm_export]
	#[no_mangle]
	pub extern "C" fn ft_sr25519(ptr: u32, len: u32) -> u64 {
		let data = input(ptr, len);
		if data.len() < 32 + 64 {
			return 1;
		}
		let pk: &[u8; 32] = data[..32].try_into().expect("split");
		let sig: &[u8; 64] = data[32..96].try_into().expect("split");
		if verify::sr25519_verify(sig, &data[96..], pk) {
			0
		} else {
			4
		}
	}

	#[polkavm_derive::polkavm_export]
	#[no_mangle]
	pub extern "C" fn ft_ecdsa(ptr: u32, len: u32) -> u64 {
		let data = input(ptr, len);
		if data.len() != 33 + 65 + 32 {
			return 1;
		}
		let pk: &[u8; 33] = data[..33].try_into().expect("split");
		let sig: &[u8; 65] = data[33..98].try_into().expect("split");
		let hash: &[u8; 32] = data[98..].try_into().expect("split");
		if verify::ecdsa_verify_prehashed(sig, hash, pk) {
			0
		} else {
			4
		}
	}
}
