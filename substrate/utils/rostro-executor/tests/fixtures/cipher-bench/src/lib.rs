// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! # Multi-cipher verify bench fixture (RVM interpreter)
//!
//! Guest side of the cipher matrix benchmark: for every verify-class
//! primitive on hand in this tree, measure what verification costs when
//! it runs interpreted inside RostroVM ("soft"), and — where a Tier-2
//! ecalli intrinsic exists — through the intrinsic. The companion
//! harness supplies native baselines. Decision input for which ciphers
//! earn an intrinsic next.
//!
//! Exports (substrate PVM call ABI `(input_ptr, input_len)`, input at
//! `heap_base`, status in `A0`; 0 = ok unless noted):
//!
//! - `bench_noop` — call-overhead calibration.
//! - `bench_ed25519_soft` / `bench_ed25519_intrinsic` (ID 122) —
//!   input `pk(32) ‖ sig(64) ‖ msg(..)`. ed25519-zebra ZIP-215 both ways.
//! - `bench_sr25519_soft` — input `pk(32) ‖ sig(64) ‖ msg(..)`;
//!   schnorrkel `verify_simple` under context `b"substrate"`. No
//!   intrinsic exists — this is the CURRENT default account scheme's
//!   interpreted cost.
//! - `bench_ecrecover_soft` / `bench_ecrecover_intrinsic` (ID 123) —
//!   input `hash(32) ‖ sig_rs(64) ‖ v(1) ‖ expected_pk(64)`; recover and
//!   compare.
//! - `bench_p521_soft` / `bench_p521_intrinsic` (ID 111) — input
//!   `vk(133 uncompressed) ‖ sig(132) ‖ digest(64)`.
//! - `bench_mldsa_soft` / `bench_mldsa_intrinsic` (ID 110) — input
//!   `pk(1952) ‖ sig(3309) ‖ msg(..)`; ML-DSA-65, empty context.
//! - `bench_slhdsa_soft` / `bench_slhdsa_intrinsic` (ID 113) — input
//!   `pk(32) ‖ sig(7856) ‖ msg(..)`; SLH-DSA-SHA2-128s (the PQ finality
//!   vote scheme), empty context.
//! - `bench_bls_pairing_check_soft` / `bench_bls_pairing_check_intrinsic`
//!   (ID 114) — input `2 × (g1(96) ‖ g2(192))`; multi-pairing product ==
//!   identity with CHECKED deserialization (mirrors the intrinsic ABI).
//! - `bench_bls_pairing_soft` — input `g1(96 uncompressed) ‖ g2(192
//!   uncompressed)`; one BLS12-381 pairing (unchecked deserialize, so
//!   the number isolates the pairing itself). Returns the first 8 bytes
//!   (LE) of the serialized target-field element so the work can't be
//!   optimized away; the harness compares against the native value.
//!   This is the cost preview for ring-VRF / Groth16 verification.
//!
//! Return codes: 0 ok, 1 framing, 2 key parse, 3 sig parse, 4 verify
//! failed (pairing export returns the digest u64 instead).

#![cfg_attr(not(feature = "std"), no_std)]

// Re-export the PVM blob produced by build.rs for the host-side harness.
#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

/// Returns the PVM blob bytes. Panics if `SKIP_WASM_BUILD` was set.
#[cfg(feature = "std")]
pub fn binary_unwrap() -> &'static [u8] {
	WASM_BINARY.expect(
		"rostro-executor-fixture-cipher-bench binary missing — build was \
		 skipped via SKIP_WASM_BUILD or substrate-wasm-builder reported failure",
	)
}

// ─── Runtime side (no_std) ─────────────────────────────────────────────────

// Link sp-io for its `#[panic_handler]` and `#[global_allocator]`: no guest
// export here calls sp_io directly (unlike the p256 fixture's hostsha
// variant), and an unused dependency does not get linked, so the handler
// and allocator would otherwise be missing from the blob.
#[cfg(not(feature = "std"))]
extern crate sp_io;

#[cfg(not(feature = "std"))]
mod guest {
	// NOTE: no `min_stack_size!` here on purpose — the vendored linker's
	// Rostro default is now 1 MiB, and this fixture running its deep
	// verifiers (k256 recovery, ML-DSA-65) without an explicit override is
	// the end-to-end proof of that default.

	/// Read the input payload the executor wrote at `heap_base`.
	fn input<'a>(ptr: u32, len: u32) -> &'a [u8] {
		unsafe { core::slice::from_raw_parts(ptr as *const u8, len as usize) }
	}

	// RVM Tier-2 intrinsic imports (dispatched inline by the vendored
	// interpreter's FAST_OP_ECALLI arms; symbols only satisfy the host
	// linker's import resolution via stubs). polkavm-derive rejects doc
	// comments on the extern block — keep comments as `//` lines.
	#[polkavm_derive::polkavm_import]
	extern "C" {
		// ROSTRO_INTRINSIC_DILITHIUM_VERIFY (ML-DSA-65)
		#[polkavm_import(index = 110)]
		pub fn rostro_mldsa65_verify(
			pk_ptr: u32,
			msg_ptr: u32,
			msg_len: u32,
			sig_ptr: u32,
			ctx_ptr: u32,
			ctx_len: u32,
		) -> u32;
		// ROSTRO_INTRINSIC_P521_ECDSA_VERIFY
		#[polkavm_import(index = 111)]
		pub fn rostro_p521_verify_prehash(
			vk_ptr: u32,
			sig_ptr: u32,
			prehash_ptr: u32,
			prehash_len: u32,
		) -> u32;
		// ROSTRO_INTRINSIC_SLHDSA_128S_VERIFY
		#[polkavm_import(index = 113)]
		pub fn rostro_slhdsa128s_verify(
			pk_ptr: u32,
			msg_ptr: u32,
			msg_len: u32,
			sig_ptr: u32,
			ctx_ptr: u32,
			ctx_len: u32,
		) -> u32;
		// ROSTRO_INTRINSIC_BLS381_PAIRING_CHECK
		#[polkavm_import(index = 114)]
		pub fn rostro_bls381_pairing_check(pairs_ptr: u32, n_pairs: u32) -> u32;
		// ROSTRO_INTRINSIC_ED25519_VERIFY
		#[polkavm_import(index = 122)]
		pub fn rostro_ed25519_verify(pk_ptr: u32, sig_ptr: u32, msg_ptr: u32, msg_len: u32) -> u32;
		// ROSTRO_INTRINSIC_SECP256K1_RECOVER
		#[polkavm_import(index = 123)]
		pub fn rostro_secp256k1_recover(hash_ptr: u32, sig_ptr: u32, out_pk_ptr: u32) -> u32;
	}

	#[polkavm_derive::polkavm_export]
	#[no_mangle]
	pub extern "C" fn bench_noop(_ptr: u32, _len: u32) -> u64 {
		0
	}

	// ── ed25519 ────────────────────────────────────────────────────────

	#[polkavm_derive::polkavm_export]
	#[no_mangle]
	pub extern "C" fn bench_ed25519_soft(ptr: u32, len: u32) -> u64 {
		let data = input(ptr, len);
		if data.len() < 32 + 64 {
			return 1;
		}
		let (pk, rest) = data.split_at(32);
		let (sig, msg) = rest.split_at(64);
		let Ok(vk) = ed25519_zebra::VerificationKey::try_from(pk) else { return 2 };
		let sig_arr: [u8; 64] = sig.try_into().expect("split_at(64); qed");
		match vk.verify(&ed25519_zebra::Signature::from(sig_arr), msg) {
			Ok(()) => 0,
			Err(_) => 4,
		}
	}

	#[polkavm_derive::polkavm_export]
	#[no_mangle]
	pub extern "C" fn bench_ed25519_intrinsic(ptr: u32, len: u32) -> u64 {
		if len < 32 + 64 {
			return 1;
		}
		let msg_len = len - 96;
		let ok = unsafe { rostro_ed25519_verify(ptr, ptr + 32, ptr + 96, msg_len) };
		if ok == 1 {
			0
		} else {
			4
		}
	}

	// ── sr25519 (schnorrkel) — no intrinsic ────────────────────────────

	#[polkavm_derive::polkavm_export]
	#[no_mangle]
	pub extern "C" fn bench_sr25519_soft(ptr: u32, len: u32) -> u64 {
		let data = input(ptr, len);
		if data.len() < 32 + 64 {
			return 1;
		}
		let (pk, rest) = data.split_at(32);
		let (sig, msg) = rest.split_at(64);
		let Ok(vk) = schnorrkel::PublicKey::from_bytes(pk) else { return 2 };
		let Ok(sig) = schnorrkel::Signature::from_bytes(sig) else { return 3 };
		match vk.verify_simple(b"substrate", msg, &sig) {
			Ok(()) => 0,
			Err(_) => 4,
		}
	}

	// ── secp256k1 ecrecover ────────────────────────────────────────────

	#[polkavm_derive::polkavm_export]
	#[no_mangle]
	pub extern "C" fn bench_ecrecover_soft(ptr: u32, len: u32) -> u64 {
		use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
		let data = input(ptr, len);
		if data.len() != 32 + 64 + 1 + 64 {
			return 1;
		}
		let hash = &data[..32];
		let Ok(sig) = Signature::from_slice(&data[32..96]) else { return 3 };
		let Some(recid) = RecoveryId::from_byte(data[96]) else { return 3 };
		let Ok(vk) = VerifyingKey::recover_from_prehash(hash, &sig, recid) else { return 4 };
		let point = vk.to_encoded_point(false);
		if &point.as_bytes()[1..65] == &data[97..161] {
			0
		} else {
			4
		}
	}

	#[polkavm_derive::polkavm_export]
	#[no_mangle]
	pub extern "C" fn bench_ecrecover_intrinsic(ptr: u32, len: u32) -> u64 {
		if len != 32 + 64 + 1 + 64 {
			return 1;
		}
		// Input framing puts r||s||v contiguous at offset 32 (65 bytes).
		let mut out_pk = [0u8; 64];
		let ok = unsafe { rostro_secp256k1_recover(ptr, ptr + 32, out_pk.as_mut_ptr() as u32) };
		if ok != 1 {
			return 4;
		}
		let expected = &input(ptr, len)[97..161];
		if out_pk == expected {
			0
		} else {
			4
		}
	}

	// ── P-521 ──────────────────────────────────────────────────────────

	#[polkavm_derive::polkavm_export]
	#[no_mangle]
	pub extern "C" fn bench_p521_soft(ptr: u32, len: u32) -> u64 {
		use p521::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
		let data = input(ptr, len);
		if data.len() != 133 + 132 + 64 {
			return 1;
		}
		let Ok(vk) = VerifyingKey::from_sec1_bytes(&data[..133]) else { return 2 };
		let Ok(sig) = Signature::from_slice(&data[133..265]) else { return 3 };
		match vk.verify_prehash(&data[265..329], &sig) {
			Ok(()) => 0,
			Err(_) => 4,
		}
	}

	#[polkavm_derive::polkavm_export]
	#[no_mangle]
	pub extern "C" fn bench_p521_intrinsic(ptr: u32, len: u32) -> u64 {
		if len != 133 + 132 + 64 {
			return 1;
		}
		let ok = unsafe { rostro_p521_verify_prehash(ptr, ptr + 133, ptr + 265, 64) };
		if ok == 1 {
			0
		} else {
			4
		}
	}

	// ── ML-DSA-65 (Dilithium) ──────────────────────────────────────────

	const MLDSA_PK: usize = 1952;
	const MLDSA_SIG: usize = 3309;

	#[polkavm_derive::polkavm_export]
	#[no_mangle]
	pub extern "C" fn bench_mldsa_soft(ptr: u32, len: u32) -> u64 {
		use fips204::ml_dsa_65;
		use fips204::traits::{SerDes, Verifier};
		let data = input(ptr, len);
		if data.len() < MLDSA_PK + MLDSA_SIG {
			return 1;
		}
		let pk_arr: &[u8; MLDSA_PK] =
			data[..MLDSA_PK].try_into().expect("length checked; qed");
		let sig_arr: &[u8; MLDSA_SIG] =
			data[MLDSA_PK..MLDSA_PK + MLDSA_SIG].try_into().expect("length checked; qed");
		let msg = &data[MLDSA_PK + MLDSA_SIG..];
		let Ok(pk) = ml_dsa_65::PublicKey::try_from_bytes(*pk_arr) else { return 2 };
		if pk.verify(msg, sig_arr, &[]) {
			0
		} else {
			4
		}
	}

	#[polkavm_derive::polkavm_export]
	#[no_mangle]
	pub extern "C" fn bench_mldsa_intrinsic(ptr: u32, len: u32) -> u64 {
		if (len as usize) < MLDSA_PK + MLDSA_SIG {
			return 1;
		}
		let msg_len = len - (MLDSA_PK + MLDSA_SIG) as u32;
		let ok = unsafe {
			rostro_mldsa65_verify(
				ptr,
				ptr + (MLDSA_PK + MLDSA_SIG) as u32,
				msg_len,
				ptr + MLDSA_PK as u32,
				0,
				0,
			)
		};
		if ok == 1 {
			0
		} else {
			4
		}
	}

	// ── SLH-DSA-SHA2-128s — no intrinsic ───────────────────────────────

	const SLH_PK: usize = 32;
	const SLH_SIG: usize = 7856;

	#[polkavm_derive::polkavm_export]
	#[no_mangle]
	pub extern "C" fn bench_slhdsa_soft(ptr: u32, len: u32) -> u64 {
		use slh_dsa::Sha2_128s;
		let data = input(ptr, len);
		if data.len() < SLH_PK + SLH_SIG {
			return 1;
		}
		let Ok(vk) = slh_dsa::VerifyingKey::<Sha2_128s>::try_from(&data[..SLH_PK]) else {
			return 2;
		};
		let Ok(sig) = slh_dsa::Signature::<Sha2_128s>::try_from(&data[SLH_PK..SLH_PK + SLH_SIG])
		else {
			return 3;
		};
		let msg = &data[SLH_PK + SLH_SIG..];
		match vk.try_verify_with_context(msg, &[], &sig) {
			Ok(()) => 0,
			Err(_) => 4,
		}
	}

	#[polkavm_derive::polkavm_export]
	#[no_mangle]
	pub extern "C" fn bench_slhdsa_intrinsic(ptr: u32, len: u32) -> u64 {
		if (len as usize) < SLH_PK + SLH_SIG {
			return 1;
		}
		let msg_len = len - (SLH_PK + SLH_SIG) as u32;
		let ok = unsafe {
			rostro_slhdsa128s_verify(
				ptr,
				ptr + (SLH_PK + SLH_SIG) as u32,
				msg_len,
				ptr + SLH_PK as u32,
				0,
				0,
			)
		};
		if ok == 1 {
			0
		} else {
			4
		}
	}

	// ── BLS12-381 pairing-check (2 pairs) — soft vs intrinsic 114 ──────
	// Mirrors the intrinsic exactly (CHECKED deserialize incl. subgroup),
	// unlike bench_bls_pairing_soft below which isolates one raw pairing.

	#[polkavm_derive::polkavm_export]
	#[no_mangle]
	pub extern "C" fn bench_bls_pairing_check_soft(ptr: u32, len: u32) -> u64 {
		use ark_bls12_381::{Bls12_381, G1Affine, G2Affine};
		use ark_ec::{pairing::Pairing, AffineRepr};
		use ark_ff::One;
		use ark_serialize::CanonicalDeserialize;
		let data = input(ptr, len);
		if data.len() != 2 * 288 {
			return 1;
		}
		let mut g1s = [G1Affine::identity(); 2];
		let mut g2s = [G2Affine::identity(); 2];
		for i in 0..2 {
			let off = i * 288;
			let Ok(g1) = G1Affine::deserialize_uncompressed(&data[off..off + 96]) else {
				return 2;
			};
			let Ok(g2) = G2Affine::deserialize_uncompressed(&data[off + 96..off + 288]) else {
				return 2;
			};
			g1s[i] = g1;
			g2s[i] = g2;
		}
		if Bls12_381::multi_pairing(g1s, g2s).0.is_one() {
			0
		} else {
			4
		}
	}

	#[polkavm_derive::polkavm_export]
	#[no_mangle]
	pub extern "C" fn bench_bls_pairing_check_intrinsic(ptr: u32, len: u32) -> u64 {
		if len != 2 * 288 {
			return 1;
		}
		let ok = unsafe { rostro_bls381_pairing_check(ptr, 2) };
		if ok == 1 {
			0
		} else {
			4
		}
	}

	// ── BLS12-381 pairing — no intrinsic (ring-VRF / Groth16 preview) ──

	#[polkavm_derive::polkavm_export]
	#[no_mangle]
	pub extern "C" fn bench_bls_pairing_soft(ptr: u32, len: u32) -> u64 {
		use ark_bls12_381::{Bls12_381, G1Affine, G2Affine};
		use ark_ec::pairing::Pairing;
		use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
		let data = input(ptr, len);
		if data.len() != 96 + 192 {
			return 1;
		}
		// Unchecked deserialize isolates the pairing cost (subgroup checks
		// excluded); both sides of the comparison use the same points.
		let Ok(g1) = G1Affine::deserialize_uncompressed_unchecked(&data[..96]) else { return 2 };
		let Ok(g2) = G2Affine::deserialize_uncompressed_unchecked(&data[96..288]) else { return 2 };
		let out = Bls12_381::pairing(g1, g2);
		let mut buf = [0u8; 576];
		if out.0.serialize_uncompressed(&mut buf[..]).is_err() {
			return 3;
		}
		u64::from_le_bytes(buf[..8].try_into().expect("576 >= 8; qed"))
	}
}
