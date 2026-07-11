// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! # p256 ECDSA verify bench fixture (RVM interpreter)
//!
//! Guest side of the EcdsaP256 signature-variant decision benchmark:
//! measures what a P-256 ECDSA verification costs when it runs
//! interpreted inside RostroVM versus native, to decide whether the
//! future `RostroSignature::EcdsaP256` variant verifies in-runtime
//! (pure set_code, zero new consensus surface) or via a `p256_verify`
//! host function (native speed, ships in the testnet-reset binary).
//!
//! Exports (all take the substrate PVM call ABI `(input_ptr, input_len)`
//! with input bytes at `heap_base`, and return a status in `A0`):
//!
//! - `bench_noop` — call-overhead calibration; returns 0.
//! - `bench_sha256_soft` — SHA-256 over the whole input using the sha2
//!   crate's soft path (the only path on riscv64); returns the first 8
//!   digest bytes LE so the work can't be optimized away.
//! - `bench_verify_prehash` — input `pubkey(33) ‖ sig(64) ‖ digest(32)`;
//!   pure EC verify with the digest supplied. This is the floor for the
//!   in-RVM option (models the digest lifted through
//!   `sp_io::hashing::sha2_256`, hashing cost excluded entirely).
//! - `bench_verify_full_soft` — input `pubkey(33) ‖ sig(64) ‖ msg(..)`;
//!   EC verify plus in-guest soft SHA-256 of the message (worst case).
//! - `bench_verify_full_hostsha` — same input; digest computed via the
//!   `sp_io::hashing::sha2_256` host function (native SHA on the host),
//!   then EC verify of the prehash. The realistic in-RVM candidate.
//! - `bench_verify_prehash_intrinsic` — same input as
//!   `bench_verify_prehash`; verification via the RVM Tier-2 ecalli
//!   intrinsic (`ROSTRO_INTRINSIC_P256_ECDSA_VERIFY = 112`) — native
//!   verify body, zero-copy operand borrow. The intrinsic candidate.
//!
//! Return codes for the verify exports: 0 = signature valid,
//! 1 = malformed input framing, 2 = pubkey rejected, 3 = signature
//! encoding rejected, 4 = signature invalid.

#![cfg_attr(not(feature = "std"), no_std)]

// Re-export the PVM blob produced by build.rs for the host-side harness.
#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

/// Returns the PVM blob bytes. Panics if `SKIP_WASM_BUILD` was set.
#[cfg(feature = "std")]
pub fn binary_unwrap() -> &'static [u8] {
	WASM_BINARY.expect(
		"rostro-executor-fixture-p256-bench binary missing — build was \
		 skipped via SKIP_WASM_BUILD or substrate-wasm-builder reported failure",
	)
}

// ─── Runtime side (no_std) ─────────────────────────────────────────────────

#[cfg(not(feature = "std"))]
mod guest {
	use p256::ecdsa::{
		signature::{hazmat::PrehashVerifier, Verifier},
		Signature, VerifyingKey,
	};

	/// Read the input payload the executor wrote at `heap_base`. The
	/// pointer/length come straight from the call ABI and address guest
	/// memory, so the deref is sound for the lifetime of the call.
	fn input<'a>(ptr: u32, len: u32) -> &'a [u8] {
		unsafe { core::slice::from_raw_parts(ptr as *const u8, len as usize) }
	}

	/// Split `pubkey(33) ‖ sig(64) ‖ rest` framing.
	fn split(data: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
		if data.len() < 33 + 64 {
			return None;
		}
		let (pk, rest) = data.split_at(33);
		let (sig, tail) = rest.split_at(64);
		Some((pk, sig, tail))
	}

	fn parse(pk: &[u8], sig: &[u8]) -> Result<(VerifyingKey, Signature), u64> {
		let key = VerifyingKey::from_sec1_bytes(pk).map_err(|_| 2u64)?;
		let sig = Signature::from_slice(sig).map_err(|_| 3u64)?;
		Ok((key, sig))
	}

	#[polkavm_derive::polkavm_export]
	#[no_mangle]
	pub extern "C" fn bench_noop(_ptr: u32, _len: u32) -> u64 {
		0
	}

	#[polkavm_derive::polkavm_export]
	#[no_mangle]
	pub extern "C" fn bench_sha256_soft(ptr: u32, len: u32) -> u64 {
		use sha2::{Digest, Sha256};
		let digest = Sha256::digest(input(ptr, len));
		let mut out = [0u8; 8];
		out.copy_from_slice(&digest[..8]);
		u64::from_le_bytes(out)
	}

	#[polkavm_derive::polkavm_export]
	#[no_mangle]
	pub extern "C" fn bench_verify_prehash(ptr: u32, len: u32) -> u64 {
		let Some((pk, sig, digest)) = split(input(ptr, len)) else { return 1 };
		if digest.len() != 32 {
			return 1;
		}
		let (key, sig) = match parse(pk, sig) {
			Ok(v) => v,
			Err(code) => return code,
		};
		match key.verify_prehash(digest, &sig) {
			Ok(()) => 0,
			Err(_) => 4,
		}
	}

	#[polkavm_derive::polkavm_export]
	#[no_mangle]
	pub extern "C" fn bench_verify_full_soft(ptr: u32, len: u32) -> u64 {
		let Some((pk, sig, msg)) = split(input(ptr, len)) else { return 1 };
		let (key, sig) = match parse(pk, sig) {
			Ok(v) => v,
			Err(code) => return code,
		};
		match key.verify(msg, &sig) {
			Ok(()) => 0,
			Err(_) => 4,
		}
	}

	// RVM Tier-2 intrinsic import (dispatched inline by the vendored
	// interpreter's FAST_OP_ECALLI arm; see ROSTRO_INTRINSIC_P256_ECDSA_VERIFY
	// in rostrovm interpreter.rs). NOTE: doc comments on the extern block are
	// rejected by polkavm-derive — keep comments as `//` lines.
	#[polkavm_derive::polkavm_import]
	extern "C" {
		#[polkavm_import(index = 112)]
		pub fn rostro_p256_verify_prehash(
			vk_ptr: u32,
			sig_ptr: u32,
			prehash_ptr: u32,
			prehash_len: u32,
		) -> u32;
	}

	#[polkavm_derive::polkavm_export]
	#[no_mangle]
	pub extern "C" fn bench_verify_prehash_intrinsic(ptr: u32, len: u32) -> u64 {
		if len != (33 + 64 + 32) as u32 {
			return 1;
		}
		// Operands are borrowed zero-copy by the intrinsic straight out of
		// the input framing: pubkey(33) ‖ sig(64) ‖ digest(32).
		let ok = unsafe { rostro_p256_verify_prehash(ptr, ptr + 33, ptr + 97, 32) };
		if ok == 1 {
			0
		} else {
			4
		}
	}

	#[polkavm_derive::polkavm_export]
	#[no_mangle]
	pub extern "C" fn bench_verify_full_hostsha(ptr: u32, len: u32) -> u64 {
		let Some((pk, sig, msg)) = split(input(ptr, len)) else { return 1 };
		let (key, sig) = match parse(pk, sig) {
			Ok(v) => v,
			Err(code) => return code,
		};
		let digest = sp_io::hashing::sha2_256(msg);
		match key.verify_prehash(&digest, &sig) {
			Ok(()) => 0,
			Err(_) => 4,
		}
	}
}
