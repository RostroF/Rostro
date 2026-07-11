// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! # Ring verifier-key fixture (RVM interpreter) — the era-boundary proof
//!
//! `pallet-sassafras::update_ring_verifier` builds
//! `RingProofParams::verifier_key(&pks)` from the next session's authority
//! keys — the MSM-shaped work that livelocked the NPoS PoC at ~4.8 s
//! interpreted against a 4 s deadline. This fixture builds the SAME
//! artifact in-guest through both stacks:
//!
//! - `rb_vk_hooked`: vendored ark-vrf, hooked curves — every group
//!   operation is an ecalli intrinsic.
//! - `rb_vk_plain`: plain upstream ark-vrf — every instruction interprets.
//! - `rb_deser_hooked` / `rb_deser_plain`: params + pks deserialization
//!   only, the baseline the harness subtracts from the vk legs.
//!
//! Framing (all exports): params_len(u32 LE) ‖ params(uncompressed) ‖
//! n_pks(u32 LE) ‖ pks(n × 64B uncompressed TE affine) ‖ expected_vk_len
//! (u32 LE) ‖ expected_vk(uncompressed). Status in `A0`: 0 ok, 1 framing,
//! 2 parse, 4 mismatch.
//!
//! Success is three numbers (native / in-guest hooked / in-guest plain),
//! the middle one being the era boundary fixed — plus byte-equality of
//! the verifier key across all legs.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

/// Returns the PVM blob bytes. Panics if `SKIP_WASM_BUILD` was set.
#[cfg(feature = "std")]
pub fn binary_unwrap() -> &'static [u8] {
	WASM_BINARY.expect(
		"rostro-executor-fixture-ring-bench binary missing — build was \
		 skipped via SKIP_WASM_BUILD or substrate-wasm-builder reported failure",
	)
}

// ─── Runtime side (no_std) ─────────────────────────────────────────────────

// Link sp-io for its `#[panic_handler]` and `#[global_allocator]`: nothing
// in this guest calls sp_io directly, and an unused dependency does not get
// linked, so the handler and allocator would otherwise be missing.
#[cfg(not(feature = "std"))]
extern crate sp_io;

#[cfg(not(feature = "std"))]
mod guest {
	extern crate alloc;
	use alloc::vec::Vec;
	use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

	fn input<'a>(ptr: u32, len: u32) -> &'a [u8] {
		unsafe { core::slice::from_raw_parts(ptr as *const u8, len as usize) }
	}

	struct Framing<'a> {
		params: &'a [u8],
		pks: &'a [u8],
		n_pks: usize,
		expected_vk: &'a [u8],
	}

	fn parse(data: &[u8]) -> Option<Framing<'_>> {
		let params_len = u32::from_le_bytes(data.get(..4)?.try_into().ok()?) as usize;
		let rest = data.get(4..)?;
		let params = rest.get(..params_len)?;
		let rest = rest.get(params_len..)?;
		let n_pks = u32::from_le_bytes(rest.get(..4)?.try_into().ok()?) as usize;
		let rest = rest.get(4..)?;
		let pks = rest.get(..n_pks * 64)?;
		let rest = rest.get(n_pks * 64..)?;
		let vk_len = u32::from_le_bytes(rest.get(..4)?.try_into().ok()?) as usize;
		let expected_vk = rest.get(4..)?;
		if expected_vk.len() != vk_len {
			return None;
		}
		Some(Framing { params, pks, n_pks, expected_vk })
	}

	// One macro, two stacks: the bodies must be identical so the timing
	// difference is purely the execution backend.
	macro_rules! ring_exports {
		($deser_name:ident, $vk_name:ident, $vrf:ident) => {
			#[polkavm_derive::polkavm_export]
			#[no_mangle]
			pub extern "C" fn $deser_name(ptr: u32, len: u32) -> u64 {
				let Some(f) = parse(input(ptr, len)) else { return 1 };
				let Ok(_params) =
					$vrf::ring::RingProofParams::<
						$vrf::suites::bandersnatch::BandersnatchSha512Ell2,
					>::deserialize_uncompressed_unchecked(f.params)
				else {
					return 2;
				};
				let mut pks: Vec<$vrf::suites::bandersnatch::AffinePoint> =
					Vec::with_capacity(f.n_pks);
				for i in 0..f.n_pks {
					let Ok(p) =
						$vrf::suites::bandersnatch::AffinePoint::deserialize_uncompressed_unchecked(
							&f.pks[i * 64..(i + 1) * 64],
						)
					else {
						return 2;
					};
					pks.push(p);
				}
				core::hint::black_box(&pks);
				0
			}

			#[polkavm_derive::polkavm_export]
			#[no_mangle]
			pub extern "C" fn $vk_name(ptr: u32, len: u32) -> u64 {
				let Some(f) = parse(input(ptr, len)) else { return 1 };
				let Ok(params) =
					$vrf::ring::RingProofParams::<
						$vrf::suites::bandersnatch::BandersnatchSha512Ell2,
					>::deserialize_uncompressed_unchecked(f.params)
				else {
					return 2;
				};
				let mut pks: Vec<$vrf::suites::bandersnatch::AffinePoint> =
					Vec::with_capacity(f.n_pks);
				for i in 0..f.n_pks {
					let Ok(p) =
						$vrf::suites::bandersnatch::AffinePoint::deserialize_uncompressed_unchecked(
							&f.pks[i * 64..(i + 1) * 64],
						)
					else {
						return 2;
					};
					pks.push(p);
				}
				let vk = params.verifier_key(&pks);
				let mut out = Vec::new();
				if vk.serialize_uncompressed(&mut out).is_err() {
					return 2;
				}
				if out[..] == f.expected_vk[..] {
					0
				} else {
					4
				}
			}
		};
	}

	ring_exports!(rb_deser_hooked, rb_vk_hooked, ark_vrf);
	ring_exports!(rb_deser_plain, rb_vk_plain, ark_vrf_plain);
}
