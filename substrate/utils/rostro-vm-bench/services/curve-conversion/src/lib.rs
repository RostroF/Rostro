//! Curve-conversion micro-pipeline benchmark mirroring the OPRF inner loop:
//! hash-to-curve (Elligator2 via Ristretto), Ristretto compress, Ristretto
//! decompress, and scalar multiplication. This is the exact shape of math
//! that runs constantly in pallet-rostro-personhood's nullifier path and
//! anywhere ZK-friendly DLog crypto is exercised.

#![cfg_attr(target_os = "none", no_std)]

use javm_builtins as _;

#[cfg(target_os = "none")]
extern crate alloc;

#[cfg(target_os = "none")]
mod bump_alloc {
	use core::alloc::{GlobalAlloc, Layout};
	use core::cell::UnsafeCell;

	const HEAP_SIZE: usize = 128 * 1024;

	pub struct BumpAlloc {
		heap: UnsafeCell<[u8; HEAP_SIZE]>,
		pos: UnsafeCell<usize>,
	}

	unsafe impl Sync for BumpAlloc {}

	unsafe impl GlobalAlloc for BumpAlloc {
		unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
			let pos = unsafe { &mut *self.pos.get() };
			let aligned = (*pos + layout.align() - 1) & !(layout.align() - 1);
			let next = aligned + layout.size();
			if next > HEAP_SIZE {
				return core::ptr::null_mut();
			}
			*pos = next;
			unsafe { (*self.heap.get()).as_mut_ptr().add(aligned) }
		}

		unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
	}

	#[global_allocator]
	pub static ALLOC: BumpAlloc =
		BumpAlloc { heap: UnsafeCell::new([0; HEAP_SIZE]), pos: UnsafeCell::new(0) };
}

#[cfg(target_env = "polkavm")]
mod polkavm;

#[cfg(target_arch = "wasm32")]
mod wasm;

// 64 bytes of "uniform" input — the canonical hash-to-curve entry point. The
// OPRF flow feeds Poseidon2(input) || something here. We use a fixed pattern
// so the bench is deterministic.
const HASH_TO_CURVE_INPUT: [u8; 64] = [
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
	0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
	0x0f, 0xed, 0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21, 0xfe, 0xba, 0xfe, 0xca, 0xef, 0xbe, 0xad, 0xde,
	0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
];

// 32 bytes interpreted as a scalar mod l for the scalar-mul step (canonical
// OPRF blinding factor shape — 32 bytes of "randomness" reduced).
const BLINDING_SCALAR_BYTES: [u8; 32] = [
	0x07, 0x11, 0x1d, 0x29, 0x35, 0x41, 0x4d, 0x59, 0x65, 0x71, 0x7d, 0x89, 0x95, 0xa1, 0xad, 0xb9,
	0xc5, 0xd1, 0xdd, 0xe9, 0xf5, 0x01, 0x0d, 0x19, 0x25, 0x31, 0x3d, 0x49, 0x55, 0x61, 0x6d, 0x09,
];

/// Run one OPRF-shaped conversion pipeline. Returns the first 4 bytes of the
/// final compressed point as a u32, so the result is deterministic and used
/// (preventing dead-code elimination).
pub fn curve_conversion_bench() -> u32 {
	use curve25519_dalek::{
		ristretto::{CompressedRistretto, RistrettoPoint},
		scalar::Scalar,
	};

	// Stage 1: hash-to-curve (Elligator2 via Ristretto::from_uniform_bytes)
	let p1 = RistrettoPoint::from_uniform_bytes(&HASH_TO_CURVE_INPUT);

	// Stage 2: compress (Edwards/Ristretto internal -> 32 bytes)
	let bytes_after_compress = p1.compress().to_bytes();

	// Stage 3: decompress (32 bytes -> Edwards/Ristretto internal)
	let p2 = match CompressedRistretto::from_slice(&bytes_after_compress) {
		Ok(c) => match c.decompress() {
			Some(pt) => pt,
			None => return 0,
		},
		Err(_) => return 0,
	};

	// Stage 4: scalar mul (the meat of OPRF — k * P where k is the secret share)
	let scalar = Scalar::from_bytes_mod_order(BLINDING_SCALAR_BYTES);
	let p3 = p2 * scalar;

	// Stage 5: final compress so the whole pipeline is observed in the output
	let out = p3.compress().to_bytes();
	u32::from_le_bytes([out[0], out[1], out[2], out[3]])
}
