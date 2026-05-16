//! NIST P-521 ECDSA verify benchmark — the curve TPM2 hardware attestation
//! uses. Bench cycle is **keygen + sign + verify** with a deterministic seed
//! (same rationale as the dilithium service: avoids embedding multi-KB
//! test-vector constants and the VM dispatch loop is exercised identically
//! across all three phases). The interesting cost is the large-modulus
//! arithmetic — 521-bit modular ops — which is the part custom RVM
//! instructions would specifically target.

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

// Deterministic 66-byte (528-bit) "scalar source" — interpreted as a P-521
// private scalar. Bytes chosen so the value lies in (0, n).
const SK_SCALAR_BYTES: [u8; 66] = [
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0x01, 0x23,
];

// Pre-hashed message: 64 bytes (P-521 typically pairs with SHA-512).
const PREHASH: [u8; 64] = [
	0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
	0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
	0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
	0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
];

pub fn p521_verify_bench() -> u32 {
	use p521::ecdsa::{
		signature::hazmat::{PrehashVerifier, RandomizedPrehashSigner},
		SigningKey, VerifyingKey,
	};

	let sk = match SigningKey::from_slice(&SK_SCALAR_BYTES) {
		Ok(s) => s,
		Err(_) => return 0,
	};
	let vk = VerifyingKey::from(&sk);

	let mut rng = CounterRng { counter: 0xc0ffee };
	let sig = match sk.sign_prehash_with_rng(&mut rng, &PREHASH) {
		Ok(s) => s,
		Err(_) => return 0,
	};

	// Tier 2 H2 (2026-05-12): dispatch verify via the RostroVM intrinsic on
	// polkavm targets. Pure-Rust software path retained for other targets.
	#[cfg(target_env = "polkavm")]
	{
		let vk_pt = vk.to_encoded_point(false); // uncompressed: 0x04 || X(66) || Y(66) = 133B
		let vk_bytes = vk_pt.as_bytes();
		let sig_bytes = sig.to_bytes();
		unsafe {
			crate::polkavm::rostro_p521_ecdsa_verify(
				vk_bytes.as_ptr() as u32,
				sig_bytes.as_ptr() as u32,
				PREHASH.as_ptr() as u32,
				PREHASH.len() as u32,
			)
		}
	}
	#[cfg(not(target_env = "polkavm"))]
	{
		match vk.verify_prehash(&PREHASH, &sig) {
			Ok(_) => 1,
			Err(_) => 0,
		}
	}
}

// Deterministic counter-based RNG. `CryptoRng` is a marker trait with no
// methods — implementing it here is a "lie for bench determinism" not a
// security claim. The bench uses the same counter seed every iteration so
// the signature is identical run-to-run.
struct CounterRng {
	counter: u64,
}

impl rand_core::RngCore for CounterRng {
	fn next_u32(&mut self) -> u32 {
		self.counter = self.counter.wrapping_add(1);
		self.counter as u32
	}

	fn next_u64(&mut self) -> u64 {
		self.counter = self.counter.wrapping_add(1);
		self.counter
	}

	fn fill_bytes(&mut self, dest: &mut [u8]) {
		for chunk in dest.chunks_mut(8) {
			self.counter = self.counter.wrapping_add(1);
			let bytes = self.counter.to_le_bytes();
			let n = chunk.len();
			chunk.copy_from_slice(&bytes[..n]);
		}
	}

	fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
		self.fill_bytes(dest);
		Ok(())
	}
}

impl rand_core::CryptoRng for CounterRng {}
