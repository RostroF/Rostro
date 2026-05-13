//! ML-DSA-65 (Dilithium-3) signature verify benchmark.
//!
//! Implementation: `fips204` crate (IntegrityChain / eric-schorn). Conformance
//! evidence: the crate ships NIST's official ACVP test vectors pinned at
//! commit `65370b861b96efd30dfe0daae607bde26a78a5c8` of the usnistgov/ACVP-Server
//! repo, and replays them bit-for-bit via its integration tests. Pure Rust,
//! no unsafe, no_std, no alloc. Selected over RustCrypto's `ml-dsa-0.0.4`
//! because that pulls `sha3` with default-features (std-enabling) and Cargo
//! feature unification makes that impossible to override downstream.
//!
//! The sha2 transitive dep is FIPS-204-legitimate: Section 5.4 specifies
//! HashML-DSA pre-hash variants over SHA-256/SHA-512/SHAKE128/SHAKE256.
//! Pure ML-DSA (this bench's `try_sign(msg, ctx)` path) only touches SHAKE.
//!
//! The bench cycle is **keygen + sign + verify** with a fixed-seed counter
//! RNG. This is a full PQ-sig pipeline measurement, not verify-only — see
//! the dilithium service header for rationale. Production-side this is what
//! one PoP attestation costs through polkavm-interp.

#![cfg_attr(target_os = "none", no_std)]

use javm_builtins as _;

#[cfg(target_env = "polkavm")]
mod polkavm;

#[cfg(target_arch = "wasm32")]
mod wasm;

const MESSAGE: &[u8] = b"rostro-pop-attestation-test-vector";
const CONTEXT: &[u8] = b"";

pub fn dilithium_verify_bench() -> u32 {
	use fips204::ml_dsa_65;
	use fips204::traits::{Signer, Verifier};

	let mut rng = CounterRng { counter: 0xdeadbeef };

	let (pk, sk) = match ml_dsa_65::try_keygen_with_rng(&mut rng) {
		Ok(kp) => kp,
		Err(_) => return 0,
	};

	let sig = match sk.try_sign_with_rng(&mut rng, MESSAGE, CONTEXT) {
		Ok(s) => s,
		Err(_) => return 0,
	};

	if pk.verify(MESSAGE, &sig, CONTEXT) {
		1
	} else {
		0
	}
}

// Deterministic counter RNG. Bench needs reproducibility, not cryptographic
// randomness — CryptoRng is a marker trait with no behaviour. Each iter
// starts with counter=0xdeadbeef so the keygen+sign produces identical
// outputs every time and the verify always passes.
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
