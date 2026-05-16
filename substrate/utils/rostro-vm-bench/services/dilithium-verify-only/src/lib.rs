//! ML-DSA-65 verify-only bench. Hardcoded pk + sig precomputed natively from
//! the same fixed-seed (0xdeadbeef) counter RNG used by the keygen+sign+verify
//! variant. This isolates the verify cost so the polkavm-interp intrinsic
//! delta isn't drowned out by keygen+sign dispatch overhead.

#![cfg_attr(target_os = "none", no_std)]

use javm_builtins as _;

mod consts;

#[cfg(target_env = "polkavm")]
mod polkavm;

#[cfg(target_arch = "wasm32")]
mod wasm;

const MESSAGE: &[u8] = b"rostro-pop-attestation-test-vector";
const CONTEXT: &[u8] = b"";

pub fn dilithium_verify_bench() -> u32 {
	#[cfg(target_env = "polkavm")]
	{
		unsafe {
			crate::polkavm::rostro_dilithium_verify(
				consts::PK.as_ptr() as u32,
				MESSAGE.as_ptr() as u32,
				MESSAGE.len() as u32,
				consts::SIG.as_ptr() as u32,
				CONTEXT.as_ptr() as u32,
				CONTEXT.len() as u32,
			)
		}
	}
	#[cfg(not(target_env = "polkavm"))]
	{
		use fips204::ml_dsa_65;
		use fips204::traits::{SerDes, Verifier};
		let pk = match ml_dsa_65::PublicKey::try_from_bytes(consts::PK) {
			Ok(pk) => pk,
			Err(_) => return 0,
		};
		if pk.verify(MESSAGE, &consts::SIG, CONTEXT) { 1 } else { 0 }
	}
}
