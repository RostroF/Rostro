// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Helpers shared between `oracle_tests` and `field_air_tests`.
//! Dev-only; never reaches production code paths.

use crate::field::{bytes_to_limbs, is_canonical, FIELD_NUM_LIMBS};

/// Rejection-sample a uniform canonical-form field element from a
/// CSPRNG. Loops until a value `< p` is drawn; rejection rate is
/// negligible because `p ≈ 2^255` and we mask the top bit to 0.
pub fn random_canonical(rng: &mut rand::rngs::StdRng) -> [u32; FIELD_NUM_LIMBS] {
	use rand::RngCore;
	loop {
		let mut bytes = [0u8; 32];
		rng.fill_bytes(&mut bytes);
		// Clear top bit so values are < 2^255; rejects only the few values
		// in [p, 2^255).
		bytes[31] &= 0x7F;
		let limbs = bytes_to_limbs(&bytes);
		if is_canonical(&limbs) {
			return limbs;
		}
	}
}
