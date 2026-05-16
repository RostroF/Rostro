// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation
//
// Gas pricing for Rostro Tier 2 crypto intrinsics. Separate from the polkavm
// `CostModel` (which prices RISC-V opcodes) because intrinsics are a different
// abstraction layer — see docs/SECURITY-AUDIT-TIER2-INTRINSICS.md.
//
// Anchor: 1 gas ≈ 1 ns of native work on the audit reference machine
// (Ryzen, WSL2, release build). Numbers carry ~10% headroom over measured
// cost. Calibration source: examples/measure_intrinsic_native_cost.rs.
//
// RUNTIME INTEGRATION NOTE — when RVM serves as the network runtime
// (replacing wasm/wasmtime), substrate's `Weight` unit is 1 picosecond
// (WEIGHT_REF_TIME_PER_NANOS = 1_000). The integration layer multiplies
// RVM gas by 1000 to convert to substrate weight. The table below is
// kept in ns for direct correspondence with the measurement; the ×1000
// scale-up lives in one place in the runtime adapter.

use crate::interpreter::{
	ROSTRO_INTRINSIC_BLAKE2B_256, ROSTRO_INTRINSIC_DILITHIUM_VERIFY,
	ROSTRO_INTRINSIC_ED25519_VERIFY, ROSTRO_INTRINSIC_GOLDILOCKS_ADD,
	ROSTRO_INTRINSIC_GOLDILOCKS_INV, ROSTRO_INTRINSIC_GOLDILOCKS_MUL,
	ROSTRO_INTRINSIC_GOLDILOCKS_SUB, ROSTRO_INTRINSIC_KECCAK_256,
	ROSTRO_INTRINSIC_P521_ECDSA_VERIFY, ROSTRO_INTRINSIC_POSEIDON2_PERM,
	ROSTRO_INTRINSIC_SECP256K1_RECOVER,
};

/// Hard upper bound on the message-length argument for any intrinsic that
/// accepts variable-length input (`blake2b_256`, `keccak_256`,
/// `ed25519_verify`). Calls with `msg_len > MAX_INTRINSIC_MSG_LEN` are
/// rejected at dispatch entry — backstop against gas-formula overflow and
/// pathological single-call DoS.
///
/// 4 MiB at the per-byte rate of 1 gas/byte = ~4M gas surplus over base.
pub const MAX_INTRINSIC_MSG_LEN: u32 = 4 * 1024 * 1024;

/// Failure code returned from variable-length intrinsics when `msg_len`
/// exceeds [`MAX_INTRINSIC_MSG_LEN`]. Distinct from "memory access failed"
/// (1) to make the cap-violation case observable to the guest.
///
/// Used as the A0 return value when a hashing/verify intrinsic rejects an
/// over-cap input; the call is still gas-charged (base only, no per-byte)
/// so probing the cap is not free.
pub const ERR_MSG_LEN_TOO_LARGE: u64 = 2;

/// Flat gas cost for fixed-input intrinsics, indexed by intrinsic ID
/// (truncated to the 100..1023 reserved-ID window).
///
/// Variable-cost intrinsics (blake2b, keccak, ed25519) have their `base`
/// here and pay an additional `per_byte` charge via [`per_byte_gas`].
#[inline]
pub const fn flat_gas(id: u32) -> u32 {
	match id {
		ROSTRO_INTRINSIC_GOLDILOCKS_MUL => 1,
		ROSTRO_INTRINSIC_GOLDILOCKS_ADD => 1,
		ROSTRO_INTRINSIC_GOLDILOCKS_SUB => 1,
		ROSTRO_INTRINSIC_GOLDILOCKS_INV => 256,
		ROSTRO_INTRINSIC_DILITHIUM_VERIFY => 150_000,
		ROSTRO_INTRINSIC_P521_ECDSA_VERIFY => 600_000,
		ROSTRO_INTRINSIC_BLAKE2B_256 => 128,
		ROSTRO_INTRINSIC_KECCAK_256 => 320,
		ROSTRO_INTRINSIC_ED25519_VERIFY => 50_000,
		ROSTRO_INTRINSIC_SECP256K1_RECOVER => 160_000,
		ROSTRO_INTRINSIC_POSEIDON2_PERM => 1_024,
		// Unknown or non-Rostro intrinsic — falls back to standard ecalli
		// cost (1 gas, already paid via the block charge). No surplus.
		_ => 1,
	}
}

/// Per-byte gas for variable-length intrinsics. Multiplied by `msg_len` and
/// added to [`flat_gas`]. Zero for fixed-input intrinsics.
#[inline]
pub const fn per_byte_gas(id: u32) -> u32 {
	match id {
		ROSTRO_INTRINSIC_BLAKE2B_256 => 1,
		ROSTRO_INTRINSIC_KECCAK_256 => 2,
		ROSTRO_INTRINSIC_ED25519_VERIFY => 1,
		_ => 0,
	}
}

/// Surplus over the standard 1-gas ecalli charge already deducted via the
/// basic-block gas accounting. Returns `Some(gas_to_deduct)` for the work
/// surplus, or `None` if `msg_len > MAX_INTRINSIC_MSG_LEN`.
///
/// Caller deducts from `self.gas` and traps on underflow. `msg_len = 0` for
/// fixed-input intrinsics.
#[inline]
pub fn intrinsic_surplus_gas(id: u32, msg_len: u32) -> Option<i64> {
	if per_byte_gas(id) != 0 && msg_len > MAX_INTRINSIC_MSG_LEN {
		return None;
	}
	// The standard ecalli is already 1 gas (block-charged); deduct only the
	// surplus. flat_gas(unknown) == 1, so unknown IDs naturally yield 0
	// surplus — JIT host-call path takes over.
	let flat = flat_gas(id).saturating_sub(1);
	let variable = per_byte_gas(id).saturating_mul(msg_len);
	Some(i64::from(flat) + i64::from(variable))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn unknown_id_is_zero_surplus() {
		assert_eq!(intrinsic_surplus_gas(999, 0), Some(0));
		assert_eq!(intrinsic_surplus_gas(0, 0), Some(0));
	}

	#[test]
	fn goldilocks_mul_is_zero_surplus() {
		// 1 gas total - 1 standard = 0 surplus.
		assert_eq!(intrinsic_surplus_gas(ROSTRO_INTRINSIC_GOLDILOCKS_MUL, 0), Some(0));
	}

	#[test]
	fn ecrecover_full_surplus() {
		// 160_000 total - 1 standard = 159_999 surplus.
		assert_eq!(intrinsic_surplus_gas(ROSTRO_INTRINSIC_SECP256K1_RECOVER, 0), Some(159_999));
	}

	#[test]
	fn blake2b_per_byte_scales() {
		// 128 base + 1 per byte - 1 standard = 127 + msg_len.
		assert_eq!(intrinsic_surplus_gas(ROSTRO_INTRINSIC_BLAKE2B_256, 0), Some(127));
		assert_eq!(intrinsic_surplus_gas(ROSTRO_INTRINSIC_BLAKE2B_256, 1024), Some(127 + 1024));
	}

	#[test]
	fn msg_len_cap_rejects() {
		assert_eq!(
			intrinsic_surplus_gas(ROSTRO_INTRINSIC_BLAKE2B_256, MAX_INTRINSIC_MSG_LEN + 1),
			None,
		);
	}

	#[test]
	fn msg_len_cap_boundary_accepts() {
		assert!(intrinsic_surplus_gas(ROSTRO_INTRINSIC_BLAKE2B_256, MAX_INTRINSIC_MSG_LEN).is_some());
	}

	#[test]
	fn cap_only_applies_to_variable_length() {
		// secp256k1_recover has no per-byte component; msg_len is ignored.
		assert_eq!(
			intrinsic_surplus_gas(ROSTRO_INTRINSIC_SECP256K1_RECOVER, u32::MAX),
			Some(159_999),
		);
	}
}
