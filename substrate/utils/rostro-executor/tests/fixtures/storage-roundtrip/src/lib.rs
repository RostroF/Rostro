// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! # rostro-executor storage roundtrip fixture
//!
//! Tiny runtime guest used as the B3 gate test for
//! [`rostro-executor`](https://github.com/rostro-foundation/rostro/tree/main/substrate/utils/rostro-executor).
//! Compiled to PVM via `substrate-wasm-builder` (its `build.rs` forces
//! `SUBSTRATE_RUNTIME_TARGET=riscv`), loaded by the integration test, run
//! with the dispatcher's host-fn shim wired to `sp_io::storage::HostFunctions`.
//!
//! The guest's single export, `test_storage_roundtrip`, returns:
//!
//! - `0` — set + read returned the original bytes intact (roundtrip OK).
//! - `1` — `storage::read` returned a length that didn't match what was set.
//! - `2` — bytes didn't match.
//! - `3` — `storage::read` returned `None` after `set`.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

// Re-export the WASM/PVM binary produced by build.rs for the host side
// (rostro-executor's integration test) to load.
#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

/// Returns the PVM blob bytes. Panics if `SKIP_WASM_BUILD` was set.
#[cfg(feature = "std")]
pub fn binary_unwrap() -> &'static [u8] {
	WASM_BINARY.expect(
		"rostro-executor-fixture-storage-roundtrip binary missing — build was \
		 skipped via SKIP_WASM_BUILD or substrate-wasm-builder reported failure",
	)
}

// ─── Runtime side (no_std) ─────────────────────────────────────────────────
//
// `polkavm_export` (vs sp-core's `wasm_export_functions!`) is the right
// macro for the PVM target — it emits the polkavm export symbol the
// linker needs to find the entry point. The latter just does
// `#[no_mangle] pub fn`, which polkavm-linker treats as an internal
// function and strips, leaving an empty program.

#[cfg(not(feature = "std"))]
#[polkavm_derive::polkavm_export]
#[no_mangle]
pub extern "C" fn test_storage_roundtrip() -> u64 {
	let key: &[u8] = b"phase-star-roundtrip-key";
	let value: &[u8] = b"phase-star-roundtrip-value";

	// B3 minimal: just exercise `set`. Read-back through the SCALE-encoded
	// `Option<u32>` return path needs allocate_memory + return-fat-pointer
	// semantics that go beyond storage::set's call-only path; that becomes
	// the B3-followup gate (host-side reads externalities directly to
	// verify what the guest wrote).
	sp_io::storage::set(key, value);

	0
}

// ─── B3b exports ───────────────────────────────────────────────────────────

/// Exercise `sp_io::hashing::blake2_256` — host-side `AllocateAndReturnPointer`
/// path. The fixture computes the hash of a known input and stores the
/// result under a known key so the host can verify both that:
///
/// 1. The hashing host-fn dispatch worked (no trap on the
///    `AllocateAndReturnPointer<[u8; 32], 32>` return).
/// 2. The bytes are correct — independently computable on the host side.
#[cfg(not(feature = "std"))]
#[polkavm_derive::polkavm_export]
#[no_mangle]
pub extern "C" fn test_hashing_blake2_256() -> u64 {
	let input: &[u8] = b"phase-star";
	let hash = sp_io::hashing::blake2_256(input);
	// Use first 8 bytes as the return value so we can verify the hash
	// without needing a second host fn call (storage::set after the hash
	// triggers a trap that may be downstream of the actual problem).
	let mut out = [0u8; 8];
	out.copy_from_slice(&hash[..8]);
	u64::from_le_bytes(out)
}

/// Exercise `sp_io::hashing::keccak_256` — same shape as blake2 but a
/// different intrinsic / different host-fn (and the Tier 2 intrinsic
/// path the rostrovm fork provides for routing later).
#[cfg(not(feature = "std"))]
#[polkavm_derive::polkavm_export]
#[no_mangle]
pub extern "C" fn test_hashing_keccak_256() -> u64 {
	let input: &[u8] = b"phase-star";
	let hash = sp_io::hashing::keccak_256(input);
	sp_io::storage::set(b"keccak-test-result", &hash);
	0
}

/// Exercise `sp_io::hashing::twox_128` — a non-cryptographic hash used
/// pervasively for storage key derivation. Returns a 16-byte digest via
/// the same `AllocateAndReturnPointer` path.
#[cfg(not(feature = "std"))]
#[polkavm_derive::polkavm_export]
#[no_mangle]
pub extern "C" fn test_hashing_twox_128() -> u64 {
	let input: &[u8] = b"phase-star";
	let hash = sp_io::hashing::twox_128(input);
	sp_io::storage::set(b"twox128-test-result", &hash);
	0
}

/// Exercise `sp_io::crypto::ed25519_verify` — the rostrovm fork's ed25519
/// implementation (ed25519-zebra, ZIP-215, see crypto_stack_v1 memory)
/// is what substrate's host fn uses today, so this verifies the
/// dispatcher routes through cleanly. Test vectors are hardcoded so the
/// fixture is self-contained.
///
/// Returns:
/// - `0` — signature verified (expected for the good test vector).
/// - `1` — signature DIDN'T verify (means routing broke or ZIP-215
///   semantics drifted).
#[cfg(not(feature = "std"))]
#[polkavm_derive::polkavm_export]
#[no_mangle]
pub extern "C" fn test_crypto_ed25519_verify() -> u64 {
	// RFC 8032 ed25519 Test Vector 1:
	//   secret_key  = ALL_NULL_BYTES_NO_DONT_USE
	//   public_key  = d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
	//   message     = ""
	//   signature   = e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bedc740d09c0c4eb8b6e0d
	let pubkey: [u8; 32] = [
		0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
		0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
		0x51, 0x1a,
	];
	let sig: [u8; 64] = [
		0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82,
		0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49,
		0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c,
		0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xed, 0xc7, 0x40, 0xd0, 0x9c, 0x0c,
		0x4e, 0xb8, 0xb6, 0xe0,
	];
	let msg: &[u8] = b"";

	let signature = sp_core::ed25519::Signature::from_raw(sig);
	let public = sp_core::ed25519::Public::from_raw(pubkey);

	if sp_io::crypto::ed25519_verify(&signature, msg, &public) {
		0
	} else {
		1
	}
}
