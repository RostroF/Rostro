// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Plonky3 STARK verifier for the personhood mint path. **Strictly siloed**
//! from the legacy arkworks `mod verifier` block in `lib.rs` per the
//! no-cross-purpose-files security principle (see
//! `feedback_no_cross_purpose_files.md`):
//!
//! - This module shares no traits, helpers, or constants with `mod verifier`
//! - Each circuit family has its own dedicated verify method (no shared
//!   dispatch surface, no enum-keyed switch)
//! - The arkworks impl will be **deleted** in the same commit that wires
//!   this verifier into `gemini-runtime`'s `Config::ProofVerifier` —
//!   single cutover, no production fallback path
//!
//! ## Three verify methods, one per circuit family
//!
//! Per `pop_design_section1b_chip_auth_methods.md`, the AA and CA paths
//! are independent circuits with independent VKs. Each has its own
//! method on this struct. The `liveness_facematch` path is also its own
//! method. The dispatch from `mint_pop` happens at the call site —
//! `mint_pop` knows from the `chip_auth_method: ChipAuthMethod` arg
//! which AA-or-CA verify to call. There is no "try both VKs" fallback
//! and no shared dispatch helper — the type system forces the caller
//! to pick the explicit method.
//!
//! ## Status
//!
//! **SCAFFOLD only.** Each method currently returns `Err(())`. The
//! `p3_uni_stark::verify` invocation, the VK byte format, and the
//! Goldilocks-limb encoding of `PassportPublicInputs` /
//! `LivenessPublicInputs` all land in follow-up commits alongside the
//! AIR constraint sets in `crate::airs::*`.

use crate::{LivenessPublicInputs, PassportPublicInputs};

/// Plonky3 STARK verifier for the personhood pallet's three circuit
/// families (passport_attest_aa, passport_attest_ca, liveness_facematch).
/// Stateless; no parameters.
pub struct Plonky3ProofVerifier;

impl Plonky3ProofVerifier {
	/// Verify a Plonky3 STARK proof for the **AA** chip-auth path with
	/// **RSA-2048 + SHA-256** chip-sig algorithm. First per-algorithm
	/// AA verifier method; siblings (`_ecdsa_p256_sha256`, `_brainpoolp256r1_sha256`,
	/// etc.) get their own dedicated methods as the AIRs land.
	///
	/// MUST NOT share any code path with the CA family or the other AA
	/// algorithm methods. The mint_pop dispatcher matches on
	/// `(chip_auth_method, sig_algorithm, hash_algorithm)` and calls the
	/// exact matching method here — explicit dispatch, no shared helpers.
	pub fn verify_passport_attest_aa_rsa2048_sha256<AccountId, BlockNumber>(
		_vk_bytes: &[u8],
		_proof_bytes: &[u8],
		_inputs: &PassportPublicInputs<AccountId, BlockNumber>,
	) -> Result<(), ()> {
		// TODO(PoP-Plonky3-AA-RSA2048): wire `p3_uni_stark::verify`
		// against `crate::airs::passport_attest_aa_rsa2048_sha256::PassportAttestAaRsa2048Sha256Air`
		// once the AIR's constraint set + Goldilocks public-input encoding
		// land. No fallback to arkworks — failure to verify rejects the mint.
		Err(())
	}

	/// Verify a Plonky3 STARK proof for the **CA** chip-auth path
	/// against the supplied verifying-key bytes and public inputs.
	///
	/// MUST NOT share any code path with the AA or facematch methods.
	pub fn verify_passport_attest_ca<AccountId, BlockNumber>(
		_vk_bytes: &[u8],
		_proof_bytes: &[u8],
		_inputs: &PassportPublicInputs<AccountId, BlockNumber>,
	) -> Result<(), ()> {
		// TODO(PoP-Plonky3): wire `p3_uni_stark::verify` against
		// `crate::airs::passport_attest_ca::PassportAttestCaAir`.
		Err(())
	}

	/// Verify a Plonky3 STARK proof for the **liveness + facematch**
	/// path against the supplied verifying-key bytes and public inputs.
	///
	/// MUST NOT share any code path with the AA or CA methods.
	pub fn verify_liveness_facematch<AccountId, BlockNumber>(
		_vk_bytes: &[u8],
		_proof_bytes: &[u8],
		_inputs: &LivenessPublicInputs<AccountId, BlockNumber>,
	) -> Result<(), ()> {
		// TODO(PoP-Plonky3): wire `p3_uni_stark::verify` against
		// `crate::airs::liveness_facematch::LivenessFacematchAir`.
		Err(())
	}
}
