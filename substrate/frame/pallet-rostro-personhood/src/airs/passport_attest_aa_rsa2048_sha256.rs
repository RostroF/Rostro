// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! `passport_attest_aa_rsa2048_sha256` AIR — verifies the **Active
//! Authentication** path of an ICAO 9303 passport whose chip-auth key is
//! **RSA-2048** with **SHA-256** as the message hash.
//!
//! First per-algorithm AIR file in the AA family. The full algorithm
//! coverage matrix (~76 combinations per AA/CA family) mirrors
//! zkpassport's production circuit-manifest — see
//! `pop_algorithm_coverage_zkpassport_mirror.md` for the locked set
//! and the order of authoring (RSA-2048-SHA256 first for US/UK, then
//! NIST-P256, then Brainpool for EU).
//!
//! Per `feedback_no_cross_purpose_files.md`, each algorithm in the matrix
//! gets its own AIR file with its own duplicated constraints. A bug in
//! one algorithm's eval cannot influence another's verification dispatch
//! because they share no code — only the public-input column constants
//! (which are pure deterministic data with no security boundary).
//!
//! ## RSA-2048 + SHA-256 chip-sig verification (what this AIR proves)
//!
//! The chip computed: `aa_signature = RSA_sign(aa_challenge, chip_priv_key)`
//! where:
//! - `aa_challenge` is the chain-anchored challenge bytes the pallet
//!   hashed via SHA-256 of `(AA_CHALLENGE_DOMAIN ‖ anchor.hash ‖ bound_account)`
//! - The signing recipe per ICAO 9303 Part 11 + RSASSA-PKCS1-v1_5:
//!   1. Compute `m = SHA-256(aa_challenge)` → 32-byte digest
//!   2. PKCS#1 v1.5-pad: `EM = 0x00 || 0x01 || PS || 0x00 || DigestInfo(m)`
//!      (PS = ones-padding to fill 256 bytes; DigestInfo = ASN.1 wrapper
//!      identifying SHA-256 + the 32-byte digest)
//!   3. Encode EM as integer, raise to private exponent mod N → signature
//! - Verifier reverses: `s^e mod N == EM` (where `e = 65537` typically)
//!
//! What this AIR enforces:
//! 1. `s^65537 mod N == EM` (modular exponentiation — the heavy lift)
//! 2. EM has the exact PKCS#1 v1.5 structure (no padding-oracle attack
//!    surface — the structure is checked, not unmarshalled)
//! 3. `EM`'s embedded digest equals SHA-256 of the witnessed `aa_challenge`
//! 4. `aa_challenge` matches the public-input-derived value the pallet
//!    asserts equality with downstream
//!
//! Witnesses (chip-auth-specific):
//! - RSA modulus `N` (2048 bits, witnessed from DG15 — chip's pubkey)
//! - RSA public exponent `e` (typically 65537, fits in 1 limb)
//! - AA signature `s` (2048 bits, chip's signature output)
//! - Decoded message `EM = s^e mod N` (intermediate, 2048 bits)
//! - SHA-256 digest of aa_challenge (32 bytes)
//! - Plus modular-exp intermediate values (TBD when modexp constraint
//!   set lands — likely 100s more columns for binary-exponentiation
//!   square-and-multiply intermediate states)
//!
//! ## Status (2026-05-10)
//!
//! - **Inlined Poseidon2 perm columns stripped** (was ~2480 cols across
//!   6 MRZ + 4 DG2 absorbs). Both Poseidon2 hashes now consumed via
//!   cross-AIR lookup buses backed by `rostro-poseidon-air`. NUM_COLS
//!   dropped 2787 → 307 (~89% reduction).
//! - **PI column layout + limb encoders + outer RSA witness block locked.**
//!   307 cols = 76 PI + 64 modulus + 1 exponent + 64 sig + 64 EM + 22
//!   canonical MRZ + 8 dg2_hash + 8 dg2_salt.
//! - **First concrete constraints:** `assert_bool(adult)`, RSA exponent
//!   pinned to 65537, full PKCS#1 v1.5 EM padding structure check, and
//!   the digest-binding equality EM[224..256] == COL_SHA256_DIGEST_OF_CHALLENGE.
//! - **TODO (phase 3b):** push bus interactions for the 6 MRZ-commitment
//!   + 4 DG2-commitment absorbs (10 absorb pairs total). Each absorb
//!   sends pre_state⊕rate_chunk to its input bus and receives post_state
//!   from its output bus; the hash AIR composition runs in the same
//!   batch and balances each bus.
//! - **TODO (phase 3c):** RSA modular exponentiation `s^e mod N == EM`
//!   (the heavy lift), DG15 inclusion in SOD, DSC chain → CSCA membership
//!   merkle proof, u16 range checks on every u32 limb via rostro-range-check.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};

// ─── Public input column layout (shared shape across all AA algorithms) ────
//
// Each `[u8; 32]` field is packed as 8 × u32 big-endian limbs. The
// Goldilocks prime is `2^64 - 2^32 + 1`, so a u32 fits safely in one
// element with no risk of wraparound.
//
// Column order matches `crate::PassportPublicInputs<AccountId, BlockNumber>`
// declaration order. The on-chain pallet's eventual
// `passport_public_inputs(...)` Goldilocks encoder MUST emit values in
// exactly this order.

/// Number of u32 limbs per 32-byte hash / AccountId field.
pub const HASH_LIMBS: usize = 8;

// Public-input layout (2026-05-10 redesign post-revert of phase 3b).
// Mirrors zkpassport's disclosure-circuit PI shape: `comm_in` is the
// salted-commitment chain anchor binding to private witnesses across
// subproofs; `scoped_nullifier` is the OPRF-protected nullifier the
// chain dedups against; `nullifier_type` discriminates production-OPRF
// vs fallback / mock variants; `oprf_pk_hash` commits to the federation
// pubkey used. NO MRZ commitment, NO DG2 commitment — both replaced by
// the salted-comm_in chain since both prior values were government-
// recomputable from passport data alone (the locked OPRF design hides
// the input under threshold-shared K, but only if no government-
// computable function of the input touches the chain). See
// `pop_zkpassport_oprf_pattern.md` for the threat-model reasoning.
//
// Field order MUST match `crate::PassportPublicInputs` declaration order.
// The on-chain pallet's `passport_public_inputs(...)` Goldilocks encoder
// emits values in exactly this order; mismatched ordering would silently
// validate against the wrong fields.

/// Starting column of the salted-commitment chain anchor `comm_in`
/// (8 limbs follow). The AIR computes `comm_in = Poseidon2(salted_dg1,
/// salted_expiry, salted_dg2_hash, salted_dg2_hash_type,
/// salted_private_nullifier)` over private witnesses; this PI exposes
/// the commitment for cross-proof binding with `liveness_facematch`.
pub const COL_COMM_IN: usize = 0;
/// Starting column of the OPRF-protected `scoped_nullifier`
/// (8 limbs follow). The AIR computes `scoped_nullifier =
/// Poseidon2(salted_private_nullifier.value, service_scope,
/// service_subscope, nullifier_secret)` where `nullifier_secret =
/// verified_oprf(...)`. Pallet stores this in [`Nullifiers`]; second
/// mint with the same value rejected.
pub const COL_SCOPED_NULLIFIER: usize = 8;
/// Column index of `nullifier_type` (single limb; encodes the
/// `crate::NullifierType` enum: 0=Salted, 1=NonSalted, 2=SaltedMock,
/// 3=NonSaltedMock). Mainnet runtimes reject NonSalted + Mock variants;
/// testnet (Camino) accepts the mock variants.
pub const COL_NULLIFIER_TYPE: usize = 16;
/// Starting column of `oprf_pk_hash` (8 limbs follow). Poseidon2 hash
/// of the federation pubkey point used in `verified_oprf`. Pallet
/// matches against the current federation pubkey hash (storage TBD)
/// and rejects proofs against a stale federation.
pub const COL_OPRF_PK_HASH: usize = 17;
/// Starting column of the `bound_account` field (8 limbs follow).
pub const COL_BOUND_ACCOUNT: usize = 25;
/// Column index of `adult` (single limb, must be 0 or 1).
pub const COL_ADULT: usize = 33;
/// Column index of `seat_id` (single u16 limb).
pub const COL_SEAT_ID: usize = 34;
/// Column index of `anchor.block` (single u32 limb).
pub const COL_ANCHOR_BLOCK: usize = 35;
/// Starting column of the `anchor.hash` field (8 limbs follow).
pub const COL_ANCHOR_HASH: usize = 36;
/// Starting column of the `csca_root` field (8 limbs follow).
pub const COL_CSCA_ROOT: usize = 44;
/// Starting column of the `seats_root` field (8 limbs follow).
pub const COL_SEATS_ROOT: usize = 52;
/// Starting column of the `aa_challenge` PI field (8 limbs follow).
///
/// **Pallet-derived, not prover-supplied.** The pallet computes
/// `aa_challenge = SHA-256(AA_CHALLENGE_DOMAIN ‖ anchor.hash ‖
/// bound_account.encode())` from chain-anchored values and passes the
/// result into the verifier as an explicit parameter; the verifier
/// places it in this PI column. The AIR uses it as the message that
/// the chip's RSA signature is verified against. (HIP nonce derivation
/// in `hip_challenge_nonce` uses the same shape with a different
/// domain constant so the two subsystems' challenges cannot be
/// cross-replayed.)
///
/// This split (pallet derives, AIR consumes via column equality)
/// avoids needing SHA-256-in-AIR as a precondition for the
/// AA-challenge ↔ chip-sig binding to work. SHA-256-in-AIR lands
/// later when DG-list inclusion in SOD requires it; until then this
/// pattern lets the chip-sig verification proceed without depending on
/// it.
pub const COL_AA_CHALLENGE: usize = 60;
/// Number of u32 limbs in the AA challenge (32 bytes / 4 = 8).
pub const AA_CHALLENGE_LIMBS: usize = HASH_LIMBS;
/// Starting column of the SHA-256 digest of `aa_challenge` (8 limbs follow).
///
/// **Pallet-derived, not prover-supplied.** Same play as the AA
/// challenge: the pallet computes `SHA-256(aa_challenge)` and forwards
/// the result to the verifier as an explicit parameter; the AIR's
/// existing PKCS#1 v1.5 constraint binds `EM[224..256]` to this PI
/// column. Together, the chain of bindings is:
///
///   pallet computes aa_challenge from anchor + bound_account → PI
///   pallet computes SHA-256(aa_challenge) → PI
///   AIR constrains EM digest bytes equal this PI
///   AIR constrains chip's RSA signature decodes to EM (modexp TODO)
///
/// Net: no SHA-256-in-AIR primitive needed for the chip-sig binding —
/// pallet does the SHA-256 (cheap on chain), AIR does column equality.
/// SHA-256-in-AIR still needed for DG-list inclusion in SOD; that's
/// a separate primitive landing later.
pub const COL_SHA256_DIGEST_OF_CHALLENGE: usize = COL_AA_CHALLENGE + AA_CHALLENGE_LIMBS;
/// Number of u32 limbs in a SHA-256 digest (32 bytes).
pub const SHA256_DIGEST_LIMBS: usize = HASH_LIMBS;
/// Total public-input columns (76 = 8+8+1+8+8+1+1+1+8+8+8+8+8).
pub const NUM_PI_COLS: usize = 76;

// ─── RSA-2048 + SHA-256 chip-sig witness columns ───────────────────────────
//
// 2048-bit values pack as 64 × u32 big-endian limbs. The modular
// exponentiation that proves `s^e mod N == EM` will need many MORE
// intermediate witness columns (binary square-and-multiply state per
// bit of the exponent, modular-reduction quotients, etc.) — those land
// when the constraint set is authored.

/// Number of u32 limbs in a 2048-bit RSA value.
pub const RSA2048_LIMBS: usize = 64;

/// Canonical RSA public exponent for ICAO chip-auth keys: Fermat prime
/// F_4 = 2^16 + 1 = 65537. The eval() body constrains the witnessed
/// `COL_RSA_EXPONENT_E` to this exact value. Other exponents (e=3,
/// e=17, etc.) are out of scope for this AIR variant; chips using them
/// would dispatch to a different AIR.
pub const RSA_PUBLIC_EXPONENT: u32 = 65537;

/// Starting column of the witnessed RSA modulus `N` (64 u32 limbs).
/// Extracted by dotwave from DG15; not a public input because the chip's
/// public key isn't part of the on-chain trust anchor — what's anchored
/// is the CSCA → DSC → SOD → DG15 chain, which the AIR must prove
/// elsewhere.
pub const COL_RSA_MODULUS_N: usize = NUM_PI_COLS;

/// Column index of the RSA public exponent `e` (single limb; canonically 65537).
pub const COL_RSA_EXPONENT_E: usize = COL_RSA_MODULUS_N + RSA2048_LIMBS;

/// Starting column of the witnessed AA signature `s` (64 u32 limbs).
pub const COL_RSA_SIGNATURE_S: usize = COL_RSA_EXPONENT_E + 1;

/// Starting column of the intermediate decoded-message `EM = s^e mod N`
/// (64 u32 limbs). Witnessed by the prover for efficiency; constrained
/// equal to the modular-exp result by the modexp subcircuit.
pub const COL_RSA_DECODED_EM: usize = COL_RSA_SIGNATURE_S + RSA2048_LIMBS;

// COL_SHA256_DIGEST_OF_CHALLENGE + SHA256_DIGEST_LIMBS were promoted
// to the PI block on 2026-05-09 (see top-of-file PI section). The
// witness section currently stops here at COL_RSA_DECODED_EM +
// RSA2048_LIMBS.
//
// **Removed 2026-05-10:** the canonical_mrz / dg2_hash / dg2_salt
// witness columns and their associated *_COMMIT_DOMAIN_CAPACITY_*
// constants and POSEIDON2_NUM_*_PERMS counters. Those were scaffolding
// for the wrong OPRF flow (Poseidon2(MRZ) → mrz_commitment as a PI;
// see `pop_zkpassport_oprf_pattern.md` for why that breaks the threat
// model). The correct OPRF flow witnesses DG1, eContent, sod_sig, and
// salts privately and computes `private_nullifier` + `comm_in` +
// `scoped_nullifier` per the zkpassport pattern. Those witness columns
// land when Ristretto255-over-Goldilocks curve primitives are scaffolded
// (see `pop_lookup_integration_next_work.md` for the unblocking work).

/// Total trace columns for this AIR. Phase 3a-stripped + 2026-05-10 PI
/// redesign baseline. Includes: PI block (76 cols), RSA witness block
/// (modulus + exponent + signature + EM = 193 cols).
///
/// Grows when (a) Ristretto255 curve-arithmetic AIR primitives land and
/// witness columns for DG1 / eContent / sod_sig / salts / OPRF artifacts
/// are added; (b) modular exponentiation `s^65537 mod N == EM` constraint
/// set lands with its square-and-multiply intermediate witness columns;
/// (c) DG-list inclusion in SOD lands.
pub const NUM_COLS: usize = COL_RSA_DECODED_EM + RSA2048_LIMBS;

// ─── Limb-encoding helpers (siloed to this AIR) ────────────────────────────
//
// Per the no-cross-purpose-files rule, byte→limb conversion is duplicated
// per algorithm AIR rather than extracted to a shared module. Pure
// deterministic functions; duplication's risk is "two copies drift over
// time" — accepted in exchange for guaranteed independence across
// algorithm variants.

/// Pack a 32-byte field as 8 big-endian u32 limbs.
#[inline]
pub fn bytes_to_u32_limbs(bytes: &[u8; 32]) -> [u32; HASH_LIMBS] {
	let mut out = [0u32; HASH_LIMBS];
	for (i, chunk) in bytes.chunks_exact(4).enumerate() {
		out[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
	}
	out
}

/// Inverse of [`bytes_to_u32_limbs`] — reconstruct 32 bytes from 8 BE limbs.
#[inline]
pub fn u32_limbs_to_bytes(limbs: &[u32; HASH_LIMBS]) -> [u8; 32] {
	let mut out = [0u8; 32];
	for (i, limb) in limbs.iter().enumerate() {
		let bytes = limb.to_be_bytes();
		out[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
	}
	out
}

/// Pack a 256-byte (2048-bit) RSA value as 64 big-endian u32 limbs.
#[inline]
pub fn rsa2048_bytes_to_u32_limbs(bytes: &[u8; 256]) -> [u32; RSA2048_LIMBS] {
	let mut out = [0u32; RSA2048_LIMBS];
	for (i, chunk) in bytes.chunks_exact(4).enumerate() {
		out[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
	}
	out
}

/// Inverse of [`rsa2048_bytes_to_u32_limbs`].
#[inline]
pub fn rsa2048_u32_limbs_to_bytes(limbs: &[u32; RSA2048_LIMBS]) -> [u8; 256] {
	let mut out = [0u8; 256];
	for (i, limb) in limbs.iter().enumerate() {
		let bytes = limb.to_be_bytes();
		out[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
	}
	out
}

/// AIR for the AA passport-attestation path with RSA-2048 chip key + SHA-256
/// message hash. Stateless; no parameters.
pub struct PassportAttestAaRsa2048Sha256Air;

impl<F: Field> BaseAir<F> for PassportAttestAaRsa2048Sha256Air {
	fn width(&self) -> usize {
		NUM_COLS
	}
}

impl<AB: AirBuilder> Air<AB> for PassportAttestAaRsa2048Sha256Air
where
	AB::F: Field,
{
	fn eval(&self, builder: &mut AB) {
		let main = builder.main();
		let local = main.current_slice();

		// First real constraint: `adult` is boolean — must be 0 or 1.
		// Structural decomposition validity for the `adult: bool` field
		// of `PassportPublicInputs`. Without it, the prover could supply
		// a non-boolean Goldilocks value and bypass downstream pallet
		// adult-gate logic.
		//
		// Per silo rule: this same constraint will be duplicated in every
		// per-algorithm AA AIR. Acceptable cost.
		builder.assert_bool(local[COL_ADULT].clone());

		// ─── PKCS#1 v1.5 padding structure check on EM ─────────────────
		//
		// EM = 0x00 ‖ 0x01 ‖ (0xFF × 202) ‖ 0x00 ‖ DigestInfo ‖ H
		// where DigestInfo is the DER-encoded ASN.1 SEQUENCE wrapping the
		// SHA-256 OID + a 32-byte digest field.
		//
		// Layout in the 64-limb (256-byte) EM column block (BE u32 limbs):
		//   limb[0]      = 0x0001_FFFF       (header + first 2 padding bytes)
		//   limb[1..51]  = 0xFFFF_FFFF       (50 limbs = 200 bytes of 0xFF)
		//   limb[51]     = 0x0030_3130       (separator + DigestInfo[0..3])
		//   limb[52]     = 0x0d06_0960       (DigestInfo[3..7])
		//   limb[53]     = 0x8648_0165       (DigestInfo[7..11])
		//   limb[54]     = 0x0304_0201       (DigestInfo[11..15])
		//   limb[55]     = 0x0500_0420       (DigestInfo[15..19])
		//   limb[56..64] = SHA-256 digest    (must equal witnessed digest)
		//
		// These are byte-equality assertions to fixed constants — no
		// parsing, no padding-oracle attack surface. The
		// `pkcs1_v15_sha256_padding_constants_match_reference` test
		// verifies these constants against a generative encoder.

		// Header + leading 2 padding bytes.
		builder.assert_eq(
			local[COL_RSA_DECODED_EM].clone(),
			AB::Expr::from_u32(0x0001_FFFFu32),
		);

		// 50 limbs of all-FF padding (limbs 1 through 50 inclusive).
		for i in 1..51 {
			builder.assert_eq(
				local[COL_RSA_DECODED_EM + i].clone(),
				AB::Expr::from_u32(0xFFFF_FFFFu32),
			);
		}

		// Separator + DigestInfo first 3 bytes (SEQUENCE header).
		builder.assert_eq(
			local[COL_RSA_DECODED_EM + 51].clone(),
			AB::Expr::from_u32(0x0030_3130u32),
		);

		// Remaining 16 bytes of DigestInfo (the SHA-256 algorithm OID
		// + NULL params + OCTET STRING tag + length).
		builder.assert_eq(
			local[COL_RSA_DECODED_EM + 52].clone(),
			AB::Expr::from_u32(0x0d06_0960u32),
		);
		builder.assert_eq(
			local[COL_RSA_DECODED_EM + 53].clone(),
			AB::Expr::from_u32(0x8648_0165u32),
		);
		builder.assert_eq(
			local[COL_RSA_DECODED_EM + 54].clone(),
			AB::Expr::from_u32(0x0304_0201u32),
		);
		builder.assert_eq(
			local[COL_RSA_DECODED_EM + 55].clone(),
			AB::Expr::from_u32(0x0500_0420u32),
		);

		// Digest binding: the trailing 32 bytes of EM (limbs 56..64) must
		// equal the witnessed SHA-256 digest of `aa_challenge`. This is
		// the constraint that ties the chip's RSA-signed bytes back to
		// the chain-anchored challenge — without it, a prover could
		// supply any well-padded EM and any hash and the AIR would accept.
		for i in 0..SHA256_DIGEST_LIMBS {
			builder.assert_eq(
				local[COL_RSA_DECODED_EM + 56 + i].clone(),
				local[COL_SHA256_DIGEST_OF_CHALLENGE + i].clone(),
			);
		}

		// RSA public exponent: this AIR variant constrains `e == 65537`
		// (Fermat prime F_4 = 2^16 + 1). This is the de facto standard
		// for ICAO RSA passports and essentially every real chip in
		// circulation uses it. Constraining here lets the future modexp
		// subcircuit specialize for a fixed exponent (16 squarings + 1
		// multiplication) rather than handle variable-length exponents.
		// Chips using other exponents (e.g., e=3 or e=17 — rare in the
		// passport space) would require a separate AIR variant.
		builder.assert_eq(
			local[COL_RSA_EXPONENT_E].clone(),
			AB::Expr::from_u32(RSA_PUBLIC_EXPONENT),
		);

		// TODO(PoP-AA-RSA2048): u32 limb range checks for every prover-
		// controlled u32 column (RSA modulus + signature + canonical_mrz
		// + Poseidon2 round states + future SHA-256 / modexp intermediates).
		// **DEFERRED to v1** per `pop_air_range_check_strategy.md` —
		// requires PermutationAirBuilder + lookup-argument integration,
		// significant infrastructure beyond basic AirBuilder. NO STUB
		// HELPERS allowed (silent no-ops are an audit footgun). Mainnet
		// release gate: range checks landed + audited.

		// TODO(PoP-AA-RSA2048): modular exponentiation `s^e mod N == EM`.
		// THIS IS THE BIG ONE. Implementation pattern: binary
		// square-and-multiply over the bits of `e`, with each iteration
		// constrained as `(acc^2 mod N) [* s mod N if bit_set]`. Each
		// modular operation needs witnessed quotient + range checks.
		// Goldilocks-limb modular arithmetic for a 2048-bit modulus
		// requires ~64 limbs per operand; one modular multiply expands
		// to 1000s of constraints. Total constraint count for full RSA
		// verify likely 100K-1M. This is the largest unit of work in
		// the AIR and the largest source of proving time + memory cost.

		// TODO(PoP-AA-RSA2048): PKCS#1 v1.5 structure check on `EM`.
		// Layout: 0x00 || 0x01 || (0xFF * (256 - 32 - 19 - 3)) || 0x00 ||
		// DigestInfo(SHA-256) || digest. Constrain the byte positions
		// directly — no parsing, just byte-equality assertions to fixed
		// constants. Closes the padding-oracle attack surface.

		// SOLVED via pallet-side cross-check 2026-05-09: the
		// `digest == SHA-256(aa_challenge_bytes)` binding lives in the
		// pallet, NOT in the AIR. Both `COL_AA_CHALLENGE` and
		// `COL_SHA256_DIGEST_OF_CHALLENGE` are now PI columns; the pallet
		// computes `expected_digest = SHA-256(aa_challenge_pi_bytes)` and
		// asserts equality with `COL_SHA256_DIGEST_OF_CHALLENGE` PI.
		// AIR's PKCS#1 constraint above already ties EM[224..256] to that
		// PI digest. SHA-256-in-AIR still needed for DG-list inclusion in
		// SOD; no longer a precondition for the chip-sig binding.

		// TODO(PoP-AA-RSA2048, phase 3b): mrz_commitment ==
		// Poseidon2(canonical_mrz, ROSTRO_MRZ_COMMIT_DOMAIN-via-capacity).
		// Hash primitive lives in `rostro-poseidon-air`, consumed via
		// cross-AIR lookup buses.
		//
		// Per absorb i (POSEIDON2_NUM_MRZ_PERMS = 6 total):
		//   1. Form bus-input message = state[i-1][0..4] + rate_chunk_i,
		//      state[i-1][4..8]  (8 cells; 4 rate + 4 capacity).
		//   2. Send to per-absorb input bus with multiplicity = 1.
		//   3. Receive post_state from per-absorb output bus, multiplicity
		//      -1; store as state[i].
		//
		// state[0]'s capacity half = MRZ_COMMIT_DOMAIN_CAPACITY_LIMBS,
		// rate half = 0. state[6] is the squeezed hash output; constrain
		// state[6][0..8] == local[COL_MRZ_COMMITMENT..COL_MRZ_COMMITMENT + 8].
		//
		// Plus: u16 range checks on every u32 limb of canonical_mrz +
		// state vectors via the rostro-range-check bus. See
		// pop_lookup_integration_next_work.md for the harness composition.

		// TODO(PoP-AA-RSA2048): DG15 inclusion in SOD. Hash witnessed
		// DG15 bytes, prove the hash appears in the SOD's DG hash list
		// (linear search pattern from zkpassport's
		// `lib/data-check/integrity/src/lib.nr`).

		// TODO(PoP-AA-RSA2048): DSC chain → CSCA membership in
		// `csca_root` merkle tree. Witness the merkle path; constrain
		// hash composition matches public-input csca_root.
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn limb_round_trip_preserves_bytes_32() {
		let mut bytes = [0u8; 32];
		for i in 0..32 {
			bytes[i] = (i as u8).wrapping_mul(7).wrapping_add(13);
		}
		let limbs = bytes_to_u32_limbs(&bytes);
		let recovered = u32_limbs_to_bytes(&limbs);
		assert_eq!(bytes, recovered);
	}

	#[test]
	fn limb_round_trip_preserves_bytes_256() {
		let mut bytes = [0u8; 256];
		for i in 0..256 {
			bytes[i] = (i as u8).wrapping_mul(11).wrapping_add(7);
		}
		let limbs = rsa2048_bytes_to_u32_limbs(&bytes);
		let recovered = rsa2048_u32_limbs_to_bytes(&limbs);
		assert_eq!(bytes, recovered);
	}

	#[test]
	fn first_limb_is_first_four_bytes_big_endian() {
		let mut bytes = [0u8; 32];
		bytes[0] = 0x12;
		bytes[1] = 0x34;
		bytes[2] = 0x56;
		bytes[3] = 0x78;
		let limbs = bytes_to_u32_limbs(&bytes);
		assert_eq!(limbs[0], 0x12345678);
	}

	#[test]
	fn pi_column_layout_matches_field_declaration_order() {
		// PI layout (2026-05-10 redesign post-revert of phase 3b) — mirrors
		// the field order in `crate::PassportPublicInputs`:
		// comm_in(8) || scoped_nullifier(8) || nullifier_type(1) ||
		// oprf_pk_hash(8) || bound_account(8) || adult(1) || seat_id(1) ||
		// anchor.block(1) || anchor.hash(8) || csca_root(8) || seats_root(8) ||
		// aa_challenge(8) || sha256_digest_of_challenge(8)
		assert_eq!(COL_COMM_IN, 0);
		assert_eq!(COL_SCOPED_NULLIFIER, COL_COMM_IN + HASH_LIMBS);
		assert_eq!(COL_NULLIFIER_TYPE, COL_SCOPED_NULLIFIER + HASH_LIMBS);
		assert_eq!(COL_OPRF_PK_HASH, COL_NULLIFIER_TYPE + 1);
		assert_eq!(COL_BOUND_ACCOUNT, COL_OPRF_PK_HASH + HASH_LIMBS);
		assert_eq!(COL_ADULT, COL_BOUND_ACCOUNT + HASH_LIMBS);
		assert_eq!(COL_SEAT_ID, COL_ADULT + 1);
		assert_eq!(COL_ANCHOR_BLOCK, COL_SEAT_ID + 1);
		assert_eq!(COL_ANCHOR_HASH, COL_ANCHOR_BLOCK + 1);
		assert_eq!(COL_CSCA_ROOT, COL_ANCHOR_HASH + HASH_LIMBS);
		assert_eq!(COL_SEATS_ROOT, COL_CSCA_ROOT + HASH_LIMBS);
		assert_eq!(COL_AA_CHALLENGE, COL_SEATS_ROOT + HASH_LIMBS);
		assert_eq!(
			COL_SHA256_DIGEST_OF_CHALLENGE,
			COL_AA_CHALLENGE + AA_CHALLENGE_LIMBS,
		);
		assert_eq!(
			NUM_PI_COLS,
			COL_SHA256_DIGEST_OF_CHALLENGE + SHA256_DIGEST_LIMBS,
		);
		// Sanity total: 8+8+1+8+8+1+1+1+8+8+8+8+8 = 76.
		assert_eq!(NUM_PI_COLS, 76);
	}

	/// Build the canonical PKCS#1 v1.5 EM block (256 bytes) for
	/// RSASSA-PKCS1-v1_5-SIGN with SHA-256, given a 32-byte digest.
	/// Reference encoder per RFC 8017 § 9.2 — used only by tests to
	/// pin the AIR's hardcoded constraint constants against a generative
	/// implementation. NOT used in production AIR paths.
	fn build_canonical_pkcs1_v15_sha256_em(digest: &[u8; 32]) -> [u8; 256] {
		// PKCS#1 v1.5 DigestInfo for SHA-256 (RFC 8017 § 9.2 step 2 + § B.1):
		// ASN.1 SEQUENCE { SEQUENCE { OID(2.16.840.1.101.3.4.2.1), NULL }, OCTET STRING (32 bytes) }
		// DER-encoded prefix (without the digest itself) is exactly 19 bytes.
		const DIGEST_INFO_PREFIX: [u8; 19] = [
			0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
			0x01, 0x05, 0x00, 0x04, 0x20,
		];

		let mut em = [0u8; 256];
		em[0] = 0x00;
		em[1] = 0x01;
		// Padding string: 0xFF until the 0x00 separator. Trailing structure
		// is 1 separator + 19 DigestInfo + 32 digest = 52 bytes; padding
		// fills the rest.
		let padding_end = 256 - 52; // = 204
		for byte in em.iter_mut().take(padding_end).skip(2) {
			*byte = 0xFF;
		}
		em[padding_end] = 0x00;
		em[padding_end + 1..padding_end + 1 + 19].copy_from_slice(&DIGEST_INFO_PREFIX);
		em[padding_end + 1 + 19..].copy_from_slice(digest);
		em
	}

	#[test]
	fn pkcs1_v15_sha256_padding_constants_match_reference_encoder() {
		// Pin the AIR's hardcoded PKCS#1 v1.5 limb constants against a
		// from-spec generative encoder. If anyone edits the constraint
		// constants in eval(), this test fails and tells them which
		// limb diverged. If anyone changes the EM layout assumption
		// (e.g., wrong DigestInfo OID, wrong padding length), this also
		// fails. Catches both directions of drift.
		let digest = [0xCDu8; 32];
		let em = build_canonical_pkcs1_v15_sha256_em(&digest);
		let limbs = rsa2048_bytes_to_u32_limbs(&em);

		// Header + leading 2 padding bytes (matches eval() constraint).
		assert_eq!(limbs[0], 0x0001_FFFF, "limb[0] header constant drift");

		// 50 limbs of all-FF padding.
		for i in 1..51 {
			assert_eq!(limbs[i], 0xFFFF_FFFF, "limb[{}] padding constant drift", i);
		}

		// Separator + DigestInfo header.
		assert_eq!(limbs[51], 0x0030_3130, "limb[51] separator+DigestInfo drift");
		assert_eq!(limbs[52], 0x0d06_0960, "limb[52] DigestInfo drift");
		assert_eq!(limbs[53], 0x8648_0165, "limb[53] DigestInfo drift");
		assert_eq!(limbs[54], 0x0304_0201, "limb[54] DigestInfo drift");
		assert_eq!(limbs[55], 0x0500_0420, "limb[55] DigestInfo drift");

		// Digest occupies the trailing 32 bytes / 8 limbs.
		let digest_limbs = bytes_to_u32_limbs(&digest);
		for i in 0..SHA256_DIGEST_LIMBS {
			assert_eq!(
				limbs[56 + i],
				digest_limbs[i],
				"limb[{}] digest binding drift",
				56 + i,
			);
		}
	}

	#[test]
	fn pkcs1_v15_em_total_size_is_2048_bits() {
		// Defense against accidentally constructing a 1024-bit or 4096-bit
		// EM in the reference encoder — would silently invalidate every
		// constraint check above.
		let em = build_canonical_pkcs1_v15_sha256_em(&[0u8; 32]);
		assert_eq!(em.len(), 256);
		assert_eq!(em.len() * 8, 2048);
	}

	#[test]
	fn rsa_public_exponent_is_fermat_prime_f4() {
		// Pin the canonical e value. If anyone changes it, the modexp
		// subcircuit (when authored) will be specialized for the wrong
		// exponent and silently accept the wrong signatures. Catch the
		// drift here.
		assert_eq!(RSA_PUBLIC_EXPONENT, 65537);
		assert_eq!(RSA_PUBLIC_EXPONENT, (1u32 << 16) + 1, "e must equal 2^16 + 1");
	}

	#[test]
	fn rsa2048_witness_layout_is_contiguous() {
		// Pin the witness column ordering. Layout (post 2026-05-10
		// redesign): PI block (76) → RSA modulus → exponent → signature
		// → decoded EM. The MRZ / DG2 / OPRF / sponge witness columns
		// land later when Ristretto255-over-Goldilocks curve primitives
		// are scaffolded. NUM_COLS will grow at that point.
		assert_eq!(COL_RSA_MODULUS_N, NUM_PI_COLS);
		assert_eq!(COL_RSA_EXPONENT_E, COL_RSA_MODULUS_N + RSA2048_LIMBS);
		assert_eq!(COL_RSA_SIGNATURE_S, COL_RSA_EXPONENT_E + 1);
		assert_eq!(COL_RSA_DECODED_EM, COL_RSA_SIGNATURE_S + RSA2048_LIMBS);
		assert_eq!(NUM_COLS, COL_RSA_DECODED_EM + RSA2048_LIMBS);
		// Breakdown: 76 PI + 64 modulus + 1 exponent + 64 sig + 64 EM = 269 cols.
		assert_eq!(NUM_COLS, 269);
	}
}
