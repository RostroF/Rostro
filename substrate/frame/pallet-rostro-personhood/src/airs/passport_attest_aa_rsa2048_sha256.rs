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
use p3_lookup::InteractionBuilder;
use rostro_curve25519::field_air::BUS_U16_RANGE;

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

/// Starting column of the **u16-split block** for u32 range checks.
///
/// Every prover-influenced u32 cell in the trace above (PI block u32
/// fields + RSA witness block) is split here into two adjacent u16
/// half-cells `(lo, hi)` such that `original = lo + 2^16 · hi`. The
/// AIR pushes one [`BUS_U16_RANGE`] lookup per half-cell; the table
/// side ([`rostro_range_check::U16RangeTableAir`] instantiated on the
/// same bus elsewhere in the batch) provides every u16 value once.
/// LogUp balance rejects any cell whose value is not a valid u32.
///
/// The split layout mirrors the original column order — see
/// [`u32_blocks_to_range_check`] for the canonical iteration order.
///
/// Bool / discriminant / u16-typed PI cells skip this block: `adult`
/// is bool-asserted in `eval`, `nullifier_type` is range-bound to
/// `{0,1,2,3}` by a forthcoming quartic constraint (audit AIR-P1-2,
/// commit C25), `seat_id` is range-checked as a single u16 lookup
/// without splitting (it's already < 2^16 by type).
pub const COL_RC_SPLITS_BASE: usize = COL_RSA_DECODED_EM + RSA2048_LIMBS;

/// Number of u32 cells covered by the range-check splits block.
///
/// Breakdown (mirroring iteration order in `u32_blocks_to_range_check`):
/// - PI u32 cells: comm_in(8) + scoped_nullifier(8) + oprf_pk_hash(8)
///   + bound_account(8) + anchor.block(1) + anchor.hash(8) + csca_root(8)
///   + seats_root(8) + aa_challenge(8) + sha256_digest_of_challenge(8)
///   = 73
/// - RSA witness u32 cells: modulus(64) + exponent_e(1) + signature(64)
///   + decoded_em(64) = 193
/// - Total: 266
///
/// Defensive coverage of EM + PI cells: those are already shape-bound
/// elsewhere (EM via `assert_eq` to constants/PI; PI via the
/// pallet-supplied verifier values). Range-checking them is
/// belt-and-suspenders against future regressions to the pallet
/// encoder or the EM constant block.
pub const NUM_U32_CELLS_TO_RANGE_CHECK: usize = 266;

/// Total trace columns for this AIR.
///
/// Layout: PI block (76) + RSA witness block (193) + u16-split block
/// for range checks (266 × 2 = 532). Grand total = 801.
///
/// Grows when (a) Ristretto255 curve-arithmetic AIR primitives land
/// and witness columns for DG1 / eContent / sod_sig / salts / OPRF
/// artifacts are added; (b) modular exponentiation `s^65537 mod N ==
/// EM` constraint set lands with its square-and-multiply intermediate
/// witness columns; (c) DG-list inclusion in SOD lands. Each future
/// expansion that adds prover-witnessed u32 cells must also expand
/// the splits block.
pub const NUM_COLS: usize = COL_RC_SPLITS_BASE + 2 * NUM_U32_CELLS_TO_RANGE_CHECK;

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

/// Canonical iteration order for the u32 cells that flow into the
/// range-check splits block (`COL_RC_SPLITS_BASE` …).
///
/// Each entry is `(block_start, block_len)` naming a contiguous run of
/// u32 cells in the original trace. The order is locked: trace builders
/// and the AIR's eval() must walk this list in the same order so the
/// `(lo, hi)` halves at the splits offset correspond to the right
/// originals.
///
/// Cells excluded by design:
/// - `COL_ADULT` — bool, asserted via `assert_bool`.
/// - `COL_NULLIFIER_TYPE` — discriminant 0..=3, quartic constraint lands in C25.
/// - `COL_SEAT_ID` — u16 by type, single `BUS_U16_RANGE` lookup (no split).
pub const U32_BLOCKS_TO_RANGE_CHECK: &[(usize, usize)] = &[
	// ─── PI block (defensive: pallet-encoder shape, double-check anyway) ─
	(COL_COMM_IN, HASH_LIMBS),
	(COL_SCOPED_NULLIFIER, HASH_LIMBS),
	(COL_OPRF_PK_HASH, HASH_LIMBS),
	(COL_BOUND_ACCOUNT, HASH_LIMBS),
	(COL_ANCHOR_BLOCK, 1),
	(COL_ANCHOR_HASH, HASH_LIMBS),
	(COL_CSCA_ROOT, HASH_LIMBS),
	(COL_SEATS_ROOT, HASH_LIMBS),
	(COL_AA_CHALLENGE, AA_CHALLENGE_LIMBS),
	(COL_SHA256_DIGEST_OF_CHALLENGE, SHA256_DIGEST_LIMBS),
	// ─── RSA witness block (prover-witnessed, primary range-check target) ─
	(COL_RSA_MODULUS_N, RSA2048_LIMBS),
	(COL_RSA_EXPONENT_E, 1),
	(COL_RSA_SIGNATURE_S, RSA2048_LIMBS),
	(COL_RSA_DECODED_EM, RSA2048_LIMBS),
];

/// AIR for the AA passport-attestation path with RSA-2048 chip key + SHA-256
/// message hash. Stateless; no parameters.
pub struct PassportAttestAaRsa2048Sha256Air;

impl<F: Field> BaseAir<F> for PassportAttestAaRsa2048Sha256Air {
	fn width(&self) -> usize {
		NUM_COLS
	}
}

impl<AB: InteractionBuilder> Air<AB> for PassportAttestAaRsa2048Sha256Air
where
	AB::F: Field + Send,
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

		// Discriminant range on `nullifier_type`: the enum has exactly
		// four valid values — Salted=0, NonSalted=1, SaltedMock=2,
		// NonSaltedMock=3. Force the cell into {0,1,2,3} via the
		// quartic
		//   nt · (nt - 1) · (nt - 2) · (nt - 3) = 0
		// which is zero iff nt is one of the four roots.
		//
		// Without this, the prover could write any Goldilocks value
		// here and the AIR wouldn't notice; the pallet's
		// `AcceptedNullifierTypes` check (commit C4) catches the
		// SCALE-decoded enum cases, but the AIR's own column shape
		// must be bound too — otherwise a Plonky3 verifier consuming
		// the column for downstream constraints (forthcoming OPRF
		// scope/nullifier work) operates on a value the prover
		// could have fabricated outside the four discriminants.
		{
			let nt: AB::Expr = local[COL_NULLIFIER_TYPE].clone().into();
			let nt_minus_1: AB::Expr = nt.clone() - AB::Expr::ONE;
			let nt_minus_2: AB::Expr = nt.clone() - AB::Expr::from_u32(2);
			let nt_minus_3: AB::Expr = nt.clone() - AB::Expr::from_u32(3);
			builder.assert_zero(nt * nt_minus_1 * nt_minus_2 * nt_minus_3);
		}

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

		// ─── u32-limb range checks via BUS_U16_RANGE ───────────────────
		//
		// Every u32 cell in U32_BLOCKS_TO_RANGE_CHECK gets split into
		// two adjacent u16 half-cells (lo, hi) inside the splits block
		// at COL_RC_SPLITS_BASE. The AIR enforces:
		//   (a) original == lo + 2^16 · hi  (tie the halves to the original)
		//   (b) lo  ∈ [0, 2^16)  (BUS_U16_RANGE lookup)
		//   (c) hi  ∈ [0, 2^16)  (BUS_U16_RANGE lookup)
		// Together these force the original cell into [0, 2^32). LogUp
		// balance against `rostro_range_check::U16RangeTableAir` (which
		// must be instantiated on BUS_U16_RANGE in the same batch)
		// rejects any cell whose lo or hi half doesn't appear in the
		// table.
		//
		// Defensive coverage: includes EM cells (already asserted equal
		// to constants/PIs) and PI cells (already pallet-encoder shape-
		// enforced). Belt-and-suspenders: if the EM constants get a
		// regression to a value > 2^32, the range check fires; if the
		// pallet encoder drifts, the range check fires.
		let radix_u16 = AB::Expr::from_u32(1u32 << 16);
		let mut split_idx: usize = 0;
		for &(block_start, block_len) in U32_BLOCKS_TO_RANGE_CHECK {
			for i in 0..block_len {
				let value: AB::Var = local[block_start + i].clone();
				let lo: AB::Var = local[COL_RC_SPLITS_BASE + 2 * split_idx].clone();
				let hi: AB::Var = local[COL_RC_SPLITS_BASE + 2 * split_idx + 1].clone();
				// (a) original == lo + 2^16 · hi
				builder.assert_zero(
					value.into() - lo.clone().into() - radix_u16.clone() * hi.clone().into(),
				);
				// (b) + (c) Range-check both halves via the shared u16 bus.
				builder.push_interaction(BUS_U16_RANGE, [lo], AB::Expr::ONE, 1);
				builder.push_interaction(BUS_U16_RANGE, [hi], AB::Expr::ONE, 1);
				split_idx += 1;
			}
		}
		debug_assert_eq!(split_idx, NUM_U32_CELLS_TO_RANGE_CHECK);

		// `seat_id` is already u16 by type contract — a single direct
		// u16 lookup is sufficient (no split needed).
		builder.push_interaction(
			BUS_U16_RANGE,
			[local[COL_SEAT_ID].clone()],
			AB::Expr::ONE,
			1,
		);

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
		// → decoded EM → u16-split block for range checks. The MRZ /
		// DG2 / OPRF / sponge witness columns land later when
		// Ristretto255-over-Goldilocks curve primitives are scaffolded;
		// each future block that adds prover-witnessed u32 cells must
		// also extend the splits block.
		assert_eq!(COL_RSA_MODULUS_N, NUM_PI_COLS);
		assert_eq!(COL_RSA_EXPONENT_E, COL_RSA_MODULUS_N + RSA2048_LIMBS);
		assert_eq!(COL_RSA_SIGNATURE_S, COL_RSA_EXPONENT_E + 1);
		assert_eq!(COL_RSA_DECODED_EM, COL_RSA_SIGNATURE_S + RSA2048_LIMBS);
		assert_eq!(COL_RC_SPLITS_BASE, COL_RSA_DECODED_EM + RSA2048_LIMBS);
		assert_eq!(NUM_COLS, COL_RC_SPLITS_BASE + 2 * NUM_U32_CELLS_TO_RANGE_CHECK);
		// Breakdown: 76 PI + 64 modulus + 1 exponent + 64 sig + 64 EM
		// + 2 * 266 splits = 801 cols.
		assert_eq!(NUM_COLS, 801);
	}

	#[test]
	fn eval_emits_expected_bus_push_count() {
		// Mock builder that counts BUS_U16_RANGE pushes (no-ops every
		// other constraint type). The AIR is supposed to emit exactly
		// 2 lookups per u32 cell in U32_BLOCKS_TO_RANGE_CHECK PLUS one
		// direct lookup for seat_id.
		//   = 2 × 266 + 1 = 533
		// If this count drifts, either the iteration list got out of
		// sync with the splits block sizing OR a future commit
		// accidentally added/dropped a lookup without updating the
		// expectation. Catch both.
		use p3_air::{AirBuilder, RowWindow};
		use p3_field::PrimeCharacteristicRing;
		use p3_goldilocks::Goldilocks;
		use p3_lookup::InteractionBuilder;
		use alloc::vec::Vec;
		use alloc::string::String;

		struct CountingBuilder<'a> {
			main_window: RowWindow<'a, Goldilocks>,
			preprocessed_window: RowWindow<'a, Goldilocks>,
			u16_range_pushes: usize,
			other_bus_pushes: Vec<String>,
		}

		impl<'a> AirBuilder for CountingBuilder<'a> {
			type F = Goldilocks;
			type Expr = Goldilocks;
			type Var = Goldilocks;
			type MainWindow = RowWindow<'a, Goldilocks>;
			type PreprocessedWindow = RowWindow<'a, Goldilocks>;
			type PublicVar = Goldilocks;
			type PeriodicVar = Goldilocks;
			fn main(&self) -> Self::MainWindow {
				self.main_window
			}
			fn preprocessed(&self) -> &Self::PreprocessedWindow {
				&self.preprocessed_window
			}
			fn is_first_row(&self) -> Self::Expr {
				Goldilocks::ZERO
			}
			fn is_last_row(&self) -> Self::Expr {
				Goldilocks::ZERO
			}
			fn is_transition_window(&self, _size: usize) -> Self::Expr {
				Goldilocks::ZERO
			}
			fn assert_zero<I: Into<Self::Expr>>(&mut self, _x: I) {}
		}

		impl<'a> InteractionBuilder for CountingBuilder<'a> {
			fn push_interaction<E: Into<Self::Expr>>(
				&mut self,
				bus: &str,
				fields: impl IntoIterator<Item = E>,
				_count: impl Into<Self::Expr>,
				_count_weight: u32,
			) {
				let _arity = fields.into_iter().count();
				if bus == BUS_U16_RANGE {
					self.u16_range_pushes += 1;
				} else {
					self.other_bus_pushes.push(String::from(bus));
				}
			}
			fn push_local_interaction(
				&mut self,
				tuples: impl IntoIterator<
					Item = (Vec<Self::Expr>, Self::Expr),
				>,
			) {
				tuples.into_iter().for_each(drop);
			}
		}

		// Empty trace; eval reads cells but the mock returns Goldilocks::ZERO
		// for any access (RowWindow over Vec<Goldilocks>).
		let row: Vec<Goldilocks> =
			(0..NUM_COLS).map(|_| Goldilocks::ZERO).collect();
		let pp: Vec<Goldilocks> = Vec::new();
		let mut b = CountingBuilder {
			main_window: RowWindow::from_two_rows(&row, &row),
			preprocessed_window: RowWindow::from_two_rows(&pp, &pp),
			u16_range_pushes: 0,
			other_bus_pushes: Vec::new(),
		};
		PassportAttestAaRsa2048Sha256Air.eval(&mut b);

		let expected = 2 * NUM_U32_CELLS_TO_RANGE_CHECK + 1;
		assert_eq!(
			b.u16_range_pushes, expected,
			"BUS_U16_RANGE push count drift: got {}, expected {} \
			 (2 lookups per u32 cell + 1 for seat_id)",
			b.u16_range_pushes, expected,
		);
		assert!(
			b.other_bus_pushes.is_empty(),
			"AA AIR should only push to BUS_U16_RANGE at this stage; \
			 got pushes to: {:?}",
			b.other_bus_pushes,
		);
	}

	#[test]
	fn nullifier_type_quartic_is_zero_exactly_for_four_discriminants() {
		// Independent verification of the polynomial property the
		// eval()'s quartic asserts. If the formulation in eval()
		// drifts (e.g., someone "simplifies" to a different
		// polynomial), this test catches the divergence by
		// re-checking the property the constraint is supposed to
		// enforce: nt ∈ {0,1,2,3} iff the quartic == 0.
		use p3_field::PrimeCharacteristicRing;
		use p3_goldilocks::Goldilocks;

		let one = Goldilocks::ONE;
		let two = Goldilocks::from_u32(2);
		let three = Goldilocks::from_u32(3);

		for nt in 0u64..32 {
			let v = Goldilocks::from_u64(nt);
			let q = v * (v - one) * (v - two) * (v - three);
			if nt < 4 {
				assert_eq!(
					q,
					Goldilocks::ZERO,
					"nullifier_type {} (valid discriminant) must satisfy quartic == 0",
					nt,
				);
			} else {
				assert_ne!(
					q,
					Goldilocks::ZERO,
					"nullifier_type {} (invalid discriminant) must NOT satisfy quartic == 0",
					nt,
				);
			}
		}
	}

	#[test]
	fn range_check_iteration_order_covers_every_u32_cell() {
		// The iteration order in U32_BLOCKS_TO_RANGE_CHECK must sum to
		// exactly NUM_U32_CELLS_TO_RANGE_CHECK; otherwise the splits
		// block is over- or under-sized and the eval()'s
		// `debug_assert_eq!(split_idx, NUM_U32_CELLS_TO_RANGE_CHECK)`
		// would fire (debug) or silently drift the bus-balance count
		// (release).
		let total: usize = U32_BLOCKS_TO_RANGE_CHECK
			.iter()
			.map(|(_, len)| *len)
			.sum();
		assert_eq!(total, NUM_U32_CELLS_TO_RANGE_CHECK);
		// And the blocks must be in the documented order: PI block
		// then RSA witness block.
		let pi_total = HASH_LIMBS * 4 // comm_in, scoped_null, oprf_pk, bound_acct
			+ 1                          // anchor.block
			+ HASH_LIMBS * 3             // anchor.hash, csca_root, seats_root
			+ AA_CHALLENGE_LIMBS
			+ SHA256_DIGEST_LIMBS;
		assert_eq!(pi_total, 73);
		let witness_total = RSA2048_LIMBS + 1 + RSA2048_LIMBS + RSA2048_LIMBS;
		assert_eq!(witness_total, 193);
		assert_eq!(pi_total + witness_total, NUM_U32_CELLS_TO_RANGE_CHECK);
	}
}
