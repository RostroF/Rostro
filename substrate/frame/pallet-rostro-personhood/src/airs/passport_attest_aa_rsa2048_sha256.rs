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
//!   hashed via SHA-256 of `(ROSTRO_POP_DOMAIN ‖ anchor.hash ‖ bound_account)`
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

// Public-input layout per `pop_design_section1c_oprf_nullifier.md` (§1c
// revision 2026-05-09). Removed `ttl_block` (privacy: passport expiry
// was a quasi-identifier; now chain-imposed via FIXED_POP_TTL).
// Renamed `dg2_hash` → `dg2_commitment` (privacy: random-salted commitment
// instead of raw photo hash). Added `oprf_key_version` (chain matches
// against `OprfKeyVersion`). Added `mrz_commitment` (Poseidon2 of
// canonical_mrz; OPRF input fed to validator federation off-chain;
// nullifier comes back from federation as a separate PI).

/// Starting column of the `nullifier` field (8 limbs follow). The AIR
/// does NOT constrain this value — the pallet verifies the OPRF proof
/// that binds nullifier = OPRF(mrz_commitment, K) using the on-chain
/// `OprfFederationPublicKey`. The AIR just exposes the value the prover
/// supplies; the binding to passport identity comes via mrz_commitment.
pub const COL_NULLIFIER: usize = 0;
/// Column index of `oprf_key_version` (single u32 limb). Pallet matches
/// against on-chain `OprfKeyVersion` — rejects if mismatch.
pub const COL_OPRF_KEY_VERSION: usize = 8;
/// Starting column of the `mrz_commitment` field (8 limbs follow).
/// Computed in this AIR via Poseidon2 over witnessed canonical_mrz +
/// ROSTRO_MRZ_COMMIT_DOMAIN. Becomes the OPRF input the federation
/// processes off-chain.
pub const COL_MRZ_COMMITMENT: usize = 9;
/// Starting column of the `bound_account` field (8 limbs follow).
pub const COL_BOUND_ACCOUNT: usize = 17;
/// Column index of `adult` (single limb, must be 0 or 1).
pub const COL_ADULT: usize = 25;
/// Column index of `seat_id` (single u16 limb).
pub const COL_SEAT_ID: usize = 26;
/// Column index of `anchor.block` (single u32 limb).
pub const COL_ANCHOR_BLOCK: usize = 27;
/// Starting column of the `anchor.hash` field (8 limbs follow).
pub const COL_ANCHOR_HASH: usize = 28;
/// Starting column of the `csca_root` field (8 limbs follow).
pub const COL_CSCA_ROOT: usize = 36;
/// Starting column of the `seats_root` field (8 limbs follow).
pub const COL_SEATS_ROOT: usize = 44;
/// Starting column of the `dg2_commitment` field (8 limbs follow).
/// Random-salted commitment to dg2_hash per §1c privacy review.
/// Cross-proof binding: liveness_facematch AIR computes the same
/// commitment from the same (dg2_hash, salt) pair.
pub const COL_DG2_COMMITMENT: usize = 52;
/// Starting column of the `aa_challenge` PI field (8 limbs follow).
///
/// **Promoted from witness to PI 2026-05-09.** The pallet computes
/// `expected_aa_challenge = SHA-256(ROSTRO_POP_DOMAIN ‖ anchor.hash ‖
/// bound_account.encode())` (per `lib.rs::hip_challenge_nonce`'s formula)
/// and asserts it equals the proof's PI value here. The AIR uses this
/// as the message that the chip's RSA signature is verified against.
///
/// This split (pallet computes SHA-256, AIR uses pre-computed result as
/// PI) avoids needing SHA-256-in-AIR as a precondition for the
/// AA-challenge ↔ chip-sig binding to work. SHA-256 in-circuit lands
/// later when DG-list inclusion in SOD requires it; until then this
/// pattern lets the chip-sig verification proceed without depending on
/// it.
pub const COL_AA_CHALLENGE: usize = 60;
/// Number of u32 limbs in the AA challenge (32 bytes / 4 = 8).
pub const AA_CHALLENGE_LIMBS: usize = HASH_LIMBS;
/// Starting column of the SHA-256 digest of `aa_challenge` (8 limbs follow).
///
/// **Promoted from witness to PI 2026-05-09.** Same play as the AA
/// challenge promotion: the pallet computes `expected_digest = SHA-256(
/// proof.aa_challenge_pi_bytes)` and asserts it equals this PI value;
/// the AIR's existing PKCS#1 v1.5 constraint binds `EM[224..256]` to
/// these limbs. Together, the chain of bindings is:
///
///   pallet computes aa_challenge from anchor + bound_account → checks PI
///   pallet computes SHA-256(aa_challenge) → checks PI
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
/// Total public-input columns (76 = 8+1+8+8+1+1+1+8+8+8+8+8+8).
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
// to the PI block on 2026-05-09 (see top-of-file PI section). Witness
// block now ends at COL_RSA_DECODED_EM + RSA2048_LIMBS; the next
// witness section (canonical MRZ) starts there.

// ─── Canonical MRZ witness columns (for nullifier derivation) ──────────────
//
// ICAO 9303 Type 3 (passport) MRZ canonical form is `dg1[0..88]` per
// zkpassport's reference pattern — 88 ASCII bytes, two 44-character lines
// concatenated. Packs as 22 u32 limbs (88 / 4). The witnessed bytes feed
// the Poseidon2 nullifier hash whose output must equal the public-input
// `nullifier` columns.

/// Number of u32 limbs in the canonical MRZ slice (88 bytes / 4).
pub const CANONICAL_MRZ_LIMBS: usize = 22;

// ─── Poseidon2 MRZ-commitment sponge schedule ──────────────────────────────
//
// **Repurposed 2026-05-09 per §1c.** Was the nullifier hash; now computes
// the MRZ commitment that gets fed to the OPRF federation. The nullifier
// itself is OPRF-derived off-chain (federation holds threshold-shared K,
// pallet verifies the federation's proof against on-chain K_pub) — the
// AIR no longer hashes to a nullifier directly.
//
// The MRZ commitment is `Poseidon2(canonical_mrz, ROSTRO_MRZ_COMMIT_DOMAIN)`
// over Goldilocks. Same sponge shape as before; different OUTPUT binding
// (squeeze lands at COL_MRZ_COMMITMENT instead of COL_NULLIFIER) and
// different DOMAIN separator (ROSTRO_MRZ_COMMIT_DOMAIN, NOT ROSTRO_POP_DOMAIN
// which is now reserved for HIP challenge derivation).
//
// **Input encoding.** Per `pop_air_goldilocks_packing_convention.md`
// (locked 2026-05-09): one u32 per Goldilocks element, no paired
// packing. canonical_mrz (88 bytes) packs as **22 Goldilocks elements**
// (one per u32 limb). The 20-byte `ROSTRO_MRZ_COMMIT_DOMAIN =
// b"rostro-mrz-commit-v1"` is NOT mixed into the rate stream — it's
// used as an init tweak to the state's CAPACITY half. Standard "domain
// separation via capacity initialization":
// `state[RATE..WIDTH] = mrz_commit_domain_capacity_init`,
// `state[0..RATE] = 0`. Closes the byte-shifting attack across the
// domain/message boundary AND keeps the MRZ commitment hash space
// separate from any other Poseidon2 use of the same input bytes
// (cross-protocol attack defense).
//
// **Absorb schedule.** WIDTH=8, RATE=4. **22 input elements split into
// 6 absorbs:**
//   absorb 0 → elements [0..4]
//   absorb 1 → elements [4..8]
//   absorb 2 → elements [8..12]
//   absorb 3 → elements [12..16]
//   absorb 4 → elements [16..20]
//   absorb 5 → elements [20..22] + 2 padding elements (10*-pad to RATE)
// Six absorb permutations total. Each permutation runs the full
// 30-round (4 + 22 + 4) Poseidon2 schedule.
//
// **Squeeze.** After the final absorb, take the first 4 Goldilocks
// elements of state (`state[0..RATE]`) as the hash output. Each is a
// Goldilocks element holding values up to ~p; for the public-input
// `mrz_commitment` representation we'll constrain the squeezed elements
// to fit in u32 form too (i.e., 4 elements give 4 u32 limbs = 16
// bytes, NOT the full 32 bytes a u64-packing would give).
//
// Wait: 4 Goldilocks elements × 32 bits each = 128 bits = 16 bytes,
// only HALF the COL_MRZ_COMMITMENT (8 limbs = 32 bytes). So the squeeze
// extracts 8 elements (= 8 u32 limbs = 32 bytes) which means we squeeze
// the FULL state (`state[0..WIDTH]`), not just the rate slot. Standard
// sponge protocol: tap-and-permute again if more output is needed,
// but here taking the WIDTH=8 state as 8-element output is fine
// because it follows the final absorb (no further input to leak via
// state extraction). Output: state[0..8] → 8 u32 limbs = 32 bytes
// = COL_MRZ_COMMITMENT.
//
// **Cost.** 6 permutations × 248 trace columns each = 1488 columns
// dedicated to Poseidon2 in this AIR. ~2× the previous (3-perm)
// estimate that assumed unsafe paired-u64 packing. Per the packing
// convention memo, this is the right safety/columns tradeoff.

/// Starting column of the witnessed canonical MRZ bytes (22 u32 limbs).
/// Sits immediately after the RSA witness block (modulus + exponent +
/// signature + EM); the SHA-256 digest column was promoted to PI on
/// 2026-05-09 so canonical MRZ no longer follows it in the witness block.
pub const COL_CANONICAL_MRZ: usize = COL_RSA_DECODED_EM + RSA2048_LIMBS;

/// Number of Poseidon2 permutation invocations needed to absorb the
/// canonical MRZ (22 elements / RATE 4 = 6 absorbs, last with 2-element
/// 10*-padding). The hash primitive lives in `rostro-poseidon-air`; this
/// constant is consumed by the trace generator to size the bus message
/// stream + by the harness orchestrator to allocate that many AIR
/// instances. Per `pop_air_goldilocks_packing_convention.md`.
pub const POSEIDON2_NUM_MRZ_PERMS: usize = 6;

// ─── DG2 commitment witness columns (chip photo hash + per-mint salt) ──────
//
// Per `pop_design_section1c_oprf_nullifier.md` privacy review: replace
// raw `dg2_hash` PI with `dg2_commitment = Poseidon2(dg2_hash, salt)` so
// possessing the user's photo elsewhere can no longer link to a chain
// account. The salt is fresh per mint, witnessed never on chain.
// Cross-proof binding with `liveness_facematch`: same (dg2_hash, salt)
// pair → same dg2_commitment in both circuits.
//
// AIR doesn't witness raw DG2 photo bytes — those would be megabytes
// per passport. Caller hashes DG2 → 32-byte dg2_hash off-circuit; the
// AIR witnesses the hash. SOD inclusion (DG-list contains this dg2_hash)
// is constrained elsewhere (see TODO at end of eval).

/// Starting column of the witnessed DG2 hash (8 u32 limbs = 32 bytes).
pub const COL_DG2_HASH: usize = COL_CANONICAL_MRZ + CANONICAL_MRZ_LIMBS;
/// Starting column of the witnessed DG2 salt (8 u32 limbs = 32 bytes).
/// Fresh-randomness per mint; never appears on chain.
pub const COL_DG2_SALT: usize = COL_DG2_HASH + HASH_LIMBS;

/// Number of Poseidon2 permutation invocations in the DG2-commitment hash.
/// dg2_hash (8 u32 limbs) + salt (8 u32 limbs) = 16 elements / RATE 4 =
/// exactly 4 absorbs (no padding). Different DOMAIN separator
/// (ROSTRO_DG2_COMMIT_DOMAIN) from the MRZ sponge — cross-protocol attack
/// defense even if (dg2_hash, salt) somehow equals (canonical_mrz_chunk,
/// padding) for adversarial inputs. The hash primitive lives in
/// `rostro-poseidon-air`.
pub const POSEIDON2_NUM_DG2_PERMS: usize = 4;

// ─── Domain capacity-init constants for the Poseidon2 DG2-commitment sponge ─
//
// `crate::ROSTRO_DG2_COMMIT_DOMAIN` (b"rostro-dg2-commit-v1", 20 bytes)
// right-padded with zeros to 32 bytes. Pinned at compile time so the
// constants are auditable from this file.

/// `crate::ROSTRO_DG2_COMMIT_DOMAIN` right-padded with zeros to 32 bytes.
pub const DG2_COMMIT_DOMAIN_CAPACITY_PADDED: [u8; 32] = {
	let mut out = [0u8; 32];
	let domain: &[u8; 20] = b"rostro-dg2-commit-v1";
	let mut i = 0;
	while i < 20 {
		out[i] = domain[i];
		i += 1;
	}
	out
};

/// `DG2_COMMIT_DOMAIN_CAPACITY_PADDED` packed as 8 big-endian u32 limbs
/// (= 4 Goldilocks elements at 2 limbs each — the AIR's DG2-sponge
/// capacity-init target value).
pub const DG2_COMMIT_DOMAIN_CAPACITY_LIMBS: [u32; 8] = {
	let bytes = DG2_COMMIT_DOMAIN_CAPACITY_PADDED;
	let mut out = [0u32; 8];
	let mut i = 0;
	while i < 8 {
		out[i] = u32::from_be_bytes([
			bytes[4 * i],
			bytes[4 * i + 1],
			bytes[4 * i + 2],
			bytes[4 * i + 3],
		]);
		i += 1;
	}
	out
};

// ─── Domain capacity-init constants for the Poseidon2 MRZ-commitment sponge ─
//
// The sponge initializes its CAPACITY half (`state[RATE..WIDTH]` =
// `state[4..8]`) from `crate::ROSTRO_MRZ_COMMIT_DOMAIN` (= b"rostro-mrz-commit-v1",
// 20 bytes), right-padded with zeros to 32 bytes (= 4 Goldilocks
// elements at 8 bytes each). Pinned at compile time so the constants
// are auditable directly from this file.
//
// The actual `state[4..8] == capacity_init` constraint in `eval()` is
// deferred — it depends on the u32-limbs ↔ Goldilocks-element packing
// convention. When that lands, this constant is what the constraint
// asserts equality to.

/// `crate::ROSTRO_MRZ_COMMIT_DOMAIN` right-padded with zeros to 32 bytes.
pub const MRZ_COMMIT_DOMAIN_CAPACITY_PADDED: [u8; 32] = {
	let mut out = [0u8; 32];
	let domain: &[u8; 20] = b"rostro-mrz-commit-v1";
	let mut i = 0;
	while i < 20 {
		out[i] = domain[i];
		i += 1;
	}
	out
};

/// `MRZ_COMMIT_DOMAIN_CAPACITY_PADDED` packed as 8 big-endian u32 limbs
/// (= 4 Goldilocks elements at 2 limbs each — the AIR's capacity-init
/// target value for the MRZ-commitment sponge).
pub const MRZ_COMMIT_DOMAIN_CAPACITY_LIMBS: [u32; 8] = {
	let bytes = MRZ_COMMIT_DOMAIN_CAPACITY_PADDED;
	let mut out = [0u32; 8];
	let mut i = 0;
	while i < 8 {
		out[i] = u32::from_be_bytes([
			bytes[4 * i],
			bytes[4 * i + 1],
			bytes[4 * i + 2],
			bytes[4 * i + 3],
		]);
		i += 1;
	}
	out
};

// ─── Post-absorb state vectors (witnessed; consumed via lookup bus) ─────────
//
// One 8-cell post-state vector per Poseidon2 absorb. The trace generator
// computes the sponge step-by-step off-circuit and writes the resulting
// state after each absorb into these columns. The AIR's eval pushes a
// `recv` interaction on the output bus for each post_state, balanced by a
// matching `send` from the corresponding `rostro-poseidon-air` AIR
// instance in the same batch.
//
// The FINAL post_state of each hash is the squeezed commitment value.
// `eval` constrains:
//   COL_MRZ_STATE_AFTER_ABSORB_5[0..8]  ==  COL_MRZ_COMMITMENT[0..8]
//   COL_DG2_STATE_AFTER_ABSORB_3[0..8]  ==  COL_DG2_COMMITMENT[0..8]
// closing the loop between the bus-received hash output and the public
// input the pallet binds against.

/// Width of one post-absorb state vector (Poseidon2 WIDTH = 8).
pub const STATE_WIDTH: usize = 8;

/// Starting column of the state vector witnessed AFTER MRZ absorb i,
/// for i in 0..POSEIDON2_NUM_MRZ_PERMS. Each holds 8 u32 limbs.
pub const COL_MRZ_STATE_AFTER_ABSORB_0: usize = COL_DG2_SALT + HASH_LIMBS;
pub const COL_MRZ_STATE_AFTER_ABSORB_1: usize = COL_MRZ_STATE_AFTER_ABSORB_0 + STATE_WIDTH;
pub const COL_MRZ_STATE_AFTER_ABSORB_2: usize = COL_MRZ_STATE_AFTER_ABSORB_1 + STATE_WIDTH;
pub const COL_MRZ_STATE_AFTER_ABSORB_3: usize = COL_MRZ_STATE_AFTER_ABSORB_2 + STATE_WIDTH;
pub const COL_MRZ_STATE_AFTER_ABSORB_4: usize = COL_MRZ_STATE_AFTER_ABSORB_3 + STATE_WIDTH;
pub const COL_MRZ_STATE_AFTER_ABSORB_5: usize = COL_MRZ_STATE_AFTER_ABSORB_4 + STATE_WIDTH;

/// Starting column of the state vector witnessed AFTER DG2 absorb i,
/// for i in 0..POSEIDON2_NUM_DG2_PERMS. Each holds 8 u32 limbs.
pub const COL_DG2_STATE_AFTER_ABSORB_0: usize = COL_MRZ_STATE_AFTER_ABSORB_5 + STATE_WIDTH;
pub const COL_DG2_STATE_AFTER_ABSORB_1: usize = COL_DG2_STATE_AFTER_ABSORB_0 + STATE_WIDTH;
pub const COL_DG2_STATE_AFTER_ABSORB_2: usize = COL_DG2_STATE_AFTER_ABSORB_1 + STATE_WIDTH;
pub const COL_DG2_STATE_AFTER_ABSORB_3: usize = COL_DG2_STATE_AFTER_ABSORB_2 + STATE_WIDTH;

// ─── Lookup bus names (algorithm-scoped) ────────────────────────────────────
//
// Per-algorithm AA AIRs are siloed by `feedback_no_cross_purpose_files.md`
// and `pop_algorithm_coverage_zkpassport_mirror.md`. Each (sig_alg,
// hash_alg) AIR file gets its own bus namespace so when multiple
// algorithm AIRs deploy in the same batch they don't crosstalk.
//
// Within this AIR, MRZ-commitment and DG2-commitment hashes share the
// same bus pair across all 6/4 absorbs respectively — LogUp matches
// (input, output) message pairs by content, so 6 MRZ Poseidon2-hash
// instances on a shared output bus pair up correctly with the caller's
// 6 receive operations.

/// Bus carrying the input message of each MRZ-commitment Poseidon2 absorb
/// (state with rate_chunk added). Caller sends; rostro-poseidon-air
/// (External-Initial) on this bus receives.
pub const BUS_MRZ_INPUT: &str = "rostro-pop-aa-rsa2048-sha256-mrz-input";

/// Bus carrying the output message of each MRZ-commitment Poseidon2 absorb
/// (post-state). rostro-poseidon-air (External-Terminal) on this bus
/// sends; caller receives.
pub const BUS_MRZ_OUTPUT: &str = "rostro-pop-aa-rsa2048-sha256-mrz-output";

/// Bus carrying the input message of each DG2-commitment Poseidon2 absorb.
pub const BUS_DG2_INPUT: &str = "rostro-pop-aa-rsa2048-sha256-dg2-input";

/// Bus carrying the output message of each DG2-commitment Poseidon2 absorb.
pub const BUS_DG2_OUTPUT: &str = "rostro-pop-aa-rsa2048-sha256-dg2-output";

/// Map MRZ-commitment absorb index `i in 0..6` to its post_state's
/// starting column. Pure const lookup — keeps the eval body readable.
#[inline]
const fn mrz_state_col(absorb: usize) -> usize {
	match absorb {
		0 => COL_MRZ_STATE_AFTER_ABSORB_0,
		1 => COL_MRZ_STATE_AFTER_ABSORB_1,
		2 => COL_MRZ_STATE_AFTER_ABSORB_2,
		3 => COL_MRZ_STATE_AFTER_ABSORB_3,
		4 => COL_MRZ_STATE_AFTER_ABSORB_4,
		5 => COL_MRZ_STATE_AFTER_ABSORB_5,
		_ => panic!("mrz_state_col: absorb out of range; qed"),
	}
}

/// Map DG2-commitment absorb index `i in 0..4` to its post_state's
/// starting column.
#[inline]
const fn dg2_state_col(absorb: usize) -> usize {
	match absorb {
		0 => COL_DG2_STATE_AFTER_ABSORB_0,
		1 => COL_DG2_STATE_AFTER_ABSORB_1,
		2 => COL_DG2_STATE_AFTER_ABSORB_2,
		3 => COL_DG2_STATE_AFTER_ABSORB_3,
		_ => panic!("dg2_state_col: absorb out of range; qed"),
	}
}

/// Total trace columns for this AIR after phase 3b. Includes: PI block,
/// RSA witness block (modulus + exponent + signature + EM), MRZ canonical
/// bytes, DG2 hash + salt, 6 MRZ post-absorb state vectors, 4 DG2
/// post-absorb state vectors. Grows further when modexp + SHA-256
/// intermediate columns land in phase 3c.
pub const NUM_COLS: usize = COL_DG2_STATE_AFTER_ABSORB_3 + STATE_WIDTH;

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

impl<AB: InteractionBuilder> Air<AB> for PassportAttestAaRsa2048Sha256Air
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

		// ─── MRZ-commitment Poseidon2 bus interactions ─────────────────
		//
		// The 22-element canonical_mrz absorbs into a Goldilocks-Poseidon2
		// WIDTH=8 sponge (RATE=4, CAPACITY=4) over POSEIDON2_NUM_MRZ_PERMS
		// = 6 absorb steps. State after each absorb is witnessed at
		// COL_MRZ_STATE_AFTER_ABSORB_i; the harness AIR composition runs
		// 3 rostro-poseidon-air round AIRs per absorb on these buses to
		// prove each (input → output) transformation.
		//
		// Per absorb i, eval emits two interactions:
		//   send (count=+1) on BUS_MRZ_INPUT  with input_message_i
		//        = pre_state[i] with rate_chunk_i added to first 4 cells
		//   recv (count=-1) on BUS_MRZ_OUTPUT with post_state[i]
		//
		// pre_state[0]: rate half = 0, capacity half = MRZ capacity init
		// pre_state[i>0] = post_state[i-1]
		//
		// LogUp matches each (input, output) pair by content; six
		// rostro-poseidon-air composed-hash instances on the same buses
		// pair up correctly with the six caller emissions because the
		// permutation is deterministic.
		//
		// MRZ rate-chunk schedule (RATE=4, 22 elements, last absorb has
		// 2 inputs + 2-element 10*-padding):
		//   absorb 0: canonical_mrz[ 0..4]
		//   absorb 1: canonical_mrz[ 4..8]
		//   absorb 2: canonical_mrz[ 8..12]
		//   absorb 3: canonical_mrz[12..16]
		//   absorb 4: canonical_mrz[16..20]
		//   absorb 5: canonical_mrz[20..22] || [1, 0]   (10*-pad)

		let mrz_capacity_init: [AB::Expr; 4] = core::array::from_fn(|i| {
			AB::Expr::from_u32(MRZ_COMMIT_DOMAIN_CAPACITY_LIMBS[i])
		});

		for absorb in 0..POSEIDON2_NUM_MRZ_PERMS {
			let pre_rate: [AB::Expr; 4] = if absorb == 0 {
				core::array::from_fn(|_| AB::Expr::ZERO)
			} else {
				let prev = mrz_state_col(absorb - 1);
				core::array::from_fn(|i| local[prev + i].clone().into())
			};
			let pre_capacity: [AB::Expr; 4] = if absorb == 0 {
				mrz_capacity_init.clone()
			} else {
				let prev = mrz_state_col(absorb - 1);
				core::array::from_fn(|i| local[prev + 4 + i].clone().into())
			};

			let rate_chunk: [AB::Expr; 4] = match absorb {
				5 => [
					local[COL_CANONICAL_MRZ + 20].clone().into(),
					local[COL_CANONICAL_MRZ + 21].clone().into(),
					AB::Expr::ONE,
					AB::Expr::ZERO,
				],
				_ => core::array::from_fn(|i| {
					local[COL_CANONICAL_MRZ + absorb * 4 + i].clone().into()
				}),
			};

			let input_message: [AB::Expr; STATE_WIDTH] = core::array::from_fn(|i| {
				if i < 4 {
					pre_rate[i].clone() + rate_chunk[i].clone()
				} else {
					pre_capacity[i - 4].clone()
				}
			});

			builder.push_interaction(BUS_MRZ_INPUT, input_message, AB::Expr::ONE, 1);

			let post = mrz_state_col(absorb);
			let output_message: [AB::Var; STATE_WIDTH] =
				core::array::from_fn(|i| local[post + i]);
			builder.push_interaction(
				BUS_MRZ_OUTPUT,
				output_message,
				AB::Expr::ZERO - AB::Expr::ONE,
				1,
			);
		}

		// MRZ-commitment squeeze: the final post_state IS the public
		// `mrz_commitment` value. Constrain equality (8 limbs).
		for i in 0..STATE_WIDTH {
			builder.assert_eq(
				local[COL_MRZ_STATE_AFTER_ABSORB_5 + i].clone(),
				local[COL_MRZ_COMMITMENT + i].clone(),
			);
		}

		// ─── DG2-commitment Poseidon2 bus interactions ─────────────────
		//
		// 16 input elements (dg2_hash[0..8] || salt[0..8]) absorb cleanly
		// into 4 absorbs, no padding. Different domain init
		// (DG2_COMMIT_DOMAIN_CAPACITY_LIMBS) so the hash space is disjoint
		// from MRZ's. Same bus convention (separate bus pair).
		//
		// Rate-chunk schedule:
		//   absorb 0: dg2_hash[0..4]
		//   absorb 1: dg2_hash[4..8]
		//   absorb 2: dg2_salt[0..4]
		//   absorb 3: dg2_salt[4..8]

		let dg2_capacity_init: [AB::Expr; 4] = core::array::from_fn(|i| {
			AB::Expr::from_u32(DG2_COMMIT_DOMAIN_CAPACITY_LIMBS[i])
		});

		for absorb in 0..POSEIDON2_NUM_DG2_PERMS {
			let pre_rate: [AB::Expr; 4] = if absorb == 0 {
				core::array::from_fn(|_| AB::Expr::ZERO)
			} else {
				let prev = dg2_state_col(absorb - 1);
				core::array::from_fn(|i| local[prev + i].clone().into())
			};
			let pre_capacity: [AB::Expr; 4] = if absorb == 0 {
				dg2_capacity_init.clone()
			} else {
				let prev = dg2_state_col(absorb - 1);
				core::array::from_fn(|i| local[prev + 4 + i].clone().into())
			};

			let rate_chunk: [AB::Expr; 4] = match absorb {
				0 => core::array::from_fn(|i| local[COL_DG2_HASH + i].clone().into()),
				1 => core::array::from_fn(|i| local[COL_DG2_HASH + 4 + i].clone().into()),
				2 => core::array::from_fn(|i| local[COL_DG2_SALT + i].clone().into()),
				_ => core::array::from_fn(|i| local[COL_DG2_SALT + 4 + i].clone().into()),
			};

			let input_message: [AB::Expr; STATE_WIDTH] = core::array::from_fn(|i| {
				if i < 4 {
					pre_rate[i].clone() + rate_chunk[i].clone()
				} else {
					pre_capacity[i - 4].clone()
				}
			});

			builder.push_interaction(BUS_DG2_INPUT, input_message, AB::Expr::ONE, 1);

			let post = dg2_state_col(absorb);
			let output_message: [AB::Var; STATE_WIDTH] =
				core::array::from_fn(|i| local[post + i]);
			builder.push_interaction(
				BUS_DG2_OUTPUT,
				output_message,
				AB::Expr::ZERO - AB::Expr::ONE,
				1,
			);
		}

		// DG2-commitment squeeze: final post_state IS the public
		// `dg2_commitment` value.
		for i in 0..STATE_WIDTH {
			builder.assert_eq(
				local[COL_DG2_STATE_AFTER_ABSORB_3 + i].clone(),
				local[COL_DG2_COMMITMENT + i].clone(),
			);
		}

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
		// PI layout per §1c (revised 2026-05-09):
		// nullifier(8) || oprf_key_version(1) || mrz_commitment(8) ||
		// bound_account(8) || adult(1) || seat_id(1) || anchor.block(1) ||
		// anchor.hash(8) || csca_root(8) || seats_root(8) || dg2_commitment(8)
		assert_eq!(COL_NULLIFIER, 0);
		assert_eq!(COL_OPRF_KEY_VERSION, COL_NULLIFIER + HASH_LIMBS);
		assert_eq!(COL_MRZ_COMMITMENT, COL_OPRF_KEY_VERSION + 1);
		assert_eq!(COL_BOUND_ACCOUNT, COL_MRZ_COMMITMENT + HASH_LIMBS);
		assert_eq!(COL_ADULT, COL_BOUND_ACCOUNT + HASH_LIMBS);
		assert_eq!(COL_SEAT_ID, COL_ADULT + 1);
		assert_eq!(COL_ANCHOR_BLOCK, COL_SEAT_ID + 1);
		assert_eq!(COL_ANCHOR_HASH, COL_ANCHOR_BLOCK + 1);
		assert_eq!(COL_CSCA_ROOT, COL_ANCHOR_HASH + HASH_LIMBS);
		assert_eq!(COL_SEATS_ROOT, COL_CSCA_ROOT + HASH_LIMBS);
		assert_eq!(COL_DG2_COMMITMENT, COL_SEATS_ROOT + HASH_LIMBS);
		assert_eq!(COL_AA_CHALLENGE, COL_DG2_COMMITMENT + HASH_LIMBS);
		assert_eq!(
			COL_SHA256_DIGEST_OF_CHALLENGE,
			COL_AA_CHALLENGE + AA_CHALLENGE_LIMBS,
		);
		assert_eq!(
			NUM_PI_COLS,
			COL_SHA256_DIGEST_OF_CHALLENGE + SHA256_DIGEST_LIMBS,
		);
		// Sanity total: 8+1+8+8+1+1+1+8+8+8+8+8+8 = 76.
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
		// Pin the witness column ordering after the 2026-05-10 strip
		// (phase 3a) and bus-interaction wiring (phase 3b). Layout:
		// PI block → RSA modulus → exponent → signature → decoded EM →
		// canonical MRZ → DG2 hash → DG2 salt → 6 MRZ post-absorb state
		// vectors → 4 DG2 post-absorb state vectors.
		assert_eq!(COL_RSA_MODULUS_N, NUM_PI_COLS);
		assert_eq!(COL_RSA_EXPONENT_E, COL_RSA_MODULUS_N + RSA2048_LIMBS);
		assert_eq!(COL_RSA_SIGNATURE_S, COL_RSA_EXPONENT_E + 1);
		assert_eq!(COL_RSA_DECODED_EM, COL_RSA_SIGNATURE_S + RSA2048_LIMBS);
		assert_eq!(COL_CANONICAL_MRZ, COL_RSA_DECODED_EM + RSA2048_LIMBS);
		assert_eq!(COL_DG2_HASH, COL_CANONICAL_MRZ + CANONICAL_MRZ_LIMBS);
		assert_eq!(COL_DG2_SALT, COL_DG2_HASH + HASH_LIMBS);
		// Six MRZ post-absorb state vectors, contiguous, 8 cells each.
		assert_eq!(COL_MRZ_STATE_AFTER_ABSORB_0, COL_DG2_SALT + HASH_LIMBS);
		assert_eq!(COL_MRZ_STATE_AFTER_ABSORB_1, COL_MRZ_STATE_AFTER_ABSORB_0 + STATE_WIDTH);
		assert_eq!(COL_MRZ_STATE_AFTER_ABSORB_2, COL_MRZ_STATE_AFTER_ABSORB_1 + STATE_WIDTH);
		assert_eq!(COL_MRZ_STATE_AFTER_ABSORB_3, COL_MRZ_STATE_AFTER_ABSORB_2 + STATE_WIDTH);
		assert_eq!(COL_MRZ_STATE_AFTER_ABSORB_4, COL_MRZ_STATE_AFTER_ABSORB_3 + STATE_WIDTH);
		assert_eq!(COL_MRZ_STATE_AFTER_ABSORB_5, COL_MRZ_STATE_AFTER_ABSORB_4 + STATE_WIDTH);
		// Four DG2 post-absorb state vectors, contiguous, 8 cells each.
		assert_eq!(COL_DG2_STATE_AFTER_ABSORB_0, COL_MRZ_STATE_AFTER_ABSORB_5 + STATE_WIDTH);
		assert_eq!(COL_DG2_STATE_AFTER_ABSORB_1, COL_DG2_STATE_AFTER_ABSORB_0 + STATE_WIDTH);
		assert_eq!(COL_DG2_STATE_AFTER_ABSORB_2, COL_DG2_STATE_AFTER_ABSORB_1 + STATE_WIDTH);
		assert_eq!(COL_DG2_STATE_AFTER_ABSORB_3, COL_DG2_STATE_AFTER_ABSORB_2 + STATE_WIDTH);
		assert_eq!(NUM_COLS, COL_DG2_STATE_AFTER_ABSORB_3 + STATE_WIDTH);
		// Breakdown: 76 PI + 64 modulus + 1 exponent + 64 sig + 64 EM
		// + 22 MRZ + 8 dg2_hash + 8 dg2_salt + 6×8 MRZ post-absorb
		// + 4×8 DG2 post-absorb = 307 + 80 = 387 cols.
		assert_eq!(NUM_COLS, 387);
	}

	#[test]
	fn poseidon2_state_columns_match_locked_width() {
		// State width is fixed by the Goldilocks-Poseidon2-WIDTH=8
		// instance. If this changes, every post-absorb column shifts and
		// every bus message has the wrong arity.
		assert_eq!(STATE_WIDTH, 8);
	}

	#[test]
	fn bus_names_are_algorithm_scoped_and_distinct() {
		// Per-algorithm AA AIRs share no buses. The names embed
		// "rsa2048-sha256" so future per-algorithm AIR files
		// (passport_attest_aa_p256, ...) get their own namespaces.
		assert_eq!(BUS_MRZ_INPUT,  "rostro-pop-aa-rsa2048-sha256-mrz-input");
		assert_eq!(BUS_MRZ_OUTPUT, "rostro-pop-aa-rsa2048-sha256-mrz-output");
		assert_eq!(BUS_DG2_INPUT,  "rostro-pop-aa-rsa2048-sha256-dg2-input");
		assert_eq!(BUS_DG2_OUTPUT, "rostro-pop-aa-rsa2048-sha256-dg2-output");
		// All 4 buses must be distinct — same-name buses on a batch
		// would silently merge LogUp accounts.
		let buses = [BUS_MRZ_INPUT, BUS_MRZ_OUTPUT, BUS_DG2_INPUT, BUS_DG2_OUTPUT];
		for i in 0..buses.len() {
			for j in (i + 1)..buses.len() {
				assert_ne!(buses[i], buses[j]);
			}
		}
	}

	#[test]
	fn mrz_commit_domain_capacity_init_matches_be_packing() {
		// First half: padded form's first 20 bytes equal the source
		// domain string; remaining 12 bytes are zero padding.
		assert_eq!(
			&MRZ_COMMIT_DOMAIN_CAPACITY_PADDED[0..20],
			crate::ROSTRO_MRZ_COMMIT_DOMAIN,
		);
		assert_eq!(&MRZ_COMMIT_DOMAIN_CAPACITY_PADDED[20..32], &[0u8; 12][..]);

		// Second half: u32-limb packing matches big-endian byte chunks.
		// "rostro-mrz-commit-v1" laid out 4 bytes per limb, big-endian:
		//   limb[0] = "rost" = 0x726F7374
		//   limb[1] = "ro-m" = 0x726F2D6D
		//   limb[2] = "rz-c" = 0x727A2D63
		//   limb[3] = "ommi" = 0x6F6D6D69
		//   limb[4] = "t-v1" = 0x742D7631
		//   limb[5..8] = zero padding
		assert_eq!(MRZ_COMMIT_DOMAIN_CAPACITY_LIMBS[0], 0x726F_7374); // "rost"
		assert_eq!(MRZ_COMMIT_DOMAIN_CAPACITY_LIMBS[1], 0x726F_2D6D); // "ro-m"
		assert_eq!(MRZ_COMMIT_DOMAIN_CAPACITY_LIMBS[2], 0x727A_2D63); // "rz-c"
		assert_eq!(MRZ_COMMIT_DOMAIN_CAPACITY_LIMBS[3], 0x6F6D_6D69); // "ommi"
		assert_eq!(MRZ_COMMIT_DOMAIN_CAPACITY_LIMBS[4], 0x742D_7631); // "t-v1"
		assert_eq!(MRZ_COMMIT_DOMAIN_CAPACITY_LIMBS[5], 0);
		assert_eq!(MRZ_COMMIT_DOMAIN_CAPACITY_LIMBS[6], 0);
		assert_eq!(MRZ_COMMIT_DOMAIN_CAPACITY_LIMBS[7], 0);

		// Round-trip cross-check: the const-fn packing matches the
		// runtime `bytes_to_u32_limbs` implementation. If either drifts,
		// this fails.
		assert_eq!(
			MRZ_COMMIT_DOMAIN_CAPACITY_LIMBS,
			bytes_to_u32_limbs(&MRZ_COMMIT_DOMAIN_CAPACITY_PADDED),
		);
	}

	#[test]
	fn poseidon2_absorb_counts_match_locked_sponge_schedule() {
		// Six absorbs per MRZ-commitment hash: 22 elements / RATE 4 = 6
		// absorbs, last with 2-element 10*-padding. Per
		// `pop_air_goldilocks_packing_convention.md`.
		assert_eq!(POSEIDON2_NUM_MRZ_PERMS, 6);
		// Four absorbs per DG2-commitment hash: dg2_hash (8 limbs) + salt
		// (8 limbs) = 16 elements / RATE 4 = exactly 4 absorbs (no
		// padding). Same Poseidon2 instance, different domain.
		assert_eq!(POSEIDON2_NUM_DG2_PERMS, 4);
	}

	#[test]
	fn dg2_commit_domain_capacity_init_matches_be_packing() {
		// Padding shape: first 20 bytes equal source domain string;
		// remaining 12 bytes are zero padding.
		assert_eq!(
			&DG2_COMMIT_DOMAIN_CAPACITY_PADDED[0..20],
			crate::ROSTRO_DG2_COMMIT_DOMAIN,
		);
		assert_eq!(&DG2_COMMIT_DOMAIN_CAPACITY_PADDED[20..32], &[0u8; 12][..]);

		// "rostro-dg2-commit-v1" packed as 4-byte big-endian limbs:
		//   limb[0] = "rost" = 0x726F7374
		//   limb[1] = "ro-d" = 0x726F2D64
		//   limb[2] = "g2-c" = 0x67322D63
		//   limb[3] = "ommi" = 0x6F6D6D69
		//   limb[4] = "t-v1" = 0x742D7631
		//   limb[5..8] = zero padding
		assert_eq!(DG2_COMMIT_DOMAIN_CAPACITY_LIMBS[0], 0x726F_7374); // "rost"
		assert_eq!(DG2_COMMIT_DOMAIN_CAPACITY_LIMBS[1], 0x726F_2D64); // "ro-d"
		assert_eq!(DG2_COMMIT_DOMAIN_CAPACITY_LIMBS[2], 0x6732_2D63); // "g2-c"
		assert_eq!(DG2_COMMIT_DOMAIN_CAPACITY_LIMBS[3], 0x6F6D_6D69); // "ommi"
		assert_eq!(DG2_COMMIT_DOMAIN_CAPACITY_LIMBS[4], 0x742D_7631); // "t-v1"
		assert_eq!(DG2_COMMIT_DOMAIN_CAPACITY_LIMBS[5], 0);
		assert_eq!(DG2_COMMIT_DOMAIN_CAPACITY_LIMBS[6], 0);
		assert_eq!(DG2_COMMIT_DOMAIN_CAPACITY_LIMBS[7], 0);

		// Round-trip cross-check.
		assert_eq!(
			DG2_COMMIT_DOMAIN_CAPACITY_LIMBS,
			bytes_to_u32_limbs(&DG2_COMMIT_DOMAIN_CAPACITY_PADDED),
		);
	}

	#[test]
	fn dg2_commit_domain_distinct_from_mrz_commit_domain() {
		// Cross-protocol attack defense: the two capacity-init values
		// MUST differ so DG2 hashes never collide with MRZ hashes even
		// for adversarial inputs. Catches a copy-paste error that would
		// homogenize the domain separators.
		assert_ne!(
			DG2_COMMIT_DOMAIN_CAPACITY_LIMBS,
			MRZ_COMMIT_DOMAIN_CAPACITY_LIMBS,
		);
	}

	#[test]
	fn canonical_mrz_size_matches_icao_type3_passport() {
		// ICAO 9303 Type 3 (passport) MRZ is 88 chars: two 44-character
		// lines. Each char is one ASCII byte. 88 / 4 = 22 u32 limbs.
		// If anyone changes CANONICAL_MRZ_LIMBS without justification,
		// the nullifier hash inputs change shape and every existing
		// nullifier becomes unreachable.
		assert_eq!(CANONICAL_MRZ_LIMBS, 22);
		assert_eq!(CANONICAL_MRZ_LIMBS * 4, 88);
	}

	// ─── Bus interaction structural tests ───────────────────────────────
	//
	// Recording builder: drives `eval` and captures every push_interaction
	// call. Verifies that the AIR emits exactly 20 bus messages (10
	// MRZ pair + 10 DG2... wait, 6+4 = 10 absorbs × 2 messages each = 20)
	// across the four expected buses, in the expected order, with the
	// expected sign convention (+1 for sends, -1 for receives).

	use alloc::string::String;
	use p3_air::RowWindow;
	use p3_field::Field;
	use p3_goldilocks::Goldilocks;
	use p3_lookup::InteractionBuilder as InteractionBuilderTrait;

	struct RecordingInteractionBuilder<'a> {
		main_window: RowWindow<'a, Goldilocks>,
		preprocessed_window: RowWindow<'a, Goldilocks>,
		pushed: Vec<(String, Goldilocks, usize, u32)>,
	}

	impl<'a> p3_air::AirBuilder for RecordingInteractionBuilder<'a> {
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
			Goldilocks::ONE
		}
		fn is_last_row(&self) -> Self::Expr {
			Goldilocks::ONE
		}
		fn is_transition_window(&self, _: usize) -> Self::Expr {
			Goldilocks::ZERO
		}
		// Don't enforce constraints — recording is the only purpose.
		fn assert_zero<I: Into<Self::Expr>>(&mut self, _x: I) {}
	}

	impl<'a> InteractionBuilderTrait for RecordingInteractionBuilder<'a> {
		fn push_interaction<E: Into<Self::Expr>>(
			&mut self,
			bus_name: &str,
			fields: impl IntoIterator<Item = E>,
			count: impl Into<Self::Expr>,
			count_weight: u32,
		) {
			let multiplicity: Goldilocks = count.into();
			let collected: Vec<Goldilocks> = fields.into_iter().map(Into::into).collect();
			self.pushed
				.push((String::from(bus_name), multiplicity, collected.len(), count_weight));
		}

		fn push_local_interaction(
			&mut self,
			tuples: impl IntoIterator<Item = (Vec<Self::Expr>, Self::Expr)>,
		) {
			tuples.into_iter().for_each(drop);
		}
	}

	#[test]
	fn eval_emits_expected_bus_interactions() {
		let air = PassportAttestAaRsa2048Sha256Air;
		// Single all-zero row is enough — we're counting structure, not
		// verifying constraint values.
		let main: Vec<Goldilocks> = (0..NUM_COLS).map(|_| Goldilocks::ZERO).collect();
		let main_next = main.clone();
		let pp: Vec<Goldilocks> = Vec::new();
		let pp_next: Vec<Goldilocks> = Vec::new();

		let mut builder = RecordingInteractionBuilder {
			main_window: RowWindow::from_two_rows(&main, &main_next),
			preprocessed_window: RowWindow::from_two_rows(&pp, &pp_next),
			pushed: Vec::new(),
		};
		<PassportAttestAaRsa2048Sha256Air as Air<RecordingInteractionBuilder>>::eval(
			&air,
			&mut builder,
		);

		// 6 MRZ absorbs × 2 (send + recv) + 4 DG2 absorbs × 2 = 20.
		assert_eq!(
			builder.pushed.len(),
			20,
			"expected exactly 20 bus interactions; got {}",
			builder.pushed.len(),
		);

		// Tally by (bus_name, sign). Sends carry +1; receives carry
		// 0 - 1 = -1 in Goldilocks (= p - 1).
		let one = Goldilocks::ONE;
		let neg_one = Goldilocks::ZERO - Goldilocks::ONE;
		let mut mrz_sends = 0;
		let mut mrz_recvs = 0;
		let mut dg2_sends = 0;
		let mut dg2_recvs = 0;
		for (bus, mult, arity, weight) in &builder.pushed {
			assert_eq!(*arity, STATE_WIDTH, "every bus message is exactly WIDTH=8 cells");
			assert_eq!(*weight, 1, "all caller-side messages carry count_weight 1");
			match (bus.as_str(), *mult) {
				(BUS_MRZ_INPUT, m) if m == one => mrz_sends += 1,
				(BUS_MRZ_OUTPUT, m) if m == neg_one => mrz_recvs += 1,
				(BUS_DG2_INPUT, m) if m == one => dg2_sends += 1,
				(BUS_DG2_OUTPUT, m) if m == neg_one => dg2_recvs += 1,
				other => panic!("unexpected bus interaction: {:?}", other),
			}
		}
		assert_eq!(mrz_sends, POSEIDON2_NUM_MRZ_PERMS);
		assert_eq!(mrz_recvs, POSEIDON2_NUM_MRZ_PERMS);
		assert_eq!(dg2_sends, POSEIDON2_NUM_DG2_PERMS);
		assert_eq!(dg2_recvs, POSEIDON2_NUM_DG2_PERMS);
	}

	#[test]
	fn eval_bus_messages_alternate_send_then_recv_per_absorb() {
		// Pin the per-absorb interaction order: each absorb emits a send
		// to the input bus immediately followed by a receive from the
		// output bus. Holds for MRZ (6 absorbs) followed by DG2 (4).
		// Catches accidental reordering that could let a malicious AIR
		// instance pair up the wrong (input, output) by timing.
		let air = PassportAttestAaRsa2048Sha256Air;
		let main: Vec<Goldilocks> = (0..NUM_COLS).map(|_| Goldilocks::ZERO).collect();
		let main_next = main.clone();
		let pp: Vec<Goldilocks> = Vec::new();
		let pp_next: Vec<Goldilocks> = Vec::new();
		let mut builder = RecordingInteractionBuilder {
			main_window: RowWindow::from_two_rows(&main, &main_next),
			preprocessed_window: RowWindow::from_two_rows(&pp, &pp_next),
			pushed: Vec::new(),
		};
		<PassportAttestAaRsa2048Sha256Air as Air<RecordingInteractionBuilder>>::eval(
			&air,
			&mut builder,
		);

		// First 12 entries: 6 MRZ absorb pairs (input then output).
		for absorb in 0..POSEIDON2_NUM_MRZ_PERMS {
			let send_idx = absorb * 2;
			let recv_idx = absorb * 2 + 1;
			assert_eq!(builder.pushed[send_idx].0, BUS_MRZ_INPUT);
			assert_eq!(builder.pushed[recv_idx].0, BUS_MRZ_OUTPUT);
		}
		// Next 8: 4 DG2 absorb pairs.
		let mrz_block = POSEIDON2_NUM_MRZ_PERMS * 2;
		for absorb in 0..POSEIDON2_NUM_DG2_PERMS {
			let send_idx = mrz_block + absorb * 2;
			let recv_idx = mrz_block + absorb * 2 + 1;
			assert_eq!(builder.pushed[send_idx].0, BUS_DG2_INPUT);
			assert_eq!(builder.pushed[recv_idx].0, BUS_DG2_OUTPUT);
		}
	}
}
