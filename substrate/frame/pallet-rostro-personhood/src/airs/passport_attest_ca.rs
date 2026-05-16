// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! `passport_attest_ca` AIR — verifies the **Chip Authentication** (CA)
//! chip-key path of an ICAO 9303 passport (key in DG14, ECDH session-key
//! derivation as the proof-of-possession).
//!
//! Required because German + French + a long tail of EU passports ship
//! CA-only with NO AA (DG15 absent, DG14 present). AA-only would
//! exclude those populations — see `pop_design_section1b_chip_auth_methods.md`
//! for the dual-path lock-in rationale.
//!
//! Witnesses (private inputs):
//! - DG14 bytes (carries the CA static public key per ICAO BSI TR-03110)
//! - Reader's ephemeral private key + corresponding ephemeral public key
//! - ECDH-derived shared secret + key-derivation transcript
//! - SOD bytes + DSC + CSCA chain — proves DG14 is signed by a CSCA-rooted DSC
//! - Canonical-MRZ bytes (raw form for nullifier hashing)
//!
//! Public inputs match `crate::PassportPublicInputs<...>` byte-identical
//! to the AA path — same `bound_account`, same `nullifier`, same `dg2_hash`,
//! same `anchor`, same `csca_root` / `seats_root`, same `ttl_block` /
//! `adult` / `seat_id`. The chain-side `mint_pop` consumer cannot tell
//! AA from CA proofs by inspecting the public inputs; the discriminator
//! is the `chip_auth_method: ChipAuthMethod` arg passed by dotwave at
//! submission time, which dispatches to the matching VK slot.
//!
//! CA-specific constraint commitments:
//! - The reader-supplied ephemeral public key is well-formed (point on curve)
//! - The witnessed shared secret matches `ECDH(reader_eph_priv, dg14_static_pub)`
//! - The session-key derivation matches the witnessed transcript
//! - The CA challenge binding (analogous to AA's signature-over-challenge):
//!   `binding == kdf(shared_secret ‖ anchor_hash ‖ bound_account)`
//! - `dg14_bytes_hash ∈ SOD-signed DG list`
//! - DSC chain → CSCA root membership in `csca_root` merkle tree
//! - `nullifier == Poseidon(canonical_mrz, <scope_domain>)`
//!   (exact domain TBD when this AIR's constraint set lands — the
//!   AA path uses `AA_CHALLENGE_DOMAIN` for its challenge derivation;
//!   CA's nullifier scope is a separate design decision)
//!
//! Per the no-cross-purpose-files rule, this circuit shares no helper
//! functions, no column constants, and no input parsers with `passport_attest_aa`.
//! A discovered vulnerability in the AA constraint set cannot impact
//! CA-path verification correctness (and vice versa). Each is independently
//! patchable + ceremony-rotatable via the existing per-circuit `srt_set_vk`.
//!
//! ## Reference material (verified 2026-05-09 by code survey)
//!
//! zkpassport DOES NOT verify CA's ECDH session-key derivation in-circuit.
//! Same trust-the-reader posture as their AA path. The CA-derivation +
//! binding-against-chain-anchor primitive is **ours to author** with no
//! direct reference, derived from ICAO 9303 / BSI TR-03110 spec +
//! standard ECDH-in-circuit techniques.
//!
//! Lower-level primitives shared with `passport_attest_aa.rs` references:
//!
//! - DG hashing + SOD-list inclusion: `~/Polkadot/zkpassport/circuits/src/noir/lib/data-check/integrity/src/lib.nr`
//! - DG14 hash extraction from DER (analogous to DG2 / DG15 patterns):
//!   same file (the ASN.1 pattern matching is per-DG-tag-keyed; lift the
//!   shape, swap the tag from DG2's to DG14's per ICAO 9303 Doc 9303 Part 10)
//! - MRZ canonical form: same as AA path
//! - Poseidon byte-packing: same `pack_be_bytes_into_fields` adaptation
//!
//! Per the no-cross-purpose-files rule, this circuit shares no helper
//! functions, no column constants, and no input parsers with
//! `passport_attest_aa`. Even the Poseidon nullifier hash that both
//! circuits compute identically gets duplicated, not extracted to a
//! shared helper.
//!
//! ## Status
//!
//! **SCAFFOLD only.** Constraint design lands in a follow-up commit.

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::Field;

/// Total trace columns. Placeholder until the constraint design lands.
pub const NUM_COLS: usize = 0;

/// AIR for the CA passport-attestation path. Stateless; no parameters.
pub struct PassportAttestCaAir;

impl<F: Field> BaseAir<F> for PassportAttestCaAir {
	fn width(&self) -> usize {
		NUM_COLS
	}
}

impl<AB: AirBuilder> Air<AB> for PassportAttestCaAir
where
	AB::F: Field,
{
	fn eval(&self, _builder: &mut AB) {
		// TODO(PoP-CA): constraint set per the commitments listed in the
		// module docstring. Crucially: NO shared evaluator helpers with
		// `passport_attest_aa` even where the math overlaps (e.g., Poseidon
		// nullifier hash) — duplication is cheaper than the cross-circuit
		// dispatch surface a shared helper would create.
	}
}
