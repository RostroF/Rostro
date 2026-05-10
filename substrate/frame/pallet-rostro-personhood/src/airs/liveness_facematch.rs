// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! `liveness_facematch` AIR — verifies the biometric layer of a PoP mint:
//! a live selfie was actually captured (not a photo or replay) AND the
//! captured face matches the chip's DG2 photo bytes.
//!
//! Witnesses (private inputs):
//! - Pre-extracted facial landmarks from N selfie frames (N ≥ 3)
//! - Stability commitment across frames (point-mapping consistency)
//! - DG2 bytes (chip's photo)
//! - Pre-extracted DG2 facial landmarks
//! - Match score / distance vector between selfie-landmarks and DG2-landmarks
//!
//! Public inputs match `crate::LivenessPublicInputs<AccountId, BlockNumber>`:
//! `dg2_hash ‖ bound_account ‖ liveness_passed ‖ anchor.{block,hash}`.
//!
//! Constraint commitments per `pop_design_section1_circuits.md`:
//! - `dg2_hash == hash(witnessed_dg2_bytes)` (the same `dg2_hash` that
//!   appears in the paired `passport_attest_*` proof — cross-proof binding)
//! - Witnessed selfie landmarks are stable across frames within a tolerance
//! - Witnessed DG2 landmarks come from the witnessed DG2 bytes
//! - Match-score between landmark sets is below the spoof threshold
//! - `liveness_passed` boolean reflects the conjunction of the above
//!
//! ## Trust scoping
//!
//! The landmark extraction itself happens off-circuit (on-device) and is
//! transitively trusted via the user's active zkpki HW cert. Without that
//! trust anchor, a malicious app could fabricate landmarks. The PoP mint
//! requires both an active HW cert AND a valid liveness proof; if either
//! is absent or compromised, the mint is rejected.
//!
//! Per the no-cross-purpose-files rule, this circuit shares no helper
//! functions or column layout with the `passport_attest_*` circuits. The
//! cross-proof binding is enforced **at the pallet layer** via
//! `passport.dg2_hash == liveness.dg2_hash` — not by sharing decoder code.
//!
//! ## Reference material (verified 2026-05-09 by code survey)
//!
//! zkpassport's `lib/facematch/` IS a partial reference for this AIR —
//! they verify Apple/Google attestation chains in-circuit AND bind to
//! DG2 hash via DER-extracted client_data. **However**, the in-circuit
//! attestation-chain portion is **deferred** for our build pending
//! dotwave's distribution strategy decision (see "Deferred scope" below).
//! Today this AIR's responsibility is the biometric layer only —
//! landmark stability + facematch + DG2 binding. HW attestation runs
//! at the pallet boundary via zkpki HIP (`T::ZkPki::verify_cert_and_hip`)
//! regardless of distribution channel.
//!
//! - DG2-hash extraction from DER pattern: `~/Polkadot/zkpassport/circuits/src/noir/lib/facematch/src/lib.nr`
//!   (the `get_dg2_hash_from_client_data` flow — DER traversal to find
//!   `FaceMatchAttestation.dg2Hash.digest` OCTET STRING)
//!
//! Translation gaps (their design → ours):
//!
//! - They commit attestation params into a single `param_commitment`
//!   public input. We expose `bound_account` + `anchor` separately and
//!   bind them per-field at the pallet boundary.
//! - They bind `dg2_hash` via the salted-witnessed value pattern (DG2
//!   hash never appears as a public input). We expose `dg2_hash`
//!   directly so the pallet enforces `passport.dg2_hash == liveness.dg2_hash`
//!   without trusting a commitment hash.
//!
//! ## Deferred scope (parked 2026-05-09 pending dotwave distribution decision)
//!
//! In-circuit Apple App Attest / Google KeyMint + Play Integrity
//! attestation-chain validation is OUT OF SCOPE for this AIR until
//! dotwave's distribution channel is decided (Play Store + App Store vs
//! self-distributed F-Droid / direct APK / sideload). Without
//! Play-Store-blessed distribution, Play Integrity verdicts return
//! `UNEVALUATED` and the entire branch is dead weight; same shape on
//! iOS where App Attest requires App Store / TestFlight blessing.
//!
//! The KeyMint cert chain + RootOfTrust extraction (verified_boot_state,
//! device_locked, etc.) ARE meaningful regardless of distribution and
//! are already covered by our zkpki HIP at the pallet layer. The only
//! thing in-circuit attestation would add beyond HIP is per-mint-call
//! freshness, which we already get by calling `verify_cert_and_hip`
//! from `mint_pop` directly.
//!
//! When distribution is decided: if Play Store / App Store, revisit
//! adding the full in-circuit attestation chain (zkpassport's
//! `bin/facematch/{ios,android}/...` flows are the reference). If
//! self-distributed, this section stays out of scope permanently and
//! HIP-only HW attestation is the design.
//!
//! ## Status
//!
//! **SCAFFOLD only.** Constraint design lands in a follow-up commit.

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::Field;

/// Total trace columns. Placeholder until the constraint design lands.
pub const NUM_COLS: usize = 0;

/// AIR for the liveness + facematch path. Stateless; no parameters.
pub struct LivenessFacematchAir;

impl<F: Field> BaseAir<F> for LivenessFacematchAir {
	fn width(&self) -> usize {
		NUM_COLS
	}
}

impl<AB: AirBuilder> Air<AB> for LivenessFacematchAir
where
	AB::F: Field,
{
	fn eval(&self, _builder: &mut AB) {
		// TODO(PoP-Liveness): constraint set per the commitments listed
		// in the module docstring. Landmark-comparison constants
		// (tolerance windows, spoof thresholds) MUST live in this module
		// only — never reused by another circuit module.
	}
}
