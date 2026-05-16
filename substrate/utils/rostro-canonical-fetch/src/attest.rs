// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Canonical-root attestation protocol primitives.
//!
//! Phase 7b step 5.
//!
//! When two Rostro nodes establish a libp2p connection, they exchange
//! a canonical-root attestation before normal protocol gossip is
//! allowed to proceed. Each side asks the other "what's your view of
//! the canonical-files Merkle root?" and verifies the answer against
//! the on-chain `CanonicalFilesApi::canonical_root()` value (which is
//! the authoritative reference, since both peers are by definition
//! reading the same chain state).
//!
//! ## What this catches
//!
//! - **Honest drift.** Operator forgot to upgrade. Their gemini-node
//!   computes a stale canonical_root from its (out-of-date) local
//!   files. Attestation says: "your root doesn't match chain's
//!   root." Peer is routed to the heal flow — they fetch missing
//!   bytes via [`crate::FetchTransport`], stage, exit code 90,
//!   supervisor swaps, comes back current.
//! - **Trivial fake roots.** A peer that claims a deliberately
//!   different root than the chain's. The asker compares against
//!   on-chain canonical_root and rejects.
//!
//! ## What this does NOT catch
//!
//! - **Sophisticated tampering.** A binary that lies *convincingly*
//!   — i.e., reports the chain's canonical_root verbatim while
//!   actually executing arbitrary bytes. This protocol is purely a
//!   self-report; without hardware-rooted measurement (Phase 6.9
//!   TPM/Strongbox attestation), there is no cryptographic proof of
//!   file possession. Defending against that class is what Phase
//!   6.9 plugs in for. Step 5 is a soft attestation that catches
//!   the bulk of real-world drift (honest mistakes, lazy
//!   tampering); 6.9 makes it unfakeable.
//!
//! ## Protocol shape
//!
//! Asymmetric request/response per peer pair. On connection, each
//! side issues an [`AttestationRequest`] with a fresh nonce. The
//! responder builds an [`AttestationResponse`] carrying its locally-
//! computed canonical_root (read from the on-chain registry via
//! `CanonicalFilesApi::canonical_root()` at the latest block it
//! knows about). The asker calls [`verify`], compares the response's
//! claim to its own on-chain canonical_root, and routes the result.
//!
//! The nonce defends against replay (same response can't be cached
//! and re-sent for a different challenge). Without hardware
//! attestation it doesn't prove freshness in any cryptographic sense
//! — but it's a cheap protocol-layer hygiene measure.

use codec::{Decode, Encode};

/// On-the-wire attestation request: a fresh challenge nonce. The
/// nonce isn't cryptographically bound to anything in this protocol
/// (Phase 5 is soft attestation; 6.9 adds hardware binding) but it
/// gives the asker a way to correlate response → request and
/// rejects naïve cached-response replay.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct AttestationRequest {
	pub nonce: [u8; 32],
}

/// On-the-wire attestation response. Carries the responder's view
/// of the canonical-files Merkle root (computed from its on-chain
/// `CanonicalFilesApi::canonical_root()` at the latest block it has
/// imported), echoed nonce, and a self-reported peer role hint.
///
/// **The role hint is informational, not authoritative.** The asker
/// must verify role independently against the on-chain validator
/// set, session-key registration, etc. — a malicious peer can claim
/// to be `NonValidator` to dodge slashing. The asker's
/// [`drift_action`] consults the *asker's* on-chain knowledge of
/// the peer's role, not the response's claim.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct AttestationResponse {
	/// Echoed nonce from the request, for correlation.
	pub nonce: [u8; 32],
	/// Responder's locally-computed canonical-files Merkle root.
	pub claimed_root: [u8; 32],
	/// Self-reported role. Informational only.
	pub claimed_role: PeerRole,
}

/// What role the peer plays on the network. Determines drift-
/// remediation routing: validators with drift get slashed (Phase 7b
/// step 6 hook); non-validators with drift are routed to the heal
/// flow (Phase 7b step 4 already wired in gemini-node).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub enum PeerRole {
	/// Active-set validator. Drift here is a slashable offense.
	Validator,
	/// Non-validator full node, light client, or operator. Drift
	/// triggers heal, no slash.
	NonValidator,
	/// Role unknown to the asker. Conservative: disconnect; do not
	/// slash (no evidence) and do not assume heal will work
	/// (peer might not have the heal flow wired).
	Unknown,
}

/// Outcome of [`verify`] — peer's claimed root vs. authoritative
/// on-chain canonical_root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationOutcome {
	/// Peer's claimed root matches the chain's canonical root. Pass.
	Match,
	/// Nonce in the response doesn't echo the request. Indicates a
	/// confused or malicious responder; do not trust.
	NonceMismatch { sent: [u8; 32], echoed: [u8; 32] },
	/// Claimed root differs from the chain's canonical_root. Drift
	/// detected; route via [`drift_action`].
	RootMismatch {
		peer_claimed: [u8; 32],
		chain_canonical: [u8; 32],
	},
}

/// Routing decision for a confirmed [`AttestationOutcome::RootMismatch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriftAction {
	/// Peer is a known non-validator. Disconnect from any consensus-
	/// relevant protocols, but keep the heal-flow channel open so
	/// they can pull the correct bytes via [`crate::FetchTransport`]
	/// and self-recover.
	AwaitPeerHeal,
	/// Peer is in the active validator set. Disconnect AND surface a
	/// drift event to the slashing pipeline (Phase 7b step 6 hook).
	/// Do NOT serve heal bytes — a drifted validator is misbehaving,
	/// not just stale.
	SlashValidator,
	/// Peer's role is unknown. Conservative: disconnect, no slash,
	/// no heal. They can reconnect after their role is established
	/// or they've upgraded.
	Disconnect,
}

/// Verify a peer's [`AttestationResponse`] against the asker's local
/// view of the on-chain canonical_root. Caller is responsible for
/// reading `chain_canonical_root` from the runtime API
/// (`CanonicalFilesApi::canonical_root()`) at the latest block.
pub fn verify(
	request: &AttestationRequest,
	response: &AttestationResponse,
	chain_canonical_root: [u8; 32],
) -> AttestationOutcome {
	if response.nonce != request.nonce {
		return AttestationOutcome::NonceMismatch {
			sent: request.nonce,
			echoed: response.nonce,
		};
	}
	if response.claimed_root != chain_canonical_root {
		return AttestationOutcome::RootMismatch {
			peer_claimed: response.claimed_root,
			chain_canonical: chain_canonical_root,
		};
	}
	AttestationOutcome::Match
}

/// Decide what to do about a peer that has confirmed
/// [`AttestationOutcome::RootMismatch`]. The role argument is the
/// asker's authoritative view of the peer's role (e.g., from
/// the on-chain validator set), NOT the peer's self-reported
/// `claimed_role` from the attestation response.
pub fn drift_action(asker_known_role: PeerRole) -> DriftAction {
	match asker_known_role {
		PeerRole::Validator => DriftAction::SlashValidator,
		PeerRole::NonValidator => DriftAction::AwaitPeerHeal,
		PeerRole::Unknown => DriftAction::Disconnect,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	const NONCE_A: [u8; 32] = [0x11; 32];
	const NONCE_B: [u8; 32] = [0x22; 32];
	const ROOT_CANONICAL: [u8; 32] = [0xCA; 32];
	const ROOT_DRIFTED: [u8; 32] = [0xDD; 32];

	fn req(nonce: [u8; 32]) -> AttestationRequest {
		AttestationRequest { nonce }
	}

	fn resp(
		nonce: [u8; 32],
		claimed_root: [u8; 32],
		claimed_role: PeerRole,
	) -> AttestationResponse {
		AttestationResponse { nonce, claimed_root, claimed_role }
	}

	#[test]
	fn request_scale_roundtrip() {
		let r = req(NONCE_A);
		let bytes = r.encode();
		let decoded = AttestationRequest::decode(&mut &bytes[..]).unwrap();
		assert_eq!(r, decoded);
	}

	#[test]
	fn response_scale_roundtrip() {
		let r = resp(NONCE_A, ROOT_CANONICAL, PeerRole::Validator);
		let bytes = r.encode();
		let decoded = AttestationResponse::decode(&mut &bytes[..]).unwrap();
		assert_eq!(r, decoded);
	}

	#[test]
	fn verify_passes_on_matching_root_and_nonce() {
		let outcome = verify(
			&req(NONCE_A),
			&resp(NONCE_A, ROOT_CANONICAL, PeerRole::NonValidator),
			ROOT_CANONICAL,
		);
		assert_eq!(outcome, AttestationOutcome::Match);
	}

	#[test]
	fn verify_rejects_nonce_mismatch_before_root_check() {
		// Even if the root happens to match, a wrong nonce makes the
		// response untrustworthy (replay or confused responder).
		let outcome = verify(
			&req(NONCE_A),
			&resp(NONCE_B, ROOT_CANONICAL, PeerRole::Validator),
			ROOT_CANONICAL,
		);
		match outcome {
			AttestationOutcome::NonceMismatch { sent, echoed } => {
				assert_eq!(sent, NONCE_A);
				assert_eq!(echoed, NONCE_B);
			},
			other => panic!("expected NonceMismatch, got {:?}", other),
		}
	}

	#[test]
	fn verify_reports_root_mismatch_when_drifted() {
		let outcome = verify(
			&req(NONCE_A),
			&resp(NONCE_A, ROOT_DRIFTED, PeerRole::Validator),
			ROOT_CANONICAL,
		);
		match outcome {
			AttestationOutcome::RootMismatch { peer_claimed, chain_canonical } => {
				assert_eq!(peer_claimed, ROOT_DRIFTED);
				assert_eq!(chain_canonical, ROOT_CANONICAL);
			},
			other => panic!("expected RootMismatch, got {:?}", other),
		}
	}

	#[test]
	fn drift_action_validator_slashes() {
		assert_eq!(drift_action(PeerRole::Validator), DriftAction::SlashValidator);
	}

	#[test]
	fn drift_action_non_validator_awaits_heal() {
		assert_eq!(drift_action(PeerRole::NonValidator), DriftAction::AwaitPeerHeal);
	}

	#[test]
	fn drift_action_unknown_disconnects() {
		assert_eq!(drift_action(PeerRole::Unknown), DriftAction::Disconnect);
	}

	#[test]
	fn role_self_report_is_advisory_not_authoritative() {
		// A drifted peer claims to be NonValidator (hoping to dodge
		// slash). The asker, using its OWN authoritative view that
		// this peer is in the active validator set, should still
		// route to SlashValidator. This test documents that
		// `drift_action` takes the asker's role (the second
		// argument, conceptually), not the response's
		// `claimed_role`.
		let attacker_response = resp(NONCE_A, ROOT_DRIFTED, PeerRole::NonValidator);
		let outcome =
			verify(&req(NONCE_A), &attacker_response, ROOT_CANONICAL);
		assert!(matches!(outcome, AttestationOutcome::RootMismatch { .. }));
		// Asker knows the peer is actually a Validator (via its own
		// on-chain query, not the peer's self-report).
		let action = drift_action(PeerRole::Validator);
		assert_eq!(action, DriftAction::SlashValidator);
	}

	#[test]
	fn peer_role_scale_roundtrip() {
		for role in [PeerRole::Validator, PeerRole::NonValidator, PeerRole::Unknown] {
			let bytes = role.encode();
			let decoded = PeerRole::decode(&mut &bytes[..]).unwrap();
			assert_eq!(role, decoded);
		}
	}
}
