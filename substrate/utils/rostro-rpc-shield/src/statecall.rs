// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! `state_call` method policy.
//!
//! `state_call` invokes a runtime API method by name. Substrate exposes
//! it unauthenticated by default. Many runtime API methods are unsafe
//! to call externally: they may panic on every invocation (when they
//! call offchain-only host functions), they may return very large
//! responses (bandwidth amplification), or they may perform unbounded
//! work (CPU DoS).
//!
//! This module classifies each runtime API method into one of four
//! policies, and the [`StateCallPolicy::lookup`] function returns the
//! policy for an arbitrary method name. Methods absent from the table
//! default to [`MethodPolicy::Deny`] — explicit allowlist, not
//! denylist.

/// Policy class for a `state_call` method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodPolicy {
	/// Cheap, side-effect-free, safe response size. Subject to per-source
	/// rate limit but no per-method cap.
	PublicSafe,
	/// Externally callable but expensive; per-method rate limit applies.
	PublicGated,
	/// Only callable from loopback (development tools, validator-side
	/// equivocation reporting). External callers receive Deny.
	LocalOnly,
	/// Always denied. Reserved for runtime APIs known to panic on
	/// every call or known to be a strict bandwidth amplifier.
	Deny,
}

/// Policy table for `state_call` method names. Lookup is a linear scan
/// — the table is small (~30 entries) and lookups are not on a hot
/// path that justifies a more complex structure.
pub struct StateCallPolicy;

impl StateCallPolicy {
	/// Resolve a runtime API method name to a policy.
	///
	/// Methods are referenced by their wire name, e.g.
	/// `"Core_version"`, not by their Rust path.
	pub fn lookup(method: &str) -> MethodPolicy {
		// Check exact matches first; they short-circuit prefix scans.
		match method {
			// ----- DENY: known panic vectors or amplifiers -----
			//
			// F-NEW-2: ring_context returns ~580KB of KZG SRS per call,
			// unauthenticated. Bandwidth amplification.
			"SassafrasApi_ring_context" => MethodPolicy::Deny,
			//
			// F-NEW-1: panics on every external call (offchain-only host fn).
			"SassafrasApi_submit_tickets_unsigned_extrinsic"
			| "SassafrasApi_submit_report_equivocation_unsigned_extrinsic"
			| "GrandpaApi_submit_report_equivocation_unsigned_extrinsic" => MethodPolicy::Deny,

			// ----- LOCAL ONLY: validator-internal -----
			"SassafrasApi_generate_key_ownership_proof"
			| "GrandpaApi_generate_key_ownership_proof"
			| "SessionKeys_generate_session_keys"
			| "SessionKeys_decode_session_keys" => MethodPolicy::LocalOnly,

			// ----- PUBLIC SAFE: cheap reads -----
			"Core_version"
			| "Core_initialize_block"
			| "Metadata_metadata_versions"
			| "AccountNonceApi_account_nonce"
			| "GrandpaApi_grandpa_authorities"
			| "GrandpaApi_current_set_id"
			| "SassafrasApi_current_epoch"
			| "SassafrasApi_next_epoch"
			| "TransactionPaymentApi_query_info"
			| "TransactionPaymentApi_query_fee_details"
			| "TransactionPaymentApi_query_weight_to_fee"
			| "TransactionPaymentApi_query_length_to_fee"
			| "GenesisBuilder_get_preset"
			| "GenesisBuilder_preset_names" => MethodPolicy::PublicSafe,

			// ----- PUBLIC GATED: callable but expensive -----
			//
			// F-6: slot_ticket triggers sort_segments(u32::MAX, ...) when
			// segments are present. Heavy per-method limit.
			"SassafrasApi_slot_ticket"
			| "SassafrasApi_slot_ticket_id"
			// Metadata responses are ~96KB; not catastrophic but
			// worth gating.
			| "Metadata_metadata"
			| "Metadata_metadata_at_version"
			// Block builder operations: structurally fine but expensive.
			| "BlockBuilder_apply_extrinsic"
			| "BlockBuilder_finalize_block"
			| "BlockBuilder_inherent_extrinsics"
			| "BlockBuilder_check_inherents"
			// TaggedTransactionQueue is the F-25-sub vector; pre-decode
			// helps but rate limit is the second layer.
			| "TaggedTransactionQueue_validate_transaction"
			// State queries: read-only but can be made expensive.
			| "GenesisBuilder_build_state" => MethodPolicy::PublicGated,

			// Unknown method: deny by default. New runtime APIs added
			// to the runtime must be classified here before they can
			// be called publicly.
			_ => MethodPolicy::Deny,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn ring_context_is_denied() {
		assert_eq!(
			StateCallPolicy::lookup("SassafrasApi_ring_context"),
			MethodPolicy::Deny,
		);
	}

	#[test]
	fn equivocation_apis_are_denied() {
		assert_eq!(
			StateCallPolicy::lookup("SassafrasApi_submit_tickets_unsigned_extrinsic"),
			MethodPolicy::Deny,
		);
		assert_eq!(
			StateCallPolicy::lookup("GrandpaApi_submit_report_equivocation_unsigned_extrinsic"),
			MethodPolicy::Deny,
		);
	}

	#[test]
	fn key_ownership_proofs_are_local_only() {
		assert_eq!(
			StateCallPolicy::lookup("SassafrasApi_generate_key_ownership_proof"),
			MethodPolicy::LocalOnly,
		);
	}

	#[test]
	fn cheap_reads_are_public_safe() {
		assert_eq!(StateCallPolicy::lookup("Core_version"), MethodPolicy::PublicSafe);
		assert_eq!(
			StateCallPolicy::lookup("AccountNonceApi_account_nonce"),
			MethodPolicy::PublicSafe,
		);
	}

	#[test]
	fn slot_ticket_is_publicly_gated() {
		assert_eq!(
			StateCallPolicy::lookup("SassafrasApi_slot_ticket"),
			MethodPolicy::PublicGated,
		);
	}

	#[test]
	fn unknown_methods_default_to_deny() {
		assert_eq!(StateCallPolicy::lookup("FakeApi_made_up_method"), MethodPolicy::Deny);
		assert_eq!(StateCallPolicy::lookup(""), MethodPolicy::Deny);
	}
}
