// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # rostro-consensus-sassafras
//!
//! Node-side client for Sassafras consensus. Phase Ring's R2 deliverable.
//!
//! ## Why this crate exists
//!
//! Upstream `paritytech/polkadot-sdk` ships the runtime side of
//! Sassafras (`pallet-sassafras` + `sp-consensus-sassafras`) but has
//! never published a node-side client. The `substrate/client/consensus/`
//! tree has aura, babe, beefy, grandpa, manual-seal, pow, slots — no
//! sassafras. This crate fills the gap.
//!
//! Apache-2.0 (not GPL-3.0 like the upstream `rc-consensus-*` siblings)
//! and lives outside `substrate/client/` deliberately — that subtree
//! is the GPL-3.0 zone in our fork's license posture.
//!
//! ## Naming
//!
//! Polkadot's documentation has rebranded the protocol to "Safrole"
//! ([wiki][1]), but the actual SDK code (pallet, primitives, all
//! references in upstream `master` as of 2026-05-05) still uses
//! Sassafras. We follow the SDK code, not the documentation rebrand;
//! if upstream renames the pallet, we follow at that point.
//!
//! [1]: https://wiki.polkadot.com/learn/learn-safrole/
//!
//! ## Phase Ring R2 stages
//!
//! - **R2a (this commit)** — `slot_claim` verifier. Pure-crypto: given
//!   a `SlotClaim` digest, the epoch's authorities + randomness +
//!   index, decide whether the bandersnatch IETF VRF signature is
//!   valid. No IO, no runtime API calls. Foundation that R2b's import
//!   queue and R2c's slot worker compose on.
//! - R2b — block-level import-queue verifier wrapping `slot_claim`,
//!   plus `aux_schema` for epoch-state persistence across restarts.
//! - R2c — slot worker (block production): claim slots, drive proposer.
//! - R2d — ticket generation worker (epoch-start ring-VRF tickets +
//!   unsigned-extrinsic submission, riding rostro-ratchet for the
//!   peer-to-peer relay channel since `pallet-sassafras` rejects
//!   tickets from `TransactionSource::External`).
//! - R2e — equivocation reporter (double-sign detection + slashing
//!   report).
//!
//! ## What R2a explicitly does NOT do
//!
//! - No ticket-claim verification. `SlotClaim::ticket_claim` is the
//!   ephemeral signature proving the block author held the
//!   ticket-binding key; verifying it requires the runtime API
//!   (`SassafrasApi::slot_ticket`) to learn which ticket is bound to
//!   the slot. That cross-check is import-queue territory (R2b) where
//!   we have a `Client` handle.
//! - No fallback-slot logic. If a slot has no assigned ticket, the
//!   protocol falls back to a deterministic-but-not-anonymous selection
//!   from the active set. R2b decides which path applies; R2a just
//!   verifies the VRF.
//! - No randomness derivation. The caller provides the epoch's
//!   randomness; deriving it from chain state is the runtime's job.

#![warn(missing_docs)]

pub mod aux_schema;
pub mod client_providers;
pub mod epoch;
pub mod equivocation;
pub mod equivocation_reporter;
pub mod error;
pub mod header;
pub mod import_verifier;
pub mod producer;
pub mod providers;
pub mod signer;
pub mod slot_claim;
pub mod slot_driver;
pub mod slot_worker;
pub mod ticket_claim;
pub mod ticket_generation;
pub mod ticket_submission;
pub mod verifier;

#[cfg(test)]
mod tests;

pub use aux_schema::CachedEpochProvider;
pub use client_providers::ClientProviders;
pub use epoch::EpochContext;
pub use equivocation::EquivocationDetector;
pub use equivocation_reporter::{process_equivocation, ReportOutcome};
pub use error::VerificationError;
pub use header::{extract_consensus_log, extract_next_epoch_descriptor, extract_slot_claim};
pub use import_verifier::SassafrasImportVerifier;
pub use producer::{produce_primary_slot_claim, produce_slot_claim, produce_ticket_claim};
pub use providers::{
	EpochProvider, EquivocationReporter, KeyOwnershipProver, ProviderError, TicketProvider,
};
pub use signer::{BandersnatchVrfSigner, KeystoreSigner};
pub use slot_claim::verify_slot_claim;
pub use slot_driver::{start_sassafras, SassafrasClaim, StartSassafrasParams};
pub use slot_worker::{fallback_winner_index, try_claim_slot, ClaimDecision};
pub use ticket_claim::{signed_data_for_ticket_binding, verify_ticket_claim};
pub use ticket_generation::{compute_ticket_id, produce_ticket_envelope};
pub use ticket_submission::{
	submit_batch, ticket_threshold, SubmissionStats, TicketSubmitter, TicketThresholdParams,
};
pub use verifier::{verify_block, verify_header, VerifiedHeader};
