// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # rostro-ratchet
//!
//! Pairwise Signal Double Ratchet, written from the spec:
//! <https://signal.org/docs/specifications/doubleratchet/>. Provides per-
//! message forward secrecy AND post-compromise security:
//!
//! - **Per-message forward secrecy**: each message uses a fresh key derived
//!   from a chain that's advanced and the prior chain key deleted. A
//!   compromise of current state cannot decrypt past messages.
//! - **Post-compromise security**: receiving a message with a fresh DH
//!   ratchet pubkey triggers a new DH exchange, deriving a new root key.
//!   After one full round-trip, an attacker holding old key state cannot
//!   decrypt new messages.
//!
//! ## Scope (v0, library only)
//!
//! - Pairwise sessions (one ratchet per peer pair)
//! - X25519 DH (djb-aligned per crypto_stack_v1.md)
//! - HKDF-SHA256 for root-key advancement
//! - HMAC-SHA256 for chain-key advancement (KDF_CK)
//! - ChaCha20-Poly1305 AEAD (already the wire cipher per crypto_stack_v1.md)
//! - Out-of-order receipt with bounded skipped-key cache
//!
//! ## Out of scope at v0
//!
//! - Group / Sender Keys protocol (broadcast). Pairwise only at v0.
//! - Header encryption (Signal's optional second AEAD layer over headers).
//! - Persistent state (serialize/deserialize Session). In-memory only.
//! - X3DH-style asynchronous bootstrap. The v0 caller supplies an initial
//!   shared secret and the responder's DH pubkey directly.
//! - sc-network-gossip integration. That's its own phase.
//!
//! ## License posture
//!
//! Written from spec rather than vendoring `libsignal` (AGPL-3.0,
//! incompatible with our Apache-2.0 tree). Pure RustCrypto primitives.

#![warn(missing_docs)]

mod kdf;
mod ratchet;
mod session;

#[cfg(test)]
mod tests;

pub use ratchet::{Header, MAX_SKIP};
pub use session::{Error, Session};
