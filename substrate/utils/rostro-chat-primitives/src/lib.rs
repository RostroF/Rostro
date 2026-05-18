// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # Rostro chat primitives
//!
//! Wire types and pure-function verification primitives for the Rostro
//! decentralized chat layer. Lives on the general (non-validator) gossip
//! channel; access is gated by the canonical-files gate. The chat layer
//! is dumb routing of encrypted blobs between authenticated SS58
//! endpoints — all access control lives upstream of it.
//!
//! ## What's in this crate
//!
//! - [`stripe`]: XOR-stripe split/combine for relay-side ciphertext
//!   privacy. Sender splits ciphertext into N shares such that any
//!   single relay holds noise rather than partial ciphertext; recipient
//!   reconstructs by XORing all N together. Information-theoretic
//!   confidentiality against `<N` colluders.
//! - [`descriptor`]: Share descriptor + 256-bit ID types
//!   (`MessageId`, `GroupId`, `RecipientHash`) + block-anchored TTL
//!   helpers. SCALE-encoded wire types, `no_std`-compatible.
//! - [`envelope`]: Sealed Sender envelope. Outer envelope reveals only
//!   `{target, ciphertext_share, sender_blob}`; sender SS58 is encrypted
//!   inside `sender_blob` to recipients only. Mirrors Signal's Sealed
//!   Sender pattern, adapted for SCALE encoding.
//! - [`verify`]: Per-response verification primitives (signature checks,
//!   HMAC checks, TTL checks). Caller supplies session state; this crate
//!   doesn't own MLS or Double Ratchet — those plug in at the boundary.
//!
//! ## What's NOT in this crate
//!
//! No libp2p, no `sc-network`, no async runtime, no MLS implementation,
//! no Double Ratchet implementation. Each is a separate concern that
//! plugs into these primitives at well-defined boundaries:
//!
//! - **MLS** (group session state) consumes [`envelope`] types to wrap
//!   group-encrypted ciphertexts.
//! - **Double Ratchet** (pairwise session state) consumes [`envelope`]
//!   types for pairwise DMs.
//! - **libp2p binding** in `gemini-node` carries [`stripe`] shares over
//!   protocol streams + publishes [`descriptor`] entries to the DHT.
//!
//! Keeping these primitives transport-agnostic means they're testable
//! without spinning up async runtimes or networking stacks, and the
//! wire format is decoupled from any particular transport binding.
//!
//! ## Apache-2.0 stays Apache-2.0
//!
//! Three minimal workspace deps (`codec`, `sp-crypto-hashing`,
//! `ed25519-zebra`); no Substrate-client dependencies. Lives in
//! `substrate/utils/`, consistent with the project's "Apache-2.0
//! utilities go here, not in `substrate/client/`" convention.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod descriptor;
pub mod envelope;
pub mod fetch_protocol;
pub mod store_protocol;
pub mod stripe;
pub mod verify;
