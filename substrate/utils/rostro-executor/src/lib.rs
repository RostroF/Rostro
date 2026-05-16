// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! # rostro-executor — PVM runtime executor for Rostro
//!
//! Apache-2.0 implementation of the substrate runtime executor surface,
//! targeting the vendored rostrovm fork at `substrate/external/rostrovm/`
//! (polkavm 0.32 + Tier 2 crypto intrinsics + audit hardening). Replaces
//! the inherited GPL-3.0 `rc-executor-polkavm` so the Rostro runtime path
//! can ship under Apache-2.0 — see [[feedback_client_dir_gpl3]].
//!
//! ## Scope (Phase Star, workstream B)
//!
//! This crate is built in stages on the `phase-star` branch:
//!
//! - **B1** (this commit) — crate scaffold, workspace registration. No
//!   functionality yet.
//! - **B2** — engine/module/instance lifecycle against the fork, call
//!   dispatch, trap → `WasmError` mapping, gas → `Weight` conversion
//!   (1 RVM gas ≈ 1 ns; ×1000 at the substrate boundary).
//! - **B3a/b/c** — `sp-io` host-fn bindings: storage, hashing + crypto
//!   (routing ed25519 and secp256k1_recover through the Tier 2 intrinsics
//!   so ZIP-215 + strict-mode rejection are inherited from the fork),
//!   allocator + logging + trie.
//!
//! Once B1–B3 land, [`rostro-runtime-builder`] (workstream B4) lets a
//! runtime crate cross-compile to a PVM blob, and B6+ wires this crate
//! into `rostro-node` (and later `gemini-node`).
//!
//! ## Non-goals
//!
//! - Smart-contract execution. Camino is runtime-only; the contract VM
//!   question is deferred. This crate is the chain-runtime executor, not
//!   a contract executor.
//! - WASM execution. `rc-executor-wasmtime` keeps the WASM path until
//!   workstream B9 retires it.

#![cfg_attr(not(feature = "std"), no_std)]

// Module layout is the planned shape; modules are added stage-by-stage
// rather than declared empty up front, so the surface this crate exposes
// always matches what's actually implemented.
