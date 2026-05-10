// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Plonky3 AIRs for the personhood verifier path.
//!
//! Each circuit family lives in its own module file — siloed per the
//! no-cross-purpose-files security principle (see
//! `feedback_no_cross_purpose_files.md`). A bug in one circuit's
//! `eval` cannot influence another's verification dispatch because
//! they share no helpers, no traits beyond Plonky3's own
//! [`p3_air::Air`], no input parsers, no column constants.
//!
//! These AIRs are SCAFFOLDS as of 2026-05-09. The constraint sets are
//! TODO and reference zkpassport's Apache-2.0 Noir circuits as the
//! logical specification — not as code to lift. Each must be
//! independently audited before mainnet.

pub mod liveness_facematch;
// AA family — one module per (signature_algorithm, hash_algorithm) combination
// per `pop_algorithm_coverage_zkpassport_mirror.md`. Each combo is its own
// AIR file with its own VK slot and its own Plonky3ProofVerifier method.
// First combo authored: RSA-2048 + SHA-256 (US/UK passport coverage).
pub mod passport_attest_aa_rsa2048_sha256;
// CA family — same per-algorithm pattern. To be expanded in parallel as AA
// algorithms land.
pub mod passport_attest_ca;
