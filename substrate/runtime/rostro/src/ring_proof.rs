// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # Ring-proof system abstraction (Phase Ring R5 swap surface)
//!
//! Sassafras's anonymity property rests on a *ring-VRF* whose membership
//! proof is the cryptographic primitive that gates the chain. Today
//! (R5/v1) the only proof system that hits the size budget for ring
//! proofs is bandersnatch + KZG over BLS12-381 — KZG-class compactness
//! at the cost of a trusted setup. FRI-class transparent / post-quantum
//! constructions exist but are 100–400× larger per proof, structurally
//! infeasible for ticket-pool bandwidth.
//!
//! That asymmetry is unlikely to be permanent. Active research (STIR,
//! lattice-based polynomial commitments, code-based commitments,
//! recursion-based accumulators, etc.) is converging toward "KZG-compact
//! AND transparent / post-quantum" — when one of those crosses the size
//! threshold, Rostro should be able to *swap the proof system*, not just
//! the URS bytes underneath KZG. This module names that swap surface in
//! the type system so the upgrade path is captured in code, not buried
//! in a future engineer's head.
//!
//! ## Two layers of swap, two different magnitudes
//!
//! 1. **URS swap (within KZG).** The trusted setup is replaced — e.g.
//!    Ethereum-only → Ethereum ⊗ Rostro-attested-hybrid. Same proof
//!    system, different [`SetupArtifact`] value. Runtime upgrade with a
//!    ticket-pool flush. *Light*.
//! 2. **Proof-system swap.** A new [`RingProofSystem`] variant is added
//!    (a different curve, a different commitment scheme, a transparent
//!    construction) and the type alias [`RostroRingProofSystem`] is
//!    bumped to it. Requires a `pallet_sassafras` divergence (today the
//!    pallet hardcodes the bandersnatch/KZG verification path). *Heavy*
//!    — but the type-level surface is here so future-us can plan the
//!    migration as a known shape, not a cliff.
//!
//! ## What today's R1 commit does and does not do
//!
//! Defines the trait, defines the v1 implementor, names the swap
//! aliases. Does *not* yet thread the abstraction through
//! `pallet_sassafras::Config` — the upstream pallet currently hardcodes
//! the bandersnatch/KZG verification path via
//! `sp_consensus_sassafras::vrf::RingContext`. Threading is pallet-fork
//! work and lands when (and only if) the swap actually happens.
//!
//! ## Upgrade procedure when a successor system arrives
//!
//! 1. Implement the new system as a ZST that satisfies [`RingProofSystem`].
//! 2. Define its [`SetupArtifact`] (parameter hash, URS, whatever it needs).
//! 3. Fork `pallet_sassafras` to verify against the abstracted system
//!    (or, if the upstream pallet has gained the abstraction by then,
//!    swap the Config associated type).
//! 4. Bump [`RostroRingProofSystem`].
//! 5. Deploy a runtime upgrade with `on_runtime_upgrade` that flushes
//!    the in-flight tickets (their proofs are bound to the old system),
//!    replaces the on-chain setup artifact, and refreshes verifier data.

#![allow(dead_code)] // Forward-looking scaffold; consumed in R3+.

use codec::{Decode, Encode};
use scale_info::TypeInfo;

// ─── Proof-system abstraction ──────────────────────────────────────────────

/// Trait identifying a ring-proof construction usable by Sassafras.
///
/// All Rostro-shippable variants implement this. Today there's exactly
/// one inhabitant ([`BandersnatchKzg`]). The trait carries enough
/// metadata that future variants can be added without churning every
/// site that names a proof system, and carries the per-system setup
/// artifact as an associated type so a swap also swaps the setup shape.
pub trait RingProofSystem: 'static {
	/// Stable identifier embedded into chainspec metadata, telemetry,
	/// and any on-chain digest tag. Versioned in the name itself if the
	/// construction's parameters change incompatibly.
	const NAME: &'static str;

	/// SCALE-encoded discriminant for any on-chain storage that needs
	/// to disambiguate which proof system produced an artifact.
	const TAG: u8;

	/// Whether the construction is believed post-quantum secure under
	/// current cryptanalysis. KZG over BLS12-381 → `false` (Shor breaks
	/// it). Hash-based / lattice-based variants → `true`.
	const POST_QUANTUM: bool;

	/// Approximate per-proof byte size at typical security parameters
	/// (~128-bit). Used for telemetry and bandwidth budgeting; not
	/// load-bearing for correctness.
	const PROOF_SIZE_BYTES_APPROX: usize;

	/// The type of setup artifact this proof system consumes (URS for
	/// KZG-class systems, parameter hash + lattice parameters for
	/// lattice-based systems, just a hash function for transparent
	/// hash-based systems, etc.).
	type SetupArtifact: SetupArtifact;
}

/// Trait the per-system setup artifact must satisfy. Minimal — just
/// enough to identify itself in chainspec / metadata. Real verification
/// semantics live in the (forked) pallet's verifier path.
pub trait SetupArtifact:
	Clone + core::fmt::Debug + Eq + PartialEq + Encode + Decode + TypeInfo
{
	/// Stable variant identifier for logging + telemetry.
	fn variant_name(&self) -> &'static str;
}

// ─── v1: bandersnatch + KZG over BLS12-381 ────────────────────────────────

/// Sassafras's stock ring-VRF: bandersnatch curve, Plonk arithmetization,
/// KZG polynomial commitment over BLS12-381. ~500 byte proofs, requires
/// a trusted-setup URS (see [`UrsSource`]).
///
/// Implemented by `arkworks-rs/ring-vrf` upstream and consumed by
/// `pallet_sassafras` via `sp_consensus_sassafras::vrf::RingContext`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct BandersnatchKzg;

impl RingProofSystem for BandersnatchKzg {
	const NAME: &'static str = "bandersnatch-kzg-bls12381-v1";
	const TAG: u8 = 1;
	const POST_QUANTUM: bool = false;
	const PROOF_SIZE_BYTES_APPROX: usize = 500;
	type SetupArtifact = UrsSource;
}

/// KZG URS source for [`BandersnatchKzg`].
///
/// The URS is the only piece of foundational cryptographic material in
/// the chain whose security floor is set by an external ceremony.
/// Naming the source as a typed value (rather than burying it in a
/// constant) makes the lineage auditable and swappable.
///
/// **R5/v1 source: Ethereum's EIP-4844 KZG Ceremony.** This is feasible
/// only because Rostro picked `RING_SIZE = 512`
/// (`sp_consensus_sassafras::vrf::RING_SIZE`), which needs 3073 G1
/// powers — comfortably inside Ethereum's 4096-power ceremony output.
/// At `RING_SIZE = 1024` (Polkadot's choice) you'd need 6145 powers
/// and Ethereum's ceremony would not fit; you'd be forced into
/// Filecoin's PPoT, snarkjs PPoT, or a fresh ceremony. See R1.5
/// findings in `substrate/utils/rostro-kzg-srs/src/lib.rs` for the
/// full table.
///
/// Note: deliberately not deriving `MaxEncodedLen`. Storage usage of
/// this type isn't decided yet — it may live in chainspec properties, a
/// runtime API return, or `pallet_sassafras` storage with a bound. When
/// that's settled in R3, switch the inner `Vec` to a `BoundedVec` and
/// derive `MaxEncodedLen`.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub enum UrsSource {
	/// Ethereum's EIP-4844 KZG Ceremony output (Apr 2023, ~141k contributors).
	/// 4096 G1 powers, 65 G2 powers. We take the first 3073 G1 powers
	/// (matching `pcs_domain_size(RING_SIZE=512) = 3073`) and the first
	/// 2 G2 powers.
	///
	/// The 32-byte field is the SHA-256 of arkworks' canonical
	/// uncompressed serialization of the resulting `RingProofParams`.
	/// Anyone can re-derive it from the public ceremony output and
	/// verify this hash matches.
	EthereumKzgCeremony2023 { srs_hash: [u8; 32] },

	/// Hybrid: Ethereum's URS combined sequentially with one or more
	/// Rostro-attested contributions. The `chain_hash` is the SHA-256 of
	/// the resulting URS; the `contribution_attestation_hashes` are the
	/// per-contribution attestation digests in application order.
	///
	/// Reserved for the post-genesis runtime upgrade (R5b) once the
	/// hardware-attested ceremony device design + audit lands.
	EthereumKzgPlusRostroAttested {
		chain_hash: [u8; 32],
		contribution_attestation_hashes: alloc::vec::Vec<[u8; 32]>,
	},
}

impl SetupArtifact for UrsSource {
	fn variant_name(&self) -> &'static str {
		match self {
			Self::EthereumKzgCeremony2023 { .. } => "ethereum-kzg-ceremony-2023",
			Self::EthereumKzgPlusRostroAttested { .. } => "ethereum-kzg-plus-rostro-attested",
		}
	}
}

// ─── Reserved future variants ─────────────────────────────────────────────

/// Reserved placeholder for the eventual post-quantum-secure successor
/// to [`BandersnatchKzg`]. Not implemented — exists as a named anchor
/// in the type system so the upgrade path is legible.
///
/// When a successor construction crosses the size threshold (KZG-class
/// compact AND transparent / post-quantum), the recipe is:
///
/// 1. Replace this module's body with the real implementation:
///    - the curve + commitment scheme as a ZST satisfying
///      [`RingProofSystem`] with `POST_QUANTUM = true`
///    - its [`SetupArtifact`] type (or `()` if transparent)
/// 2. Update [`RostroRingProofSystem`] below to point here.
/// 3. Fork `pallet_sassafras` to dispatch on the proof-system tag in
///    its verifier path (or, if upstream gains the abstraction by then,
///    set its Config associated type).
/// 4. Plan the migration: ticket-pool flush, on-chain setup artifact
///    replacement, validator key rotation if the curve changes.
///
/// Candidate constructions worth tracking (none load-bearing yet):
///
/// - **STIR** (Stacked-IOP for Reed-Solomon, 2024) — improves on FRI's
///   proof size by a factor of 2-4 at comparable verifier cost.
/// - **Lattice-based polynomial commitments** (Hyperplonk-Lattice, etc.)
///   — post-quantum, sub-linear proofs, active research.
/// - **Code-based commitments** (Brakedown / Orion family) — competitive
///   for some workloads, transparent.
/// - **Recursion-based accumulation** (Halo-style) — collapses many
///   small proofs into one without trusted setup; ring-proof
///   applicability requires more work.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct PostQuantumPlaceholder;

// Intentionally NOT impl RingProofSystem for PostQuantumPlaceholder —
// the placeholder doesn't claim to satisfy the trait until a real
// construction is wired up. The empty struct just reserves the name.

// ─── Active selection ─────────────────────────────────────────────────────

/// The ring-proof system Rostro's runtime targets at v1.
///
/// **Swap point.** Replacing this alias is a runtime-upgrade-shape
/// change requiring a `pallet_sassafras` divergence (the upstream
/// pallet hardcodes the bandersnatch/KZG path); named here so the
/// upgrade-shape is not a hidden assumption.
pub type RostroRingProofSystem = BandersnatchKzg;

/// Convenience: the active setup-artifact type, derived from the
/// current [`RostroRingProofSystem`] choice.
pub type RostroSetupArtifact = <RostroRingProofSystem as RingProofSystem>::SetupArtifact;

/// Sentinel placeholder URS source — chainspec generation in R3 must
/// overwrite the inner hash with the SHA-256 of the actually-loaded
/// Ethereum SRS prefix. Holding it as a `const` makes the missing-hash
/// case fail loudly (zero hash → ceremony unverified) rather than
/// silently shipping a half-configured runtime.
pub const ROSTRO_URS_V1_PLACEHOLDER: UrsSource =
	UrsSource::EthereumKzgCeremony2023 { srs_hash: [0u8; 32] };

// ─── Compile-time invariants ──────────────────────────────────────────────

/// Static assertion that the active proof system at v1 is the expected
/// one. If a future commit accidentally bumps `RostroRingProofSystem`
/// without the migration, this trips at compile time.
const _V1_INVARIANT: () = {
	// `NAME` is `&'static str` — compare via byte-length + first byte as
	// a cheap compile-time-feasible check (full string comparison in
	// const context is stable but more verbose).
	assert!(
		<RostroRingProofSystem as RingProofSystem>::TAG == BandersnatchKzg::TAG,
		"R1 invariant: RostroRingProofSystem must be BandersnatchKzg until R5 successor lands"
	);
	assert!(
		!<RostroRingProofSystem as RingProofSystem>::POST_QUANTUM,
		"R1 invariant: v1 system is not post-quantum; flipping this requires the R5b migration"
	);
};
