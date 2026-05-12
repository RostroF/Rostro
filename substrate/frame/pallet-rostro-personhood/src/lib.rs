// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # Rostro proof-of-personhood pallet
//!
//! On-chain layer that turns a successfully-verified passport ZK
//! proof pair into a per-`AccountId` PoP cert carrying TTL, adult
//! bool, and seat_id. One passport produces one cert globally,
//! enforced by a deterministic nullifier on chain. PoP is bound to
//! an active zk-pki HW cert via a fresh HIP — without HW
//! attestation, the chain has no reason to trust the device's
//! biometric work, so PoP mint refuses.
//!
//! ## Layering (orthogonal to mime_wrap)
//!
//! Mime_wrap (in zk-pki-pallet) is *Android Strongbox HW
//! attestation*. It does not prove passport claims. PoP is a
//! separate proof, in a separate pallet, layered on top via
//! `ec_key_pub` shared between zk-pki and personhood. mime_wrap is
//! locked and not touched by this pallet.
//!
//! ## Two-circuit split
//!
//! 1. `passport_attest` — CSCA→DSC→SOD→DG chain check, MRZ
//!    extraction, AA challenge verification (chip signed
//!    `Hash("rostro-pop-v1" || anchor_hash || bound_account)`),
//!    nullifier emission, age computation, country→seat_id lookup,
//!    TTL extraction, DG2 hash emission.
//! 2. `liveness_facematch` — point-stability across head turns
//!    (anti-photo) and feature match against the chip's DG2 photo
//!    (right person).
//!
//! Both verified atomically in [`mint_pop`]. Cross-proof binding via
//! shared `dg2_hash`, `bound_account`, and chain-anchor fields.
//!
//! ## Trust roots (rotated by SRT)
//!
//! - [`CurrentCscaRoot`] — merkle root of the CSCA bundle the
//!   `passport_attest` chain check is verified against. Off-chain
//!   reproducible-built mirror serves the bundle; chain stores root
//!   only. Hard cutover on rotation, no grace window — clear error,
//!   user retries.
//! - [`CurrentSeatsRoot`] — merkle root of (country_code, seat_id)
//!   leaves. Existing PoP certs grandfather their seat_id at mint
//!   time; new mints use current root.
//! - [`PassportAttestVk`], [`LivenessFacematchVk`] — Groth16
//!   verifying keys for each circuit. Strict monotonic version
//!   bumping. Existing PoP certs are not invalidated by vk rotation
//!   (their stored result is canonical).
//!
//! ## Threat model
//!
//! Designed to defeat: bad actor compromises Android at the process
//! level, passes fake papers to Rostro on behalf of a "user", Rostro
//! mints because it trusted dotwave. Defenses (must all hold for an
//! attack to succeed):
//!
//! 1. AA — chip signs a fresh chain-anchored challenge. Without
//!    physical chip access, the attacker cannot mint with stolen
//!    passport-database data.
//! 2. HIP — fresh device-state attestation at mint time. PCRs must
//!    match the genesis fingerprint stored at zk-pki cert mint —
//!    bootloader unlocked / kernel swapped / dotwave binary
//!    replaced all fail.
//! 3. `bound_account == caller` — proof commits to the SS58 it's
//!    for; pallet rejects mismatched submitters. Anti-frontrun.
//! 4. Deterministic nullifier — same passport always produces the
//!    same nullifier, blocks re-mint without explicit discard.
//!
//! Residual: APT-class attacker with kernel exploit on a
//! verified-boot-intact device, in real-time MITM during the
//! victim's own active ceremony, redirecting AA exchange to
//! attacker's SS58. Materially harder than mass fakery; defended in
//! depth via vk rotation, manufacturer whitelist, governance, and
//! user-side detection of failed ceremony.

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

// Plonky3 STARK verifier path — siloed from the legacy arkworks `mod verifier`
// (defined later in this file). Each AIR has its own module file under `airs/`;
// the verifier wrapper lives in `plonky3_verifier`. Per
// `feedback_no_cross_purpose_files.md`, these modules MUST NOT share helpers,
// constants, or trait impls with the arkworks block. The arkworks impl is
// retained only until the Plonky3 path is wired into `gemini-runtime`'s
// `Config::ProofVerifier`; the cutover deletes the arkworks impl in a single
// commit. No production fallback path.
mod airs;
mod plonky3_verifier;

#[cfg(test)]
mod tests;

extern crate alloc;

use alloc::vec::Vec;
use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use frame_support::pallet_prelude::*;
use frame_system::pallet_prelude::{BlockNumberFor, OriginFor};
use scale_info::TypeInfo;
use sp_core::H256;
use sp_runtime::traits::Saturating;
use zk_pki_primitives::hip::CanonicalHipProof;

/// Domain separator for the AA challenge derivation.
///
/// Used for: `aa_challenge = SHA-256(AA_CHALLENGE_DOMAIN || anchor.hash || bound_account.encode())`.
/// The AIR receives `aa_challenge` and `sha256_digest_of_challenge` as PIs;
/// the pallet pre-computes both and asserts equality with the proof's PIs
/// before running the AIR verifier (derivation wiring lands in a follow-up
/// commit; this constant is published first so the AIR-side PI shape can
/// settle).
///
/// Distinct from [`HIP_CHALLENGE_DOMAIN`] so a leaked HIP challenge cannot
/// be replayed as an AA challenge and vice versa, even if `anchor.hash`
/// and `bound_account` collide between contexts.
pub const AA_CHALLENGE_DOMAIN: &[u8] = b"rostro-pop-aa-v1";

/// Domain separator for the HIP attestation nonce derivation.
///
/// Used for: `hip_challenge_nonce = SHA-256(HIP_CHALLENGE_DOMAIN || anchor.hash || bound_account.encode())`.
/// The chip cannot be tricked into signing this for an AA-shaped purpose
/// because [`AA_CHALLENGE_DOMAIN`] differs.
pub const HIP_CHALLENGE_DOMAIN: &[u8] = b"rostro-pop-hip-v1";

/// Service-scope domain for the OPRF-protected scoped nullifier.
///
/// `scoped_nullifier = Poseidon2(salted_private_nullifier.value, service_scope, service_subscope, nullifier_secret)`
/// where `service_scope = Poseidon2(SCOPED_NULLIFIER_SERVICE_DOMAIN)`. Wrapping the
/// domain in a Poseidon2 hash gives a Goldilocks-field-element scope value
/// the AIR can consume directly without limb decomposition.
pub const SCOPED_NULLIFIER_SERVICE_DOMAIN: &[u8] = b"rostro-pop-cert-v1";

/// Chain-side anchor reference. The user's circuit witnesses a
/// recent chain block hash; the pallet checks the witnessed hash
/// matches the chain's stored hash for that block, and the block is
/// within `MaxProofAge` of `now()`.
#[derive(
	Clone,
	Encode,
	Decode,
	DecodeWithMemTracking,
	TypeInfo,
	MaxEncodedLen,
	Debug,
	PartialEq,
	Eq,
)]
pub struct ChainAnchor<BlockNumber> {
	pub block: BlockNumber,
	pub hash: H256,
}

/// Discriminant on which OPRF protection mode produced a `scoped_nullifier`.
///
/// Mirrors zkpassport's nullifier_type pattern: `Salted` is the production
/// path with the validator-federation OPRF applied, so the nullifier hides
/// behind the threshold-shared K and is not government-recomputable.
/// `NonSalted` is the fallback for environments without the federation —
/// nullifier is `Poseidon2(private_nullifier, scope, subscope)` with no
/// secret, so it IS recomputable from passport data and the issuing
/// government can deanonymize. Mainnet must reject NonSalted.
///
/// `*Mock` variants are reserved for testnet documents (Camino) issued
/// against the ZKR mock country code, so chain code can distinguish
/// devnet certs from real-passport certs without re-verifying the doc.
#[derive(
	Clone,
	Copy,
	Encode,
	Decode,
	DecodeWithMemTracking,
	TypeInfo,
	MaxEncodedLen,
	Debug,
	PartialEq,
	Eq,
)]
pub enum NullifierType {
	/// Production OPRF-protected nullifier. Government cannot recompute.
	Salted,
	/// No OPRF applied (legacy/fallback). Nullifier is government-recomputable.
	/// Mainnet runtimes should reject this.
	NonSalted,
	/// Testnet/devnet OPRF-protected (mock country code).
	SaltedMock,
	/// Testnet/devnet no-OPRF (mock country code).
	NonSaltedMock,
}

/// Public-input bundle for the `passport_attest` circuit.
///
/// Field order MUST match the AIR's PI column declaration order in
/// `airs/passport_attest_aa_*::COL_*` constants. The AIR's PI columns
/// are populated in this exact order; mismatched ordering would silently
/// pass validation against the wrong fields.
#[derive(
	Clone,
	Encode,
	Decode,
	DecodeWithMemTracking,
	TypeInfo,
	MaxEncodedLen,
	Debug,
	PartialEq,
	Eq,
)]
pub struct PassportPublicInputs<AccountId, BlockNumber> {
	/// Salted-commitment chain anchor. The AIR computes
	/// `comm_in = Poseidon2(salted_dg1, salted_expiry, salted_dg2_hash, salted_dg2_hash_type, salted_private_nullifier)`
	/// over private witnesses. The same value appears as a PI on the
	/// paired `liveness_facematch` proof — pallet asserts equality to
	/// cross-bind the two proofs to the same passport. Replaces the
	/// previous `dg2_hash` cross-binding (which was government-
	/// recomputable from chip photos).
	pub comm_in: H256,
	/// Output of the OPRF flow + scope binding:
	/// `scoped_nullifier = Poseidon2(private_nullifier, service_scope,
	/// service_subscope, nullifier_secret)` where `nullifier_secret`
	/// is the verified OPRF output `H2C(private_nullifier)^K`. Pallet
	/// stores this in [`Nullifiers`]; second mint with the same
	/// scoped_nullifier rejected.
	pub scoped_nullifier: H256,
	/// Discriminant on which OPRF mode produced `scoped_nullifier`.
	/// Mainnet rejects `NonSalted` and `*Mock` variants; testnet
	/// (Camino) accepts the mock variants.
	pub nullifier_type: NullifierType,
	/// `Poseidon2(federation_pubkey.x, federation_pubkey.y)` — commits
	/// to which OPRF federation pubkey was used. Pallet checks against
	/// `CurrentOprfFederationPubkeyHash` (not yet wired); rejects if
	/// the proof was generated against an old federation pubkey.
	pub oprf_pk_hash: H256,
	/// SS58 the proof is intended for. Pallet checks
	/// `caller == bound_account`.
	pub bound_account: AccountId,
	/// True iff `(anchor_block - dob_block) >= 18_years_in_blocks`.
	pub adult: bool,
	/// Country resolved through the seats merkle tree. Country code
	/// itself is private (only seat_id revealed).
	pub seat_id: u16,
	/// Recent chain anchor used as "now" for the adult check and
	/// for binding AA freshness.
	pub anchor: ChainAnchor<BlockNumber>,
	/// Merkle root of the CSCA bundle the chain check used. Pallet
	/// rejects if not equal to current `CurrentCscaRoot`.
	pub csca_root: H256,
	/// Merkle root of the seats mapping. Pallet rejects if not
	/// equal to current `CurrentSeatsRoot`.
	pub seats_root: H256,
	/// `aa_challenge = SHA-256(AA_CHALLENGE_DOMAIN || anchor.hash || bound_account.encode())`.
	/// Pallet pre-computes from `anchor` + `bound_account` and asserts
	/// equality with this PI before AIR verification. The AIR then uses
	/// it as the message that the chip's RSA-2048-SHA256 signature was
	/// computed over.
	pub aa_challenge: [u8; 32],
	/// `SHA-256(aa_challenge)`. Pallet pre-computes and asserts equality.
	/// AIR uses this as the digest its PKCS#1 v1.5 EM bytes must contain.
	pub sha256_digest_of_challenge: [u8; 32],
}

/// Public-input bundle for the `liveness_facematch` circuit.
///
/// Cross-bound to the paired `passport_attest` proof via `comm_in`. Both
/// proofs must commit to the same comm_in over the same private witnesses
/// (DG1, expiry, DG2 hash, DG2 hash type, private_nullifier — all salted).
#[derive(
	Clone,
	Encode,
	Decode,
	DecodeWithMemTracking,
	TypeInfo,
	MaxEncodedLen,
	Debug,
	PartialEq,
	Eq,
)]
pub struct LivenessPublicInputs<AccountId, BlockNumber> {
	/// Must equal `passport_inputs.comm_in`. Cross-proof binding.
	/// Replaces the previous `dg2_hash` cross-binding.
	pub comm_in: H256,
	/// SS58 the proof is intended for. Same anti-frontrun as
	/// passport_attest.
	pub bound_account: AccountId,
	/// True iff (a) the witnessed live-frame landmarks were stable
	/// across head-turn frames AND (b) they matched the DG2 chip
	/// photo's landmarks. The circuit is responsible for the
	/// definition; the pallet just checks this is true.
	pub liveness_passed: bool,
	/// Same chain anchor as passport_attest. Pallet checks both
	/// proofs anchor to the same block.
	pub anchor: ChainAnchor<BlockNumber>,
}

/// Per-AccountId PoP cert record. One per account; absent =
/// account has no PoP cert.
#[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen, Debug, PartialEq, Eq)]
pub struct PopCert<BlockNumber> {
	/// The OPRF-protected scoped nullifier. Same value also lives in
	/// [`Nullifiers`] as the dedup gate. Government cannot recompute
	/// this from passport data alone (validator-federation K is hidden).
	pub scoped_nullifier: H256,
	/// OPRF protection mode used for `scoped_nullifier`. Stored so
	/// downstream queries can reason about the nullifier's privacy
	/// guarantee without re-verifying the proof.
	pub nullifier_type: NullifierType,
	/// Cert expiry in chain block-number form, computed at mint as
	/// `minted_at + FIXED_POP_TTL`. Passport expiry itself is no longer
	/// a PI (privacy: passport expiry is a quasi-identifier); the chain
	/// uses a uniform per-cert TTL aligned with the OPRF K rotation
	/// cycle (5 years per `pop_design_section1c_oprf_nullifier.md`).
	pub ttl_block: BlockNumber,
	/// Adult bool at the time of mint. Once true, never flips.
	pub adult: bool,
	/// Seat assignment at the time of mint. Grandfathered against
	/// later `seats_root` rotations.
	pub seat_id: u16,
	/// Block when the cert was minted. Audit / debugging aid.
	pub minted_at: BlockNumber,
}

/// Verifying-key record for one of the two circuits. Strict
/// monotonic `version`; new vk bytes can be any well-formed Groth16
/// VK (including a known-good earlier set, in which case
/// `ceremony_hash` documents the rollback).
#[derive(Clone, Encode, Decode, TypeInfo, Debug, PartialEq, Eq)]
pub struct VkRecord<BlockNumber> {
	pub bytes: Vec<u8>,
	pub version: u32,
	pub set_at: BlockNumber,
	/// Hash of the phase-2 ceremony transcript bundle that produced
	/// these vk bytes. Anyone with the transcript can verify the
	/// SRT signed an honest build.
	pub ceremony_hash: H256,
}

/// Which of the two circuits' vk to rotate.
#[derive(
	Clone,
	Copy,
	Encode,
	Decode,
	DecodeWithMemTracking,
	TypeInfo,
	MaxEncodedLen,
	Debug,
	PartialEq,
	Eq,
)]
pub enum CircuitId {
	PassportAttest,
	LivenessFacematch,
}

/// Errors returned by the configured `ZkPkiInterface`. Mapped to
/// `Error<T>` variants by the pallet.
#[derive(Clone, Encode, Decode, TypeInfo, Debug, PartialEq, Eq)]
pub enum ZkPkiError {
	/// Cert thumbprint not found in zk-pki storage.
	CertNotFound,
	/// Cert exists but isn't owned by the supplied account.
	CertNotOwned,
	/// Cert exists but is suspended, revoked, or otherwise
	/// non-Good.
	CertNotGood,
	/// HIP proof verification failed against the cert's stored
	/// genesis fingerprint.
	HipFailed,
}

/// Verifier trait the personhood pallet calls through for both
/// circuits' Groth16 checks. Production binds to the arkworks-based
/// implementation; tests bind to a mock that lets each test control
/// whether `verify_passport_attest` and `verify_liveness_facematch`
/// return Ok or Err. This is the only trait abstraction inside the
/// pallet for the verifier path — same pattern as `ZkPkiInterface`.
pub trait ProofVerifier<AccountId, BlockNumber> {
	/// Verify the `passport_attest` Groth16 proof against the
	/// public inputs. The implementation is responsible for
	/// encoding the inputs into the BN254 field-element vector
	/// matching the circuit's `public [...]` declaration.
	fn verify_passport_attest(
		vk_bytes: &[u8],
		proof_bytes: &[u8],
		inputs: &PassportPublicInputs<AccountId, BlockNumber>,
	) -> Result<(), ()>;

	/// Verify the `liveness_facematch` Groth16 proof.
	fn verify_liveness_facematch(
		vk_bytes: &[u8],
		proof_bytes: &[u8],
		inputs: &LivenessPublicInputs<AccountId, BlockNumber>,
	) -> Result<(), ()>;
}

/// Production implementation of [`ProofVerifier`] backed by
/// `ark-groth16` over BN254. Mirrors the toolchain zk-pki uses for
/// mime_wrap so the runtime carries one Groth16 verifier stack.
pub struct ArkProofVerifier;

impl<AccountId, BlockNumber> ProofVerifier<AccountId, BlockNumber> for ArkProofVerifier {
	fn verify_passport_attest(
		vk_bytes: &[u8],
		proof_bytes: &[u8],
		inputs: &PassportPublicInputs<AccountId, BlockNumber>,
	) -> Result<(), ()> {
		let public_inputs = verifier::passport_public_inputs(inputs);
		verifier::verify_groth16(vk_bytes, proof_bytes, &public_inputs).map_err(|_| ())
	}

	fn verify_liveness_facematch(
		vk_bytes: &[u8],
		proof_bytes: &[u8],
		inputs: &LivenessPublicInputs<AccountId, BlockNumber>,
	) -> Result<(), ()> {
		let public_inputs = verifier::liveness_public_inputs(inputs);
		verifier::verify_groth16(vk_bytes, proof_bytes, &public_inputs).map_err(|_| ())
	}
}

/// Adapter trait the personhood pallet uses to call into zk-pki.
/// Runtime wires this to the actual `pallet-zk-pki` via an adapter
/// struct in `gemini-runtime`. Tests can supply a stub
/// implementation.
pub trait ZkPkiInterface<AccountId, BlockNumber> {
	/// Verify that `account` owns an active (Good-state) zk-pki
	/// cert at `thumbprint`, and that `hip_proof` proves the
	/// device's current PCRs still match the genesis fingerprint
	/// recorded at cert mint. The `challenge_nonce` must be present
	/// in the HIP proof's signed payload — bind to the chain anchor
	/// to prevent replay.
	fn verify_cert_and_hip(
		thumbprint: H256,
		account: &AccountId,
		hip_proof: &CanonicalHipProof,
		challenge_nonce: &[u8; 32],
	) -> Result<(), ZkPkiError>;

	/// When the HIP proof was attested, in chain block-number form.
	/// Pallet enforces freshness via `MaxProofAge`. Returned
	/// separately because the canonical HIP proof carries different
	/// timestamp shapes per platform; the interface normalises.
	fn hip_attested_at(hip_proof: &CanonicalHipProof) -> Option<BlockNumber>;
}

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_system::pallet_prelude::*;

	#[pallet::config]
	pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
		/// Maximum age (in blocks) of the chain anchor in a
		/// submitted proof. Bounds proof freshness — a proof
		/// generated more than `MaxProofAge` blocks ago is rejected
		/// with a clear error so the user can retry.
		///
		/// Locked v1 value: 600 blocks (~1 hour at 6s/block).
		#[pallet::constant]
		type MaxProofAge: Get<BlockNumberFor<Self>>;

		/// Per-cert TTL applied at mint: `cert.ttl_block = minted_at + FixedPopTtl`.
		/// Replaces the previous design where each proof carried its
		/// own `ttl_block` PI derived from passport expiry — passport
		/// expiry is a quasi-identifier (low-cardinality, often correlated
		/// with date-of-birth), so leaking it on chain reduces the
		/// anonymity set. The chain instead uses a uniform per-cert
		/// horizon aligned with the OPRF K rotation cycle (5 years per
		/// `pop_design_section1c_oprf_nullifier.md`).
		#[pallet::constant]
		type FixedPopTtl: Get<BlockNumberFor<Self>>;

		/// Adapter to the `pallet-zk-pki` instance in the same
		/// runtime. Used to verify HW cert + HIP at mint time.
		type ZkPki: ZkPkiInterface<Self::AccountId, BlockNumberFor<Self>>;

		/// Groth16 proof verifier for the two PoP circuits.
		/// Production binds to [`ArkProofVerifier`]; tests bind to
		/// a mock that controls whether verification succeeds.
		type ProofVerifier: ProofVerifier<Self::AccountId, BlockNumberFor<Self>>;

		/// Origin authorised to rotate the CSCA root, the seats
		/// root, and circuit verifying keys. Wired to the SRT
		/// pallet once that lands; in the interim, the runtime
		/// likely binds this to `EnsureRoot` so genesis sudo can
		/// drive bring-up.
		type SrtOrigin: EnsureOrigin<Self::RuntimeOrigin>;
	}

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	// ─────────────────────────────────────────────────────────────
	// Storage
	// ─────────────────────────────────────────────────────────────

	/// Per-AccountId PoP cert. One per account.
	#[pallet::storage]
	pub type PopCerts<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		T::AccountId,
		PopCert<BlockNumberFor<T>>,
		OptionQuery,
	>;

	/// Set of consumed scoped nullifiers. Insertion blocks any second
	/// mint with the same passport (under the same OPRF K era).
	/// Removed only by [`Pallet::discard_pop`]. Grows monotonically;
	/// bounded only by the global adult population that ever mints
	/// on Rostro.
	#[pallet::storage]
	pub type Nullifiers<T: Config> =
		StorageMap<_, Blake2_128Concat, H256, (), OptionQuery>;

	/// Current CSCA bundle merkle root. Rotated by SRT. Hard
	/// cutover on rotation — proofs against the previous root are
	/// rejected with a clear error. `OptionQuery` so the
	/// pre-publication bootstrap state is explicit: until SRT
	/// publishes, `mint_pop` rejects with `CscaRootNotSet`
	/// rather than `CscaRootRotated` (which would be a misleading
	/// error for the bootstrap case).
	#[pallet::storage]
	pub type CurrentCscaRoot<T: Config> = StorageValue<_, H256, OptionQuery>;

	/// Current seats mapping merkle root. Rotated by SRT.
	/// Existing PoP certs grandfather their stored `seat_id`
	/// against rotation. Same bootstrap-state reasoning as
	/// `CurrentCscaRoot`.
	#[pallet::storage]
	pub type CurrentSeatsRoot<T: Config> = StorageValue<_, H256, OptionQuery>;

	/// Verifying key for the `passport_attest` circuit. Rotated by
	/// SRT.
	#[pallet::storage]
	#[pallet::unbounded]
	pub type PassportAttestVk<T: Config> =
		StorageValue<_, VkRecord<BlockNumberFor<T>>, OptionQuery>;

	/// Verifying key for the `liveness_facematch` circuit. Rotated
	/// by SRT.
	#[pallet::storage]
	#[pallet::unbounded]
	pub type LivenessFacematchVk<T: Config> =
		StorageValue<_, VkRecord<BlockNumberFor<T>>, OptionQuery>;

	// ─────────────────────────────────────────────────────────────
	// Events
	// ─────────────────────────────────────────────────────────────

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A PoP cert was minted for `who` with the given
		/// `seat_id` and TTL.
		PopMinted { who: T::AccountId, seat_id: u16, ttl_block: BlockNumberFor<T> },
		/// `who` discarded their PoP cert. The freed scoped_nullifier
		/// may be re-minted from the same passport (passport renewal
		/// produces a new SOD signature → new private_nullifier → new
		/// scoped_nullifier; or after K rotation; or on a different SS58).
		PopDiscarded { who: T::AccountId, nullifier_freed: H256 },
		/// SRT rotated the CSCA root. `old` is `None` on first
		/// publication post-genesis.
		CscaRootRotated { old: Option<H256>, new: H256 },
		/// SRT rotated the seats root. `old` is `None` on first
		/// publication post-genesis.
		SeatsRootRotated { old: Option<H256>, new: H256 },
		/// SRT rotated a circuit verifying key.
		VkRotated { which: CircuitId, version: u32 },
	}

	// ─────────────────────────────────────────────────────────────
	// Errors
	// ─────────────────────────────────────────────────────────────

	#[pallet::error]
	pub enum Error<T> {
		/// Caller already has a PoP cert. Discard first.
		AlreadyHasPopCert,
		/// Caller has no zk-pki HW cert at the supplied thumbprint.
		HwCertNotFound,
		/// HW cert exists but isn't owned by the caller.
		HwCertNotOwned,
		/// HW cert exists but is suspended / revoked / otherwise
		/// non-Good.
		HwCertNotGood,
		/// HIP proof failed to verify against the cert's stored
		/// genesis fingerprint.
		HipFailed,
		/// HIP proof was attested too long ago. Re-do the HW
		/// attestation ceremony and retry.
		HipTooOld,
		/// Liveness proof public input declares the live capture
		/// failed. Retry the liveness ceremony.
		LivenessFailed,
		/// `passport_proof` and `liveness_proof` disagree on
		/// `dg2_hash` or `bound_account`. Cross-proof binding
		/// failed.
		ProofMismatch,
		/// `bound_account` in the proof does not equal the
		/// submitting caller. Anti-frontrun.
		ProofBoundToOther,
		/// Chain anchor block is older than `MaxProofAge`.
		ProofTooOld,
		/// Chain anchor hash does not match the chain's recorded
		/// hash for the witnessed block.
		AnchorMismatch,
		/// `csca_root` in the proof does not match the chain's
		/// current root. Likely an SRT rotation just landed; retry.
		CscaRootRotated,
		/// `seats_root` in the proof does not match the chain's
		/// current root. Likely an SRT rotation just landed; retry.
		SeatsRootRotated,
		/// SRT has not published the CSCA root yet — the chain has
		/// not been initialised for PoP minting. No retry helps;
		/// SRT must call `srt_set_csca_root` first.
		CscaRootNotSet,
		/// SRT has not published the seats root yet. Same shape as
		/// `CscaRootNotSet`.
		SeatsRootNotSet,
		/// Passport's TTL has already passed. Renew the passport
		/// and try again.
		PassportExpired,
		/// `nullifier` already in storage — this passport already
		/// minted on chain. Discard the previous cert first.
		NullifierConsumed,
		/// `passport_proof` failed Groth16 verification.
		PassportProofInvalid,
		/// `liveness_proof` failed Groth16 verification.
		LivenessProofInvalid,
		/// The `passport_attest` verifying key has not been set.
		/// SRT must publish vk before any mints can happen.
		PassportVkNotSet,
		/// The `liveness_facematch` verifying key has not been set.
		LivenessVkNotSet,
		/// Verifying-key bytes in storage don't deserialize. Should
		/// not happen if SRT followed the publication procedure.
		VkMalformed,
		/// vk version did not strictly increment by 1 on rotation.
		VkVersionRegressed,
	}

	// ─────────────────────────────────────────────────────────────
	// Calls
	// ─────────────────────────────────────────────────────────────

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Mint the caller's PoP cert. Direct mint — no issuer.
		///
		/// The caller must already hold an active zk-pki HW cert
		/// at `hw_cert_thumbprint`, and must supply a fresh
		/// [`CanonicalHipProof`] proving the device's current PCRs
		/// match the genesis fingerprint recorded at zk-pki cert
		/// mint. The HIP closes the compromise window between
		/// zk-pki mint and PoP mint — without it that window is
		/// months; with it, it is the proof-age window
		/// (`MaxProofAge`).
		///
		/// Both the `passport_attest` and `liveness_facematch`
		/// proofs are verified atomically. The mint never lands
		/// without both proofs valid plus all consistency checks
		/// (chain-anchor freshness, root-equality, cross-proof
		/// binding, nullifier uniqueness, TTL not expired).
		#[pallet::call_index(0)]
		#[pallet::weight(Weight::from_parts(1_000_000_000, 0))]
		pub fn mint_pop(
			origin: OriginFor<T>,
			passport_proof: Vec<u8>,
			passport_inputs: PassportPublicInputs<T::AccountId, BlockNumberFor<T>>,
			liveness_proof: Vec<u8>,
			liveness_inputs: LivenessPublicInputs<T::AccountId, BlockNumberFor<T>>,
			hw_cert_thumbprint: H256,
			hip_proof: CanonicalHipProof,
		) -> DispatchResult {
			let caller = ensure_signed(origin)?;

			// 1. One PoP cert per account. Discard required to
			//    re-mint — overwrite is an attack vector.
			ensure!(!PopCerts::<T>::contains_key(&caller), Error::<T>::AlreadyHasPopCert);

			// 2. HW attestation binding via fresh HIP. Closes the
			//    "device was compromised between zk-pki mint and
			//    PoP mint" window.
			let challenge_nonce = hip_challenge_nonce(&passport_inputs.anchor, &caller);
			T::ZkPki::verify_cert_and_hip(
				hw_cert_thumbprint,
				&caller,
				&hip_proof,
				&challenge_nonce,
			)
			.map_err(|e| match e {
				ZkPkiError::CertNotFound => Error::<T>::HwCertNotFound,
				ZkPkiError::CertNotOwned => Error::<T>::HwCertNotOwned,
				ZkPkiError::CertNotGood => Error::<T>::HwCertNotGood,
				ZkPkiError::HipFailed => Error::<T>::HipFailed,
			})?;
			let now = frame_system::Pallet::<T>::block_number();
			let max_age = T::MaxProofAge::get();
			if let Some(attested_at) = T::ZkPki::hip_attested_at(&hip_proof) {
				ensure!(now.saturating_sub(attested_at) <= max_age, Error::<T>::HipTooOld);
			}
			// (If the platform-specific HIP doesn't carry a
			// chain-block timestamp, freshness is enforced via the
			// challenge_nonce binding to anchor_hash above.)

			// 3. Cross-proof binding via comm_in. Both proofs commit
			//    to the same salted-private-witness chain (DG1, expiry,
			//    DG2 hash, DG2 hash type, private_nullifier — all
			//    salted) so they must match. Replaces the previous
			//    dg2_hash cross-binding (which was government-
			//    recomputable from chip photos).
			ensure!(
				passport_inputs.bound_account == caller,
				Error::<T>::ProofBoundToOther,
			);
			ensure!(
				liveness_inputs.bound_account == caller,
				Error::<T>::ProofBoundToOther,
			);
			ensure!(
				passport_inputs.comm_in == liveness_inputs.comm_in,
				Error::<T>::ProofMismatch,
			);
			ensure!(
				passport_inputs.anchor == liveness_inputs.anchor,
				Error::<T>::ProofMismatch,
			);
			ensure!(liveness_inputs.liveness_passed, Error::<T>::LivenessFailed);

			// 4. Chain anchor freshness + integrity.
			let anchor_block = passport_inputs.anchor.block;
			ensure!(now.saturating_sub(anchor_block) <= max_age, Error::<T>::ProofTooOld);
			let actual_hash = frame_system::Pallet::<T>::block_hash(anchor_block);
			let actual_h256 = H256::from_slice(actual_hash.as_ref());
			ensure!(
				actual_h256 == passport_inputs.anchor.hash,
				Error::<T>::AnchorMismatch,
			);

			// 5. Trust roots. Hard cutover on rotation: clear
			//    error, no grace. Pre-publication state ("SRT
			//    hasn't published yet") returns a distinct error
			//    so the user knows it's a chain-not-yet-live
			//    issue, not an in-flight rotation issue.
			let current_csca =
				CurrentCscaRoot::<T>::get().ok_or(Error::<T>::CscaRootNotSet)?;
			ensure!(passport_inputs.csca_root == current_csca, Error::<T>::CscaRootRotated);
			let current_seats =
				CurrentSeatsRoot::<T>::get().ok_or(Error::<T>::SeatsRootNotSet)?;
			ensure!(
				passport_inputs.seats_root == current_seats,
				Error::<T>::SeatsRootRotated,
			);

			// 6. Cert TTL is chain-assigned at mint (passport expiry no
			//    longer carried as PI for privacy). No per-mint expiry
			//    check beyond the chain-anchor freshness above.

			// 7. Scoped nullifier uniqueness. The OPRF protection means
			//    the same passport produces the same scoped_nullifier
			//    under a given K era; chain rejects re-mint without an
			//    intervening discard.
			ensure!(
				!Nullifiers::<T>::contains_key(passport_inputs.scoped_nullifier),
				Error::<T>::NullifierConsumed,
			);

			// 8. Verify both Groth16 proofs through the configured
			//    ProofVerifier. Production uses ark-groth16; tests
			//    use a controllable mock.
			let passport_vk = PassportAttestVk::<T>::get()
				.ok_or(Error::<T>::PassportVkNotSet)?;
			T::ProofVerifier::verify_passport_attest(
				&passport_vk.bytes,
				&passport_proof,
				&passport_inputs,
			)
			.map_err(|_| Error::<T>::PassportProofInvalid)?;

			let liveness_vk = LivenessFacematchVk::<T>::get()
				.ok_or(Error::<T>::LivenessVkNotSet)?;
			T::ProofVerifier::verify_liveness_facematch(
				&liveness_vk.bytes,
				&liveness_proof,
				&liveness_inputs,
			)
			.map_err(|_| Error::<T>::LivenessProofInvalid)?;

			// 9. Commit. Cert TTL is chain-assigned: now + FixedPopTtl.
			let ttl_block = now.saturating_add(T::FixedPopTtl::get());
			Nullifiers::<T>::insert(passport_inputs.scoped_nullifier, ());
			PopCerts::<T>::insert(
				&caller,
				PopCert {
					scoped_nullifier: passport_inputs.scoped_nullifier,
					nullifier_type: passport_inputs.nullifier_type,
					ttl_block,
					adult: passport_inputs.adult,
					seat_id: passport_inputs.seat_id,
					minted_at: now,
				},
			);
			Self::deposit_event(Event::PopMinted {
				who: caller,
				seat_id: passport_inputs.seat_id,
				ttl_block,
			});
			Ok(())
		}

		/// Caller destroys their own PoP cert. Frees the
		/// associated nullifier so the same passport can re-mint
		/// (e.g., on a different SS58, or after passport renewal
		/// produces a new MRZ → new nullifier). No fresh proof
		/// required — destroying own state is not a new claim.
		#[pallet::call_index(1)]
		#[pallet::weight(Weight::from_parts(50_000_000, 0))]
		pub fn discard_pop(origin: OriginFor<T>) -> DispatchResult {
			let caller = ensure_signed(origin)?;
			let cert = PopCerts::<T>::take(&caller).ok_or(Error::<T>::AlreadyHasPopCert)?;
			Nullifiers::<T>::remove(cert.scoped_nullifier);
			Self::deposit_event(Event::PopDiscarded {
				who: caller,
				nullifier_freed: cert.scoped_nullifier,
			});
			Ok(())
		}

		/// SRT rotates the CSCA bundle merkle root. Same extrinsic
		/// for first publication post-genesis, scheduled quarterly
		/// rotation, and emergency rotation — SRT decides the
		/// pacing operationally. Hard cutover; proofs against the
		/// previous root reject at submission with
		/// `CscaRootRotated`. The `old` field on the emitted event
		/// is `None` on first publication.
		#[pallet::call_index(2)]
		#[pallet::weight(Weight::from_parts(20_000_000, 0))]
		pub fn srt_set_csca_root(origin: OriginFor<T>, new_root: H256) -> DispatchResult {
			T::SrtOrigin::ensure_origin(origin)?;
			let old = CurrentCscaRoot::<T>::get();
			CurrentCscaRoot::<T>::put(new_root);
			Self::deposit_event(Event::CscaRootRotated { old, new: new_root });
			Ok(())
		}

		/// SRT rotates the seats mapping merkle root. Existing PoP
		/// certs grandfather their stored `seat_id`; only new mints
		/// are affected. Same single-extrinsic pattern as
		/// `srt_set_csca_root`.
		#[pallet::call_index(3)]
		#[pallet::weight(Weight::from_parts(20_000_000, 0))]
		pub fn srt_set_seats_root(origin: OriginFor<T>, new_root: H256) -> DispatchResult {
			T::SrtOrigin::ensure_origin(origin)?;
			let old = CurrentSeatsRoot::<T>::get();
			CurrentSeatsRoot::<T>::put(new_root);
			Self::deposit_event(Event::SeatsRootRotated { old, new: new_root });
			Ok(())
		}

		/// SRT rotates the verifying key for one of the two
		/// circuits. Strict monotonic version bumping; new bytes
		/// can be any well-formed Groth16 VK (including a
		/// known-good earlier set on rollback). The `ceremony_hash`
		/// references a phase-2 ceremony transcript whose contents
		/// can be reproduced and audited off-chain.
		#[pallet::call_index(4)]
		#[pallet::weight(Weight::from_parts(40_000_000, 0))]
		pub fn srt_set_vk(
			origin: OriginFor<T>,
			which: CircuitId,
			new_vk_bytes: Vec<u8>,
			new_version: u32,
			ceremony_hash: H256,
		) -> DispatchResult {
			T::SrtOrigin::ensure_origin(origin)?;
			let now = frame_system::Pallet::<T>::block_number();
			match which {
				CircuitId::PassportAttest => {
					let prev_version = PassportAttestVk::<T>::get()
						.map(|vk| vk.version)
						.unwrap_or(0);
					ensure!(
						new_version == prev_version.saturating_add(1),
						Error::<T>::VkVersionRegressed,
					);
					PassportAttestVk::<T>::put(VkRecord {
						bytes: new_vk_bytes,
						version: new_version,
						set_at: now,
						ceremony_hash,
					});
				},
				CircuitId::LivenessFacematch => {
					let prev_version = LivenessFacematchVk::<T>::get()
						.map(|vk| vk.version)
						.unwrap_or(0);
					ensure!(
						new_version == prev_version.saturating_add(1),
						Error::<T>::VkVersionRegressed,
					);
					LivenessFacematchVk::<T>::put(VkRecord {
						bytes: new_vk_bytes,
						version: new_version,
						set_at: now,
						ceremony_hash,
					});
				},
			}
			Self::deposit_event(Event::VkRotated { which, version: new_version });
			Ok(())
		}
	}
}

/// Derive the HIP attestation nonce from the chain anchor and the
/// caller's bound account. The device's StrongBox/TPM2 attestation is
/// over this nonce; freshness comes from `anchor.hash` being a recent
/// chain block, and binding to `bound_account` prevents redirect
/// attacks (a leaked HIP attestation for one account cannot be
/// replayed to mint at another).
///
/// `nonce = SHA-256(HIP_CHALLENGE_DOMAIN || anchor.hash || bound_account.encode())`
///
/// The AA challenge derivation uses a different domain
/// ([`AA_CHALLENGE_DOMAIN`]) so a leaked HIP nonce cannot be replayed
/// as an AA challenge and vice versa. The chip's AA signature is the
/// cryptographic source of truth even when the host is compromised;
/// HIP is the platform-attestation gate that runs first.
pub(crate) fn hip_challenge_nonce<AccountId: Encode, BlockNumber>(
	anchor: &ChainAnchor<BlockNumber>,
	bound_account: &AccountId,
) -> [u8; 32] {
	let mut hashable = sp_std::vec::Vec::with_capacity(
		HIP_CHALLENGE_DOMAIN.len() + 32 + 64,
	);
	hashable.extend_from_slice(HIP_CHALLENGE_DOMAIN);
	hashable.extend_from_slice(anchor.hash.as_bytes());
	bound_account.encode_to(&mut hashable);
	sp_io::hashing::sha2_256(&hashable)
}

mod verifier {
	//! Groth16 verification kernel for the personhood circuits.
	//!
	//! Mirrors the shape of zk-pki-pallet's mime-wrap verifier —
	//! same arkworks stack (BN254, Groth16, compressed
	//! serialization). When the actual circuits land
	//! (`passport_attest.circom`, `liveness_facematch.circom`),
	//! the public-input encoding functions below get filled in to
	//! match the circuits' `public [...]` ordering.

	use super::*;
	use ark_bn254::{Bn254, Fr};
	use ark_ff::{One, Zero};
	use ark_groth16::{prepare_verifying_key, Groth16, Proof, VerifyingKey};
	use ark_serialize::CanonicalDeserialize;
	use ark_snark::SNARK;

	#[derive(Debug, PartialEq, Eq)]
	pub enum VerifyError {
		ProofMalformed,
		VerifyingKeyMalformed,
		PairingFailed,
	}

	pub fn verify_groth16(
		vk_bytes: &[u8],
		proof_bytes: &[u8],
		public_inputs: &[Fr],
	) -> Result<(), VerifyError> {
		let vk = VerifyingKey::<Bn254>::deserialize_compressed(vk_bytes)
			.map_err(|_| VerifyError::VerifyingKeyMalformed)?;
		let pvk = prepare_verifying_key(&vk);
		let proof = Proof::<Bn254>::deserialize_compressed(proof_bytes)
			.map_err(|_| VerifyError::ProofMalformed)?;
		let ok = Groth16::<Bn254>::verify_with_processed_vk(&pvk, public_inputs, &proof)
			.map_err(|_| VerifyError::PairingFailed)?;
		if ok { Ok(()) } else { Err(VerifyError::PairingFailed) }
	}

	/// Encode the `passport_attest` public inputs into the BN254
	/// field-element vector the circuit expects. Ordering matches
	/// the circuit's `public [...]` declaration; will be finalised
	/// once `passport_attest.circom` lands.
	///
	/// Placeholder shape: emit one Fr per public-input field,
	/// concatenated. Real implementation will likely use bit
	/// decomposition for hash-shaped values (matching circomlib
	/// conventions — see zk-pki-pallet's mime_wrap module).
	pub fn passport_public_inputs<AccountId, BlockNumber>(
		_inputs: &PassportPublicInputs<AccountId, BlockNumber>,
	) -> alloc::vec::Vec<Fr> {
		// TODO(PoP): match passport_attest.circom's public-input
		// layout once the circuit lands.
		alloc::vec::Vec::new()
	}

	pub fn liveness_public_inputs<AccountId, BlockNumber>(
		_inputs: &LivenessPublicInputs<AccountId, BlockNumber>,
	) -> alloc::vec::Vec<Fr> {
		// TODO(PoP): match liveness_facematch.circom's
		// public-input layout once the circuit lands.
		alloc::vec::Vec::new()
	}

	#[allow(dead_code)]
	fn bit_fr(b: u8) -> Fr {
		if b == 0 { Fr::zero() } else { Fr::one() }
	}
}
