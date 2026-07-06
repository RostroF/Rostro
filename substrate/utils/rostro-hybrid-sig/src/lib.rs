// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # rostro-hybrid-sig
//!
//! ed25519 + SLH-DSA-SHA2-128s hybrid signature for Rostro finality votes
//! (docs/CONSENSUS-KEY-LIFECYCLE.md, workstream 2 / pq-finality-v0).
//!
//! A finality justification is the one signature artifact verified years
//! after signing, so it is the chain's real quantum exposure: every
//! historical authority public key is on-chain forever, and at Q-day a
//! CRQC turns any retired ed25519 key into a history-forgery tool. The
//! hybrid rule mirrors `rostro-hybrid-kex` on the signing side: **both
//! components sign, both must verify.** A vote forgery requires breaking
//! ed25519 AND the hash-based SLH-DSA at once; a break of the younger
//! scheme alone changes nothing.
//!
//! Parameter set: **SLH-DSA-SHA2-128s** (FIPS 205 final). Stateless on
//! purpose (no key-evolution state grenade until the F4 hardware
//! watermark exists). The **`s` (small) variant** is chosen over `f`
//! deliberately for validator SCALE: a finality justification carries one
//! signature PER validator and is verified by EVERY node, so signature
//! size and verify speed are the bottlenecks while per-validator signing
//! (once per slot) is the slack. Measured (see tests/param_bench.rs):
//! `s` sig 7856 B vs `f` 17088 B (~2.2x smaller) and verify ~0.17 ms vs
//! ~0.47 ms (~2.7x faster), paid for by slower signing (~170 ms vs ~8 ms,
//! trivially inside a 6 s slot). 32-byte public key, 7856-byte signature.
//!
//! ## Domain separation
//!
//! Every sign/verify call takes an explicit `domain` (≤ 255 bytes). The
//! SLH-DSA half consumes it natively as the FIPS 205 context string; the
//! ed25519 half signs the identically framed preimage
//! `0x00 || len(domain) || domain || msg` (the exact FIPS 205 `M'`
//! framing, so the two halves can never disagree about where the domain
//! ends). A signature under one domain is unverifiable under any other.
//!
//! ## Determinism
//!
//! Signing uses the FIPS 205 *deterministic* variant (no per-signature
//! randomizer) and RFC 8032 ed25519, so the voter hot path needs no RNG
//! and double-signing an identical payload yields an identical signature.
//! The hedged variant guards fault/side-channel attackers, which for
//! validators is the F3/F4 hardware layer's job, not this crate's.
//!
//! Verification checks ed25519 first (microseconds) and SLH-DSA second
//! (milliseconds): reject-fast on garbage, and `verify_strict` on the
//! ed25519 half so consensus never accepts malleable/small-order forms.
//!
//! This crate is also where the NIST ACVP known-answer tests for the
//! vendored `slh-dsa` crate's SHA2-128f parameter set live: the vendored
//! tarball's own ACVP sample covers other parameter sets only (see
//! `substrate/external/slh-dsa/VENDOR.md`). Vectors under `tests/acvp/`
//! are filtered verbatim from the NIST ACVP-Server repository.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;

use ed25519_dalek::Signer as _;
use hkdf::Hkdf;
use sha2::Sha256;
use slh_dsa::Sha2_128s;

/// ed25519 public-key length in bytes (RFC 8032).
pub const ED25519_PK_BYTES: usize = 32;
/// ed25519 signature length in bytes (RFC 8032).
pub const ED25519_SIG_BYTES: usize = 64;
/// ed25519 secret-key (seed) length in bytes (RFC 8032).
pub const ED25519_SK_BYTES: usize = 32;
/// SLH-DSA-SHA2-128f public-key length in bytes (FIPS 205, table 2).
pub const SLH_PK_BYTES: usize = 32;
/// SLH-DSA-SHA2-128f signature length in bytes (FIPS 205, table 2).
pub const SLH_SIG_BYTES: usize = 7856;
/// SLH-DSA-SHA2-128f secret-key length in bytes (FIPS 205, table 2).
pub const SLH_SK_BYTES: usize = 64;

/// Hybrid public key wire length: ed25519 pk || SLH-DSA pk.
pub const HYBRID_PK_BYTES: usize = ED25519_PK_BYTES + SLH_PK_BYTES;
/// Hybrid signature wire length: ed25519 sig || SLH-DSA sig.
pub const HYBRID_SIG_BYTES: usize = ED25519_SIG_BYTES + SLH_SIG_BYTES;
/// Hybrid secret key wire length: ed25519 seed || SLH-DSA sk.
pub const HYBRID_SK_BYTES: usize = ED25519_SK_BYTES + SLH_SK_BYTES;
/// Master-seed length for deterministic keygen ([`HybridSigningKey::from_seed`]).
pub const SEED_BYTES: usize = 32;

/// HKDF salt for the one-seed keygen expansion. Versioned: changing the
/// expansion is a new suffix, never a silent re-derivation.
const KEYGEN_SALT: &[u8] = b"rostro/hybrid-sig/keygen/v1";

/// Domain for GRANDPA finality votes. The era/round/set_id scoping rides
/// inside the vote preimage built by the caller; the domain pins the
/// *protocol*, so a finality-vote signature can never double as anything
/// else (and vice versa).
pub const FINALITY_VOTE_DOMAIN: &[u8] = b"rostro/finality-vote/hybrid/v1";

/// Errors from hybrid signing/verification/decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HybridSigError {
	/// Domain string exceeds the FIPS 205 context limit of 255 bytes.
	DomainTooLong,
	/// Input slice has the wrong length for the type being decoded.
	BadLength,
	/// Key bytes do not decode to a valid key.
	BadKey,
	/// The ed25519 component failed strict verification.
	Ed25519Reject,
	/// The SLH-DSA component failed verification.
	SlhReject,
}

impl core::fmt::Display for HybridSigError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		let s = match self {
			Self::DomainTooLong => "domain exceeds the 255-byte FIPS 205 context limit",
			Self::BadLength => "wrong input length",
			Self::BadKey => "invalid key bytes",
			Self::Ed25519Reject => "ed25519 component rejected",
			Self::SlhReject => "SLH-DSA component rejected",
		};
		f.write_str(s)
	}
}

/// The FIPS 205 `M'` framing, applied identically to the ed25519 half:
/// `0x00 || len(domain) || domain || msg`. Length-prefixing removes any
/// ambiguity about where the domain ends and the message begins.
fn ed25519_preimage(domain: &[u8], msg: &[u8]) -> Result<Vec<u8>, HybridSigError> {
	let len = u8::try_from(domain.len()).map_err(|_| HybridSigError::DomainTooLong)?;
	let mut preimage = Vec::with_capacity(2 + domain.len() + msg.len());
	preimage.push(0u8);
	preimage.push(len);
	preimage.extend_from_slice(domain);
	preimage.extend_from_slice(msg);
	Ok(preimage)
}

/// Hybrid signing key: ed25519 seed + SLH-DSA-SHA2-128f secret key.
#[derive(Clone)]
pub struct HybridSigningKey {
	ed: ed25519_dalek::SigningKey,
	slh: slh_dsa::SigningKey<Sha2_128s>,
}

impl HybridSigningKey {
	/// Generate a fresh hybrid keypair from a cryptographic RNG.
	pub fn generate(rng: &mut impl rand_core::CryptoRngCore) -> Self {
		Self {
			ed: ed25519_dalek::SigningKey::generate(rng),
			slh: slh_dsa::SigningKey::new(rng),
		}
	}

	/// Deterministic keygen from one 32-byte master seed: HKDF-SHA256
	/// expands the seed into the ed25519 seed and the three FIPS 205
	/// keygen seeds (sk_seed, sk_prf, pk_seed), so keystores, chain-spec
	/// seeding, and hard derivation stay one-seed exactly like the
	/// classical schemes.
	pub fn from_seed(seed: &[u8; SEED_BYTES]) -> Self {
		let hk = Hkdf::<Sha256>::new(Some(KEYGEN_SALT), seed);
		let mut okm = [0u8; ED25519_SK_BYTES + 3 * 16];
		hk.expand(KEYGEN_SALT, &mut okm)
			.expect("80-byte expansion is far below the HKDF-SHA256 limit; qed");
		let ed_seed: [u8; ED25519_SK_BYTES] =
			okm[..ED25519_SK_BYTES].try_into().expect("slice length fixed above; qed");
		let (sk_seed, rest) = okm[ED25519_SK_BYTES..].split_at(16);
		let (sk_prf, pk_seed) = rest.split_at(16);
		Self {
			ed: ed25519_dalek::SigningKey::from_bytes(&ed_seed),
			slh: slh_dsa::SigningKey::slh_keygen_internal(sk_seed, sk_prf, pk_seed),
		}
	}

	/// Decode from `ed25519 seed (32) || SLH-DSA sk (64)`.
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, HybridSigError> {
		if bytes.len() != HYBRID_SK_BYTES {
			return Err(HybridSigError::BadLength);
		}
		let ed_seed: [u8; ED25519_SK_BYTES] =
			bytes[..ED25519_SK_BYTES].try_into().map_err(|_| HybridSigError::BadLength)?;
		let slh = slh_dsa::SigningKey::try_from(&bytes[ED25519_SK_BYTES..])
			.map_err(|_| HybridSigError::BadKey)?;
		Ok(Self { ed: ed25519_dalek::SigningKey::from_bytes(&ed_seed), slh })
	}

	/// Encode as `ed25519 seed (32) || SLH-DSA sk (64)`.
	pub fn to_vec(&self) -> Vec<u8> {
		let mut out = Vec::with_capacity(HYBRID_SK_BYTES);
		out.extend_from_slice(self.ed.as_bytes());
		out.extend_from_slice(&self.slh.to_bytes());
		out
	}

	/// The corresponding hybrid public key.
	pub fn verifying_key(&self) -> HybridVerifyingKey {
		HybridVerifyingKey {
			ed: self.ed.verifying_key(),
			slh: self.slh.as_ref().clone(),
		}
	}

	/// Sign `msg` with ONLY the ed25519 component, over the raw bytes
	/// (no hybrid `M'` framing). For consumers with hard byte budgets that
	/// authenticate against the ed25519 component of the hybrid public key
	/// (the validator-channel cert, docs/PQ-FINALITY.md D5). The caller's
	/// preimage must carry its own domain string. Raw preimages here can
	/// never collide with hybrid `M'` framings: `M'` begins with 0x00
	/// while every Rostro domain-prefixed preimage begins with an ASCII
	/// domain byte.
	pub fn sign_ed25519_component(&self, msg: &[u8]) -> [u8; ED25519_SIG_BYTES] {
		self.ed.sign(msg).to_bytes()
	}

	/// Sign `msg` under `domain` with both components (deterministic
	/// variants of both schemes; see crate docs).
	pub fn sign(&self, domain: &[u8], msg: &[u8]) -> Result<HybridSignature, HybridSigError> {
		let ed_sig = self.ed.sign(&ed25519_preimage(domain, msg)?);
		let slh_sig = self
			.slh
			.try_sign_with_context(msg, domain, None)
			.map_err(|_| HybridSigError::DomainTooLong)?;
		Ok(HybridSignature { ed: ed_sig, slh: slh_sig })
	}
}

/// Hybrid public key: ed25519 pk + SLH-DSA-SHA2-128f pk.
#[derive(Clone)]
pub struct HybridVerifyingKey {
	ed: ed25519_dalek::VerifyingKey,
	slh: slh_dsa::VerifyingKey<Sha2_128s>,
}

impl HybridVerifyingKey {
	/// Decode from `ed25519 pk (32) || SLH-DSA pk (32)`.
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, HybridSigError> {
		if bytes.len() != HYBRID_PK_BYTES {
			return Err(HybridSigError::BadLength);
		}
		let ed_pk: [u8; ED25519_PK_BYTES] =
			bytes[..ED25519_PK_BYTES].try_into().map_err(|_| HybridSigError::BadLength)?;
		let ed = ed25519_dalek::VerifyingKey::from_bytes(&ed_pk)
			.map_err(|_| HybridSigError::BadKey)?;
		let slh = slh_dsa::VerifyingKey::try_from(&bytes[ED25519_PK_BYTES..])
			.map_err(|_| HybridSigError::BadKey)?;
		Ok(Self { ed, slh })
	}

	/// Encode as `ed25519 pk (32) || SLH-DSA pk (32)`.
	pub fn to_vec(&self) -> Vec<u8> {
		let mut out = Vec::with_capacity(HYBRID_PK_BYTES);
		out.extend_from_slice(self.ed.as_bytes());
		out.extend_from_slice(&self.slh.to_bytes());
		out
	}

	/// The ed25519 component of the public key (the first 32 bytes of the
	/// hybrid encoding). Verifies signatures from
	/// [`HybridSigningKey::sign_ed25519_component`].
	pub fn ed25519_component(&self) -> [u8; ED25519_PK_BYTES] {
		*self.ed.as_bytes()
	}

	/// Verify both components over `msg` under `domain`. BOTH must pass.
	/// ed25519 (strict) is checked first: it is ~100x cheaper, so garbage
	/// rejects before any SLH-DSA hashing is spent.
	pub fn verify(
		&self,
		domain: &[u8],
		msg: &[u8],
		sig: &HybridSignature,
	) -> Result<(), HybridSigError> {
		self.ed
			.verify_strict(&ed25519_preimage(domain, msg)?, &sig.ed)
			.map_err(|_| HybridSigError::Ed25519Reject)?;
		self.slh
			.try_verify_with_context(msg, domain, &sig.slh)
			.map_err(|_| HybridSigError::SlhReject)
	}
}

/// Hybrid signature: ed25519 sig + SLH-DSA-SHA2-128f sig.
#[derive(Clone)]
pub struct HybridSignature {
	ed: ed25519_dalek::Signature,
	slh: slh_dsa::Signature<Sha2_128s>,
}

impl HybridSignature {
	/// Decode from `ed25519 sig (64) || SLH-DSA sig (7856)`.
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, HybridSigError> {
		if bytes.len() != HYBRID_SIG_BYTES {
			return Err(HybridSigError::BadLength);
		}
		let ed_sig: [u8; ED25519_SIG_BYTES] =
			bytes[..ED25519_SIG_BYTES].try_into().map_err(|_| HybridSigError::BadLength)?;
		let slh = slh_dsa::Signature::try_from(&bytes[ED25519_SIG_BYTES..])
			.map_err(|_| HybridSigError::BadLength)?;
		Ok(Self { ed: ed25519_dalek::Signature::from_bytes(&ed_sig), slh })
	}

	/// Encode as `ed25519 sig (64) || SLH-DSA sig (7856)`.
	pub fn to_vec(&self) -> Vec<u8> {
		let mut out = Vec::with_capacity(HYBRID_SIG_BYTES);
		out.extend_from_slice(&self.ed.to_bytes());
		out.extend_from_slice(&self.slh.to_vec());
		out
	}
}

#[cfg(test)]
mod tests;
