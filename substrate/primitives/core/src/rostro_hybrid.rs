// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Rostro hybrid consensus signature: ed25519 + SLH-DSA-SHA2-128f.
//!
//! sp-core-level scheme module for the post-quantum finality-vote key
//! (docs/PQ-FINALITY.md, decision D2). All cryptography delegates to
//! `rostro-hybrid-sig`, the KAT-pinned leaf crate: both components sign
//! the same domain-framed preimage and BOTH must verify. This module only
//! adapts that leaf to the `sp_core::crypto::Pair` shape so the
//! `app_crypto!` machinery, the keystore, and session keys can carry it
//! exactly like the classical schemes.
//!
//! The secret material is the 32-byte master seed (`to_raw_vec` returns
//! it, `from_seed_slice` reconstructs deterministically via the leaf's
//! HKDF expansion), so keystore files, chain-spec seeding, and hard
//! derivation stay one-seed. Soft derivation is impossible for a
//! hash-based component and returns `DeriveError::SoftKeyInPath`.

use crate::{
	crypto::{
		CryptoType, CryptoTypeId, DeriveError, DeriveJunction, Pair as TraitPair, PublicBytes,
		SecretStringError, SignatureBytes,
	},
	proof_of_possession::NonAggregatable,
};

use alloc::vec::Vec;
use rostro_hybrid_sig::{
	HybridSignature, HybridSigningKey, HybridVerifyingKey, FINALITY_VOTE_DOMAIN,
};

/// An identifier used to match public keys against Rostro hybrid keys.
pub const CRYPTO_ID: CryptoTypeId = CryptoTypeId(*b"rhyb");

/// The byte length of a public key: ed25519 (32) || SLH-DSA-SHA2-128f (32).
pub const PUBLIC_KEY_SERIALIZED_SIZE: usize = rostro_hybrid_sig::HYBRID_PK_BYTES;

/// The byte length of a signature: ed25519 (64) || SLH-DSA-SHA2-128f (17088).
pub const SIGNATURE_SERIALIZED_SIZE: usize = rostro_hybrid_sig::HYBRID_SIG_BYTES;

/// The domain every signature from this scheme is framed under. The
/// protocol-level scoping (round, set_id) rides in the message payload as
/// with classical GRANDPA; the scheme domain guarantees a signature from
/// this key type verifies under no other Rostro domain and vice versa.
const SCHEME_DOMAIN: &[u8] = FINALITY_VOTE_DOMAIN;

/// A secret seed: the single 32-byte master the whole hybrid pair expands
/// from (HKDF-SHA256, see `rostro-hybrid-sig`).
type Seed = [u8; 32];

#[doc(hidden)]
pub struct RostroHybridTag;

/// A public key.
pub type Public = PublicBytes<PUBLIC_KEY_SERIALIZED_SIZE, RostroHybridTag>;

/// A signature.
pub type Signature = SignatureBytes<SIGNATURE_SERIALIZED_SIZE, RostroHybridTag>;

/// Proof of Possession is a plain signature, as for ed25519.
pub type ProofOfPossession = Signature;

/// A key pair.
#[derive(Clone)]
pub struct Pair {
	seed: Seed,
	inner: HybridSigningKey,
}

/// Derive a single hard junction on the master seed.
fn derive_hard_junction(secret_seed: &Seed, cc: &[u8; 32]) -> Seed {
	use codec::Encode;
	("RostroHybridHDKD", secret_seed, cc).using_encoded(sp_crypto_hashing::blake2_256)
}

impl TraitPair for Pair {
	type Public = Public;
	type Seed = Seed;
	type Signature = Signature;
	type ProofOfPossession = ProofOfPossession;

	fn from_seed_slice(seed_slice: &[u8]) -> Result<Pair, SecretStringError> {
		let seed: Seed =
			seed_slice.try_into().map_err(|_| SecretStringError::InvalidSeedLength)?;
		Ok(Pair { seed, inner: HybridSigningKey::from_seed(&seed) })
	}

	fn derive<Iter: Iterator<Item = DeriveJunction>>(
		&self,
		path: Iter,
		_seed: Option<Seed>,
	) -> Result<(Pair, Option<Seed>), DeriveError> {
		let mut acc = self.seed;
		for j in path {
			match j {
				DeriveJunction::Soft(_cc) => return Err(DeriveError::SoftKeyInPath),
				DeriveJunction::Hard(cc) => acc = derive_hard_junction(&acc, &cc),
			}
		}
		Ok((Self::from_seed(&acc), Some(acc)))
	}

	fn public(&self) -> Public {
		let bytes: [u8; PUBLIC_KEY_SERIALIZED_SIZE] = self
			.inner
			.verifying_key()
			.to_vec()
			.try_into()
			.expect("hybrid public key length is pinned by rostro-hybrid-sig tests; qed");
		Public::from_raw(bytes)
	}

	#[cfg(feature = "full_crypto")]
	fn sign(&self, message: &[u8]) -> Signature {
		let sig = self
			.inner
			.sign(SCHEME_DOMAIN, message)
			.expect("SCHEME_DOMAIN is far below the 255-byte context limit; qed");
		let bytes: alloc::boxed::Box<[u8; SIGNATURE_SERIALIZED_SIZE]> = sig
			.to_vec()
			.into_boxed_slice()
			.try_into()
			.expect("hybrid signature length is pinned by rostro-hybrid-sig tests; qed");
		Signature::from_raw(*bytes)
	}

	fn verify<M: AsRef<[u8]>>(sig: &Signature, message: M, public: &Public) -> bool {
		let Ok(vk) = HybridVerifyingKey::from_bytes(public.as_ref() as &[u8]) else {
			return false;
		};
		let Ok(signature) = HybridSignature::from_bytes(sig.as_ref() as &[u8]) else {
			return false;
		};
		vk.verify(SCHEME_DOMAIN, message.as_ref(), &signature).is_ok()
	}

	fn to_raw_vec(&self) -> Vec<u8> {
		self.seed.to_vec()
	}
}

impl Pair {
	/// Get the master seed for this key.
	pub fn seed(&self) -> Seed {
		self.seed
	}

	/// The ed25519 component of the public key: the first 32 bytes of the
	/// hybrid encoding. Consumers with hard byte budgets (the
	/// validator-channel cert, docs/PQ-FINALITY.md D5) authenticate
	/// against this component.
	pub fn public_ed25519_component(public: &Public) -> [u8; 32] {
		let mut out = [0u8; 32];
		out.copy_from_slice(&(public.as_ref() as &[u8])[..32]);
		out
	}
}

impl CryptoType for Public {
	type Pair = Pair;
}

impl CryptoType for Signature {
	type Pair = Pair;
}

impl CryptoType for Pair {
	type Pair = Pair;
}

impl NonAggregatable for Pair {}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn seed_determinism_and_roundtrip() {
		let seed = [11u8; 32];
		let a = Pair::from_seed(&seed);
		let b = Pair::from_seed(&seed);
		assert_eq!(a.public(), b.public());
		assert_eq!(a.to_raw_vec(), seed.to_vec());

		let msg = b"hybrid sp-core roundtrip";
		let sig = a.sign(msg);
		assert!(Pair::verify(&sig, msg, &b.public()));
		assert!(!Pair::verify(&sig, b"other message", &b.public()));
	}

	#[test]
	fn hard_derivation_works_soft_fails() {
		let pair = Pair::from_seed(&[3u8; 32]);
		let (hard, hard_seed) =
			pair.derive([DeriveJunction::hard("rot1")].into_iter(), None).unwrap();
		assert_ne!(pair.public(), hard.public());
		// Derivation is deterministic and reconstructible from the seed.
		let again = Pair::from_seed(&hard_seed.unwrap());
		assert_eq!(hard.public(), again.public());

		assert!(matches!(
			pair.derive([DeriveJunction::soft("nope")].into_iter(), None),
			Err(DeriveError::SoftKeyInPath)
		));
	}

	#[test]
	fn string_paths_work() {
		// The //hard derivation path used by chain-spec seeding.
		let alice = Pair::from_string("//Alice", None).unwrap();
		let alice2 = Pair::from_string("//Alice", None).unwrap();
		let bob = Pair::from_string("//Bob", None).unwrap();
		assert_eq!(alice.public(), alice2.public());
		assert_ne!(alice.public(), bob.public());
	}

	#[test]
	fn sizes_pinned() {
		assert_eq!(PUBLIC_KEY_SERIALIZED_SIZE, 64);
		assert_eq!(SIGNATURE_SERIALIZED_SIZE, 17152);
		let pair = Pair::from_seed(&[9u8; 32]);
		let public = pair.public();
		let public_bytes: &[u8] = public.as_ref();
		assert_eq!(public_bytes.len(), PUBLIC_KEY_SERIALIZED_SIZE);
	}

	#[test]
	fn proof_of_possession_works() {
		use crate::proof_of_possession::{ProofOfPossessionGenerator, ProofOfPossessionVerifier};
		let mut pair = Pair::from_seed(&[5u8; 32]);
		let other = Pair::from_seed(&[6u8; 32]);
		let owner = b"validator-stash";
		let pop = pair.generate_proof_of_possession(owner);
		assert!(Pair::verify_proof_of_possession(owner, &pop, &pair.public()));
		assert!(!Pair::verify_proof_of_possession(owner, &pop, &other.public()));
		assert!(!Pair::verify_proof_of_possession(b"not-owner", &pop, &pair.public()));
	}
}
