// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Bandersnatch VRF signing abstraction.
//!
//! The producer side of Sassafras (slot-claim VRF, ticket-id VRF
//! pre-output) needs to sign with a bandersnatch private key. Two
//! shapes that signing comes in:
//!
//! - **`AuthorityPair`** — direct keypair access. Used in tests
//!   where the test fixture generates a pair via SURI and signs
//!   directly. Cannot be safely used in production because the
//!   secret material is in plain memory.
//!
//! - **`KeystoreSigner`** — routes signing through
//!   [`sp_keystore::Keystore::bandersnatch_vrf_sign`]. The keystore
//!   may be memory-backed (testbed) or HSM-backed (production); the
//!   signer doesn't care.
//!
//! Both implement [`BandersnatchVrfSigner`]. Producer functions
//! ([`crate::produce_slot_claim`], [`crate::try_claim_slot`]) take
//! `&impl BandersnatchVrfSigner`, so the same code path serves tests
//! and production.

use sp_consensus_sassafras::{
	vrf::{VrfSignData, VrfSignature},
	AuthorityId, AuthorityPair, KEY_TYPE,
};
use sp_core::crypto::{VrfSecret, Wraps};
use sp_keystore::{Keystore, KeystorePtr};

/// Sign a Sassafras VRF input with the local bandersnatch key.
///
/// Returns `None` if the signer can't produce a signature — for the
/// keystore-backed signer, that means the public key isn't held
/// locally or the keystore returned an error.
pub trait BandersnatchVrfSigner {
	/// Sign `data` and return the VRF signature, or `None` if the
	/// signer can't produce one.
	fn vrf_sign(&self, data: &VrfSignData) -> Option<VrfSignature>;
}

impl BandersnatchVrfSigner for AuthorityPair {
	fn vrf_sign(&self, data: &VrfSignData) -> Option<VrfSignature> {
		Some(self.as_inner_ref().vrf_sign(data))
	}
}

/// Borrow form so test fixtures can pass `&authority_pair` directly.
impl<'a> BandersnatchVrfSigner for &'a AuthorityPair {
	fn vrf_sign(&self, data: &VrfSignData) -> Option<VrfSignature> {
		Some((*self).as_inner_ref().vrf_sign(data))
	}
}

/// Keystore-backed signer. Production path; routes signing through
/// [`sp_keystore::Keystore::bandersnatch_vrf_sign`].
pub struct KeystoreSigner<'a> {
	/// Substrate keystore handle.
	pub keystore: &'a KeystorePtr,
	/// The local authority's public key — used to identify which
	/// keypair in the keystore signs.
	pub authority: &'a AuthorityId,
}

impl<'a> BandersnatchVrfSigner for KeystoreSigner<'a> {
	fn vrf_sign(&self, data: &VrfSignData) -> Option<VrfSignature> {
		Keystore::bandersnatch_vrf_sign(
			self.keystore.as_ref(),
			KEY_TYPE,
			self.authority.as_inner_ref(),
			data,
		)
		.ok()
		.flatten()
	}
}
