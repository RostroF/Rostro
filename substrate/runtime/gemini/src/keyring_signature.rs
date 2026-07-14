// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Keyring-aware extrinsic signature: the stateful-verification shim.
//!
//! `generic::UncheckedExtrinsic`'s `Checkable` impl authenticates a
//! signed extrinsic with `signature.verify(payload, &signer)` — the
//! stateless `Verify` trait. The account keyring (docs/KEYRING.md)
//! needs that check to consult chain state, so the extrinsic signature
//! type is this newtype: SCALE-transparent over [`RostroSignature`]
//! (signed extrinsics are byte-identical on the wire), with a `Verify`
//! impl that routes through
//! `pallet_rostro_keyring::verify_extrinsic_signature`. Upstream
//! substrate would never accept stateful signature verification; we own
//! the stack, so we can.
//!
//! Only the extrinsic path uses this type. Pallet-level signature
//! checks (bilateral receipts etc.) stay on plain `RostroSignature` —
//! those verify *documents*, where derived-key semantics are the
//! correct, stateless contract.

use crate::Runtime;
use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use rostro_multi_key::{RostroSignature, RostroSigner};
use scale_info::TypeInfo;
use sp_core::crypto::AccountId32;
use sp_runtime::traits::{Lazy, Verify};

/// The gemini extrinsic signature: [`RostroSignature`] with keyring-
/// aware verification. Wire-format identical to the inner enum.
#[derive(
	Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo, Clone, Eq, PartialEq, Debug,
)]
pub struct KeyringSignature(pub RostroSignature);

impl From<RostroSignature> for KeyringSignature {
	fn from(sig: RostroSignature) -> Self {
		Self(sig)
	}
}

impl Verify for KeyringSignature {
	type Signer = RostroSigner;
	fn verify<L: Lazy<[u8]>>(&self, mut msg: L, signer: &AccountId32) -> bool {
		pallet_rostro_keyring::Pallet::<Runtime>::verify_extrinsic_signature(
			&self.0,
			msg.get(),
			signer,
		)
	}
}
