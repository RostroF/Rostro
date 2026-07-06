// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Rostro hybrid (ed25519 + SLH-DSA-SHA2-128f) crypto types.
//!
//! Application-crypto plumbing for the post-quantum finality-vote scheme
//! (docs/PQ-FINALITY.md). Keystore-touching operations (`all`,
//! `generate_pair`, `sign`) route through the sp_io host functions like
//! every other scheme; `verify` is deliberately PURE in-runtime (decision
//! D6): a justification or equivocation proof verifies identically under
//! native and RISC-V execution, fixed by the runtime blob rather than the
//! node build, with no host function on the trust path.

use crate::{KeyTypeId, RuntimePublic};

use alloc::vec::Vec;

use sp_core::proof_of_possession::NonAggregatable;
pub use sp_core::{
	crypto::{CryptoBytes, SignatureBytes},
	rostro_hybrid::*,
};

mod app {
	crate::app_crypto!(super, sp_core::testing::ROSTRO_HYBRID);
}

pub use app::{
	Pair as AppPair, ProofOfPossession as AppProofOfPossession, Public as AppPublic,
	Signature as AppSignature,
};

impl RuntimePublic for Public {
	type Signature = Signature;
	type ProofOfPossession = Signature;

	fn all(key_type: KeyTypeId) -> crate::Vec<Self> {
		sp_io::crypto::rostro_hybrid_public_keys(key_type)
	}

	fn generate_pair(key_type: KeyTypeId, seed: Option<Vec<u8>>) -> Self {
		sp_io::crypto::rostro_hybrid_generate(key_type, seed)
	}

	fn sign<M: AsRef<[u8]>>(&self, key_type: KeyTypeId, msg: &M) -> Option<Self::Signature> {
		sp_io::crypto::rostro_hybrid_sign(key_type, self, msg.as_ref())
	}

	fn verify<M: AsRef<[u8]>>(&self, msg: &M, signature: &Self::Signature) -> bool {
		// Pure in-runtime verification (D6): no host call.
		<Pair as sp_core::crypto::Pair>::verify(signature, msg.as_ref(), self)
	}

	fn generate_proof_of_possession(
		&mut self,
		key_type: KeyTypeId,
		owner: &[u8],
	) -> Option<Self::ProofOfPossession> {
		let proof_of_possession_statement = Pair::proof_of_possession_statement(owner);
		sp_io::crypto::rostro_hybrid_sign(key_type, self, &proof_of_possession_statement)
	}

	fn verify_proof_of_possession(
		&self,
		owner: &[u8],
		proof_of_possession: &Self::ProofOfPossession,
	) -> bool {
		let proof_of_possession_statement = Pair::proof_of_possession_statement(owner);
		<Pair as sp_core::crypto::Pair>::verify(
			proof_of_possession,
			&proof_of_possession_statement,
			self,
		)
	}

	fn to_raw_vec(&self) -> Vec<u8> {
		sp_core::crypto::ByteArray::to_raw_vec(self)
	}
}
