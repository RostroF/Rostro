// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! Per-cipher verify operations. Guest (`target_env = "polkavm"`) marshals
//! to the RVM ecalli intrinsics; native mirrors the intrinsic bodies using
//! the same reference crates (see the crate doc's single-source-of-truth
//! requirement). Classical schemes that sp_io already covers (ed25519,
//! sr25519, ecdsa-k1 verify) delegate to sp_io on both targets — those host
//! functions are already native.
//!
//! All zero-length slices are safe to pass on the guest: the intrinsic arms
//! short-circuit `len == 0` before borrowing, so the dangling pointer a
//! guest-side empty slice carries is never dereferenced.

/// P-256 ECDSA verify over a caller-supplied prehash (usually SHA-256).
/// `vk` is a 33-byte compressed SEC1 point; `sig` is raw `r ‖ s`.
/// Verify-only by threat model: all inputs are consensus-public.
pub fn p256_verify_prehash(vk: &[u8; 33], sig: &[u8; 64], prehash: &[u8]) -> bool {
	#[cfg(target_env = "polkavm")]
	unsafe {
		crate::ecalli::rostro_p256_verify_prehash(
			vk.as_ptr() as u32,
			sig.as_ptr() as u32,
			prehash.as_ptr() as u32,
			prehash.len() as u32,
		) == 1
	}
	#[cfg(not(target_env = "polkavm"))]
	{
		use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
		let Ok(vk) = VerifyingKey::from_sec1_bytes(vk) else { return false };
		let Ok(sig) = Signature::from_slice(sig) else { return false };
		vk.verify_prehash(prehash, &sig).is_ok()
	}
}

/// P-521 ECDSA verify over a caller-supplied prehash (usually SHA-512).
/// `vk` is a 133-byte uncompressed SEC1 point; `sig` is raw `r ‖ s`.
pub fn p521_verify_prehash(vk: &[u8; 133], sig: &[u8; 132], prehash: &[u8]) -> bool {
	#[cfg(target_env = "polkavm")]
	unsafe {
		crate::ecalli::rostro_p521_verify_prehash(
			vk.as_ptr() as u32,
			sig.as_ptr() as u32,
			prehash.as_ptr() as u32,
			prehash.len() as u32,
		) == 1
	}
	#[cfg(not(target_env = "polkavm"))]
	{
		use p521::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
		let Ok(vk) = VerifyingKey::from_sec1_bytes(vk) else { return false };
		let Ok(sig) = Signature::from_slice(sig) else { return false };
		vk.verify_prehash(prehash, &sig).is_ok()
	}
}

/// ML-DSA-65 (FIPS 204) verify with context string.
pub fn mldsa65_verify(pk: &[u8; 1952], msg: &[u8], sig: &[u8; 3309], ctx: &[u8]) -> bool {
	#[cfg(target_env = "polkavm")]
	unsafe {
		crate::ecalli::rostro_mldsa65_verify(
			pk.as_ptr() as u32,
			msg.as_ptr() as u32,
			msg.len() as u32,
			sig.as_ptr() as u32,
			ctx.as_ptr() as u32,
			ctx.len() as u32,
		) == 1
	}
	#[cfg(not(target_env = "polkavm"))]
	{
		use fips204::ml_dsa_65;
		use fips204::traits::{SerDes, Verifier};
		let Ok(pk) = ml_dsa_65::PublicKey::try_from_bytes(*pk) else { return false };
		pk.verify(msg, sig, ctx)
	}
}

/// SLH-DSA-SHA2-128s (FIPS 205) verify with context string. The finality-
/// vote scheme; natively this uses the SAME vendored `slh-dsa` crate the
/// node's hybrid verifier (rostro-hybrid-sig) and the intrinsic body trust.
pub fn slhdsa128s_verify(pk: &[u8; 32], msg: &[u8], sig: &[u8; 7856], ctx: &[u8]) -> bool {
	#[cfg(target_env = "polkavm")]
	unsafe {
		crate::ecalli::rostro_slhdsa128s_verify(
			pk.as_ptr() as u32,
			msg.as_ptr() as u32,
			msg.len() as u32,
			sig.as_ptr() as u32,
			ctx.as_ptr() as u32,
			ctx.len() as u32,
		) == 1
	}
	#[cfg(not(target_env = "polkavm"))]
	{
		use slh_dsa::Sha2_128s;
		let Ok(vk) = slh_dsa::VerifyingKey::<Sha2_128s>::try_from(&pk[..]) else { return false };
		let Ok(sig) = slh_dsa::Signature::<Sha2_128s>::try_from(&sig[..]) else { return false };
		vk.try_verify_with_context(msg, ctx, &sig).is_ok()
	}
}

/// secp256k1 ECDSA public-key recovery (Ethereum-strict: low-s only,
/// recovery id ∈ {0, 1}). `sig` is `r ‖ s ‖ v`; returns the 64-byte
/// uncompressed public key (`X ‖ Y`, no 0x04 prefix) or `None`.
///
/// For extrinsic signature checking, sp_io's `secp256k1_ecdsa_recover`
/// remains the established path; this entry serves guest code outside
/// sp_io contexts.
pub fn secp256k1_recover(msg_hash: &[u8; 32], sig: &[u8; 65]) -> Option<[u8; 64]> {
	#[cfg(target_env = "polkavm")]
	unsafe {
		let mut out = [0u8; 64];
		(crate::ecalli::rostro_secp256k1_recover(
			msg_hash.as_ptr() as u32,
			sig.as_ptr() as u32,
			out.as_mut_ptr() as u32,
		) == 1)
			.then_some(out)
	}
	#[cfg(not(target_env = "polkavm"))]
	{
		use k256::ecdsa::{RecoveryId, Signature as K256Signature, VerifyingKey};
		let v = sig[64];
		if v > 1 {
			return None;
		}
		let Ok(parsed) = K256Signature::from_slice(&sig[..64]) else { return None };
		// Reject high-s rather than normalize: exactly one canonical sig
		// per (msg, pk), matching the intrinsic body and Ethereum.
		if parsed.normalize_s().is_some() {
			return None;
		}
		let recid = RecoveryId::from_byte(v)?;
		let Ok(vk) = VerifyingKey::recover_from_prehash(msg_hash, &parsed, recid) else {
			return None;
		};
		let pk_sec1 = vk.to_encoded_point(false);
		let pk_bytes = pk_sec1.as_bytes();
		if pk_bytes.len() != 65 || pk_bytes[0] != 0x04 {
			return None;
		}
		let mut out = [0u8; 64];
		out.copy_from_slice(&pk_bytes[1..]);
		Some(out)
	}
}

/// BLS12-381 multi-pairing product-is-identity check with CHECKED
/// deserialization (on-curve + subgroup) — the standalone adversarial
/// verifier, distinct from the hooks' unchecked Miller-loop path.
/// `pairs` is `n × 288` bytes (`G1 uncompressed 96 ‖ G2 uncompressed 192`),
/// `1 ≤ n ≤ MAX_BLS_PAIRS`.
pub fn bls381_pairing_check(pairs: &[u8]) -> bool {
	if pairs.is_empty() || pairs.len() % 288 != 0 {
		return false;
	}
	let n = pairs.len() / 288;
	if n > crate::MAX_BLS_PAIRS {
		return false;
	}
	#[cfg(target_env = "polkavm")]
	unsafe {
		crate::ecalli::rostro_bls381_pairing_check(pairs.as_ptr() as u32, n as u32) == 1
	}
	#[cfg(not(target_env = "polkavm"))]
	{
		use ark_bls12_381::{Bls12_381, G1Affine, G2Affine};
		use ark_ec::pairing::Pairing;
		use ark_ff::One;
		use ark_serialize::CanonicalDeserialize;
		let mut g1s = ark_std::vec::Vec::with_capacity(n);
		let mut g2s = ark_std::vec::Vec::with_capacity(n);
		for i in 0..n {
			let off = i * 288;
			let Ok(g1) = G1Affine::deserialize_uncompressed(&pairs[off..off + 96]) else {
				return false;
			};
			let Ok(g2) = G2Affine::deserialize_uncompressed(&pairs[off + 96..off + 288]) else {
				return false;
			};
			g1s.push(g1);
			g2s.push(g2);
		}
		Bls12_381::multi_pairing(g1s, g2s).0.is_one()
	}
}

/// Ed25519 verify (ZIP-215 semantics via the node's host function).
/// Delegates to sp_io on both targets.
pub fn ed25519_verify(sig: &[u8; 64], msg: &[u8], pk: &[u8; 32]) -> bool {
	let sig = sp_core::ed25519::Signature::from_raw(*sig);
	let pk = sp_core::ed25519::Public::from_raw(*pk);
	sp_io::crypto::ed25519_verify(&sig, msg, &pk)
}

/// sr25519 verify (substrate signing context). Delegates to sp_io on both
/// targets.
pub fn sr25519_verify(sig: &[u8; 64], msg: &[u8], pk: &[u8; 32]) -> bool {
	let sig = sp_core::sr25519::Signature::from_raw(*sig);
	let pk = sp_core::sr25519::Public::from_raw(*pk);
	sp_io::crypto::sr25519_verify(&sig, msg, &pk)
}

/// secp256k1 ECDSA verify of a 65-byte recoverable signature against a
/// 33-byte compressed public key. Delegates to sp_io on both targets.
pub fn ecdsa_verify_prehashed(sig: &[u8; 65], msg_hash: &[u8; 32], pk: &[u8; 33]) -> bool {
	let sig = sp_core::ecdsa::Signature::from_raw(*sig);
	let pk = sp_core::ecdsa::Public::from_raw(*pk);
	sp_io::crypto::ecdsa_verify_prehashed(&sig, msg_hash, &pk)
}
