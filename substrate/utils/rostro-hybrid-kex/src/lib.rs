// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # rostro-hybrid-kex
//!
//! X25519MLKEM768-style hybrid key agreement for Rostro transport
//! handshakes (see `docs/PQ-TRANSPORT.md`).
//!
//! The construction mirrors the TLS `X25519MLKEM768` named group: an
//! ML-KEM-768 encapsulation rides alongside the existing X25519
//! ephemeral exchange, and the two shared secrets are combined with
//! HKDF-SHA256 — **ML-KEM secret first, X25519 secret second**, matching
//! the TLS ordering. The hybrid secret is post-quantum confidential as
//! long as *either* component holds: Shor breaks X25519, and a future
//! lattice-cryptanalysis result could break ML-KEM, but recorded traffic
//! only falls if both do.
//!
//! Feeding the hybrid secret into a handshake in place of the raw X25519
//! secret is the *entire* integration: because the double-ratchet key
//! schedule threads the handshake secret through every message key (the
//! root key salts every HKDF step), a hybrid initial handshake already
//! defeats retroactive decryption of the whole recorded session. Ratchet
//! steps stay classical X25519.
//!
//! Both chain and wallet MUST derive the hybrid secret through this
//! crate. A parallel reimplementation risks combine-order or info-string
//! drift, which desynchronizes sessions undetectably until Q-day.
//!
//! This crate is also where the NIST ACVP known-answer tests for the
//! vendored `ml-kem` crate live: the crates.io tarball excludes
//! upstream's own KAT files, so the fixtures here are the only KAT
//! coverage the vendored code gets. See `src/kat_mlkem768.rs`.

#![cfg_attr(not(feature = "std"), no_std)]

use hkdf::Hkdf;
use ml_kem::{
	array::Array, kem::TryDecapsulate, ml_kem_768, B32, DecapsulationKey768, EncapsulationKey768,
	KeyExport, Seed,
};
use sha2::Sha256;

/// ML-KEM-768 encapsulation-key length in bytes (FIPS 203, table 3).
pub const MLKEM768_EK_BYTES: usize = 1184;
/// ML-KEM-768 ciphertext length in bytes (FIPS 203, table 3).
pub const MLKEM768_CT_BYTES: usize = 1088;
/// ML-KEM-768 keypair seed length in bytes (`d || z`).
pub const MLKEM768_SEED_BYTES: usize = 64;
/// Shared-secret length in bytes — ML-KEM output, X25519 output, and the
/// hybrid combination are all 32 bytes.
pub const SHARED_SECRET_BYTES: usize = 32;

/// HKDF info string for the hybrid combine. Versioned: any change to the
/// construction (ordering, KDF, parameter set) is a new info string and a
/// new handshake protocol version, never a silent in-place change.
const HYBRID_KDF_INFO: &[u8] = b"rostro/hybrid-kex/v1/mlkem768+x25519";

/// Re-export of the vendored ML-KEM-768 decapsulation key. Hold it (or
/// its 64-byte seed) on the responder side of a handshake.
pub type MlKemDecapKey = DecapsulationKey768;

/// Errors from ML-KEM operations on untrusted wire bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HybridKexError {
	/// The peer's encapsulation key failed FIPS 203 modulus validation.
	InvalidEncapsulationKey,
	/// Decapsulation rejected the input outright (distinct from implicit
	/// rejection, which succeeds with a garbage-but-deterministic key).
	InvalidCiphertext,
}

/// Deterministically derive an ML-KEM-768 keypair from a 64-byte seed
/// (`d || z`). The seed MUST be fresh CSPRNG output; it is the long-lived
/// secret and is sufficient to reconstruct the decapsulation key.
///
/// Returns the decapsulation key and the encapsulation key's wire bytes.
pub fn mlkem_keypair_from_seed(
	seed: &[u8; MLKEM768_SEED_BYTES],
) -> (MlKemDecapKey, [u8; MLKEM768_EK_BYTES]) {
	let seed: Seed = Array::from(*seed);
	let dk = DecapsulationKey768::from_seed(seed);
	let mut ek_bytes = [0u8; MLKEM768_EK_BYTES];
	ek_bytes.copy_from_slice(dk.encapsulation_key().to_bytes().as_slice());
	(dk, ek_bytes)
}

/// Encapsulate against a peer's encapsulation key using caller-supplied
/// randomness `m`, which MUST be 32 fresh CSPRNG bytes and never reused.
/// (Randomness is a parameter rather than an RNG so no_std callers and
/// the KAT fixtures share one code path.)
///
/// Returns the ciphertext to send to the peer and the local copy of the
/// ML-KEM shared secret.
pub fn mlkem_encapsulate(
	peer_ek: &[u8; MLKEM768_EK_BYTES],
	m: &[u8; 32],
) -> Result<([u8; MLKEM768_CT_BYTES], [u8; SHARED_SECRET_BYTES]), HybridKexError> {
	let ek_arr = Array::from(*peer_ek);
	let ek = EncapsulationKey768::new(&ek_arr)
		.map_err(|_| HybridKexError::InvalidEncapsulationKey)?;
	let m: B32 = Array::from(*m);
	let (ct, ss) = ek.encapsulate_deterministic(&m);
	let mut ct_bytes = [0u8; MLKEM768_CT_BYTES];
	ct_bytes.copy_from_slice(ct.as_slice());
	let mut ss_bytes = [0u8; SHARED_SECRET_BYTES];
	ss_bytes.copy_from_slice(ss.as_slice());
	Ok((ct_bytes, ss_bytes))
}

/// Decapsulate a peer's ciphertext. Per FIPS 203, a mangled ciphertext
/// does not error: implicit rejection returns a deterministic
/// garbage key and the handshake fails later at the AEAD, revealing
/// nothing about *why* to the peer.
pub fn mlkem_decapsulate(
	dk: &MlKemDecapKey,
	ct: &[u8; MLKEM768_CT_BYTES],
) -> Result<[u8; SHARED_SECRET_BYTES], HybridKexError> {
	let ct: ml_kem_768::Ciphertext = Array::from(*ct);
	let ss = dk.try_decapsulate(&ct).map_err(|_| HybridKexError::InvalidCiphertext)?;
	let mut ss_bytes = [0u8; SHARED_SECRET_BYTES];
	ss_bytes.copy_from_slice(ss.as_slice());
	Ok(ss_bytes)
}

/// Combine the two component secrets into the hybrid handshake secret:
/// `HKDF-SHA256(salt = none, ikm = mlkem_ss || x25519_ss, info = v1)`.
///
/// ML-KEM secret first, X25519 second — the TLS `X25519MLKEM768`
/// ordering. The output feeds the channel key schedule exactly where the
/// raw X25519 shared secret goes today.
pub fn hybrid_shared_secret(
	mlkem_ss: &[u8; SHARED_SECRET_BYTES],
	x25519_ss: &[u8; SHARED_SECRET_BYTES],
) -> [u8; SHARED_SECRET_BYTES] {
	let mut ikm = [0u8; 64];
	ikm[..32].copy_from_slice(mlkem_ss);
	ikm[32..].copy_from_slice(x25519_ss);
	let hk = Hkdf::<Sha256>::new(None, &ikm);
	let mut out = [0u8; SHARED_SECRET_BYTES];
	hk.expand(HYBRID_KDF_INFO, &mut out)
		.expect("32 bytes is a valid HKDF-SHA256 output length; qed");
	ikm.iter_mut().for_each(|b| *b = 0);
	out
}

#[cfg(test)]
mod kat_mlkem768;
#[cfg(test)]
mod tests;
