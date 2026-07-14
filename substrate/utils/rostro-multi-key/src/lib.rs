// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # rostro-multi-key
//!
//! Multi-scheme signer + signature primitive for Rostro. Supports three
//! signing schemes — Ed25519, Sr25519 (substrate-native), and Ecdsa
//! (secp256k1) — and produces a single 32-byte `AccountId32` per pubkey:
//!
//! - **Ed25519:** raw 32-byte pubkey. Source-matches Solana, Aptos, Sui,
//!   Cosmos, and Polkadot-Ledger accounts.
//! - **Sr25519:** raw 32-byte pubkey — byte-for-byte identical to
//!   Polkadot/Substrate `MultiSignature`. A Polkadot holder's existing
//!   account *is* their Rostro account (modulo SS58 prefix), which is
//!   what lets a stock Polkadot wallet see and spend a Rostro airdrop.
//!
//! Sr25519 and Ed25519 therefore share the raw-pubkey namespace. We do
//! **not** domain-separate them: a cross-scheme collision needs one
//! 32-byte value to be a valid point under both curves with someone
//! holding both secret keys — ~1 in 2^256 by chance, and DLP-infeasible
//! to target. The scheme is identified by the *signature* variant, never
//! inferred from the account, so verification always uses the right
//! curve. This is exactly the posture Substrate has shipped for years.
//!
//! - **Ecdsa:** Ethereum-style — `last_20_bytes(keccak256(uncompressed_pubkey))`
//!   zero-padded to 32 bytes. Source-matches Ethereum: a MetaMask user's
//!   `0xABC…` is the trailing 20 bytes of their Rostro AccountId32.
//!
//! Variant order — `Ed25519`, `Sr25519`, `Ecdsa` — mirrors substrate's
//! `MultiSigner`/`MultiSignature`, so the three native signature variants
//! are byte-identical on the wire: a stock Polkadot wallet's signed
//! extrinsic decodes and verifies here unchanged. A fourth signature
//! variant, `EcdsaEip191`, carries the MetaMask `personal_sign` flow.
//!
//! - `Ed25519(sig)` / `Sr25519(sig)` — pubkey taken from the signer
//!   AccountId32 (which *is* the raw pubkey).
//! - `Ecdsa(sig)` — substrate-style raw ecdsa over `blake2_256(msg)`,
//!   pubkey recovered via `secp256k1_ecdsa_recover`.
//! - `EcdsaEip191(sig)` — MetaMask `personal_sign` flow: payload wrapped
//!   as `"\x19Ethereum Signed Message:\n<len>" ‖ msg`, keccak256-hashed
//!   before recovery.
//!
//! A fifth scheme, **EcdsaP256** (NIST secp256r1), is the
//! hardware-secure-element variant: the signing key lives in device
//! silicon (StrongBox, TPM2, and the zkpki/PoP stack all speak P-256) and
//! never leaves it. It breaks the raw-pubkey-as-address mould because a
//! P-256 pubkey is 33 bytes: the account is `blake2_256(compressed
//! pubkey)`, so the pubkey rides *in* the signature and gets a pubkey-hash
//! shield for free. Verify routes through `rostro-guest-crypto` (RVM
//! ecalli 112 in the runtime, the `p256` crate natively), over
//! `sha256(payload)`, with low-s canonicalization enforced on-chain. It is
//! append-only variant index 4 on `RostroSignature` (after `EcdsaEip191`);
//! the `WebAuthnP256` envelope reserves index 5 next to it. A device key
//! is never a *sole* authority — the wallet enrolls a recoverable key
//! beside it (client-enforced in Stage A; see docs/PQ-SIGNATURES.md).
//!
//! Both chain (`gemini-runtime`) and wallet (`dotwave`) MUST import this
//! crate's `RostroSigner::into_account()` directly. Parallel
//! reimplementation in either layer would risk address-derivation drift
//! and stranded funds. The fixture tests pin known `(scheme, pubkey) →
//! AccountId32` vectors — including a Polkadot-parity vector — and re-run
//! on every CI build to catch any accidental change to the derivation.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_core::{crypto::AccountId32, ecdsa, ed25519, sr25519};
use sp_io::{
	crypto::{secp256k1_ecdsa_recover, secp256k1_ecdsa_recover_compressed},
	hashing::{blake2_256, keccak_256, sha2_256},
};
use sp_runtime::traits::{IdentifyAccount, Lazy, Verify};

/// serde `with` adapter for byte arrays longer than 32 (serde's blanket
/// impls stop at 32). Serializes as the raw byte sequence; used for the
/// P-256 compressed pubkey (33) and raw signature (64). std-only, matching
/// the enum's `cfg_attr(std, derive(Serialize, Deserialize))`.
#[cfg(feature = "std")]
mod serde_bytes_array {
	use serde::{Deserialize, Deserializer, Serialize, Serializer};

	pub fn serialize<S: Serializer, const N: usize>(bytes: &[u8; N], s: S) -> Result<S::Ok, S::Error> {
		bytes[..].serialize(s)
	}

	pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(d: D) -> Result<[u8; N], D::Error> {
		let v = alloc::vec::Vec::<u8>::deserialize(d)?;
		v.try_into()
			.map_err(|v: alloc::vec::Vec<u8>| serde::de::Error::invalid_length(v.len(), &"N bytes"))
	}
}

/// Multi-scheme signer enum. Variant order mirrors substrate's
/// `MultiSigner` (`Ed25519`, `Sr25519`, `Ecdsa`); the `IdentifyAccount`
/// impl differs only in the Ecdsa arm (Ethereum-style derivation).
#[derive(Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub enum RostroSigner {
	Ed25519(ed25519::Public),
	Sr25519(sr25519::Public),
	Ecdsa(ecdsa::Public),
	/// NIST P-256 (secp256r1) compressed SEC1 pubkey (`0x02/0x03 ‖ X`).
	/// One signer arm for both P-256 signature envelopes (`EcdsaP256`,
	/// `WebAuthnP256`) — same curve, same device key, same account. Kept
	/// as raw bytes: sp_core has no P-256 type, and the account is a hash
	/// of these bytes regardless.
	EcdsaP256(#[cfg_attr(feature = "std", serde(with = "serde_bytes_array"))] [u8; 33]),
}

impl From<sr25519::Public> for RostroSigner {
	fn from(pk: sr25519::Public) -> Self {
		RostroSigner::Sr25519(pk)
	}
}

impl From<ed25519::Public> for RostroSigner {
	fn from(pk: ed25519::Public) -> Self {
		RostroSigner::Ed25519(pk)
	}
}

impl From<ecdsa::Public> for RostroSigner {
	fn from(pk: ecdsa::Public) -> Self {
		RostroSigner::Ecdsa(pk)
	}
}

impl From<[u8; 33]> for RostroSigner {
	fn from(pk: [u8; 33]) -> Self {
		RostroSigner::EcdsaP256(pk)
	}
}

impl IdentifyAccount for RostroSigner {
	type AccountId = AccountId32;
	fn into_account(self) -> AccountId32 {
		match self {
			RostroSigner::Ed25519(pk) => ed25519_to_account(&pk),
			RostroSigner::Sr25519(pk) => sr25519_to_account(&pk),
			RostroSigner::Ecdsa(pk) => ecdsa_compressed_to_account(&pk),
			RostroSigner::EcdsaP256(pk) => ecdsa_p256_to_account(&pk),
		}
	}
}

/// Standalone derivation for Sr25519 pubkey → AccountId32. Raw 32-byte
/// pubkey — byte-for-byte identical to Polkadot/Substrate, so a DOT
/// holder's account is unchanged on Rostro (modulo SS58 prefix).
pub fn sr25519_to_account(pk: &sr25519::Public) -> AccountId32 {
	let pk_bytes: &[u8; 32] = pk.as_ref();
	(*pk_bytes).into()
}

/// Standalone derivation for Ed25519 pubkey → AccountId32. Raw 32-byte
/// pubkey — source-matches Solana/Aptos/Sui/Cosmos/Ledger.
pub fn ed25519_to_account(pk: &ed25519::Public) -> AccountId32 {
	let bytes: [u8; 32] = pk.0;
	bytes.into()
}

/// Standalone derivation for Ecdsa compressed pubkey → AccountId32.
/// Decompresses to 64-byte uncompressed, keccak256-hashes, takes last
/// 20 bytes, zero-pads to 32 bytes. Source-matches Ethereum.
pub fn ecdsa_compressed_to_account(pk: &ecdsa::Public) -> AccountId32 {
	let h160 = ecdsa_compressed_to_eth_h160(pk).unwrap_or([0u8; 20]);
	let mut bytes = [0u8; 32];
	bytes[12..].copy_from_slice(&h160);
	bytes.into()
}

/// Standalone derivation for a P-256 (secp256r1) compressed SEC1 pubkey →
/// AccountId32: `blake2_256(compressed_33_byte_pubkey)`.
///
/// Unlike Sr25519/Ed25519 (raw-pubkey-as-address), a P-256 pubkey is 33
/// bytes and cannot *be* the 32-byte account. Hashing also gives the
/// P-256 class a pubkey-hash shield the raw-25519 classes lack: the
/// address never reveals the pubkey, only a spend does. Deterministic by
/// construction — the same 33 bytes map to the same account on-chain and
/// in the wallet, which is the invariant the fixture tests pin. No
/// on-curve validation here: an off-curve pubkey simply never verifies
/// (its account is unspendable), and derivation must stay total.
pub fn ecdsa_p256_to_account(pk: &[u8; 33]) -> AccountId32 {
	blake2_256(pk).into()
}

/// Decompress a 33-byte secp256k1 compressed pubkey to 64-byte
/// uncompressed (X ‖ Y), keccak256-hash, take last 20 bytes →
/// Ethereum-style H160. Returns `None` if the pubkey doesn't
/// decompress (point not on curve / invalid encoding).
pub fn ecdsa_compressed_to_eth_h160(pk: &ecdsa::Public) -> Option<[u8; 20]> {
	let pk_bytes: &[u8; 33] = pk.as_ref();
	let verifying = k256::ecdsa::VerifyingKey::from_sec1_bytes(pk_bytes).ok()?;
	let encoded = verifying.to_encoded_point(false);
	let bytes = encoded.as_bytes();
	if bytes.len() != 65 || bytes[0] != 0x04 {
		return None;
	}
	let h = keccak_256(&bytes[1..]);
	let mut out = [0u8; 20];
	out.copy_from_slice(&h[12..]);
	Some(out)
}

/// Multi-scheme signature enum. Variant order mirrors substrate's
/// `MultiSignature` (`Ed25519`, `Sr25519`, `Ecdsa`) so the three native
/// variants are byte-identical on the wire; `EcdsaEip191` is the one
/// Rostro-specific addition.
#[derive(Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub enum RostroSignature {
	Ed25519(ed25519::Signature),
	/// Sr25519 signature — bare 64-byte sig. The pubkey is the signer
	/// AccountId32 (raw-pubkey-as-address), so nothing is carried
	/// alongside; byte-identical to `MultiSignature::Sr25519`.
	Sr25519(sr25519::Signature),
	/// Substrate-style ecdsa: signature is over `blake2_256(payload)`.
	Ecdsa(ecdsa::Signature),
	/// MetaMask `personal_sign` style: signature is over
	/// `keccak256("\x19Ethereum Signed Message:\n<len>" ‖ payload)`.
	/// The `v` byte must be 0 or 1 (not 27 or 28); the wallet/dotwave
	/// is responsible for normalizing the recovery ID before submission.
	EcdsaEip191(ecdsa::Signature),
	/// NIST P-256 (secp256r1) raw ECDSA — the hardware-secure-element
	/// scheme (StrongBox, TPM2, the zkpki/PoP stack all speak P-256). The
	/// signature is over `sha256(payload)` (Android Keystore
	/// `SHA256withECDSA` / the TPM ECDSA convention). The account is
	/// `blake2_256(pubkey)`, so the pubkey is not recoverable from the
	/// address, and P-256 verify is not recovery-based — hence the 33-byte
	/// compressed pubkey rides in the signature; `verify` re-derives the
	/// account from it and rejects any mismatch with the signer.
	///
	/// Canonicalization: `sig` is raw `r ‖ s` and **must be low-s**
	/// (`s ≤ n/2`); high-s is rejected so exactly one signature verifies
	/// per `(payload, pubkey)` (same non-malleability discipline as the
	/// secp256k1 recover path). StrongBox emits DER with an unnormalized
	/// s, so the wallet/dotwave converts DER→`r‖s` and normalizes s to
	/// low-s before submission — the P-256 analogue of the EcdsaEip191
	/// `v`-normalization contract above.
	EcdsaP256 {
		/// Compressed SEC1 pubkey (`0x02/0x03 ‖ X`).
		#[cfg_attr(feature = "std", serde(with = "serde_bytes_array"))]
		pubkey: [u8; 33],
		/// Raw ECDSA signature `r ‖ s`, low-s canonical.
		#[cfg_attr(feature = "std", serde(with = "serde_bytes_array"))]
		sig: [u8; 64],
	},
}

impl Verify for RostroSignature {
	type Signer = RostroSigner;
	fn verify<L: Lazy<[u8]>>(&self, mut msg: L, signer: &AccountId32) -> bool {
		match self {
			RostroSignature::Ed25519(sig) => {
				let m = msg.get();
				let signer_bytes: &[u8; 32] = signer.as_ref();
				match ed25519::Public::try_from(&signer_bytes[..]) {
					Ok(pubkey) => sig.verify(m, &pubkey),
					Err(_) => false,
				}
			},
			RostroSignature::Sr25519(sig) => {
				let m = msg.get();
				let signer_bytes: &[u8; 32] = signer.as_ref();
				match sr25519::Public::try_from(&signer_bytes[..]) {
					Ok(pubkey) => sig.verify(m, &pubkey),
					Err(_) => false,
				}
			},
			RostroSignature::Ecdsa(sig) => {
				let m = msg.get();
				let sig_bytes: &[u8; 65] = sig.as_ref();
				verify_ecdsa_eth(sig_bytes, &blake2_256(m), signer)
			},
			RostroSignature::EcdsaEip191(sig) => {
				let m = msg.get();
				let sig_bytes: &[u8; 65] = sig.as_ref();
				verify_ecdsa_eth(sig_bytes, &eip191_hash(m), signer)
			},
			RostroSignature::EcdsaP256 { pubkey, sig } => {
				let m = msg.get();
				verify_p256(pubkey, sig, m, signer)
			},
		}
	}
}

impl RostroSignature {
	/// Verify this signature over `payload` against an explicitly supplied
	/// authorized key, rather than against the address-derived default.
	///
	/// This is the keyring entry point (docs/KEYRING.md): the caller — the
	/// keyring pallet — has already established that `key` is authorized
	/// for the signing account, so the address-binding step of the derived
	/// path is replaced by an exact match against the enrolled pubkey. The
	/// cryptographic checks are otherwise identical to [`Verify::verify`],
	/// including P-256 low-s canonicalization.
	///
	/// Scheme discipline: the signature variant must match the enrolled
	/// key's scheme. The two secp256k1 envelopes (`Ecdsa`, `EcdsaEip191`)
	/// both match an enrolled `Ecdsa` key — same key, two wrap formats,
	/// exactly the derived-path posture. Every other cross-scheme pairing
	/// is `false`, never an error: sr25519 and ed25519 stay distinct here
	/// even though they share the raw-pubkey *address* namespace, because
	/// an enrolled key names its scheme explicitly.
	pub fn verify_against(&self, payload: &[u8], key: &RostroSigner) -> bool {
		match (self, key) {
			(RostroSignature::Ed25519(sig), RostroSigner::Ed25519(pk)) => sig.verify(payload, pk),
			(RostroSignature::Sr25519(sig), RostroSigner::Sr25519(pk)) => sig.verify(payload, pk),
			(RostroSignature::Ecdsa(sig), RostroSigner::Ecdsa(pk)) =>
				recovered_compressed_matches(sig.as_ref(), &blake2_256(payload), pk),
			(RostroSignature::EcdsaEip191(sig), RostroSigner::Ecdsa(pk)) =>
				recovered_compressed_matches(sig.as_ref(), &eip191_hash(payload), pk),
			(RostroSignature::EcdsaP256 { pubkey, sig }, RostroSigner::EcdsaP256(pk)) => {
				if pubkey != pk || !is_low_s_p256(&sig[32..64]) {
					return false;
				}
				let prehash = sha2_256(payload);
				rostro_guest_crypto::verify::p256_verify_prehash(pubkey, sig, &prehash)
			},
			_ => false,
		}
	}
}

/// Recover the compressed secp256k1 pubkey from `(sig, hash)` and compare
/// it byte-exact against an enrolled key. The recover-and-compare shape
/// mirrors `verify_ecdsa_eth`, but against the enrolled pubkey instead of
/// the H160-derived address.
fn recovered_compressed_matches(sig: &[u8; 65], hash: &[u8; 32], pk: &ecdsa::Public) -> bool {
	match secp256k1_ecdsa_recover_compressed(sig, hash) {
		Ok(recovered) => {
			let pk_bytes: &[u8; 33] = pk.as_ref();
			&recovered == pk_bytes
		},
		Err(_) => false,
	}
}

/// P-256 raw-ECDSA verify for the `EcdsaP256` variant:
///  1. re-derive the account from the carried pubkey and bind it to
///     `signer` — a signature carrying any other pubkey is rejected, so
///     the pubkey riding in the signature can't be swapped;
///  2. enforce low-s canonicalization (`0 < s ≤ n/2`) so exactly one
///     signature verifies per `(payload, pubkey)`;
///  3. verify `r ‖ s` over `sha256(payload)` through the crypto facade —
///     ecalli 112 in the runtime, the p256 crate natively.
fn verify_p256(pubkey: &[u8; 33], sig: &[u8; 64], payload: &[u8], signer: &AccountId32) -> bool {
	if ecdsa_p256_to_account(pubkey) != *signer {
		return false;
	}
	if !is_low_s_p256(&sig[32..64]) {
		return false;
	}
	let prehash = sha2_256(payload);
	rostro_guest_crypto::verify::p256_verify_prehash(pubkey, sig, &prehash)
}

/// P-256 group order `n` halved (floor), big-endian. A signature with
/// `s > n/2` is the malleable high-s twin of a canonical low-s signature;
/// rejecting it makes `(payload, pubkey) → sig` one-to-one. The constant
/// is self-verified against the `p256` crate's curve order in `tests`, so
/// a transcription error fails CI rather than shipping.
const P256_HALF_ORDER: [u8; 32] = [
	0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];

/// True iff `s` (big-endian 32 bytes) is a canonical low-s scalar,
/// `0 < s ≤ n/2`. `s == 0` is not a valid ECDSA scalar; `s > n/2` is the
/// malleable high-s form the wallet must normalize away before submission.
fn is_low_s_p256(s: &[u8]) -> bool {
	if s.len() != 32 || s.iter().all(|&b| b == 0) {
		return false;
	}
	for (a, b) in s.iter().zip(P256_HALF_ORDER.iter()) {
		if a < b {
			return true;
		}
		if a > b {
			return false;
		}
	}
	// s == n/2 exactly: the canonical low-s boundary, accepted.
	true
}

/// Recover an uncompressed pubkey from `(sig, hash)`, derive the
/// Eth H160, and compare to the trailing 20 bytes of `signer` (with
/// the leading 12 bytes asserted to be zero per the Ethereum
/// padding convention).
fn verify_ecdsa_eth(sig: &[u8; 65], hash: &[u8; 32], signer: &AccountId32) -> bool {
	let pubkey_uncompressed = match secp256k1_ecdsa_recover(sig, hash) {
		Ok(p) => p,
		Err(_) => return false,
	};
	let pubkey_hash = keccak_256(&pubkey_uncompressed);
	let signer_bytes: &[u8; 32] = signer.as_ref();
	signer_bytes[..12] == [0u8; 12] && signer_bytes[12..] == pubkey_hash[12..]
}

/// Compute the EIP-191 `personal_sign` hash for an arbitrary payload.
/// Wraps as `"\x19Ethereum Signed Message:\n<len_decimal>" ‖ payload`
/// then keccak256.
pub fn eip191_hash(payload: &[u8]) -> [u8; 32] {
	let mut wrapped = Vec::with_capacity(28 + 10 + payload.len());
	wrapped.extend_from_slice(b"\x19Ethereum Signed Message:\n");
	write_u32_decimal(payload.len() as u32, &mut wrapped);
	wrapped.extend_from_slice(payload);
	keccak_256(&wrapped)
}

fn write_u32_decimal(mut n: u32, out: &mut Vec<u8>) {
	if n == 0 {
		out.push(b'0');
		return;
	}
	let mut buf = [0u8; 10];
	let mut i = 0;
	while n > 0 {
		buf[i] = b'0' + (n % 10) as u8;
		n /= 10;
		i += 1;
	}
	for j in (0..i).rev() {
		out.push(buf[j]);
	}
}

#[cfg(test)]
mod tests;
