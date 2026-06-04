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
	crypto::secp256k1_ecdsa_recover,
	hashing::{blake2_256, keccak_256},
};
use sp_runtime::traits::{IdentifyAccount, Lazy, Verify};

/// Multi-scheme signer enum. Variant order mirrors substrate's
/// `MultiSigner` (`Ed25519`, `Sr25519`, `Ecdsa`); the `IdentifyAccount`
/// impl differs only in the Ecdsa arm (Ethereum-style derivation).
#[derive(Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub enum RostroSigner {
	Ed25519(ed25519::Public),
	Sr25519(sr25519::Public),
	Ecdsa(ecdsa::Public),
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

impl IdentifyAccount for RostroSigner {
	type AccountId = AccountId32;
	fn into_account(self) -> AccountId32 {
		match self {
			RostroSigner::Ed25519(pk) => ed25519_to_account(&pk),
			RostroSigner::Sr25519(pk) => sr25519_to_account(&pk),
			RostroSigner::Ecdsa(pk) => ecdsa_compressed_to_account(&pk),
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
		}
	}
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
