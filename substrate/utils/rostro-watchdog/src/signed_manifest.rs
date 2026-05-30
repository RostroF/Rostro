// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! SSH-format ed25519 signature verifier for the SRT-signed
//! `manifest.txt` covering the canonical-cache files.
//!
//! Implements the subset of PROTOCOL.sshsig (the `ssh-keygen -Y sign` /
//! `ssh-keygen -Y verify` format) needed to verify a manifest.txt
//! against a manifest.txt.sig under a known ed25519 pubkey:
//!
//!   Armored signature: `-----BEGIN SSH SIGNATURE-----` envelope
//!   surrounding a base64-encoded SSHSIG blob.
//!
//!   SSHSIG blob (length-prefixed SSH wire format):
//!     6 bytes        magic = "SSHSIG"
//!     u32 BE         sig_version = 1
//!     string         publickey      (e.g. ssh-ed25519 wire format)
//!     string         namespace      (e.g. "rostro-release")
//!     string         reserved       (empty)
//!     string         hash_algorithm (must be "sha512")
//!     string         signature      (e.g. ssh-ed25519 wire format)
//!
//!   The data actually signed is:
//!     6 bytes        magic = "SSHSIG"
//!     string         namespace
//!     string         reserved
//!     string         hash_algorithm
//!     string         sha512(file_contents)
//!
//! Per [[feedback_trust_but_verify_baked_plus_onchain]]: this is the
//! Layer 1 check that closes the self-consistent-pair attack — an
//! attacker without the rostro_release private key cannot forge a
//! {manifest.txt, manifest.txt.sig, expected_pubkey} triple that
//! passes this function.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha512};

/// Errors from `verify_ssh_signature`. Distinguished so callers (and
/// tests) can assert specific failure modes.
#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
	/// Armor envelope (`-----BEGIN SSH SIGNATURE-----` … `-----END …-----`)
	/// is missing or malformed.
	BadArmor,
	/// Base64 inside the armor envelope failed to decode.
	BadBase64,
	/// SSHSIG blob is too short to contain the required fields.
	BadBlobTruncated,
	/// SSHSIG magic prefix is wrong.
	BadMagic,
	/// `sig_version` is not 1.
	BadVersion(u32),
	/// `publickey` field is not an `ssh-ed25519` 32-byte key.
	BadPubkeyFraming,
	/// Decoded pubkey does not match the expected (compile-time-baked) key.
	PubkeyMismatch,
	/// `namespace` is not the expected value (e.g. `rostro-release`).
	NamespaceMismatch,
	/// `hash_algorithm` field is not `sha512`.
	HashAlgoMismatch,
	/// `signature` field is not an `ssh-ed25519` 64-byte signature.
	BadSignatureFraming,
	/// ed25519 verification failed (mathematical signature invalid).
	SignatureInvalid,
}

impl core::fmt::Display for VerifyError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			VerifyError::BadArmor => write!(f, "signature missing or malformed SSH-SIGNATURE armor"),
			VerifyError::BadBase64 => write!(f, "signature base64 decode failed"),
			VerifyError::BadBlobTruncated => write!(f, "SSHSIG blob truncated"),
			VerifyError::BadMagic => write!(f, "SSHSIG magic prefix mismatch"),
			VerifyError::BadVersion(v) => write!(f, "SSHSIG version {v} not supported (expected 1)"),
			VerifyError::BadPubkeyFraming => write!(f, "embedded pubkey is not ssh-ed25519 32 bytes"),
			VerifyError::PubkeyMismatch => write!(f, "embedded pubkey does not match expected"),
			VerifyError::NamespaceMismatch => write!(f, "signature namespace does not match expected"),
			VerifyError::HashAlgoMismatch => write!(f, "signature hash algorithm is not sha512"),
			VerifyError::BadSignatureFraming => write!(f, "signature field is not ssh-ed25519 64 bytes"),
			VerifyError::SignatureInvalid => write!(f, "ed25519 signature did not verify"),
		}
	}
}

impl std::error::Error for VerifyError {}

const SSHSIG_MAGIC: &[u8; 6] = b"SSHSIG";
const SIG_VERSION: u32 = 1;

/// Verify an `ssh-keygen -Y sign` signature.
///
/// `signed_data` is the raw file bytes the signature covers (e.g. the
/// contents of `manifest.txt`).
///
/// `armored_sig` is the entire signature file contents — the
/// `-----BEGIN SSH SIGNATURE-----` envelope plus base64 body.
///
/// `expected_namespace` must match the namespace baked into the
/// signature at sign time (release-sign.sh uses `rostro-release`).
///
/// `expected_pubkey` is the 32-byte raw ed25519 public key we accept.
/// This MUST be the compile-time-baked `ROSTRO_RELEASE_PUBKEY` for the
/// recovery code path; see [[feedback_trust_but_verify_baked_plus_onchain]].
pub fn verify_ssh_signature(
	signed_data: &[u8],
	armored_sig: &[u8],
	expected_namespace: &str,
	expected_pubkey: &[u8; 32],
) -> Result<(), VerifyError> {
	let blob = strip_armor(armored_sig)?;
	let blob = base64_decode(&blob).ok_or(VerifyError::BadBase64)?;

	// Parse the SSHSIG blob fields.
	let mut p = Parser::new(&blob);
	p.expect_bytes(SSHSIG_MAGIC).map_err(|_| VerifyError::BadMagic)?;
	let version = p.read_u32().map_err(|_| VerifyError::BadBlobTruncated)?;
	if version != SIG_VERSION {
		return Err(VerifyError::BadVersion(version));
	}
	let pubkey_field = p.read_string().map_err(|_| VerifyError::BadBlobTruncated)?;
	let namespace = p.read_string().map_err(|_| VerifyError::BadBlobTruncated)?;
	let _reserved = p.read_string().map_err(|_| VerifyError::BadBlobTruncated)?;
	let hash_algo = p.read_string().map_err(|_| VerifyError::BadBlobTruncated)?;
	let sig_field = p.read_string().map_err(|_| VerifyError::BadBlobTruncated)?;

	// Pubkey must be ssh-ed25519 wire format with 32-byte key.
	let pubkey_raw = parse_ssh_ed25519_key(pubkey_field)?;
	if pubkey_raw != *expected_pubkey {
		return Err(VerifyError::PubkeyMismatch);
	}

	if namespace != expected_namespace.as_bytes() {
		return Err(VerifyError::NamespaceMismatch);
	}

	if hash_algo != b"sha512" {
		return Err(VerifyError::HashAlgoMismatch);
	}

	// Signature must be ssh-ed25519 wire format with 64-byte sig.
	let sig_raw = parse_ssh_ed25519_sig(sig_field)?;

	// Build the signed envelope: SSHSIG_MAGIC | string(namespace) |
	// string(reserved) | string(hash_algo) | string(sha512(data))
	let file_hash = {
		let mut h = Sha512::new();
		h.update(signed_data);
		h.finalize()
	};
	let mut envelope = Vec::with_capacity(6 + 4 + namespace.len() + 4 + 0 + 4 + 6 + 4 + 64);
	envelope.extend_from_slice(SSHSIG_MAGIC);
	push_string(&mut envelope, namespace);
	push_string(&mut envelope, b"");
	push_string(&mut envelope, hash_algo);
	push_string(&mut envelope, &file_hash);

	// ed25519 verify.
	let vk = VerifyingKey::from_bytes(&pubkey_raw)
		.map_err(|_| VerifyError::BadPubkeyFraming)?;
	let signature = Signature::from_bytes(&sig_raw);
	vk.verify(&envelope, &signature)
		.map_err(|_| VerifyError::SignatureInvalid)
}

fn strip_armor(content: &[u8]) -> Result<String, VerifyError> {
	let s = std::str::from_utf8(content).map_err(|_| VerifyError::BadArmor)?;
	let begin = "-----BEGIN SSH SIGNATURE-----";
	let end = "-----END SSH SIGNATURE-----";
	let start = s.find(begin).ok_or(VerifyError::BadArmor)? + begin.len();
	let stop = s[start..].find(end).ok_or(VerifyError::BadArmor)? + start;
	let body = &s[start..stop];
	Ok(body.chars().filter(|c| !c.is_whitespace()).collect())
}

fn parse_ssh_ed25519_key(field: &[u8]) -> Result<[u8; 32], VerifyError> {
	let mut p = Parser::new(field);
	let algo = p
		.read_string()
		.map_err(|_| VerifyError::BadPubkeyFraming)?;
	if algo != b"ssh-ed25519" {
		return Err(VerifyError::BadPubkeyFraming);
	}
	let key = p
		.read_string()
		.map_err(|_| VerifyError::BadPubkeyFraming)?;
	if key.len() != 32 {
		return Err(VerifyError::BadPubkeyFraming);
	}
	let mut out = [0u8; 32];
	out.copy_from_slice(key);
	Ok(out)
}

fn parse_ssh_ed25519_sig(field: &[u8]) -> Result<[u8; 64], VerifyError> {
	let mut p = Parser::new(field);
	let algo = p
		.read_string()
		.map_err(|_| VerifyError::BadSignatureFraming)?;
	if algo != b"ssh-ed25519" {
		return Err(VerifyError::BadSignatureFraming);
	}
	let sig = p
		.read_string()
		.map_err(|_| VerifyError::BadSignatureFraming)?;
	if sig.len() != 64 {
		return Err(VerifyError::BadSignatureFraming);
	}
	let mut out = [0u8; 64];
	out.copy_from_slice(sig);
	Ok(out)
}

fn push_string(out: &mut Vec<u8>, s: &[u8]) {
	out.extend_from_slice(&(s.len() as u32).to_be_bytes());
	out.extend_from_slice(s);
}

/// Cursor-style reader for SSH wire format (length-prefixed strings,
/// u32 big-endian, fixed-byte expectations).
struct Parser<'a> {
	buf: &'a [u8],
	off: usize,
}

impl<'a> Parser<'a> {
	fn new(buf: &'a [u8]) -> Self {
		Parser { buf, off: 0 }
	}

	fn expect_bytes(&mut self, expected: &[u8]) -> Result<(), ()> {
		if self.buf.len() < self.off + expected.len() {
			return Err(());
		}
		if &self.buf[self.off..self.off + expected.len()] != expected {
			return Err(());
		}
		self.off += expected.len();
		Ok(())
	}

	fn read_u32(&mut self) -> Result<u32, ()> {
		if self.buf.len() < self.off + 4 {
			return Err(());
		}
		let v = u32::from_be_bytes(self.buf[self.off..self.off + 4].try_into().unwrap());
		self.off += 4;
		Ok(v)
	}

	fn read_string(&mut self) -> Result<&'a [u8], ()> {
		let len = self.read_u32()? as usize;
		if self.buf.len() < self.off + len {
			return Err(());
		}
		let s = &self.buf[self.off..self.off + len];
		self.off += len;
		Ok(s)
	}
}

/// Minimal RFC 4648 base64 decoder. Standard + URL-safe alphabets. We
/// implement locally rather than pull in the `base64` crate because
/// the watchdog's trust surface should have the smallest possible
/// transitive dep tree; the SSH armor body is a few hundred bytes so
/// performance doesn't matter.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
	let s = s.trim_end_matches('=');
	let mut out = Vec::with_capacity(s.len() * 3 / 4);
	let mut accum: u32 = 0;
	let mut bits: u32 = 0;
	for c in s.chars() {
		let v = match c {
			'A'..='Z' => (c as u32) - ('A' as u32),
			'a'..='z' => (c as u32) - ('a' as u32) + 26,
			'0'..='9' => (c as u32) - ('0' as u32) + 52,
			'+' | '-' => 62,
			'/' | '_' => 63,
			_ => return None,
		};
		accum = (accum << 6) | v;
		bits += 6;
		if bits >= 8 {
			bits -= 8;
			out.push((accum >> bits) as u8);
			accum &= (1 << bits) - 1;
		}
	}
	Some(out)
}

#[cfg(test)]
mod tests {
	use super::*;

	const LAB_MANIFEST: &[u8] = include_bytes!(concat!(
		env!("CARGO_MANIFEST_DIR"),
		"/../../../../rostro-testnet-lab/binaries/watchdog-v0.2/manifest.txt"
	));
	const LAB_MANIFEST_SIG: &[u8] = include_bytes!(concat!(
		env!("CARGO_MANIFEST_DIR"),
		"/../../../../rostro-testnet-lab/binaries/watchdog-v0.2/manifest.txt.sig"
	));

	#[test]
	fn verify_real_lab_manifest() {
		// Positive: real lab manifest + sig verifies against the
		// baked ROSTRO_RELEASE_PUBKEY at the lab's "rostro-release"
		// namespace.
		assert_eq!(
			verify_ssh_signature(
				LAB_MANIFEST,
				LAB_MANIFEST_SIG,
				"rostro-release",
				crate::ROSTRO_RELEASE_PUBKEY,
			),
			Ok(()),
		);
	}

	#[test]
	fn flipped_byte_in_manifest_fails() {
		// Negative 1: alter one byte in the signed data → ed25519
		// verification fails.
		let mut tampered = LAB_MANIFEST.to_vec();
		tampered[0] ^= 0x01;
		assert_eq!(
			verify_ssh_signature(
				&tampered,
				LAB_MANIFEST_SIG,
				"rostro-release",
				crate::ROSTRO_RELEASE_PUBKEY,
			),
			Err(VerifyError::SignatureInvalid),
		);
	}

	#[test]
	fn wrong_expected_pubkey_fails() {
		// Negative 2: different pubkey → embedded pubkey doesn't
		// match expected.
		let mut other_pubkey = *crate::ROSTRO_RELEASE_PUBKEY;
		other_pubkey[0] ^= 0xFF;
		assert_eq!(
			verify_ssh_signature(
				LAB_MANIFEST,
				LAB_MANIFEST_SIG,
				"rostro-release",
				&other_pubkey,
			),
			Err(VerifyError::PubkeyMismatch),
		);
	}

	#[test]
	fn wrong_namespace_fails() {
		assert_eq!(
			verify_ssh_signature(
				LAB_MANIFEST,
				LAB_MANIFEST_SIG,
				"different-namespace",
				crate::ROSTRO_RELEASE_PUBKEY,
			),
			Err(VerifyError::NamespaceMismatch),
		);
	}

	#[test]
	fn truncated_signature_fails() {
		// Negative 3: chop off the BEGIN/END envelope → armor parse
		// fails.
		let truncated = b"not a signature at all";
		assert_eq!(
			verify_ssh_signature(
				LAB_MANIFEST,
				truncated,
				"rostro-release",
				crate::ROSTRO_RELEASE_PUBKEY,
			),
			Err(VerifyError::BadArmor),
		);
	}

	#[test]
	fn corrupted_base64_inside_armor_fails() {
		let armored = b"-----BEGIN SSH SIGNATURE-----\n!!!not base64!!!\n-----END SSH SIGNATURE-----\n";
		let r = verify_ssh_signature(
			LAB_MANIFEST,
			armored,
			"rostro-release",
			crate::ROSTRO_RELEASE_PUBKEY,
		);
		assert_eq!(r, Err(VerifyError::BadBase64));
	}

	#[test]
	fn empty_data_with_real_sig_fails() {
		// The empty file does not match what the manifest sig
		// covers. ed25519 verification fails.
		assert_eq!(
			verify_ssh_signature(
				b"",
				LAB_MANIFEST_SIG,
				"rostro-release",
				crate::ROSTRO_RELEASE_PUBKEY,
			),
			Err(VerifyError::SignatureInvalid),
		);
	}

	#[test]
	fn base64_decode_round_trips_round_numbers() {
		// Sanity-check the base64 helper. Use a known
		// pair from RFC 4648 §10.
		assert_eq!(base64_decode("Zg==").unwrap(), b"f");
		assert_eq!(base64_decode("Zm8=").unwrap(), b"fo");
		assert_eq!(base64_decode("Zm9v").unwrap(), b"foo");
		assert_eq!(base64_decode("Zm9vYg==").unwrap(), b"foob");
		assert_eq!(base64_decode("Zm9vYmE=").unwrap(), b"fooba");
		assert_eq!(base64_decode("Zm9vYmFy").unwrap(), b"foobar");
	}
}
