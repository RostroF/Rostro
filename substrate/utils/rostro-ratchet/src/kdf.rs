// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Key-derivation helpers for the Double Ratchet.
//!
//! Two KDFs per the Signal spec:
//! - [`kdf_rk`]: HKDF-SHA256 over the root key + DH output, splitting 64
//!   bytes of OKM into a fresh root key and a fresh chain key.
//! - [`kdf_ck`]: HMAC-SHA256 over the chain key, with two distinct
//!   constants. The 0x01 path yields the message key; the 0x02 path
//!   yields the next chain key. This guarantees the message key cannot
//!   be derived from the next chain key, giving per-message FS.
//!
//! [`kdf_msg`] then expands the per-message key into an AEAD key + nonce
//! pair, so the same `ChainKey` material never serves both as a HMAC key
//! and an AEAD key directly.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha256 = Hmac<Sha256>;

/// Domain separation tag for `KDF_RK` — distinct from any other HKDF
/// usage in the codebase. Bumping `/v1` would force a wire-incompatible
/// rotation.
const RK_INFO: &[u8] = b"RostroRatchet/RK/v1";

/// Domain separation tag for the per-message AEAD key+nonce expansion.
const MSG_INFO: &[u8] = b"RostroRatchet/Msg/v1";

/// HMAC input byte that selects "message key" output from a chain key.
const CK_TAG_MESSAGE: u8 = 0x01;
/// HMAC input byte that selects "next chain key" output from a chain key.
const CK_TAG_CHAIN: u8 = 0x02;

/// Length of the AEAD key derived per message (ChaCha20-Poly1305 = 32).
pub const AEAD_KEY_LEN: usize = 32;
/// Length of the AEAD nonce derived per message (ChaCha20-Poly1305 = 12).
pub const AEAD_NONCE_LEN: usize = 12;

/// 32-byte material wrapper that zeroizes on drop. Shared by root keys,
/// chain keys, and message keys — they're all 32-byte secrets and the
/// zeroize behavior is identical.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Secret32(pub [u8; 32]);

impl Secret32 {
	/// Wrap a 32-byte buffer.
	pub fn new(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}

	/// Borrow the underlying bytes.
	pub fn as_bytes(&self) -> &[u8; 32] {
		&self.0
	}
}

impl core::fmt::Debug for Secret32 {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.write_str("Secret32(<redacted>)")
	}
}

/// Root-key KDF. Mixes the current root key (HKDF salt) with a fresh DH
/// output (HKDF IKM). Returns `(new_root_key, new_chain_key)`.
///
/// Signal calls this `KDF_RK`. The split is deterministic: the first 32
/// bytes of OKM become the root key, the next 32 become the chain key.
pub fn kdf_rk(rk: &Secret32, dh_out: &[u8; 32]) -> (Secret32, Secret32) {
	let hk = Hkdf::<Sha256>::new(Some(rk.as_bytes()), dh_out);
	let mut okm = [0u8; 64];
	hk.expand(RK_INFO, &mut okm).expect("64 < 255 * 32 OKM bytes; qed");

	let mut new_rk = [0u8; 32];
	let mut new_ck = [0u8; 32];
	new_rk.copy_from_slice(&okm[..32]);
	new_ck.copy_from_slice(&okm[32..]);
	okm.zeroize();
	(Secret32::new(new_rk), Secret32::new(new_ck))
}

/// Chain-key KDF. Two HMAC-SHA256 evaluations under the chain key with
/// distinct one-byte inputs. Returns `(message_key, next_chain_key)`.
///
/// Signal calls this `KDF_CK`. The HMAC construction guarantees the
/// message key cannot be inverted to recover the chain key (or vice
/// versa), giving the per-message FS property.
pub fn kdf_ck(ck: &Secret32) -> (Secret32, Secret32) {
	let mut mac_msg = HmacSha256::new_from_slice(ck.as_bytes())
		.expect("HMAC accepts any key length; qed");
	mac_msg.update(&[CK_TAG_MESSAGE]);
	let msg_bytes: [u8; 32] = mac_msg.finalize().into_bytes().into();

	let mut mac_chain = HmacSha256::new_from_slice(ck.as_bytes())
		.expect("HMAC accepts any key length; qed");
	mac_chain.update(&[CK_TAG_CHAIN]);
	let chain_bytes: [u8; 32] = mac_chain.finalize().into_bytes().into();

	(Secret32::new(msg_bytes), Secret32::new(chain_bytes))
}

/// Per-message KDF: expand a message key into a (key, nonce) pair for
/// the AEAD. Domain-separated from `kdf_rk` and `kdf_ck` via `MSG_INFO`.
pub fn kdf_msg(mk: &Secret32) -> ([u8; AEAD_KEY_LEN], [u8; AEAD_NONCE_LEN]) {
	// Salt = zeros: the message key itself is the secret material; we
	// don't want a second secret salt complicating storage.
	let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), mk.as_bytes());
	let mut okm = [0u8; AEAD_KEY_LEN + AEAD_NONCE_LEN];
	hk.expand(MSG_INFO, &mut okm)
		.expect("44 < 255 * 32 OKM bytes; qed");

	let mut key = [0u8; AEAD_KEY_LEN];
	let mut nonce = [0u8; AEAD_NONCE_LEN];
	key.copy_from_slice(&okm[..AEAD_KEY_LEN]);
	nonce.copy_from_slice(&okm[AEAD_KEY_LEN..]);
	okm.zeroize();
	(key, nonce)
}
