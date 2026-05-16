// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Wire-level types for the Double Ratchet.
//!
//! The [`Header`] precedes every ciphertext on the wire. It's
//! authenticated (folded into AEAD associated data) but not encrypted —
//! header encryption (Signal's optional second layer) is out of scope at
//! v0.

use zeroize::Zeroize;

/// Ceiling on out-of-order receipt within a single chain. If a peer
/// sends `n=k` and we've only delivered up through `n=k-MAX_SKIP-1`, the
/// session refuses the message rather than burning unbounded CPU/memory
/// on chain advancement.
///
/// Signal's reference recommends 1000. We use 256 — gossip latency
/// budgets are tighter than chat, and 256 already covers any plausible
/// reorder window on a Sassafras chain. Caller can revise this constant
/// if telemetry shows real drops.
pub const MAX_SKIP: u32 = 256;

/// Ceiling on the total skipped-key cache across *all* receiving chains
/// for a session. Bounds memory regardless of how many DH ratchets the
/// peer cycles through. If both peers honestly drive `MAX_SKIP` per
/// chain, the cache holds at most this many entries before the session
/// drops to protect itself.
pub const MAX_SKIPPED_CACHE: usize = 1024;

/// Plaintext header that accompanies every ratchet message.
///
/// - `dh_pubkey`: sender's current ratchet DH public key. A change here
///   is the receiver's signal to perform a DH ratchet step.
/// - `pn`: previous sending chain length — how many messages the sender
///   sent on the *prior* sending chain before rotating. Lets the
///   receiver bound how far to skip on the old chain.
/// - `n`: current message number within the sending chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
	/// Sender's current ratchet DH public key.
	pub dh_pubkey: [u8; 32],
	/// Length of the sender's previous sending chain.
	pub pn: u32,
	/// Message number within the sender's current sending chain.
	pub n: u32,
}

impl Header {
	/// Fixed serialized length: 32 + 4 + 4 = 40 bytes.
	pub const SERIALIZED_LEN: usize = 32 + 4 + 4;

	/// Serialize to the canonical wire form (big-endian counters).
	///
	/// Used both for transmission and for folding into AEAD associated
	/// data, so any change here is wire-incompatible.
	pub fn to_bytes(&self) -> [u8; Self::SERIALIZED_LEN] {
		let mut out = [0u8; Self::SERIALIZED_LEN];
		out[..32].copy_from_slice(&self.dh_pubkey);
		out[32..36].copy_from_slice(&self.pn.to_be_bytes());
		out[36..40].copy_from_slice(&self.n.to_be_bytes());
		out
	}

	/// Parse a 40-byte buffer back into a header. Returns `None` on any
	/// length mismatch — caller decides how to surface the error.
	pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
		if bytes.len() != Self::SERIALIZED_LEN {
			return None;
		}
		let mut dh_pubkey = [0u8; 32];
		dh_pubkey.copy_from_slice(&bytes[..32]);
		let pn = u32::from_be_bytes(bytes[32..36].try_into().ok()?);
		let n = u32::from_be_bytes(bytes[36..40].try_into().ok()?);
		Some(Self { dh_pubkey, pn, n })
	}
}

/// Build the AEAD associated-data buffer: caller-supplied AD ‖ header.
///
/// Authenticating the header along with the payload ensures an attacker
/// can't swap headers between messages — doing so would change the AD
/// and the AEAD tag would fail. Internal helper, exported through the
/// session module.
pub(crate) fn aead_associated_data(caller_ad: &[u8], header: &Header) -> Vec<u8> {
	let mut buf = Vec::with_capacity(caller_ad.len() + Header::SERIALIZED_LEN);
	buf.extend_from_slice(caller_ad);
	buf.extend_from_slice(&header.to_bytes());
	buf
}

/// Bundle returned by an outbound encrypt: the wire header and the
/// ciphertext (which already includes the AEAD tag).
#[derive(Clone, Debug)]
pub struct OutboundMessage {
	/// Plaintext header to ship alongside the ciphertext.
	pub header: Header,
	/// AEAD ciphertext + 16-byte Poly1305 tag suffix.
	pub ciphertext: Vec<u8>,
}

impl Drop for OutboundMessage {
	fn drop(&mut self) {
		self.ciphertext.zeroize();
	}
}
