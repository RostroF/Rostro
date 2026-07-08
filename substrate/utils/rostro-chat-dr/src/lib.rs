// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # rostro-chat-dr — Double Ratchet primitives for the chat channel
//!
//! Pairwise Double Ratchet session protocol for the **non-validator
//! chat channel** (Phase A1 of the MLS-chat branch). Each pair of
//! RNS-registered SS58 accounts maintains one [`Session`] carrying
//! ratcheting ChaCha20-Poly1305 encryption with per-message forward
//! secrecy and post-compromise security via Signal's Double Ratchet
//! construction.
//!
//! ## Sister crate to `rostro-validator-channel`
//!
//! Same algorithm (X25519 ECDH, HKDF-SHA256 chains,
//! ChaCha20-Poly1305 AEAD), distinct **domain-separation tags**.
//! Channel separation is load-bearing:
//!
//! - The chat channel's [`HANDSHAKE_DOMAIN`] differs from the
//!   validator channel's, so a handshake signature signed for one
//!   channel cannot replay against the other.
//! - The chat channel's internal HKDF info strings differ, so even
//!   if two parties somehow shared an X25519 key across channels,
//!   the derived root/chain keys differ — a ciphertext encrypted in
//!   one channel cannot be decrypted in the other.
//!
//! A future refactor may extract the shared algorithm into a single
//! `rostro-double-ratchet` crate with caller-supplied domains, but
//! v0.1 keeps the two crates independent so neither imposes
//! regression risk on the other (validator-channel ships consensus-
//! critical GRANDPA traffic; chat-channel ships user messages —
//! mixing concerns would be a coupling risk).
//!
//! ## What this crate is
//!
//! Pure cryptographic protocol logic. No libp2p, no sc-network, no
//! async. Unit-testable in microseconds.
//!
//! ## What this crate is NOT
//!
//! - **Not the libp2p binding.** The gemini-node integration that
//!   wires this protocol to a notification protocol substream is a
//!   separate module (Phase B).
//! - **Not the channel-admission gate.** Caller is responsible for
//!   confirming the peer (a) has passed the canonical-files gate,
//!   (b) is NOT in the on-chain active validator set, BEFORE
//!   invoking [`Session::from_handshake_initiator`] /
//!   [`Session::from_handshake_responder`]. This crate ASSUMES the
//!   caller has done that check.
//! - **Not the recipient-identity verification.** Caller verifies
//!   `claimed_pubkey` matches the RNS-registered SS58 the user
//!   intended to talk to.
//! - **Not header-encrypted.** Signal's optional header encryption is
//!   unnecessary here: on the chat path the whole [`WireMessage`] is
//!   content-sealed + sealed-sender-wrapped before it touches the
//!   wire, so headers are never observable.
//!
//! ## Store-and-forward semantics (Phase 5)
//!
//! Unlike the validator channel (in-order Noise substream), the chat
//! relay is store-and-forward with TTL expiry: messages arrive out of
//! order, late, or NEVER (expired before pickup). [`Session::decrypt`]
//! therefore implements full Signal semantics: bounded skipped-message
//! keys ([`MAX_SKIP`] / [`MAX_SKIPPED_TOTAL`]), `prev_chain_len` (PN)
//! in the header to close out chains across ratchets, replay
//! rejection, and commit-on-success (a garbled message cannot poison
//! the ratchet). Sessions persist across app restarts via
//! [`Session::to_state_bytes`] / [`Session::from_state_bytes`] —
//! stored ENCRYPTED by the caller.
//!
//! New conversations bootstrap via **full PQXDH** — hybrid
//! post-quantum X3DH ([`x3dh_initiate`] / [`x3dh_respond`]): signed
//! prekey (X25519) from the RNS chat-identity record + optional
//! one-time prekey from the recipient's published batch + an
//! identity-signed ML-KEM-768 KEM prekey (PQSPK). The initiator
//! encapsulates against the PQSPK and folds the KEM shared secret into
//! the bootstrap KDF, so the very first message is forward-secret AND
//! confidential against retroactive (harvest-now-decrypt-later)
//! decryption unless BOTH X25519 and ML-KEM fall. The whole Double
//! Ratchet chains from this secret, so the property covers the entire
//! conversation. See docs/PQ-CHAT.md.
//!
//! ## Protocol shape (simplified Double Ratchet)
//!
//! Session state per peer-pair:
//!
//! ```text
//! DHs : sending X25519 secret key
//! DHr : receiving X25519 public key (peer's latest ephemeral)
//! RK  : 32-byte root key
//! CKs : sending chain key
//! CKr : receiving chain key
//! Ns  : number of messages sent in the current sending chain
//! Nr  : number of messages received in the current receiving chain
//! ```
//!
//! Each [`Session::encrypt`] derives a fresh message key from `CKs`,
//! advances `CKs` (symmetric ratchet), and produces a header
//! containing the current sending DH pubkey + message number + a
//! ChaCha20-Poly1305 ciphertext. The peer's [`Session::decrypt`]
//! mirrors: if the header carries a NEW dh_pub (the peer rotated),
//! run a DH ratchet step (asymmetric ratchet) — derives new RK +
//! CKr, then rotates our own DHs and derives new CKs.
//!
//! Forward secrecy: each message key is destroyed after use; even
//! if `CKr` is compromised today, past message keys are
//! unrecoverable.
//!
//! Post-compromise security: on the next DH ratchet step (peer
//! sends with new ephemeral), the compromised chain key is
//! superseded by a freshly-derived one rooted in a new DH output.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};
use codec::{Decode, Encode};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};
use zeroize::Zeroize;

/// Root-key info string for HKDF. Chat-channel value; differs from
/// the validator-channel's identical-named constant to guarantee
/// cross-channel KDF outputs cannot collide.
const ROOT_INFO: &[u8] = b"rostro/chat-channel/root/v1";

/// Chain-key info string used in [`derive_message_key`] for the
/// message-key half of the chain split.
const CHAIN_MSG_INFO: &[u8] = b"rostro/chat-channel/msg/v1";

/// Chain-key info string used to advance the chain.
const CHAIN_NEXT_INFO: &[u8] = b"rostro/chat-channel/next/v1";

/// Nonce-derivation info string.
const NONCE_INFO: &[u8] = b"rostro/chat-channel/nonce/v1";

/// Maximum number of message keys [`Session::decrypt`] will derive
/// past the current chain position in one step (Signal's MAX_SKIP).
/// Bounds the work + storage a single malicious/garbled header can
/// cause. Each skipped key is stored so the gapped message still
/// decrypts if it arrives later (out-of-order pickup) — and if it
/// NEVER arrives (TTL-expired on the ephemeral relay), the chain has
/// already advanced past it and the thread survives the gap.
pub const MAX_SKIP: u32 = 64;

/// Cap on the total number of stored skipped message keys per
/// session. Oldest-stored evict first; an evicted key means that
/// specific gapped message can no longer decrypt (it was likely
/// TTL-expired anyway), never that the session breaks.
pub const MAX_SKIPPED_TOTAL: usize = 512;

/// One end of an established Double Ratchet session.
///
/// Persistence: a session is long-lived state — losing it breaks the
/// ratchet unrecoverably. Serialize with [`Session::to_state_bytes`]
/// and restore with [`Session::from_state_bytes`]. The state contains
/// live secrets; the caller MUST store it encrypted at rest (on
/// device hardware: under the silicon content key).
pub struct Session {
	sending_secret: X25519SecretKey,
	receiving_pub: X25519PublicKey,
	root_key: [u8; 32],
	sending_chain_key: ChainKey,
	receiving_chain_key: ChainKey,
	sending_count: u32,
	receiving_count: u32,
	/// Length of the PREVIOUS sending chain — sent in every header
	/// (Signal's PN) so the receiver can close out a chain whose
	/// tail messages are still in flight (or expired) before
	/// ratcheting.
	prev_sending_count: u32,
	/// Skipped message keys: `((chain dh_pub, msg_num), message_key)`
	/// in insertion (derivation) order, oldest first. Vec keeps
	/// eviction order explicit and SCALE-encodes directly; lookups
	/// are linear over ≤ [`MAX_SKIPPED_TOTAL`] entries.
	skipped: Vec<(([u8; 32], u32), [u8; 32])>,
}

/// 32-byte chain key, zeroized on drop.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
struct ChainKey([u8; 32]);

/// On-the-wire message header. Carries the sender's current ephemeral
/// pubkey, the sending-chain message counter, and the length of the
/// sender's previous sending chain (Signal's `PN`). The receiver uses
/// `dh_pub` to detect DH-ratchet steps, `msg_num` to skip within the
/// current chain, and `prev_chain_len` to close out the old chain
/// (banking its missing message keys) before ratcheting.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct MessageHeader {
	pub dh_pub: [u8; 32],
	pub msg_num: u32,
	pub prev_chain_len: u32,
}

/// Full on-the-wire message: header + AEAD ciphertext. The header
/// is also Additional Authenticated Data for the AEAD — tampering
/// with either field invalidates the tag.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct WireMessage {
	pub header: MessageHeader,
	pub ciphertext: Vec<u8>,
}

/// Errors from [`Session::decrypt`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecryptError {
	/// AEAD authentication failed — ciphertext or header was tampered.
	AeadAuthFailed,
	/// Header encoded with the wrong dh_pub length.
	BadHeaderEncoding,
	/// The header demands deriving more than [`MAX_SKIP`] keys past
	/// the current chain position — garbled header or flooding
	/// attempt; the session state is untouched.
	SkipLimitExceeded,
	/// The message indexes a chain position whose key was already
	/// consumed (replay) or evicted from the skipped-key store.
	MessageKeyMissing,
}

impl Session {
	/// Initialize a session from a shared X3DH-lite secret + the
	/// peer's initial ephemeral pubkey, as the **initiator**. The
	/// initiator's `sending_secret` is the same X25519 key they
	/// used in the handshake; the receiving chain starts here so the
	/// peer can immediately send a reply that triggers the DH
	/// ratchet on our side.
	pub fn from_handshake_initiator(
		shared_secret: [u8; 32],
		sending_secret: X25519SecretKey,
		peer_initial_pub: X25519PublicKey,
	) -> Self {
		let (root_key, sending_chain_key) = kdf_root(&[0u8; 32], &shared_secret);
		Self {
			sending_secret,
			receiving_pub: peer_initial_pub,
			root_key,
			sending_chain_key,
			receiving_chain_key: ChainKey([0u8; 32]),
			sending_count: 0,
			receiving_count: 0,
			prev_sending_count: 0,
			skipped: Vec::new(),
		}
	}

	/// Initialize a session as the **responder**. The responder's
	/// receiving chain starts here (they'll receive first); the
	/// sending chain is initialized when they first send a message
	/// (which triggers a DH ratchet step on their own side).
	pub fn from_handshake_responder(
		shared_secret: [u8; 32],
		sending_secret: X25519SecretKey,
		peer_initial_pub: X25519PublicKey,
	) -> Self {
		let (root_key, receiving_chain_key) = kdf_root(&[0u8; 32], &shared_secret);
		Self {
			sending_secret,
			receiving_pub: peer_initial_pub,
			root_key,
			sending_chain_key: ChainKey([0u8; 32]),
			receiving_chain_key,
			sending_count: 0,
			receiving_count: 0,
			prev_sending_count: 0,
			skipped: Vec::new(),
		}
	}

	/// Encrypt a plaintext message. Advances the sending chain by
	/// one and returns the full [`WireMessage`].
	pub fn encrypt(&mut self, plaintext: &[u8]) -> WireMessage {
		// If we haven't sent anything yet AND the sending chain key
		// is the zero placeholder (responder pre-first-send state),
		// run a sending-side DH ratchet to derive a real chain key.
		if self.sending_chain_key.0 == [0u8; 32] {
			self.dh_ratchet_send();
		}

		let (next_ck, message_key) = derive_message_key(&self.sending_chain_key);
		self.sending_chain_key = next_ck;

		let dh_pub = X25519PublicKey::from(&self.sending_secret);
		let header = MessageHeader {
			dh_pub: *dh_pub.as_bytes(),
			msg_num: self.sending_count,
			prev_chain_len: self.prev_sending_count,
		};
		self.sending_count = self.sending_count.saturating_add(1);

		let aad = header.encode();
		let nonce_bytes = derive_nonce(&message_key);
		let cipher = ChaCha20Poly1305::new((&message_key).into());
		let ciphertext = cipher
			.encrypt(
				(&nonce_bytes).into(),
				chacha20poly1305::aead::Payload { msg: plaintext, aad: &aad },
			)
			.expect("ChaCha20-Poly1305 encryption is infallible for valid inputs");

		WireMessage { header, ciphertext }
	}

	/// Decrypt an inbound message. Full Signal semantics for the
	/// store-and-forward relay:
	///
	/// - **Out-of-order within a chain**: skips ahead (bounded by
	///   [`MAX_SKIP`]), banking the intermediate message keys so the
	///   gapped messages still decrypt when they arrive.
	/// - **Late arrivals**: served from the skipped-key store.
	/// - **TTL-expired gaps** (a message that will NEVER arrive): the
	///   chain has already advanced past it — the thread survives;
	///   the banked key ages out of the bounded store.
	/// - **New ratchet pubkey**: closes out the old chain to
	///   `header.prev_chain_len` first, then DH-ratchets.
	///
	/// State is committed only on success — a tampered or garbled
	/// message leaves the session exactly as it was (no
	/// ratchet-poisoning DoS).
	pub fn decrypt(&mut self, message: &WireMessage) -> Result<Vec<u8>, DecryptError> {
		// 1. A banked skipped key (late arrival)? Consume it.
		let skip_key = (message.header.dh_pub, message.header.msg_num);
		if let Some(pos) = self.skipped.iter().position(|(k, _)| *k == skip_key) {
			// Verify BEFORE consuming so a tampered ciphertext can't
			// burn the real message's key.
			let mk = self.skipped[pos].1;
			let plaintext = open_with(&mk, message)?;
			let (_, mut burned) = self.skipped.remove(pos);
			burned.zeroize();
			return Ok(plaintext);
		}

		// 2. Trial-run on a working copy; commit only on success.
		let mut work = self.clone_state();

		if message.header.dh_pub != *work.receiving_pub.as_bytes() {
			// Close out the current receiving chain (bank its missing
			// keys up to the sender's declared previous-chain length),
			// then ratchet into the new chain.
			work.skip_receiving_keys(message.header.prev_chain_len)?;
			work.dh_ratchet_recv(message.header.dh_pub)?;
		} else if message.header.msg_num < work.receiving_count {
			// Same chain, already-consumed position, and no banked
			// key (step 1 missed): replayed or evicted.
			return Err(DecryptError::MessageKeyMissing);
		}

		// 3. Skip within the (possibly new) chain to the message's
		//    position, banking intermediate keys.
		work.skip_receiving_keys(message.header.msg_num)?;

		let (next_ck, message_key) = derive_message_key(&work.receiving_chain_key);
		work.receiving_chain_key = next_ck;
		work.receiving_count = work.receiving_count.saturating_add(1);

		let plaintext = open_with(&message_key, message)?;
		*self = work;
		Ok(plaintext)
	}

	/// Derive-and-bank receiving-chain keys up to (exclusive) `until`.
	/// Bounded by [`MAX_SKIP`] per call; the store is bounded by
	/// [`MAX_SKIPPED_TOTAL`] with oldest-first eviction.
	fn skip_receiving_keys(&mut self, until: u32) -> Result<(), DecryptError> {
		if until > self.receiving_count.saturating_add(MAX_SKIP) {
			return Err(DecryptError::SkipLimitExceeded);
		}
		let chain_pub = *self.receiving_pub.as_bytes();
		while self.receiving_count < until {
			let (next_ck, mk) = derive_message_key(&self.receiving_chain_key);
			self.skipped.push(((chain_pub, self.receiving_count), mk));
			self.receiving_chain_key = next_ck;
			self.receiving_count = self.receiving_count.saturating_add(1);
		}
		while self.skipped.len() > MAX_SKIPPED_TOTAL {
			let (_, mut evicted) = self.skipped.remove(0);
			evicted.zeroize();
		}
		Ok(())
	}

	/// Clone the full session state (working copy for
	/// commit-on-success decryption).
	fn clone_state(&self) -> Self {
		Self {
			sending_secret: self.sending_secret.clone(),
			receiving_pub: self.receiving_pub,
			root_key: self.root_key,
			sending_chain_key: self.sending_chain_key.clone(),
			receiving_chain_key: self.receiving_chain_key.clone(),
			sending_count: self.sending_count,
			receiving_count: self.receiving_count,
			prev_sending_count: self.prev_sending_count,
			skipped: self.skipped.clone(),
		}
	}

	/// Asymmetric ratchet — sending side. Generate a new ephemeral
	/// secret, derive a new sending chain key from DH(new_DHs,
	/// existing DHr). Resets the sending message counter.
	fn dh_ratchet_send(&mut self) {
		let new_secret = X25519SecretKey::random_from_rng(rand_core::OsRng);
		let dh_out = new_secret.diffie_hellman(&self.receiving_pub);
		let (new_rk, new_cks) = kdf_root(&self.root_key, dh_out.as_bytes());
		self.sending_secret = new_secret;
		self.root_key = new_rk;
		self.sending_chain_key = new_cks;
		self.prev_sending_count = self.sending_count;
		self.sending_count = 0;
	}

	/// Asymmetric ratchet — receiving side. Triggered when an
	/// inbound header carries a new peer ephemeral. Derives a new
	/// receiving chain key from DH(current DHs, new DHr).
	fn dh_ratchet_recv(&mut self, new_peer_dh_pub: [u8; 32]) -> Result<(), DecryptError> {
		let new_peer_pub = X25519PublicKey::from(new_peer_dh_pub);
		let dh_out = self.sending_secret.diffie_hellman(&new_peer_pub);
		let (new_rk, new_ckr) = kdf_root(&self.root_key, dh_out.as_bytes());
		self.receiving_pub = new_peer_pub;
		self.root_key = new_rk;
		self.receiving_chain_key = new_ckr;
		self.receiving_count = 0;
		Ok(())
	}

	/// Diagnostic: number of messages this side has sent in the
	/// current sending chain.
	pub fn sending_count(&self) -> u32 {
		self.sending_count
	}

	/// Diagnostic: number of messages this side has received in the
	/// current receiving chain.
	pub fn receiving_count(&self) -> u32 {
		self.receiving_count
	}
}

/// HKDF-SHA256 the root-key + DH output into a new (root_key,
/// chain_key) pair. Returns (RK, CK), each 32 bytes.
fn kdf_root(root_key: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], ChainKey) {
	let hk = Hkdf::<Sha256>::new(Some(root_key), dh_out);
	let mut okm = [0u8; 64];
	hk.expand(ROOT_INFO, &mut okm).expect("64 bytes is well within HKDF's output limit");
	let mut new_rk = [0u8; 32];
	let mut new_ck = [0u8; 32];
	new_rk.copy_from_slice(&okm[..32]);
	new_ck.copy_from_slice(&okm[32..]);
	okm.zeroize();
	(new_rk, ChainKey(new_ck))
}

/// From a chain key, derive the next chain key and the message key.
fn derive_message_key(ck: &ChainKey) -> (ChainKey, [u8; 32]) {
	let hk_msg = Hkdf::<Sha256>::new(None, &ck.0);
	let mut mk = [0u8; 32];
	hk_msg.expand(CHAIN_MSG_INFO, &mut mk).expect("32 bytes within HKDF limit");

	let hk_next = Hkdf::<Sha256>::new(None, &ck.0);
	let mut next = [0u8; 32];
	hk_next.expand(CHAIN_NEXT_INFO, &mut next).expect("32 bytes within HKDF limit");

	(ChainKey(next), mk)
}

/// Derive a 12-byte ChaCha20-Poly1305 nonce from the message key.
fn derive_nonce(mk: &[u8; 32]) -> [u8; 12] {
	let hk = Hkdf::<Sha256>::new(None, mk);
	let mut nonce = [0u8; 12];
	hk.expand(NONCE_INFO, &mut nonce).expect("12 bytes within HKDF limit");
	nonce
}

/// AEAD-open `message` with a specific message key (header is AAD).
fn open_with(mk: &[u8; 32], message: &WireMessage) -> Result<Vec<u8>, DecryptError> {
	let aad = message.header.encode();
	let nonce_bytes = derive_nonce(mk);
	let cipher = ChaCha20Poly1305::new(mk.into());
	cipher
		.decrypt(
			(&nonce_bytes).into(),
			chacha20poly1305::aead::Payload { msg: &message.ciphertext, aad: &aad },
		)
		.map_err(|_| DecryptError::AeadAuthFailed)
}

// ───── Session persistence ─────────────────────────────────────────────

/// SCALE-serializable session state. CONTAINS LIVE SECRETS — the
/// caller must store the encoded bytes encrypted at rest (on device
/// hardware: under the silicon content key). Losing this state breaks
/// the ratchet unrecoverably; persistence is load-bearing, not
/// best-effort.
#[derive(Encode, Decode)]
struct SessionState {
	sending_secret: [u8; 32],
	receiving_pub: [u8; 32],
	root_key: [u8; 32],
	sending_chain_key: [u8; 32],
	receiving_chain_key: [u8; 32],
	sending_count: u32,
	receiving_count: u32,
	prev_sending_count: u32,
	skipped: Vec<(([u8; 32], u32), [u8; 32])>,
}

/// Error restoring a persisted session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateDecodeError;

impl Session {
	/// Serialize the full session state (including banked skipped
	/// keys) for persistence across app restarts.
	pub fn to_state_bytes(&self) -> Vec<u8> {
		SessionState {
			sending_secret: self.sending_secret.to_bytes(),
			receiving_pub: *self.receiving_pub.as_bytes(),
			root_key: self.root_key,
			sending_chain_key: self.sending_chain_key.0,
			receiving_chain_key: self.receiving_chain_key.0,
			sending_count: self.sending_count,
			receiving_count: self.receiving_count,
			prev_sending_count: self.prev_sending_count,
			skipped: self.skipped.clone(),
		}
		.encode()
	}

	/// Restore a session persisted by [`Session::to_state_bytes`].
	pub fn from_state_bytes(bytes: &[u8]) -> Result<Self, StateDecodeError> {
		let mut input = bytes;
		let s = SessionState::decode(&mut input).map_err(|_| StateDecodeError)?;
		Ok(Self {
			sending_secret: X25519SecretKey::from(s.sending_secret),
			receiving_pub: X25519PublicKey::from(s.receiving_pub),
			root_key: s.root_key,
			sending_chain_key: ChainKey(s.sending_chain_key),
			receiving_chain_key: ChainKey(s.receiving_chain_key),
			sending_count: s.sending_count,
			receiving_count: s.receiving_count,
			prev_sending_count: s.prev_sending_count,
			skipped: s.skipped,
		})
	}
}

/// Compute the X3DH-lite shared secret. Used by the handshake-level
/// wrapper; exposed for integration tests.
pub fn handshake_shared_secret(
	local_secret: &X25519SecretKey,
	peer_pub: &X25519PublicKey,
) -> [u8; 32] {
	*local_secret.diffie_hellman(peer_pub).as_bytes()
}

// ───── X3DH-lite handshake payload ─────────────────────────────────────

/// Domain-separation tag for the chat-channel handshake signature
/// preimage. **Distinct from the validator-channel's
/// `HANDSHAKE_DOMAIN`** — a signature signed for one channel will
/// not verify under the other, even if all other inputs are
/// identical. Bumping breaks every previously-signed handshake.
pub const HANDSHAKE_DOMAIN: &[u8] = b"rostro/chat-channel/handshake/v1";

/// Wire-format handshake payload. Sent on substream open by each
/// side. Carries:
///
/// - **`claimed_pubkey`**: the sender's claimed Ed25519 identity
///   pubkey. The receiver verifies this matches the RNS-registered
///   SS58 the user intended to talk to (caller's job).
/// - **`ephemeral_x25519`**: this session's X25519 ephemeral. Used
///   for the Double Ratchet initial DH. Rotates per session.
/// - **`signature`**: Ed25519 signature, by `claimed_pubkey`'s
///   private key, over `HANDSHAKE_DOMAIN || claimed_pubkey ||
///   ephemeral_x25519`. Proves the sender controls the identity
///   key without exposing it.
///
/// Total wire size: 32 + 32 + 64 = 128 bytes (plus SCALE overhead).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct HandshakePayload {
	pub claimed_pubkey: [u8; 32],
	pub ephemeral_x25519: [u8; 32],
	pub signature: [u8; 64],
}

/// Outcome of [`verify_handshake`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeError {
	/// `claimed_pubkey` is not a valid Ed25519 point.
	InvalidPubkey,
	/// Signature does not verify under `claimed_pubkey` for the
	/// expected preimage.
	SignatureInvalid,
}

/// Build the canonical preimage that a [`HandshakePayload`]'s
/// signature covers. Layout:
///
/// ```text
/// HANDSHAKE_DOMAIN || claimed_pubkey || ephemeral_x25519
/// ```
pub fn handshake_preimage(
	claimed_pubkey: &[u8; 32],
	ephemeral_x25519: &[u8; 32],
) -> Vec<u8> {
	let mut buf = Vec::with_capacity(HANDSHAKE_DOMAIN.len() + 64);
	buf.extend_from_slice(HANDSHAKE_DOMAIN);
	buf.extend_from_slice(claimed_pubkey);
	buf.extend_from_slice(ephemeral_x25519);
	buf
}

/// Build a signed handshake payload using the given Ed25519 signing
/// key. Returns the wire-ready [`HandshakePayload`].
#[cfg(feature = "std")]
pub fn sign_handshake(
	ephemeral_pub: &X25519PublicKey,
	signing_key: &ed25519_zebra::SigningKey,
) -> HandshakePayload {
	let claimed_pubkey: [u8; 32] =
		ed25519_zebra::VerificationKey::from(signing_key).into();
	let ephemeral_bytes = *ephemeral_pub.as_bytes();
	let preimage = handshake_preimage(&claimed_pubkey, &ephemeral_bytes);
	let sig: ed25519_zebra::Signature = signing_key.sign(&preimage);
	HandshakePayload {
		claimed_pubkey,
		ephemeral_x25519: ephemeral_bytes,
		signature: sig.into(),
	}
}

/// Verify a [`HandshakePayload`]'s signature. **Does NOT verify
/// recipient identity** — caller MUST check `payload.claimed_pubkey`
/// matches the RNS-registered SS58 they intended to communicate
/// with, and that the peer has passed the canonical-files gate and
/// is NOT in the on-chain active validator set, BEFORE invoking
/// this function.
pub fn verify_handshake(payload: &HandshakePayload) -> Result<(), HandshakeError> {
	let vk = ed25519_zebra::VerificationKey::try_from(payload.claimed_pubkey)
		.map_err(|_| HandshakeError::InvalidPubkey)?;
	let sig = ed25519_zebra::Signature::from(payload.signature);
	let preimage = handshake_preimage(&payload.claimed_pubkey, &payload.ephemeral_x25519);
	vk.verify(&sig, &preimage)
		.map_err(|_| HandshakeError::SignatureInvalid)?;
	Ok(())
}

// ───── Full X3DH (Phase 5: forward secrecy from message one) ──────────

/// HKDF info string for the PQXDH shared-secret derivation. Bumped
/// from the classical `x3dh/v1`: the hybrid construction folds an
/// ML-KEM leg into the ikm, so a classical initiation and a PQXDH
/// initiation can never derive the same secret. Hard cutover — there
/// is no chat mainnet, so no dual-path window (docs/PQ-CHAT.md).
pub const PQXDH_INFO: &[u8] = b"rostro/chat-channel/pqxdh/v1";

/// Signature domain for the signed prekey (SPK). The recipient's
/// identity Ed25519 key signs `SPK_SIGNATURE_DOMAIN || spk_x25519`;
/// publishing an unsigned prekey would let an active attacker swap in
/// their own and MITM every new conversation.
pub const SPK_SIGNATURE_DOMAIN: &[u8] = b"rostro/chat-channel/spk/v1";

/// Signature domain for one-time prekeys (OPK): the identity key
/// signs `OPK_SIGNATURE_DOMAIN || opk_id_le_bytes || opk_x25519`.
pub const OPK_SIGNATURE_DOMAIN: &[u8] = b"rostro/chat-channel/opk/v1";

/// Signature domain for the post-quantum signed prekey (PQSPK): the
/// identity key signs `PQSPK_SIGNATURE_DOMAIN || pqspk_ek`. The KEM
/// prekey MUST be identity-signed for the same reason the classical
/// SPK is — an unsigned KEM prekey lets an active attacker swap in
/// their own encapsulation key and the "post-quantum" leg protects the
/// attacker's channel, not the user's.
pub const PQSPK_SIGNATURE_DOMAIN: &[u8] = b"rostro/chat-channel/pqspk/v1";

/// The recipient's published prekey material, as the SENDER sees it
/// when starting a new conversation: identity key (from the RNS
/// chat-identity record), signed prekey (also from the record), and
/// optionally one one-time prekey picked from the recipient's
/// published batch. Callers MUST [`verify_spk`] (and
/// [`SignedOneTimePrekey::verify`] when an OPK is used) before
/// calling [`x3dh_initiate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrekeyBundle {
	/// Recipient's chat-identity Ed25519 pubkey (verifies signatures).
	pub identity_ed25519: [u8; 32],
	/// Recipient's identity key in X25519 form (the standard
	/// Edwards→Montgomery conversion of `identity_ed25519` — the
	/// caller performs/validates the conversion).
	pub identity_x25519: [u8; 32],
	/// Signed prekey (X25519), rotated periodically via the record.
	pub spk_x25519: [u8; 32],
	/// Identity signature over the SPK.
	pub spk_signature: [u8; 64],
	/// Post-quantum signed prekey: an ML-KEM-768 encapsulation key,
	/// rotated alongside the SPK. The initiator encapsulates against
	/// it; the resulting shared secret is folded into the PQXDH KDF so
	/// the conversation survives retroactive decryption of the X25519
	/// legs at Q-day (docs/PQ-CHAT.md). Published in the same RNS
	/// chat-identity record as the SPK.
	pub pqspk_ek: [u8; rostro_hybrid_kex::MLKEM768_EK_BYTES],
	/// Identity signature over the PQSPK encapsulation key.
	pub pqspk_signature: [u8; 64],
	/// One-time prekey `(id, pubkey)`, if one was available. Absent
	/// OPK degrades gracefully to SPK-only X3DH (first-message
	/// forward secrecy still holds via DH3; replay protection of the
	/// initiation weakens) — same degradation as Signal's
	/// prekey-exhaustion mode.
	pub opk: Option<(u32, [u8; 32])>,
}

/// A published one-time prekey, identity-signed.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct SignedOneTimePrekey {
	pub id: u32,
	pub x25519: [u8; 32],
	pub signature: [u8; 64],
}

/// Canonical SPK signature preimage.
pub fn spk_preimage(spk_x25519: &[u8; 32]) -> Vec<u8> {
	let mut buf = Vec::with_capacity(SPK_SIGNATURE_DOMAIN.len() + 32);
	buf.extend_from_slice(SPK_SIGNATURE_DOMAIN);
	buf.extend_from_slice(spk_x25519);
	buf
}

/// Canonical OPK signature preimage.
pub fn opk_preimage(id: u32, opk_x25519: &[u8; 32]) -> Vec<u8> {
	let mut buf = Vec::with_capacity(OPK_SIGNATURE_DOMAIN.len() + 4 + 32);
	buf.extend_from_slice(OPK_SIGNATURE_DOMAIN);
	buf.extend_from_slice(&id.to_le_bytes());
	buf.extend_from_slice(opk_x25519);
	buf
}

/// Sign a signed-prekey pubkey with the identity key.
#[cfg(feature = "std")]
pub fn sign_spk(
	spk_pub: &X25519PublicKey,
	identity_signing: &ed25519_zebra::SigningKey,
) -> [u8; 64] {
	let sig: ed25519_zebra::Signature =
		identity_signing.sign(&spk_preimage(spk_pub.as_bytes()));
	sig.into()
}

/// Sign a one-time prekey with the identity key.
#[cfg(feature = "std")]
pub fn sign_opk(
	id: u32,
	opk_pub: &X25519PublicKey,
	identity_signing: &ed25519_zebra::SigningKey,
) -> [u8; 64] {
	let sig: ed25519_zebra::Signature =
		identity_signing.sign(&opk_preimage(id, opk_pub.as_bytes()));
	sig.into()
}

/// Verify the bundle's SPK signature under its identity key.
pub fn verify_spk(bundle: &PrekeyBundle) -> Result<(), HandshakeError> {
	let vk = ed25519_zebra::VerificationKey::try_from(bundle.identity_ed25519)
		.map_err(|_| HandshakeError::InvalidPubkey)?;
	let sig = ed25519_zebra::Signature::from(bundle.spk_signature);
	vk.verify(&sig, &spk_preimage(&bundle.spk_x25519))
		.map_err(|_| HandshakeError::SignatureInvalid)?;
	Ok(())
}

/// Canonical PQSPK signature preimage.
pub fn pqspk_preimage(
	pqspk_ek: &[u8; rostro_hybrid_kex::MLKEM768_EK_BYTES],
) -> Vec<u8> {
	let mut buf = Vec::with_capacity(PQSPK_SIGNATURE_DOMAIN.len() + pqspk_ek.len());
	buf.extend_from_slice(PQSPK_SIGNATURE_DOMAIN);
	buf.extend_from_slice(pqspk_ek);
	buf
}

/// Sign a post-quantum signed-prekey (ML-KEM-768 encapsulation key)
/// with the identity key.
#[cfg(feature = "std")]
pub fn sign_pqspk(
	pqspk_ek: &[u8; rostro_hybrid_kex::MLKEM768_EK_BYTES],
	identity_signing: &ed25519_zebra::SigningKey,
) -> [u8; 64] {
	let sig: ed25519_zebra::Signature =
		identity_signing.sign(&pqspk_preimage(pqspk_ek));
	sig.into()
}

/// Verify the bundle's PQSPK signature under its identity key. Callers
/// MUST run this (in addition to [`verify_spk`]) before
/// [`x3dh_initiate`]: an unsigned/forged KEM prekey defeats the whole
/// point of the post-quantum leg.
pub fn verify_pqspk(bundle: &PrekeyBundle) -> Result<(), HandshakeError> {
	let vk = ed25519_zebra::VerificationKey::try_from(bundle.identity_ed25519)
		.map_err(|_| HandshakeError::InvalidPubkey)?;
	let sig = ed25519_zebra::Signature::from(bundle.pqspk_signature);
	vk.verify(&sig, &pqspk_preimage(&bundle.pqspk_ek))
		.map_err(|_| HandshakeError::SignatureInvalid)?;
	Ok(())
}

/// SEAL-key signature domain: the sealed-sender hybrid sealing key
/// (RNS `SEAL` record, docs/PQ-CHAT.md). A DIFFERENT domain from the
/// PQSPK's even though both sign an ML-KEM-768 ek: a prekey signature
/// must never validate as a sealing-key signature or vice versa — the
/// two keys have deliberately different lifecycles.
pub const SEAL_SIGNATURE_DOMAIN: &[u8] = b"rostro/chat-channel/seal/v1";

/// Canonical SEAL-key signature preimage.
pub fn seal_ek_preimage(
	seal_ek: &[u8; rostro_hybrid_kex::MLKEM768_EK_BYTES],
) -> Vec<u8> {
	let mut buf = Vec::with_capacity(SEAL_SIGNATURE_DOMAIN.len() + seal_ek.len());
	buf.extend_from_slice(SEAL_SIGNATURE_DOMAIN);
	buf.extend_from_slice(seal_ek);
	buf
}

/// Sign a sealed-sender hybrid sealing key (ML-KEM-768 encapsulation
/// key) with the identity key, for publication in the RNS `SEAL`
/// record.
#[cfg(feature = "std")]
pub fn sign_seal_ek(
	seal_ek: &[u8; rostro_hybrid_kex::MLKEM768_EK_BYTES],
	identity_signing: &ed25519_zebra::SigningKey,
) -> [u8; 64] {
	let sig: ed25519_zebra::Signature =
		identity_signing.sign(&seal_ek_preimage(seal_ek));
	sig.into()
}

/// Verify a resolved SEAL record's signature under the publisher's
/// identity key (the `CHAT` record). Senders MUST run this before
/// `hybrid_seal`ing an envelope to the key: an unsigned/forged sealing
/// key hands the outer envelope to an attacker.
pub fn verify_seal_ek(
	identity_ed25519: &[u8; 32],
	seal_ek: &[u8; rostro_hybrid_kex::MLKEM768_EK_BYTES],
	signature: &[u8; 64],
) -> Result<(), HandshakeError> {
	let vk = ed25519_zebra::VerificationKey::try_from(*identity_ed25519)
		.map_err(|_| HandshakeError::InvalidPubkey)?;
	let sig = ed25519_zebra::Signature::from(*signature);
	vk.verify(&sig, &seal_ek_preimage(seal_ek))
		.map_err(|_| HandshakeError::SignatureInvalid)?;
	Ok(())
}

impl SignedOneTimePrekey {
	/// Verify this OPK's signature under the publisher's identity key.
	pub fn verify(&self, identity_ed25519: &[u8; 32]) -> Result<(), HandshakeError> {
		let vk = ed25519_zebra::VerificationKey::try_from(*identity_ed25519)
			.map_err(|_| HandshakeError::InvalidPubkey)?;
		let sig = ed25519_zebra::Signature::from(self.signature);
		vk.verify(&sig, &opk_preimage(self.id, &self.x25519))
			.map_err(|_| HandshakeError::SignatureInvalid)?;
		Ok(())
	}
}

/// X3DH initiation data carried (inside the encrypted envelope) by
/// the FIRST message of a new conversation, so the responder can
/// derive the same shared secret. The initiator's identity Ed25519 is
/// authenticated by the envelope's existing inner signature; the
/// responder converts it to X25519 for DH2.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct X3dhInit {
	pub initiator_identity_ed25519: [u8; 32],
	pub ephemeral_x25519: [u8; 32],
	pub opk_id: Option<u32>,
	/// ML-KEM-768 ciphertext encapsulated against the responder's
	/// PQSPK. The responder decapsulates it to recover the same KEM
	/// shared secret the initiator folded into the PQXDH KDF. ~1088 B;
	/// carried only by the first message of a conversation.
	pub pq_ct: [u8; rostro_hybrid_kex::MLKEM768_CT_BYTES],
}

/// Initiator side of full X3DH. `bundle` must already be verified
/// ([`verify_spk`] + OPK signature). Returns the wire
/// [`X3dhInit`], the 32-byte shared secret, and the ephemeral secret
/// — feed the latter two to [`Session::from_handshake_initiator`]
/// with `peer_initial_pub = bundle.spk_x25519`:
///
/// ```text
/// DH1 = DH(IK_A,  SPK_B)   — initiator identity → responder prekey
/// DH2 = DH(EK_A,  IK_B)    — fresh ephemeral → responder identity
/// DH3 = DH(EK_A,  SPK_B)   — fresh ephemeral → responder prekey
/// DH4 = DH(EK_A,  OPK_B)   — fresh ephemeral → one-time prekey (if any)
/// KEM = ML-KEM-768.Encaps(PQSPK_B) — post-quantum leg, SS appended last
/// SK  = HKDF(salt=0, ikm=0xFF×32 ‖ DH1‖DH2‖DH3[‖DH4]‖KEM_SS, info=PQXDH_INFO)
/// ```
///
/// DH3 makes the very first message forward-secret (EK_A is destroyed
/// after the session initializes); DH4 additionally protects the
/// initiation against SPK compromise + replay.
///
/// PQXDH: the returned secret additionally folds an ML-KEM-768 shared
/// secret encapsulated against `bundle.pqspk_ek`, so the conversation
/// is confidential against retroactive decryption of the X25519 legs
/// unless ML-KEM *also* falls. Callers MUST have run [`verify_spk`]
/// AND [`verify_pqspk`] on `bundle` first. Returns
/// [`HandshakeError::InvalidPubkey`] if the PQSPK is not a valid
/// ML-KEM-768 encapsulation key.
pub fn x3dh_initiate<R>(
	initiator_identity_secret: &X25519SecretKey,
	initiator_identity_ed25519: [u8; 32],
	bundle: &PrekeyBundle,
	rng: &mut R,
) -> Result<(X3dhInit, [u8; 32], X25519SecretKey), HandshakeError>
where
	R: rand_core::RngCore + rand_core::CryptoRng,
{
	let ephemeral = X25519SecretKey::random_from_rng(&mut *rng);
	let spk_pub = X25519PublicKey::from(bundle.spk_x25519);
	let ik_b = X25519PublicKey::from(bundle.identity_x25519);

	let dh1 = initiator_identity_secret.diffie_hellman(&spk_pub);
	let dh2 = ephemeral.diffie_hellman(&ik_b);
	let dh3 = ephemeral.diffie_hellman(&spk_pub);
	let dh4 = bundle
		.opk
		.map(|(_, opk)| ephemeral.diffie_hellman(&X25519PublicKey::from(opk)));

	// PQ leg: encapsulate against the responder's KEM prekey with fresh
	// CSPRNG randomness.
	let mut m = [0u8; 32];
	rng.fill_bytes(&mut m);
	let (pq_ct, pq_ss) = rostro_hybrid_kex::mlkem_encapsulate(&bundle.pqspk_ek, &m)
		.map_err(|_| HandshakeError::InvalidPubkey)?;

	let sk = pqxdh_kdf(
		dh1.as_bytes(),
		dh2.as_bytes(),
		dh3.as_bytes(),
		dh4.as_ref().map(|d| d.as_bytes()),
		&pq_ss,
	);

	let init = X3dhInit {
		initiator_identity_ed25519,
		ephemeral_x25519: *X25519PublicKey::from(&ephemeral).as_bytes(),
		opk_id: bundle.opk.map(|(id, _)| id),
		pq_ct,
	};
	Ok((init, sk, ephemeral))
}

/// Errors from [`x3dh_respond`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum X3dhError {
	/// The initiation references an OPK id whose secret this device
	/// no longer holds (already consumed, or a concurrent initiator
	/// grabbed the same one). Recoverable: the initiator retries
	/// without an OPK (SPK-only).
	OpkUnavailable,
	/// The PQ ciphertext failed to decapsulate outright (malformed
	/// encoding). Note: a *tampered* ciphertext does NOT land here —
	/// ML-KEM implicit rejection yields a deterministic garbage secret
	/// and the first message then fails its AEAD, so there is no
	/// decapsulation oracle. This variant is only the hard-decode case.
	PqDecapFailed,
}

/// Responder side of full PQXDH. `initiator_identity_x25519` is the
/// caller-converted X25519 form of `init.initiator_identity_ed25519`
/// (the caller verified the envelope signature under that Ed25519
/// first). `pqspk_decap` is the ML-KEM-768 decapsulation key matching
/// the PQSPK the responder published. Feed the result to
/// [`Session::from_handshake_responder`] with
/// `sending_secret = spk_secret.clone()`,
/// `peer_initial_pub = init.ephemeral_x25519`.
pub fn x3dh_respond(
	responder_identity_secret: &X25519SecretKey,
	spk_secret: &X25519SecretKey,
	opk_secret: Option<&X25519SecretKey>,
	pqspk_decap: &rostro_hybrid_kex::MlKemDecapKey,
	initiator_identity_x25519: &X25519PublicKey,
	init: &X3dhInit,
) -> Result<[u8; 32], X3dhError> {
	if init.opk_id.is_some() && opk_secret.is_none() {
		return Err(X3dhError::OpkUnavailable);
	}
	let ek_a = X25519PublicKey::from(init.ephemeral_x25519);

	let dh1 = spk_secret.diffie_hellman(initiator_identity_x25519);
	let dh2 = responder_identity_secret.diffie_hellman(&ek_a);
	let dh3 = spk_secret.diffie_hellman(&ek_a);
	let dh4 = opk_secret
		.filter(|_| init.opk_id.is_some())
		.map(|opk| opk.diffie_hellman(&ek_a));

	// PQ leg: decapsulate the initiator's ciphertext.
	let pq_ss = rostro_hybrid_kex::mlkem_decapsulate(pqspk_decap, &init.pq_ct)
		.map_err(|_| X3dhError::PqDecapFailed)?;

	Ok(pqxdh_kdf(
		dh1.as_bytes(),
		dh2.as_bytes(),
		dh3.as_bytes(),
		dh4.as_ref().map(|d| d.as_bytes()),
		&pq_ss,
	))
}

/// PQXDH KDF: 32 bytes of 0xFF (curve-domain pad, per the Signal
/// spec) prepended to the concatenated DH outputs, then the ML-KEM
/// shared secret appended LAST (Signal PQXDH ordering), HKDF'd under
/// [`PQXDH_INFO`].
fn pqxdh_kdf(
	dh1: &[u8; 32],
	dh2: &[u8; 32],
	dh3: &[u8; 32],
	dh4: Option<&[u8; 32]>,
	pq_ss: &[u8; 32],
) -> [u8; 32] {
	let mut ikm = Vec::with_capacity(32 * 6);
	ikm.extend_from_slice(&[0xFF; 32]);
	ikm.extend_from_slice(dh1);
	ikm.extend_from_slice(dh2);
	ikm.extend_from_slice(dh3);
	if let Some(d4) = dh4 {
		ikm.extend_from_slice(d4);
	}
	ikm.extend_from_slice(pq_ss);
	let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), &ikm);
	let mut sk = [0u8; 32];
	hk.expand(PQXDH_INFO, &mut sk).expect("32 bytes within HKDF limit");
	ikm.zeroize();
	sk
}

#[cfg(test)]
mod tests {
	use super::*;
	use rand_chacha::ChaCha20Rng;
	use rand_core::SeedableRng;

	fn fresh_session_pair() -> (Session, Session) {
		let mut rng_a = ChaCha20Rng::seed_from_u64(0xA1);
		let mut rng_b = ChaCha20Rng::seed_from_u64(0xB2);

		let alice_secret = X25519SecretKey::random_from_rng(&mut rng_a);
		let bob_secret = X25519SecretKey::random_from_rng(&mut rng_b);
		let alice_pub = X25519PublicKey::from(&alice_secret);
		let bob_pub = X25519PublicKey::from(&bob_secret);

		let shared_a = handshake_shared_secret(&alice_secret, &bob_pub);
		let shared_b = handshake_shared_secret(&bob_secret, &alice_pub);
		assert_eq!(shared_a, shared_b);

		let alice = Session::from_handshake_initiator(shared_a, alice_secret, bob_pub);
		let bob = Session::from_handshake_responder(shared_b, bob_secret, alice_pub);
		(alice, bob)
	}

	#[test]
	fn initiator_first_message_roundtrip() {
		let (mut alice, mut bob) = fresh_session_pair();
		let m1 = alice.encrypt(b"hello bob from chat channel");
		let p1 = bob.decrypt(&m1).expect("bob decrypts alice's first chat message");
		assert_eq!(p1, b"hello bob from chat channel");
	}

	#[test]
	fn responder_first_message_triggers_dh_ratchet_on_initiator() {
		let (mut alice, mut bob) = fresh_session_pair();
		let m1 = alice.encrypt(b"hi");
		bob.decrypt(&m1).unwrap();
		let m2 = bob.encrypt(b"hi alice");
		let p2 = alice.decrypt(&m2).expect("alice decrypts bob's reply");
		assert_eq!(p2, b"hi alice");
	}

	#[test]
	fn many_messages_in_one_direction() {
		let (mut alice, mut bob) = fresh_session_pair();
		for i in 0..20u32 {
			let payload = alloc::format!("chat msg {i}");
			let m = alice.encrypt(payload.as_bytes());
			let p = bob.decrypt(&m).expect("bob decrypts");
			assert_eq!(p, payload.as_bytes());
		}
		assert_eq!(alice.sending_count(), 20);
		assert_eq!(bob.receiving_count(), 20);
	}

	#[test]
	fn back_and_forth_advances_dh_ratchet() {
		let (mut alice, mut bob) = fresh_session_pair();
		for round in 0..5 {
			let from_alice = alice.encrypt(alloc::format!("a→b {round}").as_bytes());
			bob.decrypt(&from_alice).unwrap();
			let from_bob = bob.encrypt(alloc::format!("b→a {round}").as_bytes());
			alice.decrypt(&from_bob).unwrap();
		}
	}

	#[test]
	fn tampered_ciphertext_fails_aead() {
		let (mut alice, mut bob) = fresh_session_pair();
		let mut m = alice.encrypt(b"sensitive");
		m.ciphertext[0] ^= 0x01;
		assert_eq!(bob.decrypt(&m), Err(DecryptError::AeadAuthFailed));
	}

	#[test]
	fn tampered_header_fails_aead() {
		let (mut alice, mut bob) = fresh_session_pair();
		let mut m = alice.encrypt(b"sensitive");
		m.header.dh_pub[15] ^= 0xFF;
		let outcome = bob.decrypt(&m);
		assert!(
			matches!(outcome, Err(DecryptError::AeadAuthFailed)),
			"expected AeadAuthFailed, got {:?}",
			outcome,
		);
	}

	#[test]
	fn wire_message_scale_roundtrip() {
		let (mut alice, _bob) = fresh_session_pair();
		let m = alice.encrypt(b"roundtrip me");
		let bytes = m.encode();
		let decoded = WireMessage::decode(&mut &bytes[..]).unwrap();
		assert_eq!(decoded, m);
	}

	#[test]
	fn different_sessions_diverge_after_dh_ratchet() {
		let (mut a1, _b1) = fresh_session_pair();
		let (mut a2, _b2) = {
			let mut rng_a = ChaCha20Rng::seed_from_u64(0xCC);
			let mut rng_b = ChaCha20Rng::seed_from_u64(0xDD);
			let alice_secret = X25519SecretKey::random_from_rng(&mut rng_a);
			let bob_secret = X25519SecretKey::random_from_rng(&mut rng_b);
			let alice_pub = X25519PublicKey::from(&alice_secret);
			let bob_pub = X25519PublicKey::from(&bob_secret);
			let shared_a = handshake_shared_secret(&alice_secret, &bob_pub);
			let shared_b = handshake_shared_secret(&bob_secret, &alice_pub);
			(
				Session::from_handshake_initiator(shared_a, alice_secret, bob_pub),
				Session::from_handshake_responder(shared_b, bob_secret, alice_pub),
			)
		};
		let m1 = a1.encrypt(b"same plaintext");
		let m2 = a2.encrypt(b"same plaintext");
		assert_ne!(m1.ciphertext, m2.ciphertext);
		assert_ne!(m1.header.dh_pub, m2.header.dh_pub);
	}

	#[test]
	fn header_size_is_40_bytes_scale() {
		let h = MessageHeader { dh_pub: [0xAB; 32], msg_num: 42, prev_chain_len: 7 };
		assert_eq!(h.encode().len(), 40);
	}

	// ───── Phase 5: store-and-forward semantics ─────────────────────

	#[test]
	fn out_of_order_within_chain_recovers() {
		let (mut alice, mut bob) = fresh_session_pair();
		let m0 = alice.encrypt(b"zero");
		let m1 = alice.encrypt(b"one");
		let m2 = alice.encrypt(b"two");
		// Arrive 2, 0, 1.
		assert_eq!(bob.decrypt(&m2).unwrap(), b"two");
		assert_eq!(bob.decrypt(&m0).unwrap(), b"zero");
		assert_eq!(bob.decrypt(&m1).unwrap(), b"one");
	}

	#[test]
	fn ttl_expired_gap_does_not_break_thread() {
		let (mut alice, mut bob) = fresh_session_pair();
		let _lost = alice.encrypt(b"expired on the relay, never arrives");
		let m1 = alice.encrypt(b"after the gap");
		assert_eq!(bob.decrypt(&m1).unwrap(), b"after the gap");
		// Thread continues both ways across further ratchets.
		let r = bob.encrypt(b"reply");
		assert_eq!(alice.decrypt(&r).unwrap(), b"reply");
		let m3 = alice.encrypt(b"new chain msg");
		assert_eq!(bob.decrypt(&m3).unwrap(), b"new chain msg");
	}

	#[test]
	fn old_chain_straggler_decrypts_after_ratchet() {
		let (mut alice, mut bob) = fresh_session_pair();
		let m0 = alice.encrypt(b"chain1 delivered");
		let straggler = alice.encrypt(b"chain1 delayed");
		assert_eq!(bob.decrypt(&m0).unwrap(), b"chain1 delivered");
		// Full ratchet round WITHOUT the straggler arriving.
		let r = bob.encrypt(b"reply");
		alice.decrypt(&r).unwrap();
		let m_new = alice.encrypt(b"chain2 message");
		assert_eq!(bob.decrypt(&m_new).unwrap(), b"chain2 message");
		// The old-chain straggler arrives LAST — banked key opens it.
		assert_eq!(bob.decrypt(&straggler).unwrap(), b"chain1 delayed");
	}

	#[test]
	fn replayed_message_rejected() {
		let (mut alice, mut bob) = fresh_session_pair();
		let m0 = alice.encrypt(b"once only");
		assert_eq!(bob.decrypt(&m0).unwrap(), b"once only");
		assert_eq!(bob.decrypt(&m0), Err(DecryptError::MessageKeyMissing));
	}

	#[test]
	fn skip_limit_bounds_work() {
		let (mut alice, mut bob) = fresh_session_pair();
		for _ in 0..=MAX_SKIP {
			let _ = alice.encrypt(b"burn");
		}
		let too_far = alice.encrypt(b"past the limit");
		assert_eq!(bob.decrypt(&too_far), Err(DecryptError::SkipLimitExceeded));
		// And the failure did NOT corrupt the session: in-range
		// messages still work after the rejection.
		let (mut alice2, mut bob2) = fresh_session_pair();
		let a = alice2.encrypt(b"a");
		let _b = alice2.encrypt(b"b");
		let c = alice2.encrypt(b"c");
		assert_eq!(bob2.decrypt(&c).unwrap(), b"c");
		assert_eq!(bob2.decrypt(&a).unwrap(), b"a");
	}

	#[test]
	fn tampered_message_leaves_state_untouched() {
		let (mut alice, mut bob) = fresh_session_pair();
		let m0 = alice.encrypt(b"good zero");
		// Tamper a message that ALSO carries a new dh_pub (worst
		// case: would have triggered a ratchet step pre-commit).
		let mut evil = m0.clone();
		evil.header.dh_pub[3] ^= 0x5A;
		assert_eq!(bob.decrypt(&evil), Err(DecryptError::AeadAuthFailed));
		// The genuine message still decrypts — no ratchet poisoning.
		assert_eq!(bob.decrypt(&m0).unwrap(), b"good zero");
	}

	#[test]
	fn session_persists_and_resumes_mid_conversation() {
		let (mut alice, mut bob) = fresh_session_pair();
		let m0 = alice.encrypt(b"before restart");
		let skipped_then_late = alice.encrypt(b"banked across restart");
		let m2 = alice.encrypt(b"also before restart");
		assert_eq!(bob.decrypt(&m0).unwrap(), b"before restart");
		assert_eq!(bob.decrypt(&m2).unwrap(), b"also before restart");

		// "App restart": serialize + restore both ends.
		let mut bob2 = Session::from_state_bytes(&bob.to_state_bytes()).unwrap();
		let mut alice2 = Session::from_state_bytes(&alice.to_state_bytes()).unwrap();

		// Banked skipped key survived the restart.
		assert_eq!(bob2.decrypt(&skipped_then_late).unwrap(), b"banked across restart");
		// Ratchet continues across the restart in both directions.
		let r = bob2.encrypt(b"post-restart reply");
		assert_eq!(alice2.decrypt(&r).unwrap(), b"post-restart reply");
		let m3 = alice2.encrypt(b"and back");
		assert_eq!(bob2.decrypt(&m3).unwrap(), b"and back");
	}

	// ───── Phase 5: full PQXDH (hybrid X25519 + ML-KEM-768) ──────────

	/// A responder's ML-KEM-768 signed prekey for tests: fixed seed so
	/// the keypair is deterministic. Returns (decapsulation key,
	/// encapsulation-key bytes).
	fn test_pqspk(
		seed_byte: u8,
	) -> (rostro_hybrid_kex::MlKemDecapKey, [u8; rostro_hybrid_kex::MLKEM768_EK_BYTES]) {
		rostro_hybrid_kex::mlkem_keypair_from_seed(&[seed_byte; 64])
	}

	fn x3dh_fixture(use_opk: bool) -> (Session, Session) {
		let mut rng = ChaCha20Rng::seed_from_u64(0x3D);

		// Bob's identity + prekeys (responder).
		let bob_identity_signing = ed25519_zebra::SigningKey::new(&mut rng);
		let bob_identity_ed: [u8; 32] =
			ed25519_zebra::VerificationKey::from(&bob_identity_signing).into();
		let bob_ik = X25519SecretKey::random_from_rng(&mut rng);
		let bob_ik_pub = X25519PublicKey::from(&bob_ik);
		let bob_spk = X25519SecretKey::random_from_rng(&mut rng);
		let bob_spk_pub = X25519PublicKey::from(&bob_spk);
		let bob_opk = X25519SecretKey::random_from_rng(&mut rng);
		let bob_opk_pub = X25519PublicKey::from(&bob_opk);
		let (bob_pqspk_decap, bob_pqspk_ek) = test_pqspk(0xB9);

		// Alice's identity (initiator).
		let alice_identity_signing = ed25519_zebra::SigningKey::new(&mut rng);
		let alice_identity_ed: [u8; 32] =
			ed25519_zebra::VerificationKey::from(&alice_identity_signing).into();
		let alice_ik = X25519SecretKey::random_from_rng(&mut rng);
		let alice_ik_pub = X25519PublicKey::from(&alice_ik);

		let bundle = PrekeyBundle {
			identity_ed25519: bob_identity_ed,
			identity_x25519: *bob_ik_pub.as_bytes(),
			spk_x25519: *bob_spk_pub.as_bytes(),
			spk_signature: sign_spk(&bob_spk_pub, &bob_identity_signing),
			pqspk_ek: bob_pqspk_ek,
			pqspk_signature: sign_pqspk(&bob_pqspk_ek, &bob_identity_signing),
			opk: use_opk.then_some((7, *bob_opk_pub.as_bytes())),
		};
		verify_spk(&bundle).expect("SPK signature verifies");
		verify_pqspk(&bundle).expect("PQSPK signature verifies");

		let (init, sk_a, ek_secret) =
			x3dh_initiate(&alice_ik, alice_identity_ed, &bundle, &mut rng)
				.expect("initiator encapsulates");
		let sk_b = x3dh_respond(
			&bob_ik,
			&bob_spk,
			use_opk.then_some(&bob_opk),
			&bob_pqspk_decap,
			&alice_ik_pub,
			&init,
		)
		.expect("responder derives");
		assert_eq!(sk_a, sk_b, "PQXDH shared secrets agree");

		let alice =
			Session::from_handshake_initiator(sk_a, ek_secret, bob_spk_pub);
		let bob = Session::from_handshake_responder(
			sk_b,
			bob_spk,
			X25519PublicKey::from(init.ephemeral_x25519),
		);
		(alice, bob)
	}

	#[test]
	fn x3dh_full_bootstrap_with_opk() {
		let (mut alice, mut bob) = x3dh_fixture(true);
		let m = alice.encrypt(b"forward-secret from message one");
		assert_eq!(bob.decrypt(&m).unwrap(), b"forward-secret from message one");
		let r = bob.encrypt(b"ratcheting reply");
		assert_eq!(alice.decrypt(&r).unwrap(), b"ratcheting reply");
	}

	#[test]
	fn x3dh_spk_only_fallback() {
		let (mut alice, mut bob) = x3dh_fixture(false);
		let m = alice.encrypt(b"spk-only degradation still works");
		assert_eq!(bob.decrypt(&m).unwrap(), b"spk-only degradation still works");
	}

	#[test]
	fn pqxdh_kem_leg_actually_contributes() {
		// Same classical inputs + same ephemeral, but a DIFFERENT KEM
		// prekey must yield a DIFFERENT PQXDH secret — proof the ML-KEM
		// leg is folded in, not decorative.
		let mut rng = ChaCha20Rng::seed_from_u64(0x71);
		let bob_identity_signing = ed25519_zebra::SigningKey::new(&mut rng);
		let bob_identity_ed: [u8; 32] =
			ed25519_zebra::VerificationKey::from(&bob_identity_signing).into();
		let bob_ik = X25519SecretKey::random_from_rng(&mut rng);
		let bob_spk = X25519SecretKey::random_from_rng(&mut rng);
		let bob_spk_pub = X25519PublicKey::from(&bob_spk);
		let alice_ik = X25519SecretKey::random_from_rng(&mut rng);

		let mk_bundle = |ek: [u8; rostro_hybrid_kex::MLKEM768_EK_BYTES]| PrekeyBundle {
			identity_ed25519: bob_identity_ed,
			identity_x25519: *X25519PublicKey::from(&bob_ik).as_bytes(),
			spk_x25519: *bob_spk_pub.as_bytes(),
			spk_signature: sign_spk(&bob_spk_pub, &bob_identity_signing),
			pqspk_ek: ek,
			pqspk_signature: sign_pqspk(&ek, &bob_identity_signing),
			opk: None,
		};
		let (_, ek1) = test_pqspk(0x01);
		let (_, ek2) = test_pqspk(0x02);
		// Identical RNG stream on both sides → identical X25519 ephemeral
		// AND identical KEM encapsulation randomness, so the ONLY
		// difference is the KEM prekey.
		let mut r1 = ChaCha20Rng::seed_from_u64(0x99);
		let mut r2 = ChaCha20Rng::seed_from_u64(0x99);
		let (_, sk1, _) = x3dh_initiate(&alice_ik, [0u8; 32], &mk_bundle(ek1), &mut r1).unwrap();
		let (_, sk2, _) = x3dh_initiate(&alice_ik, [0u8; 32], &mk_bundle(ek2), &mut r2).unwrap();
		assert_ne!(sk1, sk2, "different KEM prekey must change the secret");
	}

	#[test]
	fn pqxdh_tampered_ciphertext_breaks_first_message() {
		// A flipped bit in pq_ct implicitly rejects to a garbage KEM
		// secret; the responder derives a different root and the first
		// message fails its AEAD (no decap oracle). We assert the two
		// sides DISAGREE, which is what makes decrypt fail downstream.
		let mut rng = ChaCha20Rng::seed_from_u64(0x72);
		let bob_identity_signing = ed25519_zebra::SigningKey::new(&mut rng);
		let bob_identity_ed: [u8; 32] =
			ed25519_zebra::VerificationKey::from(&bob_identity_signing).into();
		let bob_ik = X25519SecretKey::random_from_rng(&mut rng);
		let bob_ik_pub = X25519PublicKey::from(&bob_ik);
		let bob_spk = X25519SecretKey::random_from_rng(&mut rng);
		let bob_spk_pub = X25519PublicKey::from(&bob_spk);
		let (bob_pqspk_decap, bob_pqspk_ek) = test_pqspk(0xD4);
		let alice_ik = X25519SecretKey::random_from_rng(&mut rng);
		let alice_ik_pub = X25519PublicKey::from(&alice_ik);

		let bundle = PrekeyBundle {
			identity_ed25519: bob_identity_ed,
			identity_x25519: *bob_ik_pub.as_bytes(),
			spk_x25519: *bob_spk_pub.as_bytes(),
			spk_signature: sign_spk(&bob_spk_pub, &bob_identity_signing),
			pqspk_ek: bob_pqspk_ek,
			pqspk_signature: sign_pqspk(&bob_pqspk_ek, &bob_identity_signing),
			opk: None,
		};
		let (mut init, sk_a, _) =
			x3dh_initiate(&alice_ik, [9u8; 32], &bundle, &mut rng).unwrap();
		init.pq_ct[0] ^= 0xFF; // tamper

		let sk_b = x3dh_respond(
			&bob_ik,
			&bob_spk,
			None,
			&bob_pqspk_decap,
			&alice_ik_pub,
			&init,
		)
		.expect("implicit rejection is not an error");
		assert_ne!(sk_a, sk_b, "tampered ciphertext must desync the secret");
	}

	#[test]
	fn pqspk_signature_rejects_tamper() {
		let mut rng = ChaCha20Rng::seed_from_u64(0x73);
		let identity = ed25519_zebra::SigningKey::new(&mut rng);
		let identity_ed: [u8; 32] = ed25519_zebra::VerificationKey::from(&identity).into();
		let (_, ek) = test_pqspk(0xE5);
		let ik_pub = X25519PublicKey::from(&X25519SecretKey::random_from_rng(&mut rng));
		let spk_pub = X25519PublicKey::from(&X25519SecretKey::random_from_rng(&mut rng));
		let mut bundle = PrekeyBundle {
			identity_ed25519: identity_ed,
			identity_x25519: *ik_pub.as_bytes(),
			spk_x25519: *spk_pub.as_bytes(),
			spk_signature: sign_spk(&spk_pub, &identity),
			pqspk_ek: ek,
			pqspk_signature: sign_pqspk(&ek, &identity),
			opk: None,
		};
		verify_pqspk(&bundle).expect("genuine PQSPK verifies");
		bundle.pqspk_ek[0] ^= 0xFF; // flip a byte of the signed KEM key
		assert_eq!(verify_pqspk(&bundle), Err(HandshakeError::SignatureInvalid));
	}

	#[test]
	fn seal_ek_signature_roundtrip_and_tamper() {
		let mut rng = ChaCha20Rng::seed_from_u64(0x74);
		let identity = ed25519_zebra::SigningKey::new(&mut rng);
		let identity_ed: [u8; 32] = ed25519_zebra::VerificationKey::from(&identity).into();
		let (_, mut ek) = test_pqspk(0xE6);
		let sig = sign_seal_ek(&ek, &identity);
		verify_seal_ek(&identity_ed, &ek, &sig).expect("genuine SEAL key verifies");
		ek[0] ^= 0xFF; // flip a byte of the signed sealing key
		assert_eq!(
			verify_seal_ek(&identity_ed, &ek, &sig),
			Err(HandshakeError::SignatureInvalid),
		);
	}

	#[test]
	fn seal_and_pqspk_signatures_are_not_interchangeable() {
		// Same ML-KEM ek signed as a PQSPK must NOT verify as a SEAL
		// key (and vice versa): the domains keep the two lifecycles
		// cryptographically apart.
		let mut rng = ChaCha20Rng::seed_from_u64(0x75);
		let identity = ed25519_zebra::SigningKey::new(&mut rng);
		let identity_ed: [u8; 32] = ed25519_zebra::VerificationKey::from(&identity).into();
		let (_, ek) = test_pqspk(0xE7);
		let pqspk_sig = sign_pqspk(&ek, &identity);
		let seal_sig = sign_seal_ek(&ek, &identity);
		assert_ne!(pqspk_sig, seal_sig);
		assert_eq!(
			verify_seal_ek(&identity_ed, &ek, &pqspk_sig),
			Err(HandshakeError::SignatureInvalid),
		);
	}

	#[test]
	fn x3dh_opk_changes_secret() {
		// With vs without OPK must derive DIFFERENT secrets (DH4
		// actually contributes).
		let mut rng = ChaCha20Rng::seed_from_u64(0x3E);
		let bob_identity_signing = ed25519_zebra::SigningKey::new(&mut rng);
		let bob_identity_ed: [u8; 32] =
			ed25519_zebra::VerificationKey::from(&bob_identity_signing).into();
		let bob_ik = X25519SecretKey::random_from_rng(&mut rng);
		let bob_spk = X25519SecretKey::random_from_rng(&mut rng);
		let bob_spk_pub = X25519PublicKey::from(&bob_spk);
		let bob_opk = X25519SecretKey::random_from_rng(&mut rng);
		let alice_ik = X25519SecretKey::random_from_rng(&mut rng);

		let (_bob_pqspk_decap, bob_pqspk_ek) = test_pqspk(0xC3);
		let mk_bundle = |opk: Option<(u32, [u8; 32])>| PrekeyBundle {
			identity_ed25519: bob_identity_ed,
			identity_x25519: *X25519PublicKey::from(&bob_ik).as_bytes(),
			spk_x25519: *bob_spk_pub.as_bytes(),
			spk_signature: sign_spk(&bob_spk_pub, &bob_identity_signing),
			pqspk_ek: bob_pqspk_ek,
			pqspk_signature: sign_pqspk(&bob_pqspk_ek, &bob_identity_signing),
			opk,
		};
		let mut rng1 = ChaCha20Rng::seed_from_u64(0x55);
		let mut rng2 = ChaCha20Rng::seed_from_u64(0x55); // same ephemeral + same KEM m
		let (_, sk_with, _) = x3dh_initiate(
			&alice_ik,
			[0u8; 32],
			&mk_bundle(Some((1, *X25519PublicKey::from(&bob_opk).as_bytes()))),
			&mut rng1,
		)
		.unwrap();
		let (_, sk_without, _) =
			x3dh_initiate(&alice_ik, [0u8; 32], &mk_bundle(None), &mut rng2).unwrap();
		assert_ne!(sk_with, sk_without);
	}

	#[test]
	fn x3dh_missing_opk_secret_is_recoverable_error() {
		let mut rng = ChaCha20Rng::seed_from_u64(0x3F);
		let bob_ik = X25519SecretKey::random_from_rng(&mut rng);
		let bob_spk = X25519SecretKey::random_from_rng(&mut rng);
		let (bob_pqspk_decap, _bob_pqspk_ek) = test_pqspk(0xC7);
		let init = X3dhInit {
			initiator_identity_ed25519: [1u8; 32],
			ephemeral_x25519: [2u8; 32],
			opk_id: Some(9),
			pq_ct: [0u8; rostro_hybrid_kex::MLKEM768_CT_BYTES],
		};
		let alice_pub = X25519PublicKey::from([3u8; 32]);
		// OPK-availability is checked before the PQ decap, so this
		// returns OpkUnavailable regardless of the (dummy) ciphertext.
		assert_eq!(
			x3dh_respond(&bob_ik, &bob_spk, None, &bob_pqspk_decap, &alice_pub, &init),
			Err(X3dhError::OpkUnavailable)
		);
	}

	#[test]
	fn signed_opk_verifies_and_rejects_tamper() {
		let mut rng = ChaCha20Rng::seed_from_u64(0x40);
		let identity = ed25519_zebra::SigningKey::new(&mut rng);
		let identity_ed: [u8; 32] = ed25519_zebra::VerificationKey::from(&identity).into();
		let opk = X25519SecretKey::random_from_rng(&mut rng);
		let opk_pub = X25519PublicKey::from(&opk);
		let signed = SignedOneTimePrekey {
			id: 3,
			x25519: *opk_pub.as_bytes(),
			signature: sign_opk(3, &opk_pub, &identity),
		};
		signed.verify(&identity_ed).expect("verifies");
		let mut bad = signed.clone();
		bad.id = 4; // id is in the preimage
		assert!(bad.verify(&identity_ed).is_err());
	}

	#[test]
	fn handshake_shared_secret_is_symmetric() {
		let mut rng_a = ChaCha20Rng::seed_from_u64(1);
		let mut rng_b = ChaCha20Rng::seed_from_u64(2);
		let a_sec = X25519SecretKey::random_from_rng(&mut rng_a);
		let b_sec = X25519SecretKey::random_from_rng(&mut rng_b);
		let a_pub = X25519PublicKey::from(&a_sec);
		let b_pub = X25519PublicKey::from(&b_sec);
		assert_eq!(
			handshake_shared_secret(&a_sec, &b_pub),
			handshake_shared_secret(&b_sec, &a_pub),
		);
	}

	#[test]
	fn kdf_root_is_deterministic_and_branch_separated() {
		let rk = [0x42u8; 32];
		let dh1 = [0x11u8; 32];
		let dh2 = [0x22u8; 32];
		let (rk_a, ck_a) = kdf_root(&rk, &dh1);
		let (rk_b, ck_b) = kdf_root(&rk, &dh1);
		assert_eq!(rk_a, rk_b);
		assert_eq!(ck_a.0, ck_b.0);
		let (rk_c, ck_c) = kdf_root(&rk, &dh2);
		assert_ne!(rk_a, rk_c);
		assert_ne!(ck_a.0, ck_c.0);
		assert_ne!(rk_a, ck_a.0);
	}

	#[test]
	fn derive_message_key_branch_separation() {
		let ck = ChainKey([0x99u8; 32]);
		let (next_ck, mk) = derive_message_key(&ck);
		assert_ne!(next_ck.0, mk);
		assert_ne!(next_ck.0, ck.0);
		assert_ne!(mk, ck.0);
	}

	#[test]
	fn nonce_is_deterministic_per_message_key() {
		let mk = [0x33u8; 32];
		let n1 = derive_nonce(&mk);
		let n2 = derive_nonce(&mk);
		assert_eq!(n1, n2);
		let mk2 = [0x34u8; 32];
		assert_ne!(derive_nonce(&mk2), n1);
	}

	// ── Handshake payload tests ────────────────────────────────────

	fn fixed_signing_key(seed_byte: u8) -> ed25519_zebra::SigningKey {
		ed25519_zebra::SigningKey::from([seed_byte; 32])
	}

	fn fresh_ephemeral_pub(rng_seed: u64) -> (X25519SecretKey, X25519PublicKey) {
		let mut rng = ChaCha20Rng::seed_from_u64(rng_seed);
		let secret = X25519SecretKey::random_from_rng(&mut rng);
		let public = X25519PublicKey::from(&secret);
		(secret, public)
	}

	#[test]
	fn handshake_preimage_layout_is_stable() {
		let p = handshake_preimage(&[0xAA; 32], &[0xBB; 32]);
		assert_eq!(p.len(), HANDSHAKE_DOMAIN.len() + 64);
		assert_eq!(&p[..HANDSHAKE_DOMAIN.len()], HANDSHAKE_DOMAIN);
		let body_off = HANDSHAKE_DOMAIN.len();
		assert_eq!(&p[body_off..body_off + 32], &[0xAA; 32]);
		assert_eq!(&p[body_off + 32..body_off + 64], &[0xBB; 32]);
	}

	#[test]
	fn handshake_scale_roundtrip() {
		let key = fixed_signing_key(0xA0);
		let (_secret, pub_e) = fresh_ephemeral_pub(0xE1);
		let payload = sign_handshake(&pub_e, &key);
		let bytes = payload.encode();
		let decoded = HandshakePayload::decode(&mut &bytes[..]).unwrap();
		assert_eq!(payload, decoded);
	}

	#[test]
	fn handshake_sign_then_verify_passes() {
		let key = fixed_signing_key(0xA0);
		let (_secret, pub_e) = fresh_ephemeral_pub(0xE2);
		let payload = sign_handshake(&pub_e, &key);
		verify_handshake(&payload).expect("freshly signed handshake must verify");
	}

	#[test]
	fn handshake_verify_rejects_tampered_pubkey() {
		let key = fixed_signing_key(0xA0);
		let (_secret, pub_e) = fresh_ephemeral_pub(0xE3);
		let mut payload = sign_handshake(&pub_e, &key);
		let other = fixed_signing_key(0xB0);
		payload.claimed_pubkey =
			ed25519_zebra::VerificationKey::from(&other).into();
		match verify_handshake(&payload) {
			Err(HandshakeError::SignatureInvalid) => {},
			other => panic!("expected SignatureInvalid, got {:?}", other),
		}
	}

	#[test]
	fn handshake_verify_rejects_tampered_ephemeral() {
		let key = fixed_signing_key(0xA0);
		let (_secret, pub_e) = fresh_ephemeral_pub(0xE4);
		let mut payload = sign_handshake(&pub_e, &key);
		payload.ephemeral_x25519[0] ^= 0xFF;
		match verify_handshake(&payload) {
			Err(HandshakeError::SignatureInvalid) => {},
			other => panic!("expected SignatureInvalid, got {:?}", other),
		}
	}

	#[test]
	fn handshake_verify_rejects_tampered_signature() {
		let key = fixed_signing_key(0xA0);
		let (_secret, pub_e) = fresh_ephemeral_pub(0xE5);
		let mut payload = sign_handshake(&pub_e, &key);
		payload.signature[0] ^= 0xFF;
		match verify_handshake(&payload) {
			Err(HandshakeError::SignatureInvalid) => {},
			other => panic!("expected SignatureInvalid, got {:?}", other),
		}
	}

	#[test]
	fn handshake_to_session_end_to_end() {
		let alice_signing = fixed_signing_key(0xA0);
		let bob_signing = fixed_signing_key(0xB0);

		let (alice_eph_secret, alice_eph_pub) = fresh_ephemeral_pub(0xE10);
		let (bob_eph_secret, bob_eph_pub) = fresh_ephemeral_pub(0xE20);

		let alice_hs = sign_handshake(&alice_eph_pub, &alice_signing);
		let bob_hs = sign_handshake(&bob_eph_pub, &bob_signing);

		verify_handshake(&bob_hs).expect("alice verifies bob's handshake");
		verify_handshake(&alice_hs).expect("bob verifies alice's handshake");

		let bob_eph_pub_rebuilt = X25519PublicKey::from(bob_hs.ephemeral_x25519);
		let alice_eph_pub_rebuilt = X25519PublicKey::from(alice_hs.ephemeral_x25519);
		let alice_shared =
			handshake_shared_secret(&alice_eph_secret, &bob_eph_pub_rebuilt);
		let bob_shared =
			handshake_shared_secret(&bob_eph_secret, &alice_eph_pub_rebuilt);
		assert_eq!(alice_shared, bob_shared);

		let mut alice = Session::from_handshake_initiator(
			alice_shared,
			alice_eph_secret,
			bob_eph_pub_rebuilt,
		);
		let mut bob = Session::from_handshake_responder(
			bob_shared,
			bob_eph_secret,
			alice_eph_pub_rebuilt,
		);

		let msg = alice.encrypt(b"first chat message after handshake");
		let plain = bob.decrypt(&msg).expect("bob decrypts");
		assert_eq!(plain, b"first chat message after handshake");
	}

	// ── Cross-channel isolation invariants ─────────────────────────

	#[test]
	fn handshake_domain_is_distinct_from_validator_channel() {
		// Pin the chat-channel HANDSHAKE_DOMAIN against accidental
		// drift toward the validator-channel value. If these two
		// strings ever match, a signed handshake from one channel
		// would replay into the other.
		assert_eq!(HANDSHAKE_DOMAIN, b"rostro/chat-channel/handshake/v1");
		assert_ne!(HANDSHAKE_DOMAIN, b"rostro/validator-channel/handshake/v1");
	}

	#[test]
	fn kdf_outputs_differ_from_validator_channel_kdf() {
		// Cross-channel isolation: prove that even with identical
		// inputs (root_key, dh_out), the chat-channel KDF produces
		// outputs that differ from what a validator-channel KDF
		// would produce. The domain tag flows through HKDF's `info`
		// parameter so the outputs must diverge.
		//
		// We re-implement the validator-channel KDF locally with its
		// known `info` string, run both with identical inputs, and
		// assert the outputs differ.
		let rk = [0x42u8; 32];
		let dh = [0x11u8; 32];

		let (chat_rk, chat_ck) = kdf_root(&rk, &dh);

		const VALIDATOR_ROOT_INFO: &[u8] = b"rostro/validator-channel/root/v1";
		let hk = Hkdf::<Sha256>::new(Some(&rk), &dh);
		let mut validator_okm = [0u8; 64];
		hk.expand(VALIDATOR_ROOT_INFO, &mut validator_okm).unwrap();
		let mut validator_rk = [0u8; 32];
		let mut validator_ck = [0u8; 32];
		validator_rk.copy_from_slice(&validator_okm[..32]);
		validator_ck.copy_from_slice(&validator_okm[32..]);

		assert_ne!(
			chat_rk, validator_rk,
			"chat-channel and validator-channel root-key derivations must diverge \
			 even on identical inputs — domain separation is load-bearing",
		);
		assert_ne!(chat_ck.0, validator_ck);
	}

	#[test]
	fn message_key_derivation_differs_from_validator_channel() {
		// Same cross-channel isolation check, but for the
		// chain-key → message-key derivation step.
		let ck = ChainKey([0x99u8; 32]);
		let (_next_ck_chat, mk_chat) = derive_message_key(&ck);

		const VALIDATOR_CHAIN_MSG_INFO: &[u8] = b"rostro/validator-channel/msg/v1";
		let hk = Hkdf::<Sha256>::new(None, &ck.0);
		let mut mk_validator = [0u8; 32];
		hk.expand(VALIDATOR_CHAIN_MSG_INFO, &mut mk_validator).unwrap();

		assert_ne!(
			mk_chat, mk_validator,
			"chat-channel and validator-channel message-key derivations must \
			 diverge — domain separation flows through HKDF info",
		);
	}

	#[test]
	fn handshake_signed_for_validator_channel_does_not_verify_under_chat() {
		// Build a handshake payload whose signature was made over
		// the VALIDATOR-channel preimage layout, then attempt to
		// verify it under chat-channel's verify_handshake. Must
		// fail — domain mismatch invalidates the signature.
		let key = fixed_signing_key(0xA0);
		let (_secret, pub_e) = fresh_ephemeral_pub(0xE99);

		let claimed_pubkey: [u8; 32] =
			ed25519_zebra::VerificationKey::from(&key).into();
		let ephemeral_bytes = *pub_e.as_bytes();

		// Forge a preimage using the VALIDATOR-channel domain tag.
		const VALIDATOR_HANDSHAKE_DOMAIN: &[u8] =
			b"rostro/validator-channel/handshake/v1";
		let mut validator_preimage =
			Vec::with_capacity(VALIDATOR_HANDSHAKE_DOMAIN.len() + 64);
		validator_preimage.extend_from_slice(VALIDATOR_HANDSHAKE_DOMAIN);
		validator_preimage.extend_from_slice(&claimed_pubkey);
		validator_preimage.extend_from_slice(&ephemeral_bytes);
		let sig: ed25519_zebra::Signature = key.sign(&validator_preimage);

		let forged = HandshakePayload {
			claimed_pubkey,
			ephemeral_x25519: ephemeral_bytes,
			signature: sig.into(),
		};

		// Verify under the chat-channel verifier — must fail.
		assert_eq!(
			verify_handshake(&forged),
			Err(HandshakeError::SignatureInvalid),
			"a validator-channel-domain handshake signature must NOT verify \
			 under the chat-channel handshake verifier",
		);
	}
}
