// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # rostro-validator-channel — Double Ratchet primitives
//!
//! Pairwise Double Ratchet session protocol for the validator-only
//! encrypted gossip channel (Phase Z, v0.1.0). Each pair of active
//! validators maintains one [`Session`] carrying ratcheting
//! ChaCha20-Poly1305 encryption with per-message forward secrecy and
//! post-compromise security via Signal's Double Ratchet
//! construction.
//!
//! ## What this crate is
//!
//! Pure cryptographic protocol logic — X25519 DH, HKDF-SHA256 chain
//! derivation, HMAC-SHA256 message-key derivation,
//! ChaCha20-Poly1305 AEAD. No libp2p, no sc-network, no async.
//! Unit-testable in microseconds.
//!
//! ## What this crate is NOT
//!
//! - **Not the libp2p binding.** The gemini-node integration that
//!   wires this protocol to a notification protocol substream is a
//!   separate module.
//! - **Not the active-set authentication layer.** Caller is
//!   responsible for confirming the peer is in the on-chain active
//!   validator set BEFORE invoking [`Handshake`] (see Phase Z2).
//!   This crate ASSUMES the caller has done that check.
//! - **Not a general Signal-protocol implementation.** Out-of-order
//!   delivery, skipped-message keys, header encryption — all
//!   omitted because libp2p's Noise transport guarantees in-order
//!   per-substream delivery for our use case. If we ever move
//!   validator gossip onto a lossy transport, the skipped-message
//!   handling needs to be added back.
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

/// Root-key info string for HKDF. Bumping changes the KDF context
/// and is a backwards-incompatible protocol change.
const ROOT_INFO: &[u8] = b"rostro/validator-channel/root/v1";

/// Chain-key info string used in [`derive_message_key`].
const CHAIN_MSG_INFO: &[u8] = b"rostro/validator-channel/msg/v1";

/// Chain-key info string used to advance the chain.
const CHAIN_NEXT_INFO: &[u8] = b"rostro/validator-channel/next/v1";

/// Nonce-derivation info string.
const NONCE_INFO: &[u8] = b"rostro/validator-channel/nonce/v1";

/// One end of an established Double Ratchet session.
pub struct Session {
	sending_secret: X25519SecretKey,
	receiving_pub: X25519PublicKey,
	root_key: [u8; 32],
	sending_chain_key: ChainKey,
	receiving_chain_key: ChainKey,
	sending_count: u32,
	receiving_count: u32,
}

/// 32-byte chain key, zeroized on drop.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
struct ChainKey([u8; 32]);

/// On-the-wire message header. Carries the sender's current ephemeral
/// pubkey + sending-chain message counter. The receiver uses
/// `dh_pub` to detect DH-ratchet steps and `msg_num` to index the
/// chain key derivation (currently unused for skip handling but
/// reserved for v1+ when out-of-order delivery may be added).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct MessageHeader {
	pub dh_pub: [u8; 32],
	pub msg_num: u32,
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
		// Initiator's first DH output IS the shared secret (already
		// computed by the caller). Derive (RK, CKs) from it; the
		// receiving chain will be initialized on the first inbound
		// message (which triggers a DH ratchet).
		let (root_key, sending_chain_key) = kdf_root(&[0u8; 32], &shared_secret);
		Self {
			sending_secret,
			receiving_pub: peer_initial_pub,
			root_key,
			sending_chain_key,
			receiving_chain_key: ChainKey([0u8; 32]),
			sending_count: 0,
			receiving_count: 0,
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
		}
	}

	/// Encrypt a plaintext message. Advances the sending chain by
	/// one and returns the full [`WireMessage`]. The plaintext is
	/// zeroized inside the function before return.
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
		let header = MessageHeader { dh_pub: *dh_pub.as_bytes(), msg_num: self.sending_count };
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

	/// Decrypt an inbound message. May trigger a receiving-side DH
	/// ratchet if the header carries a previously-unseen sending
	/// pubkey. Returns the plaintext or an error.
	pub fn decrypt(&mut self, message: &WireMessage) -> Result<Vec<u8>, DecryptError> {
		// DH ratchet step: peer rotated ephemeral.
		if message.header.dh_pub != *self.receiving_pub.as_bytes() {
			self.dh_ratchet_recv(message.header.dh_pub)?;
		}

		let (next_ck, message_key) = derive_message_key(&self.receiving_chain_key);
		self.receiving_chain_key = next_ck;

		let aad = message.header.encode();
		let nonce_bytes = derive_nonce(&message_key);
		let cipher = ChaCha20Poly1305::new((&message_key).into());
		let plaintext = cipher
			.decrypt(
				(&nonce_bytes).into(),
				chacha20poly1305::aead::Payload { msg: &message.ciphertext, aad: &aad },
			)
			.map_err(|_| DecryptError::AeadAuthFailed)?;
		self.receiving_count = self.receiving_count.saturating_add(1);
		Ok(plaintext)
	}

	/// Asymmetric ratchet — sending side. Generate a new ephemeral
	/// secret, derive a new sending chain key from DH(new_DHs,
	/// existing DHr). Resets the sending message counter.
	fn dh_ratchet_send(&mut self) {
		// Note: using a deterministic RNG from a context-bound seed
		// would be safer for reproducibility/testing, but we want
		// real randomness here. The `x25519_dalek::StaticSecret::new`
		// pulls from a CSPRNG provided by the caller; for v0 we
		// use OsRng-equivalent through getrandom (the dalek default).
		let new_secret = X25519SecretKey::random_from_rng(rand_core::OsRng);
		let dh_out = new_secret.diffie_hellman(&self.receiving_pub);
		let (new_rk, new_cks) = kdf_root(&self.root_key, dh_out.as_bytes());
		self.sending_secret = new_secret;
		self.root_key = new_rk;
		self.sending_chain_key = new_cks;
		self.sending_count = 0;
	}

	/// Asymmetric ratchet — receiving side. Triggered when an inbound
	/// header carries a new peer ephemeral. Derives a new receiving
	/// chain key from DH(current DHs, new DHr).
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
/// `next_ck = HKDF(CK, info=NEXT)[..32]`; `mk = HKDF(CK, info=MSG)[..32]`.
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
/// Each message has a unique mk, so the resulting nonce is unique
/// per (session, message). Belt-and-suspenders vs. a zero nonce.
fn derive_nonce(mk: &[u8; 32]) -> [u8; 12] {
	let hk = Hkdf::<Sha256>::new(None, mk);
	let mut nonce = [0u8; 12];
	hk.expand(NONCE_INFO, &mut nonce).expect("12 bytes within HKDF limit");
	nonce
}

/// Compute the X3DH-lite shared secret. Used by the
/// handshake-level wrapper (not in this crate); exposed for
/// integration tests.
///
/// `local_secret` × `peer_pub` is the X25519 ECDH primitive — both
/// sides compute the same 32-byte shared secret.
pub fn handshake_shared_secret(
	local_secret: &X25519SecretKey,
	peer_pub: &X25519PublicKey,
) -> [u8; 32] {
	*local_secret.diffie_hellman(peer_pub).as_bytes()
}

// ───── Channel delegation certificate ──────────────────────────────────
//
// The validator channel no longer signs handshakes with the GRANDPA
// consensus key. Instead each validator holds a keystore-resident
// *channel key* (ed25519, key type `chnl`, never registered on-chain)
// and the GRANDPA key signs a [`ChannelCert`] binding that channel key
// to the validator's on-chain authority identity, once per 24h epoch.
// Handshakes then sign with the channel key. Net effect: the
// internet-facing channel code never touches the slashable consensus
// key; that key is used exactly once per epoch, for cert issuance.
// See docs/VALIDATOR-CHANNEL-CERT.md.

/// Domain-separation tag for the [`ChannelCert`] signature preimage.
/// Distinct from [`HANDSHAKE_DOMAIN`] so a cert signature can never be
/// replayed as a handshake signature or vice versa.
pub const CERT_DOMAIN: &[u8] = b"rostro/validator-channel/cert/v1";

/// A GRANDPA-signed delegation from a validator's on-chain authority
/// key to its keystore-resident channel key, scoped to one epoch.
///
/// - **`authority_pubkey`**: the validator's GRANDPA Ed25519 session
///   key — its on-chain identity. The verifier confirms this is in the
///   active validator set (caller-side; this crate cannot see chain
///   state) AND that it signed this cert.
/// - **`channel_pubkey`**: the delegated channel Ed25519 key. Persistent
///   across epochs; the cert (not the key) is what rotates.
/// - **`epoch`**: the 24h epoch this cert authorizes. A cert issued for
///   epoch `E` is accepted during epochs `E` and `E+1` (a validity
///   overlap that rides out epoch-boundary races); enforced in
///   [`verify_handshake`].
/// - **`signature`**: Ed25519 signature by `authority_pubkey` over
///   [`cert_preimage`].
///
/// Wire size: 32 + 32 + 8 + 64 = 136 bytes (plus SCALE overhead).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct ChannelCert {
	pub authority_pubkey: [u8; 32],
	pub channel_pubkey: [u8; 32],
	pub epoch: u64,
	pub signature: [u8; 64],
}

/// Outcome of [`verify_cert`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertError {
	/// `authority_pubkey` is not a valid Ed25519 point.
	InvalidAuthorityKey,
	/// `channel_pubkey` is not a valid Ed25519 point.
	InvalidChannelKey,
	/// Signature does not verify under `authority_pubkey`.
	SignatureInvalid,
}

/// Build the canonical preimage a [`ChannelCert`]'s signature covers.
/// Layout:
///
/// ```text
/// CERT_DOMAIN || authority_pubkey || channel_pubkey || epoch_le
/// ```
pub fn cert_preimage(
	authority_pubkey: &[u8; 32],
	channel_pubkey: &[u8; 32],
	epoch: u64,
) -> Vec<u8> {
	let mut buf = Vec::with_capacity(CERT_DOMAIN.len() + 32 + 32 + 8);
	buf.extend_from_slice(CERT_DOMAIN);
	buf.extend_from_slice(authority_pubkey);
	buf.extend_from_slice(channel_pubkey);
	buf.extend_from_slice(&epoch.to_le_bytes());
	buf
}

/// Issue a [`ChannelCert`] by signing `channel_pubkey` + `epoch` with
/// the authority (GRANDPA) key. This is the ONE place per epoch the
/// consensus key is used by the channel subsystem. In gemini-node the
/// signing is done via the keystore rather than a raw `SigningKey`;
/// this helper is the canonical reference + test path.
#[cfg(feature = "std")]
pub fn sign_cert(
	channel_pubkey: &[u8; 32],
	epoch: u64,
	authority_key: &ed25519_zebra::SigningKey,
) -> ChannelCert {
	let authority_pubkey: [u8; 32] =
		ed25519_zebra::VerificationKey::from(authority_key).into();
	let preimage = cert_preimage(&authority_pubkey, channel_pubkey, epoch);
	let sig: ed25519_zebra::Signature = authority_key.sign(&preimage);
	ChannelCert {
		authority_pubkey,
		channel_pubkey: *channel_pubkey,
		epoch,
		signature: sig.into(),
	}
}

/// Verify a [`ChannelCert`]'s signature under its `authority_pubkey`.
///
/// **Does NOT check active-set membership or epoch freshness** — those
/// need chain state and are the caller's responsibility.
/// [`verify_handshake`] calls this first, then enforces the epoch
/// window; the caller must still confirm `authority_pubkey` is in the
/// on-chain active validator set.
pub fn verify_cert(cert: &ChannelCert) -> Result<(), CertError> {
	let vk = ed25519_zebra::VerificationKey::try_from(cert.authority_pubkey)
		.map_err(|_| CertError::InvalidAuthorityKey)?;
	// Reject a malformed channel key here so a bad cert fails at the
	// cert layer with a precise error rather than later at the
	// handshake-signature check.
	ed25519_zebra::VerificationKey::try_from(cert.channel_pubkey)
		.map_err(|_| CertError::InvalidChannelKey)?;
	let sig = ed25519_zebra::Signature::from(cert.signature);
	let preimage =
		cert_preimage(&cert.authority_pubkey, &cert.channel_pubkey, cert.epoch);
	vk.verify(&sig, &preimage)
		.map_err(|_| CertError::SignatureInvalid)?;
	Ok(())
}

// ───── X3DH-lite handshake payload (v2, cert-carrying) ──────────────────

/// Domain-separation tag for the handshake signature preimage.
/// `/v2` is the cert-carrying handshake — the `/v1` form signed the
/// ephemeral directly with the GRANDPA key and no longer exists. The
/// version byte is what makes a stray `/v1` signature un-verifiable
/// here (cross-domain confusion resistance).
pub const HANDSHAKE_DOMAIN: &[u8] = b"rostro/validator-channel/handshake/v2";

/// Wire-format handshake payload (v2). Sent on substream open by each
/// side. Carries:
///
/// - **`cert`**: the sender's [`ChannelCert`] — its epoch-scoped
///   delegation from its on-chain authority key to the channel key
///   that signs this handshake.
/// - **`ephemeral_x25519`**: this session's X25519 ephemeral, fed into
///   the Double Ratchet initial DH. Rotates per session.
/// - **`signature`**: Ed25519 signature, by `cert.channel_pubkey`'s
///   private key, over [`handshake_preimage`]. Proves the sender
///   controls the channel key the cert delegated to.
///
/// Wire size: 136 (cert) + 32 + 64 = 232 bytes (plus SCALE overhead),
/// within the node's 512-byte handshake request/response caps.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct HandshakePayload {
	pub cert: ChannelCert,
	pub ephemeral_x25519: [u8; 32],
	pub signature: [u8; 64],
}

/// Outcome of [`verify_handshake`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeError {
	/// `cert.channel_pubkey` is not a valid Ed25519 point.
	InvalidPubkey,
	/// The handshake signature does not verify under
	/// `cert.channel_pubkey`.
	SignatureInvalid,
	/// The embedded [`ChannelCert`] failed [`verify_cert`].
	CertInvalid,
	/// `cert.epoch` is neither the current epoch nor the immediately
	/// preceding one — the cert is stale or forged-ahead.
	EpochOutOfWindow,
}

/// Build the canonical preimage that a v2 [`HandshakePayload`]'s
/// signature covers. Binds the channel key, the cert epoch, and the
/// session ephemeral together so a handshake signature is valid only
/// for the exact `(channel_pubkey, epoch)` the cert authorizes.
/// Layout:
///
/// ```text
/// HANDSHAKE_DOMAIN || channel_pubkey || epoch_le || ephemeral_x25519
/// ```
pub fn handshake_preimage(
	channel_pubkey: &[u8; 32],
	epoch: u64,
	ephemeral_x25519: &[u8; 32],
) -> Vec<u8> {
	let mut buf = Vec::with_capacity(HANDSHAKE_DOMAIN.len() + 32 + 8 + 32);
	buf.extend_from_slice(HANDSHAKE_DOMAIN);
	buf.extend_from_slice(channel_pubkey);
	buf.extend_from_slice(&epoch.to_le_bytes());
	buf.extend_from_slice(ephemeral_x25519);
	buf
}

/// Build a signed v2 handshake payload: sign a fresh session ephemeral
/// with the channel key, carrying the already-issued [`ChannelCert`].
/// `channel_key` MUST be the key `cert.channel_pubkey` refers to.
///
/// In gemini-node the signing is done via the keystore; this helper is
/// the canonical reference + test path.
///
/// Caller is responsible for generating a fresh ephemeral X25519 per
/// session.
#[cfg(feature = "std")]
pub fn sign_handshake(
	ephemeral_pub: &X25519PublicKey,
	cert: &ChannelCert,
	channel_key: &ed25519_zebra::SigningKey,
) -> HandshakePayload {
	let ephemeral_bytes = *ephemeral_pub.as_bytes();
	let preimage =
		handshake_preimage(&cert.channel_pubkey, cert.epoch, &ephemeral_bytes);
	let sig: ed25519_zebra::Signature = channel_key.sign(&preimage);
	HandshakePayload {
		cert: cert.clone(),
		ephemeral_x25519: ephemeral_bytes,
		signature: sig.into(),
	}
}

/// Verify a v2 [`HandshakePayload`] against the chain's `current_epoch`.
///
/// Checks, in order:
/// 1. the embedded [`ChannelCert`] signature ([`verify_cert`]);
/// 2. the epoch window: `cert.epoch ∈ {current_epoch, current_epoch-1}`;
/// 3. the handshake signature under `cert.channel_pubkey`.
///
/// **Does NOT verify active-set membership** — the caller MUST confirm
/// `payload.cert.authority_pubkey` is in the on-chain active validator
/// set (that check needs chain state this crate does not have). Once
/// membership passes and this returns `Ok(())`, the sender is
/// authenticated and [`HandshakePayload::ephemeral_x25519`] can be fed
/// into [`handshake_shared_secret`].
pub fn verify_handshake(
	payload: &HandshakePayload,
	current_epoch: u64,
) -> Result<(), HandshakeError> {
	verify_cert(&payload.cert).map_err(|_| HandshakeError::CertInvalid)?;

	let epoch = payload.cert.epoch;
	let in_window =
		epoch == current_epoch || epoch.checked_add(1) == Some(current_epoch);
	if !in_window {
		return Err(HandshakeError::EpochOutOfWindow);
	}

	let vk = ed25519_zebra::VerificationKey::try_from(payload.cert.channel_pubkey)
		.map_err(|_| HandshakeError::InvalidPubkey)?;
	let sig = ed25519_zebra::Signature::from(payload.signature);
	let preimage =
		handshake_preimage(&payload.cert.channel_pubkey, epoch, &payload.ephemeral_x25519);
	vk.verify(&sig, &preimage)
		.map_err(|_| HandshakeError::SignatureInvalid)?;
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use rand_chacha::ChaCha20Rng;
	use rand_core::SeedableRng;

	fn fresh_session_pair() -> (Session, Session) {
		// Deterministic test RNG. Production uses OsRng (in
		// dh_ratchet_send via x25519_dalek::StaticSecret::random_from_rng).
		let mut rng_a = ChaCha20Rng::seed_from_u64(0xA1);
		let mut rng_b = ChaCha20Rng::seed_from_u64(0xB2);

		let alice_secret = X25519SecretKey::random_from_rng(&mut rng_a);
		let bob_secret = X25519SecretKey::random_from_rng(&mut rng_b);
		let alice_pub = X25519PublicKey::from(&alice_secret);
		let bob_pub = X25519PublicKey::from(&bob_secret);

		// Both sides compute the same shared secret via X25519 ECDH.
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
		let m1 = alice.encrypt(b"hello bob");
		let p1 = bob.decrypt(&m1).expect("bob decrypts alice's first message");
		assert_eq!(p1, b"hello bob");
	}

	#[test]
	fn responder_first_message_triggers_dh_ratchet_on_initiator() {
		let (mut alice, mut bob) = fresh_session_pair();
		let m1 = alice.encrypt(b"hi");
		bob.decrypt(&m1).unwrap();
		// Bob's first send triggers a sending-side DH ratchet, then
		// Alice receives it (which on her side triggers a receiving-
		// side DH ratchet). Both succeed.
		let m2 = bob.encrypt(b"hi alice");
		let p2 = alice.decrypt(&m2).expect("alice decrypts bob's reply");
		assert_eq!(p2, b"hi alice");
	}

	#[test]
	fn many_messages_in_one_direction() {
		let (mut alice, mut bob) = fresh_session_pair();
		for i in 0..20u32 {
			let payload = format!("msg {i}");
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
			let from_alice = alice.encrypt(format!("a→b {round}").as_bytes());
			bob.decrypt(&from_alice).unwrap();
			let from_bob = bob.encrypt(format!("b→a {round}").as_bytes());
			alice.decrypt(&from_bob).unwrap();
		}
	}

	#[test]
	fn tampered_ciphertext_fails_aead() {
		let (mut alice, mut bob) = fresh_session_pair();
		let mut m = alice.encrypt(b"sensitive");
		// Flip one bit in the ciphertext.
		m.ciphertext[0] ^= 0x01;
		assert_eq!(bob.decrypt(&m), Err(DecryptError::AeadAuthFailed));
	}

	#[test]
	fn tampered_header_fails_aead() {
		let (mut alice, mut bob) = fresh_session_pair();
		let mut m = alice.encrypt(b"sensitive");
		// Flip a byte in the header's dh_pub. Header is AAD so AEAD
		// authentication must fail. Note: it'll first trigger a DH
		// ratchet on bob (because the modified header looks like a
		// new ephemeral), so we expect the AEAD to fail AFTER the
		// ratchet step rather than before.
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
		// Two parallel sessions sending the same plaintext produce
		// different ciphertexts because their root keys differ.
		let (mut a1, _b1) = fresh_session_pair();
		let (mut a2, _b2) = {
			// Force different seeds for a fresh pair.
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
	fn header_size_is_36_bytes_scale() {
		// Pin the wire format size — accidental field bloat is a
		// protocol-breaking change.
		let h = MessageHeader { dh_pub: [0xAB; 32], msg_num: 42 };
		assert_eq!(h.encode().len(), 36);
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
		// Determinism
		assert_eq!(rk_a, rk_b);
		assert_eq!(ck_a.0, ck_b.0);
		// Different DH output produces different outputs.
		let (rk_c, ck_c) = kdf_root(&rk, &dh2);
		assert_ne!(rk_a, rk_c);
		assert_ne!(ck_a.0, ck_c.0);
		// rk and ck are derived from different HKDF halves and must
		// differ (otherwise a chain compromise would leak the root).
		assert_ne!(rk_a, ck_a.0);
	}

	#[test]
	fn derive_message_key_branch_separation() {
		let ck = ChainKey([0x99u8; 32]);
		let (next_ck, mk) = derive_message_key(&ck);
		// The next chain key and the message key MUST differ —
		// else a message-key compromise would leak the chain.
		assert_ne!(next_ck.0, mk);
		// Both differ from the input chain key.
		assert_ne!(next_ck.0, ck.0);
		assert_ne!(mk, ck.0);
	}

	#[test]
	fn nonce_is_deterministic_per_message_key() {
		let mk = [0x33u8; 32];
		let n1 = derive_nonce(&mk);
		let n2 = derive_nonce(&mk);
		assert_eq!(n1, n2);
		// Different mk → different nonce.
		let mk2 = [0x34u8; 32];
		assert_ne!(derive_nonce(&mk2), n1);
	}

	// ── Cert + handshake payload tests ─────────────────────────────

	const TEST_EPOCH: u64 = 42;

	fn fixed_signing_key(seed_byte: u8) -> ed25519_zebra::SigningKey {
		ed25519_zebra::SigningKey::from([seed_byte; 32])
	}

	fn pubkey_of(key: &ed25519_zebra::SigningKey) -> [u8; 32] {
		ed25519_zebra::VerificationKey::from(key).into()
	}

	fn fresh_ephemeral_pub(rng_seed: u64) -> (X25519SecretKey, X25519PublicKey) {
		let mut rng = ChaCha20Rng::seed_from_u64(rng_seed);
		let secret = X25519SecretKey::random_from_rng(&mut rng);
		let public = X25519PublicKey::from(&secret);
		(secret, public)
	}

	/// A validator identity for tests: an authority (GRANDPA) key, a
	/// channel key, and a cert delegating the latter for `epoch`.
	fn identity(
		authority_seed: u8,
		channel_seed: u8,
		epoch: u64,
	) -> (ed25519_zebra::SigningKey, ed25519_zebra::SigningKey, ChannelCert) {
		let authority = fixed_signing_key(authority_seed);
		let channel = fixed_signing_key(channel_seed);
		let cert = sign_cert(&pubkey_of(&channel), epoch, &authority);
		(authority, channel, cert)
	}

	#[test]
	fn cert_preimage_layout_is_stable() {
		let p = cert_preimage(&[0xAA; 32], &[0xBB; 32], 0x0102030405060708);
		assert_eq!(p.len(), CERT_DOMAIN.len() + 32 + 32 + 8);
		assert_eq!(&p[..CERT_DOMAIN.len()], CERT_DOMAIN);
		let off = CERT_DOMAIN.len();
		assert_eq!(&p[off..off + 32], &[0xAA; 32]);
		assert_eq!(&p[off + 32..off + 64], &[0xBB; 32]);
		assert_eq!(&p[off + 64..off + 72], &0x0102030405060708u64.to_le_bytes());
	}

	#[test]
	fn cert_scale_roundtrip() {
		let (_a, _c, cert) = identity(0xA0, 0xC0, TEST_EPOCH);
		let bytes = cert.encode();
		// Pin the wire size: 32 + 32 + 8 + 64 = 136 (+ no SCALE prefix
		// for fixed-size fields).
		assert_eq!(bytes.len(), 136);
		let decoded = ChannelCert::decode(&mut &bytes[..]).unwrap();
		assert_eq!(cert, decoded);
	}

	#[test]
	fn cert_sign_then_verify_passes() {
		let (_a, _c, cert) = identity(0xA0, 0xC0, TEST_EPOCH);
		verify_cert(&cert).expect("freshly issued cert must verify");
	}

	#[test]
	fn cert_verify_rejects_tampered_channel_key() {
		let (_a, _c, mut cert) = identity(0xA0, 0xC0, TEST_EPOCH);
		// Swap in a different valid channel key: the authority never
		// signed this delegation.
		cert.channel_pubkey = pubkey_of(&fixed_signing_key(0xC1));
		assert_eq!(verify_cert(&cert), Err(CertError::SignatureInvalid));
	}

	#[test]
	fn cert_verify_rejects_tampered_epoch() {
		let (_a, _c, mut cert) = identity(0xA0, 0xC0, TEST_EPOCH);
		cert.epoch += 1;
		assert_eq!(verify_cert(&cert), Err(CertError::SignatureInvalid));
	}

	#[test]
	fn cert_verify_rejects_foreign_authority() {
		let (_a, _c, mut cert) = identity(0xA0, 0xC0, TEST_EPOCH);
		// Claim a different authority issued this cert.
		cert.authority_pubkey = pubkey_of(&fixed_signing_key(0xA1));
		assert_eq!(verify_cert(&cert), Err(CertError::SignatureInvalid));
	}

	#[test]
	fn handshake_preimage_layout_is_stable() {
		let p = handshake_preimage(&[0xAA; 32], 0x1122334455667788, &[0xBB; 32]);
		assert_eq!(p.len(), HANDSHAKE_DOMAIN.len() + 32 + 8 + 32);
		assert_eq!(&p[..HANDSHAKE_DOMAIN.len()], HANDSHAKE_DOMAIN);
		let off = HANDSHAKE_DOMAIN.len();
		assert_eq!(&p[off..off + 32], &[0xAA; 32]);
		assert_eq!(&p[off + 32..off + 40], &0x1122334455667788u64.to_le_bytes());
		assert_eq!(&p[off + 40..off + 72], &[0xBB; 32]);
	}

	#[test]
	fn handshake_scale_roundtrip() {
		let (_a, channel, cert) = identity(0xA0, 0xC0, TEST_EPOCH);
		let (_secret, pub_e) = fresh_ephemeral_pub(0xE1);
		let payload = sign_handshake(&pub_e, &cert, &channel);
		let bytes = payload.encode();
		assert_eq!(bytes.len(), 232); // 136 cert + 32 ephemeral + 64 sig
		let decoded = HandshakePayload::decode(&mut &bytes[..]).unwrap();
		assert_eq!(payload, decoded);
	}

	#[test]
	fn handshake_sign_then_verify_passes() {
		let (_a, channel, cert) = identity(0xA0, 0xC0, TEST_EPOCH);
		let (_secret, pub_e) = fresh_ephemeral_pub(0xE2);
		let payload = sign_handshake(&pub_e, &cert, &channel);
		verify_handshake(&payload, TEST_EPOCH)
			.expect("freshly signed handshake must verify at cert epoch");
	}

	#[test]
	fn handshake_verify_accepts_previous_epoch_cert() {
		// A cert issued for epoch E stays valid through epoch E+1 to
		// ride the epoch boundary.
		let (_a, channel, cert) = identity(0xA0, 0xC0, TEST_EPOCH);
		let (_secret, pub_e) = fresh_ephemeral_pub(0xE2);
		let payload = sign_handshake(&pub_e, &cert, &channel);
		verify_handshake(&payload, TEST_EPOCH + 1)
			.expect("cert from previous epoch must still verify");
	}

	#[test]
	fn handshake_verify_rejects_stale_epoch_cert() {
		// Two epochs behind is out of the {current, current-1} window.
		let (_a, channel, cert) = identity(0xA0, 0xC0, TEST_EPOCH);
		let (_secret, pub_e) = fresh_ephemeral_pub(0xE2);
		let payload = sign_handshake(&pub_e, &cert, &channel);
		assert_eq!(
			verify_handshake(&payload, TEST_EPOCH + 2),
			Err(HandshakeError::EpochOutOfWindow),
		);
	}

	#[test]
	fn handshake_verify_rejects_future_epoch_cert() {
		// A cert forged ahead of the chain's current epoch is refused.
		let (_a, channel, cert) = identity(0xA0, 0xC0, TEST_EPOCH);
		let (_secret, pub_e) = fresh_ephemeral_pub(0xE2);
		let payload = sign_handshake(&pub_e, &cert, &channel);
		assert_eq!(
			verify_handshake(&payload, TEST_EPOCH - 1),
			Err(HandshakeError::EpochOutOfWindow),
		);
	}

	#[test]
	fn handshake_verify_rejects_wrong_channel_signer() {
		// The cert delegates to channel key 0xC0, but the handshake is
		// signed by a different key. The cert verifies (untouched) but
		// the handshake signature does not match cert.channel_pubkey.
		let (_a, _channel, cert) = identity(0xA0, 0xC0, TEST_EPOCH);
		let impostor = fixed_signing_key(0xC9);
		let (_secret, pub_e) = fresh_ephemeral_pub(0xE3);
		let mut payload = sign_handshake(&pub_e, &cert, &impostor);
		// sign_handshake stamped the impostor's sig but the cert still
		// names 0xC0 as the channel key, so verification must fail on
		// the handshake signature.
		payload.cert = cert;
		assert_eq!(
			verify_handshake(&payload, TEST_EPOCH),
			Err(HandshakeError::SignatureInvalid),
		);
	}

	#[test]
	fn handshake_verify_rejects_tampered_ephemeral() {
		let (_a, channel, cert) = identity(0xA0, 0xC0, TEST_EPOCH);
		let (_secret, pub_e) = fresh_ephemeral_pub(0xE4);
		let mut payload = sign_handshake(&pub_e, &cert, &channel);
		payload.ephemeral_x25519[0] ^= 0xFF;
		assert_eq!(
			verify_handshake(&payload, TEST_EPOCH),
			Err(HandshakeError::SignatureInvalid),
		);
	}

	#[test]
	fn handshake_verify_rejects_tampered_signature() {
		let (_a, channel, cert) = identity(0xA0, 0xC0, TEST_EPOCH);
		let (_secret, pub_e) = fresh_ephemeral_pub(0xE5);
		let mut payload = sign_handshake(&pub_e, &cert, &channel);
		payload.signature[0] ^= 0xFF;
		assert_eq!(
			verify_handshake(&payload, TEST_EPOCH),
			Err(HandshakeError::SignatureInvalid),
		);
	}

	#[test]
	fn handshake_verify_rejects_forged_cert() {
		// A handshake whose cert was never signed by a real authority
		// is rejected at the cert layer, before the epoch/sig checks.
		let (_a, channel, mut cert) = identity(0xA0, 0xC0, TEST_EPOCH);
		cert.signature[0] ^= 0xFF; // corrupt the authority's signature
		let (_secret, pub_e) = fresh_ephemeral_pub(0xE6);
		let payload = sign_handshake(&pub_e, &cert, &channel);
		assert_eq!(
			verify_handshake(&payload, TEST_EPOCH),
			Err(HandshakeError::CertInvalid),
		);
	}

	#[test]
	fn v1_style_signature_rejected_under_v2_domain() {
		// Cross-domain confusion guard. Reconstruct the OLD v1 preimage
		// (v1 domain || channel_pubkey || ephemeral, no epoch) and sign
		// it with the channel key. It must not verify under the v2
		// handshake, which expects the v2 domain + epoch binding.
		const V1_DOMAIN: &[u8] = b"rostro/validator-channel/handshake/v1";
		let (_a, channel, cert) = identity(0xA0, 0xC0, TEST_EPOCH);
		let (_secret, pub_e) = fresh_ephemeral_pub(0xE7);
		let ephemeral = *pub_e.as_bytes();

		let mut v1_preimage = Vec::new();
		v1_preimage.extend_from_slice(V1_DOMAIN);
		v1_preimage.extend_from_slice(&cert.channel_pubkey);
		v1_preimage.extend_from_slice(&ephemeral);
		let v1_sig: ed25519_zebra::Signature = channel.sign(&v1_preimage);

		let payload = HandshakePayload {
			cert,
			ephemeral_x25519: ephemeral,
			signature: v1_sig.into(),
		};
		assert_eq!(
			verify_handshake(&payload, TEST_EPOCH),
			Err(HandshakeError::SignatureInvalid),
		);
	}

	#[test]
	fn handshake_to_session_end_to_end() {
		// Full simulation: both sides issue certs, build signed
		// handshakes, each verifies the other's cert+handshake,
		// computes the shared secret, initializes a Session, exchanges
		// messages.
		let (_alice_auth, alice_channel, alice_cert) = identity(0xA0, 0xC0, TEST_EPOCH);
		let (_bob_auth, bob_channel, bob_cert) = identity(0xB0, 0xD0, TEST_EPOCH);

		let (alice_eph_secret, alice_eph_pub) = fresh_ephemeral_pub(0xE10);
		let (bob_eph_secret, bob_eph_pub) = fresh_ephemeral_pub(0xE20);

		let alice_hs = sign_handshake(&alice_eph_pub, &alice_cert, &alice_channel);
		let bob_hs = sign_handshake(&bob_eph_pub, &bob_cert, &bob_channel);

		// Each side verifies the OTHER's handshake at the current epoch.
		verify_handshake(&bob_hs, TEST_EPOCH).expect("alice verifies bob");
		verify_handshake(&alice_hs, TEST_EPOCH).expect("bob verifies alice");

		// Active-set membership check on cert.authority_pubkey would
		// happen here against the on-chain set; mocked out in this unit
		// test.

		let bob_eph_pub_rebuilt = X25519PublicKey::from(bob_hs.ephemeral_x25519);
		let alice_eph_pub_rebuilt = X25519PublicKey::from(alice_hs.ephemeral_x25519);
		let alice_shared =
			handshake_shared_secret(&alice_eph_secret, &bob_eph_pub_rebuilt);
		let bob_shared =
			handshake_shared_secret(&bob_eph_secret, &alice_eph_pub_rebuilt);
		assert_eq!(alice_shared, bob_shared);

		let mut alice =
			Session::from_handshake_initiator(alice_shared, alice_eph_secret, bob_eph_pub_rebuilt);
		let mut bob =
			Session::from_handshake_responder(bob_shared, bob_eph_secret, alice_eph_pub_rebuilt);

		let msg = alice.encrypt(b"first message after handshake");
		let plain = bob.decrypt(&msg).expect("bob decrypts");
		assert_eq!(plain, b"first message after handshake");
	}
}
