// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Pairwise Double Ratchet session.
//!
//! A [`Session`] tracks both a sending chain and a receiving chain
//! between two peers, plus an unbounded-but-capped cache of skipped
//! receiving keys for out-of-order delivery.
//!
//! Caller responsibilities:
//! - Provide an initial 32-byte shared secret (the "root key seed"),
//!   established out of band — X3DH-style bootstrap is not in v0.
//! - For the initiator side, also provide the responder's current DH
//!   public key.
//! - Pass a `RngCore + CryptoRng` into `decrypt` so the session can
//!   generate fresh ratchet keypairs when the peer triggers a DH step.
//!
//! The session is in-memory only at v0; no serialize/deserialize.

use crate::kdf::{kdf_ck, kdf_msg, kdf_rk, Secret32};
use crate::ratchet::{aead_associated_data, Header, OutboundMessage, MAX_SKIP, MAX_SKIPPED_CACHE};

use chacha20poly1305::{
	aead::{Aead, KeyInit, Payload},
	ChaCha20Poly1305, Key, Nonce,
};
use rand_core::{CryptoRng, RngCore};
use std::collections::BTreeMap;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

/// Errors a session can produce.
#[derive(Debug, Error)]
pub enum Error {
	/// AEAD decryption failed — wrong key, modified ciphertext, or
	/// modified header (which is folded into AD).
	#[error("AEAD decryption failed; ciphertext or header was tampered with")]
	AeadFailed,
	/// Header advanced more than `MAX_SKIP` messages on the current
	/// receiving chain. Either a peer fault, a peer attempting to
	/// exhaust our memory, or honest extreme drop — drop the session.
	#[error("message advances more than MAX_SKIP={MAX_SKIP} on current receiving chain")]
	TooManySkipped,
	/// Total skipped-key cache exceeded `MAX_SKIPPED_CACHE` across all
	/// receiving chains. Bound on session-wide memory.
	#[error("skipped-key cache exceeded MAX_SKIPPED_CACHE={MAX_SKIPPED_CACHE} entries")]
	SkippedCacheFull,
	/// Sending or receiving chain counter overflow. u32::MAX messages
	/// in a single chain is well past any honest workload; treat as
	/// session-fatal.
	#[error("ratchet message counter overflowed u32")]
	CounterOverflow,
	/// Session state was inconsistent for the requested operation.
	/// Currently only thrown if `encrypt` is called on a Bob session
	/// before any inbound message has populated `CKs`.
	#[error("session not yet ready to {0}")]
	NotReady(&'static str),
}

/// Pairwise Double Ratchet session state.
///
/// One per peer pair. Not thread-safe — wrap externally if needed.
pub struct Session {
	/// Own ratchet DH keypair (`DHs`).
	dhs: StaticSecret,
	/// Cached own DH public — saves repeated derivation in `encrypt`.
	dhs_public: PublicKey,
	/// Peer's current ratchet DH public (`DHr`). `None` until the first
	/// inbound message bootstraps the receiving chain (Bob path).
	dhr: Option<PublicKey>,
	/// Root key (`RK`).
	rk: Secret32,
	/// Sending chain key (`CKs`). `None` until our own first DH ratchet
	/// step has run (Bob before first inbound).
	cks: Option<Secret32>,
	/// Receiving chain key (`CKr`). `None` until the first DH ratchet
	/// step has populated it.
	ckr: Option<Secret32>,
	/// Sending message counter (`Ns`).
	ns: u32,
	/// Receiving message counter (`Nr`).
	nr: u32,
	/// Length of the previous sending chain (`PN`).
	pn: u32,
	/// Skipped receiving keys, keyed by (peer_dh_pub_bytes, n).
	mkskipped: BTreeMap<([u8; 32], u32), Secret32>,
}

impl Session {
	/// Initialize the side that initiates communication. The caller
	/// already knows the responder's DH public key (out-of-band).
	///
	/// After init the session has a sending chain (`CKs`) ready, and no
	/// receiving chain yet — the first inbound message will trigger a
	/// DH ratchet that derives `CKr`.
	pub fn initialize_alice<R: RngCore + CryptoRng>(
		rng: &mut R,
		shared_secret: [u8; 32],
		peer_dh_pub: [u8; 32],
	) -> Self {
		let dhs = StaticSecret::random_from_rng(&mut *rng);
		let dhs_public = PublicKey::from(&dhs);
		let dhr = PublicKey::from(peer_dh_pub);
		let dh_out = dhs.diffie_hellman(&dhr);

		let rk_seed = Secret32::new(shared_secret);
		let (rk, cks) = kdf_rk(&rk_seed, dh_out.as_bytes());

		Self {
			dhs,
			dhs_public,
			dhr: Some(dhr),
			rk,
			cks: Some(cks),
			ckr: None,
			ns: 0,
			nr: 0,
			pn: 0,
			mkskipped: BTreeMap::new(),
		}
	}

	/// Initialize the responder side. The caller supplies the same
	/// shared secret and the DH keypair whose public key was already
	/// published to the initiator.
	///
	/// After init the session has neither sending nor receiving chain
	/// keys; both come online when the first inbound message arrives.
	pub fn initialize_bob(shared_secret: [u8; 32], dhs: StaticSecret) -> Self {
		let dhs_public = PublicKey::from(&dhs);
		Self {
			dhs,
			dhs_public,
			dhr: None,
			rk: Secret32::new(shared_secret),
			cks: None,
			ckr: None,
			ns: 0,
			nr: 0,
			pn: 0,
			mkskipped: BTreeMap::new(),
		}
	}

	/// Own ratchet DH public key — the value the peer should embed in
	/// header.dh on outbound messages until they see ours rotate.
	pub fn dh_public(&self) -> [u8; 32] {
		*self.dhs_public.as_bytes()
	}

	/// Encrypt a plaintext + caller-supplied associated data.
	///
	/// Bob can't encrypt until he's processed at least one inbound
	/// message (his `CKs` is None until DHRatchet runs); call sites
	/// that hit `Error::NotReady("encrypt")` should wait for the first
	/// message from Alice.
	pub fn encrypt(&mut self, plaintext: &[u8], ad: &[u8]) -> Result<OutboundMessage, Error> {
		let cks = self.cks.as_ref().ok_or(Error::NotReady("encrypt"))?;
		let (mk, next_cks) = kdf_ck(cks);
		self.cks = Some(next_cks);

		let header = Header { dh_pubkey: self.dh_public(), pn: self.pn, n: self.ns };
		self.ns = self.ns.checked_add(1).ok_or(Error::CounterOverflow)?;

		let (key, nonce_bytes) = kdf_msg(&mk);
		let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
		let nonce = Nonce::from_slice(&nonce_bytes);
		let aad = aead_associated_data(ad, &header);
		let ciphertext = cipher
			.encrypt(nonce, Payload { msg: plaintext, aad: &aad })
			.map_err(|_| Error::AeadFailed)?;

		Ok(OutboundMessage { header, ciphertext })
	}

	/// Decrypt an inbound message. Performs the DH ratchet step if the
	/// header carries a new `dh_pubkey`, and pre-derives skipped keys
	/// to handle out-of-order receipt within or across chains.
	pub fn decrypt<R: RngCore + CryptoRng>(
		&mut self,
		rng: &mut R,
		header: &Header,
		ciphertext: &[u8],
		ad: &[u8],
	) -> Result<Vec<u8>, Error> {
		// Fast path: this might be a previously skipped key.
		if let Some(plaintext) = self.try_skipped(header, ciphertext, ad)? {
			return Ok(plaintext);
		}

		// New peer DH pub means a DH ratchet step. We first skip up to
		// pn on the *current* (about-to-retire) receiving chain, then
		// rotate, then skip up to n on the new receiving chain.
		let header_pub = PublicKey::from(header.dh_pubkey);
		let dh_changed = match self.dhr {
			Some(current) => current.as_bytes() != header_pub.as_bytes(),
			None => true,
		};
		if dh_changed {
			self.skip_message_keys(header.pn)?;
			self.dh_ratchet(rng, &header_pub);
		}

		self.skip_message_keys(header.n)?;

		// Derive the message key for this message and advance CKr.
		let ckr = self.ckr.as_ref().ok_or(Error::NotReady("decrypt"))?;
		let (mk, next_ckr) = kdf_ck(ckr);
		self.ckr = Some(next_ckr);
		self.nr = self.nr.checked_add(1).ok_or(Error::CounterOverflow)?;

		Self::aead_open(&mk, header, ciphertext, ad)
	}

	/// Look up `(header.dh_pubkey, header.n)` in the skipped-key cache.
	/// On hit, decrypt and remove the entry.
	fn try_skipped(
		&mut self,
		header: &Header,
		ciphertext: &[u8],
		ad: &[u8],
	) -> Result<Option<Vec<u8>>, Error> {
		let key = (header.dh_pubkey, header.n);
		if let Some(mk) = self.mkskipped.remove(&key) {
			let plaintext = Self::aead_open(&mk, header, ciphertext, ad)?;
			return Ok(Some(plaintext));
		}
		Ok(None)
	}

	/// Advance `CKr` up to (but not including) `until`, banking each
	/// derived message key in `mkskipped`. Refuses to advance beyond
	/// `MAX_SKIP` per chain or beyond `MAX_SKIPPED_CACHE` total.
	fn skip_message_keys(&mut self, until: u32) -> Result<(), Error> {
		// If until is in the past or equal, nothing to skip.
		if until <= self.nr {
			return Ok(());
		}
		// Per-chain skip distance bound — protects against a peer
		// claiming `n = u32::MAX` to force ~4B HMAC iterations.
		if until - self.nr > MAX_SKIP {
			return Err(Error::TooManySkipped);
		}

		let dhr_bytes = match self.dhr {
			Some(pk) => *pk.as_bytes(),
			// No CKr yet means nothing to skip and a None DHr — nothing
			// to bank against. Leave Nr where it is; the upcoming DH
			// ratchet will reset it anyway.
			None => return Ok(()),
		};

		if self.ckr.is_none() {
			return Ok(());
		}

		while self.nr < until {
			if self.mkskipped.len() >= MAX_SKIPPED_CACHE {
				return Err(Error::SkippedCacheFull);
			}
			let ckr = self.ckr.as_ref().expect("checked is_some above; qed");
			let (mk, next_ckr) = kdf_ck(ckr);
			self.ckr = Some(next_ckr);
			self.mkskipped.insert((dhr_bytes, self.nr), mk);
			self.nr = self.nr.checked_add(1).ok_or(Error::CounterOverflow)?;
		}
		Ok(())
	}

	/// One DH ratchet step. Derives a fresh `CKr` against the peer's
	/// new DH pub, generates a new own DH keypair, then derives a fresh
	/// `CKs` against the same peer pub. Resets per-chain counters; the
	/// previous sending chain length is captured into `PN`.
	fn dh_ratchet<R: RngCore + CryptoRng>(&mut self, rng: &mut R, peer: &PublicKey) {
		self.pn = self.ns;
		self.ns = 0;
		self.nr = 0;
		self.dhr = Some(*peer);

		let dh1 = self.dhs.diffie_hellman(peer);
		let (rk1, ckr) = kdf_rk(&self.rk, dh1.as_bytes());
		self.rk = rk1;
		self.ckr = Some(ckr);

		let new_dhs = StaticSecret::random_from_rng(&mut *rng);
		self.dhs_public = PublicKey::from(&new_dhs);
		self.dhs = new_dhs;

		let dh2 = self.dhs.diffie_hellman(peer);
		let (rk2, cks) = kdf_rk(&self.rk, dh2.as_bytes());
		self.rk = rk2;
		self.cks = Some(cks);
	}

	/// AEAD-open helper. Folds the header into associated data exactly
	/// the way `encrypt` did, so any header-tampering surfaces as a
	/// failed open.
	fn aead_open(
		mk: &Secret32,
		header: &Header,
		ciphertext: &[u8],
		ad: &[u8],
	) -> Result<Vec<u8>, Error> {
		let (key, nonce_bytes) = kdf_msg(mk);
		let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
		let nonce = Nonce::from_slice(&nonce_bytes);
		let aad = aead_associated_data(ad, header);
		cipher
			.decrypt(nonce, Payload { msg: ciphertext, aad: &aad })
			.map_err(|_| Error::AeadFailed)
	}
}
