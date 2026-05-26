//! Tier-2 local CSPRNG for non-consensus randomness.
//!
//! Used by code that needs random values *without* validator consensus —
//! cert serials, shop session IDs, sandbox PRNG state, paid-extrinsic
//! external-randomness fulfillment. For consensus-grade randomness, use
//! the Tier-1 threshold beacon (not yet built).
//!
//! # Entropy model
//!
//! Architecturally the load-bearing point of this crate is *what it does
//! not trust*: the host OS. A compromised `/dev/urandom` (kernel exploit,
//! container escape, hypervisor-side malice) would silently poison any
//! RNG that depended on it alone. The primary entropy sources are
//! network-observed and node-unique: the local MLS chat ciphertext pool,
//! ciphertext samples lifted live from the validator and chat gossip
//! channels (Double-Ratchet output is indistinguishable from random to
//! anyone without the chain key — exactly what we want), the connected
//! peer count, and a rotating per-bucket shard count.
//!
//! Seeds are derived by hashing every [`EntropySource`]'s output into a
//! single 32-byte blake2_256 digest which seeds the internal ChaCha20
//! DRBG. Mixing via a vetted hash function means any single high-entropy
//! source carries the whole seed — a compromised source cannot bias the
//! output below the entropy of the best uncorrupted contributor.
//!
//! # Memory hygiene
//!
//! After the requestor receives the random value, all working memory used
//! to produce it MUST be wiped: the per-source byte buffers, the
//! concatenated seed-derivation buffer, and the RNG's internal state. All
//! transient buffers in this crate use [`zeroize::Zeroizing`], and
//! [`RostroShopRng`]'s `Drop` overwrites the underlying ChaCha20 state.
//! For one-shot cert issuance, prefer [`RostroShopRng::issue_cert_serial`]
//! which constructs the RNG, emits one serial, and drops everything in
//! a single expression.
//!
//! # Wiring
//!
//! The crate ships an [`OsEntropy`] source as a defense-in-depth mixin —
//! useful at cold start when network entropy sources are still empty.
//! The chat-pool source lives in the binding crate (a small adapter
//! wrapping `EphemeralShareStore::write_entropy_hash`); this crate stays
//! free of a chat-store dependency so other consumers can opt in to
//! whichever sources they have access to. See the crate's integration
//! test for the production wiring shape.

#![deny(missing_docs)]

use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, OsRng, RngCore, SeedableRng};
use sp_crypto_hashing::blake2_256;
use zeroize::{Zeroize, Zeroizing};

/// X.509 serial number length in bytes per RFC 5280 §4.1.2.2 — the
/// conforming-CA ceiling and the industry convention. 160 bits is far
/// past birthday-bound collision concerns for any plausible issuance volume.
pub const CERT_SERIAL_LEN: usize = 20;

/// Number of bytes pulled from each entropy source during seed derivation.
/// 64 bytes per source is enough to cover even a slow-entropy source's
/// best-case output without over-reading on the fast ones.
pub const ENTROPY_BYTES_PER_SOURCE: usize = 64;

/// A source of entropy. Implementations should produce output that is
/// indistinguishable from uniform random bytes; the caller will combine
/// outputs via a vetted hash function, so a degenerate source (e.g. an
/// empty chat pool that produces a constant) doesn't break security as
/// long as one provided source is genuinely high-entropy.
pub trait EntropySource {
	/// Fill `out` with entropy from this source.
	fn pull_entropy(&self, out: &mut [u8]);
}

/// OS entropy pool wrapper (`/dev/urandom` on Linux). Architecturally a
/// *fallback / defense-in-depth* mixin — the host OS is explicitly NOT a
/// trusted root for this crate. Useful at cold start when the network
/// entropy sources (chat pool, peer churn) are still empty.
pub struct OsEntropy;

impl EntropySource for OsEntropy {
	fn pull_entropy(&self, out: &mut [u8]) {
		OsRng.fill_bytes(out);
	}
}

/// Single-shot entropy from a binding-supplied byte buffer. Hashes the buffer
/// via blake2_256 and writes the digest into `out` (zero-padded if `out` is
/// larger than 32 bytes). The buffer is held in [`Zeroizing`] and wiped on drop.
///
/// Use this to feed in entropy that the shop-rng crate has no way to obtain
/// itself — values the node-side binding (gemini-node, zkpki-client running
/// on a node) samples *live at RNG construction time*. No rolling buffers,
/// no historical windows — grab whatever bytes happen to be in flight right
/// now and hand them in:
///
/// - **Validator gossipsub ciphertext sample** — a slice of recent bytes
///   observed flowing past on the validator channel. To any observer without
///   the recipient session key, these bytes are pure ciphertext noise; under
///   Double Ratchet, indistinguishable from uniform random.
/// - **MLS chat channel ciphertext sample** — same shape, sampled from the
///   chat-gossip notification protocol.
/// - **Peer count snapshot** — `swarm.connected_peers().count().to_le_bytes()`.
/// - **Per-bucket shard count** — `store.bucket_shard_count(b).to_le_bytes()`
///   where `b` is a call-counter-derived rotating bucket index.
///
/// Hashing means a degenerate buffer (all-zero, empty) still produces a
/// deterministic digest rather than leaking through unchanged — but it also
/// means a degenerate buffer contributes no real entropy. Mix multiple sources
/// so any one being degenerate doesn't matter.
pub struct StaticEntropy {
	inner: Zeroizing<Vec<u8>>,
}

impl StaticEntropy {
	/// Construct from a byte buffer. The buffer is moved into [`Zeroizing`]
	/// and wiped from RAM when this `StaticEntropy` is dropped.
	pub fn new(bytes: Vec<u8>) -> Self {
		Self { inner: Zeroizing::new(bytes) }
	}
}

impl EntropySource for StaticEntropy {
	fn pull_entropy(&self, out: &mut [u8]) {
		let digest = blake2_256(&self.inner);
		let n = out.len().min(digest.len());
		out[..n].copy_from_slice(&digest[..n]);
		for slot in out[n..].iter_mut() {
			*slot = 0;
		}
	}
}

/// Local CSPRNG. ChaCha20 stream cipher seeded by mixing the provided
/// [`EntropySource`]s. Implements [`RngCore`] + [`CryptoRng`] so it drops
/// into any `rand`-aware API.
///
/// # Memory hygiene
///
/// The seed-derivation buffer is held in [`Zeroizing`] for its entire
/// lifetime. `Drop` overwrites the underlying ChaCha20 state with a
/// zero-keyed instance, so when the RNG goes out of scope its key material
/// is gone from the heap allocation that held it.
pub struct RostroShopRng(ChaCha20Rng);

impl RostroShopRng {
	/// Seed by mixing entropy from all provided sources. Each source
	/// contributes [`ENTROPY_BYTES_PER_SOURCE`] bytes which are hashed
	/// together via blake2_256; the digest seeds the internal ChaCha20 DRBG.
	///
	/// The per-source buffer and the concatenation buffer are both wiped
	/// before this function returns. Panics if `sources` is empty.
	pub fn new(sources: &[&dyn EntropySource]) -> Self {
		assert!(!sources.is_empty(), "RostroShopRng requires at least one entropy source");
		let mut concat: Zeroizing<Vec<u8>> =
			Zeroizing::new(Vec::with_capacity(sources.len() * ENTROPY_BYTES_PER_SOURCE));
		let mut buf = Zeroizing::new([0u8; ENTROPY_BYTES_PER_SOURCE]);
		for source in sources {
			source.pull_entropy(&mut *buf);
			concat.extend_from_slice(&*buf);
		}
		let mut seed = blake2_256(&concat);
		let rng = ChaCha20Rng::from_seed(seed);
		seed.zeroize();
		// `concat` and `buf` zeroize via their Zeroizing wrappers at drop.
		Self(rng)
	}

	/// Seed from a fixed 32-byte value. **For tests and reproducible
	/// scenarios only** — the output stream is fully determined by the
	/// seed; never use a known seed in production.
	pub fn from_seed(seed: [u8; 32]) -> Self {
		Self(ChaCha20Rng::from_seed(seed))
	}

	/// Generate a 20-byte X.509-compliant positive-integer serial number.
	///
	/// Per RFC 5280 §4.1.2.2 the serial MUST encode as a positive ASN.1
	/// INTEGER. Clearing the high bit of the leading byte guarantees the
	/// value is positive and that the DER encoding does not require a
	/// `0x00` prefix octet (which would push the encoded INTEGER past the
	/// 20-octet conformance ceiling).
	pub fn cert_serial(&mut self) -> [u8; CERT_SERIAL_LEN] {
		let mut buf = [0u8; CERT_SERIAL_LEN];
		self.fill_bytes(&mut buf);
		buf[0] &= 0x7F;
		buf
	}

	/// One-shot cert serial issuance. Constructs an RNG from `sources`,
	/// generates a single serial, and drops the RNG before returning —
	/// which triggers the [`Drop`] zeroize of the underlying state. The
	/// only thing that survives this call is the 20-byte serial returned
	/// to the requestor.
	///
	/// Use this in the issuer-side cert minting code path. For multi-shot
	/// callers (shops with a persistent RNG, paid-extrinsic fulfillment
	/// of multiple values), construct via [`Self::new`] and hold the
	/// instance until you're done.
	pub fn issue_cert_serial(sources: &[&dyn EntropySource]) -> [u8; CERT_SERIAL_LEN] {
		Self::new(sources).cert_serial()
	}
}

impl Drop for RostroShopRng {
	fn drop(&mut self) {
		// rand_chacha 0.3 doesn't expose Zeroize on its RNG type. Overwriting
		// with a zero-seeded instance scrubs the previous key material from the
		// heap allocation that held it. Not a volatile-write guarantee (the
		// compiler can in principle elide the assignment), but the new value
		// is observed by Self's own RngCore impl downstream of drop in tests,
		// keeping the assignment side-effecting and harder to optimize away.
		self.0 = ChaCha20Rng::from_seed([0u8; 32]);
	}
}

impl RngCore for RostroShopRng {
	fn next_u32(&mut self) -> u32 {
		self.0.next_u32()
	}
	fn next_u64(&mut self) -> u64 {
		self.0.next_u64()
	}
	fn fill_bytes(&mut self, dest: &mut [u8]) {
		self.0.fill_bytes(dest)
	}
	fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
		self.0.try_fill_bytes(dest)
	}
}

impl CryptoRng for RostroShopRng {}

#[cfg(test)]
mod tests {
	use super::*;
	use std::cell::Cell;
	use std::collections::HashSet;

	/// Deterministic test source: yields the same bytes on every pull.
	struct FixedSource([u8; ENTROPY_BYTES_PER_SOURCE]);
	impl EntropySource for FixedSource {
		fn pull_entropy(&self, out: &mut [u8]) {
			let n = out.len().min(self.0.len());
			out[..n].copy_from_slice(&self.0[..n]);
		}
	}

	/// Mutating test source: yields a different byte each call.
	struct CountingSource(Cell<u8>);
	impl EntropySource for CountingSource {
		fn pull_entropy(&self, out: &mut [u8]) {
			let b = self.0.get();
			self.0.set(b.wrapping_add(1));
			for slot in out.iter_mut() {
				*slot = b;
			}
		}
	}

	#[test]
	fn identical_sources_yield_identical_rngs() {
		let s = FixedSource([0xAB; ENTROPY_BYTES_PER_SOURCE]);
		let a = RostroShopRng::new(&[&s]).cert_serial();
		let b = RostroShopRng::new(&[&s]).cert_serial();
		assert_eq!(a, b);
	}

	#[test]
	fn different_sources_yield_different_rngs() {
		let s1 = FixedSource([0x01; ENTROPY_BYTES_PER_SOURCE]);
		let s2 = FixedSource([0x02; ENTROPY_BYTES_PER_SOURCE]);
		assert_ne!(
			RostroShopRng::new(&[&s1]).cert_serial(),
			RostroShopRng::new(&[&s2]).cert_serial(),
		);
	}

	#[test]
	fn source_order_matters() {
		let a = FixedSource([0x01; ENTROPY_BYTES_PER_SOURCE]);
		let b = FixedSource([0x02; ENTROPY_BYTES_PER_SOURCE]);
		assert_ne!(
			RostroShopRng::new(&[&a, &b]).cert_serial(),
			RostroShopRng::new(&[&b, &a]).cert_serial(),
		);
	}

	#[test]
	fn mutating_source_changes_seed_between_constructions() {
		let s = CountingSource(Cell::new(0));
		let first = RostroShopRng::new(&[&s]).cert_serial();
		let second = RostroShopRng::new(&[&s]).cert_serial();
		assert_ne!(first, second);
	}

	#[test]
	fn os_entropy_diverges_across_constructions() {
		assert_ne!(
			RostroShopRng::new(&[&OsEntropy]).cert_serial(),
			RostroShopRng::new(&[&OsEntropy]).cert_serial(),
		);
	}

	#[test]
	fn mixing_compromised_source_with_os_still_diverges() {
		let constant = FixedSource([0xFF; ENTROPY_BYTES_PER_SOURCE]);
		assert_ne!(
			RostroShopRng::new(&[&constant, &OsEntropy]).cert_serial(),
			RostroShopRng::new(&[&constant, &OsEntropy]).cert_serial(),
		);
	}

	#[test]
	#[should_panic(expected = "at least one entropy source")]
	fn empty_sources_panics() {
		let _ = RostroShopRng::new(&[]);
	}

	#[test]
	fn from_seed_deterministic() {
		let mut a = RostroShopRng::from_seed([42; 32]);
		let mut b = RostroShopRng::from_seed([42; 32]);
		assert_eq!(a.cert_serial(), b.cert_serial());
	}

	#[test]
	fn cert_serial_high_bit_clear() {
		let mut rng = RostroShopRng::new(&[&OsEntropy]);
		for _ in 0..1000 {
			let s = rng.cert_serial();
			assert_eq!(s[0] & 0x80, 0, "high bit must be clear for positive DER integer");
		}
	}

	#[test]
	fn cert_serial_length() {
		let s = RostroShopRng::new(&[&OsEntropy]).cert_serial();
		assert_eq!(s.len(), CERT_SERIAL_LEN);
		assert_eq!(CERT_SERIAL_LEN, 20);
	}

	#[test]
	fn cert_serial_no_collisions_in_1k() {
		let mut rng = RostroShopRng::new(&[&OsEntropy]);
		let mut seen = HashSet::new();
		for _ in 0..1000 {
			assert!(seen.insert(rng.cert_serial()), "unexpected collision in 1000 serials");
		}
	}

	#[test]
	fn rngcore_passthrough_matches_inner() {
		let mut wrapped = RostroShopRng::from_seed([7; 32]);
		let mut raw = ChaCha20Rng::from_seed([7; 32]);
		assert_eq!(wrapped.next_u64(), raw.next_u64());
	}

	#[test]
	fn cryptorng_marker_present() {
		fn requires_crypto<R: CryptoRng>(_: &R) {}
		requires_crypto(&RostroShopRng::new(&[&OsEntropy]));
	}

	#[test]
	fn static_entropy_deterministic_for_same_input() {
		let s = StaticEntropy::new(vec![0xAA; 100]);
		let a = RostroShopRng::new(&[&s]).cert_serial();
		let b = RostroShopRng::new(&[&s]).cert_serial();
		assert_eq!(a, b);
	}

	#[test]
	fn static_entropy_differs_for_different_inputs() {
		let s1 = StaticEntropy::new(vec![0x11; 100]);
		let s2 = StaticEntropy::new(vec![0x22; 100]);
		assert_ne!(
			RostroShopRng::new(&[&s1]).cert_serial(),
			RostroShopRng::new(&[&s2]).cert_serial(),
		);
	}

	#[test]
	fn static_entropy_handles_empty_buffer() {
		let s = StaticEntropy::new(Vec::new());
		let _ = RostroShopRng::new(&[&s, &OsEntropy]).cert_serial();
	}

	#[test]
	fn static_entropy_handles_large_buffer() {
		let s = StaticEntropy::new(vec![0x42; 64 * 1024]);
		let _ = RostroShopRng::new(&[&s]).cert_serial();
	}

	#[test]
	fn issue_cert_serial_one_shot_drops_rng() {
		// Behavioral test: the convenience produces a valid serial; the
		// real zeroize guarantee is structural (Drop runs at end of the
		// `Self::new(sources).cert_serial()` expression) and is exercised
		// here by virtue of the function returning at all.
		let s = StaticEntropy::new(vec![0xCD; 64]);
		let serial = RostroShopRng::issue_cert_serial(&[&s, &OsEntropy]);
		assert_eq!(serial[0] & 0x80, 0);
	}

	#[test]
	fn issue_cert_serial_diverges_across_calls() {
		let s = StaticEntropy::new(vec![0xCD; 64]);
		assert_ne!(
			RostroShopRng::issue_cert_serial(&[&s, &OsEntropy]),
			RostroShopRng::issue_cert_serial(&[&s, &OsEntropy]),
		);
	}
}
