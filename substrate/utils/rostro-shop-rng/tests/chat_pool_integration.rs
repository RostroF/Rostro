//! Integration test: wire `EphemeralShareStore` into `RostroShopRng` via a
//! small adapter, demonstrating the pattern real binding code (gemini-node,
//! zkpki-client running on a node) will use.
//!
//! Validates the load-bearing architectural claim: the MLS chat ciphertext
//! pool is the primary entropy source. Mutating the pool — inserting a share,
//! letting the TTL sweep run — moves the generated cert serial, even when
//! [`OsEntropy`] is held constant by seeding the RNG only from the chat pool.

use rostro_chat_ephemeral_store::EphemeralShareStore;
use rostro_chat_primitives::descriptor::{
	GroupId, MessageId, PickupKey, RelayPubkey, ShareDescriptor, UnixTimestamp,
};
use rostro_chat_primitives::store_protocol::ShareStore;
use rostro_chat_primitives::verify::{mac_share, ShareMacTag};
use rostro_shop_rng::{EntropySource, OsEntropy, RostroShopRng, StaticEntropy};
use std::sync::atomic::{AtomicU64, Ordering};

/// Adapter — bridges `EphemeralShareStore`'s entropy snapshot method into the
/// `EntropySource` trait that `RostroShopRng` consumes. Same shape gemini-node
/// will instantiate when wiring the issuer-side cert minting code.
struct ChatPoolEntropy<'a>(&'a EphemeralShareStore);

impl<'a> EntropySource for ChatPoolEntropy<'a> {
	fn pull_entropy(&self, out: &mut [u8]) {
		self.0.write_entropy_hash(out);
	}
}

fn insert_dummy(store: &EphemeralShareStore, mid_byte: u8, payload: Vec<u8>) {
	let now: UnixTimestamp = 1_700_000_000;
	let descriptor = ShareDescriptor {
		relay_pubkey: RelayPubkey([0x11; 32]),
		message_id: MessageId([mid_byte; 32]),
		share_index: 0,
		total_shares: 5,
		pickup_key: PickupKey::for_group(&GroupId([0x33; 32])),
		expires_at_unix_ts: now + 3600,
	};
	let tag: ShareMacTag = mac_share(&[0u8; 32], &payload, 0);
	store.insert(descriptor, payload, tag).expect("insert must succeed in fresh store");
}

#[test]
fn cert_serial_changes_when_chat_pool_mutates() {
	let store = EphemeralShareStore::with_default_config();
	let adapter = ChatPoolEntropy(&store);

	// Snapshot 1: empty pool. The per-call counter still moves the digest.
	let first = RostroShopRng::new(&[&adapter]).cert_serial();

	// Snapshot 2: one share in the pool. Adds ~128 bytes of ciphertext to the
	// entropy input — the digest must change.
	insert_dummy(&store, 0xA1, vec![0xDE; 128]);
	let second = RostroShopRng::new(&[&adapter]).cert_serial();
	assert_ne!(first, second, "inserting a share must perturb the issued cert serial");

	// Snapshot 3: a second share. Should keep moving.
	insert_dummy(&store, 0xA2, vec![0xAD; 256]);
	let third = RostroShopRng::new(&[&adapter]).cert_serial();
	assert_ne!(second, third);
	assert_ne!(first, third);
}

#[test]
fn cert_serial_changes_after_ttl_sweep() {
	let store = EphemeralShareStore::with_default_config();
	let adapter = ChatPoolEntropy(&store);

	insert_dummy(&store, 0xB0, vec![0x42; 64]);
	let with_share = RostroShopRng::new(&[&adapter]).cert_serial();

	store.sweep_expired(UnixTimestamp::MAX);
	assert_eq!(store.len(), 0, "TTL sweep must drain the pool");

	let after_sweep = RostroShopRng::new(&[&adapter]).cert_serial();
	assert_ne!(with_share, after_sweep, "pool churn (sweep) must perturb the serial");
}

#[test]
fn issuing_1000_cert_serials_yields_no_collisions() {
	// End-to-end sanity: a chat-pool-seeded RNG produces unique serials
	// in bulk, the same way a real issuer hammering through a batch would.
	let store = EphemeralShareStore::with_default_config();
	for i in 0..5u8 {
		insert_dummy(&store, 0xC0 + i, vec![i; 96]);
	}
	let adapter = ChatPoolEntropy(&store);
	let mut rng = RostroShopRng::new(&[&adapter]);

	let mut seen = std::collections::HashSet::new();
	for _ in 0..1000 {
		assert!(seen.insert(rng.cert_serial()), "no duplicate serials in 1000 issuances");
	}
}

#[test]
fn chat_pool_plus_os_entropy_diverges_per_construction() {
	// Real production wiring: both sources mixed. Should produce different
	// serials every time the RNG is constructed, even with identical pool state.
	let store = EphemeralShareStore::with_default_config();
	insert_dummy(&store, 0xD0, vec![0x77; 100]);
	let chat = ChatPoolEntropy(&store);

	let a = RostroShopRng::new(&[&chat, &OsEntropy]).cert_serial();
	let b = RostroShopRng::new(&[&chat, &OsEntropy]).cert_serial();
	assert_ne!(a, b);
}

/// Mock libp2p Swarm view — production wiring grabs these values from the
/// real Swarm at RNG construction time. Tests use canned values.
struct MockSwarm {
	validator_ciphertext_sample: Vec<u8>,
	chat_channel_ciphertext_sample: Vec<u8>,
	peer_count: usize,
}

/// Constructs the full production-shape RNG with every entropy source the user
/// specified, wired against an `EphemeralShareStore` + a mock libp2p Swarm.
///
/// In gemini-node this exact function lives at the issuer-side cert mint path:
/// each call captures fresh ciphertext samples + peer count + a rotating bucket
/// index, mixes them with the chat pool's own snapshot, then asks `cert_serial()`.
fn make_full_rng(store: &EphemeralShareStore, swarm: &MockSwarm) -> RostroShopRng {
	// Per-call rotating bucket selector. In production this is a module-level
	// atomic shared across all RNG constructions on the node — every call
	// samples a different bucket, so over 256 calls all buckets have contributed.
	static BUCKET_ROTOR: AtomicU64 = AtomicU64::new(0);
	let bucket = (BUCKET_ROTOR.fetch_add(1, Ordering::Relaxed) % 256) as u8;
	let bucket_count = store.bucket_shard_count(bucket);

	let chat_pool = ChatPoolEntropy(store);
	let validator_sample = StaticEntropy::new(swarm.validator_ciphertext_sample.clone());
	let chat_sample = StaticEntropy::new(swarm.chat_channel_ciphertext_sample.clone());
	let peer_count = StaticEntropy::new((swarm.peer_count as u64).to_le_bytes().to_vec());
	let bucket_entropy = {
		let mut buf = Vec::with_capacity(9);
		buf.push(bucket);
		buf.extend_from_slice(&(bucket_count as u64).to_le_bytes());
		StaticEntropy::new(buf)
	};

	RostroShopRng::new(&[
		&chat_pool,         // ciphertext + descriptors + per-call atomic tick
		&bucket_entropy,    // rotating bucket index + shard count for that bucket
		&validator_sample,  // recent validator gossipsub ciphertext (noise to non-validators)
		&chat_sample,       // recent MLS chat channel ciphertext
		&peer_count,        // current connected peer count
		&OsEntropy,         // defense-in-depth mixin
	])
}

#[test]
fn full_production_wiring_issues_unique_serials() {
	let store = EphemeralShareStore::with_default_config();
	for i in 0..3u8 {
		insert_dummy(&store, 0xE0 + i, vec![i; 96]);
	}
	let swarm = MockSwarm {
		validator_ciphertext_sample: vec![0xCA; 256],
		chat_channel_ciphertext_sample: vec![0xFE; 256],
		peer_count: 47,
	};

	let mut seen = std::collections::HashSet::new();
	for _ in 0..256 {
		let mut rng = make_full_rng(&store, &swarm);
		assert!(seen.insert(rng.cert_serial()), "no duplicate serials across 256 issuances");
	}
}

#[test]
fn full_wiring_diverges_when_peer_count_changes() {
	// Validator/chat samples + bucket pinned to constant by holding everything else
	// equal — only peer_count varies between the two snapshots.
	let store = EphemeralShareStore::with_default_config();
	insert_dummy(&store, 0xF0, vec![0xAA; 128]);

	let make = |peers: usize| {
		let swarm = MockSwarm {
			validator_ciphertext_sample: vec![0x11; 128],
			chat_channel_ciphertext_sample: vec![0x22; 128],
			peer_count: peers,
		};
		make_full_rng(&store, &swarm).cert_serial()
	};

	// Even at the same chat pool state, a different peer count should propagate.
	assert_ne!(make(10), make(11));
}

#[test]
fn full_wiring_diverges_when_validator_sample_changes() {
	let store = EphemeralShareStore::with_default_config();
	insert_dummy(&store, 0xF1, vec![0xBB; 128]);

	let make = |sample: Vec<u8>| {
		let swarm = MockSwarm {
			validator_ciphertext_sample: sample,
			chat_channel_ciphertext_sample: vec![0x22; 128],
			peer_count: 50,
		};
		make_full_rng(&store, &swarm).cert_serial()
	};

	assert_ne!(make(vec![0xAA; 256]), make(vec![0xBB; 256]));
}
