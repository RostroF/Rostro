// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! `rostro-chat-cli` — user-side test-harness for the Rostro chat
//! layer.
//!
//! Stand-in for the future mobile-app SDK. Demonstrates the proper
//! architecture: the user's chat-identity Ed25519 keypair lives on
//! the user's device (here, derivable from a CLI-provided seed),
//! all encryption + decryption happens on-device, and the running
//! gemini-node sees only ciphertext + routing metadata.
//!
//! ## Subcommands
//!
//! - `gen-identity --seed <hex>` — derive an Ed25519 chat-identity
//!   keypair from a deterministic 32-byte seed. Prints the public
//!   key + the corresponding X25519 pubkey (for sealed-sender ECDH)
//!   + the pickup key.
//! - `pickup-key --pubkey <hex>` — compute a pickup key from a
//!   chat-identity Ed25519 pubkey. Utility for scripts.
//! - `send --node-rpc <url> --sender-seed <hex> --recipient-pubkey <hex> --message <text>`
//!   — build + sign + sealed-sender-seal an envelope locally, chunk +
//!   MAC it on-device (`prepare_batch`), then call
//!   `chat_send_prepared` against the named gemini-node.
//! - `fetch --node-rpc <url> --recipient-seed <hex> --peer-pubkey <hex> [--relay-peer <peer_id>]`
//!   — call `chat_fetch_shares`, group + MAC-verify + reassemble +
//!   unseal + verify locally, print recovered plaintexts.
//!
//! ## Conversation secret (chunk-MAC keying)
//!
//! The per-chunk MAC key derives from a per-conversation secret
//! (docs/CHAT-SHARE-CHUNKING.md §4.3). This Tier-0 harness has no DR
//! session state, so it uses the static-static X25519 ECDH between
//! the two chat identities: sender computes
//! `x25519(sender_x_secret, recipient_x_pub)`, recipient computes
//! `x25519(recipient_x_secret, sender_x_pub)` — same secret, no
//! wire bytes. That is why `fetch` takes `--peer-pubkey`: the
//! recipient must know whose conversation it is reassembling before
//! it can verify tags (dotwave holds this per contact; the dead-drop
//! label identifies the conversation there).

use std::collections::HashMap;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use codec::{Decode, Encode};
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::HttpClientBuilder;
use jsonrpsee::rpc_params;
use rand_core::{OsRng, RngCore};
use rostro_chat_primitives::{
	chunk::{combine_chunks_authenticated, prepare_batch, TaggedChunk},
	descriptor::{MessageId, PickupKey, CHAT_TTL_SECONDS},
	envelope::{sign_inner, EnvelopeKind, SealedEnvelope, UnsealedInner},
	identity_key::{ed25519_seed_to_x25519_secret, ed25519_to_x25519_pubkey},
	verify::{
		derive_share_mac_key, derive_stripe_mac_secret, verify_sender, ShareMacTag,
	},
};
use rostro_chat_sealed_sender::{seal as ss_seal, unseal as ss_unseal, SealedOutput};

// ── response-type mirrors (must match gemini-node/src/chat_rpc.rs) ──

#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct ChatSendResult {
	message_id_hex: String,
	share_count: u32,
	recipient_pickup_key_hex: String,
}

#[derive(Debug, serde::Deserialize)]
struct ChatShareDescriptorRpc {
	#[allow(dead_code)]
	relay_pubkey_hex: String,
	message_id_hex: String,
	share_index: u8,
	total_shares: u8,
	#[allow(dead_code)]
	pickup_key_hex: String,
	expires_at_unix_ts: u64,
}

#[derive(Debug, serde::Deserialize)]
struct ChatFetchedShareRaw {
	descriptor: ChatShareDescriptorRpc,
	share_bytes_hex: String,
	mac_tag_hex: String,
}

// ── CLI ─────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "rostro-chat-cli")]
struct Cli {
	#[command(subcommand)]
	cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
	/// Derive a chat-identity keypair from a deterministic seed.
	/// Prints the derived public keys + pickup key so scripts can
	/// pre-compute the routing metadata two parties need to exchange.
	GenIdentity {
		/// 32-byte (64-char hex) chat-identity seed. The Ed25519
		/// signing key is `SigningKey::from(seed)`; the X25519
		/// secret is derived via XEdDSA from the same seed.
		#[arg(long)]
		seed: String,
	},

	/// Compute a pickup key from a chat-identity Ed25519 pubkey.
	PickupKey {
		/// 32-byte (64-char hex) chat-identity Ed25519 pubkey.
		#[arg(long)]
		pubkey: String,
	},

	/// Build + sign + sealed-sender-seal a chat envelope locally,
	/// chunk + MAC it on-device, then call `chat_send_prepared` on
	/// the named gemini-node. The node sees only ciphertext chunks +
	/// routing metadata — it holds no MAC key and does no splitting.
	Send {
		/// JSON-RPC URL of the gemini-node to dispatch through.
		/// Typically `http://127.0.0.1:9944` for a locally-running
		/// node.
		#[arg(long)]
		node_rpc: String,

		/// 32-byte (64-char hex) sender chat-identity seed. The
		/// CLI signs the `UnsealedInner` with the corresponding
		/// Ed25519 signing key — this key never leaves the CLI.
		#[arg(long)]
		sender_seed: String,

		/// 32-byte (64-char hex) recipient chat-identity Ed25519
		/// pubkey. Converted to X25519 for sealed-sender ECDH.
		#[arg(long)]
		recipient_pubkey: String,

		/// UTF-8 plaintext message body.
		#[arg(long)]
		message: String,

		/// Number of chunks to split the envelope into (client-side).
		#[arg(long, default_value_t = 5)]
		total_chunks: u8,
	},

	/// Call `chat_fetch_shares` on the named gemini-node, then
	/// MAC-verify + reassemble + unseal + verify any complete
	/// messages locally. Prints recovered plaintexts.
	Fetch {
		/// JSON-RPC URL of the gemini-node to query.
		#[arg(long)]
		node_rpc: String,

		/// 32-byte (64-char hex) recipient chat-identity seed. The
		/// CLI derives the X25519 secret on-the-fly for unsealing;
		/// the seed never leaves the CLI.
		#[arg(long)]
		recipient_seed: String,

		/// The conversation peer's (sender's) 32-byte chat-identity
		/// Ed25519 pubkey (hex). Needed to derive the conversation
		/// secret that keys the chunk MACs — see the module docs.
		#[arg(long)]
		peer_pubkey: String,

		/// Optional libp2p PeerId of a remote relay to also query
		/// in addition to the named node's local store.
		#[arg(long)]
		relay_peer: Option<String>,
	},
}

// ── crypto helpers ──────────────────────────────────────────────────

fn decode_hex32(s: &str) -> Result<[u8; 32]> {
	let trimmed = s.trim_start_matches("0x");
	let bytes = hex::decode(trimmed).context("invalid hex")?;
	if bytes.len() != 32 {
		return Err(anyhow!("expected 32 bytes, got {}", bytes.len()));
	}
	let mut out = [0u8; 32];
	out.copy_from_slice(&bytes);
	Ok(out)
}

/// Derive (Ed25519 pubkey, X25519 pubkey, pickup key) from a 32-byte
/// chat-identity seed.
fn identity_from_seed(seed: &[u8; 32]) -> Result<([u8; 32], [u8; 32], [u8; 32])> {
	let signing = ed25519_zebra::SigningKey::from(*seed);
	let ed_pubkey: [u8; 32] = ed25519_zebra::VerificationKey::from(&signing).into();
	let x25519_pubkey = ed25519_to_x25519_pubkey(&ed_pubkey)
		.ok_or_else(|| anyhow!("Ed25519 pubkey doesn't decode as a valid Edwards point"))?;
	let pickup = PickupKey::for_pairwise(&x25519_pubkey).0;
	Ok((ed_pubkey, x25519_pubkey, pickup))
}

// ── subcommand: gen-identity ────────────────────────────────────────

fn cmd_gen_identity(seed_hex: &str) -> Result<()> {
	let seed = decode_hex32(seed_hex)?;
	let (ed_pub, x_pub, pickup) = identity_from_seed(&seed)?;
	println!("seed_hex:            {}", hex::encode(seed));
	println!("ed25519_pubkey_hex:  {}", hex::encode(ed_pub));
	println!("x25519_pubkey_hex:   {}", hex::encode(x_pub));
	println!("pickup_key_hex:      {}", hex::encode(pickup));
	Ok(())
}

// ── subcommand: pickup-key ──────────────────────────────────────────

fn cmd_pickup_key(pubkey_hex: &str) -> Result<()> {
	let ed_pub = decode_hex32(pubkey_hex)?;
	let x_pub = ed25519_to_x25519_pubkey(&ed_pub)
		.ok_or_else(|| anyhow!("input doesn't decode as a valid Edwards point"))?;
	let pickup = PickupKey::for_pairwise(&x_pub).0;
	println!("{}", hex::encode(pickup));
	Ok(())
}

// ── subcommand: send ────────────────────────────────────────────────

async fn cmd_send(
	node_rpc: &str,
	sender_seed_hex: &str,
	recipient_pubkey_hex: &str,
	message: &str,
	total_chunks: u8,
) -> Result<()> {
	let sender_seed = decode_hex32(sender_seed_hex)?;
	let recipient_ed = decode_hex32(recipient_pubkey_hex)?;
	let recipient_x = ed25519_to_x25519_pubkey(&recipient_ed)
		.ok_or_else(|| anyhow!("recipient pubkey not on Edwards curve"))?;

	let signing = ed25519_zebra::SigningKey::from(sender_seed);

	// Fresh per-send MessageId.
	let mut message_id_bytes = [0u8; 32];
	OsRng.fill_bytes(&mut message_id_bytes);
	let message_id = MessageId(message_id_bytes);

	// v0.1 inner_ciphertext = plaintext bytes verbatim. The DR
	// pairwise wrapper would replace this with a DR WireMessage in a
	// later phase.
	let inner_ciphertext = message.as_bytes().to_vec();

	// Sign UnsealedInner on-device.
	let unsealed = sign_inner(inner_ciphertext, &message_id, &signing);
	let unsealed_encoded = unsealed.encode();

	// Sealed-sender-seal to the recipient's X25519 pubkey.
	let mut rng = OsRng;
	let sealed = ss_seal(&recipient_x, &unsealed_encoded, &mut rng);

	// Build SealedEnvelope.
	let envelope = SealedEnvelope {
		kind: EnvelopeKind::Pairwise,
		outer_ciphertext: sealed.ciphertext,
		ephemeral_pubkey: sealed.ephemeral_pub,
		message_id,
	};
	let envelope_bytes = envelope.encode();

	// Chunk + MAC on-device (the prepare-side of the chunk cutover).
	// Conversation secret: static-static X25519 between the two chat
	// identities (see module docs); the per-message MAC key derives
	// from it + the message_id.
	let sender_x_secret = ed25519_seed_to_x25519_secret(&sender_seed);
	let conversation_secret = x25519_dalek::x25519(sender_x_secret, recipient_x);
	let stripe_mac_secret = derive_stripe_mac_secret(&conversation_secret);
	let mac_key = derive_share_mac_key(&stripe_mac_secret, &message_id);

	let pickup_key = PickupKey::for_pairwise(&recipient_x);
	let now_unix = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	let batch = prepare_batch(
		&envelope_bytes,
		total_chunks as usize,
		&mac_key,
		message_id,
		pickup_key,
		now_unix + CHAT_TTL_SECONDS,
	)
	.map_err(|e| anyhow!("prepare_batch failed: {e:?}"))?;
	let batch_hex = hex::encode(batch.encode());

	// Call the node via JSON-RPC.
	let client = HttpClientBuilder::default()
		.build(node_rpc)
		.with_context(|| format!("connecting to {node_rpc}"))?;
	// v0.1 demo path: no HW-attested chat-auth cert available, so
	// the three auth-* parameters are sent as `null`; a Phase-2
	// cert-gated node rejects this (the dotwave app passes real
	// values: cert thumbprint + timestamp + signature over
	// blake2_256(CHAT_AUTH_DOMAIN || batch_bytes || ts_be)).
	let auth_thumbprint: Option<String> = None;
	let auth_timestamp: Option<u64> = None;
	let auth_sig: Option<String> = None;
	let result: ChatSendResult = client
		.request(
			"chat_send_prepared",
			rpc_params![batch_hex, auth_thumbprint, auth_timestamp, auth_sig],
		)
		.await
		.context("chat_send_prepared RPC failed")?;

	println!("sent.");
	println!("  message_id_hex:           {}", result.message_id_hex);
	println!("  share_count:              {}", result.share_count);
	println!("  recipient_pickup_key_hex: {}", result.recipient_pickup_key_hex);
	Ok(())
}

// ── subcommand: fetch ───────────────────────────────────────────────

async fn cmd_fetch(
	node_rpc: &str,
	recipient_seed_hex: &str,
	peer_pubkey_hex: &str,
	relay_peer: Option<&str>,
) -> Result<()> {
	let recipient_seed = decode_hex32(recipient_seed_hex)?;
	let (recipient_ed, _recipient_x_pub, pickup_bytes) =
		identity_from_seed(&recipient_seed)?;
	let recipient_x_secret = ed25519_seed_to_x25519_secret(&recipient_seed);

	// Conversation secret for chunk-MAC verification (module docs):
	// same static-static X25519 the sender computed, from this side.
	let peer_ed = decode_hex32(peer_pubkey_hex)?;
	let peer_x = ed25519_to_x25519_pubkey(&peer_ed)
		.ok_or_else(|| anyhow!("peer pubkey not on Edwards curve"))?;
	let conversation_secret = x25519_dalek::x25519(recipient_x_secret, peer_x);
	let stripe_mac_secret = derive_stripe_mac_secret(&conversation_secret);
	let pickup_key = PickupKey(pickup_bytes);

	// Call chat_fetch_shares.
	let client = HttpClientBuilder::default()
		.build(node_rpc)
		.with_context(|| format!("connecting to {node_rpc}"))?;
	let shares: Vec<ChatFetchedShareRaw> = client
		.request(
			"chat_fetch_shares",
			rpc_params![hex::encode(pickup_bytes), relay_peer.map(|s| s.to_string())],
		)
		.await
		.context("chat_fetch_shares RPC failed")?;

	if shares.is_empty() {
		println!("(no shares found for this pickup key)");
		return Ok(());
	}

	// Group by message_id_hex, keeping the fetched descriptor fields
	// (index, total, expires) + tag per chunk — the MAC binds them
	// all, so they must be fed to verification exactly as fetched.
	// Dedupe on (message_id, share_index): with per-chunk replica
	// sets, aggregation may return the same chunk from two relays.
	type FetchedChunk = (u8, u8, u64, Vec<u8>, ShareMacTag);
	let mut by_message: HashMap<String, Vec<FetchedChunk>> = HashMap::new();
	for s in shares {
		let mid = s.descriptor.message_id_hex.clone();
		let bytes = hex::decode(s.share_bytes_hex.trim_start_matches("0x"))
			.context("share_bytes_hex not valid hex")?;
		let tag_bytes = decode_hex32(&s.mac_tag_hex).context("mac_tag_hex")?;
		let entry = by_message.entry(mid).or_default();
		if entry.iter().any(|(idx, ..)| *idx == s.descriptor.share_index) {
			continue;
		}
		entry.push((
			s.descriptor.share_index,
			s.descriptor.total_shares,
			s.descriptor.expires_at_unix_ts,
			bytes,
			tag_bytes,
		));
	}

	let mut printed_any = false;
	for (mid_hex, chunk_list) in by_message {
		let message_id = MessageId(match decode_hex32(&mid_hex) {
			Ok(b) => b,
			Err(e) => {
				eprintln!("message {mid_hex}: bad message_id ({e}); skipping");
				continue;
			},
		});
		// Per-message MAC key: conversation secret + message_id, both
		// known BEFORE any decryption.
		let mac_key = derive_share_mac_key(&stripe_mac_secret, &message_id);
		let refs: Vec<TaggedChunk<'_>> = chunk_list
			.iter()
			.map(|(idx, total, expires, bytes, tag)| TaggedChunk {
				share_index: *idx,
				total_shares: *total,
				expires_at_unix_ts: *expires,
				bytes,
				tag,
			})
			.collect();
		let envelope_bytes =
			match combine_chunks_authenticated(&mac_key, &message_id, &pickup_key, &refs) {
				Ok(b) => b,
				Err(e) => {
					// Includes IncompleteSet (fetch more replicas) and
					// TamperedChunk (localized — retry via a NORMAL
					// fetch against another relay; the attribution
					// stays here on the device).
					eprintln!("message {mid_hex}: reassembly failed ({e:?}); skipping");
					continue;
				},
			};
		let envelope = SealedEnvelope::decode(&mut &envelope_bytes[..])
			.context("decode SealedEnvelope failed")?;

		if !matches!(envelope.kind, EnvelopeKind::Pairwise) {
			eprintln!("message {mid_hex}: not a Pairwise envelope; skipping (group flow not yet wired)");
			continue;
		}

		// Sealed-sender-unseal.
		let sealed = SealedOutput {
			ephemeral_pub: envelope.ephemeral_pubkey,
			ciphertext: envelope.outer_ciphertext,
		};
		let unsealed_bytes = match ss_unseal(&recipient_x_secret, &sealed) {
			Ok(b) => b,
			Err(e) => {
				eprintln!("message {mid_hex}: unseal failed ({e:?}); skipping");
				continue;
			},
		};
		let unsealed = UnsealedInner::decode(&mut &unsealed_bytes[..])
			.context("decode UnsealedInner failed")?;

		// Verify sender signature.
		let sender_pubkey = match verify_sender(&unsealed, &envelope.message_id) {
			Ok(pk) => pk,
			Err(e) => {
				eprintln!("message {mid_hex}: signature verify failed ({e:?}); skipping");
				continue;
			},
		};

		let plaintext_bytes = unsealed.inner_ciphertext;
		let plaintext_utf8 = std::str::from_utf8(&plaintext_bytes).ok();

		println!("─────────────────────────────────────────────");
		println!("  message_id:    {mid_hex}");
		println!("  sender_pubkey: {}", hex::encode(sender_pubkey));
		println!("  recipient:     {}", hex::encode(recipient_ed));
		if let Some(s) = plaintext_utf8 {
			println!("  plaintext:     {s}");
		} else {
			println!("  plaintext_hex: {}", hex::encode(&plaintext_bytes));
		}
		printed_any = true;
	}

	if !printed_any {
		println!("(no complete + decryptable messages)");
	}
	Ok(())
}

// ── main ────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
	let cli = Cli::parse();
	match cli.cmd {
		Cmd::GenIdentity { seed } => cmd_gen_identity(&seed),
		Cmd::PickupKey { pubkey } => cmd_pickup_key(&pubkey),
		Cmd::Send {
			node_rpc,
			sender_seed,
			recipient_pubkey,
			message,
			total_chunks,
		} => cmd_send(&node_rpc, &sender_seed, &recipient_pubkey, &message, total_chunks)
			.await,
		Cmd::Fetch { node_rpc, recipient_seed, peer_pubkey, relay_peer } => {
			cmd_fetch(&node_rpc, &recipient_seed, &peer_pubkey, relay_peer.as_deref())
				.await
		},
	}
}
