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
//!   — build + sign + sealed-sender-seal an envelope locally, then
//!   call `chat_send_envelope` against the named gemini-node.
//! - `fetch --node-rpc <url> --recipient-seed <hex> [--relay-peer <peer_id>]`
//!   — call `chat_fetch_shares`, group + combine + unseal + verify
//!   locally, print recovered plaintexts.

use std::collections::HashMap;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use codec::{Decode, Encode};
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::HttpClientBuilder;
use jsonrpsee::rpc_params;
use rand_core::{OsRng, RngCore};
use rostro_chat_primitives::{
	descriptor::{MessageId, PickupKey},
	envelope::{sign_inner, EnvelopeKind, SealedEnvelope, UnsealedInner},
	identity_key::{ed25519_seed_to_x25519_secret, ed25519_to_x25519_pubkey},
	stripe::combine_xor,
	verify::verify_sender,
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
	#[allow(dead_code)]
	expires_at_block: u32,
}

#[derive(Debug, serde::Deserialize)]
struct ChatFetchedShareRaw {
	descriptor: ChatShareDescriptorRpc,
	share_bytes_hex: String,
	#[allow(dead_code)]
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
	/// then call `chat_send_envelope` on the named gemini-node.
	/// The node sees only the encrypted envelope + routing metadata.
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

		/// Number of XOR-stripe shares the node should split the
		/// envelope into.
		#[arg(long, default_value_t = 5)]
		total_shares: u8,
	},

	/// Call `chat_fetch_shares` on the named gemini-node, then
	/// reconstruct + unseal + verify any complete message stripes
	/// locally. Prints recovered plaintexts.
	Fetch {
		/// JSON-RPC URL of the gemini-node to query.
		#[arg(long)]
		node_rpc: String,

		/// 32-byte (64-char hex) recipient chat-identity seed. The
		/// CLI derives the X25519 secret on-the-fly for unsealing;
		/// the seed never leaves the CLI.
		#[arg(long)]
		recipient_seed: String,

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
	total_shares: u8,
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
	let envelope_hex = hex::encode(&envelope_bytes);

	// Call the node via JSON-RPC.
	let client = HttpClientBuilder::default()
		.build(node_rpc)
		.with_context(|| format!("connecting to {node_rpc}"))?;
	let result: ChatSendResult = client
		.request(
			"chat_send_envelope",
			rpc_params![
				hex::encode(recipient_ed),
				envelope_hex,
				total_shares
			],
		)
		.await
		.context("chat_send_envelope RPC failed")?;

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
	relay_peer: Option<&str>,
) -> Result<()> {
	let recipient_seed = decode_hex32(recipient_seed_hex)?;
	let (recipient_ed, _recipient_x_pub, pickup_bytes) =
		identity_from_seed(&recipient_seed)?;
	let recipient_x_secret = ed25519_seed_to_x25519_secret(&recipient_seed);

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

	// Group by message_id_hex; track total_shares for each.
	let mut by_message: HashMap<String, (u8, Vec<(u8, Vec<u8>)>)> = HashMap::new();
	for s in shares {
		let mid = s.descriptor.message_id_hex.clone();
		let bytes = hex::decode(s.share_bytes_hex.trim_start_matches("0x"))
			.context("share_bytes_hex not valid hex")?;
		let entry = by_message
			.entry(mid)
			.or_insert((s.descriptor.total_shares, Vec::new()));
		entry.1.push((s.descriptor.share_index, bytes));
	}

	let mut printed_any = false;
	for (mid_hex, (total, mut share_list)) in by_message {
		if share_list.len() != total as usize {
			eprintln!(
				"message {mid_hex}: incomplete ({} of {} shares); skipping",
				share_list.len(),
				total,
			);
			continue;
		}
		share_list.sort_by_key(|(idx, _)| *idx);
		let share_refs: Vec<&[u8]> = share_list.iter().map(|(_, b)| b.as_slice()).collect();
		let envelope_bytes = combine_xor(&share_refs)
			.map_err(|e| anyhow!("combine_xor failed: {e:?}"))?;
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
			total_shares,
		} => cmd_send(&node_rpc, &sender_seed, &recipient_pubkey, &message, total_shares)
			.await,
		Cmd::Fetch { node_rpc, recipient_seed, relay_peer } => {
			cmd_fetch(&node_rpc, &recipient_seed, relay_peer.as_deref()).await
		},
	}
}
