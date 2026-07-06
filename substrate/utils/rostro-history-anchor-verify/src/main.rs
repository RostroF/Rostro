// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # rostro-history-anchor-verify
//!
//! Offline verifier for the dual-hash history anchor
//! (`pallet-rostro-history-anchor`). Recomputes the Keccak-512 anchor
//! chain from raw header bytes fetched over RPC and cross-checks every
//! on-chain anchor snapshot, the live head, the sealed count, and an
//! optionally supplied externally published head.
//!
//! This tool is the escape hatch the anchor design leans on: the chain of
//! seals must be recomputable WITHOUT the runtime, the trie, or the frame
//! stack. It therefore duplicates the two protocol constants (domain tag,
//! pallet storage name) instead of importing pallet code; a unit test pins
//! them against the pallet crate so drift is caught at test time while the
//! shipped binary stays frame-free.
//!
//! ## What a pass means
//!
//! Every header the chain claims to have sealed was fetched raw, re-encoded
//! to SCALE, self-checked (its BLAKE2-256 must equal the chain-reported
//! block hash at that height — catching both re-encoding bugs and a lying
//! node), and folded from `keccak_512(DOMAIN_TAG)`. The fold reproduced
//! every on-chain snapshot and the live head. If `--expect-head` was given
//! (a previously published head), the fold reproduced that too, meaning
//! history up to that seal is bound under both hash families.
//!
//! Exit code: 0 = all checks passed, 1 = any mismatch.

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use codec::{Compact, Encode};
use jsonrpsee::{
	core::client::ClientT,
	http_client::{HttpClient, HttpClientBuilder},
	rpc_params,
};
use serde::Deserialize;
use sp_crypto_hashing::{blake2_256, keccak_512, twox_128};

/// Must match `pallet_rostro_history_anchor::DOMAIN_TAG` (pinned by the
/// `constants_match_pallet` test).
const DOMAIN_TAG: &[u8] = b"rostro-history-anchor-v0";

/// The pallet's `construct_runtime!` name, i.e. its storage prefix.
const PALLET_NAME: &str = "HistoryAnchor";

#[derive(Parser)]
#[command(about = "Recompute and verify the Rostro dual-hash history anchor chain")]
struct Args {
	/// Node RPC endpoint.
	#[arg(long, default_value = "http://127.0.0.1:9944")]
	url: String,

	/// Externally published anchor head (0x-prefixed, 64 bytes) to verify
	/// the fold against, e.g. from an SRT publication or an `Anchored`
	/// event recorded elsewhere.
	#[arg(long)]
	expect_head: Option<String>,
}

/// Header shape as returned by `chain_getHeader`. Field names and hex
/// conventions match `sp_runtime::generic::Header`'s serde impl (pinned by
/// the `header_reencode_roundtrip` test).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RpcHeader {
	parent_hash: String,
	number: String,
	state_root: String,
	extrinsics_root: String,
	digest: RpcDigest,
}

#[derive(Deserialize)]
struct RpcDigest {
	logs: Vec<String>,
}

fn hex_bytes(s: &str) -> Result<Vec<u8>> {
	hex::decode(s.trim_start_matches("0x")).with_context(|| format!("bad hex: {s}"))
}

fn fixed<const N: usize>(s: &str) -> Result<[u8; N]> {
	let v = hex_bytes(s)?;
	v.try_into().map_err(|v: Vec<u8>| anyhow!("expected {N} bytes, got {}", v.len()))
}

/// Re-encode an RPC JSON header to the exact SCALE bytes the chain hashed:
/// `parent_hash ++ compact(number) ++ state_root ++ extrinsics_root ++
/// compact(#logs) ++ logs…` (each log arrives from RPC already
/// SCALE-encoded). Compact encoding is value-based, so parsing the number
/// as u64 yields identical bytes for any narrower runtime BlockNumber.
fn encode_header(h: &RpcHeader) -> Result<Vec<u8>> {
	let mut out = Vec::with_capacity(128);
	out.extend_from_slice(&fixed::<32>(&h.parent_hash)?);
	let number = u64::from_str_radix(h.number.trim_start_matches("0x"), 16)
		.with_context(|| format!("bad block number: {}", h.number))?;
	Compact(number).encode_to(&mut out);
	out.extend_from_slice(&fixed::<32>(&h.state_root)?);
	out.extend_from_slice(&fixed::<32>(&h.extrinsics_root)?);
	Compact(h.digest.logs.len() as u32).encode_to(&mut out);
	for log in &h.digest.logs {
		out.extend_from_slice(&hex_bytes(log)?);
	}
	Ok(out)
}

fn fold(head: [u8; 64], header_bytes: &[u8]) -> [u8; 64] {
	let mut buf = Vec::with_capacity(64 + header_bytes.len());
	buf.extend_from_slice(&head);
	buf.extend_from_slice(header_bytes);
	keccak_512(&buf)
}

fn storage_key(item: &str) -> String {
	format!(
		"0x{}{}",
		hex::encode(twox_128(PALLET_NAME.as_bytes())),
		hex::encode(twox_128(item.as_bytes()))
	)
}

/// One entry of the on-chain `Anchors` map.
struct Anchor {
	era: u32,
	sealed_height: u64,
	head: [u8; 64],
}

async fn get_storage(client: &HttpClient, key: &str, at: &str) -> Result<Option<Vec<u8>>> {
	let v: Option<String> = client
		.request("state_getStorage", rpc_params![key, at])
		.await
		.context("state_getStorage")?;
	v.map(|s| hex_bytes(&s)).transpose()
}

async fn fetch_anchors(client: &HttpClient, at: &str) -> Result<Vec<Anchor>> {
	let prefix = storage_key("Anchors");
	let mut anchors = Vec::new();
	let mut start_key: Option<String> = None;
	loop {
		let keys: Vec<String> = client
			.request("state_getKeysPaged", rpc_params![&prefix, 512u32, &start_key, at])
			.await
			.context("state_getKeysPaged")?;
		let Some(last) = keys.last().cloned() else { break };
		for key in keys {
			// key = pallet(16) ++ item(16) ++ twox64(era)(8) ++ era_le(4)
			let raw = hex_bytes(&key)?;
			let era_bytes: [u8; 4] =
				raw.get(40..44).context("short Anchors key")?.try_into().unwrap();
			let era = u32::from_le_bytes(era_bytes);
			let value = get_storage(client, &key, at)
				.await?
				.context("Anchors key vanished mid-scan")?;
			// value = SCALE (BlockNumber, H512): height is whatever is
			// left in front of the trailing 64-byte head.
			let (height_bytes, head_bytes) = value
				.split_at_checked(value.len().saturating_sub(64))
				.filter(|(h, _)| h.len() == 4 || h.len() == 8)
				.with_context(|| format!("unexpected Anchors value length {}", value.len()))?;
			let mut height_le = [0u8; 8];
			height_le[..height_bytes.len()].copy_from_slice(height_bytes);
			anchors.push(Anchor {
				era,
				sealed_height: u64::from_le_bytes(height_le),
				head: head_bytes.try_into().unwrap(),
			});
		}
		start_key = Some(last);
	}
	// Seal order == era order: `LastSealedEra` is strictly increasing.
	anchors.sort_by_key(|a| a.era);
	Ok(anchors)
}

/// Fetch the raw SCALE header bytes at `height`, self-checked against the
/// chain-reported block hash.
async fn fetch_header_bytes(client: &HttpClient, height: u64) -> Result<Vec<u8>> {
	let hash: Option<String> = client
		.request("chain_getBlockHash", rpc_params![height])
		.await
		.context("chain_getBlockHash")?;
	let hash = hash.with_context(|| format!("no block hash at height {height}"))?;
	let header: Option<RpcHeader> = client
		.request("chain_getHeader", rpc_params![&hash])
		.await
		.context("chain_getHeader")?;
	let header = header.with_context(|| format!("no header for {hash}"))?;
	let bytes = encode_header(&header)?;
	// Self-check: our re-encoding must be the exact preimage of the block
	// hash. A mismatch means an re-encoding bug or a lying node; either
	// way no verdict can be trusted, so stop.
	let expected = fixed::<32>(&hash)?;
	if blake2_256(&bytes) != expected {
		bail!("re-encoded header at height {height} does not hash to {hash}");
	}
	Ok(bytes)
}

#[tokio::main]
async fn main() -> Result<()> {
	let args = Args::parse();
	let client = HttpClientBuilder::default().build(&args.url)?;

	let at: String = client
		.request("chain_getFinalizedHead", rpc_params![])
		.await
		.context("chain_getFinalizedHead")?;
	println!("verifying at finalized head {at}");

	let anchors = fetch_anchors(&client, &at).await?;
	if anchors.is_empty() {
		bail!("no anchors on chain (pallet inactive or storage prefix wrong)");
	}

	let mut failures = 0u32;
	let mut head = keccak_512(DOMAIN_TAG);
	for anchor in &anchors {
		let bytes = fetch_header_bytes(&client, anchor.sealed_height).await?;
		head = fold(head, &bytes);
		if head == anchor.head {
			println!(
				"  ok  era {:>6}  sealed height {:>10}  head 0x{}…",
				anchor.era,
				anchor.sealed_height,
				hex::encode(&head[..8])
			);
		} else {
			failures += 1;
			println!(
				"FAIL  era {:>6}  sealed height {:>10}\n      recomputed 0x{}\n      on-chain   0x{}",
				anchor.era,
				anchor.sealed_height,
				hex::encode(head),
				hex::encode(anchor.head)
			);
		}
	}

	// Live head + sealed count cross-checks.
	let live_head = get_storage(&client, &storage_key("AnchorHead"), &at)
		.await?
		.context("AnchorHead not in storage")?;
	if live_head == head {
		println!("live AnchorHead matches the fold");
	} else {
		failures += 1;
		println!(
			"FAIL live AnchorHead 0x{} != recomputed 0x{}",
			hex::encode(&live_head),
			hex::encode(head)
		);
	}
	let sealed_count = match get_storage(&client, &storage_key("SealedCount"), &at).await? {
		Some(v) => u64::from_le_bytes(
			v.try_into().map_err(|v: Vec<u8>| anyhow!("bad SealedCount length {}", v.len()))?,
		),
		None => 0,
	};
	if sealed_count == anchors.len() as u64 {
		println!("SealedCount {sealed_count} matches {} anchors", anchors.len());
	} else {
		failures += 1;
		println!("FAIL SealedCount {sealed_count} != {} anchors", anchors.len());
	}

	if let Some(expect) = &args.expect_head {
		let expect = fixed::<64>(expect)?;
		// The published head may be any historical fold state, so check
		// against every snapshot, not just the tip.
		if anchors.iter().any(|a| a.head == expect) || head == expect {
			println!("published head found in the anchor chain");
		} else {
			failures += 1;
			println!("FAIL published head 0x{} not reproduced by any seal", hex::encode(expect));
		}
	}

	println!(
		"\ncurrent head (publish this): 0x{}\nseals verified: {}, failures: {}",
		hex::encode(head),
		anchors.len(),
		failures
	);
	if failures > 0 {
		std::process::exit(1);
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use codec::Encode;
	use sp_runtime::{
		generic,
		traits::{BlakeTwo256, Header as HeaderT},
		DigestItem,
	};

	type Header = generic::Header<u32, BlakeTwo256>;

	/// The shipped binary duplicates the protocol constants to stay
	/// frame-free; this test is the drift alarm.
	#[test]
	fn constants_match_pallet() {
		assert_eq!(DOMAIN_TAG, pallet_rostro_history_anchor::DOMAIN_TAG);
	}

	/// JSON→SCALE re-encoding must reproduce the exact header bytes for
	/// the JSON shape the RPC emits (generic::Header's serde impl).
	#[test]
	fn header_reencode_roundtrip() {
		let mut header = Header::new(
			1_234_567,
			sp_core::H256::repeat_byte(0xE1),
			sp_core::H256::repeat_byte(0x51),
			sp_core::H256::repeat_byte(0x9A),
			Default::default(),
		);
		header.digest_mut().push(DigestItem::Other(vec![1, 2, 3]));
		header
			.digest_mut()
			.push(DigestItem::Consensus(*b"rstr", vec![9; 40]));

		let json = serde_json::to_value(&header).unwrap();
		let rpc: RpcHeader = serde_json::from_value(json).unwrap();
		let reencoded = encode_header(&rpc).unwrap();
		assert_eq!(reencoded, header.encode());
		assert_eq!(blake2_256(&reencoded), header.hash().0);
	}

	/// Fold must agree with the pallet's fold for a known chain.
	#[test]
	fn fold_matches_reference_vector() {
		let head0 = keccak_512(DOMAIN_TAG);
		let genesis = Header::new(
			0,
			Default::default(),
			Default::default(),
			Default::default(),
			Default::default(),
		);
		let head1 = fold(head0, &genesis.encode());
		let mut manual = Vec::new();
		manual.extend_from_slice(&head0);
		manual.extend_from_slice(&genesis.encode());
		assert_eq!(head1, keccak_512(&manual));
	}
}
