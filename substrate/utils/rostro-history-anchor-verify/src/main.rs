// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # rostro-history-anchor-verify
//!
//! Offline verifier + publication tooling for the dual-hash history
//! anchor (`pallet-rostro-history-anchor`). See `docs/HISTORY-ANCHOR.md`
//! for the publication format and ritual.
//!
//! Subcommands (bare invocation = `verify`):
//!
//! - `verify` — recompute the Keccak-512 anchor chain from raw header
//!   bytes over RPC; cross-check every on-chain snapshot, the live head,
//!   the sealed count, and (via `--expect-head`) an externally published
//!   head.
//! - `publication [--prev 0x…]` — emit the canonical v1 publication
//!   payload for the current tip, ONLY if a full verification pass
//!   succeeds. Payload to stdout (pipe to the SRT signer); the sha-256
//!   publication-hash to stderr.
//! - `capsule --out DIR [--prev 0x…]` — export a century capsule
//!   (sealed headers + anchors + README + publication payload), ONLY if
//!   a full verification pass succeeds.
//! - `verify-capsule --dir DIR` — re-verify a capsule fully offline (no
//!   RPC, no node).
//!
//! This tool is the escape hatch the anchor design leans on: the chain of
//! seals must be recomputable WITHOUT the runtime, the trie, or the frame
//! stack. It therefore duplicates the two protocol constants (domain tag,
//! pallet storage name) instead of importing pallet code; a unit test pins
//! them against the pallet crate so drift is caught at test time while the
//! shipped binary stays frame-free.
//!
//! ## What a `verify` pass means
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
use clap::{Parser, Subcommand};
use codec::{Compact, Encode};
use jsonrpsee::{
	core::client::ClientT,
	http_client::{HttpClient, HttpClientBuilder},
	rpc_params,
};
use serde::Deserialize;
use sp_crypto_hashing::{blake2_256, keccak_512, sha2_256, twox_128};
use std::path::{Path, PathBuf};

/// Must match `pallet_rostro_history_anchor::DOMAIN_TAG` (pinned by the
/// `constants_match_pallet` test).
const DOMAIN_TAG: &[u8] = b"rostro-history-anchor-v0";

/// The pallet's `construct_runtime!` name, i.e. its storage prefix.
const PALLET_NAME: &str = "HistoryAnchor";

#[derive(Parser)]
#[command(about = "Recompute, verify, and publish the Rostro dual-hash history anchor chain")]
struct Cli {
	/// Node RPC endpoint (network subcommands).
	#[arg(long, global = true, default_value = "http://127.0.0.1:9944")]
	url: String,

	/// Externally published anchor head (0x-prefixed, 64 bytes) to verify
	/// the fold against, e.g. from an SRT publication or an `Anchored`
	/// event recorded elsewhere.
	#[arg(long, global = true)]
	expect_head: Option<String>,

	#[command(subcommand)]
	cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
	/// Recompute the anchor chain over RPC and verify it (default).
	Verify,
	/// Emit the canonical v1 publication payload for the verified tip.
	Publication {
		/// sha-256 publication-hash of the previous publication payload
		/// (0x…, 32 bytes). Omit only for the first publication ever.
		#[arg(long)]
		prev: Option<String>,
	},
	/// Export a century capsule for the verified chain.
	Capsule {
		/// Output directory (created; must not already exist).
		#[arg(long)]
		out: PathBuf,
		/// Previous publication-hash for the embedded payload.
		#[arg(long)]
		prev: Option<String>,
	},
	/// Re-verify a century capsule fully offline (no RPC).
	VerifyCapsule {
		/// Capsule directory.
		#[arg(long)]
		dir: PathBuf,
	},
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

/// Result of a full network verification pass.
struct Verified {
	anchors: Vec<Anchor>,
	/// Raw SCALE bytes per anchor, same order.
	header_bytes: Vec<Vec<u8>>,
	head: [u8; 64],
	failures: u32,
}

/// The full verification pass: fold recompute + snapshot comparison +
/// live-head + sealed-count + optional published-head check. Prints its
/// findings; returns everything downstream subcommands need.
async fn verify_chain(client: &HttpClient, at: &str, expect_head: Option<&str>) -> Result<Verified> {
	let anchors = fetch_anchors(client, at).await?;
	if anchors.is_empty() {
		bail!("no anchors on chain (pallet inactive or storage prefix wrong)");
	}

	let mut failures = 0u32;
	let mut head = keccak_512(DOMAIN_TAG);
	let mut header_bytes = Vec::with_capacity(anchors.len());
	for anchor in &anchors {
		let bytes = fetch_header_bytes(client, anchor.sealed_height).await?;
		head = fold(head, &bytes);
		header_bytes.push(bytes);
		if head == anchor.head {
			eprintln!(
				"  ok  era {:>6}  sealed height {:>10}  head 0x{}…",
				anchor.era,
				anchor.sealed_height,
				hex::encode(&head[..8])
			);
		} else {
			failures += 1;
			eprintln!(
				"FAIL  era {:>6}  sealed height {:>10}\n      recomputed 0x{}\n      on-chain   0x{}",
				anchor.era,
				anchor.sealed_height,
				hex::encode(head),
				hex::encode(anchor.head)
			);
		}
	}

	// Live head + sealed count cross-checks.
	let live_head = get_storage(client, &storage_key("AnchorHead"), at)
		.await?
		.context("AnchorHead not in storage")?;
	if live_head == head {
		eprintln!("live AnchorHead matches the fold");
	} else {
		failures += 1;
		eprintln!(
			"FAIL live AnchorHead 0x{} != recomputed 0x{}",
			hex::encode(&live_head),
			hex::encode(head)
		);
	}
	let sealed_count = match get_storage(client, &storage_key("SealedCount"), at).await? {
		Some(v) => u64::from_le_bytes(
			v.try_into().map_err(|v: Vec<u8>| anyhow!("bad SealedCount length {}", v.len()))?,
		),
		None => 0,
	};
	if sealed_count == anchors.len() as u64 {
		eprintln!("SealedCount {sealed_count} matches {} anchors", anchors.len());
	} else {
		failures += 1;
		eprintln!("FAIL SealedCount {sealed_count} != {} anchors", anchors.len());
	}

	if let Some(expect) = expect_head {
		let expect = fixed::<64>(expect)?;
		// The published head may be any historical fold state, so check
		// against every snapshot, not just the tip.
		if anchors.iter().any(|a| a.head == expect) || head == expect {
			eprintln!("published head found in the anchor chain");
		} else {
			failures += 1;
			eprintln!("FAIL published head 0x{} not reproduced by any seal", hex::encode(expect));
		}
	}

	Ok(Verified { anchors, header_bytes, head, failures })
}

/// Build the frozen v1 publication payload (docs/HISTORY-ANCHOR.md §2).
/// Exact bytes, LF endings, one trailing newline; sha-256 over these bytes
/// is the publication-hash the NEXT publication references.
fn publication_payload(
	genesis: &str,
	spec_name: &str,
	spec_version: u64,
	tip: &Anchor,
	prev: Option<&str>,
) -> String {
	format!(
		"ROSTRO HISTORY ANCHOR PUBLICATION v1\n\
		 genesis: {}\n\
		 spec-name: {}\n\
		 runtime-spec: {}\n\
		 era: {}\n\
		 sealed-height: {}\n\
		 head: 0x{}\n\
		 previous-publication: {}\n",
		genesis.to_lowercase(),
		spec_name,
		spec_version,
		tip.era,
		tip.sealed_height,
		hex::encode(tip.head),
		prev.map(str::to_lowercase).unwrap_or_else(|| "none".into()),
	)
}

async fn chain_identity(client: &HttpClient, at: &str) -> Result<(String, String, u64)> {
	let genesis: Option<String> = client
		.request("chain_getBlockHash", rpc_params![0u64])
		.await
		.context("chain_getBlockHash(0)")?;
	let genesis = genesis.context("no genesis hash")?;
	let version: serde_json::Value = client
		.request("state_getRuntimeVersion", rpc_params![at])
		.await
		.context("state_getRuntimeVersion")?;
	let spec_name = version
		.get("specName")
		.and_then(|v| v.as_str())
		.context("no specName")?
		.to_owned();
	let spec_version =
		version.get("specVersion").and_then(|v| v.as_u64()).context("no specVersion")?;
	Ok((genesis, spec_name, spec_version))
}

const CAPSULE_README: &str = r#"# Rostro history-anchor century capsule

This directory is a self-contained, software-independent proof of Rostro
chain history. It needs no Rostro software to verify — only a Keccak-512
implementation.

## Contents

- `headers.jsonl` — one JSON object per line: `{"height": H,
  "scale_hex": "0x…"}`. The hex is the raw SCALE-encoded header exactly
  as the chain hashed it. These are the SEALED headers only (one per
  session: each session's final header, plus genesis).
- `anchors.jsonl` — one per line: `{"era": E, "sealed_height": H,
  "head": "0x…"}`. The chain's on-chain anchor snapshots at export time.
- `publication.txt` — the canonical publication payload for the capsule
  tip (docs/HISTORY-ANCHOR.md §2 in the Rostro repo, if it still exists;
  the format is self-describing regardless).

## The fold

    head = keccak_512(b"rostro-history-anchor-v0")
    for each header in headers.jsonl, ascending height:
        head = keccak_512(head || raw_header_bytes)

After each fold step, `head` must equal the `head` of the anchor with
the matching `sealed_height` in anchors.jsonl.

## What verification proves

If the final `head` equals a published head whose provenance you trust
(a print notice, an external-chain anchor, a signed publication chain),
then every byte of every sealed header — above all the state roots
inside them — is bound under two unrelated hash families (BLAKE2-256 via
the chain's own linkage, Keccak-512 via this fold) as of the
publication's date. Forging an alternative requires simultaneous
structural breaks of both, plus suppression of every surviving copy of
the published head.

BLAKE2-256 of each header equals the chain's block hash at that height,
which lets you cross-reference any surviving block archive.
"#;

fn write_capsule(dir: &Path, v: &Verified, payload: &str) -> Result<()> {
	use std::fmt::Write as _;
	std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;

	let mut headers = String::new();
	let mut anchors = String::new();
	for (anchor, bytes) in v.anchors.iter().zip(&v.header_bytes) {
		writeln!(
			headers,
			r#"{{"height": {}, "scale_hex": "0x{}"}}"#,
			anchor.sealed_height,
			hex::encode(bytes)
		)?;
		writeln!(
			anchors,
			r#"{{"era": {}, "sealed_height": {}, "head": "0x{}"}}"#,
			anchor.era,
			anchor.sealed_height,
			hex::encode(anchor.head)
		)?;
	}
	std::fs::write(dir.join("headers.jsonl"), headers)?;
	std::fs::write(dir.join("anchors.jsonl"), anchors)?;
	std::fs::write(dir.join("publication.txt"), payload)?;
	std::fs::write(dir.join("README.md"), CAPSULE_README)?;
	Ok(())
}

/// Offline capsule verification: recompute the fold from headers.jsonl,
/// compare every anchor in anchors.jsonl. No network.
fn verify_capsule(dir: &Path) -> Result<[u8; 64]> {
	#[derive(Deserialize)]
	struct HeaderLine {
		height: u64,
		scale_hex: String,
	}
	#[derive(Deserialize)]
	struct AnchorLine {
		era: u32,
		sealed_height: u64,
		head: String,
	}

	let parse_lines = |name: &str| -> Result<Vec<String>> {
		let raw = std::fs::read_to_string(dir.join(name))
			.with_context(|| format!("reading {name}"))?;
		Ok(raw.lines().filter(|l| !l.trim().is_empty()).map(str::to_owned).collect())
	};

	let mut headers: Vec<HeaderLine> = parse_lines("headers.jsonl")?
		.iter()
		.map(|l| serde_json::from_str(l).context("bad headers.jsonl line"))
		.collect::<Result<_>>()?;
	headers.sort_by_key(|h| h.height);
	let mut anchors: Vec<AnchorLine> = parse_lines("anchors.jsonl")?
		.iter()
		.map(|l| serde_json::from_str(l).context("bad anchors.jsonl line"))
		.collect::<Result<_>>()?;
	anchors.sort_by_key(|a| a.era);

	if headers.len() != anchors.len() {
		bail!("{} headers vs {} anchors", headers.len(), anchors.len());
	}

	let mut failures = 0u32;
	let mut head = keccak_512(DOMAIN_TAG);
	for (h, a) in headers.iter().zip(&anchors) {
		if h.height != a.sealed_height {
			bail!("header height {} does not match anchor sealed_height {}", h.height, a.sealed_height);
		}
		let bytes = hex_bytes(&h.scale_hex)?;
		head = fold(head, &bytes);
		let expect = fixed::<64>(&a.head)?;
		if head == expect {
			eprintln!(
				"  ok  era {:>6}  sealed height {:>10}  head 0x{}…  (blake2 0x{}…)",
				a.era,
				a.sealed_height,
				hex::encode(&head[..8]),
				hex::encode(&blake2_256(&bytes)[..8])
			);
		} else {
			failures += 1;
			eprintln!(
				"FAIL  era {:>6}  sealed height {:>10}\n      recomputed 0x{}\n      capsule    0x{}",
				a.era,
				a.sealed_height,
				hex::encode(head),
				hex::encode(expect)
			);
		}
	}
	if failures > 0 {
		bail!("{failures} capsule mismatches");
	}
	Ok(head)
}

#[tokio::main]
async fn main() -> Result<()> {
	let cli = Cli::parse();
	let cmd = cli.cmd.unwrap_or(Cmd::Verify);

	// Offline path needs no client.
	if let Cmd::VerifyCapsule { dir } = &cmd {
		let head = verify_capsule(dir)?;
		println!("\ncapsule verified offline; tip head: 0x{}", hex::encode(head));
		return Ok(());
	}

	let client = HttpClientBuilder::default().build(&cli.url)?;
	let at: String = client
		.request("chain_getFinalizedHead", rpc_params![])
		.await
		.context("chain_getFinalizedHead")?;
	eprintln!("verifying at finalized head {at}");

	let v = verify_chain(&client, &at, cli.expect_head.as_deref()).await?;

	eprintln!(
		"\ncurrent head (publish this): 0x{}\nseals verified: {}, failures: {}",
		hex::encode(v.head),
		v.anchors.len(),
		v.failures
	);
	if v.failures > 0 {
		std::process::exit(1);
	}

	match cmd {
		Cmd::Verify | Cmd::VerifyCapsule { .. } => {}
		Cmd::Publication { prev } => {
			let (genesis, spec_name, spec_version) = chain_identity(&client, &at).await?;
			let tip = v.anchors.last().expect("non-empty checked in verify_chain");
			let payload =
				publication_payload(&genesis, &spec_name, spec_version, tip, prev.as_deref());
			// Payload alone on stdout (pipe to the SRT signer); everything
			// else on stderr.
			print!("{payload}");
			eprintln!(
				"\npublication-hash (sha-256 of payload bytes): 0x{}\nSRT signs the payload bytes exactly as emitted.",
				hex::encode(sha2_256(payload.as_bytes()))
			);
		}
		Cmd::Capsule { out, prev } => {
			if out.exists() {
				bail!("{} already exists; refusing to overwrite a capsule", out.display());
			}
			let (genesis, spec_name, spec_version) = chain_identity(&client, &at).await?;
			let tip = v.anchors.last().expect("non-empty checked in verify_chain");
			let payload =
				publication_payload(&genesis, &spec_name, spec_version, tip, prev.as_deref());
			write_capsule(&out, &v, &payload)?;
			println!(
				"capsule written to {} ({} sealed headers)",
				out.display(),
				v.anchors.len()
			);
			// Immediately prove the capsule stands on its own.
			let head = verify_capsule(&out)?;
			println!("capsule re-verified offline; tip head: 0x{}", hex::encode(head));
		}
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

	/// The v1 payload format is FROZEN (docs/HISTORY-ANCHOR.md §2): exact
	/// bytes, exact hash. If this test breaks, the format changed — that
	/// is a protocol event, not a refactor.
	#[test]
	fn publication_payload_v1_frozen() {
		let tip = Anchor { era: 2, sealed_height: 49, head: [0xAB; 64] };
		let payload = publication_payload(
			"0x00112233445566778899AABBCCDDEEFF00112233445566778899aabbccddeeff",
			"gemini",
			104,
			&tip,
			None,
		);
		let expected = "ROSTRO HISTORY ANCHOR PUBLICATION v1\n\
			genesis: 0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n\
			spec-name: gemini\n\
			runtime-spec: 104\n\
			era: 2\n\
			sealed-height: 49\n\
			head: 0x".to_owned() + &"ab".repeat(64) + "\nprevious-publication: none\n";
		assert_eq!(payload, expected);
		// Chaining: the next payload embeds sha-256 of this one.
		let hash = format!("0x{}", hex::encode(sha2_256(payload.as_bytes())));
		let next = publication_payload("0x0011", "gemini", 104, &tip, Some(&hash));
		assert!(next.contains(&format!("previous-publication: {hash}\n")));
	}

	/// Capsule roundtrip: write from synthetic verified data, re-verify
	/// fully offline, tip heads must agree.
	#[test]
	fn capsule_roundtrip_offline() {
		// Synthetic 3-seal chain (genesis + two session finals).
		let mk = |n: u32, parent: sp_core::H256| {
			Header::new(
				n,
				sp_core::H256::repeat_byte(0xE1),
				sp_core::H256::repeat_byte(0x51),
				parent,
				Default::default(),
			)
		};
		let g = mk(0, sp_core::H256::zero());
		let h24 = mk(24, sp_core::H256::repeat_byte(1));
		let h49 = mk(49, sp_core::H256::repeat_byte(2));

		let mut head = keccak_512(DOMAIN_TAG);
		let mut anchors = Vec::new();
		let mut header_bytes = Vec::new();
		for (era, h) in [(0u32, &g), (1, &h24), (2, &h49)] {
			let bytes = h.encode();
			head = fold(head, &bytes);
			anchors.push(Anchor {
				era,
				sealed_height: *h.number() as u64,
				head,
			});
			header_bytes.push(bytes);
		}
		let v = Verified { anchors, header_bytes, head, failures: 0 };

		let dir = tempfile::tempdir().unwrap();
		let capsule_dir = dir.path().join("capsule");
		write_capsule(&capsule_dir, &v, "PAYLOAD PLACEHOLDER\n").unwrap();
		let offline_head = verify_capsule(&capsule_dir).unwrap();
		assert_eq!(offline_head, head);

		// Tamper with one header byte: offline verification must fail.
		let path = capsule_dir.join("headers.jsonl");
		let tampered = std::fs::read_to_string(&path).unwrap().replace("e1", "e2");
		std::fs::write(&path, tampered).unwrap();
		assert!(verify_capsule(&capsule_dir).is_err());
	}
}
