// SPDX-License-Identifier: Apache-2.0
//! rotation-probe — star-scenario driver for the consensus-key lifecycle
//! (docs/CONSENSUS-KEY-LIFECYCLE.md workstream 1 P3).
//!
//! Subcommands:
//!   rotate        insert a fresh ed25519 GRANDPA key into the target
//!                 node's keystore (author_insertKey) and register it via
//!                 account-signed Session::set_keys with a real
//!                 proof-of-possession. Prints the new key (and its seed,
//!                 so a later `canary` can sign with it once retired —
//!                 lab-only ergonomics, obviously).
//!   canary        sign a GRANDPA-domain preimage (message ++ round ++
//!                 set_id, the localized_payload layout) with a retired
//!                 key's seed and submit
//!                 KeyLineage::report_retired_key_signature.
//!   lineage-key   print the lineage KeyRecord for a GRANDPA key.
//!   session-state print current session index, GRANDPA set id, session
//!                 validators.
//!   wait-event    watch finalized blocks until Pallet::Variant appears
//!                 (exit 0) or timeout (exit 2).
//!   force-roster  sudo(KeyLineage::force_roster([...])) — live-chain
//!                 roster bootstrap.
//!
//! Exit codes: 0 ok, 1 error, 2 timeout, 3 extrinsic rejected.

use anyhow::{bail, Context, Result};
use codec::{Compact, Decode, Encode};
use ed25519_dalek::{Signer as _, SigningKey};
use subxt::utils::AccountId32;
use subxt::{OnlineClient, SubstrateConfig};
use subxt_rpcs::{rpc_params, RpcClient};
use subxt_signer::sr25519::Keypair;
use subxt_signer::SecretUri;

/// Pre-encoded call bytes (same trick as the lab's lab-sudo: the dynamic
/// Value path heap-allocates one Value per byte). Pallet/call indices come
/// from live metadata, not hardcoded numbers.
struct RawCall(Vec<u8>);

impl subxt::tx::Payload for RawCall {
	fn encode_call_data_to(
		&self,
		_metadata: &subxt::Metadata,
		out: &mut Vec<u8>,
	) -> Result<(), subxt::ext::subxt_core::Error> {
		out.extend_from_slice(&self.0);
		Ok(())
	}
}

fn call_indices(metadata: &subxt::Metadata, pallet: &str, call: &str) -> Result<(u8, u8)> {
	let p = metadata
		.pallet_by_name(pallet)
		.with_context(|| format!("pallet {pallet} not in metadata"))?;
	let c = p
		.call_variant_by_name(call)
		.with_context(|| format!("call {pallet}::{call} not in metadata"))?;
	Ok((p.index(), c.index))
}

/// Mirror of pallet-rostro-key-lineage's storage types (SCALE layout is the
/// contract; field names here are for JSON output only).
#[derive(Decode, Debug)]
struct LifecyclePoint {
	era: u32,
	session: u32,
	set_id: u64,
}
#[derive(Decode, Debug)]
struct KeyRecord {
	owner: AccountId32,
	registered_era: u32,
	activated: Option<LifecyclePoint>,
	retired: Option<LifecyclePoint>,
}

struct Args(Vec<String>);
impl Args {
	fn get(&self, flag: &str) -> Option<String> {
		self.0
			.iter()
			.position(|a| a == flag)
			.and_then(|i| self.0.get(i + 1).cloned())
	}
	fn get_or(&self, flag: &str, default: &str) -> String {
		self.get(flag).unwrap_or_else(|| default.to_string())
	}
	fn require(&self, flag: &str) -> Result<String> {
		self.get(flag).with_context(|| format!("missing required flag {flag}"))
	}
}

fn dev_keypair(suri: &str) -> Result<Keypair> {
	let uri: SecretUri = suri.parse().context("bad --suri")?;
	Keypair::from_uri(&uri).context("keypair from suri")
}

fn parse_hex32(s: &str) -> Result<[u8; 32]> {
	let b = hex::decode(s.trim_start_matches("0x")).context("bad hex")?;
	b.try_into().map_err(|_| anyhow::anyhow!("expected 32 bytes"))
}

fn random_seed() -> Result<[u8; 32]> {
	use std::io::Read;
	let mut f = std::fs::File::open("/dev/urandom").context("open /dev/urandom")?;
	let mut seed = [0u8; 32];
	f.read_exact(&mut seed)?;
	Ok(seed)
}

/// GRANDPA signing domain, byte-identical to
/// sp_consensus_grandpa::localized_payload(round, set_id, message).
fn grandpa_domain_payload(message: &[u8], round: u64, set_id: u64) -> Vec<u8> {
	let mut payload = message.to_vec();
	round.encode_to(&mut payload);
	set_id.encode_to(&mut payload);
	payload
}

async fn connect(ws: &str) -> Result<OnlineClient<SubstrateConfig>> {
	OnlineClient::<SubstrateConfig>::from_url(ws)
		.await
		.context("OnlineClient::from_url failed (node up? RPC reachable?)")
}

async fn submit(
	api: &OnlineClient<SubstrateConfig>,
	call: RawCall,
	signer: &Keypair,
	timeout_secs: u64,
) -> Result<subxt::blocks::ExtrinsicEvents<SubstrateConfig>> {
	let params = subxt::config::DefaultExtrinsicParamsBuilder::<SubstrateConfig>::new()
		.immortal()
		.tip(0)
		.build();
	let progress = api
		.tx()
		.sign_and_submit_then_watch(&call, signer, params)
		.await
		.context("sign_and_submit_then_watch failed")?;
	eprintln!("[probe] submitted {:?}", progress.extrinsic_hash());
	match tokio::time::timeout(
		std::time::Duration::from_secs(timeout_secs),
		progress.wait_for_finalized_success(),
	)
	.await
	{
		Ok(Ok(events)) => Ok(events),
		Ok(Err(e)) => {
			eprintln!("[probe] REJECTED: {e:?}");
			std::process::exit(3);
		},
		Err(_) => {
			eprintln!("[probe] TIMEOUT waiting for finalization ({timeout_secs}s)");
			std::process::exit(2);
		},
	}
}

async fn fetch_storage(
	api: &OnlineClient<SubstrateConfig>,
	pallet: &str,
	entry: &str,
	keys: Vec<subxt::dynamic::Value>,
) -> Result<Option<Vec<u8>>> {
	let addr = subxt::dynamic::storage(pallet, entry, keys);
	let thunk = api.storage().at_latest().await?.fetch(&addr).await?;
	Ok(thunk.map(|t| t.encoded().to_vec()))
}

async fn cmd_rotate(args: Args) -> Result<()> {
	let ws = args.get_or("--ws", "ws://127.0.0.1:9944");
	let suri = args.require("--suri")?;
	let signer = dev_keypair(&suri)?;
	let account = signer.public_key().to_account_id();

	let seed = match args.get("--seed") {
		Some(s) => parse_hex32(&s)?,
		None => random_seed()?,
	};
	let sk = SigningKey::from_bytes(&seed);
	let new_pub: [u8; 32] = sk.verifying_key().to_bytes();

	// Keystore insertion is NOT done here: gemini validators (correctly)
	// refuse --rpc-methods=unsafe, so author_insertKey is unavailable. The
	// caller must have placed the secret in the node's file keystore first
	// (`gemini-node key insert --suri 0x<seed> --key-type gran --scheme
	// ed25519` against the running node's base path — LocalKeystore scans
	// the directory per lookup, so live inserts are picked up). Opt-in
	// escape hatch for non-validator targets: --insert-rpc.
	if args.get("--insert-rpc").is_some() {
		let rpc = RpcClient::from_insecure_url(&ws).await.context("raw RPC connect")?;
		let suri_hex = format!("0x{}", hex::encode(seed));
		let pub_hex = format!("0x{}", hex::encode(new_pub));
		let _: () = rpc
			.request("author_insertKey", rpc_params!["gran", &suri_hex, &pub_hex])
			.await
			.context("author_insertKey failed (unsafe RPC not exposed)")?;
		eprintln!("[probe] inserted gran key 0x{} via RPC", hex::encode(new_pub));
	}

	// 2. Proof of possession: new key signs "POP_" ++ owner-account bytes
	//    (sp_core::proof_of_possession::statement_of_ownership layout).
	let mut statement = b"POP_".to_vec();
	statement.extend_from_slice(&account.0);
	let pop = sk.sign(&statement).to_bytes(); // 64 bytes

	// 3. Account-signed Session::set_keys(SessionKeys { grandpa }, proof).
	let api = connect(&ws).await?;
	let metadata = api.metadata();
	let (p, c) = call_indices(&metadata, "Session", "set_keys")?;
	let mut call = vec![p, c];
	call.extend_from_slice(&new_pub); // SessionKeys = { grandpa: [u8; 32] }
	pop.to_vec().encode_to(&mut call); // proof: Vec<u8>
	let events = submit(&api, RawCall(call), &signer, 90).await?;

	for ev in events.iter() {
		let ev = ev?;
		if ev.pallet_name() == "KeyLineage" {
			eprintln!("[probe] event: KeyLineage::{}", ev.variant_name());
		}
	}
	println!(
		"{}",
		serde_json::json!({
			"account": account.to_string(),
			"new_pub": format!("0x{}", hex::encode(new_pub)),
			"seed": format!("0x{}", hex::encode(seed)),
		})
	);
	Ok(())
}

async fn cmd_canary(args: Args) -> Result<()> {
	let ws = args.get_or("--ws", "ws://127.0.0.1:9944");
	let signer = dev_keypair(&args.get_or("--signer", "//Ferdie"))?;
	let seed = parse_hex32(&args.require("--retired-seed")?)?;
	let round: u64 = args.get_or("--round", "1").parse()?;
	let set_id: u64 = args.require("--set-id")?.parse()?;
	let message = args.get_or("--message", "forged-after-retirement").into_bytes();

	let sk = SigningKey::from_bytes(&seed);
	let key: [u8; 32] = sk.verifying_key().to_bytes();
	let signature = sk.sign(&grandpa_domain_payload(&message, round, set_id)).to_bytes();

	let api = connect(&ws).await?;
	let metadata = api.metadata();
	let (p, c) = call_indices(&metadata, "KeyLineage", "report_retired_key_signature")?;
	let mut call = vec![p, c];
	call.extend_from_slice(&key); // key: AuthorityId
	round.encode_to(&mut call); // round: u64
	set_id.encode_to(&mut call); // set_id: u64
	message.encode_to(&mut call); // message: BoundedVec<u8> (Vec-compatible)
	call.extend_from_slice(&signature); // signature: AuthoritySignature
	let events = submit(&api, RawCall(call), &signer, 90).await?;

	let mut accepted = false;
	for ev in events.iter() {
		let ev = ev?;
		if ev.pallet_name() == "KeyLineage" || ev.pallet_name() == "Offences" {
			eprintln!("[probe] event: {}::{}", ev.pallet_name(), ev.variant_name());
			if ev.variant_name() == "RetiredKeyEvidenceAccepted" {
				accepted = true;
			}
		}
	}
	if !accepted {
		bail!("finalized but no RetiredKeyEvidenceAccepted event");
	}
	println!(
		"{}",
		serde_json::json!({
			"key": format!("0x{}", hex::encode(key)),
			"set_id": set_id,
			"round": round,
			"accepted": true,
		})
	);
	Ok(())
}

async fn cmd_lineage_key(args: Args) -> Result<()> {
	let ws = args.get_or("--ws", "ws://127.0.0.1:9944");
	let key = parse_hex32(&args.require("--key")?)?;
	let api = connect(&ws).await?;
	let bytes = fetch_storage(
		&api,
		"KeyLineage",
		"Keys",
		vec![subxt::dynamic::Value::from_bytes(key)],
	)
	.await?
	.context("no lineage record for key")?;
	let record = KeyRecord::decode(&mut &bytes[..]).context("KeyRecord decode")?;
	let point = |p: &Option<LifecyclePoint>| {
		p.as_ref().map(|p| {
			serde_json::json!({ "era": p.era, "session": p.session, "set_id": p.set_id })
		})
	};
	println!(
		"{}",
		serde_json::json!({
			"owner": record.owner.to_string(),
			"registered_era": record.registered_era,
			"activated": point(&record.activated),
			"retired": point(&record.retired),
		})
	);
	Ok(())
}

async fn cmd_session_state(args: Args) -> Result<()> {
	let ws = args.get_or("--ws", "ws://127.0.0.1:9944");
	let api = connect(&ws).await?;
	let session = fetch_storage(&api, "Session", "CurrentIndex", vec![])
		.await?
		.map(|b| u32::decode(&mut &b[..]))
		.transpose()?
		.unwrap_or(0);
	let set_id = fetch_storage(&api, "Grandpa", "CurrentSetId", vec![])
		.await?
		.map(|b| u64::decode(&mut &b[..]))
		.transpose()?
		.unwrap_or(0);
	let validators = fetch_storage(&api, "Session", "Validators", vec![])
		.await?
		.map(|b| Vec::<AccountId32>::decode(&mut &b[..]))
		.transpose()?
		.unwrap_or_default();
	println!(
		"{}",
		serde_json::json!({
			"session": session,
			"set_id": set_id,
			"validators": validators.iter().map(|v| v.to_string()).collect::<Vec<_>>(),
			"validator_count": validators.len(),
		})
	);
	Ok(())
}

fn dev_account(name: &str) -> Result<AccountId32> {
	Ok(match name.to_lowercase().as_str() {
		"alice" => dev_keypair("//Alice")?.public_key().to_account_id(),
		"bob" => dev_keypair("//Bob")?.public_key().to_account_id(),
		"charlie" => dev_keypair("//Charlie")?.public_key().to_account_id(),
		"dave" => dev_keypair("//Dave")?.public_key().to_account_id(),
		"eve" => dev_keypair("//Eve")?.public_key().to_account_id(),
		"ferdie" => dev_keypair("//Ferdie")?.public_key().to_account_id(),
		other => other.parse().map_err(|e| anyhow::anyhow!("bad account {other}: {e:?}"))?,
	})
}

async fn cmd_disabled(args: Args) -> Result<()> {
	let ws = args.get_or("--ws", "ws://127.0.0.1:9944");
	let who = dev_account(&args.require("--account")?)?;
	let api = connect(&ws).await?;
	let bytes = fetch_storage(
		&api,
		"KeyLineage",
		"Disabled",
		vec![subxt::dynamic::Value::from_bytes(who.0)],
	)
	.await?;
	match bytes {
		None => println!("{}", serde_json::json!({ "disabled": false })),
		Some(b) => {
			// DisableRecord { reason: enum(u8), era: u32, session: u32 }
			let reason = match b.first() {
				Some(0) => "DeadlineMissed",
				Some(1) => "Offence",
				_ => "Unknown",
			};
			let era = u32::decode(&mut &b[1..5]).unwrap_or(0);
			let session = u32::decode(&mut &b[5..9]).unwrap_or(0);
			println!(
				"{}",
				serde_json::json!({
					"disabled": true, "reason": reason, "era": era, "session": session
				})
			);
		},
	}
	Ok(())
}

async fn cmd_wait_event(args: Args) -> Result<()> {
	let ws = args.get_or("--ws", "ws://127.0.0.1:9944");
	let pallet = args.require("--pallet")?;
	let variant = args.require("--variant")?;
	let timeout: u64 = args.get_or("--timeout", "300").parse()?;
	let api = connect(&ws).await?;

	let watch = async {
		let mut sub = api.blocks().subscribe_finalized().await?;
		while let Some(block) = sub.next().await {
			let block = block?;
			let events = block.events().await?;
			for ev in events.iter() {
				let ev = ev?;
				if ev.pallet_name() == pallet && ev.variant_name() == variant {
					println!(
						"{}",
						serde_json::json!({
							"block": block.number(),
							"pallet": pallet,
							"variant": variant,
						})
					);
					return Ok::<bool, anyhow::Error>(true);
				}
			}
		}
		Ok(false)
	};
	match tokio::time::timeout(std::time::Duration::from_secs(timeout), watch).await {
		Ok(Ok(true)) => Ok(()),
		Ok(Ok(false)) => bail!("finalized-block subscription ended without a match"),
		Ok(Err(e)) => Err(e),
		Err(_) => {
			eprintln!("[probe] TIMEOUT: no {pallet}::{variant} within {timeout}s");
			std::process::exit(2);
		},
	}
}

async fn cmd_force_roster(args: Args) -> Result<()> {
	let ws = args.get_or("--ws", "ws://127.0.0.1:9944");
	let signer = dev_keypair(&args.get_or("--suri", "//Alice"))?;
	let members: Vec<AccountId32> = args
		.require("--members")?
		.split(',')
		.map(|m| dev_account(m.trim()))
		.collect::<Result<_>>()?;

	let api = connect(&ws).await?;
	let metadata = api.metadata();
	let (sudo_p, sudo_c) = call_indices(&metadata, "Sudo", "sudo")?;
	let (kl_p, kl_c) = call_indices(&metadata, "KeyLineage", "force_roster")?;
	let mut call = vec![sudo_p, sudo_c, kl_p, kl_c];
	Compact(members.len() as u32).encode_to(&mut call);
	for m in &members {
		call.extend_from_slice(&m.0);
	}
	let events = submit(&api, RawCall(call), &signer, 90).await?;
	for ev in events.iter() {
		let ev = ev?;
		if ev.pallet_name() == "Sudo" || ev.pallet_name() == "KeyLineage" {
			eprintln!("[probe] event: {}::{}", ev.pallet_name(), ev.variant_name());
		}
	}
	println!("{}", serde_json::json!({ "roster": members.len() }));
	Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
	let mut argv: Vec<String> = std::env::args().skip(1).collect();
	if argv.is_empty() {
		bail!("usage: rotation-probe <rotate|canary|lineage-key|session-state|wait-event|force-roster> [flags]");
	}
	let cmd = argv.remove(0);
	let args = Args(argv);
	match cmd.as_str() {
		"rotate" => cmd_rotate(args).await,
		"canary" => cmd_canary(args).await,
		"lineage-key" => cmd_lineage_key(args).await,
		"session-state" => cmd_session_state(args).await,
		"disabled" => cmd_disabled(args).await,
		"wait-event" => cmd_wait_event(args).await,
		"force-roster" => cmd_force_roster(args).await,
		other => bail!("unknown subcommand: {other}"),
	}
}
