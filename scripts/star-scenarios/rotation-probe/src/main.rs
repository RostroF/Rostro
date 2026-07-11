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
//!
//! (`force-roster` was removed with the NPoS cutover: the roster is
//! produced by pallet-staking's election, not a sudo bootstrap.)
//!
//! Exit codes: 0 ok, 1 error, 2 timeout, 3 extrinsic rejected.

use anyhow::{bail, Context, Result};
use codec::{Decode, Encode};

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

fn parse_hex64(s: &str) -> Result<[u8; 64]> {
	let bytes = hex::decode(s.trim_start_matches("0x")).context("hex decode")?;
	bytes.as_slice().try_into().context("expected 64 bytes")
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
	// PQ cutover: the GRANDPA session key is the 64-byte hybrid
	// (ed25519 + SLH-DSA-SHA2-128f). Derivation MUST match the node's
	// one-seed HKDF expansion, so this goes through rostro-hybrid-sig
	// (the same leaf sp_core::rostro_hybrid wraps), never raw dalek.
	let sk = rostro_hybrid_sig::HybridSigningKey::from_seed(&seed);
	let new_pub: [u8; 64] = sk
		.verifying_key()
		.to_vec()
		.try_into()
		.expect("hybrid public is 64 bytes");

	// Keystore insertion is NOT done here: gemini validators (correctly)
	// refuse --rpc-methods=unsafe, so author_insertKey is unavailable. The
	// caller must have placed the secret in the node's file keystore first
	// (`gemini-node key insert --suri 0x<seed> --key-type gran --scheme
	// rostro-hybrid` against the running node's base path — LocalKeystore scans
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

	// 2. Proof of possession: each session key signs "POP_" ++
	//    owner-account bytes (sp_core::proof_of_possession::
	//    statement_of_ownership layout). Since NPoS (spec 106) the
	//    SessionKeys struct is { sassafras, grandpa }, and the proof is
	//    the SCALE tuple of one PoP per key in field order. The sassafras
	//    (bandersnatch) key is NOT rotated here — same public re-signed;
	//    lineage's reuse ban covers GRANDPA keys only. Its pair derives
	//    from --sass-suri (default: --suri, matching the star scripts'
	//    `key insert --key-type sass --suri //Name`). The hybrid GRANDPA
	//    PoP goes through TraitPair::sign, which frames under the
	//    finality-vote domain — mirror that exactly or the runtime
	//    rejects the registration.
	let mut statement = b"POP_".to_vec();
	statement.extend_from_slice(&account.0);

	let sass_suri = args.get("--sass-suri").unwrap_or_else(|| suri.clone());
	let band_pair = <sp_core::bandersnatch::Pair as sp_core::Pair>::from_string(&sass_suri, None)
		.map_err(|e| anyhow::anyhow!("bad --sass-suri: {e:?}"))?;
	let band_pub = <sp_core::bandersnatch::Pair as sp_core::Pair>::public(&band_pair);
	let band_pop = <sp_core::bandersnatch::Pair as sp_core::Pair>::sign(&band_pair, &statement);

	let pop = sk
		.sign(rostro_hybrid_sig::FINALITY_VOTE_DOMAIN, &statement)
		.expect("domain is under the 255-byte limit")
		.to_vec(); // 17152 bytes

	// 3. Account-signed Session::set_keys(SessionKeys, proof).
	let api = connect(&ws).await?;
	let metadata = api.metadata();
	let (p, c) = call_indices(&metadata, "Session", "set_keys")?;
	let mut call = vec![p, c];
	call.extend_from_slice(band_pub.as_ref()); // SessionKeys.sassafras: [u8; 32]
	call.extend_from_slice(&new_pub); // SessionKeys.grandpa: [u8; 64]
	let mut proof: Vec<u8> = Vec::with_capacity(64 + pop.len());
	proof.extend_from_slice(band_pop.as_ref()); // tuple.0: bandersnatch sig, 64 raw
	proof.extend_from_slice(&pop); // tuple.1: hybrid sig, 17152 raw
	proof.encode_to(&mut call); // proof: Vec<u8>
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

	// The runtime verifies AuthoritySignature via the sp-core hybrid
	// scheme, which frames every message under the finality-vote domain;
	// the probe must sign the same way or honest evidence is rejected.
	let sk = rostro_hybrid_sig::HybridSigningKey::from_seed(&seed);
	let key: [u8; 64] = sk
		.verifying_key()
		.to_vec()
		.try_into()
		.expect("hybrid public is 64 bytes");
	let signature = sk
		.sign(
			rostro_hybrid_sig::FINALITY_VOTE_DOMAIN,
			&grandpa_domain_payload(&message, round, set_id),
		)
		.expect("domain is under the 255-byte limit")
		.to_vec();

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
	let key = parse_hex64(&args.require("--key")?)?;
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

/// NPoS joiner driver: account-signed Staking::bond + Staking::validate.
/// Combined with `rotate` (which registers the session keys) this is the
/// full "candidate validator" flow the VM-farm scenarios drive; the era
/// election then decides admission. Bond value in ROS (12 decimals applied
/// here).
async fn cmd_bond_validate(args: Args) -> Result<()> {
	const ROSTO: u128 = 1_000_000_000_000;
	let ws = args.get_or("--ws", "ws://127.0.0.1:9944");
	let signer = dev_keypair(&args.require("--suri")?)?;
	let bond_ros: u128 = args.get_or("--bond-ros", "100000").parse()?;

	let api = connect(&ws).await?;
	let metadata = api.metadata();

	// Staking::bond(#[compact] value, payee: RewardDestination::Staked)
	let (p, c) = call_indices(&metadata, "Staking", "bond")?;
	let mut call = vec![p, c];
	codec::Compact(bond_ros * ROSTO).encode_to(&mut call);
	call.push(0); // RewardDestination::Staked
	submit(&api, RawCall(call), &signer, 90).await?;
	eprintln!("[probe] bonded {bond_ros} ROS (payee: Staked)");

	// Staking::validate(ValidatorPrefs { #[compact] commission, blocked })
	let commission_percent: u32 = args.get_or("--commission", "10").parse()?;
	let (p, c) = call_indices(&metadata, "Staking", "validate")?;
	let mut call = vec![p, c];
	codec::Compact(commission_percent.saturating_mul(10_000_000)).encode_to(&mut call); // Perbill
	call.push(0); // blocked: false
	submit(&api, RawCall(call), &signer, 90).await?;
	eprintln!("[probe] validating (commission {commission_percent}%)");
	println!(
		"{}",
		serde_json::json!({ "bonded_ros": bond_ros, "commission_percent": commission_percent })
	);
	Ok(())
}

/// Staking era/count state: ActiveEra, CurrentEra, ValidatorCount, and the
/// staking Validators (candidate) key count.
async fn cmd_staking_state(args: Args) -> Result<()> {
	let ws = args.get_or("--ws", "ws://127.0.0.1:9944");
	let api = connect(&ws).await?;

	// ActiveEra: Option storage of ActiveEraInfo { index: u32, start: Option<u64> }
	let active = fetch_storage(&api, "Staking", "ActiveEra", vec![]).await?;
	let active_era = active.as_deref().map(|mut b| {
		let info: (u32, Option<u64>) =
			Decode::decode(&mut b).expect("ActiveEraInfo layout: (u32, Option<u64>)");
		info.0
	});
	let current = fetch_storage(&api, "Staking", "CurrentEra", vec![]).await?;
	let current_era = current.as_deref().map(|mut b| u32::decode(&mut b).expect("u32"));
	let count = fetch_storage(&api, "Staking", "ValidatorCount", vec![]).await?;
	let validator_count = count.as_deref().map(|mut b| u32::decode(&mut b).expect("u32"));

	println!(
		"{}",
		serde_json::json!({
			"active_era": active_era,
			"current_era": current_era,
			"validator_count": validator_count,
		})
	);
	Ok(())
}

/// sudo(Staking::set_validator_count(#[compact] new)) — the churn knob the
/// farm scenarios turn to admit waiting candidates.
async fn cmd_set_validator_count(args: Args) -> Result<()> {
	let ws = args.get_or("--ws", "ws://127.0.0.1:9944");
	let signer = dev_keypair(&args.get_or("--suri", "//Alice"))?;
	let count: u32 = args.require("--count")?.parse()?;

	let api = connect(&ws).await?;
	let metadata = api.metadata();
	let (sudo_p, sudo_c) = call_indices(&metadata, "Sudo", "sudo")?;
	let (st_p, st_c) = call_indices(&metadata, "Staking", "set_validator_count")?;
	let mut call = vec![sudo_p, sudo_c, st_p, st_c];
	codec::Compact(count).encode_to(&mut call);
	submit(&api, RawCall(call), &signer, 90).await?;
	println!("{}", serde_json::json!({ "validator_count": count }));
	Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
	let mut argv: Vec<String> = std::env::args().skip(1).collect();
	if argv.is_empty() {
		bail!("usage: rotation-probe <rotate|bond-validate|set-validator-count|canary|lineage-key|session-state|wait-event|derive> [flags]");
	}
	let cmd = argv.remove(0);
	let args = Args(argv);
	match cmd.as_str() {
		"rotate" => cmd_rotate(args).await,
		"bond-validate" => cmd_bond_validate(args).await,
		"set-validator-count" => cmd_set_validator_count(args).await,
		"staking-state" => cmd_staking_state(args).await,
		"canary" => cmd_canary(args).await,
		"lineage-key" => cmd_lineage_key(args).await,
		"session-state" => cmd_session_state(args).await,
		"disabled" => cmd_disabled(args).await,
		"wait-event" => cmd_wait_event(args).await,
		"derive" => cmd_derive(args),
		other => bail!("unknown subcommand: {other}"),
	}
}

/// Derive the 64-byte hybrid GRANDPA public key and its 32-byte master
/// seed for a suri (`//Alice`) or a raw `--seed 0x…`. Replaces the
/// ed25519 `key inspect` the classical scenario used — the hybrid public
/// has no account identity, so `gemini-node key inspect` rejects it, and
/// this derives through the exact sp_core::rostro_hybrid path the node
/// keystore uses.
fn cmd_derive(args: Args) -> Result<()> {
	use sp_core::crypto::Pair as _;
	let (pair, seed): (sp_core::rostro_hybrid::Pair, [u8; 32]) = match args.get("--seed") {
		Some(hex_seed) => {
			let seed = parse_hex32(&hex_seed)?;
			(sp_core::rostro_hybrid::Pair::from_seed(&seed), seed)
		},
		None => {
			let suri = args.require("--suri")?;
			let (pair, opt_seed) =
				sp_core::rostro_hybrid::Pair::from_string_with_seed(&suri, None)
					.map_err(|e| anyhow::anyhow!("suri derive: {e:?}"))?;
			(pair, opt_seed.expect("dev suri yields a seed"))
		},
	};
	let public = pair.public();
	println!(
		"{}",
		serde_json::json!({
			"public": format!("0x{}", hex::encode(<sp_core::rostro_hybrid::Public as AsRef<[u8]>>::as_ref(&public))),
			"seed": format!("0x{}", hex::encode(seed)),
		})
	);
	Ok(())
}
