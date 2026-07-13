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
	// from_insecure_url: the VM farm drives plain ws:// over the lab LAN
	// (driver at 192.168.50.100); subxt's from_url rejects non-localhost
	// ws. Lab tool, lab posture.
	OnlineClient::<SubstrateConfig>::from_insecure_url(ws)
		.await
		.context("OnlineClient::from_insecure_url failed (node up? RPC reachable?)")
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
		Ok(Ok(events)) => {
			// Weight capture (farm churn runs record the real "gas" of
			// every exercised call): ExtrinsicSuccess carries
			// dispatch_info { weight { ref_time, proof_size }, class }.
			for ev in events.iter().flatten() {
				if ev.pallet_name() == "System" && ev.variant_name() == "ExtrinsicSuccess" {
					if let Ok(fields) = ev.field_values() {
						eprintln!("[probe] weight: {}", fields);
					}
				}
			}
			Ok(events)
		},
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

/// Best-block hash via raw RPC — subxt's `at_latest()` resolves to the
/// latest FINALIZED block, which on a finality-stalled chain (farm before
/// the 7/10 GRANDPA quorum) pins every read to genesis state. Reads that
/// diagnose a live-but-unfinalized chain must query at the BEST block.
async fn best_hash(ws: &str) -> Result<subxt::utils::H256> {
	let rpc = RpcClient::from_insecure_url(ws).await.context("raw RPC connect")?;
	let hash: String = rpc
		.request("chain_getBlockHash", rpc_params![])
		.await
		.context("chain_getBlockHash")?;
	hash.trim_start_matches("0x")
		.parse::<subxt::utils::H256>()
		.or_else(|_| {
			let b = hex::decode(hash.trim_start_matches("0x")).context("hash hex")?;
			let arr: [u8; 32] = b.as_slice().try_into().context("hash len")?;
			Ok(subxt::utils::H256::from(arr))
		})
}

async fn fetch_storage_at(
	api: &OnlineClient<SubstrateConfig>,
	at: subxt::utils::H256,
	pallet: &str,
	entry: &str,
	keys: Vec<subxt::dynamic::Value>,
) -> Result<Option<Vec<u8>>> {
	let addr = subxt::dynamic::storage(pallet, entry, keys);
	let thunk = api.storage().at(at).fetch(&addr).await?;
	Ok(thunk.map(|t| t.encoded().to_vec()))
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
	let at = best_hash(&ws).await?;
	let session = fetch_storage_at(&api, at, "Session", "CurrentIndex", vec![])
		.await?
		.map(|b| u32::decode(&mut &b[..]))
		.transpose()?
		.unwrap_or(0);
	let set_id = fetch_storage_at(&api, at, "Grandpa", "CurrentSetId", vec![])
		.await?
		.map(|b| u64::decode(&mut &b[..]))
		.transpose()?
		.unwrap_or(0);
	let validators = fetch_storage_at(&api, at, "Session", "Validators", vec![])
		.await?
		.map(|b| Vec::<AccountId32>::decode(&mut &b[..]))
		.transpose()?
		.unwrap_or_default();
	// Farm diagnostics: the on-chain sassafras epoch — under
	// EpochChangeExternalTrigger this should move in lockstep with the
	// session index; divergence = session wiring problem.
	let epoch_index = fetch_storage_at(&api, at, "Sassafras", "EpochIndex", vec![])
		.await?
		.map(|b| u64::decode(&mut &b[..]))
		.transpose()?
		.unwrap_or(0);
	let genesis_slot = fetch_storage_at(&api, at, "Sassafras", "GenesisSlot", vec![])
		.await?
		.map(|b| u64::decode(&mut &b[..]))
		.transpose()?;
	let current_slot = fetch_storage_at(&api, at, "Sassafras", "CurrentSlot", vec![])
		.await?
		.map(|b| u64::decode(&mut &b[..]))
		.transpose()?;
	println!(
		"{}",
		serde_json::json!({
			"session": session,
			"set_id": set_id,
			"epoch_index": epoch_index,
			"genesis_slot": genesis_slot,
			"current_slot": current_slot,
			"slots_since_genesis": current_slot
				.zip(genesis_slot)
				.map(|(c, g)| c.saturating_sub(g)),
			"validators": validators.iter().map(|v| v.to_string()).collect::<Vec<_>>(),
			"validator_count": validators.len(),
		})
	);
	Ok(())
}

fn dev_account(name: &str) -> Result<AccountId32> {
	// Match dev names case-insensitively, but parse a real address/suri from
	// the ORIGINAL string — SS58 is case-sensitive (lowercasing it corrupts
	// the checksum) and `//FarmVal09`-style suris carry case too.
	Ok(match name.to_lowercase().as_str() {
		"alice" => dev_keypair("//Alice")?.public_key().to_account_id(),
		"bob" => dev_keypair("//Bob")?.public_key().to_account_id(),
		"charlie" => dev_keypair("//Charlie")?.public_key().to_account_id(),
		"dave" => dev_keypair("//Dave")?.public_key().to_account_id(),
		"eve" => dev_keypair("//Eve")?.public_key().to_account_id(),
		"ferdie" => dev_keypair("//Ferdie")?.public_key().to_account_id(),
		_ if name.starts_with("//") => dev_keypair(name)?.public_key().to_account_id(),
		_ => name.parse().map_err(|e| anyhow::anyhow!("bad account {name}: {e:?}"))?,
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
/// System.Account balance for a stash: free + frozen. The FROZEN amount
/// is the staking lock — bonding freezes it, unbond keeps it frozen
/// (unlocking), withdraw_unbonded RELEASES it. So frozen is the clean
/// observable for the unbond→withdraw lifecycle (P6). Reads at BEST block.
async fn cmd_balance(args: Args) -> Result<()> {
	let ws = args.get_or("--ws", "ws://127.0.0.1:9944");
	let who = dev_account(&args.require("--account")?)?;
	let api = connect(&ws).await?;
	let at = best_hash(&ws).await?;
	let bytes = fetch_storage_at(
		&api, at, "System", "Account",
		vec![subxt::dynamic::Value::from_bytes(who.0)],
	)
	.await?;
	match bytes {
		None => println!("{}", serde_json::json!({ "free": 0, "frozen": 0 })),
		Some(b) => {
			// AccountInfo: nonce(4)+consumers(4)+providers(4)+sufficients(4)=16,
			// then AccountData { free u128, reserved u128, frozen u128, .. }.
			let free = u128::from_le_bytes(b[16..32].try_into().unwrap());
			let frozen = u128::from_le_bytes(b[48..64].try_into().unwrap());
			const ROSTO: u128 = 1_000_000_000_000;
			println!(
				"{}",
				serde_json::json!({
					"free_ros": free / ROSTO,
					"frozen_ros": frozen / ROSTO,
					"free_planck": free.to_string(),
					"frozen_planck": frozen.to_string(),
				})
			);
		},
	}
	Ok(())
}

async fn cmd_staking_state(args: Args) -> Result<()> {
	let ws = args.get_or("--ws", "ws://127.0.0.1:9944");
	let api = connect(&ws).await?;
	let at = best_hash(&ws).await?;

	// ActiveEra: Option storage of ActiveEraInfo { index: u32, start: Option<u64> }
	let active = fetch_storage_at(&api, at, "Staking", "ActiveEra", vec![]).await?;
	let active_era = active.as_deref().map(|mut b| {
		let info: (u32, Option<u64>) =
			Decode::decode(&mut b).expect("ActiveEraInfo layout: (u32, Option<u64>)");
		info.0
	});
	let current = fetch_storage_at(&api, at, "Staking", "CurrentEra", vec![]).await?;
	let current_era = current.as_deref().map(|mut b| u32::decode(&mut b).expect("u32"));
	let count = fetch_storage_at(&api, at, "Staking", "ValidatorCount", vec![]).await?;
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


/// Resolve --suri or an SS58 --account into AccountId32 bytes.
fn target_account(spec: &str) -> Result<AccountId32> {
	if spec.starts_with("//") {
		Ok(dev_keypair(spec)?.public_key().to_account_id())
	} else {
		spec.parse().map_err(|e| anyhow::anyhow!("bad account {spec}: {e:?}"))
	}
}

/// Staking::nominate(targets) — comma-separated //suris or SS58 in --targets.
async fn cmd_nominate(args: Args) -> Result<()> {
	let ws = args.get_or("--ws", "ws://127.0.0.1:9944");
	let signer = dev_keypair(&args.require("--suri")?)?;
	let targets: Vec<AccountId32> = args
		.require("--targets")?
		.split(',')
		.map(|t| target_account(t.trim()))
		.collect::<Result<_>>()?;
	let api = connect(&ws).await?;
	let (p, c) = call_indices(&api.metadata(), "Staking", "nominate")?;
	let mut call = vec![p, c];
	codec::Compact(targets.len() as u32).encode_to(&mut call);
	for t in &targets {
		call.push(0); // MultiAddress::Id
		call.extend_from_slice(&t.0);
	}
	submit(&api, RawCall(call), &signer, 90).await?;
	println!(
		"{}",
		serde_json::json!({ "nominated": targets.iter().map(|t| t.to_string()).collect::<Vec<_>>() })
	);
	Ok(())
}

/// Staking::chill() — stop validating/nominating (stays bonded).
async fn cmd_chill(args: Args) -> Result<()> {
	let ws = args.get_or("--ws", "ws://127.0.0.1:9944");
	let signer = dev_keypair(&args.require("--suri")?)?;
	let api = connect(&ws).await?;
	let (p, c) = call_indices(&api.metadata(), "Staking", "chill")?;
	submit(&api, RawCall(vec![p, c]), &signer, 90).await?;
	println!("{}", serde_json::json!({ "chilled": true }));
	Ok(())
}

/// Staking::validate(ValidatorPrefs) — re-declare validator intent for an
/// ALREADY-bonded stash (the rejoin path after a chill; bond-validate
/// would fail on the redundant bond). Commission via --commission.
async fn cmd_validate(args: Args) -> Result<()> {
	let ws = args.get_or("--ws", "ws://127.0.0.1:9944");
	let signer = dev_keypair(&args.require("--suri")?)?;
	let commission_percent: u32 = args.get_or("--commission", "10").parse()?;
	let api = connect(&ws).await?;
	let (p, c) = call_indices(&api.metadata(), "Staking", "validate")?;
	let mut call = vec![p, c];
	codec::Compact(commission_percent.saturating_mul(10_000_000)).encode_to(&mut call); // Perbill
	call.push(0); // blocked: false
	submit(&api, RawCall(call), &signer, 90).await?;
	println!("{}", serde_json::json!({ "validating": true, "commission_percent": commission_percent }));
	Ok(())
}

/// Staking::unbond(#[compact] value) — value in ROS via --ros.
async fn cmd_unbond(args: Args) -> Result<()> {
	const ROSTO: u128 = 1_000_000_000_000;
	let ws = args.get_or("--ws", "ws://127.0.0.1:9944");
	let signer = dev_keypair(&args.require("--suri")?)?;
	let ros: u128 = args.require("--ros")?.parse()?;
	let api = connect(&ws).await?;
	let (p, c) = call_indices(&api.metadata(), "Staking", "unbond")?;
	let mut call = vec![p, c];
	codec::Compact(ros * ROSTO).encode_to(&mut call);
	submit(&api, RawCall(call), &signer, 90).await?;
	println!("{}", serde_json::json!({ "unbonded_ros": ros }));
	Ok(())
}

/// Staking::withdraw_unbonded(num_slashing_spans) — after BondingDuration.
async fn cmd_withdraw_unbonded(args: Args) -> Result<()> {
	let ws = args.get_or("--ws", "ws://127.0.0.1:9944");
	let signer = dev_keypair(&args.require("--suri")?)?;
	let spans: u32 = args.get_or("--spans", "0").parse()?;
	let api = connect(&ws).await?;
	let (p, c) = call_indices(&api.metadata(), "Staking", "withdraw_unbonded")?;
	let mut call = vec![p, c];
	spans.encode_to(&mut call);
	submit(&api, RawCall(call), &signer, 90).await?;
	println!("{}", serde_json::json!({ "withdrew": true }));
	Ok(())
}

/// Balances::transfer_keep_alive — faucet plumbing (--to //suri|SS58, --ros N).
async fn cmd_transfer(args: Args) -> Result<()> {
	const ROSTO: u128 = 1_000_000_000_000;
	let ws = args.get_or("--ws", "ws://127.0.0.1:9944");
	let signer = dev_keypair(&args.get_or("--suri", "//Alice"))?;
	let dest = target_account(&args.require("--to")?)?;
	let ros: u128 = args.require("--ros")?.parse()?;
	let api = connect(&ws).await?;
	let (p, c) = call_indices(&api.metadata(), "Balances", "transfer_keep_alive")?;
	let mut call = vec![p, c];
	call.push(0); // MultiAddress::Id
	call.extend_from_slice(&dest.0);
	codec::Compact(ros * ROSTO).encode_to(&mut call);
	submit(&api, RawCall(call), &signer, 90).await?;
	println!("{}", serde_json::json!({ "to": dest.to_string(), "ros": ros }));
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
		"derive-authority" => cmd_derive_authority(args),
		"nominate" => cmd_nominate(args).await,
		"chill" => cmd_chill(args).await,
		"validate" => cmd_validate(args).await,
		"balance" => cmd_balance(args).await,
		"unbond" => cmd_unbond(args).await,
		"withdraw-unbonded" => cmd_withdraw_unbonded(args).await,
		"transfer" => cmd_transfer(args).await,
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

/// Derive the full genesis-authority triple for a suri: the sr25519
/// stash account (SS58), the bandersnatch sassafras public, and the
/// hybrid GRANDPA public. Mirrors chain_spec.rs::authority_keys_from_seed
/// so the VM-farm chainspec generator can populate `session.keys` +
/// `staking.stakers` for arbitrary `//FarmValNN` suris without touching
/// the node binary.
fn cmd_derive_authority(args: Args) -> Result<()> {
	use sp_core::crypto::{Pair as _, Ss58Codec as _};
	let suri = args.require("--suri")?;
	let sr_pair = <sp_core::sr25519::Pair as sp_core::Pair>::from_string(&suri, None)
		.map_err(|e| anyhow::anyhow!("sr25519 derive: {e:?}"))?;
	// sr25519 public bytes ARE the AccountId32 bytes (MultiSigner::into_account).
	let account = sp_core::crypto::AccountId32::from(sr_pair.public());
	let band_pair = <sp_core::bandersnatch::Pair as sp_core::Pair>::from_string(&suri, None)
		.map_err(|e| anyhow::anyhow!("bandersnatch derive: {e:?}"))?;
	let hybrid_pair = <sp_core::rostro_hybrid::Pair as sp_core::Pair>::from_string(&suri, None)
		.map_err(|e| anyhow::anyhow!("hybrid derive: {e:?}"))?;
	let band_pub = <sp_core::bandersnatch::Pair as sp_core::Pair>::public(&band_pair);
	let hybrid_pub = hybrid_pair.public();
	// SS58 throughout — chain-spec genesis JSON serializes session keys
	// as SS58 strings (see `build-spec --chain local` output), so emit
	// the exact format the genesis deserializer round-trips.
	println!(
		"{}",
		serde_json::json!({
			"account": account.to_ss58check(),
			"sassafras": band_pub.to_ss58check(),
			"grandpa": hybrid_pub.to_ss58check(),
		})
	);
	Ok(())
}
