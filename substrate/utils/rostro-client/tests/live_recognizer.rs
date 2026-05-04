// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Live integration test for the rostro-client recognizer.
//!
//! Requires a running `rostro-node --dev --tmp --alice --rpc-external` on
//! `ws://127.0.0.1:9944`. Marked `#[ignore]` so plain `cargo test` skips it;
//! run explicitly with:
//!
//!     cargo test --release -p rostro-client --test live_recognizer \
//!         -- --ignored --nocapture
//!
//! The test asserts the end-to-end Tier-2 contract:
//! - rostro-client connects via WebSocket JSON-RPC
//! - fetches metadata + on-chain WellKnownTypeFingerprints
//! - the recognizer Verifies AccountId32 in the runtime's metadata as the
//!   Account role, by *fingerprint match* — not by hardcoded path string

use rostro_client::{Recognition, RostroClient, WellKnownRole};

const NODE_URL: &str = "ws://127.0.0.1:9944";

#[tokio::test]
#[ignore]
async fn recognizer_verifies_well_known_roles_against_live_dev_node() {
	let client = RostroClient::connect(NODE_URL).await.expect("node reachable");
	let recognizer = client.recognize().await.expect("recognize succeeds");

	// Collect a single snapshot of all recognition outcomes before
	// asserting anything — fail-fast assertions hide the full picture and
	// make per-role bug investigation harder.
	let mut counts = std::collections::BTreeMap::<&str, (Vec<u32>, Vec<u32>, Vec<u32>)>::new();
	let labels = [
		(WellKnownRole::Account, "Account"),
		(WellKnownRole::Hash, "Hash"),
		(WellKnownRole::Weight, "Weight"),
		(WellKnownRole::Balance, "Balance"),
		(WellKnownRole::BlockNumber, "BlockNumber"),
	];
	for (role, label) in labels.iter() {
		counts.insert(label, (Vec::new(), Vec::new(), Vec::new()));
		for (id, recog) in recognizer.by_type.iter() {
			match recog {
				Recognition::Verified(r) if r == role =>
					counts.get_mut(label).unwrap().0.push(*id),
				Recognition::HintMismatch { hinted } if hinted == role =>
					counts.get_mut(label).unwrap().1.push(*id),
				Recognition::Inferred { roles } if roles.contains(role) =>
					counts.get_mut(label).unwrap().2.push(*id),
				_ => {},
			}
		}
	}
	for (label, (verified, mismatch, inferred)) in counts.iter() {
		println!(
			"  {:13} verified={:?} hint_mismatch={:?} inferred={}",
			label,
			verified,
			mismatch,
			inferred.len(),
		);
	}

	// Hard assertions: the path-hint roles must each have ≥1 verified
	// metadata type. Account, Hash, Weight are all path-hint roles in
	// the v0 set; Balance and BlockNumber are not (they're primitive
	// shapes; verified-recognition for them is not expected at v0 because
	// Substrate uses them via type aliases and the metadata shows the
	// raw primitive without a path hint).
	let account_verified = counts.get("Account").map(|c| c.0.len()).unwrap_or(0);
	let hash_verified = counts.get("Hash").map(|c| c.0.len()).unwrap_or(0);
	let weight_verified = counts.get("Weight").map(|c| c.0.len()).unwrap_or(0);
	assert!(account_verified > 0, "no Account types verified");
	assert!(hash_verified > 0, "no Hash types verified");
	assert!(weight_verified > 0, "no Weight types verified");

	// Forgery signal: any HintMismatch on a healthy --dev chain. Print
	// them with their paths so a real mismatch is debuggable.
	let mismatches: Vec<(u32, WellKnownRole)> = recognizer
		.by_type
		.iter()
		.filter_map(|(id, r)| match r {
			Recognition::HintMismatch { hinted } => Some((*id, *hinted)),
			_ => None,
		})
		.collect();
	if !mismatches.is_empty() {
		println!("HINT MISMATCHES ON HEALTHY CHAIN — BUG OR FORGERY:");
		for (id, hinted) in mismatches.iter() {
			println!("  type id {} hinted as {:?}", id, hinted);
		}
		panic!(
			"recognizer emitted {} HintMismatch on a healthy chain",
			mismatches.len()
		);
	}
}
