// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! NIST ACVP known-answer tests for the vendored `slh-dsa` crate,
//! SLH-DSA-SHA2-128f only — the parameter set Rostro ships. The vendored
//! tarball's in-crate ACVP sample covers other parameter sets; this file
//! plus the vectors under `tests/acvp/` close that gap (see
//! `substrate/external/slh-dsa/VENDOR.md`).
//!
//! Vector provenance: <https://github.com/usnistgov/ACVP-Server>
//! `gen-val/json-files/SLH-DSA-{keyGen,sigGen,sigVer}-FIPS205/internalProjection.json`,
//! fetched 2026-07-05, filtered verbatim to the `SLH-DSA-SHA2-128f` test
//! groups (whole-group JSON subset, individual vectors untouched).
//!
//! Coverage note (no silent skips): the sigGen file carries 6 groups and
//! sigVer 3. The `preHash: "preHash"` groups (HashSLH-DSA, FIPS 205 §10.2)
//! exercise an API the vendored 0.1.0 crate does not expose, so they are
//! skipped EXPLICITLY and counted: sigGen runs 4 of 6 groups, sigVer 2 of
//! 3. The counts are asserted so a re-vendor that changes coverage fails
//! loudly here.

#![allow(non_snake_case)]

use serde::Deserialize;
use slh_dsa::{Sha2_128f, Signature, SigningKey, VerifyingKey};

#[derive(Deserialize)]
#[serde(transparent)]
struct HexBytes {
	#[serde(with = "hex::serde")]
	data: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyGenTest {
	sk_seed: HexBytes,
	sk_prf: HexBytes,
	pk_seed: HexBytes,
	sk: HexBytes,
	pk: HexBytes,
}

#[derive(Deserialize)]
struct KeyGenGroup {
	tests: Vec<KeyGenTest>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigGenGroup {
	deterministic: bool,
	signature_interface: String,
	pre_hash: String,
	tests: Vec<SigGenTest>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigGenTest {
	tc_id: u32,
	sk: HexBytes,
	message: HexBytes,
	context: Option<HexBytes>,
	additional_randomness: Option<HexBytes>,
	signature: HexBytes,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigVerGroup {
	signature_interface: String,
	pre_hash: String,
	tests: Vec<SigVerTest>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigVerTest {
	tc_id: u32,
	test_passed: bool,
	pk: HexBytes,
	message: HexBytes,
	context: Option<HexBytes>,
	signature: HexBytes,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestFile<G> {
	test_groups: Vec<G>,
}

#[test]
fn acvp_keygen_sha2_128f() {
	let file: TestFile<KeyGenGroup> = serde_json::from_str(include_str!(
		"acvp/SLH-DSA-keyGen-FIPS205.sha2-128f.json"
	))
	.unwrap();
	assert_eq!(file.test_groups.len(), 1);
	let mut cases = 0;
	for t in &file.test_groups[0].tests {
		let sk = SigningKey::<Sha2_128f>::slh_keygen_internal(
			&t.sk_seed.data,
			&t.sk_prf.data,
			&t.pk_seed.data,
		);
		// sk encoding embeds the verifying key (seed || prf || pk), so
		// both comparisons together validate the full keygen output.
		assert_eq!(sk.to_vec(), t.sk.data);
		assert_eq!(&sk.to_vec()[32..], t.pk.data.as_slice());
		cases += 1;
	}
	assert_eq!(cases, 10);
}

#[test]
fn acvp_siggen_sha2_128f() {
	let file: TestFile<SigGenGroup> = serde_json::from_str(include_str!(
		"acvp/SLH-DSA-sigGen-FIPS205.sha2-128f.json"
	))
	.unwrap();
	assert_eq!(file.test_groups.len(), 6);
	let (mut ran, mut skipped_prehash, mut cases) = (0, 0, 0);
	for g in &file.test_groups {
		if g.pre_hash == "preHash" {
			skipped_prehash += 1;
			continue;
		}
		ran += 1;
		for t in &g.tests {
			let sk = SigningKey::<Sha2_128f>::try_from(t.sk.data.as_slice()).unwrap();
			let opt_rand = if g.deterministic {
				None
			} else {
				Some(t.additional_randomness.as_ref().unwrap().data.as_slice())
			};
			let sig = match g.signature_interface.as_str() {
				"internal" => sk.slh_sign_internal(&t.message.data, opt_rand),
				"external" => sk
					.try_sign_with_context(
						&t.message.data,
						&t.context.as_ref().unwrap().data,
						opt_rand,
					)
					.unwrap(),
				other => panic!("unexpected signatureInterface {other} (tcId {})", t.tc_id),
			};
			assert_eq!(sig.to_vec(), t.signature.data, "sigGen mismatch tcId {}", t.tc_id);
			cases += 1;
		}
	}
	assert_eq!((ran, skipped_prehash), (4, 2));
	assert_eq!(cases, 28);
}

#[test]
fn acvp_sigver_sha2_128f() {
	let file: TestFile<SigVerGroup> = serde_json::from_str(include_str!(
		"acvp/SLH-DSA-sigVer-FIPS205.sha2-128f.json"
	))
	.unwrap();
	assert_eq!(file.test_groups.len(), 3);
	let (mut ran, mut skipped_prehash, mut cases) = (0, 0, 0);
	for g in &file.test_groups {
		if g.pre_hash == "preHash" {
			skipped_prehash += 1;
			continue;
		}
		ran += 1;
		for t in &g.tests {
			let verified = (|| -> Result<(), ()> {
				let pk =
					VerifyingKey::<Sha2_128f>::try_from(t.pk.data.as_slice()).map_err(|_| ())?;
				let sig =
					Signature::<Sha2_128f>::try_from(t.signature.data.as_slice()).map_err(|_| ())?;
				match g.signature_interface.as_str() {
					"internal" => pk.slh_verify_internal(&t.message.data, &sig).map_err(|_| ()),
					"external" => pk
						.try_verify_with_context(
							&t.message.data,
							&t.context.as_ref().unwrap().data,
							&sig,
						)
						.map_err(|_| ()),
					other => panic!("unexpected signatureInterface {other} (tcId {})", t.tc_id),
				}
			})()
			.is_ok();
			assert_eq!(verified, t.test_passed, "sigVer mismatch tcId {}", t.tc_id);
			cases += 1;
		}
	}
	assert_eq!((ran, skipped_prehash), (2, 1));
	assert_eq!(cases, 28);
}
