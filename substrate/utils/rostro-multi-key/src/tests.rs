// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Pinned test vectors for AccountId derivation + signature verify.
//!
//! These tests are the discipline that prevents "address derivation
//! drift" between chain (gemini-runtime) and wallet (dotwave). Any
//! change to the derivation function will fail these vectors loudly,
//! and a failed CI run flags the change for explicit human review
//! before any addresses get stranded. The Polkadot-parity vector in
//! particular guards against anyone reintroducing a tag/hash on the
//! Sr25519 path — which would re-strand every DOT-refugee airdrop.

use super::*;
use sp_core::{ecdsa, ed25519, sr25519, Pair as PairTrait};

// Well-known Anvil/Hardhat deterministic dev account #0:
//   private: 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
//   address: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
// This is the first account every Ethereum dev sees on every dev chain
// they spin up. If our Ecdsa derivation doesn't produce this address
// from this key, our derivation isn't really Ethereum-compatible.
const ANVIL_DEV_0_SECRET: &str =
	"ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const ANVIL_DEV_0_ETH_ADDRESS: &str = "f39fd6e51aad88f6f4ce6ab8827279cfffb92266";

#[test]
fn sr25519_derivation_is_raw_pubkey() {
	let pair = sr25519::Pair::from_seed(&[0x42u8; 32]);
	let pubkey = pair.public();
	let derived = sr25519_to_account(&pubkey);
	let derived_bytes: &[u8; 32] = derived.as_ref();
	let pubkey_bytes: &[u8; 32] = pubkey.as_ref();
	assert_eq!(
		derived_bytes, pubkey_bytes,
		"Sr25519 AccountId MUST equal the raw pubkey — no tag, no hash. This is what gives \
		 Polkadot holders the same account on Rostro."
	);
}

#[test]
fn sr25519_matches_polkadot_alice_account() {
	// Canonical Polkadot/Substrate dev account //Alice. Its sr25519
	// public key — and therefore its AccountId32 on any chain that uses
	// raw-pubkey-as-address — is well-known and published:
	//   AccountId32 / pubkey:
	//     0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d
	//   SS58 (prefix 42): 5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY
	// If Rostro's Sr25519 derivation ever drifts from raw-pubkey, this
	// vector breaks loudly and every Polkadot-refugee airdrop is at risk.
	const ALICE_ACCOUNT: &str =
		"d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d";
	let pair = sr25519::Pair::from_string("//Alice", None).expect("//Alice derives");
	let pubkey = pair.public();
	let derived = sr25519_to_account(&pubkey);
	let derived_bytes: &[u8; 32] = derived.as_ref();
	assert_eq!(
		hex::encode(derived_bytes),
		ALICE_ACCOUNT,
		"Sr25519 AccountId MUST match Polkadot's //Alice — raw-pubkey parity is the whole point"
	);
}

#[test]
fn ed25519_derivation_is_raw_pubkey() {
	let pair = ed25519::Pair::from_seed(&[0x42u8; 32]);
	let pubkey = pair.public();
	let derived = ed25519_to_account(&pubkey);
	let derived_bytes: &[u8; 32] = derived.as_ref();
	assert_eq!(
		derived_bytes,
		&pubkey.0,
		"Ed25519 derivation MUST source-match Solana/Aptos/Sui/Cosmos/Ledger (raw pubkey-as-address)"
	);
}

#[test]
fn sr25519_and_ed25519_share_raw_pubkey_namespace() {
	// Post-untag reality, and it is intentional: both schemes are
	// raw-pubkey-as-address, exactly like Substrate's MultiSignature, so
	// identical pubkey bytes map to the same AccountId regardless of
	// scheme. We accept the shared namespace — a cross-scheme collision
	// needs one 32-byte value to be a valid point under both curves with
	// both secret keys held: ~1 in 2^256 by chance, DLP-infeasible to
	// target, and the signature variant (not the account) selects the
	// curve at verify time.
	let bytes = [0x42u8; 32];
	let sr_account = sr25519_to_account(&sr25519::Public::from_raw(bytes));
	let ed_account = ed25519_to_account(&ed25519::Public::from_raw(bytes));
	assert_eq!(
		sr_account, ed_account,
		"raw-pubkey parity means identical pubkey bytes derive identical AccountIds across schemes"
	);
}

#[test]
fn ecdsa_derivation_matches_anvil_dev_account_0() {
	let secret_bytes: [u8; 32] = hex::decode(ANVIL_DEV_0_SECRET)
		.expect("hex decodes")
		.try_into()
		.expect("32 bytes");
	let pair = ecdsa::Pair::from_seed(&secret_bytes);
	let pubkey = pair.public();
	let h160 = ecdsa_compressed_to_eth_h160(&pubkey).expect("decompresses");
	assert_eq!(
		hex::encode(h160),
		ANVIL_DEV_0_ETH_ADDRESS,
		"Ecdsa derivation must produce the Ethereum H160 every dev wallet would expect"
	);

	let derived = ecdsa_compressed_to_account(&pubkey);
	let derived_bytes: &[u8; 32] = derived.as_ref();
	assert_eq!(&derived_bytes[..12], &[0u8; 12], "leading 12 bytes are zero-padding");
	assert_eq!(hex::encode(&derived_bytes[12..]), ANVIL_DEV_0_ETH_ADDRESS);
}

#[test]
fn sr25519_signature_verifies_when_account_is_raw_pubkey() {
	let pair = sr25519::Pair::from_seed(&[0x42u8; 32]);
	let pubkey = pair.public();
	let account = sr25519_to_account(&pubkey);
	let msg = b"hello rostro".to_vec();
	let sig = pair.sign(&msg);
	let rs = RostroSignature::Sr25519(sig);
	assert!(rs.verify(&msg[..], &account));
}

#[test]
fn sr25519_signature_rejected_for_wrong_account() {
	let pair = sr25519::Pair::from_seed(&[0x42u8; 32]);
	let msg = b"hello rostro".to_vec();
	let sig = pair.sign(&msg);
	// A different account (not the signing pubkey) must not verify.
	let attacker_account: AccountId32 = [0x99u8; 32].into();
	let rs = RostroSignature::Sr25519(sig);
	assert!(
		!rs.verify(&msg[..], &attacker_account),
		"verify must reject when the signer account isn't the signing pubkey"
	);
}

#[test]
fn ed25519_signature_verifies() {
	let pair = ed25519::Pair::from_seed(&[0x42u8; 32]);
	let pubkey = pair.public();
	let account = ed25519_to_account(&pubkey);
	let msg = b"hello rostro".to_vec();
	let sig = pair.sign(&msg);
	let rs = RostroSignature::Ed25519(sig);
	assert!(rs.verify(&msg[..], &account));
}

#[test]
fn ecdsa_substrate_style_signature_verifies() {
	let secret_bytes: [u8; 32] = hex::decode(ANVIL_DEV_0_SECRET).unwrap().try_into().unwrap();
	let pair = ecdsa::Pair::from_seed(&secret_bytes);
	let pubkey = pair.public();
	let account = ecdsa_compressed_to_account(&pubkey);
	let msg = b"hello rostro".to_vec();
	// sp_core::ecdsa::Pair::sign signs blake2_256(msg) — substrate-style.
	let sig = pair.sign(&msg);
	let rs = RostroSignature::Ecdsa(sig);
	assert!(rs.verify(&msg[..], &account));
}

#[test]
fn ecdsa_eip191_signature_verifies_with_eth_wrap() {
	let secret_bytes: [u8; 32] = hex::decode(ANVIL_DEV_0_SECRET).unwrap().try_into().unwrap();
	let pair = ecdsa::Pair::from_seed(&secret_bytes);
	let pubkey = pair.public();
	let account = ecdsa_compressed_to_account(&pubkey);
	let msg = b"hello rostro".to_vec();
	// Sign the EIP-191 hash using the lower-level pair — sign_prehashed
	// takes a 32-byte hash directly and produces a 65-byte (r||s||v)
	// signature with v ∈ {0,1}. This is exactly what MetaMask produces
	// (after subtracting 27 from its v ∈ {27,28} convention).
	let hash = eip191_hash(&msg);
	let sig = pair.sign_prehashed(&hash);
	let rs = RostroSignature::EcdsaEip191(sig);
	assert!(rs.verify(&msg[..], &account));
}

#[test]
fn ecdsa_eip191_rejects_signature_without_wrap() {
	let secret_bytes: [u8; 32] = hex::decode(ANVIL_DEV_0_SECRET).unwrap().try_into().unwrap();
	let pair = ecdsa::Pair::from_seed(&secret_bytes);
	let pubkey = pair.public();
	let account = ecdsa_compressed_to_account(&pubkey);
	let msg = b"hello rostro".to_vec();
	// Sign the substrate-style hash (blake2_256), NOT the EIP-191 hash —
	// then submit as if EcdsaEip191. Verify must reject.
	let sig = pair.sign(&msg);
	let rs = RostroSignature::EcdsaEip191(sig);
	assert!(
		!rs.verify(&msg[..], &account),
		"EcdsaEip191 verify must reject a substrate-style signature (not EIP-191 wrapped)"
	);
}

#[test]
fn eip191_hash_matches_canonical_test_vector() {
	// Canonical EIP-191 test vector — short message, well-known wrap:
	//     "Hello, world!" (13 bytes)
	// Wrapped:
	//     "\x19Ethereum Signed Message:\n13Hello, world!"
	// keccak256 of that wrapped form is published in EIP-191 reference
	// implementations; this is the value `web3.utils.hashMessage(msg)`
	// returns and the value MetaMask hashes before signing.
	let msg = b"Hello, world!";
	let h = eip191_hash(msg);
	assert_eq!(
		hex::encode(h),
		"b453bd4e271eed985cbab8231da609c4ce0a9cf1f763b6c1594e76315510e0f1",
	);
}
