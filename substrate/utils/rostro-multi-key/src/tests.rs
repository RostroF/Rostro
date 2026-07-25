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

// ---------------------------------------------------------------------------
// P-256 (secp256r1) — EcdsaP256 variant
// ---------------------------------------------------------------------------

/// secp256r1 group order n, big-endian (SEC2). Used only to synthesize the
/// high-s malleable twin and to cross-check `P256_HALF_ORDER`.
const P256_ORDER: [u8; 32] = [
	0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// Fixed P-256 test secret, well below the group order.
const P256_TEST_SECRET: [u8; 32] = [0x42u8; 32];

/// Right-shift a 32-byte big-endian integer by one bit.
fn be_shr1(a: &[u8; 32]) -> [u8; 32] {
	let mut out = [0u8; 32];
	let mut carry = 0u8;
	for i in 0..32 {
		out[i] = (carry << 7) | (a[i] >> 1);
		carry = a[i] & 1;
	}
	out
}

/// Big-endian `a - b` (assumes `a >= b`).
fn be_sub(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
	let mut out = [0u8; 32];
	let mut borrow = 0i16;
	for i in (0..32).rev() {
		let mut d = a[i] as i16 - b[i] as i16 - borrow;
		if d < 0 {
			d += 256;
			borrow = 1;
		} else {
			borrow = 0;
		}
		out[i] = d as u8;
	}
	out
}

fn p256_test_key() -> (p256::ecdsa::SigningKey, [u8; 33]) {
	let sk = p256::ecdsa::SigningKey::from_slice(&P256_TEST_SECRET).expect("valid P-256 scalar");
	let pt = sk.verifying_key().to_encoded_point(true);
	let pubkey: [u8; 33] = pt.as_bytes().try_into().expect("compressed sec1 is 33 bytes");
	(sk, pubkey)
}

/// Sign `msg` the way StrongBox's `SHA256withECDSA` does: SHA-256 the
/// payload, ECDSA over the digest. RustCrypto's signer does NOT force
/// low-s (roughly half its signatures are high-s), so we normalize to
/// low-s here — exactly the step the wallet/dotwave owns before submission
/// and the canonical form `verify_p256` requires.
fn p256_sign(sk: &p256::ecdsa::SigningKey, msg: &[u8]) -> [u8; 64] {
	use p256::ecdsa::{signature::Signer, Signature};
	let sig: Signature = sk.sign(msg);
	let sig = sig.normalize_s().unwrap_or(sig);
	sig.to_bytes().as_slice().try_into().expect("64-byte r||s")
}

#[test]
fn ecdsa_p256_derivation_is_blake2_of_pubkey() {
	let (_sk, pubkey) = p256_test_key();
	let derived = ecdsa_p256_to_account(&pubkey);
	let derived_bytes: &[u8; 32] = derived.as_ref();
	assert_eq!(
		derived_bytes,
		&blake2_256(&pubkey),
		"P-256 account MUST be blake2_256(compressed pubkey) — deterministic on chain and in wallet"
	);
	assert_eq!(ecdsa_p256_to_account(&pubkey), derived, "derivation must be a pure function of the bytes");
}

#[test]
fn ecdsa_p256_signature_verifies() {
	let (sk, pubkey) = p256_test_key();
	let account = ecdsa_p256_to_account(&pubkey);
	// Several payloads: deterministic ECDSA samples s across (0, n/2], so a
	// wrong P256_HALF_ORDER would trip at least one of these.
	for m in [
		&b"hello rostro"[..],
		&b""[..],
		&b"a second payload"[..],
		&b"strongbox p256 native signing"[..],
	] {
		let sig = p256_sign(&sk, m);
		let rs = RostroSignature::EcdsaP256 { pubkey, sig };
		assert!(rs.verify(m, &account), "valid low-s P-256 signature must verify");
	}
}

#[test]
fn ecdsa_p256_rejects_wrong_account() {
	let (sk, pubkey) = p256_test_key();
	let msg = b"hello rostro";
	let sig = p256_sign(&sk, msg);
	let attacker: AccountId32 = [0x99u8; 32].into();
	let rs = RostroSignature::EcdsaP256 { pubkey, sig };
	assert!(
		!rs.verify(&msg[..], &attacker),
		"P-256 verify must reject when the account isn't blake2_256(pubkey)"
	);
}

#[test]
fn ecdsa_p256_rejects_pubkey_swap() {
	// A signature carrying a different (valid) pubkey than the account
	// derives from must fail — the pubkey-in-signature is bound by hash.
	let (sk, pubkey) = p256_test_key();
	let account = ecdsa_p256_to_account(&pubkey);
	let msg = b"hello rostro";
	let sig = p256_sign(&sk, msg);
	let sk2 = p256::ecdsa::SigningKey::from_slice(&[0x07u8; 32]).unwrap();
	let pt2 = sk2.verifying_key().to_encoded_point(true);
	let pubkey2: [u8; 33] = pt2.as_bytes().try_into().unwrap();
	let rs = RostroSignature::EcdsaP256 { pubkey: pubkey2, sig };
	assert!(!rs.verify(&msg[..], &account), "swapping the carried pubkey must break account binding");
}

#[test]
fn ecdsa_p256_rejects_high_s() {
	let (sk, pubkey) = p256_test_key();
	let account = ecdsa_p256_to_account(&pubkey);
	let msg = b"hello rostro";
	let low = p256_sign(&sk, msg);
	// s' = n - s is the valid high-s malleable twin: same r, verifies under
	// raw ECDSA, but the low-s gate must reject it.
	let s_low: [u8; 32] = low[32..].try_into().unwrap();
	let s_high = be_sub(&P256_ORDER, &s_low);
	let mut high = low;
	high[32..].copy_from_slice(&s_high);
	let rs_high = RostroSignature::EcdsaP256 { pubkey, sig: high };
	assert!(!rs_high.verify(&msg[..], &account), "high-s (malleable) P-256 signature must be rejected");
	// Isolate the cause: the low-s original does verify.
	let rs_low = RostroSignature::EcdsaP256 { pubkey, sig: low };
	assert!(rs_low.verify(&msg[..], &account));
}

#[test]
fn p256_half_order_is_group_order_shifted() {
	// Frozen-constant guard: n/2 == n >> 1.
	assert_eq!(
		be_shr1(&P256_ORDER),
		P256_HALF_ORDER,
		"P256_HALF_ORDER must equal the secp256r1 group order shifted right one bit"
	);
}

#[test]
fn p256_low_s_boundary() {
	assert!(!is_low_s_p256(&[0u8; 32]), "s == 0 is not a valid scalar");
	let mut one = [0u8; 32];
	one[31] = 1;
	assert!(is_low_s_p256(&one), "s == 1 is low");
	assert!(is_low_s_p256(&P256_HALF_ORDER), "s == n/2 is the accepted boundary");
	let mut half_plus = P256_HALF_ORDER;
	half_plus[31] += 1; // 0xa8 -> 0xa9, no carry
	assert!(!is_low_s_p256(&half_plus), "s == n/2 + 1 is high");
}

// ---------------------------------------------------------------------------
// verify_against — the keyring entry point (docs/KEYRING.md)
// ---------------------------------------------------------------------------

#[test]
fn verify_against_accepts_every_scheme_matched_pair() {
	let msg = b"hello rostro".to_vec();

	let sr = sr25519::Pair::from_seed(&[0x42u8; 32]);
	assert!(RostroSignature::Sr25519(sr.sign(&msg))
		.verify_against(&msg, &RostroSigner::Sr25519(sr.public())));

	let ed = ed25519::Pair::from_seed(&[0x42u8; 32]);
	assert!(RostroSignature::Ed25519(ed.sign(&msg))
		.verify_against(&msg, &RostroSigner::Ed25519(ed.public())));

	let secret_bytes: [u8; 32] = hex::decode(ANVIL_DEV_0_SECRET).unwrap().try_into().unwrap();
	let k1 = ecdsa::Pair::from_seed(&secret_bytes);
	assert!(RostroSignature::Ecdsa(k1.sign(&msg))
		.verify_against(&msg, &RostroSigner::Ecdsa(k1.public())));
	assert!(
		RostroSignature::EcdsaEip191(k1.sign_prehashed(&eip191_hash(&msg)))
			.verify_against(&msg, &RostroSigner::Ecdsa(k1.public())),
		"both secp256k1 envelopes must match an enrolled Ecdsa key"
	);

	let (sk, pubkey) = p256_test_key();
	let sig = p256_sign(&sk, &msg);
	assert!(RostroSignature::EcdsaP256 { pubkey, sig }
		.verify_against(&msg, &RostroSigner::EcdsaP256(pubkey)));
}

#[test]
fn verify_against_ignores_address_binding() {
	// The keyring use case itself: a P-256 device key signs for an account
	// it does NOT derive to (the account belongs to a 25519 root; the
	// keyring authorized the device key). verify_against must accept purely
	// on the enrolled-key match — Verify::verify on the same signature
	// rejects, because the account isn't blake2_256(pubkey).
	let msg = b"hello rostro".to_vec();
	let (sk, pubkey) = p256_test_key();
	let sig = p256_sign(&sk, &msg);
	let rs = RostroSignature::EcdsaP256 { pubkey, sig };

	let root = sr25519::Pair::from_seed(&[0x42u8; 32]);
	let root_account = sr25519_to_account(&root.public());
	assert!(!rs.verify(&msg[..], &root_account), "derived path must still reject");
	assert!(rs.verify_against(&msg, &RostroSigner::EcdsaP256(pubkey)));
}

#[test]
fn verify_against_rejects_cross_scheme_and_wrong_key() {
	let msg = b"hello rostro".to_vec();

	// Same 32 seed bytes, different curves: an sr25519 signature must not
	// satisfy an enrolled ed25519 key (schemes are explicit in the keyring,
	// unlike the shared raw-pubkey address namespace).
	let sr = sr25519::Pair::from_seed(&[0x42u8; 32]);
	let ed = ed25519::Pair::from_seed(&[0x42u8; 32]);
	assert!(!RostroSignature::Sr25519(sr.sign(&msg))
		.verify_against(&msg, &RostroSigner::Ed25519(ed.public())));

	// Wrong enrolled key of the right scheme.
	let sr2 = sr25519::Pair::from_seed(&[0x43u8; 32]);
	assert!(!RostroSignature::Sr25519(sr.sign(&msg))
		.verify_against(&msg, &RostroSigner::Sr25519(sr2.public())));

	// secp256k1 signature against an enrolled key it doesn't recover to.
	let secret_bytes: [u8; 32] = hex::decode(ANVIL_DEV_0_SECRET).unwrap().try_into().unwrap();
	let k1 = ecdsa::Pair::from_seed(&secret_bytes);
	let k1_other = ecdsa::Pair::from_seed(&[0x44u8; 32]);
	assert!(!RostroSignature::Ecdsa(k1.sign(&msg))
		.verify_against(&msg, &RostroSigner::Ecdsa(k1_other.public())));

	// P-256 signature against a secp256k1 enrolled key (and vice versa).
	let (sk, pubkey) = p256_test_key();
	let sig = p256_sign(&sk, &msg);
	assert!(!RostroSignature::EcdsaP256 { pubkey, sig }
		.verify_against(&msg, &RostroSigner::Ecdsa(k1.public())));
	assert!(!RostroSignature::Ecdsa(k1.sign(&msg))
		.verify_against(&msg, &RostroSigner::EcdsaP256(pubkey)));
}

#[test]
fn verify_against_p256_keeps_pubkey_and_low_s_discipline() {
	let msg = b"hello rostro".to_vec();
	let (sk, pubkey) = p256_test_key();
	let sig = p256_sign(&sk, &msg);

	// Carried pubkey must equal the enrolled pubkey exactly.
	let sk2 = p256::ecdsa::SigningKey::from_slice(&[0x07u8; 32]).unwrap();
	let pubkey2: [u8; 33] =
		sk2.verifying_key().to_encoded_point(true).as_bytes().try_into().unwrap();
	assert!(
		!RostroSignature::EcdsaP256 { pubkey, sig }
			.verify_against(&msg, &RostroSigner::EcdsaP256(pubkey2)),
		"carried pubkey != enrolled pubkey must be rejected"
	);

	// High-s twin still rejected on the keyring path.
	let s_low: [u8; 32] = sig[32..].try_into().unwrap();
	let s_high = be_sub(&P256_ORDER, &s_low);
	let mut high = sig;
	high[32..].copy_from_slice(&s_high);
	assert!(
		!RostroSignature::EcdsaP256 { pubkey, sig: high }
			.verify_against(&msg, &RostroSigner::EcdsaP256(pubkey)),
		"low-s canonicalization must hold on the keyring path too"
	);
}

// ── WebAuthn (secp256r1) — WebAuthnP256 variant (index 5) ──────────────────

#[test]
fn base64url_encode_known_vectors() {
	// RFC 4648 §10 vectors — validate the bit-packing, all three remainder
	// cases, and no padding. base64url == base64 for these inputs.
	assert_eq!(base64url_encode(b"").as_slice(), b"".as_slice());
	assert_eq!(base64url_encode(b"f").as_slice(), b"Zg".as_slice());
	assert_eq!(base64url_encode(b"fo").as_slice(), b"Zm8".as_slice());
	assert_eq!(base64url_encode(b"foo").as_slice(), b"Zm9v".as_slice());
	assert_eq!(base64url_encode(b"foob").as_slice(), b"Zm9vYg".as_slice());
	assert_eq!(base64url_encode(b"fooba").as_slice(), b"Zm9vYmE".as_slice());
	assert_eq!(base64url_encode(b"foobar").as_slice(), b"Zm9vYmFy".as_slice());
	// URL alphabet: indices 62/63 are '-'/'_' (not base64's '+'/'/').
	assert_eq!(B64URL[62], b'-');
	assert_eq!(B64URL[63], b'_');
}

/// A well-formed `clientDataJSON` binding `payload`
/// (challenge = base64url(sha2_256(payload))).
fn client_data_for(payload: &[u8]) -> Vec<u8> {
	let challenge = base64url_encode(&sha2_256(payload));
	let mut cdj = Vec::new();
	cdj.extend_from_slice(br#"{"type":"webauthn.get","challenge":""#);
	cdj.extend_from_slice(&challenge);
	cdj.extend_from_slice(br#"","origin":"https://rostro.example"}"#);
	cdj
}

/// Assemble a WebAuthn assertion from `sk` over `client_data_json`, with `flags`
/// in a minimal 37-byte `authenticatorData`. Signs `authData ‖ sha256(clientDataJSON)`
/// low-s — exactly what a passkey authenticator produces.
fn webauthn_assertion(
	sk: &p256::ecdsa::SigningKey,
	pubkey: [u8; 33],
	client_data_json: Vec<u8>,
	flags: u8,
) -> RostroSignature {
	let mut authenticator_data = vec![0u8; 37];
	authenticator_data[32] = flags;
	let mut m = authenticator_data.clone();
	m.extend_from_slice(&sha2_256(&client_data_json));
	let sig = p256_sign(sk, &m);
	RostroSignature::WebAuthnP256 {
		pubkey,
		authenticator_data: BoundedVec::try_from(authenticator_data).expect("<= 256 bytes"),
		client_data_json: BoundedVec::try_from(client_data_json).expect("<= 1024 bytes"),
		sig,
	}
}

const UP_UV: u8 = 0x05; // User Present + User Verified

#[test]
fn webauthn_p256_verifies_both_paths() {
	let (sk, pubkey) = p256_test_key();
	let account = ecdsa_p256_to_account(&pubkey);
	let signer = RostroSigner::EcdsaP256(pubkey);
	for payload in [&b"register anthony.rst"[..], &b""[..], &b"transfer 1 ROS to bob"[..]] {
		let rs = webauthn_assertion(&sk, pubkey, client_data_for(payload), UP_UV);
		assert!(rs.verify(payload, &account), "valid WebAuthn assertion must verify (derived path)");
		assert!(
			rs.verify_against(payload, &signer),
			"valid WebAuthn assertion must verify (keyring path)"
		);
	}
}

#[test]
fn webauthn_p256_rejects_challenge_for_other_payload() {
	// An assertion signed while approving payload A must not verify for payload
	// B — the challenge binds the exact extrinsic (anti-replay across payloads).
	let (sk, pubkey) = p256_test_key();
	let account = ecdsa_p256_to_account(&pubkey);
	let rs = webauthn_assertion(&sk, pubkey, client_data_for(b"payload A"), UP_UV);
	assert!(!rs.verify(&b"payload B"[..], &account), "challenge must bind the exact payload");
}

#[test]
fn webauthn_p256_requires_user_present_flag() {
	let (sk, pubkey) = p256_test_key();
	let account = ecdsa_p256_to_account(&pubkey);
	let payload = b"register anthony.rst";
	let rs = webauthn_assertion(&sk, pubkey, client_data_for(payload), 0x00);
	assert!(!rs.verify(&payload[..], &account), "User-Present flag must be set");
}

#[test]
fn webauthn_p256_rejects_wrong_type() {
	let (sk, pubkey) = p256_test_key();
	let account = ecdsa_p256_to_account(&pubkey);
	let payload = b"register anthony.rst";
	let challenge = base64url_encode(&sha2_256(payload));
	let mut cdj = Vec::new();
	cdj.extend_from_slice(br#"{"type":"webauthn.create","challenge":""#);
	cdj.extend_from_slice(&challenge);
	cdj.extend_from_slice(br#""}"#);
	let rs = webauthn_assertion(&sk, pubkey, cdj, UP_UV);
	assert!(!rs.verify(&payload[..], &account), "type must be webauthn.get");
}

#[test]
fn webauthn_p256_rejects_backslash_in_client_data() {
	// Any backslash could escape a decoy `"challenge"`; reject wholesale so the
	// substring scan stays provably unambiguous.
	let (sk, pubkey) = p256_test_key();
	let account = ecdsa_p256_to_account(&pubkey);
	let payload = b"register anthony.rst";
	let challenge = base64url_encode(&sha2_256(payload));
	let mut cdj = Vec::new();
	cdj.extend_from_slice(br#"{"type":"webauthn.get","challenge":""#);
	cdj.extend_from_slice(&challenge);
	cdj.extend_from_slice(br#"","origin":"https:\/\/rostro.example"}"#);
	let rs = webauthn_assertion(&sk, pubkey, cdj, UP_UV);
	assert!(!rs.verify(&payload[..], &account), "any backslash must reject");
}

#[test]
fn webauthn_p256_rejects_tampered_authenticator_data() {
	let (sk, pubkey) = p256_test_key();
	let account = ecdsa_p256_to_account(&pubkey);
	let payload = b"register anthony.rst";
	let mut rs = webauthn_assertion(&sk, pubkey, client_data_for(payload), UP_UV);
	if let RostroSignature::WebAuthnP256 { authenticator_data, .. } = &mut rs {
		// Flip a byte in the signed authenticatorData: envelope checks still pass
		// (rpIdHash isn't enforced), but the signature no longer matches.
		let mut bytes = authenticator_data.clone().into_inner();
		bytes[0] ^= 0xff;
		*authenticator_data = BoundedVec::try_from(bytes).unwrap();
	}
	assert!(!rs.verify(&payload[..], &account), "tampered authenticatorData must fail the signature");
}

#[test]
fn webauthn_p256_rejects_short_authenticator_data() {
	let (sk, pubkey) = p256_test_key();
	let account = ecdsa_p256_to_account(&pubkey);
	let payload = b"x";
	let cdj = client_data_for(payload);
	let authenticator_data = vec![0u8; 36]; // < 37
	let mut m = authenticator_data.clone();
	m.extend_from_slice(&sha2_256(&cdj));
	let sig = p256_sign(&sk, &m);
	let rs = RostroSignature::WebAuthnP256 {
		pubkey,
		authenticator_data: BoundedVec::try_from(authenticator_data).unwrap(),
		client_data_json: BoundedVec::try_from(cdj).unwrap(),
		sig,
	};
	assert!(!rs.verify(&payload[..], &account), "authenticatorData < 37 bytes must reject");
}

#[test]
fn webauthn_p256_rejects_wrong_account_and_pubkey_swap() {
	let (sk, pubkey) = p256_test_key();
	let payload = b"register anthony.rst";
	let rs = webauthn_assertion(&sk, pubkey, client_data_for(payload), UP_UV);
	let attacker: AccountId32 = [0x99u8; 32].into();
	assert!(!rs.verify(&payload[..], &attacker), "must reject when account != blake2_256(pubkey)");
	let other = RostroSigner::EcdsaP256([0x02u8; 33]);
	assert!(
		!rs.verify_against(payload, &other),
		"keyring path must reject when the enrolled key != the carried pubkey"
	);
}
