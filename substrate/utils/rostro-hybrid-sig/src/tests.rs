// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

use super::*;
use rand::rngs::OsRng;

fn keypair() -> (HybridSigningKey, HybridVerifyingKey) {
	let sk = HybridSigningKey::generate(&mut OsRng);
	let vk = sk.verifying_key();
	(sk, vk)
}

#[test]
fn sign_verify_roundtrip() {
	let (sk, vk) = keypair();
	let msg = b"vote: prevote #4242";
	let sig = sk.sign(FINALITY_VOTE_DOMAIN, msg).unwrap();
	vk.verify(FINALITY_VOTE_DOMAIN, msg, &sig).unwrap();
}

#[test]
fn wire_sizes_pinned() {
	// The whole point of pinning: silent size drift in a vendored bump
	// would break vote gossip and justification formats. These MUST fail
	// loudly instead.
	let (sk, vk) = keypair();
	let sig = sk.sign(FINALITY_VOTE_DOMAIN, b"m").unwrap();
	assert_eq!(sig.to_vec().len(), HYBRID_SIG_BYTES);
	assert_eq!(HYBRID_SIG_BYTES, 17152);
	assert_eq!(vk.to_vec().len(), HYBRID_PK_BYTES);
	assert_eq!(HYBRID_PK_BYTES, 64);
	assert_eq!(sk.to_vec().len(), HYBRID_SK_BYTES);
	assert_eq!(HYBRID_SK_BYTES, 96);
}

#[test]
fn encode_decode_roundtrip() {
	let (sk, vk) = keypair();
	let msg = b"round trip";
	let sig = sk.sign(FINALITY_VOTE_DOMAIN, msg).unwrap();

	let sig2 = HybridSignature::from_bytes(&sig.to_vec()).unwrap();
	let vk2 = HybridVerifyingKey::from_bytes(&vk.to_vec()).unwrap();
	let sk2 = HybridSigningKey::from_bytes(&sk.to_vec()).unwrap();

	vk2.verify(FINALITY_VOTE_DOMAIN, msg, &sig2).unwrap();
	let sig3 = sk2.sign(FINALITY_VOTE_DOMAIN, msg).unwrap();
	vk.verify(FINALITY_VOTE_DOMAIN, msg, &sig3).unwrap();
}

#[test]
fn deterministic_signing() {
	// Both components are deterministic: identical payload → identical
	// signature. Equivocation evidence stays canonical.
	let (sk, _) = keypair();
	let a = sk.sign(FINALITY_VOTE_DOMAIN, b"same").unwrap().to_vec();
	let b = sk.sign(FINALITY_VOTE_DOMAIN, b"same").unwrap().to_vec();
	assert_eq!(a, b);
}

#[test]
fn tampered_ed25519_component_rejected() {
	let (sk, vk) = keypair();
	let msg = b"tamper ed";
	let mut bytes = sk.sign(FINALITY_VOTE_DOMAIN, msg).unwrap().to_vec();
	bytes[3] ^= 0x01; // inside the ed25519 sig
	let sig = HybridSignature::from_bytes(&bytes).unwrap();
	assert_eq!(
		vk.verify(FINALITY_VOTE_DOMAIN, msg, &sig),
		Err(HybridSigError::Ed25519Reject)
	);
}

#[test]
fn tampered_slh_component_rejected() {
	let (sk, vk) = keypair();
	let msg = b"tamper slh";
	let mut bytes = sk.sign(FINALITY_VOTE_DOMAIN, msg).unwrap().to_vec();
	bytes[ED25519_SIG_BYTES + 100] ^= 0x01; // inside the SLH-DSA sig
	let sig = HybridSignature::from_bytes(&bytes).unwrap();
	assert_eq!(
		vk.verify(FINALITY_VOTE_DOMAIN, msg, &sig),
		Err(HybridSigError::SlhReject)
	);
}

#[test]
fn stripped_pq_component_unforgeable() {
	// The classical-downgrade check: a signature whose SLH-DSA half was
	// swapped for one over a DIFFERENT message must reject, even though
	// the ed25519 half is honest for this message.
	let (sk, vk) = keypair();
	let honest = sk.sign(FINALITY_VOTE_DOMAIN, b"msg A").unwrap().to_vec();
	let other = sk.sign(FINALITY_VOTE_DOMAIN, b"msg B").unwrap().to_vec();
	let mut spliced = honest[..ED25519_SIG_BYTES].to_vec();
	spliced.extend_from_slice(&other[ED25519_SIG_BYTES..]);
	let sig = HybridSignature::from_bytes(&spliced).unwrap();
	assert_eq!(
		vk.verify(FINALITY_VOTE_DOMAIN, b"msg A", &sig),
		Err(HybridSigError::SlhReject)
	);
}

#[test]
fn cross_domain_rejected() {
	let (sk, vk) = keypair();
	let msg = b"same message";
	let sig = sk.sign(b"rostro/test-domain/a", msg).unwrap();
	assert!(vk.verify(b"rostro/test-domain/b", msg, &sig).is_err());
	assert!(vk.verify(FINALITY_VOTE_DOMAIN, msg, &sig).is_err());
	vk.verify(b"rostro/test-domain/a", msg, &sig).unwrap();
}

#[test]
fn domain_framing_unambiguous() {
	// (domain="ab", msg="c") and (domain="a", msg="bc") concatenate
	// identically; the length prefix must keep them distinct.
	let (sk, vk) = keypair();
	let sig = sk.sign(b"ab", b"c").unwrap();
	assert!(vk.verify(b"a", b"bc", &sig).is_err());
	vk.verify(b"ab", b"c", &sig).unwrap();
}

#[test]
fn oversized_domain_rejected() {
	let (sk, _) = keypair();
	let long = [0u8; 256];
	assert_eq!(sk.sign(&long, b"m").err(), Some(HybridSigError::DomainTooLong));
}

#[test]
fn bad_lengths_rejected() {
	let (sk, vk) = keypair();
	let sig = sk.sign(FINALITY_VOTE_DOMAIN, b"m").unwrap().to_vec();
	assert_eq!(
		HybridSignature::from_bytes(&sig[..sig.len() - 1]).err(),
		Some(HybridSigError::BadLength)
	);
	let pk = vk.to_vec();
	assert_eq!(
		HybridVerifyingKey::from_bytes(&pk[..pk.len() - 1]).err(),
		Some(HybridSigError::BadLength)
	);
	assert_eq!(
		HybridSigningKey::from_bytes(&[0u8; HYBRID_SK_BYTES - 1]).err(),
		Some(HybridSigError::BadLength)
	);
}

#[test]
fn from_seed_deterministic_and_functional() {
	let seed = [7u8; SEED_BYTES];
	let a = HybridSigningKey::from_seed(&seed);
	let b = HybridSigningKey::from_seed(&seed);
	assert_eq!(a.to_vec(), b.to_vec());
	assert_eq!(a.verifying_key().to_vec(), b.verifying_key().to_vec());

	let c = HybridSigningKey::from_seed(&[8u8; SEED_BYTES]);
	assert_ne!(a.verifying_key().to_vec(), c.verifying_key().to_vec());

	let msg = b"seeded";
	let sig = a.sign(FINALITY_VOTE_DOMAIN, msg).unwrap();
	b.verifying_key().verify(FINALITY_VOTE_DOMAIN, msg, &sig).unwrap();
}

#[test]
fn wrong_key_rejected() {
	let (sk, _) = keypair();
	let (_, other_vk) = keypair();
	let msg = b"wrong key";
	let sig = sk.sign(FINALITY_VOTE_DOMAIN, msg).unwrap();
	assert!(other_vk.verify(FINALITY_VOTE_DOMAIN, msg, &sig).is_err());
}
