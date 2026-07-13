// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Keyring semantics tests, driven end-to-end with real keys: sr25519
//! roots minted from seeds, P-256 device keys signed the way StrongBox's
//! `SHA256withECDSA` does (low-s normalized). The founding use case —
//! 25519 root + P-256 convenience key, either rescindable, at least one
//! authority always standing — is exercised literally.

use crate::{
	enroll_challenge, mock::*, Error, Event, KeyringEntry, Policy, ENROLL_DOMAIN_TAG,
};
use codec::Encode;
use frame_support::{assert_noop, assert_ok, traits::ConstU32};
use rostro_multi_key::{sr25519_to_account, RostroSignature, RostroSigner};
use sp_core::{crypto::AccountId32, sr25519, Pair as PairTrait};

fn storage(who: &AccountId32) -> Option<KeyringEntry<ConstU32<5>>> {
	crate::Keyring::<Test>::get(who)
}

fn verify(sig: &RostroSignature, payload: &[u8], who: &AccountId32) -> bool {
	Keyring::verify_extrinsic_signature(sig, payload, who)
}

/// The sr25519 root: the account's minting key (mnemonic today, Ledger
/// later). Its raw pubkey IS the AccountId32.
fn root(seed: u8) -> (sr25519::Pair, AccountId32) {
	let pair = sr25519::Pair::from_seed(&[seed; 32]);
	let account = sr25519_to_account(&pair.public());
	(pair, account)
}

fn p256_key(seed: u8) -> (p256::ecdsa::SigningKey, [u8; 33]) {
	let sk = p256::ecdsa::SigningKey::from_slice(&[seed; 32]).expect("valid P-256 scalar");
	let pubkey: [u8; 33] =
		sk.verifying_key().to_encoded_point(true).as_bytes().try_into().expect("33 bytes");
	(sk, pubkey)
}

/// StrongBox-shaped signing: ECDSA over sha256(msg), normalized to low-s
/// (the wallet's submission contract).
fn p256_sign(sk: &p256::ecdsa::SigningKey, msg: &[u8]) -> [u8; 64] {
	use p256::ecdsa::{signature::Signer, Signature};
	let sig: Signature = sk.sign(msg);
	let sig = sig.normalize_s().unwrap_or(sig);
	sig.to_bytes().as_slice().try_into().expect("64-byte r||s")
}

/// Proof of possession: the candidate P-256 key signs `who`'s enroll
/// challenge. Must run inside externalities (reads the genesis hash).
fn p256_pop(sk: &p256::ecdsa::SigningKey, pubkey: [u8; 33], who: &AccountId32) -> RostroSignature {
	let challenge = Keyring::enroll_challenge_for(who);
	RostroSignature::EcdsaP256 { pubkey, sig: p256_sign(sk, &challenge) }
}

fn sr25519_pop(pair: &sr25519::Pair, who: &AccountId32) -> RostroSignature {
	let challenge = Keyring::enroll_challenge_for(who);
	RostroSignature::Sr25519(pair.sign(&challenge))
}

#[test]
fn no_entry_is_the_stateless_default() {
	new_test_ext().execute_with(|| {
		let (pair, account) = root(0x42);
		let msg = b"spend".to_vec();
		let good = RostroSignature::Sr25519(pair.sign(&msg));
		assert!(verify(&good, &msg, &account));

		let (other_pair, _) = root(0x43);
		let bad = RostroSignature::Sr25519(other_pair.sign(&msg));
		assert!(!verify(&bad, &msg, &account));
		assert!(storage(&account).is_none(), "no state was created");
	});
}

#[test]
fn founding_use_case_root_plus_p256_convenience_key() {
	new_test_ext().execute_with(|| {
		let (root_pair, account) = root(0x42);
		let (sk, pubkey) = p256_key(0x07);

		assert_ok!(Keyring::enroll_key(
			RuntimeOrigin::signed(account.clone()),
			RostroSigner::EcdsaP256(pubkey),
			p256_pop(&sk, pubkey, &account),
		));
		System::assert_last_event(
			Event::KeyEnrolled { who: account.clone(), key: RostroSigner::EcdsaP256(pubkey) }
				.into(),
		);
		let entry = storage(&account).expect("entry created");
		assert_eq!(entry.policy, Policy::Either);
		assert!(!entry.derived_rescinded);

		// The device key now signs for the ROOT's account — an account its
		// own pubkey does not hash to. This is the keyring's whole point.
		let msg = b"spend".to_vec();
		let device_sig = RostroSignature::EcdsaP256 { pubkey, sig: p256_sign(&sk, &msg) };
		assert!(verify(&device_sig, &msg, &account));

		// The root still signs (Either, derived authority intact).
		let root_sig = RostroSignature::Sr25519(root_pair.sign(&msg));
		assert!(verify(&root_sig, &msg, &account));

		// The device key does NOT sign for anyone else.
		let (_, other_account) = root(0x43);
		assert!(!verify(&device_sig, &msg, &other_account));
	});
}

#[test]
fn enroll_rejects_bad_or_replayed_pop() {
	new_test_ext().execute_with(|| {
		let (_, account) = root(0x42);
		let (_, other_account) = root(0x43);
		let (sk, pubkey) = p256_key(0x07);

		// PoP over the wrong bytes (not the challenge).
		let garbage =
			RostroSignature::EcdsaP256 { pubkey, sig: p256_sign(&sk, b"not the challenge") };
		assert_noop!(
			Keyring::enroll_key(
				RuntimeOrigin::signed(account.clone()),
				RostroSigner::EcdsaP256(pubkey),
				garbage,
			),
			Error::<Test>::BadProofOfPossession
		);

		// PoP minted for another account must not enroll here: the
		// challenge binds the account.
		let other_pop = p256_pop(&sk, pubkey, &other_account);
		assert_noop!(
			Keyring::enroll_key(
				RuntimeOrigin::signed(account.clone()),
				RostroSigner::EcdsaP256(pubkey),
				other_pop,
			),
			Error::<Test>::BadProofOfPossession
		);

		// PoP by a different key than the one being enrolled.
		let (sk2, pubkey2) = p256_key(0x08);
		let wrong_key_pop = p256_pop(&sk2, pubkey2, &account);
		assert_noop!(
			Keyring::enroll_key(
				RuntimeOrigin::signed(account.clone()),
				RostroSigner::EcdsaP256(pubkey),
				wrong_key_pop,
			),
			Error::<Test>::BadProofOfPossession
		);

		assert!(storage(&account).is_none(), "nothing enrolled");
	});
}

#[test]
fn enroll_challenge_format_is_the_documented_wire_contract() {
	new_test_ext().execute_with(|| {
		// The wallet builds this byte sequence independently; freeze it.
		let (_, account) = root(0x42);
		let genesis = frame_system::Pallet::<Test>::block_hash(0u64);
		assert_eq!(
			Keyring::enroll_challenge_for(&account),
			(ENROLL_DOMAIN_TAG, &genesis, &account).encode(),
		);
		assert_eq!(
			enroll_challenge(&genesis, &account),
			Keyring::enroll_challenge_for(&account),
		);
	});
}

#[test]
fn enroll_rejects_duplicates_and_overflow() {
	new_test_ext().execute_with(|| {
		let (_, account) = root(0x42);
		let (sk, pubkey) = p256_key(0x07);

		assert_ok!(Keyring::enroll_key(
			RuntimeOrigin::signed(account.clone()),
			RostroSigner::EcdsaP256(pubkey),
			p256_pop(&sk, pubkey, &account),
		));
		assert_noop!(
			Keyring::enroll_key(
				RuntimeOrigin::signed(account.clone()),
				RostroSigner::EcdsaP256(pubkey),
				p256_pop(&sk, pubkey, &account),
			),
			Error::<Test>::AlreadyEnrolled
		);

		// Fill to MaxKeys = 5, then one more must overflow.
		for seed in 0x08u8..0x0c {
			let (sk_n, pk_n) = p256_key(seed);
			assert_ok!(Keyring::enroll_key(
				RuntimeOrigin::signed(account.clone()),
				RostroSigner::EcdsaP256(pk_n),
				p256_pop(&sk_n, pk_n, &account),
			));
		}
		let (sk_x, pk_x) = p256_key(0x0c);
		assert_noop!(
			Keyring::enroll_key(
				RuntimeOrigin::signed(account.clone()),
				RostroSigner::EcdsaP256(pk_x),
				p256_pop(&sk_x, pk_x, &account),
			),
			Error::<Test>::TooManyKeys
		);
	});
}

#[test]
fn rescind_derived_flips_root_authority_and_restore_returns_it() {
	new_test_ext().execute_with(|| {
		let (root_pair, account) = root(0x42);
		let (sk, pubkey) = p256_key(0x07);
		let msg = b"spend".to_vec();
		let root_sig = RostroSignature::Sr25519(root_pair.sign(&msg));
		let device_sig = RostroSignature::EcdsaP256 { pubkey, sig: p256_sign(&sk, &msg) };

		assert_ok!(Keyring::enroll_key(
			RuntimeOrigin::signed(account.clone()),
			RostroSigner::EcdsaP256(pubkey),
			p256_pop(&sk, pubkey, &account),
		));
		assert_ok!(Keyring::rescind_derived(RuntimeOrigin::signed(account.clone())));
		System::assert_last_event(Event::DerivedRescinded { who: account.clone() }.into());

		// Root (derived) authority is gone; only the enrolled key signs.
		assert!(!verify(&root_sig, &msg, &account), "derived path must be dead");
		assert!(verify(&device_sig, &msg, &account));

		assert_noop!(
			Keyring::rescind_derived(RuntimeOrigin::signed(account.clone())),
			Error::<Test>::DerivedAlreadyRescinded
		);

		assert_ok!(Keyring::restore_derived(RuntimeOrigin::signed(account.clone())));
		System::assert_last_event(Event::DerivedRestored { who: account.clone() }.into());
		assert!(verify(&root_sig, &msg, &account), "derived authority restored");
	});
}

#[test]
fn at_least_one_authority_always_remains() {
	new_test_ext().execute_with(|| {
		let (_, account) = root(0x42);
		let (sk, pubkey) = p256_key(0x07);
		let key = RostroSigner::EcdsaP256(pubkey);

		// No entry: nothing to rescind.
		assert_noop!(
			Keyring::rescind_derived(RuntimeOrigin::signed(account.clone())),
			Error::<Test>::NoKeyringEntry
		);
		assert_noop!(
			Keyring::rescind_key(RuntimeOrigin::signed(account.clone()), key.clone()),
			Error::<Test>::NoKeyringEntry
		);

		assert_ok!(Keyring::enroll_key(
			RuntimeOrigin::signed(account.clone()),
			key.clone(),
			p256_pop(&sk, pubkey, &account),
		));
		assert_ok!(Keyring::rescind_derived(RuntimeOrigin::signed(account.clone())));

		// Derived rescinded + one key left: that key is the last authority.
		assert_noop!(
			Keyring::rescind_key(RuntimeOrigin::signed(account.clone()), key.clone()),
			Error::<Test>::LastAuthority
		);

		// Restore derived, then the key can go — and the entry with it.
		assert_ok!(Keyring::restore_derived(RuntimeOrigin::signed(account.clone())));
		assert_ok!(Keyring::rescind_key(RuntimeOrigin::signed(account.clone()), key.clone()));
		assert!(storage(&account).is_none(), "empty entry must be deleted, not kept");

		// And rescinding an unknown key on a fresh entry errors cleanly.
		let (sk2, pubkey2) = p256_key(0x08);
		assert_ok!(Keyring::enroll_key(
			RuntimeOrigin::signed(account.clone()),
			RostroSigner::EcdsaP256(pubkey2),
			p256_pop(&sk2, pubkey2, &account),
		));
		assert_noop!(
			Keyring::rescind_key(RuntimeOrigin::signed(account.clone()), key),
			Error::<Test>::KeyNotEnrolled
		);
	});
}

#[test]
fn rescinded_key_stops_signing_immediately() {
	new_test_ext().execute_with(|| {
		let (_, account) = root(0x42);
		let (sk, pubkey) = p256_key(0x07);
		let msg = b"spend".to_vec();
		let device_sig = RostroSignature::EcdsaP256 { pubkey, sig: p256_sign(&sk, &msg) };

		assert_ok!(Keyring::enroll_key(
			RuntimeOrigin::signed(account.clone()),
			RostroSigner::EcdsaP256(pubkey),
			p256_pop(&sk, pubkey, &account),
		));
		assert!(verify(&device_sig, &msg, &account));

		assert_ok!(Keyring::rescind_key(
			RuntimeOrigin::signed(account.clone()),
			RostroSigner::EcdsaP256(pubkey)
		));
		assert!(
			!verify(&device_sig, &msg, &account),
			"a rescinded key must not authorize anything — no grace window"
		);
	});
}

#[test]
fn second_25519_key_enrolls_and_signs_for_the_root_account() {
	new_test_ext().execute_with(|| {
		// Not just device keys: a second sr25519 (e.g. a successor mnemonic
		// during root rotation) enrolls the same way.
		let (_, account) = root(0x42);
		let (successor, _) = root(0x43);
		let msg = b"spend".to_vec();

		assert_ok!(Keyring::enroll_key(
			RuntimeOrigin::signed(account.clone()),
			RostroSigner::Sr25519(successor.public()),
			sr25519_pop(&successor, &account),
		));
		let successor_sig = RostroSignature::Sr25519(successor.sign(&msg));
		assert!(verify(&successor_sig, &msg, &account));

		// After rescinding derived, the account is fully re-rooted on the
		// successor key: same AccountId32, new authority. RNS names, certs,
		// reputation — all keyed by account — ride through untouched.
		assert_ok!(Keyring::rescind_derived(RuntimeOrigin::signed(account.clone())));
		assert!(verify(&successor_sig, &msg, &account));
	});
}

#[test]
fn restore_derived_requires_rescinded_state() {
	new_test_ext().execute_with(|| {
		let (_, account) = root(0x42);
		let (sk, pubkey) = p256_key(0x07);

		assert_noop!(
			Keyring::restore_derived(RuntimeOrigin::signed(account.clone())),
			Error::<Test>::NoKeyringEntry
		);
		assert_ok!(Keyring::enroll_key(
			RuntimeOrigin::signed(account.clone()),
			RostroSigner::EcdsaP256(pubkey),
			p256_pop(&sk, pubkey, &account),
		));
		assert_noop!(
			Keyring::restore_derived(RuntimeOrigin::signed(account.clone())),
			Error::<Test>::DerivedNotRescinded
		);
	});
}
