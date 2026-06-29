//! Optimization-pass tests — covers the new expiry/purge schedule,
//! Hot/Cold cert split, secondary double-map indexes, and the
//! permissionless `cleanup` extrinsic with optional recipient redirect.
//!
//! These tests run against the reference runtime and exercise
//! `on_initialize` by manually driving block numbers. The
//! `NoopBindingProofVerifier` is wired up so mints are exercised
//! against a real flow without live TPM hardware.

use codec::Encode;
use frame_support::{assert_noop, assert_ok, traits::{Currency, Hooks}, BoundedVec};
use sp_core::crypto::AccountId32;
use sp_runtime::BuildStorage;
use zk_pki_primitives::crypto::DevicePublicKey;
use zk_pki_primitives::template::PopRequirement;
use zk_pki_runtime::{Runtime, RuntimeOrigin, ZkPki};
use zk_pki_tpm::test_mock_verifier::MockVerdict;
use zk_pki_tpm::AttestationPayloadV3;

fn template_name() -> BoundedVec<u8, frame_support::traits::ConstU32<64>> {
    BoundedVec::try_from(b"test-template".to_vec()).unwrap()
}

// ──────────────────────────────────────────────────────────────────────
// Shared harness (mirrors mint_cert.rs / query_api.rs)
// ──────────────────────────────────────────────────────────────────────

const ROOT_ACCOUNT: [u8; 32] = [0xA1; 32];
const ISSUER_ACCOUNT: [u8; 32] = [0xB2; 32];
const USER_ACCOUNT: [u8; 32] = [0xC3; 32];
const ROOT_PROXY: [u8; 32] = [0xD4; 32];
const ISSUER_PROXY: [u8; 32] = [0xE5; 32];
const RECIPIENT_ACCOUNT: [u8; 32] = [0xF6; 32];

const INITIAL_BALANCE: u128 = 100_000_000_000_000;

fn account(seed: [u8; 32]) -> AccountId32 {
    AccountId32::from(seed)
}

fn test_cert_ec_pubkey() -> Vec<u8> {
    use p256::ecdsa::{SigningKey, VerifyingKey};
    let sk = SigningKey::from_slice(&[7u8; 32]).expect("valid P-256 scalar");
    let vk: VerifyingKey = *sk.verifying_key();
    vk.to_encoded_point(false).as_bytes().to_vec()
}

fn new_test_ext() -> sp_io::TestExternalities {
    let mut t = frame_system::GenesisConfig::<Runtime>::default()
        .build_storage()
        .unwrap();
    pallet_balances::GenesisConfig::<Runtime> {
        balances: vec![
            (account(ROOT_ACCOUNT), INITIAL_BALANCE),
            (account(ISSUER_ACCOUNT), INITIAL_BALANCE),
            (account(USER_ACCOUNT), INITIAL_BALANCE),
            (account(ROOT_PROXY), INITIAL_BALANCE),
            (account(ISSUER_PROXY), INITIAL_BALANCE),
            (account(RECIPIENT_ACCOUNT), INITIAL_BALANCE),
        ],
        dev_accounts: None,
    }
    .assimilate_storage(&mut t)
    .unwrap();
    t.into()
}

fn run<R>(f: impl FnOnce() -> R) -> R {
    new_test_ext().execute_with(|| {
        frame_system::Pallet::<Runtime>::set_block_number(1);
        f()
    })
}

fn set_block(n: u64) {
    frame_system::Pallet::<Runtime>::set_block_number(n);
}

/// Advance the block number to `target` and fire on_initialize at
/// every block between the current and target (inclusive). Needed
/// because tests must deliberately exercise on_initialize at both
/// the expiry block and the scheduled purge block.
fn advance_to(target: u64) {
    let mut n = frame_system::Pallet::<Runtime>::block_number();
    while n < target {
        n += 1;
        set_block(n);
        let _ = <zk_pki_pallet::Pallet<Runtime> as Hooks<u64>>::on_initialize(n);
    }
}

fn setup_up_to_offer(user: [u8; 32]) -> ([u8; 32], u64) {
    let root_pubkey =
        DevicePublicKey::new_p256(&test_cert_ec_pubkey()).expect("valid P-256 pubkey");
    let empty_att: BoundedVec<_, _> = BoundedVec::try_from(vec![]).unwrap();
    let empty_cap_ekus:
        BoundedVec<zk_pki_primitives::eku::Eku, frame_support::traits::ConstU32<8>> =
        BoundedVec::try_from(vec![]).unwrap();
    let empty_template_ekus:
        BoundedVec<zk_pki_primitives::eku::Eku, frame_support::traits::ConstU32<16>> =
        BoundedVec::try_from(vec![]).unwrap();
    assert_ok!(ZkPki::register_root(
        RuntimeOrigin::signed(account(ROOT_ACCOUNT)),
        account(ROOT_PROXY),
        root_pubkey.clone(),
        empty_att.clone(),
        1_000_000u64,
        empty_cap_ekus.clone(),
    ));
    assert_ok!(ZkPki::issue_issuer_cert(
        RuntimeOrigin::signed(account(ROOT_ACCOUNT)),
        account(ISSUER_ACCOUNT),
        account(ISSUER_PROXY),
        root_pubkey,
        empty_att,
        500_000u64,
        empty_cap_ekus,
    ));
    assert_ok!(ZkPki::create_cert_template(
        RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
        template_name(),
        PopRequirement::NotRequired,
        None, // pop_mechanism
        400_000u64,
        1_000u64,
        None,
        None,
        empty_template_ekus,
    ));
    let empty_meta: BoundedVec<_, _> = BoundedVec::try_from(vec![]).unwrap();
    assert_ok!(ZkPki::offer_contract(
        RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
        account(user),
        10_000u64,
        template_name(),
        empty_meta,
    ));
    let ui_key = zk_pki_primitives::keys::IssuerUserKey::new(
        account(ISSUER_ACCOUNT),
        account(user),
    );
    let nonce = zk_pki_pallet::OfferIndex::<Runtime>::get(&ui_key).unwrap();
    let offer = zk_pki_pallet::ContractOffers::<Runtime>::get(nonce).unwrap();
    (nonce, offer.created_at)
}

fn mint_tpm_cert(user: [u8; 32], ek_hash: [u8; 32]) -> [u8; 32] {
    let (nonce, created_at) = setup_up_to_offer(user);
    let payload = AttestationPayloadV3 {
        cert_ec_chain: vec![vec![]],
        attest_ec_chain: vec![vec![]],
        hmac_binding_output: [0u8; 32],
        binding_signature: vec![],
        integrity_blob: MockVerdict::Tpm {
            ek_hash,
            pubkey_bytes: test_cert_ec_pubkey(),
        }
        .encode(),
        integrity_signature: vec![],
    };
    assert_ok!(ZkPki::mint_cert(
        RuntimeOrigin::signed(account(user)),
        nonce,
        payload,
        created_at,
        None,
        None, // commitment_c
        None, // ec_key_pub_claimed
        None, // chat_enrollment
    ));
    let ui_key = zk_pki_primitives::keys::UserIssuerKey::new(
        account(user),
        account(ISSUER_ACCOUNT),
    );
    zk_pki_pallet::UserIssuerIndex::<Runtime>::get(&ui_key)
        .expect("cert minted")
}

// ──────────────────────────────────────────────────────────────────────
// Expiry schedule
// ──────────────────────────────────────────────────────────────────────

#[test]
fn expiry_index_written_at_mint() {
    run(|| {
        let thumbprint = mint_tpm_cert(USER_ACCOUNT, [0x42u8; 32]);
        let hot = zk_pki_pallet::CertLookupHot::<Runtime>::get(thumbprint).unwrap();
        let scheduled = zk_pki_pallet::ExpiryIndex::<Runtime>::get(hot.expiry_block);
        assert!(
            scheduled.contains(&thumbprint),
            "expiry block must contain the minted thumbprint",
        );
    });
}

#[test]
fn on_initialize_flips_is_active_at_expiry_block() {
    run(|| {
        let thumbprint = mint_tpm_cert(USER_ACCOUNT, [0x42u8; 32]);
        let expiry = zk_pki_pallet::CertLookupHot::<Runtime>::get(thumbprint)
            .unwrap()
            .expiry_block;
        advance_to(expiry);
        let hot = zk_pki_pallet::CertLookupHot::<Runtime>::get(thumbprint).unwrap();
        assert!(!hot.is_active(), "expiry should flip state to Suspended");
        // Cold suspension_block should be set by on_initialize.
        let cold = zk_pki_pallet::CertLookupCold::<Runtime>::get(thumbprint).unwrap();
        assert_eq!(cold.suspension_block, Some(expiry));
    });
}

#[test]
fn on_initialize_purges_at_30_day_grace_mark() {
    run(|| {
        let thumbprint = mint_tpm_cert(USER_ACCOUNT, [0x42u8; 32]);
        let expiry = zk_pki_pallet::CertLookupHot::<Runtime>::get(thumbprint)
            .unwrap()
            .expiry_block;
        let reserved_before = pallet_balances::Pallet::<Runtime>::reserved_balance(
            &account(USER_ACCOUNT),
        );
        let purge_block = expiry + 432_000u64; // InactivePurgePeriod
        advance_to(purge_block);
        assert!(
            zk_pki_pallet::CertLookupHot::<Runtime>::get(thumbprint).is_none(),
            "hot record removed after purge",
        );
        assert!(
            zk_pki_pallet::CertLookupCold::<Runtime>::get(thumbprint).is_none(),
            "cold record removed after purge",
        );
        let reserved_after = pallet_balances::Pallet::<Runtime>::reserved_balance(
            &account(USER_ACCOUNT),
        );
        assert!(
            reserved_after < reserved_before,
            "deposit unreserved on purge",
        );
    });
}

#[test]
fn on_initialize_skips_reactivated_certs() {
    run(|| {
        let thumbprint = mint_tpm_cert(USER_ACCOUNT, [0x42u8; 32]);
        // Suspend at block 100 — schedules purge at 100 + 432_000.
        set_block(100u64);
        assert_ok!(ZkPki::suspend_cert(
            RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
            thumbprint,
            None,
        ));
        // Reactivate before the scheduled purge block.
        set_block(200u64);
        assert_ok!(ZkPki::reactivate_cert(
            RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
            thumbprint,
        ));
        // Roll past the original purge block — cert must still exist.
        advance_to(100 + 432_000 + 10);
        assert!(
            zk_pki_pallet::CertLookupHot::<Runtime>::get(thumbprint).is_some(),
            "reactivated cert must not be purged at old scheduled block",
        );
    });
}

#[test]
fn reissuance_updates_expiry_index() {
    run(|| {
        let thumbprint = mint_tpm_cert(USER_ACCOUNT, [0x42u8; 32]);
        let old_expiry = zk_pki_pallet::CertLookupHot::<Runtime>::get(thumbprint)
            .unwrap()
            .expiry_block;
        // Reissue with a fresh EK hash and new metadata.
        let new_pubkey =
            DevicePublicKey::new_p256(&test_cert_ec_pubkey()).expect("pubkey");
        let empty_att: BoundedVec<_, _> = BoundedVec::try_from(vec![]).unwrap();
        let new_meta: BoundedVec<_, _> =
            BoundedVec::try_from(b"reissued".to_vec()).unwrap();
        assert_ok!(ZkPki::reissue_cert(
            RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
            thumbprint,
            new_pubkey,
            empty_att,
            20_000u64,
            new_meta,
        ));
        // Old expiry index slot should no longer contain the old thumbprint.
        let old_slot = zk_pki_pallet::ExpiryIndex::<Runtime>::get(old_expiry);
        assert!(
            !old_slot.contains(&thumbprint),
            "old thumbprint removed from ExpiryIndex on reissuance",
        );
    });
}

// ──────────────────────────────────────────────────────────────────────
// cleanup extrinsic
// ──────────────────────────────────────────────────────────────────────

#[test]
fn cleanup_reaps_expired_inactive_cert() {
    run(|| {
        let thumbprint = mint_tpm_cert(USER_ACCOUNT, [0x42u8; 32]);
        let expiry = zk_pki_pallet::CertLookupHot::<Runtime>::get(thumbprint)
            .unwrap()
            .expiry_block;
        // Drive to expiry so on_initialize flips state to Suspended.
        advance_to(expiry);
        // Jump past the purge window — but use set_block so on_initialize
        // is NOT fired at the scheduled purge block. This forces the
        // cleanup path rather than the automatic purge.
        set_block(expiry + 432_000 + 1);
        let reserved_before = pallet_balances::Pallet::<Runtime>::reserved_balance(
            &account(USER_ACCOUNT),
        );
        assert_ok!(ZkPki::cleanup(
            RuntimeOrigin::signed(account(RECIPIENT_ACCOUNT)),
            thumbprint,
            None, // default recipient = cert holder
        ));
        let reserved_after = pallet_balances::Pallet::<Runtime>::reserved_balance(
            &account(USER_ACCOUNT),
        );
        assert!(
            reserved_after < reserved_before,
            "deposit unreserved to holder on cleanup",
        );
        assert!(zk_pki_pallet::CertLookupHot::<Runtime>::get(thumbprint).is_none());
        assert!(zk_pki_pallet::CertLookupCold::<Runtime>::get(thumbprint).is_none());
    });
}

#[test]
fn cleanup_rejects_active_cert() {
    run(|| {
        let thumbprint = mint_tpm_cert(USER_ACCOUNT, [0x42u8; 32]);
        assert_noop!(
            ZkPki::cleanup(
                RuntimeOrigin::signed(account(RECIPIENT_ACCOUNT)),
                thumbprint,
                None,
            ),
            zk_pki_pallet::Error::<Runtime>::CertNotReapable,
        );
    });
}

#[test]
fn cleanup_rejects_recently_expired_cert() {
    run(|| {
        let thumbprint = mint_tpm_cert(USER_ACCOUNT, [0x42u8; 32]);
        let expiry = zk_pki_pallet::CertLookupHot::<Runtime>::get(thumbprint)
            .unwrap()
            .expiry_block;
        advance_to(expiry);
        // Cert is now Suspended but purge window has not passed.
        set_block(expiry + 100);
        assert_noop!(
            ZkPki::cleanup(
                RuntimeOrigin::signed(account(RECIPIENT_ACCOUNT)),
                thumbprint,
                None,
            ),
            zk_pki_pallet::Error::<Runtime>::CertNotReapable,
        );
    });
}

#[test]
fn cleanup_redirects_deposit_to_specified_recipient() {
    run(|| {
        let thumbprint = mint_tpm_cert(USER_ACCOUNT, [0x42u8; 32]);
        let expiry = zk_pki_pallet::CertLookupHot::<Runtime>::get(thumbprint)
            .unwrap()
            .expiry_block;
        advance_to(expiry);
        set_block(expiry + 432_000 + 1);
        let recipient_free_before = pallet_balances::Pallet::<Runtime>::free_balance(
            &account(RECIPIENT_ACCOUNT),
        );
        let holder_total_before =
            pallet_balances::Pallet::<Runtime>::total_balance(&account(USER_ACCOUNT));
        assert_ok!(ZkPki::cleanup(
            RuntimeOrigin::signed(account(RECIPIENT_ACCOUNT)),
            thumbprint,
            Some(account(RECIPIENT_ACCOUNT)),
        ));
        let recipient_free_after = pallet_balances::Pallet::<Runtime>::free_balance(
            &account(RECIPIENT_ACCOUNT),
        );
        let holder_total_after =
            pallet_balances::Pallet::<Runtime>::total_balance(&account(USER_ACCOUNT));
        assert!(
            recipient_free_after > recipient_free_before,
            "recipient received redirected deposit",
        );
        assert!(
            holder_total_after < holder_total_before,
            "holder lost the reserved deposit on redirect",
        );
    });
}

// ──────────────────────────────────────────────────────────────────────
// Secondary indexes & Hot/Cold split
// ──────────────────────────────────────────────────────────────────────

#[test]
fn secondary_indexes_written_at_mint() {
    run(|| {
        let thumbprint = mint_tpm_cert(USER_ACCOUNT, [0x42u8; 32]);
        assert!(zk_pki_pallet::CertsByIssuer::<Runtime>::contains_key(
            &account(ISSUER_ACCOUNT),
            thumbprint,
        ));
        assert!(zk_pki_pallet::CertsByUser::<Runtime>::contains_key(
            &account(USER_ACCOUNT),
            thumbprint,
        ));
        assert!(zk_pki_pallet::CertsByRoot::<Runtime>::contains_key(
            &account(ROOT_ACCOUNT),
            thumbprint,
        ));
    });
}

#[test]
fn secondary_indexes_removed_at_purge() {
    run(|| {
        let thumbprint = mint_tpm_cert(USER_ACCOUNT, [0x42u8; 32]);
        let expiry = zk_pki_pallet::CertLookupHot::<Runtime>::get(thumbprint)
            .unwrap()
            .expiry_block;
        advance_to(expiry + 432_000);
        assert!(!zk_pki_pallet::CertsByIssuer::<Runtime>::contains_key(
            &account(ISSUER_ACCOUNT),
            thumbprint,
        ));
        assert!(!zk_pki_pallet::CertsByUser::<Runtime>::contains_key(
            &account(USER_ACCOUNT),
            thumbprint,
        ));
        assert!(!zk_pki_pallet::CertsByRoot::<Runtime>::contains_key(
            &account(ROOT_ACCOUNT),
            thumbprint,
        ));
    });
}

#[test]
fn hot_cold_split_written_atomically() {
    run(|| {
        let thumbprint = mint_tpm_cert(USER_ACCOUNT, [0x42u8; 32]);
        assert!(zk_pki_pallet::CertLookupHot::<Runtime>::get(thumbprint).is_some());
        assert!(zk_pki_pallet::CertLookupCold::<Runtime>::get(thumbprint).is_some());
    });
}

#[test]
fn hot_cold_split_removed_atomically() {
    run(|| {
        let thumbprint = mint_tpm_cert(USER_ACCOUNT, [0x42u8; 32]);
        // Self-discard triggers remove_cert_entry.
        assert_ok!(ZkPki::self_discard_cert(
            RuntimeOrigin::signed(account(USER_ACCOUNT)),
            thumbprint,
            None,
        ));
        assert!(zk_pki_pallet::CertLookupHot::<Runtime>::get(thumbprint).is_none());
        assert!(zk_pki_pallet::CertLookupCold::<Runtime>::get(thumbprint).is_none());
    });
}
