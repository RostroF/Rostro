//! Device-key reverse index tests (identity-rails socket S1).
//!
//! Exercises `CertByDeviceKey` maintenance across the cert lifecycle,
//! the canonical `DevicePublicKey::lookup_hash` derivation (compressed /
//! uncompressed SEC1 equivalence), the guarded remove that protects a
//! repointed entry, and the v0 → v1 backfill migration. Follows the
//! query_api.rs convention: pallet functions called directly inside test
//! externalities; the runtime-API forwarding layer is verified at
//! node-binary integration time.

use codec::Encode;
use frame_support::{assert_ok, BoundedVec};
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
// Test harness — minimal duplication of `query_api.rs` helpers so the
// two test files stay decoupled
// ──────────────────────────────────────────────────────────────────────

const ROOT_ACCOUNT: [u8; 32] = [0xA1; 32];
const ISSUER_ACCOUNT: [u8; 32] = [0xB2; 32];
const USER_ACCOUNT: [u8; 32] = [0xC3; 32];
const ROOT_PROXY: [u8; 32] = [0xD4; 32];
const ISSUER_PROXY: [u8; 32] = [0xE5; 32];

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

fn test_cert_ec_pubkey_compressed() -> Vec<u8> {
    use p256::ecdsa::{SigningKey, VerifyingKey};
    let sk = SigningKey::from_slice(&[7u8; 32]).expect("valid P-256 scalar");
    let vk: VerifyingKey = *sk.verifying_key();
    vk.to_encoded_point(true).as_bytes().to_vec()
}

/// Distinct key for the root/issuer entity certs so the user cert's
/// device key maps to a unique index slot — three certs sharing one
/// key would make the backfill's winner depend on iteration order.
fn entity_cert_ec_pubkey() -> Vec<u8> {
    use p256::ecdsa::{SigningKey, VerifyingKey};
    let sk = SigningKey::from_slice(&[8u8; 32]).expect("valid P-256 scalar");
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

fn setup_up_to_offer() -> ([u8; 32], u64) {
    let root_pubkey =
        DevicePublicKey::new_p256(&entity_cert_ec_pubkey()).expect("valid P-256 pubkey");
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
        account(USER_ACCOUNT),
        10_000u64,
        template_name(),
        empty_meta,
    ));
    let ui_key = zk_pki_primitives::keys::IssuerUserKey::new(
        account(ISSUER_ACCOUNT),
        account(USER_ACCOUNT),
    );
    let nonce = zk_pki_pallet::OfferIndex::<Runtime>::get(&ui_key).unwrap();
    let offer = zk_pki_pallet::ContractOffers::<Runtime>::get(nonce).unwrap();
    (nonce, offer.created_at)
}

fn mint_tpm_cert(ek_hash: [u8; 32]) -> [u8; 32] {
    let (nonce, created_at) = setup_up_to_offer();
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
        RuntimeOrigin::signed(account(USER_ACCOUNT)),
        nonce,
        payload,
        created_at,
        None,
        None, // commitment_c
        None, // ec_key_pub_claimed
        None, // chat_enrollment
    ));
    let ui_key = zk_pki_primitives::keys::UserIssuerKey::new(
        account(USER_ACCOUNT),
        account(ISSUER_ACCOUNT),
    );
    zk_pki_pallet::UserIssuerIndex::<Runtime>::get(&ui_key)
        .expect("cert minted, thumbprint indexed")
}

fn user_key_hash() -> [u8; 32] {
    DevicePublicKey::new_p256(&test_cert_ec_pubkey())
        .expect("valid P-256 pubkey")
        .lookup_hash()
        .expect("valid key canonicalizes")
}

// ──────────────────────────────────────────────────────────────────────
// lookup_hash canonicalization
// ──────────────────────────────────────────────────────────────────────

#[test]
fn compressed_and_uncompressed_keys_share_lookup_hash() {
    let uncompressed = DevicePublicKey::new_p256(&test_cert_ec_pubkey()).unwrap();
    let compressed = DevicePublicKey::new_p256(&test_cert_ec_pubkey_compressed()).unwrap();
    assert_ne!(uncompressed.key_bytes, compressed.key_bytes);
    assert_eq!(
        uncompressed.lookup_hash().expect("canonicalizes"),
        compressed.lookup_hash().expect("canonicalizes"),
        "SEC1 encoding form must not change the index key"
    );
}

#[test]
fn invalid_key_bytes_produce_no_lookup_hash() {
    let garbage = DevicePublicKey {
        algorithm: zk_pki_primitives::crypto::KeyAlgorithm::EcdsaP256,
        key_bytes: BoundedVec::try_from(vec![0xFFu8; 65]).unwrap(),
    };
    assert_eq!(garbage.lookup_hash(), None);
}

// ──────────────────────────────────────────────────────────────────────
// Lifecycle maintenance
// ──────────────────────────────────────────────────────────────────────

#[test]
fn mint_indexes_device_key() {
    run(|| {
        let thumbprint = mint_tpm_cert([0x42u8; 32]);
        assert_eq!(
            zk_pki_pallet::Pallet::<Runtime>::query_cert_by_device_key(user_key_hash()),
            Some(thumbprint),
        );
    });
}

#[test]
fn invalidate_clears_index() {
    run(|| {
        let thumbprint = mint_tpm_cert([0x42u8; 32]);
        assert_ok!(ZkPki::invalidate_cert(
            RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
            thumbprint,
        ));
        assert_eq!(
            zk_pki_pallet::Pallet::<Runtime>::query_cert_by_device_key(user_key_hash()),
            None,
        );
    });
}

#[test]
fn suspend_keeps_index() {
    run(|| {
        let thumbprint = mint_tpm_cert([0x42u8; 32]);
        assert_ok!(ZkPki::suspend_cert(
            RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
            thumbprint,
            None,
        ));
        // Suspended certs still resolve — the verifier learns the state
        // from cert_status; the index only forgets purged records.
        assert_eq!(
            zk_pki_pallet::Pallet::<Runtime>::query_cert_by_device_key(user_key_hash()),
            Some(thumbprint),
        );
    });
}

#[test]
fn guarded_remove_preserves_repointed_entry() {
    run(|| {
        let thumbprint = mint_tpm_cert([0x42u8; 32]);
        // Simulate a reissue having repointed the key's entry at a
        // successor cert. Purging the superseded cert must not clobber
        // the live mapping.
        let successor = [0x99u8; 32];
        zk_pki_pallet::CertByDeviceKey::<Runtime>::insert(user_key_hash(), successor);
        assert_ok!(ZkPki::invalidate_cert(
            RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
            thumbprint,
        ));
        assert_eq!(
            zk_pki_pallet::Pallet::<Runtime>::query_cert_by_device_key(user_key_hash()),
            Some(successor),
            "guarded remove must only clear an entry that still points at the removed cert"
        );
    });
}

// ──────────────────────────────────────────────────────────────────────
// v0 → v1 backfill migration
// ──────────────────────────────────────────────────────────────────────

#[test]
fn migration_backfills_index_from_cold_records() {
    use frame_support::traits::{GetStorageVersion, Hooks, StorageVersion};

    run(|| {
        let thumbprint = mint_tpm_cert([0x42u8; 32]);
        // Simulate a pre-v1 chain: index absent, version 0.
        zk_pki_pallet::CertByDeviceKey::<Runtime>::remove(user_key_hash());
        StorageVersion::new(0).put::<zk_pki_pallet::Pallet<Runtime>>();

        zk_pki_pallet::Pallet::<Runtime>::on_runtime_upgrade();

        assert_eq!(
            zk_pki_pallet::Pallet::<Runtime>::query_cert_by_device_key(user_key_hash()),
            Some(thumbprint),
        );
        assert_eq!(
            zk_pki_pallet::Pallet::<Runtime>::on_chain_storage_version(),
            StorageVersion::new(1),
        );
    });
}

#[test]
fn migration_is_idempotent_at_current_version() {
    use frame_support::traits::{Hooks, StorageVersion};

    run(|| {
        let thumbprint = mint_tpm_cert([0x42u8; 32]);
        // Pin the on-chain version to 1 explicitly — the minimal test
        // externalities skip runtime genesis, which is what normally
        // writes it. An upgrade at the current version must not touch
        // the index.
        StorageVersion::new(1).put::<zk_pki_pallet::Pallet<Runtime>>();
        zk_pki_pallet::CertByDeviceKey::<Runtime>::insert(user_key_hash(), [0x77u8; 32]);
        zk_pki_pallet::Pallet::<Runtime>::on_runtime_upgrade();
        assert_eq!(
            zk_pki_pallet::Pallet::<Runtime>::query_cert_by_device_key(user_key_hash()),
            Some([0x77u8; 32]),
            "guarded no-op: version >= 1 must skip the backfill"
        );
        let _ = thumbprint;
    });
}
