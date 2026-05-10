//! Runtime-API query tests (TODO-5).
//!
//! Exercises the pallet's `query_cert_status`, `query_chain_valid_at`,
//! `query_entity_status`, and `query_ek_lookup` functions that back
//! the `ZkPkiApi` runtime API. These tests call the pallet functions
//! directly inside test externalities rather than going through the
//! `impl_runtime_apis!` macro + RPC server — the query logic is the
//! thing under test; the RPC transport is a thin forwarding layer
//! verified at node-binary integration time.

use codec::Encode;
use frame_support::{assert_ok, BoundedVec};
use sp_core::crypto::AccountId32;
use sp_runtime::BuildStorage;
use zk_pki_primitives::crypto::DevicePublicKey;
use zk_pki_primitives::runtime_api::{
    CertState, EntityState, EntityType, OcspStatus, RevocationReason,
};
use zk_pki_primitives::template::PopRequirement;
use zk_pki_runtime::{Runtime, RuntimeOrigin, ZkPki};
use zk_pki_tpm::test_mock_verifier::MockVerdict;
use zk_pki_tpm::AttestationPayloadV3;

fn template_name() -> BoundedVec<u8, frame_support::traits::ConstU32<64>> {
    BoundedVec::try_from(b"test-template".to_vec()).unwrap()
}

// ──────────────────────────────────────────────────────────────────────
// Test harness — minimal duplication of `mint_cert.rs` helpers so the
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

fn set_block(n: u64) {
    frame_system::Pallet::<Runtime>::set_block_number(n);
}

/// Register root → issue issuer cert → create offer for USER_ACCOUNT.
/// Returns (offer_nonce, offer.created_at).
fn setup_up_to_offer() -> ([u8; 32], u64) {
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
    ));
    // Locate the minted thumbprint via the user-issuer index.
    let ui_key = zk_pki_primitives::keys::UserIssuerKey::new(
        account(USER_ACCOUNT),
        account(ISSUER_ACCOUNT),
    );
    zk_pki_pallet::UserIssuerIndex::<Runtime>::get(&ui_key)
        .expect("cert minted, thumbprint indexed")
}

// ──────────────────────────────────────────────────────────────────────
// cert_status tests
// ──────────────────────────────────────────────────────────────────────

#[test]
fn cert_status_active_returns_good() {
    run(|| {
        let ek = [0x42u8; 32];
        let thumbprint = mint_tpm_cert(ek);
        let status = zk_pki_pallet::Pallet::<Runtime>::query_cert_status(thumbprint)
            .expect("active cert resolves");
        assert_eq!(status.status, OcspStatus::Good);
        assert_eq!(status.cert_state, CertState::Active);
        assert_eq!(status.revocation_reason, None);
        assert_eq!(status.revocation_time, None);
        assert!(status.manufacturer_verified);
    });
}

#[test]
fn cert_status_suspended_returns_revoked() {
    run(|| {
        let thumbprint = mint_tpm_cert([0x42u8; 32]);
        // Issuer suspends the cert.
        assert_ok!(ZkPki::suspend_cert(
            RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
            thumbprint,
            None,
        ));
        let status = zk_pki_pallet::Pallet::<Runtime>::query_cert_status(thumbprint)
            .expect("suspended cert still resolves");
        assert_eq!(status.status, OcspStatus::Revoked);
        assert_eq!(status.cert_state, CertState::Suspended);
        assert_eq!(status.revocation_reason, Some(RevocationReason::Suspended));
        assert!(status.revocation_time.is_some());
    });
}

#[test]
fn cert_status_unknown_thumbprint_returns_none() {
    run(|| {
        let status =
            zk_pki_pallet::Pallet::<Runtime>::query_cert_status([0x99u8; 32]);
        assert!(status.is_none());
    });
}

// ──────────────────────────────────────────────────────────────────────
// chain_valid_at tests
// ──────────────────────────────────────────────────────────────────────

#[test]
fn chain_valid_at_mint_block_returns_true() {
    run(|| {
        // Mint happens at the current block — whatever block
        // `setup_up_to_offer`'s final offer sits on, plus the implicit
        // block-1 set by `run()`.
        let thumbprint = mint_tpm_cert([0x42u8; 32]);
        let mint_block =
            zk_pki_pallet::CertLookupHot::<Runtime>::get(thumbprint).unwrap().mint_block;
        assert!(
            zk_pki_pallet::Pallet::<Runtime>::query_chain_valid_at(thumbprint, mint_block),
            "cert must be valid at its own mint block",
        );
    });
}

#[test]
fn chain_valid_at_before_mint_returns_false() {
    run(|| {
        let thumbprint = mint_tpm_cert([0x42u8; 32]);
        let mint_block =
            zk_pki_pallet::CertLookupHot::<Runtime>::get(thumbprint).unwrap().mint_block;
        // One block before mint — cert didn't exist yet.
        assert!(
            !zk_pki_pallet::Pallet::<Runtime>::query_chain_valid_at(
                thumbprint,
                mint_block.saturating_sub(1),
            ),
            "cert must NOT be valid before its mint block",
        );
    });
}

#[test]
fn chain_valid_at_after_expiry_returns_false() {
    run(|| {
        let thumbprint = mint_tpm_cert([0x42u8; 32]);
        let expiry =
            zk_pki_pallet::CertLookupHot::<Runtime>::get(thumbprint).unwrap().expiry_block;
        assert!(
            !zk_pki_pallet::Pallet::<Runtime>::query_chain_valid_at(thumbprint, expiry + 1),
            "cert must NOT be valid after expiry",
        );
    });
}

#[test]
fn chain_valid_at_compromised_issuer_returns_false() {
    run(|| {
        let thumbprint = mint_tpm_cert([0x42u8; 32]);
        let mint_block =
            zk_pki_pallet::CertLookupHot::<Runtime>::get(thumbprint).unwrap().mint_block;

        // Advance one block and compromise the issuer.
        set_block(mint_block + 1);
        assert_ok!(ZkPki::invalidate_issuer(
            RuntimeOrigin::signed(account(ROOT_ACCOUNT)),
            account(ISSUER_ACCOUNT),
        ));

        // At the compromise block (and after), the cert's chain is
        // no longer valid even though the cert itself is still in
        // the lookup table and hasn't expired.
        let query_block = mint_block + 2;
        assert!(
            !zk_pki_pallet::Pallet::<Runtime>::query_chain_valid_at(thumbprint, query_block),
            "cert must NOT be chain-valid after issuer compromise",
        );

        // But the cert WAS valid at its mint block, before the
        // compromise happened — compromise is not retroactive past
        // the `at_block`.
        assert!(
            zk_pki_pallet::Pallet::<Runtime>::query_chain_valid_at(thumbprint, mint_block),
            "cert must still be chain-valid at an earlier block",
        );
    });
}

// ──────────────────────────────────────────────────────────────────────
// entity_status + ek_lookup
// ──────────────────────────────────────────────────────────────────────

#[test]
fn entity_status_returns_correct_state() {
    run(|| {
        // Register only a root, skip issuer + mint — the test is
        // about the entity-status projection, not a full chain.
        let root_pubkey =
            DevicePublicKey::new_p256(&test_cert_ec_pubkey()).expect("valid P-256 pubkey");
        let empty_att: BoundedVec<_, _> = BoundedVec::try_from(vec![]).unwrap();
        let empty_cap_ekus:
            BoundedVec<zk_pki_primitives::eku::Eku, frame_support::traits::ConstU32<8>> =
            BoundedVec::try_from(vec![]).unwrap();
        assert_ok!(ZkPki::register_root(
            RuntimeOrigin::signed(account(ROOT_ACCOUNT)),
            account(ROOT_PROXY),
            root_pubkey,
            empty_att,
            1_000_000u64,
            empty_cap_ekus,
        ));

        let status = zk_pki_pallet::Pallet::<Runtime>::query_entity_status(
            account(ROOT_ACCOUNT),
        )
        .expect("root is registered");
        assert_eq!(status.address, account(ROOT_ACCOUNT));
        assert_eq!(status.entity_type, EntityType::Root);
        assert_eq!(status.state, EntityState::Active);
        assert_eq!(status.compromised_at_block, None);

        // A never-registered address returns None.
        let unknown: [u8; 32] = [0xAB; 32];
        assert!(
            zk_pki_pallet::Pallet::<Runtime>::query_entity_status(account(unknown))
                .is_none(),
        );
    });
}

#[test]
fn ek_lookup_returns_thumbprint() {
    run(|| {
        let ek = [0x42u8; 32];
        let thumbprint = mint_tpm_cert(ek);
        let root = account(ROOT_ACCOUNT);
        // Root-scoped lookup — cert minted under ROOT_ACCOUNT's
        // trust hierarchy resolves there.
        assert_eq!(
            zk_pki_pallet::Pallet::<Runtime>::query_ek_lookup(root.clone(), ek),
            Some(thumbprint),
        );
        // Different root, same EK: no hit.
        assert_eq!(
            zk_pki_pallet::Pallet::<Runtime>::query_ek_lookup(
                account([0x99u8; 32]),
                ek,
            ),
            None,
        );
        // Same root, unknown EK: no hit.
        assert_eq!(
            zk_pki_pallet::Pallet::<Runtime>::query_ek_lookup(root, [0xFFu8; 32]),
            None,
        );
    });
}
