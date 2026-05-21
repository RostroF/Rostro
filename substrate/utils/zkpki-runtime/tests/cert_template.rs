//! Integration tests for the cert-template system.
//!
//! Exercises `create_cert_template`, `deactivate_cert_template`,
//! `discard_cert_template`, the template gate on `offer_contract`, the
//! PoP enforcement on `mint_cert`, and the template fields surfaced on
//! `CertStatusResponse`.

use codec::Encode;
use frame_support::{
    assert_noop, assert_ok,
    traits::{ConstU32, Currency},
    BoundedVec,
};
use sp_core::crypto::AccountId32;
use sp_runtime::BuildStorage;
use zk_pki_primitives::crypto::DevicePublicKey;
use zk_pki_primitives::template::{PopMechanism, PopRequirement};
use zk_pki_runtime::{Runtime, RuntimeOrigin, ZkPki};
use zk_pki_tpm::test_mock_verifier::MockVerdict;
use zk_pki_tpm::AttestationPayloadV3;

// ──────────────────────────────────────────────────────────────────────
// Shared test harness
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

fn template_name_of(label: &[u8]) -> BoundedVec<u8, ConstU32<64>> {
    BoundedVec::try_from(label.to_vec()).unwrap()
}

fn default_template_name() -> BoundedVec<u8, ConstU32<64>> {
    template_name_of(b"test-template")
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

type CapEkus = BoundedVec<zk_pki_primitives::eku::Eku, ConstU32<8>>;
type TemplateEkus = BoundedVec<zk_pki_primitives::eku::Eku, ConstU32<16>>;

fn empty_cap_ekus() -> CapEkus {
    BoundedVec::try_from(vec![]).unwrap()
}

fn empty_template_ekus() -> TemplateEkus {
    BoundedVec::try_from(vec![]).unwrap()
}

/// Register a root and issue an issuer cert. Most tests start here.
fn register_root_and_issuer() {
    register_root_and_issuer_with_ekus(empty_cap_ekus(), empty_cap_ekus());
}

/// Register a root (with `root_caps`) and issue an issuer cert (with
/// `issuer_caps`). Root-registration and issuer-cert TPM attestation
/// flow through `NoopBindingProofVerifier` so this helper is safe to
/// call with any cap set the verifier accepts.
fn register_root_and_issuer_with_ekus(root_caps: CapEkus, issuer_caps: CapEkus) {
    let pubkey =
        DevicePublicKey::new_p256(&test_cert_ec_pubkey()).expect("valid P-256 pubkey");
    let empty_att: BoundedVec<_, _> = BoundedVec::try_from(vec![]).unwrap();
    assert_ok!(ZkPki::register_root(
        RuntimeOrigin::signed(account(ROOT_ACCOUNT)),
        account(ROOT_PROXY),
        pubkey.clone(),
        empty_att.clone(),
        1_000_000u64,
        root_caps,
    ));
    assert_ok!(ZkPki::issue_issuer_cert(
        RuntimeOrigin::signed(account(ROOT_ACCOUNT)),
        account(ISSUER_ACCOUNT),
        account(ISSUER_PROXY),
        pubkey,
        empty_att,
        500_000u64,
        issuer_caps,
    ));
}

/// Create a permissive template — wide TTL range, no cap, PoP optional.
/// Most tests want this baseline and customise from there.
fn create_default_template(pop: PopRequirement, max_certs: Option<u32>) {
    let pop_mechanism = pop_mechanism_for(&pop);
    assert_ok!(ZkPki::create_cert_template(
        RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
        default_template_name(),
        pop,
        pop_mechanism,
        400_000u64,
        1_000u64,
        max_certs,
        None,
        empty_template_ekus(),
    ));
}

/// Default-mechanism mapping for the test fixtures: PoP-Required
/// templates use `HipSigned` (TPM2 path — what every legacy fixture
/// expects). Non-PoP templates carry `None`. Tests exercising the
/// MimeWrap path supply `Some(PopMechanism::MimeWrap)` explicitly.
fn pop_mechanism_for(req: &PopRequirement) -> Option<PopMechanism> {
    match req {
        PopRequirement::Required => Some(PopMechanism::HipSigned),
        PopRequirement::NotRequired => None,
    }
}

fn payload_with_verdict(verdict: MockVerdict) -> AttestationPayloadV3 {
    AttestationPayloadV3 {
        cert_ec_chain: vec![vec![]],
        attest_ec_chain: vec![vec![]],
        hmac_binding_output: [0u8; 32],
        binding_signature: vec![],
        integrity_blob: verdict.encode(),
        integrity_signature: vec![],
    }
}

/// Build a synthesized but cryptographically-valid
/// `CanonicalHipProof`. Used by PoP-template mints — the pallet
/// requires *some* valid proof, and the verifier runs the full
/// internal consistency check (`blake2_256(ek_public) == ek_hash`,
/// AIK-certify signature, quote signature over
/// `blake2_256(pcr_digest || nonce)`). Non-PoP mints ignore the
/// proof silently, so passing this for every mint is harmless.
/// Build a minimal TPMS_ATTEST quote blob — extraData = nonce,
/// pcrDigest = pcr_digest, everything else zeroed.
fn synth_tpms_attest_quote(nonce: &[u8; 32], pcr_digest: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xFF54_4347u32.to_be_bytes()); // magic
    out.extend_from_slice(&0x8018u16.to_be_bytes()); // TPM_ST_ATTEST_QUOTE
    out.extend_from_slice(&0u16.to_be_bytes()); // qualifiedSigner: empty
    out.extend_from_slice(&32u16.to_be_bytes()); // extraData size
    out.extend_from_slice(nonce);
    out.extend_from_slice(&[0u8; 17]); // clockInfo zeros
    out.extend_from_slice(&0u64.to_be_bytes()); // firmwareVersion
    out.extend_from_slice(&0u32.to_be_bytes()); // pcrSelect count = 0
    out.extend_from_slice(&32u16.to_be_bytes()); // pcrDigest size
    out.extend_from_slice(pcr_digest);
    out
}

fn synth_hip_proof() -> zk_pki_primitives::hip::CanonicalHipProof {
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};

    // EK + AIK keypairs — fixed scalars so the proof is
    // deterministic across runs.
    let ek_sk = SigningKey::from_slice(&[0x11u8; 32]).expect("ek scalar");
    let aik_sk = SigningKey::from_slice(&[0x22u8; 32]).expect("aik scalar");
    let ek_pub_sec1 = ek_sk
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let aik_pub_sec1 = aik_sk
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();

    // Arbitrary AIK-certify payload. `Signer::sign` hashes the
    // message with SHA-256 internally, matching the verifier's
    // `Sha256::digest(message)` + verify_prehash.
    let aik_certify_info = b"aik-certify-info-synth".to_vec();
    let aik_certify_sig: Signature = ek_sk.sign(&aik_certify_info);

    // PCR values + digest + nonce.
    let pcr7 = [0x77u8; 32];
    let pcr_values: frame_support::BoundedVec<
        zk_pki_primitives::hip::PcrValue,
        ConstU32<16>,
    > = frame_support::BoundedVec::try_from(vec![
        zk_pki_primitives::hip::PcrValue { index: 7, value: pcr7 },
    ])
    .expect("bounded vec");
    let pcr_digest = [0xAAu8; 32];
    let nonce = [0x01u8; 32];

    // TPM2_Quote signs SHA-256(TPMS_ATTEST). Build the attest, then
    // sign it.
    let quote_attest = synth_tpms_attest_quote(&nonce, &pcr_digest);
    let quote_sig: Signature = aik_sk.sign(&quote_attest);

    let ek_hash = sp_io::hashing::blake2_256(&ek_pub_sec1);

    zk_pki_primitives::hip::CanonicalHipProof::Tpm2(zk_pki_primitives::hip::Tpm2HipProof {
        flavor: zk_pki_primitives::hip::Tpm2Flavor::Windows,
        ek_hash,
        ek_public: frame_support::BoundedVec::try_from(ek_pub_sec1).expect("ek pub"),
        aik_public: frame_support::BoundedVec::try_from(aik_pub_sec1).expect("aik pub"),
        aik_certify_info: frame_support::BoundedVec::try_from(aik_certify_info).expect("aci"),
        aik_certify_signature: frame_support::BoundedVec::try_from(aik_certify_sig.to_der().as_bytes().to_vec()).expect("aci sig"),
        pcr_values,
        pcr_digest,
        quote_attest: frame_support::BoundedVec::try_from(quote_attest).expect("attest"),
        quote_signature: frame_support::BoundedVec::try_from(quote_sig.to_der().as_bytes().to_vec()).expect("q sig"),
        nonce,
    })
}

/// Offer a contract for `user` under `template_name` then mint using
/// the given verdict. Returns the resulting thumbprint.
fn mint_under_template(
    user: [u8; 32],
    template: BoundedVec<u8, ConstU32<64>>,
    verdict: MockVerdict,
) -> [u8; 32] {
    let empty_meta: BoundedVec<_, _> = BoundedVec::try_from(vec![]).unwrap();
    assert_ok!(ZkPki::offer_contract(
        RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
        account(user),
        10_000u64,
        template,
        empty_meta,
    ));
    let ui_key = zk_pki_primitives::keys::IssuerUserKey::new(
        account(ISSUER_ACCOUNT),
        account(user),
    );
    let nonce = zk_pki_pallet::OfferIndex::<Runtime>::get(&ui_key).unwrap();
    let created_at = zk_pki_pallet::ContractOffers::<Runtime>::get(nonce)
        .unwrap()
        .created_at;
    // Always pass a valid synth HIP proof. Non-PoP templates ignore
    // it; PoP templates require it. Keeps the helper single-shot.
    assert_ok!(ZkPki::mint_cert(
        RuntimeOrigin::signed(account(user)),
        nonce,
        payload_with_verdict(verdict),
        created_at,
        Some(synth_hip_proof()),
        None, // commitment_c — HipSigned path
        None, // ec_key_pub_claimed — HipSigned path
    ));
    let user_key = zk_pki_primitives::keys::UserIssuerKey::new(
        account(user),
        account(ISSUER_ACCOUNT),
    );
    zk_pki_pallet::UserIssuerIndex::<Runtime>::get(&user_key).expect("cert minted")
}

// ──────────────────────────────────────────────────────────────────────
// create_cert_template
// ──────────────────────────────────────────────────────────────────────

#[test]
fn create_template_succeeds() {
    run(|| {
        register_root_and_issuer();
        let balance_before =
            pallet_balances::Pallet::<Runtime>::reserved_balance(&account(ISSUER_ACCOUNT));
        create_default_template(PopRequirement::NotRequired, None);
        let balance_after =
            pallet_balances::Pallet::<Runtime>::reserved_balance(&account(ISSUER_ACCOUNT));
        assert_eq!(
            balance_after - balance_before,
            10_000_000_000_000,
            "TemplateDeposit reserved"
        );
        let tpl = zk_pki_pallet::CertTemplates::<Runtime>::get(
            &account(ISSUER_ACCOUNT),
            &default_template_name(),
        )
        .expect("template stored");
        assert!(tpl.is_active);
        assert_eq!(tpl.issued_count, 0);
        let names = zk_pki_pallet::IssuerTemplateNames::<Runtime>::get(&account(ISSUER_ACCOUNT));
        assert!(names.contains(&default_template_name()));
    });
}

#[test]
fn create_template_duplicate_name_rejected() {
    run(|| {
        register_root_and_issuer();
        create_default_template(PopRequirement::NotRequired, None);
        let empty_ekus = empty_template_ekus();
        assert_noop!(
            ZkPki::create_cert_template(
                RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
                default_template_name(),
                PopRequirement::NotRequired,
                None, // pop_mechanism
                400_000u64,
                1_000u64,
                None,
                None,
                empty_ekus,
            ),
            zk_pki_pallet::Error::<Runtime>::TemplateNameTaken,
        );
    });
}

#[test]
fn create_template_ttl_exceeds_issuer_cert_rejected() {
    run(|| {
        register_root_and_issuer();
        // Issuer cert has TTL 500_000 and was issued at block 1, so
        // remaining is 499_999. A max_ttl of 600_000 exceeds it.
        let empty_ekus = empty_template_ekus();
        assert_noop!(
            ZkPki::create_cert_template(
                RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
                default_template_name(),
                PopRequirement::NotRequired,
                None, // pop_mechanism
                600_000u64,
                1_000u64,
                None,
                None,
                empty_ekus,
            ),
            zk_pki_pallet::Error::<Runtime>::TemplateTtlExceedsIssuerCert,
        );
    });
}

#[test]
fn create_template_invalid_ttl_range_rejected() {
    run(|| {
        register_root_and_issuer();
        // min >= max
        let empty_ekus = empty_template_ekus();
        assert_noop!(
            ZkPki::create_cert_template(
                RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
                default_template_name(),
                PopRequirement::NotRequired,
                None, // pop_mechanism
                1_000u64,
                1_000u64,
                None,
                None,
                empty_ekus,
            ),
            zk_pki_pallet::Error::<Runtime>::TemplateInvalidTtlRange,
        );
    });
}

#[test]
fn create_template_non_issuer_rejected() {
    run(|| {
        register_root_and_issuer();
        // USER_ACCOUNT isn't a registered issuer
        let empty_ekus = empty_template_ekus();
        assert_noop!(
            ZkPki::create_cert_template(
                RuntimeOrigin::signed(account(USER_ACCOUNT)),
                default_template_name(),
                PopRequirement::NotRequired,
                None, // pop_mechanism
                400_000u64,
                1_000u64,
                None,
                None,
                empty_ekus,
            ),
            zk_pki_pallet::Error::<Runtime>::NotAnIssuer,
        );
    });
}

#[test]
fn create_template_max_templates_exceeded_rejected() {
    run(|| {
        register_root_and_issuer();
        // MaxTemplatesPerIssuer is 256 in the test runtime. Each
        // template deposit is 10 DOT (10_000_000_000_000). Fund the
        // issuer with enough headroom for 256 templates.
        let _imb = pallet_balances::Pallet::<Runtime>::deposit_creating(
            &account(ISSUER_ACCOUNT),
            3_000_000_000_000_000u128, // 3000 DOT
        );
        let empty_ekus = empty_template_ekus();
        for i in 0..256u16 {
            let name = template_name_of(format!("tpl-{}", i).as_bytes());
            assert_ok!(ZkPki::create_cert_template(
                RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
                name,
                PopRequirement::NotRequired,
                None, // pop_mechanism
                400_000u64,
                1_000u64,
                None,
                None,
                empty_ekus.clone(),
            ));
        }
        assert_noop!(
            ZkPki::create_cert_template(
                RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
                template_name_of(b"one-too-many"),
                PopRequirement::NotRequired,
                None, // pop_mechanism
                400_000u64,
                1_000u64,
                None,
                None,
                empty_ekus,
            ),
            zk_pki_pallet::Error::<Runtime>::TooManyTemplates,
        );
    });
}

// ──────────────────────────────────────────────────────────────────────
// deactivate_cert_template
// ──────────────────────────────────────────────────────────────────────

#[test]
fn deactivate_template_succeeds() {
    run(|| {
        register_root_and_issuer();
        create_default_template(PopRequirement::NotRequired, None);
        let reserved_before =
            pallet_balances::Pallet::<Runtime>::reserved_balance(&account(ISSUER_ACCOUNT));
        assert_ok!(ZkPki::deactivate_cert_template(
            RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
            default_template_name(),
        ));
        let tpl = zk_pki_pallet::CertTemplates::<Runtime>::get(
            &account(ISSUER_ACCOUNT),
            &default_template_name(),
        )
        .expect("template still stored");
        assert!(!tpl.is_active);
        let reserved_after =
            pallet_balances::Pallet::<Runtime>::reserved_balance(&account(ISSUER_ACCOUNT));
        assert_eq!(reserved_before, reserved_after, "deposit still held");
    });
}

#[test]
fn deactivate_already_inactive_rejected() {
    run(|| {
        register_root_and_issuer();
        create_default_template(PopRequirement::NotRequired, None);
        assert_ok!(ZkPki::deactivate_cert_template(
            RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
            default_template_name(),
        ));
        assert_noop!(
            ZkPki::deactivate_cert_template(
                RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
                default_template_name(),
            ),
            zk_pki_pallet::Error::<Runtime>::TemplateAlreadyInactive,
        );
    });
}

// ──────────────────────────────────────────────────────────────────────
// discard_cert_template
// ──────────────────────────────────────────────────────────────────────

#[test]
fn discard_template_still_active_rejected() {
    run(|| {
        register_root_and_issuer();
        create_default_template(PopRequirement::NotRequired, None);
        assert_noop!(
            ZkPki::discard_cert_template(
                RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
                default_template_name(),
            ),
            zk_pki_pallet::Error::<Runtime>::TemplateStillActive,
        );
    });
}

#[test]
fn discard_template_with_active_certs_rejected() {
    run(|| {
        register_root_and_issuer();
        create_default_template(PopRequirement::NotRequired, None);
        let _thumbprint = mint_under_template(
            USER_ACCOUNT,
            default_template_name(),
            MockVerdict::Tpm {
                ek_hash: [0x42u8; 32],
                pubkey_bytes: test_cert_ec_pubkey(),
            },
        );
        assert_eq!(
            zk_pki_pallet::TemplateActiveCertCount::<Runtime>::get(
                &account(ISSUER_ACCOUNT),
                &default_template_name(),
            ),
            1,
        );
        assert_ok!(ZkPki::deactivate_cert_template(
            RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
            default_template_name(),
        ));
        assert_noop!(
            ZkPki::discard_cert_template(
                RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
                default_template_name(),
            ),
            zk_pki_pallet::Error::<Runtime>::TemplateHasActiveCerts,
        );
    });
}

#[test]
fn discard_template_succeeds() {
    run(|| {
        register_root_and_issuer();
        create_default_template(PopRequirement::NotRequired, None);
        assert_ok!(ZkPki::deactivate_cert_template(
            RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
            default_template_name(),
        ));
        let reserved_before =
            pallet_balances::Pallet::<Runtime>::reserved_balance(&account(ISSUER_ACCOUNT));
        assert_ok!(ZkPki::discard_cert_template(
            RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
            default_template_name(),
        ));
        assert!(zk_pki_pallet::CertTemplates::<Runtime>::get(
            &account(ISSUER_ACCOUNT),
            &default_template_name(),
        )
        .is_none());
        let names =
            zk_pki_pallet::IssuerTemplateNames::<Runtime>::get(&account(ISSUER_ACCOUNT));
        assert!(!names.contains(&default_template_name()));
        let reserved_after =
            pallet_balances::Pallet::<Runtime>::reserved_balance(&account(ISSUER_ACCOUNT));
        assert_eq!(
            reserved_before - reserved_after,
            10_000_000_000_000,
            "TemplateDeposit released"
        );
    });
}

// ──────────────────────────────────────────────────────────────────────
// offer_contract — template gate
// ──────────────────────────────────────────────────────────────────────

#[test]
fn offer_cert_with_inactive_template_rejected() {
    run(|| {
        register_root_and_issuer();
        create_default_template(PopRequirement::NotRequired, None);
        assert_ok!(ZkPki::deactivate_cert_template(
            RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
            default_template_name(),
        ));
        let empty_meta: BoundedVec<_, _> = BoundedVec::try_from(vec![]).unwrap();
        assert_noop!(
            ZkPki::offer_contract(
                RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
                account(USER_ACCOUNT),
                10_000u64,
                default_template_name(),
                empty_meta,
            ),
            zk_pki_pallet::Error::<Runtime>::TemplateInactive,
        );
    });
}

#[test]
fn offer_cert_template_not_found_rejected() {
    run(|| {
        register_root_and_issuer();
        // No template created — lookup returns None.
        let empty_meta: BoundedVec<_, _> = BoundedVec::try_from(vec![]).unwrap();
        assert_noop!(
            ZkPki::offer_contract(
                RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
                account(USER_ACCOUNT),
                10_000u64,
                template_name_of(b"nonexistent"),
                empty_meta,
            ),
            zk_pki_pallet::Error::<Runtime>::TemplateNotFound,
        );
    });
}

#[test]
fn offer_cert_ttl_below_min_rejected() {
    run(|| {
        register_root_and_issuer();
        create_default_template(PopRequirement::NotRequired, None);
        let empty_meta: BoundedVec<_, _> = BoundedVec::try_from(vec![]).unwrap();
        // min_ttl_blocks is 1_000; use 500.
        assert_noop!(
            ZkPki::offer_contract(
                RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
                account(USER_ACCOUNT),
                500u64,
                default_template_name(),
                empty_meta,
            ),
            zk_pki_pallet::Error::<Runtime>::TemplateTtlOutOfRange,
        );
    });
}

#[test]
fn offer_cert_ttl_above_max_rejected() {
    run(|| {
        register_root_and_issuer();
        create_default_template(PopRequirement::NotRequired, None);
        let empty_meta: BoundedVec<_, _> = BoundedVec::try_from(vec![]).unwrap();
        // max_ttl_blocks is 400_000; use 500_000.
        assert_noop!(
            ZkPki::offer_contract(
                RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
                account(USER_ACCOUNT),
                500_000u64,
                default_template_name(),
                empty_meta,
            ),
            zk_pki_pallet::Error::<Runtime>::TemplateTtlOutOfRange,
        );
    });
}

#[test]
fn offer_cert_max_certs_exceeded_rejected() {
    run(|| {
        register_root_and_issuer();
        // max_certs = 1 — one successful mint, then blocked.
        create_default_template(PopRequirement::NotRequired, Some(1));
        let _first = mint_under_template(
            USER_ACCOUNT,
            default_template_name(),
            MockVerdict::Tpm {
                ek_hash: [0x42u8; 32],
                pubkey_bytes: test_cert_ec_pubkey(),
            },
        );
        // After one mint, issued_count == 1 and max_certs == 1, so
        // the next offer is blocked.
        let second_user: [u8; 32] = [0xF6; 32];
        let _imb = pallet_balances::Pallet::<Runtime>::deposit_creating(
            &account(second_user),
            INITIAL_BALANCE,
        );
        let empty_meta: BoundedVec<_, _> = BoundedVec::try_from(vec![]).unwrap();
        assert_noop!(
            ZkPki::offer_contract(
                RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
                account(second_user),
                10_000u64,
                default_template_name(),
                empty_meta,
            ),
            zk_pki_pallet::Error::<Runtime>::TemplateMaxCertsReached,
        );
    });
}

// ──────────────────────────────────────────────────────────────────────
// mint_cert — PoP enforcement
// ──────────────────────────────────────────────────────────────────────

#[test]
fn mint_cert_pop_required_packed_rejected() {
    run(|| {
        register_root_and_issuer();
        create_default_template(PopRequirement::Required, None);
        let empty_meta: BoundedVec<_, _> = BoundedVec::try_from(vec![]).unwrap();
        assert_ok!(ZkPki::offer_contract(
            RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
            account(USER_ACCOUNT),
            10_000u64,
            default_template_name(),
            empty_meta,
        ));
        let ui_key = zk_pki_primitives::keys::IssuerUserKey::new(
            account(ISSUER_ACCOUNT),
            account(USER_ACCOUNT),
        );
        let nonce = zk_pki_pallet::OfferIndex::<Runtime>::get(&ui_key).unwrap();
        let created_at =
            zk_pki_pallet::ContractOffers::<Runtime>::get(nonce).unwrap().created_at;
        assert_noop!(
            ZkPki::mint_cert(
                RuntimeOrigin::signed(account(USER_ACCOUNT)),
                nonce,
                payload_with_verdict(MockVerdict::Packed {
                    pubkey_bytes: test_cert_ec_pubkey(),
                }),
                created_at,
                None,
                None, // commitment_c
                None, // ec_key_pub_claimed
            ),
            zk_pki_pallet::Error::<Runtime>::PopRequired,
        );
    });
}

#[test]
fn mint_cert_pop_required_tpm_succeeds() {
    run(|| {
        register_root_and_issuer();
        create_default_template(PopRequirement::Required, None);
        let thumbprint = mint_under_template(
            USER_ACCOUNT,
            default_template_name(),
            MockVerdict::Tpm {
                ek_hash: [0x42u8; 32],
                pubkey_bytes: test_cert_ec_pubkey(),
            },
        );
        let cert = zk_pki_pallet::CertLookupHot::<Runtime>::get(thumbprint).unwrap();
        assert_eq!(cert.attestation_type, zk_pki_primitives::tpm::AttestationType::Tpm);
        assert_eq!(cert.template_name, default_template_name());
    });
}

#[test]
fn mint_cert_pop_not_required_packed_succeeds() {
    run(|| {
        register_root_and_issuer();
        create_default_template(PopRequirement::NotRequired, None);
        let thumbprint = mint_under_template(
            USER_ACCOUNT,
            default_template_name(),
            MockVerdict::Packed {
                pubkey_bytes: test_cert_ec_pubkey(),
            },
        );
        let cert = zk_pki_pallet::CertLookupHot::<Runtime>::get(thumbprint).unwrap();
        assert_eq!(cert.attestation_type, zk_pki_primitives::tpm::AttestationType::Packed);
        assert_eq!(cert.template_name, default_template_name());
    });
}

#[test]
fn mint_cert_increments_issued_count() {
    run(|| {
        register_root_and_issuer();
        create_default_template(PopRequirement::NotRequired, None);
        let _thumbprint = mint_under_template(
            USER_ACCOUNT,
            default_template_name(),
            MockVerdict::Tpm {
                ek_hash: [0x42u8; 32],
                pubkey_bytes: test_cert_ec_pubkey(),
            },
        );
        let tpl = zk_pki_pallet::CertTemplates::<Runtime>::get(
            &account(ISSUER_ACCOUNT),
            &default_template_name(),
        )
        .unwrap();
        assert_eq!(tpl.issued_count, 1);
        assert_eq!(
            zk_pki_pallet::TemplateActiveCertCount::<Runtime>::get(
                &account(ISSUER_ACCOUNT),
                &default_template_name(),
            ),
            1,
        );
    });
}

// ──────────────────────────────────────────────────────────────────────
// certStatus — template projection
// ──────────────────────────────────────────────────────────────────────

#[test]
fn cert_status_returns_template_fields() {
    run(|| {
        register_root_and_issuer();
        create_default_template(PopRequirement::Required, None);
        let thumbprint = mint_under_template(
            USER_ACCOUNT,
            default_template_name(),
            MockVerdict::Tpm {
                ek_hash: [0x42u8; 32],
                pubkey_bytes: test_cert_ec_pubkey(),
            },
        );
        let status =
            zk_pki_pallet::Pallet::<Runtime>::query_cert_status(thumbprint).unwrap();
        assert_eq!(status.template_name, default_template_name());
        assert_eq!(
            status.template_pop_requirement,
            Some(PopRequirement::Required),
        );
    });
}

#[test]
fn cert_status_template_discarded_graceful() {
    run(|| {
        register_root_and_issuer();
        create_default_template(PopRequirement::NotRequired, None);
        let thumbprint = mint_under_template(
            USER_ACCOUNT,
            default_template_name(),
            MockVerdict::Tpm {
                ek_hash: [0x42u8; 32],
                pubkey_bytes: test_cert_ec_pubkey(),
            },
        );
        // User self-discards so the active-cert counter drops to 0,
        // letting the issuer deactivate + discard the template while
        // the cert record lingers only briefly — we actually do not
        // remove the cert, we test the RPC gracefulness, so we
        // instead mint to a second user then self-discard only that
        // one. Simpler: move the existing cert out via self_discard,
        // leaving no active cert, then discard the template.
        //
        // But we need a cert whose template was discarded AFTER mint
        // to exercise the graceful path. Do that by minting two
        // certs under the template, self-discarding one, deactivating
        // + discarding the template... which fails because the other
        // cert still references it. So instead: mint, self-discard,
        // then (template count = 0) deactivate + discard. Then
        // re-mint is impossible (template gone), but we already have
        // the thumbprint — wait, self_discard removed it from
        // storage. Use a different approach: run two issuers.
        //
        // Cleanest: keep the single cert, deactivate the template,
        // manually force-remove it from storage + counter to simulate
        // the "issuer discarded it" state, then query.
        zk_pki_pallet::CertTemplates::<Runtime>::remove(
            &account(ISSUER_ACCOUNT),
            &default_template_name(),
        );
        let status =
            zk_pki_pallet::Pallet::<Runtime>::query_cert_status(thumbprint).unwrap();
        assert_eq!(status.template_name, default_template_name());
        assert_eq!(status.template_pop_requirement, None);
    });
}
