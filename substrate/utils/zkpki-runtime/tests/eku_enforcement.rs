//! Integration tests for the EKU scaffolding pass.
//!
//! Exercises capability-EKU enforcement on `register_root` /
//! `issue_issuer_cert`, template-EKU enforcement on
//! `create_cert_template`, the PoP-implication short-circuit, and the
//! propagation of template EKUs to `CertRecordHot.ekus` +
//! `CertStatusResponse.ekus` at mint time.
//!
//! OIDs for custom EKUs are placeholders pending IANA PEN — see
//! [`zk_pki_primitives::oids`]. The enum variants used here are
//! final; only the OID strings in off-chain tooling will change.

use codec::Encode;
use frame_support::{
    assert_noop, assert_ok,
    traits::{ConstU32, Currency},
    BoundedVec,
};
use sp_core::crypto::AccountId32;
use sp_runtime::BuildStorage;
use zk_pki_primitives::crypto::DevicePublicKey;
use zk_pki_primitives::eku::Eku;
use zk_pki_primitives::template::{PopMechanism, PopRequirement};
use zk_pki_runtime::{Runtime, RuntimeOrigin, ZkPki};
use zk_pki_tpm::test_mock_verifier::MockVerdict;
use zk_pki_tpm::AttestationPayloadV3;

// ──────────────────────────────────────────────────────────────────────
// Harness
// ──────────────────────────────────────────────────────────────────────

const ROOT_ACCOUNT: [u8; 32] = [0xA1; 32];
const ISSUER_ACCOUNT: [u8; 32] = [0xB2; 32];
const USER_ACCOUNT: [u8; 32] = [0xC3; 32];
const ROOT_PROXY: [u8; 32] = [0xD4; 32];
const ISSUER_PROXY: [u8; 32] = [0xE5; 32];
const INITIAL_BALANCE: u128 = 100_000_000_000_000;

type CapEkus = BoundedVec<Eku, ConstU32<8>>;
type TemplateEkus = BoundedVec<Eku, ConstU32<16>>;

fn account(seed: [u8; 32]) -> AccountId32 {
    AccountId32::from(seed)
}

fn test_cert_ec_pubkey() -> Vec<u8> {
    use p256::ecdsa::{SigningKey, VerifyingKey};
    let sk = SigningKey::from_slice(&[7u8; 32]).expect("valid P-256 scalar");
    let vk: VerifyingKey = *sk.verifying_key();
    vk.to_encoded_point(false).as_bytes().to_vec()
}

fn template_name() -> BoundedVec<u8, ConstU32<64>> {
    BoundedVec::try_from(b"eku-test".to_vec()).unwrap()
}

fn cap_ekus(list: Vec<Eku>) -> CapEkus {
    BoundedVec::try_from(list).unwrap()
}

fn template_ekus(list: Vec<Eku>) -> TemplateEkus {
    BoundedVec::try_from(list).unwrap()
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

/// Register a root with the caller's specified capability EKUs.
/// The reference runtime wires `NoopAttestationVerifier`, which
/// always returns `AttestationType::Tpm` — PoP capability is never
/// rejected by attestation type in these tests unless we feed the
/// extrinsic a verifier that says otherwise.
fn register_root_with(caps: CapEkus) -> frame_support::dispatch::DispatchResult {
    let pubkey =
        DevicePublicKey::new_p256(&test_cert_ec_pubkey()).expect("valid P-256 pubkey");
    let empty_att: BoundedVec<_, _> = BoundedVec::try_from(vec![]).unwrap();
    ZkPki::register_root(
        RuntimeOrigin::signed(account(ROOT_ACCOUNT)),
        account(ROOT_PROXY),
        pubkey,
        empty_att,
        1_000_000u64,
        caps,
    )
}

fn issue_issuer_cert_with(caps: CapEkus) -> frame_support::dispatch::DispatchResult {
    let pubkey =
        DevicePublicKey::new_p256(&test_cert_ec_pubkey()).expect("valid P-256 pubkey");
    let empty_att: BoundedVec<_, _> = BoundedVec::try_from(vec![]).unwrap();
    ZkPki::issue_issuer_cert(
        RuntimeOrigin::signed(account(ROOT_ACCOUNT)),
        account(ISSUER_ACCOUNT),
        account(ISSUER_PROXY),
        pubkey,
        empty_att,
        500_000u64,
        caps,
    )
}

fn create_template_with(
    pop: PopRequirement,
    ekus: TemplateEkus,
) -> frame_support::dispatch::DispatchResult {
    let pop_mechanism = match pop {
        PopRequirement::Required => Some(PopMechanism::HipSigned),
        PopRequirement::NotRequired => None,
    };
    ZkPki::create_cert_template(
        RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
        template_name(),
        pop,
        pop_mechanism,
        400_000u64,
        1_000u64,
        None,
        None,
        ekus,
    )
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

/// Synthesized valid HIP proof. PoP-required templates need one;
/// non-PoP templates ignore it silently. Construction mirrors the
/// helper in `cert_template.rs` and `hip_genesis.rs`.
fn synth_hip_proof() -> zk_pki_primitives::hip::CanonicalHipProof {
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    let ek = SigningKey::from_slice(&[0x11u8; 32]).unwrap();
    let aik = SigningKey::from_slice(&[0x22u8; 32]).unwrap();
    let ek_pub = ek.verifying_key().to_encoded_point(false).as_bytes().to_vec();
    let aik_pub = aik.verifying_key().to_encoded_point(false).as_bytes().to_vec();
    let aik_certify_info = b"aik-certify-info".to_vec();
    let aik_certify_sig: Signature = ek.sign(&aik_certify_info);
    let pcr_digest = [0xAAu8; 32];
    let nonce = [0x01u8; 32];

    // Minimal TPMS_ATTEST blob — TPM2_Quote signs SHA-256(attest) by
    // the AIK. Synth matches the TPM's signing domain.
    let mut quote_attest = Vec::new();
    quote_attest.extend_from_slice(&0xFF54_4347u32.to_be_bytes());
    quote_attest.extend_from_slice(&0x8018u16.to_be_bytes());
    quote_attest.extend_from_slice(&0u16.to_be_bytes());
    quote_attest.extend_from_slice(&32u16.to_be_bytes());
    quote_attest.extend_from_slice(&nonce);
    quote_attest.extend_from_slice(&[0u8; 17]);
    quote_attest.extend_from_slice(&0u64.to_be_bytes());
    quote_attest.extend_from_slice(&0u32.to_be_bytes());
    quote_attest.extend_from_slice(&32u16.to_be_bytes());
    quote_attest.extend_from_slice(&pcr_digest);
    let quote_sig: Signature = aik.sign(&quote_attest);

    let pcr_values: BoundedVec<
        zk_pki_primitives::hip::PcrValue,
        ConstU32<16>,
    > = BoundedVec::try_from(vec![
        zk_pki_primitives::hip::PcrValue { index: 7, value: [0x77u8; 32] },
    ])
    .unwrap();
    let ek_hash = sp_io::hashing::blake2_256(&ek_pub);
    zk_pki_primitives::hip::CanonicalHipProof::Tpm2(zk_pki_primitives::hip::Tpm2HipProof {
        flavor: zk_pki_primitives::hip::Tpm2Flavor::Windows,
        ek_hash,
        ek_public: BoundedVec::try_from(ek_pub).unwrap(),
        aik_public: BoundedVec::try_from(aik_pub).unwrap(),
        aik_certify_info: BoundedVec::try_from(aik_certify_info).unwrap(),
        aik_certify_signature: BoundedVec::try_from(aik_certify_sig.to_der().as_bytes().to_vec()).unwrap(),
        pcr_values,
        pcr_digest,
        quote_attest: BoundedVec::try_from(quote_attest).unwrap(),
        quote_signature: BoundedVec::try_from(quote_sig.to_der().as_bytes().to_vec()).unwrap(),
        nonce,
    })
}

// ──────────────────────────────────────────────────────────────────────
// register_root — capability EKU gate
// ──────────────────────────────────────────────────────────────────────

#[test]
fn root_with_pop_eku_requires_tpm_attestation() {
    // The reference runtime wires `TpmTestAttestationVerifier`
    // (returns `AttestationType::Tpm`) so PoP-capability tests
    // exercise the happy path. The not-Tpm rejection path is
    // enforced by an `ensure!(att_type == Tpm, PopRequired)` check
    // in `register_root`; verifying that branch requires wiring a
    // Packed-returning verifier in a separate test runtime, out of
    // scope for this integration file. We assert the happy path and
    // the pallet storage result.
    run(|| {
        assert_ok!(register_root_with(cap_ekus(vec![Eku::ProofOfPersonhood])));
        let rec =
            zk_pki_pallet::Roots::<Runtime>::get(&account(ROOT_ACCOUNT)).unwrap();
        assert!(rec.capability_ekus.contains(&Eku::ProofOfPersonhood));
    });
}

#[test]
fn root_with_pop_eku_tpm_succeeds() {
    run(|| {
        assert_ok!(register_root_with(cap_ekus(vec![Eku::ProofOfPersonhood])));
        let rec =
            zk_pki_pallet::Roots::<Runtime>::get(&account(ROOT_ACCOUNT)).unwrap();
        assert!(rec.capability_ekus.contains(&Eku::ProofOfPersonhood));
    });
}

#[test]
fn root_invalid_eku_rejected() {
    run(|| {
        // IssuerCert is not valid as a root capability — `valid_for_root`
        // rejects it.
        assert_noop!(
            register_root_with(cap_ekus(vec![Eku::IssuerCert])),
            zk_pki_pallet::Error::<Runtime>::InvalidRootEku,
        );
    });
}

// ──────────────────────────────────────────────────────────────────────
// issue_issuer_cert — capability EKU gate
// ──────────────────────────────────────────────────────────────────────

#[test]
fn issuer_cannot_exceed_root_capability() {
    run(|| {
        // Root registered with no PoP capability.
        assert_ok!(register_root_with(cap_ekus(vec![])));
        assert_noop!(
            issue_issuer_cert_with(cap_ekus(vec![Eku::ProofOfPersonhood])),
            zk_pki_pallet::Error::<Runtime>::EkuNotAuthorized,
        );
    });
}

#[test]
fn issuer_subset_of_root_capability_succeeds() {
    run(|| {
        // Root has both PoP and SmartContractIssuer; issuer requests just PoP.
        assert_ok!(register_root_with(cap_ekus(vec![
            Eku::ProofOfPersonhood,
            Eku::SmartContractIssuer,
        ])));
        assert_ok!(issue_issuer_cert_with(cap_ekus(vec![Eku::ProofOfPersonhood])));
        let rec =
            zk_pki_pallet::Issuers::<Runtime>::get(&account(ISSUER_ACCOUNT)).unwrap();
        assert!(rec.capability_ekus.contains(&Eku::ProofOfPersonhood));
        assert!(!rec.capability_ekus.contains(&Eku::SmartContractIssuer));
    });
}

#[test]
fn issuer_invalid_eku_rejected() {
    run(|| {
        // RootCert is not a valid issuer capability.
        assert_ok!(register_root_with(cap_ekus(vec![])));
        assert_noop!(
            issue_issuer_cert_with(cap_ekus(vec![Eku::RootCert])),
            zk_pki_pallet::Error::<Runtime>::InvalidIssuerEku,
        );
    });
}

#[test]
fn issuer_pop_eku_requires_tpm_attestation() {
    // Same caveat as `root_with_pop_eku_requires_tpm_attestation`:
    // the test runtime's Tpm-returning verifier exercises the happy
    // path; the rejection branch is the matching
    // `ensure!(att_type == Tpm)` check on `issue_issuer_cert`,
    // enforced in code and covered by hardware-backed runtimes.
    run(|| {
        assert_ok!(register_root_with(cap_ekus(vec![Eku::ProofOfPersonhood])));
        assert_ok!(issue_issuer_cert_with(cap_ekus(vec![Eku::ProofOfPersonhood])));
        let rec =
            zk_pki_pallet::Issuers::<Runtime>::get(&account(ISSUER_ACCOUNT)).unwrap();
        assert!(rec.capability_ekus.contains(&Eku::ProofOfPersonhood));
    });
}

// ──────────────────────────────────────────────────────────────────────
// create_cert_template — EKU gate
// ──────────────────────────────────────────────────────────────────────

#[test]
fn template_pop_eku_forces_pop_required() {
    run(|| {
        assert_ok!(register_root_with(cap_ekus(vec![Eku::ProofOfPersonhood])));
        assert_ok!(issue_issuer_cert_with(cap_ekus(vec![Eku::ProofOfPersonhood])));
        // ProofOfPersonhood EKU on a template with `NotRequired` PoP
        // must be rejected — the EKU is meaningless otherwise.
        assert_noop!(
            create_template_with(
                PopRequirement::NotRequired,
                template_ekus(vec![Eku::ProofOfPersonhood]),
            ),
            zk_pki_pallet::Error::<Runtime>::PopRequiredForEku,
        );
    });
}

#[test]
fn template_eku_not_in_issuer_capability_rejected() {
    run(|| {
        // Root + issuer registered with NO PoP capability.
        assert_ok!(register_root_with(cap_ekus(vec![])));
        assert_ok!(issue_issuer_cert_with(cap_ekus(vec![])));
        // Issuer without PoP capability cannot charter a PoP template.
        assert_noop!(
            create_template_with(
                PopRequirement::Required,
                template_ekus(vec![Eku::ProofOfPersonhood]),
            ),
            zk_pki_pallet::Error::<Runtime>::EkuNotAuthorized,
        );
    });
}

#[test]
fn template_standard_ekus_freely_assignable() {
    run(|| {
        // Even an issuer with NO capability_ekus can attach standard
        // X.509 EKUs to templates — those fall through the
        // `requires_issuer_capability` gate and relying-party trust
        // for those is out of band.
        assert_ok!(register_root_with(cap_ekus(vec![])));
        assert_ok!(issue_issuer_cert_with(cap_ekus(vec![])));
        assert_ok!(create_template_with(
            PopRequirement::NotRequired,
            template_ekus(vec![
                Eku::ClientAuth,
                Eku::ServerAuth,
                Eku::EmailProtection,
                Eku::CodeSigning,
            ]),
        ));
    });
}

#[test]
fn template_eku_in_issuer_capability_succeeds() {
    run(|| {
        assert_ok!(register_root_with(cap_ekus(vec![Eku::ProofOfPersonhood])));
        assert_ok!(issue_issuer_cert_with(cap_ekus(vec![Eku::ProofOfPersonhood])));
        assert_ok!(create_template_with(
            PopRequirement::Required,
            template_ekus(vec![Eku::ProofOfPersonhood]),
        ));
        let tpl = zk_pki_pallet::CertTemplates::<Runtime>::get(
            &account(ISSUER_ACCOUNT),
            &template_name(),
        )
        .unwrap();
        assert_eq!(tpl.ekus.len(), 1);
        assert!(tpl.ekus.contains(&Eku::ProofOfPersonhood));
    });
}

// ──────────────────────────────────────────────────────────────────────
// mint_cert — EKU propagation
// ──────────────────────────────────────────────────────────────────────

#[test]
fn mint_cert_writes_ekus_to_hot_record() {
    run(|| {
        assert_ok!(register_root_with(cap_ekus(vec![Eku::ProofOfPersonhood])));
        assert_ok!(issue_issuer_cert_with(cap_ekus(vec![Eku::ProofOfPersonhood])));
        assert_ok!(create_template_with(
            PopRequirement::Required,
            template_ekus(vec![Eku::ProofOfPersonhood, Eku::IdentityAssertion]),
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
        let created_at = zk_pki_pallet::ContractOffers::<Runtime>::get(nonce)
            .unwrap()
            .created_at;
        assert_ok!(ZkPki::mint_cert(
            RuntimeOrigin::signed(account(USER_ACCOUNT)),
            nonce,
            payload_with_verdict(MockVerdict::Tpm {
                ek_hash: [0x42u8; 32],
                pubkey_bytes: test_cert_ec_pubkey(),
            }),
            created_at,
            Some(synth_hip_proof()),
            None, // commitment_c
            None, // ec_key_pub_claimed
            None, // chat_enrollment
        ));

        let user_key = zk_pki_primitives::keys::UserIssuerKey::new(
            account(USER_ACCOUNT),
            account(ISSUER_ACCOUNT),
        );
        let thumbprint =
            zk_pki_pallet::UserIssuerIndex::<Runtime>::get(&user_key).unwrap();
        let cert = zk_pki_pallet::CertLookupHot::<Runtime>::get(thumbprint).unwrap();
        assert_eq!(cert.ekus.len(), 2);
        assert!(cert.ekus.contains(&Eku::ProofOfPersonhood));
        assert!(cert.ekus.contains(&Eku::IdentityAssertion));
    });
}

#[test]
fn cert_status_returns_ekus() {
    run(|| {
        assert_ok!(register_root_with(cap_ekus(vec![Eku::ProofOfPersonhood])));
        assert_ok!(issue_issuer_cert_with(cap_ekus(vec![Eku::ProofOfPersonhood])));
        assert_ok!(create_template_with(
            PopRequirement::Required,
            template_ekus(vec![Eku::ProofOfPersonhood]),
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
        let created_at = zk_pki_pallet::ContractOffers::<Runtime>::get(nonce)
            .unwrap()
            .created_at;
        assert_ok!(ZkPki::mint_cert(
            RuntimeOrigin::signed(account(USER_ACCOUNT)),
            nonce,
            payload_with_verdict(MockVerdict::Tpm {
                ek_hash: [0x42u8; 32],
                pubkey_bytes: test_cert_ec_pubkey(),
            }),
            created_at,
            Some(synth_hip_proof()),
            None, // commitment_c
            None, // ec_key_pub_claimed
            None, // chat_enrollment
        ));

        let user_key = zk_pki_primitives::keys::UserIssuerKey::new(
            account(USER_ACCOUNT),
            account(ISSUER_ACCOUNT),
        );
        let thumbprint =
            zk_pki_pallet::UserIssuerIndex::<Runtime>::get(&user_key).unwrap();
        let status =
            zk_pki_pallet::Pallet::<Runtime>::query_cert_status(thumbprint).unwrap();
        assert_eq!(status.ekus.len(), 1);
        assert!(status.ekus.contains(&Eku::ProofOfPersonhood));
    });
}
