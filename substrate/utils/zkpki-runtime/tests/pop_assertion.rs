//! PopAssertion / PoP-gated action tests.
//!
//! Exercises `self_discard_cert`'s two-tier model:
//!
//! - **Standard path**: valid `PopAssertion` (cert_ec signature +
//!   fresh HIP proof bound to this call's nonce). Emits
//!   `CertSelfDiscarded`.
//! - **Recovery path**: `None` for pop_assertion. SS58 ownership
//!   only. Emits `CertSelfDiscardedRecovery`.
//!
//! Synthesis: every test that runs the standard path threads the
//! same cert_ec / AIK / EK keypairs through both the mint (via
//! `MockVerdict::Tpm { pubkey_bytes }` for cert_ec and via the
//! genesis HIP proof for AIK) and the PopAssertion (fresh HIP
//! proof with same AIK, cert_ec_signature with same cert_ec sk).
//! That matching is what lets the pallet verifier reach the
//! `Ok(())` branch.

use codec::Encode;
use frame_support::{
    assert_noop, assert_ok,
    traits::{ConstU32, Hooks},
    BoundedVec,
};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use sp_core::crypto::AccountId32;
use sp_runtime::BuildStorage;
use zk_pki_primitives::crypto::DevicePublicKey;
use zk_pki_primitives::eku::Eku;
use zk_pki_primitives::hip::{
    CanonicalHipProof, HipPlatform, PcrValue, Tpm2Flavor, Tpm2HipProof,
};
use zk_pki_primitives::pop::{derive_pop_nonce, PopAssertion};
use zk_pki_primitives::template::{PopMechanism, PopRequirement};
use zk_pki_runtime::{Runtime, RuntimeEvent, RuntimeOrigin, ZkPki, test_serial};
use zk_pki_tpm::test_mock_verifier::MockVerdict;
use zk_pki_tpm::AttestationPayloadV3;

// ──────────────────────────────────────────────────────────────────────
// Harness
// ──────────────────────────────────────────────────────────────────────

const ROOT_ACCOUNT: [u8; 32] = [0xA1; 32];
const ISSUER_ACCOUNT: [u8; 32] = [0xB2; 32];
const USER_ACCOUNT: [u8; 32] = [0xC3; 32];
const OTHER_ACCOUNT: [u8; 32] = [0xC4; 32];
const ROOT_PROXY: [u8; 32] = [0xD4; 32];
const ISSUER_PROXY: [u8; 32] = [0xE5; 32];

const INITIAL_BALANCE: u128 = 100_000_000_000_000;

// Fixed scalars so mint and PopAssertion share the same keys.
const CERT_EC_SCALAR: [u8; 32] = [0x07; 32];
const AIK_SCALAR: [u8; 32] = [0x22; 32];
const EK_SCALAR: [u8; 32] = [0x11; 32];
const PCR7_VALUE: [u8; 32] = [0x77; 32];

fn account(seed: [u8; 32]) -> AccountId32 {
    AccountId32::from(seed)
}

fn cert_ec_sk() -> SigningKey {
    SigningKey::from_slice(&CERT_EC_SCALAR).unwrap()
}

fn cert_ec_pubkey_bytes() -> Vec<u8> {
    cert_ec_sk()
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec()
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
            (account(OTHER_ACCOUNT), INITIAL_BALANCE),
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

// ──────────────────────────────────────────────────────────────────────
// TPMS_ATTEST + CanonicalHipProof synthesis
// ──────────────────────────────────────────────────────────────────────

fn synth_tpms_attest_quote(nonce: &[u8; 32], pcr_digest: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xFF54_4347u32.to_be_bytes());
    out.extend_from_slice(&0x8018u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&32u16.to_be_bytes());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&[0u8; 17]);
    out.extend_from_slice(&0u64.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&32u16.to_be_bytes());
    out.extend_from_slice(pcr_digest);
    out
}

/// Build a valid `CanonicalHipProof` bound to the supplied `nonce`.
/// Uses fixed EK / AIK scalars so different calls produce proofs
/// anchored to the same hardware identity — which is what both the
/// mint's genesis recording and the later PopAssertion check need.
fn synth_hip_proof(nonce: [u8; 32]) -> CanonicalHipProof {
    let ek = SigningKey::from_slice(&EK_SCALAR).unwrap();
    let aik = SigningKey::from_slice(&AIK_SCALAR).unwrap();
    let ek_pub = ek
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let aik_pub = aik
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();

    let aik_certify_info = b"aik-certify-info-pop".to_vec();
    let aik_certify_sig: Signature = ek.sign(&aik_certify_info);

    let pcr_digest = [0xAAu8; 32];
    let quote_attest = synth_tpms_attest_quote(&nonce, &pcr_digest);
    let quote_sig: Signature = aik.sign(&quote_attest);

    let pcr_values: BoundedVec<PcrValue, ConstU32<16>> = BoundedVec::try_from(vec![
        PcrValue { index: 7, value: PCR7_VALUE },
    ])
    .unwrap();

    let ek_hash = sp_io::hashing::blake2_256(&ek_pub);

    CanonicalHipProof::Tpm2(Tpm2HipProof {
        flavor: Tpm2Flavor::Windows,
        ek_hash,
        ek_public: BoundedVec::try_from(ek_pub).unwrap(),
        aik_public: BoundedVec::try_from(aik_pub).unwrap(),
        aik_certify_info: BoundedVec::try_from(aik_certify_info).unwrap(),
        aik_certify_signature: BoundedVec::try_from(
            aik_certify_sig.to_der().as_bytes().to_vec(),
        )
        .unwrap(),
        pcr_values,
        pcr_digest,
        quote_attest: BoundedVec::try_from(quote_attest).unwrap(),
        quote_signature: BoundedVec::try_from(quote_sig.to_der().as_bytes().to_vec()).unwrap(),
        nonce,
    })
}

// ──────────────────────────────────────────────────────────────────────
// Template + issuer setup (PoP-required)
// ──────────────────────────────────────────────────────────────────────

fn template_name() -> BoundedVec<u8, ConstU32<64>> {
    BoundedVec::try_from(b"pop-assertion-template".to_vec()).unwrap()
}

fn empty_att() -> BoundedVec<u8, ConstU32<4096>> {
    BoundedVec::try_from(vec![]).unwrap()
}

fn mint_pop_cert_for(user: [u8; 32]) -> [u8; 32] {
    let root_pubkey =
        DevicePublicKey::new_p256(&cert_ec_pubkey_bytes()).expect("valid P-256");
    let pop_cap: BoundedVec<Eku, ConstU32<8>> =
        BoundedVec::try_from(vec![Eku::ProofOfPersonhood]).unwrap();
    // Template must *carry* ProofOfPersonhood so mint copies it onto
    // the Hot record — that's what `verify_pop_assertion` reads.
    let pop_template_ekus: BoundedVec<Eku, ConstU32<16>> =
        BoundedVec::try_from(vec![Eku::ProofOfPersonhood]).unwrap();

    assert_ok!(ZkPki::register_root(
        RuntimeOrigin::signed(account(ROOT_ACCOUNT)),
        account(ROOT_PROXY),
        root_pubkey.clone(),
        empty_att(),
        1_000_000u64,
        pop_cap.clone(),
    
        test_serial(1),
    ));
    assert_ok!(ZkPki::issue_issuer_cert(
        RuntimeOrigin::signed(account(ROOT_ACCOUNT)),
        account(ISSUER_ACCOUNT),
        account(ISSUER_PROXY),
        root_pubkey,
        empty_att(),
        500_000u64,
        pop_cap,
    
        test_serial(2),
    ));
    assert_ok!(ZkPki::create_cert_template(
        RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
        template_name(),
        PopRequirement::Required,
        Some(PopMechanism::HipSigned), // pop_mechanism — TPM2 path
        400_000u64,
        1_000u64,
        None,
        None,
        pop_template_ekus,
    ));
    let empty_meta: BoundedVec<_, _> = BoundedVec::try_from(vec![]).unwrap();
    assert_ok!(ZkPki::offer_contract(
        RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
        account(user),
        10_000u64,
        template_name(),
        empty_meta,
    
        test_serial(3),
    ));
    let ui_key = zk_pki_primitives::keys::IssuerUserKey::new(
        account(ISSUER_ACCOUNT),
        account(user),
    );
    let nonce = zk_pki_pallet::OfferIndex::<Runtime>::get(&ui_key).unwrap();
    let offer = zk_pki_pallet::ContractOffers::<Runtime>::get(nonce).unwrap();

    // Genesis HIP nonce is the arbitrary value used at mint; the
    // PopAssertion later computes its own per-call nonce and
    // captures a fresh proof.
    let genesis_hip_nonce = [0x01u8; 32];
    let payload = AttestationPayloadV3 {
        cert_ec_chain: vec![vec![]],
        attest_ec_chain: vec![vec![]],
        hmac_binding_output: [0u8; 32],
        binding_signature: vec![],
        integrity_blob: MockVerdict::Tpm {
            ek_hash: [0x42u8; 32],
            pubkey_bytes: cert_ec_pubkey_bytes(),
        }
        .encode(),
        integrity_signature: vec![],
    };
    assert_ok!(ZkPki::mint_cert(
        RuntimeOrigin::signed(account(user)),
        nonce,
        payload,
        offer.created_at,
        Some(synth_hip_proof(genesis_hip_nonce)),
        None, // commitment_c — HipSigned path
        None, // ec_key_pub_claimed — HipSigned path
    ));

    let user_issuer_key = zk_pki_primitives::keys::UserIssuerKey::new(
        account(user),
        account(ISSUER_ACCOUNT),
    );
    zk_pki_pallet::UserIssuerIndex::<Runtime>::get(&user_issuer_key)
        .expect("pop cert minted")
}

/// Mint a non-PoP cert (template `pop_requirement = NotRequired`).
/// Used by the "non-PoP cert always takes recovery path" test.
fn mint_non_pop_cert_for(user: [u8; 32]) -> [u8; 32] {
    let root_pubkey =
        DevicePublicKey::new_p256(&cert_ec_pubkey_bytes()).expect("valid P-256");
    let empty_cap: BoundedVec<Eku, ConstU32<8>> = BoundedVec::try_from(vec![]).unwrap();
    let empty_template_ekus: BoundedVec<Eku, ConstU32<16>> =
        BoundedVec::try_from(vec![]).unwrap();

    assert_ok!(ZkPki::register_root(
        RuntimeOrigin::signed(account(ROOT_ACCOUNT)),
        account(ROOT_PROXY),
        root_pubkey.clone(),
        empty_att(),
        1_000_000u64,
        empty_cap.clone(),
    
        test_serial(4),
    ));
    assert_ok!(ZkPki::issue_issuer_cert(
        RuntimeOrigin::signed(account(ROOT_ACCOUNT)),
        account(ISSUER_ACCOUNT),
        account(ISSUER_PROXY),
        root_pubkey,
        empty_att(),
        500_000u64,
        empty_cap,
    
        test_serial(5),
    ));
    assert_ok!(ZkPki::create_cert_template(
        RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
        template_name(),
        PopRequirement::NotRequired,
        None, // pop_mechanism — non-PoP template
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
    
        test_serial(6),
    ));
    let ui_key = zk_pki_primitives::keys::IssuerUserKey::new(
        account(ISSUER_ACCOUNT),
        account(user),
    );
    let nonce = zk_pki_pallet::OfferIndex::<Runtime>::get(&ui_key).unwrap();
    let offer = zk_pki_pallet::ContractOffers::<Runtime>::get(nonce).unwrap();
    let payload = AttestationPayloadV3 {
        cert_ec_chain: vec![vec![]],
        attest_ec_chain: vec![vec![]],
        hmac_binding_output: [0u8; 32],
        binding_signature: vec![],
        integrity_blob: MockVerdict::Packed {
            pubkey_bytes: cert_ec_pubkey_bytes(),
        }
        .encode(),
        integrity_signature: vec![],
    };
    assert_ok!(ZkPki::mint_cert(
        RuntimeOrigin::signed(account(user)),
        nonce,
        payload,
        offer.created_at,
        None,
        None, // commitment_c
        None, // ec_key_pub_claimed
    ));
    let user_issuer_key = zk_pki_primitives::keys::UserIssuerKey::new(
        account(user),
        account(ISSUER_ACCOUNT),
    );
    zk_pki_pallet::UserIssuerIndex::<Runtime>::get(&user_issuer_key).unwrap()
}

// ──────────────────────────────────────────────────────────────────────
// PopAssertion construction
// ──────────────────────────────────────────────────────────────────────

/// Build a valid `PopAssertion` for a `self_discard_cert` call
/// targeting `thumbprint`. Derives the nonce the same way the
/// pallet will (parent_hash + thumbprint + call_data), signs
/// cert_ec over blake2_256(call_data || nonce), and builds a fresh
/// HIP proof bound to that nonce.
fn build_self_discard_assertion(thumbprint: [u8; 32]) -> PopAssertion {
    let call_data = thumbprint.encode();
    let parent_hash = frame_system::Pallet::<Runtime>::parent_hash();
    let parent_bytes: [u8; 32] = parent_hash.as_ref().try_into().unwrap_or([0u8; 32]);
    let nonce = derive_pop_nonce(&parent_bytes, &thumbprint, &call_data);

    let mut signed_input = Vec::with_capacity(call_data.len() + 32);
    signed_input.extend_from_slice(&call_data);
    signed_input.extend_from_slice(&nonce);
    let signed_payload = sp_io::hashing::blake2_256(&signed_input);
    let cert_ec_sig: Signature = cert_ec_sk().sign(&signed_payload);

    let hip_proof = synth_hip_proof(nonce);

    PopAssertion::HipSigned {
        cert_thumbprint: thumbprint,
        cert_ec_signature: BoundedVec::try_from(cert_ec_sig.to_der().as_bytes().to_vec())
            .unwrap(),
        hip_proof,
    }
}

// ──────────────────────────────────────────────────────────────────────
// Event helpers
// ──────────────────────────────────────────────────────────────────────

fn emitted_self_discard_events() -> (bool, bool) {
    let mut standard = false;
    let mut recovery = false;
    for rec in frame_system::Pallet::<Runtime>::events() {
        if let RuntimeEvent::ZkPki(evt) = rec.event {
            match evt {
                zk_pki_pallet::Event::CertSelfDiscarded { .. } => standard = true,
                zk_pki_pallet::Event::CertSelfDiscardedRecovery { .. } => recovery = true,
                _ => {}
            }
        }
    }
    (standard, recovery)
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

#[test]
fn self_discard_standard_path_succeeds() {
    run(|| {
        let thumbprint = mint_pop_cert_for(USER_ACCOUNT);
        // Reset event buffer so we only see the discard's event.
        frame_system::Pallet::<Runtime>::reset_events();
        let assertion = build_self_discard_assertion(thumbprint);
        assert_ok!(ZkPki::self_discard_cert(
            RuntimeOrigin::signed(account(USER_ACCOUNT)),
            thumbprint,
            Some(assertion),
        ));
        let (standard, recovery) = emitted_self_discard_events();
        assert!(standard, "standard discard event must fire");
        assert!(!recovery, "recovery event must NOT fire on standard path");
    });
}

#[test]
fn self_discard_recovery_path_succeeds() {
    run(|| {
        let thumbprint = mint_pop_cert_for(USER_ACCOUNT);
        assert_ok!(ZkPki::self_discard_cert(
            RuntimeOrigin::signed(account(USER_ACCOUNT)),
            thumbprint,
            None,
        ));
        assert!(
            zk_pki_pallet::CertLookupHot::<Runtime>::get(thumbprint).is_none(),
            "cert hot row must be gone after discard",
        );
    });
}

#[test]
fn self_discard_recovery_path_emits_recovery_event() {
    run(|| {
        let thumbprint = mint_pop_cert_for(USER_ACCOUNT);
        frame_system::Pallet::<Runtime>::reset_events();
        assert_ok!(ZkPki::self_discard_cert(
            RuntimeOrigin::signed(account(USER_ACCOUNT)),
            thumbprint,
            None,
        ));
        let (standard, recovery) = emitted_self_discard_events();
        assert!(!standard, "standard event must NOT fire on recovery path");
        assert!(recovery, "recovery event must fire");
    });
}

#[test]
fn self_discard_wrong_holder_rejected() {
    run(|| {
        let thumbprint = mint_pop_cert_for(USER_ACCOUNT);
        // OTHER_ACCOUNT is not the cert.user.
        assert_noop!(
            ZkPki::self_discard_cert(
                RuntimeOrigin::signed(account(OTHER_ACCOUNT)),
                thumbprint,
                None,
            ),
            zk_pki_pallet::Error::<Runtime>::NotCertHolder,
        );
    });
}

#[test]
fn self_discard_invalid_cert_ec_signature_rejected() {
    run(|| {
        let thumbprint = mint_pop_cert_for(USER_ACCOUNT);
        let mut assertion = build_self_discard_assertion(thumbprint);
        // Flip a byte in the signature to break verification.
        match &mut assertion {
            PopAssertion::HipSigned { cert_ec_signature, .. } => {
                let mut sig_bytes = cert_ec_signature.to_vec();
                sig_bytes[5] ^= 0x01;
                *cert_ec_signature = BoundedVec::try_from(sig_bytes).unwrap();
            }
            _ => unreachable!("build_self_discard_assertion always returns HipSigned"),
        }
        assert_noop!(
            ZkPki::self_discard_cert(
                RuntimeOrigin::signed(account(USER_ACCOUNT)),
                thumbprint,
                Some(assertion),
            ),
            zk_pki_pallet::Error::<Runtime>::CertEcSignatureInvalid,
        );
    });
}

#[test]
fn self_discard_hip_proof_invalid_rejected() {
    run(|| {
        let thumbprint = mint_pop_cert_for(USER_ACCOUNT);
        let mut assertion = build_self_discard_assertion(thumbprint);
        // Flip a byte in the quote signature — HIP verifier fails.
        // Have to pattern-match through both enum layers to reach the
        // Tpm2 variant's fields.
        match &mut assertion {
            PopAssertion::HipSigned { hip_proof, .. } => {
                if let CanonicalHipProof::Tpm2(ref mut t) = hip_proof {
                    let mut qsig = t.quote_signature.to_vec();
                    qsig[5] ^= 0x01;
                    t.quote_signature = BoundedVec::try_from(qsig).unwrap();
                }
            }
            _ => unreachable!("build_self_discard_assertion always returns HipSigned"),
        }
        assert_noop!(
            ZkPki::self_discard_cert(
                RuntimeOrigin::signed(account(USER_ACCOUNT)),
                thumbprint,
                Some(assertion),
            ),
            zk_pki_pallet::Error::<Runtime>::HipProofInvalid,
        );
    });
}

#[test]
fn self_discard_non_pop_cert_with_assertion_rejected() {
    run(|| {
        let thumbprint = mint_non_pop_cert_for(USER_ACCOUNT);
        // Build a well-formed assertion targeting the non-PoP cert.
        // It should fail the PoP-EKU gate before signature checks.
        let assertion = build_self_discard_assertion(thumbprint);
        assert_noop!(
            ZkPki::self_discard_cert(
                RuntimeOrigin::signed(account(USER_ACCOUNT)),
                thumbprint,
                Some(assertion),
            ),
            zk_pki_pallet::Error::<Runtime>::PopEkuRequired,
        );
    });
}

#[test]
fn self_discard_non_pop_cert_recovery_path_succeeds() {
    run(|| {
        let thumbprint = mint_non_pop_cert_for(USER_ACCOUNT);
        // Non-PoP certs can always recovery-discard via SS58 only.
        assert_ok!(ZkPki::self_discard_cert(
            RuntimeOrigin::signed(account(USER_ACCOUNT)),
            thumbprint,
            None,
        ));
        assert!(zk_pki_pallet::CertLookupHot::<Runtime>::get(thumbprint).is_none());
    });
}

#[test]
fn self_discard_removes_all_storage_atomically() {
    run(|| {
        let thumbprint = mint_pop_cert_for(USER_ACCOUNT);

        // Confirm everything exists pre-discard.
        assert!(zk_pki_pallet::CertLookupHot::<Runtime>::get(thumbprint).is_some());
        assert!(zk_pki_pallet::CertLookupCold::<Runtime>::get(thumbprint).is_some());
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

        assert_ok!(ZkPki::self_discard_cert(
            RuntimeOrigin::signed(account(USER_ACCOUNT)),
            thumbprint,
            None,
        ));

        assert!(zk_pki_pallet::CertLookupHot::<Runtime>::get(thumbprint).is_none());
        assert!(zk_pki_pallet::CertLookupCold::<Runtime>::get(thumbprint).is_none());
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
fn self_discard_recovery_path_knowable_thumbprint() {
    run(|| {
        let _thumbprint = mint_pop_cert_for(USER_ACCOUNT);
        // Attempt to discard a thumbprint that was never minted.
        let wrong_thumbprint = [0xDEu8; 32];
        assert_noop!(
            ZkPki::self_discard_cert(
                RuntimeOrigin::signed(account(USER_ACCOUNT)),
                wrong_thumbprint,
                None,
            ),
            zk_pki_pallet::Error::<Runtime>::CertNotFound,
        );
    });
}

// Silence unused-import warning when Hooks isn't otherwise consumed.
#[allow(dead_code)]
fn _unused_hooks() {
    let _ = <zk_pki_pallet::Pallet<Runtime> as Hooks<u64>>::on_initialize;
}
