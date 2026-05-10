//! Stage 5b architectural invariant tests.
//!
//! These tests pin the platform gate (HipSigned ↔ TPM2 / MimeWrap ↔
//! StrongBox), the Paseo-tier `ec_key_pub` equality tripwire, the
//! template `pop_requirement ↔ pop_mechanism` consistency check, and
//! the `set_mime_wrap_vk` extrinsic guards. They cover the
//! architectural invariants the migration introduced; happy-path
//! behavior is exercised by the existing
//! `pop_mint_with_strongbox_proof_records_strongbox_fingerprint` test
//! in `hip_genesis.rs` and the verifier kernel real-fixture test in
//! `pki/pallet/src/mime_wrap.rs`.

use codec::Encode;
use frame_support::{assert_noop, assert_ok, traits::ConstU32, BoundedVec};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use sp_core::crypto::AccountId32;
use sp_runtime::BuildStorage;
use zk_pki_primitives::crypto::DevicePublicKey;
use zk_pki_primitives::eku::Eku;
use zk_pki_primitives::hip::{
    CanonicalHipProof, PcrValue, StrongBoxHipProof, Tpm2Flavor, Tpm2HipProof,
};
use zk_pki_primitives::template::{PopMechanism, PopRequirement};
use zk_pki_runtime::{Runtime, RuntimeOrigin, ZkPki};
use zk_pki_tpm::test_mock_verifier::MockVerdict;
use zk_pki_tpm::AttestationPayloadV3;

// ──────────────────────────────────────────────────────────────────────
// Harness (mirrors hip_genesis.rs to keep tests decoupled)
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
    use p256::ecdsa::VerifyingKey;
    let sk = SigningKey::from_slice(&[7u8; 32]).expect("valid P-256 scalar");
    let vk: VerifyingKey = *sk.verifying_key();
    vk.to_encoded_point(false).as_bytes().to_vec()
}

fn template_name() -> BoundedVec<u8, ConstU32<64>> {
    BoundedVec::try_from(b"mw-pop-template".to_vec()).unwrap()
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

/// Register root + issuer with PoP capability + create a template
/// with the requested mechanism + open an offer for USER_ACCOUNT.
fn setup_with_mechanism(
    pop_requirement: PopRequirement,
    pop_mechanism: Option<PopMechanism>,
) -> ([u8; 32], u64) {
    let root_pubkey =
        DevicePublicKey::new_p256(&test_cert_ec_pubkey()).expect("valid P-256 pubkey");
    let empty_att: BoundedVec<_, _> = BoundedVec::try_from(vec![]).unwrap();
    let pop_cap_ekus: BoundedVec<Eku, ConstU32<8>> =
        BoundedVec::try_from(vec![Eku::ProofOfPersonhood]).unwrap();
    let empty_template_ekus: BoundedVec<Eku, ConstU32<16>> =
        BoundedVec::try_from(vec![]).unwrap();

    assert_ok!(ZkPki::register_root(
        RuntimeOrigin::signed(account(ROOT_ACCOUNT)),
        account(ROOT_PROXY),
        root_pubkey.clone(),
        empty_att.clone(),
        1_000_000u64,
        pop_cap_ekus.clone(),
    ));
    assert_ok!(ZkPki::issue_issuer_cert(
        RuntimeOrigin::signed(account(ROOT_ACCOUNT)),
        account(ISSUER_ACCOUNT),
        account(ISSUER_PROXY),
        root_pubkey,
        empty_att,
        500_000u64,
        pop_cap_ekus,
    ));
    assert_ok!(ZkPki::create_cert_template(
        RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
        template_name(),
        pop_requirement,
        pop_mechanism,
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

fn synth_tpm2_proof() -> CanonicalHipProof {
    let ek = SigningKey::from_slice(&[0x11u8; 32]).unwrap();
    let aik = SigningKey::from_slice(&[0x22u8; 32]).unwrap();
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
    let aik_certify_info = b"aik-certify-info".to_vec();
    let aik_certify_sig: Signature = ek.sign(&aik_certify_info);
    let pcr_digest = [0xAAu8; 32];
    let nonce = [0x01u8; 32];
    let quote_attest = synth_tpms_attest_quote(&nonce, &pcr_digest);
    let quote_sig: Signature = aik.sign(&quote_attest);
    let pcr_values: BoundedVec<PcrValue, ConstU32<16>> = BoundedVec::try_from(vec![
        PcrValue { index: 7, value: [0x77u8; 32] },
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

fn synth_strongbox_proof() -> CanonicalHipProof {
    let cert_ec_sk = SigningKey::from_slice(&[0x07u8; 32]).unwrap();
    let attest_ec_sk = SigningKey::from_slice(&[0x22u8; 32]).unwrap();
    let cert_ec_point = cert_ec_sk.verifying_key().to_encoded_point(false);
    let attest_ec_point = attest_ec_sk.verifying_key().to_encoded_point(false);
    let mut cert_ec_sec1 = [0u8; 65];
    cert_ec_sec1.copy_from_slice(cert_ec_point.as_bytes());
    let mut attest_ec_sec1 = [0u8; 65];
    attest_ec_sec1.copy_from_slice(attest_ec_point.as_bytes());

    let challenge = [0x11u8; 32];
    let hmac_binding_output = [0xAAu8; 32];

    let mut commit_input = [0u8; 64];
    commit_input[..32].copy_from_slice(&hmac_binding_output);
    commit_input[32..].copy_from_slice(&challenge);
    let commitment = sp_io::hashing::blake2_256(&commit_input);
    // StrongBox signs SHA256(blake2_256(...)) because KeyMint forces
    // SHA256withECDSA on cert_ec / attest_ec keys. Mirror that here so
    // the synthesized fixture passes the same verifier path real
    // ceremony bytes do.
    let commitment_sha = sp_io::hashing::sha2_256(&commitment);
    let binding_sig: Signature = attest_ec_sk
        .sign_prehash_recoverable(&commitment_sha)
        .map(|(s, _)| s)
        .unwrap_or_else(|_| attest_ec_sk.sign(&commitment_sha));

    let integrity_blob = b"integrity-placeholder".to_vec();
    let integrity_digest = sp_io::hashing::blake2_256(&integrity_blob);
    let integrity_digest_sha = sp_io::hashing::sha2_256(&integrity_digest);
    let integrity_sig: Signature = cert_ec_sk
        .sign_prehash_recoverable(&integrity_digest_sha)
        .map(|(s, _)| s)
        .unwrap_or_else(|_| cert_ec_sk.sign(&integrity_digest_sha));

    let minimal_cert =
        BoundedVec::<u8, ConstU32<2048>>::try_from(vec![0x30, 0x82]).unwrap();
    let chain: BoundedVec<BoundedVec<u8, ConstU32<2048>>, ConstU32<8>> =
        BoundedVec::try_from(vec![minimal_cert.clone(), minimal_cert.clone()]).unwrap();

    CanonicalHipProof::StrongBox(StrongBoxHipProof {
        cert_ec_public: cert_ec_sec1,
        attest_ec_public: attest_ec_sec1,
        cert_ec_chain: chain.clone(),
        attest_ec_chain: chain,
        hmac_binding_output,
        hmac_binding_signature: BoundedVec::try_from(
            binding_sig.to_der().as_bytes().to_vec(),
        )
        .unwrap(),
        binding_proof_context: BoundedVec::try_from(
            b"zkpki-binding-proof-v1".to_vec(),
        )
        .unwrap(),
        integrity_blob: BoundedVec::try_from(integrity_blob).unwrap(),
        integrity_signature: BoundedVec::try_from(
            integrity_sig.to_der().as_bytes().to_vec(),
        )
        .unwrap(),
        nonce: challenge,
    })
}

fn tpm_payload() -> AttestationPayloadV3 {
    payload_with_verdict(MockVerdict::Tpm {
        ek_hash: [0x42u8; 32],
        pubkey_bytes: test_cert_ec_pubkey(),
    })
}

// ──────────────────────────────────────────────────────────────────────
// 1 — create_cert_template invariant: pop_requirement ↔ pop_mechanism
// ──────────────────────────────────────────────────────────────────────

#[test]
fn create_cert_template_required_without_mechanism_rejected() {
    run(|| {
        // PoP is required but no mechanism declared — template would
        // produce certs the verifier couldn't dispatch on.
        let root_pubkey =
            DevicePublicKey::new_p256(&test_cert_ec_pubkey()).unwrap();
        let empty_att: BoundedVec<_, _> = BoundedVec::try_from(vec![]).unwrap();
        let pop_cap_ekus: BoundedVec<Eku, ConstU32<8>> =
            BoundedVec::try_from(vec![Eku::ProofOfPersonhood]).unwrap();
        let empty_template_ekus: BoundedVec<Eku, ConstU32<16>> =
            BoundedVec::try_from(vec![]).unwrap();
        assert_ok!(ZkPki::register_root(
            RuntimeOrigin::signed(account(ROOT_ACCOUNT)),
            account(ROOT_PROXY),
            root_pubkey.clone(),
            empty_att.clone(),
            1_000_000u64,
            pop_cap_ekus.clone(),
        ));
        assert_ok!(ZkPki::issue_issuer_cert(
            RuntimeOrigin::signed(account(ROOT_ACCOUNT)),
            account(ISSUER_ACCOUNT),
            account(ISSUER_PROXY),
            root_pubkey,
            empty_att,
            500_000u64,
            pop_cap_ekus,
        ));
        assert_noop!(
            ZkPki::create_cert_template(
                RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
                template_name(),
                PopRequirement::Required,
                None, // mechanism missing — invariant violation
                400_000u64,
                1_000u64,
                None,
                None,
                empty_template_ekus,
            ),
            zk_pki_pallet::Error::<Runtime>::PopMechanismMismatch,
        );
    });
}

#[test]
fn create_cert_template_not_required_with_mechanism_rejected() {
    run(|| {
        // Mechanism declared on a NotRequired template — the field
        // would be unconsulted, so reject as a config bug rather
        // than silently storing a meaningless value.
        let root_pubkey =
            DevicePublicKey::new_p256(&test_cert_ec_pubkey()).unwrap();
        let empty_att: BoundedVec<_, _> = BoundedVec::try_from(vec![]).unwrap();
        let empty_cap_ekus: BoundedVec<Eku, ConstU32<8>> =
            BoundedVec::try_from(vec![]).unwrap();
        let empty_template_ekus: BoundedVec<Eku, ConstU32<16>> =
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
        assert_noop!(
            ZkPki::create_cert_template(
                RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
                template_name(),
                PopRequirement::NotRequired,
                Some(PopMechanism::HipSigned), // shouldn't be set
                400_000u64,
                1_000u64,
                None,
                None,
                empty_template_ekus,
            ),
            zk_pki_pallet::Error::<Runtime>::PopMechanismMismatch,
        );
    });
}

// ──────────────────────────────────────────────────────────────────────
// 2 — Platform gate at mint
// ──────────────────────────────────────────────────────────────────────

#[test]
fn mint_hipsigned_template_with_strongbox_proof_rejected() {
    // The combo MimeWrap was created to mask: StrongBox HMAC binding
    // is too weak to carry a cert_ec_signature path safely.
    run(|| {
        let (nonce, created_at) = setup_with_mechanism(
            PopRequirement::Required,
            Some(PopMechanism::HipSigned),
        );
        assert_noop!(
            ZkPki::mint_cert(
                RuntimeOrigin::signed(account(USER_ACCOUNT)),
                nonce,
                tpm_payload(),
                created_at,
                Some(synth_strongbox_proof()),
                None,
                None,
            ),
            zk_pki_pallet::Error::<Runtime>::HipSignedNotPermittedOnStrongBox,
        );
    });
}

#[test]
fn mint_mimewrap_template_with_tpm2_proof_rejected() {
    // TPM2 has a real attestation chain — MimeWrap on TPM2 is a
    // category error, not a security improvement.
    run(|| {
        let (nonce, created_at) = setup_with_mechanism(
            PopRequirement::Required,
            Some(PopMechanism::MimeWrap),
        );
        let expected = zk_pki_pallet::mime_wrap::derive_ec_key_pub_p256(
            &test_cert_ec_pubkey(),
        )
        .unwrap();
        assert_noop!(
            ZkPki::mint_cert(
                RuntimeOrigin::signed(account(USER_ACCOUNT)),
                nonce,
                tpm_payload(),
                created_at,
                Some(synth_tpm2_proof()),
                Some([0xCCu8; 32]),
                Some(expected),
            ),
            zk_pki_pallet::Error::<Runtime>::MimeWrapNotPermittedOnTpm2,
        );
    });
}

// ──────────────────────────────────────────────────────────────────────
// 3 — Tripwire: ec_key_pub_claimed mismatch
// ──────────────────────────────────────────────────────────────────────

#[test]
fn mint_mimewrap_with_wrong_ec_key_pub_claimed_rejected() {
    // Paseo-tier guard. The chain re-derives ec_key_pub from the
    // verified cert_ec_pubkey; client-supplied bytes that don't
    // match indicate either canonicalization drift or an attempt to
    // bind a fake ec_key_pub to a real cert.
    run(|| {
        let (nonce, created_at) = setup_with_mechanism(
            PopRequirement::Required,
            Some(PopMechanism::MimeWrap),
        );
        // Wrong claimed value — tripwire fires.
        let bogus_claimed = [0xDEu8; 32];
        assert_noop!(
            ZkPki::mint_cert(
                RuntimeOrigin::signed(account(USER_ACCOUNT)),
                nonce,
                tpm_payload(),
                created_at,
                Some(synth_strongbox_proof()),
                Some([0xCCu8; 32]),
                Some(bogus_claimed),
            ),
            zk_pki_pallet::Error::<Runtime>::MimeWrapEcKeyPubMismatch,
        );
    });
}

#[test]
fn mint_mimewrap_without_commitment_rejected() {
    run(|| {
        let (nonce, created_at) = setup_with_mechanism(
            PopRequirement::Required,
            Some(PopMechanism::MimeWrap),
        );
        let expected = zk_pki_pallet::mime_wrap::derive_ec_key_pub_p256(
            &test_cert_ec_pubkey(),
        )
        .unwrap();
        // commitment_c missing.
        assert_noop!(
            ZkPki::mint_cert(
                RuntimeOrigin::signed(account(USER_ACCOUNT)),
                nonce,
                tpm_payload(),
                created_at,
                Some(synth_strongbox_proof()),
                None,
                Some(expected),
            ),
            zk_pki_pallet::Error::<Runtime>::MimeWrapCommitmentRequired,
        );
    });
}

#[test]
fn mint_hipsigned_with_commitment_rejected() {
    // Symmetric: HipSigned templates must NOT carry mime-wrap fields.
    run(|| {
        let (nonce, created_at) = setup_with_mechanism(
            PopRequirement::Required,
            Some(PopMechanism::HipSigned),
        );
        assert_noop!(
            ZkPki::mint_cert(
                RuntimeOrigin::signed(account(USER_ACCOUNT)),
                nonce,
                tpm_payload(),
                created_at,
                Some(synth_tpm2_proof()),
                Some([0xCCu8; 32]),
                None,
            ),
            zk_pki_pallet::Error::<Runtime>::MimeWrapCommitmentNotApplicable,
        );
    });
}

// ──────────────────────────────────────────────────────────────────────
// 4 — set_mime_wrap_vk extrinsic
// ──────────────────────────────────────────────────────────────────────

#[test]
fn set_mime_wrap_vk_too_long_rejected() {
    run(|| {
        // MAX_MIME_WRAP_VK_BYTES is 32_768. Submit one byte over.
        let bytes = vec![0u8; 32_769];
        assert_noop!(
            ZkPki::set_mime_wrap_vk(
                RuntimeOrigin::signed(account(USER_ACCOUNT)),
                bytes,
            ),
            zk_pki_pallet::Error::<Runtime>::MimeWrapVkTooLong,
        );
    });
}

#[test]
fn set_mime_wrap_vk_happy_path_writes_storage_and_emits_event() {
    run(|| {
        let bytes = vec![0xAAu8; 1024]; // arbitrary placeholder VK bytes
        assert_ok!(ZkPki::set_mime_wrap_vk(
            RuntimeOrigin::signed(account(USER_ACCOUNT)),
            bytes.clone(),
        ));
        // Storage written.
        let stored = zk_pki_pallet::MimeWrapVk::<Runtime>::get()
            .expect("VK must be stored after set_mime_wrap_vk");
        assert_eq!(stored.into_inner(), bytes);
        // Event emitted.
        let saw_event = frame_system::Pallet::<Runtime>::events()
            .iter()
            .any(|rec| matches!(
                rec.event,
                zk_pki_runtime::RuntimeEvent::ZkPki(
                    zk_pki_pallet::Event::MimeWrapVkSet
                )
            ));
        assert!(saw_event, "MimeWrapVkSet event must fire");
    });
}
