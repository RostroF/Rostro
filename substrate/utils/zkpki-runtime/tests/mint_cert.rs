//! Integration tests for the TODO-4 `mint_cert` wiring.
//!
//! These tests exercise the full pallet path — `register_root` →
//! `issue_issuer_cert` → `offer_contract` → `mint_cert` — against the
//! reference runtime. The runtime wires
//! `zk_pki_tpm::test_mock_verifier::NoopBindingProofVerifier` as
//! `T::BindingProofVerifier`, so each test controls the verifier's
//! verdict by SCALE-encoding a [`MockVerdict`] into
//! `payload.integrity_blob`. This keeps the tests explicit (the
//! verdict is visible in payload construction) and unblocks the
//! `Ok`-path tests that would otherwise be stopped by the placeholder
//! `DOTWAVE_SIGNING_CERT_HASH` constant.
//!
//! # Covers the four TODO-4 tests
//!
//! - `mint_cert_with_valid_attestation_succeeds` — full happy path,
//!   `AttestationType::Tpm`, cert + EK registry populated.
//! - `mint_cert_with_invalid_attestation_fails` —
//!   `MockVerdict::Fail` → `Error::AttestationInvalid`.
//! - `mint_cert_ek_dedup_blocks_second_cert` — same EK hash minted
//!   twice → second attempt blocked with `Error::EkAlreadyRegistered`.
//! - `mint_cert_packed_skips_ek_dedup` — `AttestationType::Packed` →
//!   EK registry untouched, same EK hash can appear again.
//!
//! The mock verifier does not exercise `verify_binding_proof` itself
//! — that's covered by the fixture-sanity tests in `zk-pki-tpm`. The
//! integration layer here validates the *pallet's* use of the
//! verifier output: storage writes, EK dedup gate, `CertRecord`
//! population including the new `manufacturer_verified` field.

use codec::Encode;
use frame_support::{assert_noop, assert_ok, traits::Currency, BoundedVec};
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

type BlockNumber = u64;

// ──────────────────────────────────────────────────────────────────────
// Test harness
// ──────────────────────────────────────────────────────────────────────

const ROOT_ACCOUNT: [u8; 32] = [0xA1; 32];
const ISSUER_ACCOUNT: [u8; 32] = [0xB2; 32];
const USER_ACCOUNT: [u8; 32] = [0xC3; 32];
const ROOT_PROXY: [u8; 32] = [0xD4; 32];
const ISSUER_PROXY: [u8; 32] = [0xE5; 32];

/// Starting balance per funded account. Needs to cover every storage
/// deposit the test takes across the full `register_root` →
/// `issue_issuer_cert` → `offer_contract` → `mint_cert` flow.
const INITIAL_BALANCE: u128 = 100_000_000_000_000;

/// Deterministic P-256 uncompressed SEC1 pubkey. Computed from the
/// fixed scalar `[7u8; 32]` via `p256::ecdsa::SigningKey` rather than
/// hand-rolled — tests need valid curve points or `DevicePublicKey::
/// new_p256(..)` rejects them with `BadPublicKey`.
fn test_cert_ec_pubkey() -> Vec<u8> {
    use p256::ecdsa::{SigningKey, VerifyingKey};
    let sk = SigningKey::from_slice(&[7u8; 32]).expect("valid P-256 scalar");
    let vk: VerifyingKey = *sk.verifying_key();
    vk.to_encoded_point(false).as_bytes().to_vec()
}

fn account(seed: [u8; 32]) -> AccountId32 {
    AccountId32::from(seed)
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

/// Execute a closure inside a fresh externalities block started at
/// block 1 so `frame_system::Pallet::block_number()` returns a
/// non-zero value (several pallet branches gate on `now < …` which
/// fails at block 0).
fn run<R>(f: impl FnOnce() -> R) -> R {
    new_test_ext().execute_with(|| {
        frame_system::Pallet::<Runtime>::set_block_number(1);
        f()
    })
}

/// Register a root, issue an issuer cert to `ISSUER_ACCOUNT`, create
/// a contract offer for `USER_ACCOUNT`. Returns the offer nonce and
/// the offer's `created_at` block — both needed by `mint_cert`.
///
/// Plain variant: no capability EKUs anywhere, so the template cannot
/// admit chat enrollments. Enrollment tests use
/// [`setup_up_to_offer_chat_auth`].
fn setup_up_to_offer() -> ([u8; 32], BlockNumber) {
    setup_offer_impl(None)
}

/// Chat-chartered variant: `ChatAuth` flows root capability → issuer
/// capability → template EKUs, so `mint_cert` accepts a
/// `chat_enrollment` under the offer.
fn setup_up_to_offer_chat_auth() -> ([u8; 32], BlockNumber) {
    setup_offer_impl(Some(zk_pki_primitives::eku::Eku::ChatAuth))
}

/// Witness-chartered variant: `WitnessAuth` flows root → issuer → template,
/// so `mint_witness_cert` accepts an enrollment under the offer.
fn setup_up_to_offer_witness_auth() -> ([u8; 32], BlockNumber) {
    setup_offer_impl(Some(zk_pki_primitives::eku::Eku::WitnessAuth))
}

fn setup_offer_impl(cap: Option<zk_pki_primitives::eku::Eku>) -> ([u8; 32], BlockNumber) {
    use zk_pki_primitives::eku::Eku;

    // 1. Register root. T::Attestation is NoopAttestationVerifier so
    //    the bytes of `attestation` don't matter — we pass an empty
    //    BoundedVec.  ttl_blocks must be ≤ MaxRootTtlBlocks.
    let root_pubkey =
        DevicePublicKey::new_p256(&test_cert_ec_pubkey()).expect("valid P-256 pubkey");
    let empty_att: BoundedVec<_, _> = BoundedVec::try_from(vec![]).unwrap();
    let cap_source: Vec<Eku> = cap.into_iter().collect();
    let cap_ekus:
        BoundedVec<zk_pki_primitives::eku::Eku, frame_support::traits::ConstU32<8>> =
        BoundedVec::try_from(cap_source.clone()).unwrap();
    let template_ekus:
        BoundedVec<zk_pki_primitives::eku::Eku, frame_support::traits::ConstU32<16>> =
        BoundedVec::try_from(cap_source).unwrap();
    assert_ok!(ZkPki::register_root(
        RuntimeOrigin::signed(account(ROOT_ACCOUNT)),
        account(ROOT_PROXY),
        root_pubkey.clone(),
        empty_att.clone(),
        1_000_000u64,
        cap_ekus.clone(),
    ));

    // 2. Issue issuer cert.
    assert_ok!(ZkPki::issue_issuer_cert(
        RuntimeOrigin::signed(account(ROOT_ACCOUNT)),
        account(ISSUER_ACCOUNT),
        account(ISSUER_PROXY),
        root_pubkey,
        empty_att.clone(),
        500_000u64,
        cap_ekus,
    ));

    // 3. Create a permissive cert template the offer can reference.
    assert_ok!(ZkPki::create_cert_template(
        RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
        template_name(),
        PopRequirement::NotRequired,
        None, // pop_mechanism
        400_000u64,
        1_000u64,
        None,
        None,
        template_ekus,
    ));

    // 4. Offer contract to the user under the template.
    let empty_meta: BoundedVec<_, _> = BoundedVec::try_from(vec![]).unwrap();
    assert_ok!(ZkPki::offer_contract(
        RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
        account(USER_ACCOUNT),
        10_000u64,
        template_name(),
        empty_meta,
    ));

    // Look up the nonce via OfferIndex (issuer, user → nonce).
    let ui_key = zk_pki_primitives::keys::IssuerUserKey::new(
        account(ISSUER_ACCOUNT),
        account(USER_ACCOUNT),
    );
    let nonce = zk_pki_pallet::OfferIndex::<Runtime>::get(&ui_key)
        .expect("offer registered above");
    let offer = zk_pki_pallet::ContractOffers::<Runtime>::get(nonce)
        .expect("offer present after offer_contract");
    (nonce, offer.created_at)
}

/// Build an `AttestationPayloadV3` whose `integrity_blob` is the
/// SCALE-encoded [`MockVerdict`] the test wants the mock verifier to
/// return. Every other field is dummy — the mock ignores them.
fn payload_with_verdict(verdict: MockVerdict) -> AttestationPayloadV3 {
    AttestationPayloadV3 {
        cert_ec_chain: vec![vec![0u8; 0]],
        attest_ec_chain: vec![vec![0u8; 0]],
        hmac_binding_output: [0u8; 32],
        binding_signature: vec![],
        integrity_blob: verdict.encode(),
        integrity_signature: vec![],
    }
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

#[test]
fn mint_cert_with_valid_attestation_succeeds() {
    run(|| {
        let (nonce, created_at) = setup_up_to_offer();

        let ek_hash = [0x42u8; 32];
        let payload = payload_with_verdict(MockVerdict::Tpm {
            ek_hash,
            pubkey_bytes: test_cert_ec_pubkey(),
        });

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

        // Offer consumed.
        assert!(zk_pki_pallet::ContractOffers::<Runtime>::get(nonce).is_none());

        // EK registry populated (Tpm → PoP eligible → dedup active).
        // Root-scoped: lookup keyed by (root, ek_hash). Root for an
        // end-user cert is the issuer's anchoring root — here
        // `ROOT_ACCOUNT`, since that's who issued `ISSUER_ACCOUNT`'s
        // cert.
        let thumbprint = zk_pki_pallet::EkRegistry::<Runtime>::get(
            &account(ROOT_ACCOUNT),
            ek_hash,
        )
        .expect("Tpm mint must write EK registry");
        let cert = zk_pki_pallet::CertLookupHot::<Runtime>::get(thumbprint)
            .expect("cert record present after mint");
        assert_eq!(cert.attestation_type, zk_pki_primitives::tpm::AttestationType::Tpm);
        assert_eq!(cert.ek_hash, Some(ek_hash));
        assert!(
            cert.manufacturer_verified,
            "Tpm verdict from mock sets manufacturer_verified=true",
        );
    });
}

#[test]
fn mint_cert_with_invalid_attestation_fails() {
    run(|| {
        let (nonce, created_at) = setup_up_to_offer();
        let payload = payload_with_verdict(MockVerdict::Fail);

        assert_noop!(
            ZkPki::mint_cert(
                RuntimeOrigin::signed(account(USER_ACCOUNT)),
                nonce,
                payload,
                created_at,
                None,
                None, // commitment_c
                None, // ec_key_pub_claimed
                None, // chat_enrollment
            ),
            zk_pki_pallet::Error::<Runtime>::AttestationInvalid,
        );

        // Offer still present; nothing else changed.
        assert!(zk_pki_pallet::ContractOffers::<Runtime>::get(nonce).is_some());
    });
}

#[test]
fn mint_cert_ek_dedup_blocks_second_cert() {
    run(|| {
        let (nonce, created_at) = setup_up_to_offer();
        let ek_hash = [0x77u8; 32];

        // First mint succeeds.
        let payload1 = payload_with_verdict(MockVerdict::Tpm {
            ek_hash,
            pubkey_bytes: test_cert_ec_pubkey(),
        });
        assert_ok!(ZkPki::mint_cert(
            RuntimeOrigin::signed(account(USER_ACCOUNT)),
            nonce,
            payload1,
            created_at,
            None,
            None, // commitment_c
            None, // ec_key_pub_claimed
            None, // chat_enrollment
        ));
        assert!(zk_pki_pallet::EkRegistry::<Runtime>::contains_key(
            &account(ROOT_ACCOUNT),
            ek_hash,
        ));

        // A second user tries to mint with the same EK hash.
        // New offer to a different user, same issuer.
        let second_user: [u8; 32] = [0xF6; 32];
        let _imbalance = pallet_balances::Pallet::<Runtime>::deposit_creating(
            &account(second_user),
            INITIAL_BALANCE,
        );
        let empty_meta: BoundedVec<_, _> = BoundedVec::try_from(vec![]).unwrap();
        assert_ok!(ZkPki::offer_contract(
            RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
            account(second_user),
            10_000u64,
            template_name(),
            empty_meta,
        ));
        let ui_key2 = zk_pki_primitives::keys::IssuerUserKey::new(
            account(ISSUER_ACCOUNT),
            account(second_user),
        );
        let nonce2 = zk_pki_pallet::OfferIndex::<Runtime>::get(&ui_key2)
            .expect("second offer registered");
        let offer2 = zk_pki_pallet::ContractOffers::<Runtime>::get(nonce2).unwrap();

        let payload2 = payload_with_verdict(MockVerdict::Tpm {
            ek_hash, // same EK hash as first mint
            pubkey_bytes: test_cert_ec_pubkey(),
        });

        assert_noop!(
            ZkPki::mint_cert(
                RuntimeOrigin::signed(account(second_user)),
                nonce2,
                payload2,
                offer2.created_at,
                None,
                None, // commitment_c
                None, // ec_key_pub_claimed
                None, // chat_enrollment
            ),
            zk_pki_pallet::Error::<Runtime>::EkAlreadyRegistered,
        );
    });
}

#[test]
fn mint_cert_packed_skips_ek_dedup() {
    run(|| {
        let (nonce, created_at) = setup_up_to_offer();

        // Packed verdict: mint should succeed but must NOT write the
        // EK registry (Packed isn't PoP-eligible).
        let payload = payload_with_verdict(MockVerdict::Packed {
            pubkey_bytes: test_cert_ec_pubkey(),
        });
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

        // The Packed mock returns ek_hash = [0u8; 32]. Registry must
        // NOT contain it — dedup skipped for Packed.
        assert!(
            !zk_pki_pallet::EkRegistry::<Runtime>::contains_key(
                &account(ROOT_ACCOUNT),
                [0u8; 32],
            ),
            "Packed attestation type must skip EK registry",
        );

        // A second offer/mint with the same (would-have-been-same) EK
        // must succeed — nothing to dedup against.
        let second_user: [u8; 32] = [0x99; 32];
        let _imbalance = pallet_balances::Pallet::<Runtime>::deposit_creating(
            &account(second_user),
            INITIAL_BALANCE,
        );
        let empty_meta: BoundedVec<_, _> = BoundedVec::try_from(vec![]).unwrap();
        assert_ok!(ZkPki::offer_contract(
            RuntimeOrigin::signed(account(ISSUER_ACCOUNT)),
            account(second_user),
            10_000u64,
            template_name(),
            empty_meta,
        ));
        let ui_key2 = zk_pki_primitives::keys::IssuerUserKey::new(
            account(ISSUER_ACCOUNT),
            account(second_user),
        );
        let nonce2 = zk_pki_pallet::OfferIndex::<Runtime>::get(&ui_key2).unwrap();
        let offer2 = zk_pki_pallet::ContractOffers::<Runtime>::get(nonce2).unwrap();

        let payload2 = payload_with_verdict(MockVerdict::Packed {
            pubkey_bytes: test_cert_ec_pubkey(),
        });
        assert_ok!(ZkPki::mint_cert(
            RuntimeOrigin::signed(account(second_user)),
            nonce2,
            payload2,
            offer2.created_at,
            None,
            None, // commitment_c
            None, // ec_key_pub_claimed
            None, // chat_enrollment
        ));

        // Both certs minted, both with attestation_type=Packed.
        let packed_count = zk_pki_pallet::CertLookupHot::<Runtime>::iter_values()
            .filter(|r| r.attestation_type == zk_pki_primitives::tpm::AttestationType::Packed)
            .count();
        assert_eq!(packed_count, 2, "two Packed mints must have landed");
    });
}

/// Build a valid chat enrollment for `nonce`: `id_commitment = Poseidon(s)`,
/// signed by the same P-256 key the mock returns as `attest_ec` (scalar 7,
/// via `test_cert_ec_pubkey`).
fn valid_enrollment(nonce: &[u8; 32]) -> zk_pki_tpm::ChatEnrollment {
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use rostro_poseidon_bn254::{fr_to_bytes_le, id_commitment, params, PoseidonField as Fr};

    let p = params();
    let idc_bytes = fr_to_bytes_le(&id_commitment(&p, Fr::from(12345u64)));
    let sk = SigningKey::from_slice(&[7u8; 32]).unwrap();
    let mut input = Vec::new();
    input.extend_from_slice(zk_pki_tpm::ID_BINDING_CONTEXT);
    input.extend_from_slice(&idc_bytes);
    input.extend_from_slice(nonce);
    let msg = sp_core::hashing::blake2_256(&input);
    let sig: Signature = sk.sign(&msg);
    zk_pki_tpm::ChatEnrollment {
        id_commitment: idc_bytes,
        id_binding_signature: sig.to_der().as_bytes().to_vec(),
    }
}

#[test]
fn mint_cert_with_chat_enrollment_inserts_leaf() {
    run(|| {
        let (nonce, created_at) = setup_up_to_offer_chat_auth();
        let payload = payload_with_verdict(MockVerdict::Tpm {
            ek_hash: [0x42u8; 32],
            pubkey_bytes: test_cert_ec_pubkey(),
        });
        let enrollment = valid_enrollment(&nonce);

        let empty_root = ZkPki::membership_root();
        let empty_freshness = ZkPki::freshness_root();
        assert_ok!(ZkPki::mint_cert(
            RuntimeOrigin::signed(account(USER_ACCOUNT)),
            nonce,
            payload,
            created_at,
            None,
            None, // commitment_c
            None, // ec_key_pub_claimed
            Some(enrollment),
        ));

        // A membership leaf was inserted and recorded on the cold record.
        assert_ne!(ZkPki::membership_root(), empty_root, "root advances on enrollment");
        let thumb = zk_pki_pallet::CertsByUser::<Runtime>::iter_prefix(account(USER_ACCOUNT))
            .next()
            .map(|(t, _)| t)
            .expect("cert minted");
        let cold = zk_pki_pallet::CertLookupCold::<Runtime>::get(thumb).expect("cold record");
        assert_eq!(cold.leaf_position, Some(0));

        // The parallel freshness leaf was set at the same index on enrollment.
        assert_ne!(
            ZkPki::freshness_root(),
            empty_freshness,
            "freshness leaf set on enrollment",
        );
    });
}

/// `TpmWithAttest` (the phone-mint testnet shape): the mock reports a
/// DISTINCT attest_ec, and the enrollment binding must verify against
/// THAT key — a signature by the cert key must be rejected. This is the
/// variant the dotwave client encodes so its real StrongBox attest_ec
/// signature is what `verify_chat_enrollment` checks.
#[test]
fn mint_cert_enrollment_verifies_against_distinct_attest_key() {
    use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};

    let attest_sk = SigningKey::from_slice(&[9u8; 32]).expect("valid P-256 scalar");
    let attest_pubkey_bytes = {
        let vk: VerifyingKey = *attest_sk.verifying_key();
        vk.to_encoded_point(false).as_bytes().to_vec()
    };
    let sign_with =
        |sk: &SigningKey, enrollment: &mut zk_pki_tpm::ChatEnrollment, nonce: &[u8; 32]| {
            let mut input = Vec::new();
            input.extend_from_slice(zk_pki_tpm::ID_BINDING_CONTEXT);
            input.extend_from_slice(&enrollment.id_commitment);
            input.extend_from_slice(nonce);
            let msg = sp_core::hashing::blake2_256(&input);
            let sig: Signature = sk.sign(&msg);
            enrollment.id_binding_signature = sig.to_der().as_bytes().to_vec();
        };

    // Signed by the distinct attest key -> leaf inserted.
    run(|| {
        let (nonce, created_at) = setup_up_to_offer_chat_auth();
        let payload = payload_with_verdict(MockVerdict::TpmWithAttest {
            ek_hash: [0x42u8; 32],
            pubkey_bytes: test_cert_ec_pubkey(),
            attest_pubkey_bytes: attest_pubkey_bytes.clone(),
        });
        let mut enrollment = valid_enrollment(&nonce);
        sign_with(&attest_sk, &mut enrollment, &nonce);

        let empty_root = ZkPki::membership_root();
        assert_ok!(ZkPki::mint_cert(
            RuntimeOrigin::signed(account(USER_ACCOUNT)),
            nonce,
            payload,
            created_at,
            None,
            None, // commitment_c
            None, // ec_key_pub_claimed
            Some(enrollment),
        ));
        assert_ne!(ZkPki::membership_root(), empty_root, "root advances on enrollment");
    });

    // Signed by the CERT key -> rejected: proves the mock's attest slot,
    // not its cert slot, is what the enrollment verifies against.
    run(|| {
        let (nonce, created_at) = setup_up_to_offer_chat_auth();
        let payload = payload_with_verdict(MockVerdict::TpmWithAttest {
            ek_hash: [0x42u8; 32],
            pubkey_bytes: test_cert_ec_pubkey(),
            attest_pubkey_bytes: attest_pubkey_bytes.clone(),
        });
        let cert_sk = SigningKey::from_slice(&[7u8; 32]).expect("valid P-256 scalar");
        let mut enrollment = valid_enrollment(&nonce);
        sign_with(&cert_sk, &mut enrollment, &nonce);

        assert_noop!(
            ZkPki::mint_cert(
                RuntimeOrigin::signed(account(USER_ACCOUNT)),
                nonce,
                payload,
                created_at,
                None,
                None, // commitment_c
                None, // ec_key_pub_claimed
                Some(enrollment),
            ),
            zk_pki_pallet::Error::<Runtime>::ChatEnrollmentInvalid,
        );
    });
}

#[test]
fn mint_cert_with_bad_enrollment_signature_rejected() {
    run(|| {
        let (nonce, created_at) = setup_up_to_offer_chat_auth();
        let payload = payload_with_verdict(MockVerdict::Tpm {
            ek_hash: [0x42u8; 32],
            pubkey_bytes: test_cert_ec_pubkey(),
        });
        let mut enrollment = valid_enrollment(&nonce);
        // Corrupt the binding signature: the mint must reject before any
        // storage write (assert_noop verifies no state change).
        enrollment.id_binding_signature = vec![0u8; 8];

        assert_noop!(
            ZkPki::mint_cert(
                RuntimeOrigin::signed(account(USER_ACCOUNT)),
                nonce,
                payload,
                created_at,
                None,
                None, // commitment_c
                None, // ec_key_pub_claimed
                Some(enrollment),
            ),
            zk_pki_pallet::Error::<Runtime>::ChatEnrollmentInvalid,
        );
    });
}

#[test]
fn mint_cert_enrollment_from_non_strongbox_rejected() {
    run(|| {
        let (nonce, created_at) = setup_up_to_offer_chat_auth();
        // Packed = not StrongBox-grade (not PoP-eligible). Enrollment must
        // be refused even with an otherwise-valid binding signature: the
        // §5.5 device-integrity gate fires before the signature check.
        let payload = payload_with_verdict(MockVerdict::Packed {
            pubkey_bytes: test_cert_ec_pubkey(),
        });
        let enrollment = valid_enrollment(&nonce);
        assert_noop!(
            ZkPki::mint_cert(
                RuntimeOrigin::signed(account(USER_ACCOUNT)),
                nonce,
                payload,
                created_at,
                None,
                None, // commitment_c
                None, // ec_key_pub_claimed
                Some(enrollment),
            ),
            zk_pki_pallet::Error::<Runtime>::ChatEnrollmentInsecureDevice,
        );
    });
}

#[test]
fn mint_cert_enrollment_with_imported_key_rejected() {
    run(|| {
        let (nonce, created_at) = setup_up_to_offer_chat_auth();
        // StrongBox-grade device (passes the device-integrity gate) but the
        // binding key was imported (origin != GENERATED). The §5.5
        // non-exportability gate must refuse it.
        let payload = payload_with_verdict(MockVerdict::TpmImported {
            ek_hash: [0x42u8; 32],
            pubkey_bytes: test_cert_ec_pubkey(),
        });
        let enrollment = valid_enrollment(&nonce);
        assert_noop!(
            ZkPki::mint_cert(
                RuntimeOrigin::signed(account(USER_ACCOUNT)),
                nonce,
                payload,
                created_at,
                None,
                None, // commitment_c
                None, // ec_key_pub_claimed
                Some(enrollment),
            ),
            zk_pki_pallet::Error::<Runtime>::ChatEnrollmentKeyNotHardwareGenerated,
        );
    });
}

// ──────────────────────────────────────────────────────────────────────
// ChatAuth EKU ⇔ membership leaf invariant
// ──────────────────────────────────────────────────────────────────────

/// Charter gate: an enrollment under a template that does NOT grant
/// `ChatAuth` is a hard reject — tree admission is a chartered
/// capability, not a device-class side effect.
#[test]
fn mint_cert_enrollment_without_chat_auth_template_rejected() {
    run(|| {
        let (nonce, created_at) = setup_up_to_offer(); // plain template
        let payload = payload_with_verdict(MockVerdict::Tpm {
            ek_hash: [0x42u8; 32],
            pubkey_bytes: test_cert_ec_pubkey(),
        });
        let enrollment = valid_enrollment(&nonce);
        assert_noop!(
            ZkPki::mint_cert(
                RuntimeOrigin::signed(account(USER_ACCOUNT)),
                nonce,
                payload,
                created_at,
                None,
                None, // commitment_c
                None, // ec_key_pub_claimed
                Some(enrollment),
            ),
            zk_pki_pallet::Error::<Runtime>::ChatEnrollmentNotPermittedByTemplate,
        );
    });
}

/// Stamping half of the invariant: a ChatAuth template mint that
/// declines enrollment gets the EKU STRIPPED from the cert record and
/// inserts no leaf — the cert never claims a capability it cannot
/// exercise.
#[test]
fn mint_cert_chat_auth_template_without_enrollment_strips_eku() {
    use zk_pki_primitives::eku::Eku;
    run(|| {
        let (nonce, created_at) = setup_up_to_offer_chat_auth();
        let payload = payload_with_verdict(MockVerdict::Tpm {
            ek_hash: [0x42u8; 32],
            pubkey_bytes: test_cert_ec_pubkey(),
        });
        let empty_root = ZkPki::membership_root();
        assert_ok!(ZkPki::mint_cert(
            RuntimeOrigin::signed(account(USER_ACCOUNT)),
            nonce,
            payload,
            created_at,
            None,
            None, // commitment_c
            None, // ec_key_pub_claimed
            None, // chat_enrollment declined
        ));
        assert_eq!(ZkPki::membership_root(), empty_root, "no leaf inserted");
        let thumb = zk_pki_pallet::CertsByUser::<Runtime>::iter_prefix(account(USER_ACCOUNT))
            .next()
            .map(|(t, _)| t)
            .expect("cert minted");
        let hot = zk_pki_pallet::CertLookupHot::<Runtime>::get(thumb).expect("hot record");
        assert!(
            !hot.ekus.iter().any(|e| *e == Eku::ChatAuth),
            "ChatAuth must be stripped when no enrollment happened",
        );
        let cold = zk_pki_pallet::CertLookupCold::<Runtime>::get(thumb).expect("cold record");
        assert_eq!(cold.leaf_position, None);
    });
}

/// Positive stamping: enrollment under a ChatAuth template stamps the
/// EKU onto the cert record — EKU present ⇔ leaf present.
#[test]
fn mint_cert_with_enrollment_stamps_chat_auth_eku() {
    use zk_pki_primitives::eku::Eku;
    run(|| {
        let (nonce, created_at) = setup_up_to_offer_chat_auth();
        let payload = payload_with_verdict(MockVerdict::Tpm {
            ek_hash: [0x42u8; 32],
            pubkey_bytes: test_cert_ec_pubkey(),
        });
        let enrollment = valid_enrollment(&nonce);
        assert_ok!(ZkPki::mint_cert(
            RuntimeOrigin::signed(account(USER_ACCOUNT)),
            nonce,
            payload,
            created_at,
            None,
            None, // commitment_c
            None, // ec_key_pub_claimed
            Some(enrollment),
        ));
        let thumb = zk_pki_pallet::CertsByUser::<Runtime>::iter_prefix(account(USER_ACCOUNT))
            .next()
            .map(|(t, _)| t)
            .expect("cert minted");
        let hot = zk_pki_pallet::CertLookupHot::<Runtime>::get(thumb).expect("hot record");
        assert!(hot.ekus.iter().any(|e| *e == Eku::ChatAuth), "ChatAuth stamped");
        let cold = zk_pki_pallet::CertLookupCold::<Runtime>::get(thumb).expect("cold record");
        assert_eq!(cold.leaf_position, Some(0), "leaf inserted");
    });
}

// ──────────────────────────────────────────────────────────────────────
// Witness certs (RWA credential): per-issuer keccak tree, edge-suppressed
// ──────────────────────────────────────────────────────────────────────

/// The single witness thumbprint minted in a test, found via the routing map
/// (`CertsByUser` is deliberately not written for witness certs, so the usual
/// user-index lookup can't find it).
fn witness_thumb() -> [u8; 32] {
    zk_pki_pallet::WitnessLeafIssuer::<Runtime>::iter()
        .next()
        .map(|(t, _)| t)
        .expect("a witness cert was minted")
}

#[test]
fn mint_witness_cert_lands_in_issuer_tree_not_global() {
    run(|| {
        let (nonce, created_at) = setup_up_to_offer_witness_auth();
        let payload = payload_with_verdict(MockVerdict::Tpm {
            ek_hash: [0x42u8; 32],
            pubkey_bytes: test_cert_ec_pubkey(),
        });
        let enrollment = valid_enrollment(&nonce);

        let issuer = account(ISSUER_ACCOUNT);
        let global_empty = ZkPki::membership_root();
        let issuer_empty = ZkPki::witness_root(&issuer);

        assert_ok!(ZkPki::mint_witness_cert(
            RuntimeOrigin::signed(account(USER_ACCOUNT)),
            nonce,
            payload,
            created_at,
            None,
            None,
            None,
            enrollment,
        ));

        // The leaf landed in the ISSUER's own witness tree (+ its freshness).
        assert_ne!(ZkPki::witness_root(&issuer), issuer_empty, "issuer witness root advances");
        assert_ne!(
            ZkPki::witness_freshness_root(&issuer),
            issuer_empty,
            "issuer freshness root advances",
        );
        // The global chat tree is untouched.
        assert_eq!(ZkPki::membership_root(), global_empty, "chat global tree untouched");

        // Routing entry recorded; cold record present at leaf 0.
        let thumb = witness_thumb();
        assert_eq!(
            zk_pki_pallet::WitnessLeafIssuer::<Runtime>::get(thumb),
            Some(issuer.clone()),
        );
        let cold = zk_pki_pallet::CertLookupCold::<Runtime>::get(thumb).expect("cold record");
        assert_eq!(cold.leaf_position, Some(0));
    });
}

#[test]
fn mint_witness_cert_writes_no_edge_indexes() {
    run(|| {
        let (nonce, created_at) = setup_up_to_offer_witness_auth();
        let payload = payload_with_verdict(MockVerdict::Tpm {
            ek_hash: [0x42u8; 32],
            pubkey_bytes: test_cert_ec_pubkey(),
        });
        let enrollment = valid_enrollment(&nonce);
        assert_ok!(ZkPki::mint_witness_cert(
            RuntimeOrigin::signed(account(USER_ACCOUNT)),
            nonce,
            payload,
            created_at,
            None,
            None,
            None,
            enrollment,
        ));

        let user = account(USER_ACCOUNT);
        let issuer = account(ISSUER_ACCOUNT);

        // No resolvable issuer<->holder edge in any secondary index.
        assert!(
            zk_pki_pallet::CertsByUser::<Runtime>::iter_prefix(&user).next().is_none(),
            "witness cert must not write CertsByUser",
        );
        assert!(
            zk_pki_pallet::CertsByIssuer::<Runtime>::iter_prefix(&issuer).next().is_none(),
            "witness cert must not write CertsByIssuer",
        );
        assert!(
            !zk_pki_pallet::UserIssuerIndex::<Runtime>::contains_key(
                zk_pki_primitives::keys::UserIssuerKey::new(user.clone(), issuer.clone())
            ),
            "witness cert must not write UserIssuerIndex",
        );
        // No device-key reverse index either (the key is never resolved in the
        // clear for a witness cert).
        let dpk = DevicePublicKey::new_p256(&test_cert_ec_pubkey()).expect("valid P-256 pubkey");
        let key_hash = dpk.lookup_hash().expect("canonicalizes");
        // The root and issuer certs share this test key and legitimately index
        // it; the witness cert must NOT add itself to the reverse index.
        assert!(
            !ZkPki::query_certs_by_device_key(key_hash).contains(&witness_thumb()),
            "witness cert must not write CertByDeviceKey",
        );
    });
}

#[test]
fn mint_witness_cert_requires_witness_auth_template() {
    run(|| {
        // A ChatAuth-chartered offer does NOT carry WitnessAuth.
        let (nonce, created_at) = setup_up_to_offer_chat_auth();
        let payload = payload_with_verdict(MockVerdict::Tpm {
            ek_hash: [0x42u8; 32],
            pubkey_bytes: test_cert_ec_pubkey(),
        });
        let enrollment = valid_enrollment(&nonce);
        assert_noop!(
            ZkPki::mint_witness_cert(
                RuntimeOrigin::signed(account(USER_ACCOUNT)),
                nonce,
                payload,
                created_at,
                None,
                None,
                None,
                enrollment,
            ),
            zk_pki_pallet::Error::<Runtime>::WitnessAuthNotPermittedByTemplate,
        );
    });
}

#[test]
fn witness_cert_revocation_clears_issuer_tree_leaf() {
    run(|| {
        let (nonce, created_at) = setup_up_to_offer_witness_auth();
        let payload = payload_with_verdict(MockVerdict::Tpm {
            ek_hash: [0x42u8; 32],
            pubkey_bytes: test_cert_ec_pubkey(),
        });
        let enrollment = valid_enrollment(&nonce);
        let issuer = account(ISSUER_ACCOUNT);
        let issuer_empty = ZkPki::witness_root(&issuer);

        assert_ok!(ZkPki::mint_witness_cert(
            RuntimeOrigin::signed(account(USER_ACCOUNT)),
            nonce,
            payload,
            created_at,
            None,
            None,
            None,
            enrollment,
        ));
        let thumb = witness_thumb();
        assert_ne!(ZkPki::witness_root(&issuer), issuer_empty);

        // The issuer revokes: the leaf is cleared from the ISSUER's tree, the
        // freshness leaf too, and the routing + cold records are dropped.
        assert_ok!(ZkPki::invalidate_cert(RuntimeOrigin::signed(issuer.clone()), thumb));
        assert_eq!(
            ZkPki::witness_root(&issuer),
            issuer_empty,
            "issuer witness root returns to empty on revocation",
        );
        assert_eq!(ZkPki::witness_freshness_root(&issuer), issuer_empty, "freshness returns to empty");
        assert!(
            zk_pki_pallet::WitnessLeafIssuer::<Runtime>::get(thumb).is_none(),
            "routing entry cleared",
        );
        assert!(
            zk_pki_pallet::CertLookupCold::<Runtime>::get(thumb).is_none(),
            "cold record gone",
        );
    });
}
