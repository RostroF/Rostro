//! Benchmarks for `zk-pki-pallet` — one `#[benchmark]` per extrinsic.
//!
//! # ⚠️ Status — scaffolding + placeholder weights
//!
//! These benchmarks compile under `--features runtime-benchmarks`
//! but have not been exercised against a reference-hardware
//! runtime. They are set up to drive each extrinsic through the
//! minimum valid precondition chain (register_root → issue_issuer_cert
//! → create_cert_template → offer_contract → mint_cert) so the
//! `#[extrinsic_call]`-tagged call lands in the canonical Ok path.
//!
//! The generic `T::Attestation` and `T::BindingProofVerifier` slots
//! must be wired to the pallet's test-friendly no-op/mock variants
//! (as `zk-pki-runtime` already does). Running these against a
//! production verifier would fail at attestation time — benchmarks
//! are expected to run against a test-flavoured runtime.
//!
//! `impl_benchmark_test_suite!` is deliberately omitted — the
//! pallet crate has no mock runtime of its own (`zk-pki-runtime`
//! would create a circular dep if referenced here). Benchmark
//! execution happens via the `benchmark pallet` CLI against the
//! full runtime, not via in-crate tests.

#![cfg(feature = "runtime-benchmarks")]

use super::*;
use frame_benchmarking::v2::*;
use frame_support::{pallet_prelude::ConstU32, traits::Currency, BoundedVec};
use frame_system::{pallet_prelude::BlockNumberFor, RawOrigin};
use sp_runtime::SaturatedConversion;
use zk_pki_primitives::{
    bounds::{MAX_ATTESTATION_LEN, MAX_METADATA_LEN, MAX_SUSPENSION_REASON_LEN},
    cert::Thumbprint,
    crypto::DevicePublicKey,
    eku::Eku,
    hip::{CanonicalHipProof, PcrValue, Tpm2Flavor, Tpm2HipProof},
    template::{
        PopMechanism, PopRequirement, MAX_TEMPLATE_EKUS, MAX_TEMPLATE_METADATA_SCHEMA_LEN,
        MAX_TEMPLATE_NAME_LEN,
    },
};
use zk_pki_tpm::AttestationPayloadV3;

// ──────────────────────────────────────────────────────────────────────
// Fixtures
// ──────────────────────────────────────────────────────────────────────

/// Deterministic P-256 uncompressed SEC1 pubkey for benchmark use.
/// Valid curve point so `DevicePublicKey::new_p256` accepts it.
fn bench_cert_ec_pubkey() -> sp_std::vec::Vec<u8> {
    // SEC1 uncompressed encoding of the public key for the ECDSA
    // signing key whose scalar is [0x07; 32] (big-endian). Matches
    // `test_cert_ec_pubkey_bytes()` used across the pallet's test
    // fixtures. Verified on-curve by regenerating via the p256 crate
    // and round-tripping through `DevicePublicKey::new_p256`.
    let mut out = sp_std::vec::Vec::with_capacity(65);
    out.push(0x04);
    // x
    out.extend_from_slice(&[
        0x1E, 0x18, 0x53, 0x2F, 0xD4, 0x75, 0x4C, 0x02,
        0xF3, 0x04, 0x1D, 0x9C, 0x75, 0xCE, 0xB3, 0x3B,
        0x83, 0xFF, 0xD8, 0x1A, 0xC7, 0xCE, 0x4F, 0xE8,
        0x82, 0xCC, 0xB1, 0xC9, 0x8B, 0xC5, 0x89, 0x6E,
    ]);
    // y
    out.extend_from_slice(&[
        0xA4, 0x6C, 0x31, 0x1C, 0x4E, 0x2F, 0xF4, 0x0D,
        0xD9, 0x6A, 0x36, 0x53, 0xE6, 0xE4, 0x54, 0x45,
        0xD3, 0x2D, 0xFE, 0x48, 0x6E, 0xCE, 0xD7, 0x5C,
        0x7A, 0x90, 0xC6, 0xA1, 0x88, 0x81, 0xC0, 0xA3,
    ]);
    out
}

fn bench_pubkey<T: Config>() -> DevicePublicKey {
    DevicePublicKey::new_p256(&bench_cert_ec_pubkey())
        .expect("hand-checked P-256 pubkey should decode")
}

fn empty_att() -> BoundedVec<u8, ConstU32<MAX_ATTESTATION_LEN>> {
    BoundedVec::try_from(sp_std::vec![]).unwrap()
}

fn empty_cap_ekus() -> BoundedVec<Eku, ConstU32<8>> {
    BoundedVec::try_from(sp_std::vec![]).unwrap()
}

fn empty_template_ekus() -> BoundedVec<Eku, ConstU32<MAX_TEMPLATE_EKUS>> {
    BoundedVec::try_from(sp_std::vec![]).unwrap()
}

fn empty_meta() -> BoundedVec<u8, ConstU32<MAX_METADATA_LEN>> {
    BoundedVec::try_from(sp_std::vec![]).unwrap()
}

fn bench_template_name(label: u8) -> BoundedVec<u8, ConstU32<MAX_TEMPLATE_NAME_LEN>> {
    BoundedVec::try_from(sp_std::vec![b'b', b'n', b'c', b'h', label]).unwrap()
}

fn fund<T: Config>(who: &T::AccountId) {
    let big: BalanceOf<T> = (u128::MAX / 2).saturated_into();
    T::Currency::make_free_balance_be(who, big);
}

fn benching_nonce() -> [u8; 32] {
    [0x01u8; 32]
}

fn bench_hip_proof() -> CanonicalHipProof {
    // Minimal-shape proof that satisfies `Decode` / `MaxEncodedLen`.
    // Cryptographic validity isn't exercised here — the verifier
    // path is a generic `T::BindingProofVerifier` slot that the
    // test-friendly runtime configures to a bypass. Field bounds
    // match the declared `ConstU32` caps in primitives/hip.rs.
    let pcrs: BoundedVec<PcrValue, ConstU32<16>> =
        BoundedVec::try_from(sp_std::vec![PcrValue { index: 7, value: [0u8; 32] }]).unwrap();
    // CanonicalHipProof became an enum (Tpm2/StrongBox) before the
    // 5b migration; the platform discriminator moved from a struct
    // field to the variant choice. Wrap a minimal-shape Tpm2HipProof
    // for the benchmark — the verifier path is mocked at the
    // BindingProofVerifier slot, so cryptographic validity isn't
    // exercised here.
    CanonicalHipProof::Tpm2(Tpm2HipProof {
        flavor: Tpm2Flavor::Windows,
        ek_hash: [0u8; 32],
        ek_public: BoundedVec::try_from(bench_cert_ec_pubkey()).unwrap(),
        aik_public: BoundedVec::try_from(bench_cert_ec_pubkey()).unwrap(),
        aik_certify_info: BoundedVec::try_from(sp_std::vec![0u8; 32]).unwrap(),
        aik_certify_signature: BoundedVec::try_from(sp_std::vec![0u8; 64]).unwrap(),
        pcr_values: pcrs,
        pcr_digest: [0u8; 32],
        quote_attest: BoundedVec::try_from(sp_std::vec![0u8; 96]).unwrap(),
        quote_signature: BoundedVec::try_from(sp_std::vec![0u8; 64]).unwrap(),
        nonce: benching_nonce(),
    })
}

fn bench_payload() -> AttestationPayloadV3 {
    // NoopBindingProofVerifier decodes `integrity_blob` as a
    // `MockVerdict`. Supply a Tpm verdict so mint_cert lands on the
    // PoP-eligible happy path under the test-flavoured runtime.
    use codec::Encode;
    use zk_pki_tpm::test_mock_verifier::MockVerdict;
    let verdict = MockVerdict::Tpm {
        ek_hash: [0x42u8; 32],
        pubkey_bytes: bench_cert_ec_pubkey(),
    };
    AttestationPayloadV3 {
        cert_ec_chain: sp_std::vec![sp_std::vec![]],
        attest_ec_chain: sp_std::vec![sp_std::vec![]],
        hmac_binding_output: [0u8; 32],
        binding_signature: sp_std::vec![],
        integrity_blob: verdict.encode(),
        integrity_signature: sp_std::vec![],
    }
}

// ──────────────────────────────────────────────────────────────────────
// Setup chains
// ──────────────────────────────────────────────────────────────────────

fn do_register_root<T: Config>(root: &T::AccountId, proxy: &T::AccountId)
where
    BalanceOf<T>: sp_runtime::traits::SaturatedConversion,
{
    fund::<T>(root);
    fund::<T>(proxy);
    Pallet::<T>::register_root(
        RawOrigin::Signed(root.clone()).into(),
        proxy.clone(),
        bench_pubkey::<T>(),
        empty_att(),
        1_000_000u32.into(),
        empty_cap_ekus(),
    )
    .expect("register_root benchmark setup");
}

fn do_issue_issuer_cert<T: Config>(
    root: &T::AccountId,
    issuer: &T::AccountId,
    proxy: &T::AccountId,
) where
    BalanceOf<T>: sp_runtime::traits::SaturatedConversion,
{
    fund::<T>(issuer);
    fund::<T>(proxy);
    Pallet::<T>::issue_issuer_cert(
        RawOrigin::Signed(root.clone()).into(),
        issuer.clone(),
        proxy.clone(),
        bench_pubkey::<T>(),
        empty_att(),
        500_000u32.into(),
        empty_cap_ekus(),
    )
    .expect("issue_issuer_cert benchmark setup");
}

fn do_create_template<T: Config>(
    issuer: &T::AccountId,
    label: u8,
    pop: PopRequirement,
) where
    BalanceOf<T>: sp_runtime::traits::SaturatedConversion,
{
    let pop_mechanism = match pop {
        PopRequirement::Required => Some(PopMechanism::HipSigned),
        PopRequirement::NotRequired => None,
    };
    Pallet::<T>::create_cert_template(
        RawOrigin::Signed(issuer.clone()).into(),
        bench_template_name(label),
        pop,
        pop_mechanism,
        400_000u64,
        1_000u64,
        None,
        None::<BoundedVec<u8, ConstU32<MAX_TEMPLATE_METADATA_SCHEMA_LEN>>>,
        empty_template_ekus(),
    )
    .expect("create_cert_template benchmark setup");
}

fn do_offer_contract<T: Config>(
    issuer: &T::AccountId,
    user: &T::AccountId,
    label: u8,
) {
    Pallet::<T>::offer_contract(
        RawOrigin::Signed(issuer.clone()).into(),
        user.clone(),
        10_000u32.into(),
        bench_template_name(label),
        empty_meta(),
    )
    .expect("offer_contract benchmark setup");
}

fn do_mint_cert<T: Config>(
    user: &T::AccountId,
    nonce: [u8; 32],
    created_at: BlockNumberFor<T>,
) -> Thumbprint {
    Pallet::<T>::mint_cert(
        RawOrigin::Signed(user.clone()).into(),
        nonce,
        bench_payload(),
        created_at,
        Some(bench_hip_proof()),
        None, // commitment_c
        None, // ec_key_pub_claimed
        None, // chat_enrollment
    )
    .expect("mint_cert benchmark setup");
    // Locate thumbprint via the UserIssuerIndex — one cert per
    // (user, issuer) pair. The benchmark chain always mints a
    // single cert per user per setup so this is deterministic.
    let mut found: Thumbprint = [0u8; 32];
    for (_k, thumb) in UserIssuerIndex::<T>::iter() {
        found = thumb;
        break;
    }
    found
}

/// Full chain root → issuer → template → offer → mint. Returns
/// (root, issuer, user, thumbprint).
fn setup_full_chain<T: Config>(
    label: u8,
    pop: PopRequirement,
) -> (T::AccountId, T::AccountId, T::AccountId, Thumbprint)
where
    BalanceOf<T>: sp_runtime::traits::SaturatedConversion,
{
    let root: T::AccountId = account("root", label as u32, 0);
    let issuer: T::AccountId = account("issuer", label as u32, 0);
    let user: T::AccountId = account("user", label as u32, 0);
    let root_proxy: T::AccountId = account("root_proxy", label as u32, 0);
    let issuer_proxy: T::AccountId = account("issuer_proxy", label as u32, 0);

    do_register_root::<T>(&root, &root_proxy);
    do_issue_issuer_cert::<T>(&root, &issuer, &issuer_proxy);
    do_create_template::<T>(&issuer, label, pop);

    // Resolve the offer nonce + created_at from storage after
    // `offer_contract` runs — mirrors what dotwave does client-side.
    fund::<T>(&user);
    do_offer_contract::<T>(&issuer, &user, label);
    let offer_key =
        zk_pki_primitives::keys::IssuerUserKey::new(issuer.clone(), user.clone());
    let nonce = OfferIndex::<T>::get(&offer_key).expect("offer written");
    let offer = ContractOffers::<T>::get(nonce).expect("offer record present");
    let created_at = offer.created_at;

    let thumbprint = do_mint_cert::<T>(&user, nonce, created_at);
    (root, issuer, user, thumbprint)
}

// ──────────────────────────────────────────────────────────────────────
// Benchmarks
// ──────────────────────────────────────────────────────────────────────

#[benchmarks(where BalanceOf<T>: sp_runtime::traits::SaturatedConversion)]
mod benchmarks {
    use super::*;

    #[benchmark]
    fn register_root() {
        let caller: T::AccountId = whitelisted_caller();
        let proxy: T::AccountId = account("proxy", 0, 0);
        fund::<T>(&caller);
        fund::<T>(&proxy);

        #[extrinsic_call]
        _(
            RawOrigin::Signed(caller.clone()),
            proxy,
            bench_pubkey::<T>(),
            empty_att(),
            1_000_000u32.into(),
            empty_cap_ekus(),
        );

        assert!(Roots::<T>::contains_key(&caller));
    }

    #[benchmark]
    fn issue_issuer_cert() {
        let root: T::AccountId = whitelisted_caller();
        let issuer: T::AccountId = account("issuer", 0, 0);
        let root_proxy: T::AccountId = account("root_proxy", 0, 0);
        let issuer_proxy: T::AccountId = account("issuer_proxy", 0, 0);
        do_register_root::<T>(&root, &root_proxy);
        fund::<T>(&issuer);
        fund::<T>(&issuer_proxy);

        #[extrinsic_call]
        _(
            RawOrigin::Signed(root.clone()),
            issuer.clone(),
            issuer_proxy,
            bench_pubkey::<T>(),
            empty_att(),
            500_000u32.into(),
            empty_cap_ekus(),
        );

        assert!(Issuers::<T>::contains_key(&issuer));
    }

    #[benchmark]
    fn offer_contract() {
        let root: T::AccountId = account("root", 0, 0);
        let issuer: T::AccountId = whitelisted_caller();
        let user: T::AccountId = account("user", 0, 0);
        let root_proxy: T::AccountId = account("root_proxy", 0, 0);
        let issuer_proxy: T::AccountId = account("issuer_proxy", 0, 0);
        do_register_root::<T>(&root, &root_proxy);
        do_issue_issuer_cert::<T>(&root, &issuer, &issuer_proxy);
        do_create_template::<T>(&issuer, 0, PopRequirement::NotRequired);
        fund::<T>(&user);

        #[extrinsic_call]
        _(
            RawOrigin::Signed(issuer.clone()),
            user,
            10_000u32.into(),
            bench_template_name(0),
            empty_meta(),
        );
    }

    #[benchmark]
    fn mint_cert() {
        let root: T::AccountId = account("root", 0, 0);
        let issuer: T::AccountId = account("issuer", 0, 0);
        let user: T::AccountId = whitelisted_caller();
        let root_proxy: T::AccountId = account("root_proxy", 0, 0);
        let issuer_proxy: T::AccountId = account("issuer_proxy", 0, 0);
        do_register_root::<T>(&root, &root_proxy);
        do_issue_issuer_cert::<T>(&root, &issuer, &issuer_proxy);
        do_create_template::<T>(&issuer, 0, PopRequirement::NotRequired);
        fund::<T>(&user);
        do_offer_contract::<T>(&issuer, &user, 0);
        let offer_key =
            zk_pki_primitives::keys::IssuerUserKey::new(issuer.clone(), user.clone());
        let nonce = OfferIndex::<T>::get(&offer_key).unwrap();
        let created_at = ContractOffers::<T>::get(nonce).unwrap().created_at;

        #[extrinsic_call]
        _(
            RawOrigin::Signed(user.clone()),
            nonce,
            bench_payload(),
            created_at,
            None::<CanonicalHipProof>,
            None::<[u8; 32]>, // commitment_c
            None::<[u8; 32]>, // ec_key_pub_claimed
            None, // chat_enrollment
        );
    }

    #[benchmark]
    fn suspend_cert() {
        let (_, issuer, _, thumbprint) =
            setup_full_chain::<T>(1, PopRequirement::NotRequired);
        let reason: Option<BoundedVec<u8, ConstU32<MAX_SUSPENSION_REASON_LEN>>> = None;

        #[extrinsic_call]
        _(RawOrigin::Signed(issuer), thumbprint, reason);
    }

    #[benchmark]
    fn reactivate_cert() {
        let (_, issuer, _, thumbprint) =
            setup_full_chain::<T>(2, PopRequirement::NotRequired);
        Pallet::<T>::suspend_cert(
            RawOrigin::Signed(issuer.clone()).into(),
            thumbprint,
            None,
        )
        .unwrap();

        #[extrinsic_call]
        _(RawOrigin::Signed(issuer), thumbprint);
    }

    #[benchmark]
    fn invalidate_cert() {
        let (_, issuer, _, thumbprint) =
            setup_full_chain::<T>(3, PopRequirement::NotRequired);

        #[extrinsic_call]
        _(RawOrigin::Signed(issuer), thumbprint);
    }

    #[benchmark]
    fn self_discard_cert() {
        let (_, _, user, thumbprint) =
            setup_full_chain::<T>(4, PopRequirement::NotRequired);

        #[extrinsic_call]
        _(RawOrigin::Signed(user), thumbprint, None);
    }

    #[benchmark]
    fn invalidate_issuer() {
        let root: T::AccountId = whitelisted_caller();
        let issuer: T::AccountId = account("issuer", 0, 0);
        let root_proxy: T::AccountId = account("root_proxy", 0, 0);
        let issuer_proxy: T::AccountId = account("issuer_proxy", 0, 0);
        do_register_root::<T>(&root, &root_proxy);
        do_issue_issuer_cert::<T>(&root, &issuer, &issuer_proxy);

        #[extrinsic_call]
        _(RawOrigin::Signed(root), issuer);
    }

    #[benchmark]
    fn flag_root_compromised() {
        let root: T::AccountId = account("root", 0, 0);
        let root_proxy: T::AccountId = account("root_proxy", 0, 0);
        do_register_root::<T>(&root, &root_proxy);

        #[extrinsic_call]
        _(RawOrigin::Root, root);
    }

    #[benchmark]
    fn reissue_cert() {
        let (_, issuer, _, thumbprint) =
            setup_full_chain::<T>(5, PopRequirement::NotRequired);

        #[extrinsic_call]
        _(
            RawOrigin::Signed(issuer),
            thumbprint,
            bench_pubkey::<T>(),
            empty_att(),
            20_000u32.into(),
            empty_meta(),
        );
    }

    #[benchmark]
    fn renew_cert() {
        // Renewal only applies to root/issuer self-renewal, not
        // end-user certs. Set up a root and benchmark its renewal.
        let root: T::AccountId = whitelisted_caller();
        let root_proxy: T::AccountId = account("root_proxy", 0, 0);
        do_register_root::<T>(&root, &root_proxy);
        // successor_signature bounded vec; empty works for bench
        let sig: BoundedVec<u8, ConstU32<MAX_ATTESTATION_LEN>> =
            BoundedVec::try_from(sp_std::vec![]).unwrap();

        #[extrinsic_call]
        _(
            RawOrigin::Signed(root),
            bench_pubkey::<T>(),
            empty_att(),
            // Must meet T::MinRootTtlBlocks (paseo-runtime: 90 days = 1.3M blocks).
            // Use 2M to be safely above the floor across runtimes.
            2_000_000u32.into(),
            sig,
        );
    }

    #[benchmark]
    fn deregister_root() {
        let root: T::AccountId = whitelisted_caller();
        let root_proxy: T::AccountId = account("root_proxy", 0, 0);
        do_register_root::<T>(&root, &root_proxy);

        #[extrinsic_call]
        _(RawOrigin::Signed(root));
    }

    #[benchmark]
    fn cleanup() {
        // Stage the cert in the "orphan cold" reapable state (C2):
        // Hot gone, Cold lingering. This is one of the two remaining
        // reapable conditions post-Fix 2 (C3/C4 removed) and doesn't
        // require advancing time past the 30-day grace period.
        let (_, _, _, thumbprint) =
            setup_full_chain::<T>(6, PopRequirement::NotRequired);
        CertLookupHot::<T>::remove(thumbprint);
        let caller: T::AccountId = whitelisted_caller();
        fund::<T>(&caller);

        #[extrinsic_call]
        _(RawOrigin::Signed(caller), thumbprint, None);
    }

    #[benchmark]
    fn challenge_compromise() {
        // Drive a root into Compromised first — the only state that
        // lets it call challenge_compromise.
        let root: T::AccountId = whitelisted_caller();
        let root_proxy: T::AccountId = account("root_proxy", 0, 0);
        do_register_root::<T>(&root, &root_proxy);
        Pallet::<T>::flag_root_compromised(RawOrigin::Root.into(), root.clone()).unwrap();

        #[extrinsic_call]
        _(RawOrigin::Signed(root));
    }

    #[benchmark]
    fn resolve_challenge() {
        // Same state machine as above but push forward to Challenge.
        let root: T::AccountId = whitelisted_caller();
        let root_proxy: T::AccountId = account("root_proxy", 0, 0);
        do_register_root::<T>(&root, &root_proxy);
        Pallet::<T>::flag_root_compromised(RawOrigin::Root.into(), root.clone()).unwrap();
        Pallet::<T>::challenge_compromise(RawOrigin::Signed(root.clone()).into()).unwrap();

        #[extrinsic_call]
        _(RawOrigin::Root, root, true);
    }

    #[benchmark]
    fn create_cert_template() {
        let root: T::AccountId = account("root", 0, 0);
        let issuer: T::AccountId = whitelisted_caller();
        let root_proxy: T::AccountId = account("root_proxy", 0, 0);
        let issuer_proxy: T::AccountId = account("issuer_proxy", 0, 0);
        do_register_root::<T>(&root, &root_proxy);
        do_issue_issuer_cert::<T>(&root, &issuer, &issuer_proxy);

        #[extrinsic_call]
        _(
            RawOrigin::Signed(issuer.clone()),
            bench_template_name(0),
            PopRequirement::NotRequired,
            None::<PopMechanism>, // pop_mechanism — non-PoP template
            400_000u64,
            1_000u64,
            None,
            None::<BoundedVec<u8, ConstU32<MAX_TEMPLATE_METADATA_SCHEMA_LEN>>>,
            empty_template_ekus(),
        );

        assert!(CertTemplates::<T>::contains_key(&issuer, bench_template_name(0)));
    }

    #[benchmark]
    fn deactivate_cert_template() {
        let root: T::AccountId = account("root", 0, 0);
        let issuer: T::AccountId = whitelisted_caller();
        let root_proxy: T::AccountId = account("root_proxy", 0, 0);
        let issuer_proxy: T::AccountId = account("issuer_proxy", 0, 0);
        do_register_root::<T>(&root, &root_proxy);
        do_issue_issuer_cert::<T>(&root, &issuer, &issuer_proxy);
        do_create_template::<T>(&issuer, 0, PopRequirement::NotRequired);

        #[extrinsic_call]
        _(RawOrigin::Signed(issuer), bench_template_name(0));
    }

    #[benchmark]
    fn discard_cert_template() {
        let root: T::AccountId = account("root", 0, 0);
        let issuer: T::AccountId = whitelisted_caller();
        let root_proxy: T::AccountId = account("root_proxy", 0, 0);
        let issuer_proxy: T::AccountId = account("issuer_proxy", 0, 0);
        do_register_root::<T>(&root, &root_proxy);
        do_issue_issuer_cert::<T>(&root, &issuer, &issuer_proxy);
        do_create_template::<T>(&issuer, 0, PopRequirement::NotRequired);
        Pallet::<T>::deactivate_cert_template(
            RawOrigin::Signed(issuer.clone()).into(),
            bench_template_name(0),
        )
        .unwrap();

        #[extrinsic_call]
        _(RawOrigin::Signed(issuer), bench_template_name(0));
    }

    /// Worst case: VK at the bound (`MAX_MIME_WRAP_VK_BYTES`).
    /// Real mime-wrap VKs are ~19 KB; the bound is 32 KB for slack.
    /// Benchmarking with a max-size payload pins the upper edge of
    /// the bounded-vec decode + storage write cost.
    ///
    /// Caller is signed (PoC trust model — production routes through
    /// governance, but the benchmark uses the same dispatch path).
    #[benchmark]
    fn set_mime_wrap_vk() {
        let caller: T::AccountId = whitelisted_caller();
        let vk = sp_std::vec![0u8; MAX_MIME_WRAP_VK_BYTES as usize];

        #[extrinsic_call]
        _(RawOrigin::Signed(caller), vk);
    }
}
