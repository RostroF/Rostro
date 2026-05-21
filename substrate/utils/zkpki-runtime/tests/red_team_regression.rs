//! Red-team regression tests — locks in the Fix 2 (C3/C4 removal),
//! Fix 4 (30-day grace period), TTL-semantics invariants from
//! the 2026-04-19 red-team pass, and the pre-Paseo deposit-flow +
//! distributed-purge-scheduling fixes.
//!
//! Guarantees pinned here:
//!   - End-user certs are NOT immediately reapable after
//!     `deregister_root` — the holder keeps the full grace window.
//!   - End-user certs are NOT immediately reapable after
//!     `flag_root_compromised` — compromise is a reputation signal,
//!     not a cert-lifecycle event.
//!   - Offer TTL semantics are "N usable blocks including the
//!     creation block" (exclusive upper bound, strict `<` at check).
//!   - `InactivePurgePeriod` is 432_000 blocks (30 days at 6s), not
//!     864_000 (60 days).
//!   - `deregister_root` releases the issuer cert's deposit back to
//!     the ROOT account that paid it at `issue_issuer_cert` time.
//!   - `PurgeIndex` slot overflow distributes to the next available
//!     block within a lookahead window rather than failing with
//!     `PurgeIndexFull`.

use codec::Encode;
use frame_support::{assert_noop, assert_ok, traits::Hooks, BoundedVec};
use sp_core::crypto::AccountId32;
use sp_runtime::BuildStorage;
use zk_pki_pallet::Config;
use zk_pki_primitives::crypto::DevicePublicKey;
use zk_pki_primitives::template::PopRequirement;
use zk_pki_runtime::{Runtime, RuntimeOrigin, ZkPki};
use zk_pki_tpm::test_mock_verifier::MockVerdict;
use zk_pki_tpm::AttestationPayloadV3;

// ──────────────────────────────────────────────────────────────────────
// Harness (mirrors cleanup_and_scheduling.rs)
// ──────────────────────────────────────────────────────────────────────

const ROOT_ACCOUNT: [u8; 32] = [0xA1; 32];
const ISSUER_ACCOUNT: [u8; 32] = [0xB2; 32];
const USER_ACCOUNT: [u8; 32] = [0xC3; 32];
const ROOT_PROXY: [u8; 32] = [0xD4; 32];
const ISSUER_PROXY: [u8; 32] = [0xE5; 32];
const REAPER_ACCOUNT: [u8; 32] = [0xF6; 32];

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
            (account(REAPER_ACCOUNT), INITIAL_BALANCE),
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

fn advance_to(target: u64) {
    let mut n = frame_system::Pallet::<Runtime>::block_number();
    while n < target {
        n += 1;
        set_block(n);
        let _ = <zk_pki_pallet::Pallet<Runtime> as Hooks<u64>>::on_initialize(n);
    }
}

fn template_name() -> BoundedVec<u8, frame_support::traits::ConstU32<64>> {
    BoundedVec::try_from(b"rt-template".to_vec()).unwrap()
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

fn tpm_payload(ek_hash: [u8; 32]) -> AttestationPayloadV3 {
    AttestationPayloadV3 {
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
    }
}

fn mint_tpm_cert(user: [u8; 32], ek_hash: [u8; 32]) -> [u8; 32] {
    let (nonce, created_at) = setup_up_to_offer(user);
    assert_ok!(ZkPki::mint_cert(
        RuntimeOrigin::signed(account(user)),
        nonce,
        tpm_payload(ek_hash),
        created_at,
        None,
        None, // commitment_c
        None, // ec_key_pub_claimed
    ));
    let ui_key = zk_pki_primitives::keys::UserIssuerKey::new(
        account(user),
        account(ISSUER_ACCOUNT),
    );
    zk_pki_pallet::UserIssuerIndex::<Runtime>::get(&ui_key).expect("cert minted")
}

// ──────────────────────────────────────────────────────────────────────
// Fix 2 — C3 (issuer absent) no longer triggers reapability
// ──────────────────────────────────────────────────────────────────────

#[test]
fn end_user_cert_not_reapable_when_issuer_record_absent() {
    run(|| {
        let thumbprint = mint_tpm_cert(USER_ACCOUNT, [0x42u8; 32]);

        // Directly remove the issuer record to simulate the
        // storage state left after `deregister_root` without
        // exercising that extrinsic's (currently-buggy) deposit
        // release path. The C3 removal fix is about what
        // `cleanup()` does with this state, not about how the
        // state came to be.
        zk_pki_pallet::Issuers::<Runtime>::remove(&account(ISSUER_ACCOUNT));
        assert!(
            zk_pki_pallet::Issuers::<Runtime>::get(&account(ISSUER_ACCOUNT)).is_none(),
            "precondition: issuer record is absent",
        );
        assert!(
            zk_pki_pallet::CertLookupHot::<Runtime>::get(thumbprint).is_some(),
            "precondition: end-user cert must still be in Hot storage",
        );

        // Under the red-team Fix 2, absent issuer is NOT a reap
        // trigger. A reaper bot cannot front-run the user's
        // self-discard to redirect the deposit — the cert stays
        // in storage until its natural expiry + grace period, and
        // the holder retains the self-discard path.
        assert_noop!(
            ZkPki::cleanup(
                RuntimeOrigin::signed(account(REAPER_ACCOUNT)),
                thumbprint,
                Some(account(REAPER_ACCOUNT)),
            ),
            zk_pki_pallet::Error::<Runtime>::CertNotReapable,
        );
    });
}

// ──────────────────────────────────────────────────────────────────────
// Fix 2 — C4 (root compromised) no longer triggers reapability
// ──────────────────────────────────────────────────────────────────────

#[test]
fn end_user_cert_not_reapable_immediately_after_root_compromised() {
    run(|| {
        let thumbprint = mint_tpm_cert(USER_ACCOUNT, [0x42u8; 32]);

        // Governance marks the root compromised (advisory contract
        // via OpenGov; test uses Root origin to stand in for that).
        assert_ok!(ZkPki::flag_root_compromised(
            RuntimeOrigin::root(),
            account(ROOT_ACCOUNT),
        ));

        // Cert still present, not expired, issuer record still
        // there. Under the red-team Fix 2, root compromise is a
        // reputation signal for relying parties — it does not
        // change cert-lifecycle reapability.
        assert!(
            zk_pki_pallet::CertLookupHot::<Runtime>::get(thumbprint).is_some(),
            "precondition: cert must still be in Hot storage",
        );
        assert_noop!(
            ZkPki::cleanup(
                RuntimeOrigin::signed(account(REAPER_ACCOUNT)),
                thumbprint,
                Some(account(REAPER_ACCOUNT)),
            ),
            zk_pki_pallet::Error::<Runtime>::CertNotReapable,
        );
    });
}

// ──────────────────────────────────────────────────────────────────────
// Fix 3 (no-op) — TTL semantics: exclusive upper bound
// ──────────────────────────────────────────────────────────────────────

#[test]
fn offer_ttl_mint_succeeds_at_last_valid_block() {
    run(|| {
        let (nonce, created_at) = setup_up_to_offer(USER_ACCOUNT);
        let offer = zk_pki_pallet::ContractOffers::<Runtime>::get(nonce)
            .expect("offer written by setup");
        let expiry = offer.expiry_block;

        // Last valid block is `expiry - 1` — the check uses strict
        // `<`. TTL=N delivers N usable blocks including creation
        // block (the Substrate exclusive-upper-bound convention).
        set_block(expiry - 1);
        assert_ok!(ZkPki::mint_cert(
            RuntimeOrigin::signed(account(USER_ACCOUNT)),
            nonce,
            tpm_payload([0x42u8; 32]),
            created_at,
            None,
            None, // commitment_c
            None, // ec_key_pub_claimed
        ));
    });
}

#[test]
fn offer_ttl_mint_rejected_at_expiry_block() {
    run(|| {
        let (nonce, created_at) = setup_up_to_offer(USER_ACCOUNT);
        let offer = zk_pki_pallet::ContractOffers::<Runtime>::get(nonce)
            .expect("offer written by setup");
        let expiry = offer.expiry_block;

        // At exactly `expiry_block` the offer is no longer valid —
        // strict `<` comparison.
        set_block(expiry);
        assert_noop!(
            ZkPki::mint_cert(
                RuntimeOrigin::signed(account(USER_ACCOUNT)),
                nonce,
                tpm_payload([0x42u8; 32]),
                created_at,
                None,
                None, // commitment_c
                None, // ec_key_pub_claimed
            ),
            zk_pki_pallet::Error::<Runtime>::ContractExpired,
        );
    });
}

// ──────────────────────────────────────────────────────────────────────
// Fix 4 — grace period is 30 days (432_000), not 60 (864_000)
// ──────────────────────────────────────────────────────────────────────

#[test]
fn grace_period_is_30_days_not_60() {
    // `InactivePurgePeriod` is a pallet Config constant. The red-team
    // remediation halved it from 864_000 to 432_000 blocks (60 → 30
    // days at 6s blocks) and relabeled "purge window" as "grace
    // period" throughout the codebase. Pin the numeric value.
    assert_eq!(
        <Runtime as Config>::InactivePurgePeriod::get(),
        432_000,
        "InactivePurgePeriod must be 30 days (432_000 blocks at 6s)",
    );
}

// ──────────────────────────────────────────────────────────────────────
// Pre-Paseo Fix 1 — deregister_root releases issuer-cert deposit to root
// ──────────────────────────────────────────────────────────────────────

#[test]
fn deregister_root_releases_issuer_deposit_correctly() {
    run(|| {
        // Pre-state: zero reserves on both accounts.
        let root_reserved_before =
            pallet_balances::Pallet::<Runtime>::reserved_balance(&account(ROOT_ACCOUNT));
        let issuer_reserved_before =
            pallet_balances::Pallet::<Runtime>::reserved_balance(&account(ISSUER_ACCOUNT));
        assert_eq!(root_reserved_before, 0);
        assert_eq!(issuer_reserved_before, 0);

        // Register root + issue issuer cert. Both deposits are held
        // on the ROOT account (the issuer hasn't signed anything at
        // `issue_issuer_cert` time — only the root has).
        let root_pubkey =
            DevicePublicKey::new_p256(&test_cert_ec_pubkey()).expect("valid P-256 pubkey");
        let empty_att: BoundedVec<_, _> = BoundedVec::try_from(vec![]).unwrap();
        let empty_cap_ekus:
            BoundedVec<zk_pki_primitives::eku::Eku, frame_support::traits::ConstU32<8>> =
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

        // Confirm exactly 2 × CertDeposit reserved on the root; the
        // issuer account has nothing held.
        let cert_deposit = <Runtime as Config>::CertDeposit::get();
        let root_reserved_mid =
            pallet_balances::Pallet::<Runtime>::reserved_balance(&account(ROOT_ACCOUNT));
        let issuer_reserved_mid =
            pallet_balances::Pallet::<Runtime>::reserved_balance(&account(ISSUER_ACCOUNT));
        assert_eq!(
            root_reserved_mid,
            2 * cert_deposit,
            "root should hold exactly 2 CertDeposits: its own + the issuer cert",
        );
        assert_eq!(
            issuer_reserved_mid, 0,
            "issuer pays nothing at issue_issuer_cert — they haven't signed",
        );

        // Deregister: clean voluntary exit. Must release BOTH
        // deposits back to the root.
        assert_ok!(ZkPki::deregister_root(
            RuntimeOrigin::signed(account(ROOT_ACCOUNT)),
        ));

        let root_reserved_after =
            pallet_balances::Pallet::<Runtime>::reserved_balance(&account(ROOT_ACCOUNT));
        let issuer_reserved_after =
            pallet_balances::Pallet::<Runtime>::reserved_balance(&account(ISSUER_ACCOUNT));
        assert_eq!(
            root_reserved_after, 0,
            "both root cert deposit AND issuer cert deposit must be released back to root",
        );
        assert_eq!(
            issuer_reserved_after, 0,
            "issuer had nothing held; still has nothing held",
        );

        // Storage side-effects: issuer + root records gone.
        assert!(
            zk_pki_pallet::Roots::<Runtime>::get(&account(ROOT_ACCOUNT)).is_none(),
            "root record removed on deregister",
        );
        assert!(
            zk_pki_pallet::Issuers::<Runtime>::get(&account(ISSUER_ACCOUNT)).is_none(),
            "issuer record removed by deregister cascade",
        );
    });
}

// ──────────────────────────────────────────────────────────────────────
// Pre-Paseo Fix 2 — PurgeIndex overflow distributes to next block
// ──────────────────────────────────────────────────────────────────────

/// Saturate a single `ExpiryIndex` slot by directly writing 256
/// dummy thumbprints into it. Returns the dummy thumbprint seed so
/// tests can distinguish real entries from fillers if needed.
fn fill_expiry_slot_to_cap(block: u64) {
    use frame_support::BoundedVec as BV;
    let dummies: BV<_, frame_support::traits::ConstU32<256>> = BV::try_from(
        (0u16..256).map(|i| {
            let mut t = [0u8; 32];
            t[..2].copy_from_slice(&i.to_le_bytes());
            t[2] = 0xff; // prefix marker so dummies are obvious in debug dumps
            t
        }).collect::<Vec<[u8; 32]>>(),
    ).expect("exactly 256 fits the ConstU32<256> cap");
    zk_pki_pallet::ExpiryIndex::<Runtime>::insert(block, dummies);
}

#[test]
fn purge_index_overflow_distributes_to_next_block() {
    run(|| {
        // Setup up to mint — cert's expiry_block = now + ttl_blocks
        // = 1 + 10_000 = 10_001 (test ext doesn't auto-advance
        // blocks between extrinsics; ttl_blocks=10_000 is hardcoded
        // in setup_up_to_offer).
        let (nonce, created_at) = setup_up_to_offer(USER_ACCOUNT);
        let now = frame_system::Pallet::<Runtime>::block_number();
        let intended_expiry: u64 = now + 10_000;

        // Pre-fill the intended expiry slot to the 256-entry cap.
        fill_expiry_slot_to_cap(intended_expiry);
        assert_eq!(
            zk_pki_pallet::ExpiryIndex::<Runtime>::get(intended_expiry).len(),
            256,
            "precondition: slot is saturated",
        );
        assert_eq!(
            zk_pki_pallet::ExpiryIndex::<Runtime>::get(intended_expiry + 1).len(),
            0,
            "precondition: next slot is empty",
        );

        // Mint the cert — push_to_expiry_index should redirect to
        // intended_expiry + 1 rather than failing with
        // PurgeIndexFull (pre-fix behaviour).
        assert_ok!(ZkPki::mint_cert(
            RuntimeOrigin::signed(account(USER_ACCOUNT)),
            nonce,
            tpm_payload([0x42u8; 32]),
            created_at,
            None,
            None, // commitment_c
            None, // ec_key_pub_claimed
        ));

        // Resolve the newly minted thumbprint via the user index.
        let ui_key = zk_pki_primitives::keys::UserIssuerKey::new(
            account(USER_ACCOUNT),
            account(ISSUER_ACCOUNT),
        );
        let new_thumbprint = zk_pki_pallet::UserIssuerIndex::<Runtime>::get(&ui_key)
            .expect("cert minted");

        // The intended slot is unchanged (still 256 dummies).
        assert_eq!(
            zk_pki_pallet::ExpiryIndex::<Runtime>::get(intended_expiry).len(),
            256,
            "full slot should not grow — cert redirected away from it",
        );
        assert!(
            !zk_pki_pallet::ExpiryIndex::<Runtime>::get(intended_expiry)
                .contains(&new_thumbprint),
            "new thumbprint must NOT be in the full slot",
        );

        // The next slot holds the new thumbprint.
        assert!(
            zk_pki_pallet::ExpiryIndex::<Runtime>::get(intended_expiry + 1)
                .contains(&new_thumbprint),
            "new thumbprint must land in the next available slot",
        );
    });
}

#[test]
fn purge_index_all_lookahead_slots_full_emits_skipped_event() {
    run(|| {
        let (nonce, created_at) = setup_up_to_offer(USER_ACCOUNT);
        let now = frame_system::Pallet::<Runtime>::block_number();
        let intended_expiry: u64 = now + 10_000;

        // Saturate ALL lookahead slots (intended_expiry ..
        // intended_expiry + MAX_PURGE_LOOKAHEAD).
        let lookahead: u64 = zk_pki_pallet::MAX_PURGE_LOOKAHEAD.into();
        for k in 0..lookahead {
            fill_expiry_slot_to_cap(intended_expiry + k);
        }

        // Reset event history so we only see this mint's events.
        frame_system::Pallet::<Runtime>::reset_events();

        // Mint should still succeed — no auto-schedule, but the
        // cert is in storage and recoverable via self_discard /
        // cleanup.
        assert_ok!(ZkPki::mint_cert(
            RuntimeOrigin::signed(account(USER_ACCOUNT)),
            nonce,
            tpm_payload([0x42u8; 32]),
            created_at,
            None,
            None, // commitment_c
            None, // ec_key_pub_claimed
        ));

        let ui_key = zk_pki_primitives::keys::UserIssuerKey::new(
            account(USER_ACCOUNT),
            account(ISSUER_ACCOUNT),
        );
        let new_thumbprint = zk_pki_pallet::UserIssuerIndex::<Runtime>::get(&ui_key)
            .expect("cert minted even when schedule overflow");
        assert!(
            zk_pki_pallet::CertLookupHot::<Runtime>::get(new_thumbprint).is_some(),
            "cert record lands in Hot storage regardless of schedule overflow",
        );

        // Every lookahead slot is unchanged.
        for k in 0..lookahead {
            assert_eq!(
                zk_pki_pallet::ExpiryIndex::<Runtime>::get(intended_expiry + k).len(),
                256,
            );
            assert!(
                !zk_pki_pallet::ExpiryIndex::<Runtime>::get(intended_expiry + k)
                    .contains(&new_thumbprint),
            );
        }

        // PurgeScheduleSkipped event fired for the intended block.
        let skipped = frame_system::Pallet::<Runtime>::events()
            .into_iter()
            .filter_map(|ev| match ev.event {
                zk_pki_runtime::RuntimeEvent::ZkPki(
                    zk_pki_pallet::Event::PurgeScheduleSkipped { intended_block, kind },
                ) => Some((intended_block, kind)),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(skipped.len(), 1, "expected exactly one PurgeScheduleSkipped event");
        assert_eq!(skipped[0].0, intended_expiry);
        assert_eq!(skipped[0].1, zk_pki_pallet::PurgeScheduleKind::Expiry);
    });
}

#[test]
fn cleanup_reaps_at_expiry_plus_grace_period() {
    run(|| {
        let thumbprint = mint_tpm_cert(USER_ACCOUNT, [0x42u8; 32]);
        let expiry = zk_pki_pallet::CertLookupHot::<Runtime>::get(thumbprint)
            .unwrap()
            .expiry_block;

        // Step to expiry — on_initialize flips state to Suspended.
        advance_to(expiry);
        let hot = zk_pki_pallet::CertLookupHot::<Runtime>::get(thumbprint)
            .expect("cert remains in Hot after the expiry state-flip");
        assert!(!hot.is_active(), "expiry flips state to Suspended");

        // One block before grace ends — cleanup must reject.
        // `parameter_types!` here declared `BlockNumber = u32`;
        // widen to `u64` for arithmetic with `expiry` which lives
        // in `BlockNumberFor<Runtime> = u64`.
        let grace: u64 = <Runtime as Config>::InactivePurgePeriod::get().into();
        set_block(expiry + grace - 1);
        assert_noop!(
            ZkPki::cleanup(
                RuntimeOrigin::signed(account(REAPER_ACCOUNT)),
                thumbprint,
                None,
            ),
            zk_pki_pallet::Error::<Runtime>::CertNotReapable,
        );

        // At exactly expiry + grace — cleanup succeeds (C1).
        set_block(expiry + grace);
        assert_ok!(ZkPki::cleanup(
            RuntimeOrigin::signed(account(REAPER_ACCOUNT)),
            thumbprint,
            None,
        ));
        assert!(
            zk_pki_pallet::CertLookupHot::<Runtime>::get(thumbprint).is_none(),
            "cert must be removed after successful cleanup",
        );
    });
}
