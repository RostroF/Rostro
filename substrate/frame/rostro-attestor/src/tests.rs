//! Attestor pallet tests: quorum finalization, and rejection of non-attestor /
//! wrong-root / duplicate / malformed signatures. Signatures are real
//! secp256k1 recoverable sigs so the `sp_io` recover path is exercised.

use crate::mock::*;
use crate::{
    AttestorRegistry, AuthorityId, Error, EthAddress, LatestCheckpoint, PendingSigs, Signature,
};
use codec::Decode;
use frame_support::{assert_noop, assert_ok, crypto::ecdsa::ECDSAExt, traits::OneSessionHandler};
use sp_core::{
    crypto::ByteArray,
    ecdsa,
    offchain::{
        testing::{TestOffchainExt, TestTransactionPoolExt},
        OffchainDbExt, OffchainWorkerExt, TransactionPoolExt,
    },
    Pair,
};
use sp_keystore::{testing::MemoryKeystore, Keystore, KeystoreExt};

const ROOT: [u8; 32] = [9u8; 32];
const HEIGHT: u64 = 1;

/// A deterministic test attestor: its eth-address + signing pair.
fn attestor(seed: u8) -> (EthAddress, ecdsa::Pair) {
    let pair = ecdsa::Pair::from_seed(&[seed; 32]);
    let addr = pair.public().to_eth_address().expect("valid eth address");
    (addr, pair)
}

/// A real secp256k1 recoverable signature over `(height, root)`, normalized to
/// Ethereum's `v ∈ {27,28}` form (the pallet requires it).
fn sign(pair: &ecdsa::Pair, height: u64, root: [u8; 32]) -> Signature {
    let digest = Attestor::commitment(height, &root);
    let sig = pair.sign_prehashed(&digest);
    let mut bytes = sig.0;
    bytes[64] += 27;
    bytes
}

/// Set up: root committed at HEIGHT, an attestor set, a threshold. Returns the
/// signing pairs.
fn setup(threshold: u32, n_attestors: u8) -> Vec<ecdsa::Pair> {
    set_root(ROOT);
    let mut addrs = Vec::new();
    let mut pairs = Vec::new();
    for s in 1..=n_attestors {
        let (a, p) = attestor(s);
        addrs.push(a);
        pairs.push(p);
    }
    set_attestors(addrs);
    set_threshold(threshold);
    // Finalize block HEIGHT so RecentRoots[HEIGHT] == ROOT; then we're past it.
    run_to_block(HEIGHT + 1);
    pairs
}

#[test]
fn quorum_finalizes_and_serves_checkpoint() {
    new_test_ext().execute_with(|| {
        let pairs = setup(2, 3);
        // First attestation: below threshold, nothing finalized.
        assert_ok!(Attestor::attest(
            RuntimeOrigin::none(),
            HEIGHT,
            ROOT,
            sign(&pairs[0], HEIGHT, ROOT)
        ));
        assert!(LatestCheckpoint::<Test>::get().is_none());
        assert_eq!(PendingSigs::<Test>::get(HEIGHT).len(), 1);

        // Second attestation reaches the quorum (2) and finalizes.
        assert_ok!(Attestor::attest(
            RuntimeOrigin::none(),
            HEIGHT,
            ROOT,
            sign(&pairs[1], HEIGHT, ROOT)
        ));
        let cp = LatestCheckpoint::<Test>::get().expect("finalized");
        assert_eq!(cp.root, ROOT);
        assert_eq!(cp.height, HEIGHT);
        assert_eq!(cp.sigs.len(), 2);
        // Pending set cleared on finalize.
        assert_eq!(PendingSigs::<Test>::get(HEIGHT).len(), 0);
    });
}

#[test]
fn below_threshold_does_not_finalize() {
    new_test_ext().execute_with(|| {
        let pairs = setup(3, 3);
        assert_ok!(Attestor::attest(RuntimeOrigin::none(), HEIGHT, ROOT, sign(&pairs[0], HEIGHT, ROOT)));
        assert_ok!(Attestor::attest(RuntimeOrigin::none(), HEIGHT, ROOT, sign(&pairs[1], HEIGHT, ROOT)));
        assert!(LatestCheckpoint::<Test>::get().is_none());
        assert_eq!(PendingSigs::<Test>::get(HEIGHT).len(), 2);
    });
}

#[test]
fn non_attestor_signature_rejected() {
    new_test_ext().execute_with(|| {
        let _ = setup(1, 2);
        // seed 99 is not in the attestor set.
        let (_, stranger) = attestor(99);
        assert_noop!(
            Attestor::attest(RuntimeOrigin::none(), HEIGHT, ROOT, sign(&stranger, HEIGHT, ROOT)),
            Error::<Test>::NotAnAttestor
        );
    });
}

#[test]
fn wrong_root_rejected() {
    new_test_ext().execute_with(|| {
        let pairs = setup(1, 2);
        let bad_root = [1u8; 32];
        assert_noop!(
            Attestor::attest(RuntimeOrigin::none(), HEIGHT, bad_root, sign(&pairs[0], HEIGHT, bad_root)),
            Error::<Test>::RootMismatch
        );
    });
}

#[test]
fn duplicate_signer_rejected() {
    new_test_ext().execute_with(|| {
        let pairs = setup(3, 3);
        assert_ok!(Attestor::attest(RuntimeOrigin::none(), HEIGHT, ROOT, sign(&pairs[0], HEIGHT, ROOT)));
        assert_noop!(
            Attestor::attest(RuntimeOrigin::none(), HEIGHT, ROOT, sign(&pairs[0], HEIGHT, ROOT)),
            Error::<Test>::DuplicateSigner
        );
    });
}

/// The `ATTESTOR` session key of each validator becomes the pallet's own
/// `AttestorRegistry`: `OneSessionHandler` derives its eth-address and caches it,
/// and the threshold is ⌈2/3⌉ of the set. This is the runtime binding
/// (`type Attestors = Attestor`), exercised without wiring `pallet_session`.
#[test]
fn session_keys_populate_attestor_registry() {
    new_test_ext().execute_with(|| {
        // Build three validators; each attestor(seed) gives its eth-address + pair.
        let (addr1, p1) = attestor(1);
        let (addr2, p2) = attestor(2);
        let (addr3, p3) = attestor(3);
        let key = |p: &ecdsa::Pair| AuthorityId::from_slice(p.public().as_ref()).unwrap();
        let validators: Vec<(u64, AuthorityId)> =
            vec![(1, key(&p1)), (2, key(&p2)), (3, key(&p3))];

        // Feed them through the session handler exactly as pallet_session would.
        let iter = validators.iter().map(|(a, k)| (a, k.clone()));
        <Attestor as OneSessionHandler<u64>>::on_new_session(true, iter.clone(), iter);

        // The registry now reflects the session's validators, in order.
        assert_eq!(<Attestor as AttestorRegistry>::attestors(), vec![addr1, addr2, addr3]);
        // ⌈2·3/3⌉ = 2.
        assert_eq!(<Attestor as AttestorRegistry>::threshold(), 2);
        assert!(<Attestor as AttestorRegistry>::is_attestor(&addr2));
        let (stranger, _) = attestor(99);
        assert!(!<Attestor as AttestorRegistry>::is_attestor(&stranger));

        // A rotation to a smaller set replaces (not appends to) the cache.
        let smaller: Vec<(u64, AuthorityId)> = vec![(1, key(&p1))];
        let it = smaller.iter().map(|(a, k)| (a, k.clone()));
        <Attestor as OneSessionHandler<u64>>::on_new_session(true, it.clone(), it);
        assert_eq!(<Attestor as AttestorRegistry>::attestors(), vec![addr1]);
        // ⌈2·1/3⌉ = 1.
        assert_eq!(<Attestor as AttestorRegistry>::threshold(), 1);
    });
}

/// End-to-end offchain signer: a validator holding an in-set ATTESTOR key signs
/// the height's checkpoint and submits one unsigned `attest`, and that tx is a
/// valid attestation (its signature recovers to the attestor's address and the
/// pallet accepts it). Exercises keystore + create_bare + submit + verify.
#[test]
fn offchain_worker_signs_and_submits() {
    let mut ext = new_test_ext();
    let (offchain, _os) = TestOffchainExt::new();
    let (pool, pool_state) = TestTransactionPoolExt::new();
    let keystore = MemoryKeystore::new();
    // This node owns one ATTESTOR key.
    let core_pub = keystore
        .ecdsa_generate_new(crate::app::ATTESTOR, Some("//attestor-1"))
        .expect("keygen");
    let addr = core_pub.to_eth_address().expect("eth address");

    ext.register_extension(OffchainDbExt::new(offchain.clone()));
    ext.register_extension(OffchainWorkerExt::new(offchain));
    ext.register_extension(TransactionPoolExt::new(pool));
    ext.register_extension(KeystoreExt::new(keystore));

    ext.execute_with(|| {
        // Make our key the session's attestor set. `on_new_session` populates the
        // pallet's own SessionAttestors (what the offchain worker filters on);
        // the mock binds `Attestors = MockAttestors` for `attest` verification, so
        // mirror the set there too (threshold 1 → a single sig finalizes).
        let authid = AuthorityId::from_slice(core_pub.as_ref()).unwrap();
        let validators = vec![(1u64, authid.clone())];
        let it = validators.iter().map(|(a, k)| (a, k.clone()));
        <Attestor as OneSessionHandler<u64>>::on_new_session(true, it.clone(), it);
        assert_eq!(<Attestor as AttestorRegistry>::attestors(), vec![addr]);
        set_attestors(vec![addr]);
        set_threshold(1);

        // Commit ROOT at HEIGHT so RecentRoots[HEIGHT] == ROOT.
        set_root(ROOT);
        run_to_block(HEIGHT + 1);

        // The offchain signer runs for HEIGHT.
        <Attestor as frame_support::traits::Hooks<u64>>::offchain_worker(HEIGHT);

        // Exactly one unsigned `attest` was queued.
        let txs = pool_state.read().transactions.clone();
        assert_eq!(txs.len(), 1);
        let ex = Extrinsic::decode(&mut &txs[0][..]).expect("decode extrinsic");
        match ex.function {
            RuntimeCall::Attestor(crate::Call::attest { height, root, sig }) => {
                assert_eq!(height, HEIGHT);
                assert_eq!(root, ROOT);
                // The submitted signature is a valid attestation for our key.
                assert_ok!(Attestor::attest(RuntimeOrigin::none(), height, root, sig));
                let cp = LatestCheckpoint::<Test>::get().expect("finalized (threshold 1)");
                assert_eq!(cp.root, ROOT);
            }
            other => panic!("unexpected call: {:?}", other),
        }
    });
}

#[test]
fn bad_recovery_id_rejected() {
    new_test_ext().execute_with(|| {
        let pairs = setup(1, 2);
        let mut sig = sign(&pairs[0], HEIGHT, ROOT);
        sig[64] = 0; // not the Ethereum 27/28 form
        assert_noop!(
            Attestor::attest(RuntimeOrigin::none(), HEIGHT, ROOT, sig),
            Error::<Test>::BadRecoveryId
        );
    });
}
