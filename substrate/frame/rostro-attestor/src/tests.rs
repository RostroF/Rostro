//! Attestor pallet tests: quorum finalization, and rejection of non-attestor /
//! wrong-root / duplicate / malformed signatures. Signatures are real
//! secp256k1 recoverable sigs so the `sp_io` recover path is exercised.

use crate::mock::*;
use crate::{Error, EthAddress, LatestCheckpoint, PendingSigs, Signature};
use frame_support::{assert_noop, assert_ok, crypto::ecdsa::ECDSAExt};
use sp_core::{ecdsa, Pair};

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
