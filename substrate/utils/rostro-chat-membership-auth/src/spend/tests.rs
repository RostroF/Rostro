//! Phase 1 tests: HRW committee determinism + verifier exclusion, threshold
//! `t`-of-`k` record verification (accept + every reject path), and the
//! order-independent reconcilable accumulator.

use super::*;
use ark_bn254::Fr;
use rostro_poseidon_bn254::{fr_to_bytes_le, hash_to_field_bn254, params};
use std::collections::HashMap;

// ───────────────────────────── mock signing ────────────────────────────────

/// A test keyring: each node has a secret only it knows, so a signature is
/// unforgeable by any other node. Models the unforgeability the real node key
/// gives, without pulling a signature crate into Phase 1.
struct Keyring {
    secrets: HashMap<Vec<u8>, [u8; 32]>,
}

impl Keyring {
    fn new(nodes: &[NodeId]) -> Self {
        let mut secrets = HashMap::new();
        for n in nodes {
            let mut seed = b"secret:".to_vec();
            seed.extend_from_slice(n);
            secrets.insert(n.clone(), fr_to_bytes_le(&hash_to_field_bn254(&seed)));
        }
        Self { secrets }
    }

    fn sign(&self, signer: &[u8], msg: &[u8]) -> Vec<u8> {
        let secret = self.secrets.get(signer).expect("unknown signer");
        let mut buf = secret.to_vec();
        buf.extend_from_slice(msg);
        fr_to_bytes_le(&hash_to_field_bn254(&buf)).to_vec()
    }
}

impl SpendSigVerify for Keyring {
    fn verify(&self, signer: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        match self.secrets.get(signer) {
            Some(secret) => {
                let mut buf = secret.to_vec();
                buf.extend_from_slice(msg);
                fr_to_bytes_le(&hash_to_field_bn254(&buf)).as_slice() == sig
            }
            None => false,
        }
    }
}

// ───────────────────────────── helpers ─────────────────────────────────────

fn nodes(n: usize) -> Vec<NodeId> {
    (0..n).map(|i| format!("node-{i}").into_bytes()).collect()
}

fn nf(x: u64) -> [u8; 32] {
    fr_to_bytes_le(&Fr::from(x))
}

/// Build a fully signed record where the first `n_recorders` committee members
/// have counter-signed.
fn build_record(
    kr: &Keyring,
    guard_set: &[NodeId],
    k: usize,
    nullifier: [u8; 32],
    epoch: u64,
    membership_root: [u8; 32],
    verifier: &NodeId,
    n_recorders: usize,
) -> SpendRecord {
    let vpayload = verifier_sig_payload(&nullifier, epoch, &membership_root);
    let verifier_sig = kr.sign(verifier, &vpayload);

    let comm = committee(&nullifier, epoch, guard_set, k, verifier);
    let rpayload = recorder_sig_payload(&nullifier, epoch, &membership_root, verifier);
    let recorders = comm
        .iter()
        .take(n_recorders)
        .map(|r| RecorderSig { recorder: r.clone(), sig: kr.sign(r, &rpayload) })
        .collect();

    SpendRecord { nullifier, epoch, membership_root, verifier: verifier.clone(), verifier_sig, recorders }
}

// ───────────────────────────── committee ───────────────────────────────────

#[test]
fn committee_is_order_independent() {
    let gs = nodes(8);
    let mut shuffled = gs.clone();
    shuffled.reverse();
    let v = &gs[0];
    let a = committee(&nf(7), 42, &gs, 3, v);
    let b = committee(&nf(7), 42, &shuffled, 3, v);
    assert_eq!(a, b, "committee must not depend on guard-set ordering");
    assert_eq!(a.len(), 3);
}

#[test]
fn committee_excludes_verifier_and_subsets_guard_set() {
    let gs = nodes(8);
    for v in &gs {
        let c = committee(&nf(99), 1, &gs, 3, v);
        assert!(!c.iter().any(|n| n == v), "verifier must never be a recorder");
        for n in &c {
            assert!(gs.contains(n), "committee member must be a guard");
        }
        assert_eq!(c.len(), 3);
    }
}

#[test]
fn committee_caps_at_available_nodes() {
    let gs = nodes(3); // 3 guards, exclude verifier -> at most 2 available
    let c = committee(&nf(5), 1, &gs, 4, &gs[0]);
    assert_eq!(c.len(), 2, "k is capped by the non-verifier guard count");
}

#[test]
fn committee_changes_with_nullifier_and_epoch() {
    let gs = nodes(8);
    let v = &gs[0];
    // Different nullifiers (and different epochs) should generally select
    // different committees; assert they are not all identical across a spread.
    let base = committee(&nf(1), 1, &gs, 3, v);
    let diff_n = (2..40).any(|x| committee(&nf(x), 1, &gs, 3, v) != base);
    let diff_e = (2..40).any(|e| committee(&nf(1), e, &gs, 3, v) != base);
    assert!(diff_n, "committee should vary with the nullifier");
    assert!(diff_e, "committee should vary with the epoch");
}

#[test]
fn committee_selection_is_roughly_uniform() {
    // Sanity that HRW is not degenerate: over many nullifiers, each guard lands
    // the top-1 slot a non-trivial fraction of the time. Loose bounds; this only
    // catches a broken (constant) score.
    let gs = nodes(8);
    let v = &gs[0];
    let mut top1: HashMap<NodeId, u32> = HashMap::new();
    let trials = 4_000u64;
    for x in 0..trials {
        let c = committee(&nf(x), 1, &gs, 1, v);
        *top1.entry(c[0].clone()).or_default() += 1;
    }
    // 7 eligible guards, ~571 expected each; require every one in [250, 1100].
    for n in gs.iter().filter(|n| *n != v) {
        let got = *top1.get(n).unwrap_or(&0);
        assert!(got > 250 && got < 1100, "guard {n:?} top1={got} outside band");
    }
}

#[test]
fn committee_frozen_vector() {
    // Regression pin: a fixed input must keep selecting the same committee, so
    // an accidental change to the HRW construction is caught across builds.
    let gs = nodes(8);
    let got = committee(&nf(7), 42, &gs, 3, &gs[0]);
    let got: Vec<String> = got.iter().map(|n| String::from_utf8(n.clone()).unwrap()).collect();
    assert_eq!(got, FROZEN_COMMITTEE, "HRW committee changed for the pinned vector");
}

// Filled from the first test run (see committee_frozen_vector).
const FROZEN_COMMITTEE: [&str; 3] = ["node-4", "node-5", "node-7"];

// A guard-set source that returns a fixed set regardless of epoch.
struct FixedSource(Vec<NodeId>);
impl GuardSetSource for FixedSource {
    fn guard_set(&self, _epoch: u64) -> Vec<NodeId> {
        self.0.clone()
    }
}

#[test]
fn committee_for_matches_pure_committee() {
    // The node path (read a set from a source, then select) must produce exactly
    // the pure committee for that set, across nullifiers and committee sizes.
    let gs = nodes(8);
    let src = FixedSource(gs.clone());
    let v = &gs[0];
    for x in 0..50u64 {
        for k in 1..=4usize {
            assert_eq!(
                committee_for(&src, &nf(x), 7, k, v),
                committee(&nf(x), 7, &gs, k, v),
            );
        }
    }
}

#[test]
fn committee_for_tracks_the_epoch_set() {
    // A source whose set depends on the epoch yields the committee for whichever
    // set applies to the epoch being selected.
    struct PerEpoch;
    impl GuardSetSource for PerEpoch {
        fn guard_set(&self, epoch: u64) -> Vec<NodeId> {
            if epoch == 1 {
                nodes(4)
            } else {
                nodes(8)
            }
        }
    }
    let v = b"node-0".to_vec();
    assert_eq!(
        committee_for(&PerEpoch, &nf(3), 1, 3, &v),
        committee(&nf(3), 1, &nodes(4), 3, &v),
    );
    assert_eq!(
        committee_for(&PerEpoch, &nf(3), 2, 3, &v),
        committee(&nf(3), 2, &nodes(8), 3, &v),
    );
}

// ───────────────────────────── record verify ───────────────────────────────

const K: usize = 3;
const T: usize = 2;

#[test]
fn record_with_threshold_sigs_verifies() {
    let gs = nodes(8);
    let kr = Keyring::new(&gs);
    let rec = build_record(&kr, &gs, K, nf(11), 5, [9u8; 32], &gs[0], T);
    assert_eq!(verify_record(&rec, &gs, K, T, &kr), Ok(T));
}

#[test]
fn record_full_committee_verifies() {
    let gs = nodes(8);
    let kr = Keyring::new(&gs);
    let rec = build_record(&kr, &gs, K, nf(11), 5, [9u8; 32], &gs[0], K);
    assert_eq!(verify_record(&rec, &gs, K, T, &kr), Ok(K));
}

#[test]
fn record_below_threshold_rejected() {
    let gs = nodes(8);
    let kr = Keyring::new(&gs);
    let rec = build_record(&kr, &gs, K, nf(11), 5, [9u8; 32], &gs[0], 1);
    assert_eq!(
        verify_record(&rec, &gs, K, T, &kr),
        Err(SpendRecordError::ThresholdNotMet { have: 1, need: T })
    );
}

#[test]
fn record_bad_verifier_sig_rejected() {
    let gs = nodes(8);
    let kr = Keyring::new(&gs);
    let mut rec = build_record(&kr, &gs, K, nf(11), 5, [9u8; 32], &gs[0], T);
    rec.verifier_sig[0] ^= 0xff;
    assert_eq!(verify_record(&rec, &gs, K, T, &kr), Err(SpendRecordError::BadVerifierSig));
}

#[test]
fn record_verifier_not_guard_rejected() {
    let gs = nodes(8);
    let kr_all = Keyring::new(&[gs.clone(), vec![b"intruder".to_vec()]].concat());
    let intruder = b"intruder".to_vec();
    let rec = build_record(&kr_all, &gs, K, nf(11), 5, [9u8; 32], &intruder, T);
    assert_eq!(verify_record(&rec, &gs, K, T, &kr_all), Err(SpendRecordError::VerifierNotGuard));
}

#[test]
fn record_verifier_as_recorder_rejected() {
    let gs = nodes(8);
    let kr = Keyring::new(&gs);
    let v = &gs[0];
    let mut rec = build_record(&kr, &gs, K, nf(11), 5, [9u8; 32], v, T);
    // Splice the verifier in as a recorder with a syntactically valid sig.
    let rpayload = recorder_sig_payload(&rec.nullifier, rec.epoch, &rec.membership_root, v);
    rec.recorders[0] = RecorderSig { recorder: v.clone(), sig: kr.sign(v, &rpayload) };
    assert_eq!(verify_record(&rec, &gs, K, T, &kr), Err(SpendRecordError::VerifierIsRecorder));
}

#[test]
fn record_recorder_not_in_committee_rejected() {
    let gs = nodes(8);
    let kr = Keyring::new(&gs);
    let v = &gs[0];
    let n = nf(11);
    let epoch = 5;
    let root = [9u8; 32];
    let comm = committee(&n, epoch, &gs, K, v);
    // A guard that is not on this committee.
    let outsider = gs
        .iter()
        .find(|g| *g != v && !comm.contains(g))
        .expect("an out-of-committee guard exists")
        .clone();
    let rpayload = recorder_sig_payload(&n, epoch, &root, v);
    let mut rec = build_record(&kr, &gs, K, n, epoch, root, v, T);
    rec.recorders[0] = RecorderSig { recorder: outsider.clone(), sig: kr.sign(&outsider, &rpayload) };
    assert_eq!(verify_record(&rec, &gs, K, T, &kr), Err(SpendRecordError::RecorderNotInCommittee));
}

#[test]
fn record_duplicate_recorder_rejected() {
    let gs = nodes(8);
    let kr = Keyring::new(&gs);
    let mut rec = build_record(&kr, &gs, K, nf(11), 5, [9u8; 32], &gs[0], T);
    rec.recorders[1] = rec.recorders[0].clone();
    assert_eq!(verify_record(&rec, &gs, K, T, &kr), Err(SpendRecordError::DuplicateRecorder));
}

#[test]
fn record_bad_recorder_sig_rejected() {
    let gs = nodes(8);
    let kr = Keyring::new(&gs);
    let mut rec = build_record(&kr, &gs, K, nf(11), 5, [9u8; 32], &gs[0], T);
    rec.recorders[0].sig[0] ^= 0xff;
    assert_eq!(verify_record(&rec, &gs, K, T, &kr), Err(SpendRecordError::BadRecorderSig));
}

#[test]
fn recorder_self_check_matches_committee() {
    let gs = nodes(8);
    let v = &gs[0];
    let comm = committee(&nf(3), 9, &gs, K, v);
    for g in &gs {
        let on = is_committee_member(g, &nf(3), 9, &gs, K, v);
        assert_eq!(on, comm.contains(g));
    }
}

// ───────────────────────────── accumulator ─────────────────────────────────

#[test]
fn accumulator_root_is_order_independent() {
    let p = params();
    let mut a = SpendAccumulator::new();
    let mut b = SpendAccumulator::new();
    let xs = [nf(3), nf(1), nf(2), nf(9), nf(4)];
    for x in xs {
        a.insert(x).unwrap();
    }
    for x in xs.iter().rev() {
        b.insert(*x).unwrap();
    }
    assert_eq!(a.root(&p), b.root(&p), "same set, different insert order -> same root");
}

#[test]
fn accumulator_root_distinguishes_sets() {
    let p = params();
    let mut a = SpendAccumulator::new();
    let mut b = SpendAccumulator::new();
    for x in [nf(1), nf(2), nf(3)] {
        a.insert(x).unwrap();
    }
    for x in [nf(1), nf(2)] {
        b.insert(x).unwrap();
    }
    assert_ne!(a.root(&p), b.root(&p));
    assert_ne!(a.root(&p), SpendAccumulator::new().root(&p));
}

#[test]
fn accumulator_reconciles_via_difference() {
    let p = params();
    let mut a = SpendAccumulator::new();
    let mut b = SpendAccumulator::new();
    for x in [nf(1), nf(2), nf(3)] {
        a.insert(x).unwrap();
    }
    b.insert(nf(1)).unwrap();
    assert_ne!(a.root(&p), b.root(&p));
    // a tells b what it is missing; b applies it and the roots converge.
    for missing in a.difference(&b) {
        b.insert(missing).unwrap();
    }
    assert_eq!(a.root(&p), b.root(&p));
}

#[test]
fn accumulator_rejects_noncanonical() {
    let mut a = SpendAccumulator::new();
    assert_eq!(a.insert([0xffu8; 32]), Err(AccumulatorError::NonCanonical));
    assert!(a.is_empty());
}

#[test]
fn accumulator_insert_is_idempotent() {
    let mut a = SpendAccumulator::new();
    assert_eq!(a.insert(nf(7)), Ok(true));
    assert_eq!(a.insert(nf(7)), Ok(false));
    assert_eq!(a.len(), 1);
    assert!(a.contains(&nf(7)));
}
