//! Phase 1 tests: HRW committee determinism + verifier exclusion, threshold
//! `t`-of-`k` record verification (accept + every reject path), and the
//! order-independent reconcilable accumulator.

use super::*;
use ark_bn254::Fr;
use codec::{Decode, Encode};
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

// ───────────────────────────── spend store ─────────────────────────────────

fn bare_record(nullifier: [u8; 32], epoch: u64) -> SpendRecord {
    SpendRecord {
        nullifier,
        epoch,
        membership_root: [7u8; 32],
        verifier: b"node-0".to_vec(),
        verifier_sig: vec![1, 2, 3],
        recorders: vec![RecorderSig { recorder: b"node-1".to_vec(), sig: vec![4, 5, 6] }],
    }
}

#[test]
fn spend_store_inserts_dedups_and_roots() {
    let p = params();
    let mut s = SpendStore::new(5);
    assert!(s.is_empty());
    assert_eq!(s.insert(bare_record(nf(1), 5)), Ok(true));
    assert_eq!(s.insert(bare_record(nf(2), 5)), Ok(true));
    // Duplicate nullifier is a no-op.
    assert_eq!(s.insert(bare_record(nf(1), 5)), Ok(false));
    assert_eq!(s.len(), 2);
    assert!(s.contains(&nf(1)));
    assert_eq!(s.get(&nf(2)).map(|r| r.nullifier), Some(nf(2)));
    assert_ne!(s.root(&p), SpendStore::new(5).root(&p));
}

#[test]
fn spend_store_rejects_wrong_epoch_and_noncanonical() {
    let mut s = SpendStore::new(5);
    // A record for another epoch is not merged.
    assert_eq!(s.insert(bare_record(nf(1), 6)), Ok(false));
    assert!(s.is_empty());
    // A non-canonical nullifier is rejected at the boundary.
    assert_eq!(s.insert(bare_record([0xffu8; 32], 5)), Err(AccumulatorError::NonCanonical));
    assert!(s.is_empty());
}

#[test]
fn spend_store_root_is_order_independent() {
    let p = params();
    let mut a = SpendStore::new(9);
    let mut b = SpendStore::new(9);
    for x in [3u64, 1, 2, 9, 4] {
        a.insert(bare_record(nf(x), 9)).unwrap();
    }
    for x in [9u64, 4, 2, 1, 3] {
        b.insert(bare_record(nf(x), 9)).unwrap();
    }
    assert_eq!(a.root(&p), b.root(&p));
}

#[test]
fn spend_store_rollover_clears() {
    let p = params();
    let mut s = SpendStore::new(5);
    s.insert(bare_record(nf(1), 5)).unwrap();
    s.roll_to(6);
    assert_eq!(s.epoch(), 6);
    assert!(s.is_empty());
    assert_eq!(s.root(&p), SpendStore::new(6).root(&p));
    // Now records for epoch 6 are accepted.
    assert_eq!(s.insert(bare_record(nf(1), 6)), Ok(true));
}

#[test]
fn spend_store_root_cached_matches_explicit() {
    let p = params();
    let mut s = SpendStore::new(1);
    for x in 0..5u64 {
        s.insert(bare_record(nf(x), 1)).unwrap();
    }
    assert_eq!(s.root_cached(), s.root(&p));
}

#[test]
fn spend_store_records_for_sync_is_bounded() {
    let mut s = SpendStore::new(1);
    for x in 0..10u64 {
        s.insert(bare_record(nf(x), 1)).unwrap();
    }
    assert_eq!(s.records_for_sync(4).len(), 4);
    assert_eq!(s.records_for_sync(100).len(), 10);
}

// ───────────────────────────── wire codecs ─────────────────────────────────

#[test]
fn spend_record_codec_roundtrips() {
    let gs = nodes(8);
    let kr = Keyring::new(&gs);
    let rec = build_record(&kr, &gs, 3, nf(11), 5, [9u8; 32], &gs[0], 2);
    let bytes = rec.encode();
    let back = SpendRecord::decode(&mut &bytes[..]).expect("decodes");
    assert_eq!(back, rec);
}

#[test]
fn spend_sync_wire_roundtrips() {
    let req = SpendSyncRequest { epoch: 42, root: [0xABu8; 32] };
    assert_eq!(SpendSyncRequest::decode(&mut &req.encode()[..]).unwrap(), req);

    let gs = nodes(8);
    let kr = Keyring::new(&gs);
    let rec = build_record(&kr, &gs, 3, nf(7), 5, [9u8; 32], &gs[0], 2);
    for resp in [
        SpendSyncResponse::Match,
        SpendSyncResponse::Mismatch { records: vec![rec] },
        SpendSyncResponse::EpochSkew { epoch: 99 },
    ] {
        assert_eq!(SpendSyncResponse::decode(&mut &resp.encode()[..]).unwrap(), resp);
    }
}

// ───────────────────────────── witness handshake ───────────────────────────

const W_EPOCH: u64 = 5;
const W_ROOT: [u8; 32] = [9u8; 32];

fn witness_req(kr: &Keyring, verifier: &NodeId, nullifier: [u8; 32]) -> WitnessRequest {
    let payload = verifier_sig_payload(&nullifier, W_EPOCH, &W_ROOT);
    WitnessRequest {
        nullifier,
        epoch: W_EPOCH,
        membership_root: W_ROOT,
        verifier: verifier.clone(),
        verifier_sig: kr.sign(verifier, &payload),
        // Proof fields exercised by the node's recorder, not validate_witness.
        proof: vec![0xAB; 8],
        freshness_root: [3u8; 32],
        anchor_block: 100,
        session_pubkey: vec![0xCD; 32],
    }
}

#[test]
fn recorder_state_tracks_bad_requests() {
    let mut rs = RecorderState::new(5);
    let v = b"node-0".to_vec();
    assert_eq!(rs.bad_request_count(&v), 0);
    assert_eq!(rs.record_bad_request(&v), 1);
    assert_eq!(rs.record_bad_request(&v), 2);
    assert_eq!(rs.bad_request_count(&v), 2);
    // Self-prunes on epoch rollover.
    rs.roll_to(6);
    assert_eq!(rs.bad_request_count(&v), 0);
}

#[test]
fn witness_request_reconstructs_handshake() {
    let gs = nodes(4);
    let kr = Keyring::new(&gs);
    let req = witness_req(&kr, &gs[0], nf(7));
    let hr = req.handshake_request();
    assert_eq!(hr.nullifier, req.nullifier);
    assert_eq!(hr.membership_root, req.membership_root);
    assert_eq!(hr.freshness_root, req.freshness_root);
    assert_eq!(hr.current_epoch, req.epoch);
    assert_eq!(hr.anchor_block, req.anchor_block);
    assert_eq!(hr.session_pubkey, req.session_pubkey);
    assert_eq!(hr.proof, req.proof);
}

#[test]
fn validate_witness_accepts_a_committee_member() {
    let gs = nodes(8);
    let kr = Keyring::new(&gs);
    let v = &gs[0];
    let n = nf(11);
    let req = witness_req(&kr, v, n);
    let recorder = &committee(&n, W_EPOCH, &gs, K, v)[0];
    let rs = RecorderState::new(W_EPOCH);
    assert_eq!(validate_witness(&req, recorder, &gs, K, &kr, &rs), Ok(()));
}

#[test]
fn validate_witness_refuses_repeat_same_epoch() {
    let gs = nodes(8);
    let kr = Keyring::new(&gs);
    let v = &gs[0];
    let n = nf(11);
    let req = witness_req(&kr, v, n);
    let recorder = &committee(&n, W_EPOCH, &gs, K, v)[0];
    let mut rs = RecorderState::new(W_EPOCH);
    rs.mark_witnessed(n);
    assert_eq!(
        validate_witness(&req, recorder, &gs, K, &kr, &rs),
        Err(WitnessRefusal::AlreadyWitnessed)
    );
}

#[test]
fn validate_witness_refuses_non_committee_member() {
    let gs = nodes(8);
    let kr = Keyring::new(&gs);
    let v = &gs[0];
    let n = nf(11);
    let req = witness_req(&kr, v, n);
    let comm = committee(&n, W_EPOCH, &gs, K, v);
    let outsider = gs.iter().find(|g| *g != v && !comm.contains(g)).unwrap();
    let rs = RecorderState::new(W_EPOCH);
    assert_eq!(
        validate_witness(&req, outsider, &gs, K, &kr, &rs),
        Err(WitnessRefusal::NotOnCommittee)
    );
}

#[test]
fn validate_witness_refuses_bad_sig_and_wrong_epoch() {
    let gs = nodes(8);
    let kr = Keyring::new(&gs);
    let v = &gs[0];
    let n = nf(11);
    let recorder = &committee(&n, W_EPOCH, &gs, K, v)[0];

    let mut bad = witness_req(&kr, v, n);
    bad.verifier_sig[0] ^= 0xFF;
    assert_eq!(
        validate_witness(&bad, recorder, &gs, K, &kr, &RecorderState::new(W_EPOCH)),
        Err(WitnessRefusal::BadVerifierSig)
    );

    let good = witness_req(&kr, v, n);
    assert_eq!(
        validate_witness(&good, recorder, &gs, K, &kr, &RecorderState::new(W_EPOCH + 1)),
        Err(WitnessRefusal::EpochMismatch)
    );
}

#[test]
fn validate_witness_refuses_non_guard_verifier() {
    let gs = nodes(8);
    let intruder = b"intruder".to_vec();
    let kr = Keyring::new(&[gs.clone(), vec![intruder.clone()]].concat());
    let n = nf(11);
    let req = witness_req(&kr, &intruder, n);
    // A real committee member for this (nullifier, epoch, intruder-verifier).
    let recorder = &committee(&n, W_EPOCH, &gs, K, &intruder)[0];
    assert_eq!(
        validate_witness(&req, recorder, &gs, K, &kr, &RecorderState::new(W_EPOCH)),
        Err(WitnessRefusal::VerifierNotGuard)
    );
}

#[test]
fn recorder_state_rolls_over() {
    let mut rs = RecorderState::new(5);
    rs.mark_witnessed(nf(1));
    assert!(rs.has_witnessed(&nf(1)));
    rs.roll_to(6);
    assert_eq!(rs.epoch(), 6);
    assert!(!rs.has_witnessed(&nf(1)));
}

// ───────────────────────────── quarantine ──────────────────────────────────

/// Build a record with a chosen verifier and explicit recorder ids (so tests can
/// craft overlaps), all signatures valid under `kr`.
fn rec_with(kr: &Keyring, verifier: &NodeId, nullifier: [u8; 32], recorders: &[&NodeId]) -> SpendRecord {
    let root = [9u8; 32];
    let vpayload = verifier_sig_payload(&nullifier, 5, &root);
    let rpayload = recorder_sig_payload(&nullifier, 5, &root, verifier);
    SpendRecord {
        nullifier,
        epoch: 5,
        membership_root: root,
        verifier: verifier.clone(),
        verifier_sig: kr.sign(verifier, &vpayload),
        recorders: recorders
            .iter()
            .map(|r| RecorderSig { recorder: (*r).clone(), sig: kr.sign(r, &rpayload) })
            .collect(),
    }
}

#[test]
fn quarantine_set_tracks_and_taints() {
    let gs = nodes(6);
    let mut q = QuarantineSet::new(5);
    assert!(q.is_empty());
    assert!(q.quarantine(gs[2].clone()));
    assert!(!q.quarantine(gs[2].clone())); // idempotent
    assert!(q.is_quarantined(&gs[2]));
    assert!(!q.is_quarantined(&gs[3]));

    let kr = Keyring::new(&gs);
    // Two recorders, one (gs[2]) quarantined: only 1 valid sig < t=2, not admitted.
    let one_bad = rec_with(&kr, &gs[0], nf(1), &[&gs[1], &gs[2]]);
    assert!(!q.admits(&one_bad, 2));
    // Three recorders, one quarantined: 2 valid >= t=2, still admitted.
    let three = rec_with(&kr, &gs[0], nf(4), &[&gs[1], &gs[2], &gs[3]]);
    assert!(q.admits(&three, 2));
    // A quarantined verifier is never admitted.
    let bad_v = rec_with(&kr, &gs[2], nf(2), &[&gs[1], &gs[3]]);
    assert!(!q.admits(&bad_v, 2));
    // A clean 2-of-? record is admitted.
    let clean = rec_with(&kr, &gs[0], nf(3), &[&gs[1], &gs[3]]);
    assert!(q.admits(&clean, 2));
}

#[test]
fn quarantine_set_rolls_over() {
    let mut q = QuarantineSet::new(5);
    q.quarantine(b"node-2".to_vec());
    q.roll_to(6);
    assert_eq!(q.epoch(), 6);
    assert!(q.is_empty());
}

#[test]
fn equivocators_finds_the_double_signer() {
    let gs = nodes(8);
    let kr = Keyring::new(&gs);
    // Same nullifier, DIFFERENT verifiers, recorder gs[2] signed for both.
    let a = rec_with(&kr, &gs[0], nf(7), &[&gs[1], &gs[2]]);
    let b = rec_with(&kr, &gs[3], nf(7), &[&gs[2], &gs[4]]);
    assert_eq!(equivocators(&a, &b), vec![gs[2].clone()]);
}

#[test]
fn equivocators_empty_without_a_real_conflict() {
    let gs = nodes(8);
    let kr = Keyring::new(&gs);
    let a = rec_with(&kr, &gs[0], nf(7), &[&gs[1], &gs[2]]);
    // Same verifier -> not equivocation (same signed message).
    let same_v = rec_with(&kr, &gs[0], nf(7), &[&gs[1], &gs[5]]);
    assert!(equivocators(&a, &same_v).is_empty());
    // Different nullifier -> no conflict.
    let diff_n = rec_with(&kr, &gs[3], nf(8), &[&gs[2], &gs[4]]);
    assert!(equivocators(&a, &diff_n).is_empty());
    // Identical record -> no conflict.
    assert!(equivocators(&a, &a).is_empty());
}

#[test]
fn spend_store_detects_conflict() {
    let gs = nodes(8);
    let kr = Keyring::new(&gs);
    let a = rec_with(&kr, &gs[0], nf(7), &[&gs[1], &gs[2]]);
    let b = rec_with(&kr, &gs[3], nf(7), &[&gs[2], &gs[4]]); // same N, different content
    let c = rec_with(&kr, &gs[0], nf(9), &[&gs[1], &gs[2]]); // different N

    let mut s = SpendStore::new(5);
    s.insert(a.clone()).unwrap();
    assert_eq!(s.conflict(&b), Some(a.clone())); // conflict surfaces the stored record
    assert_eq!(s.conflict(&a), None); // identical: no conflict
    assert_eq!(s.conflict(&c), None); // absent nullifier: no conflict
}

#[test]
fn witness_wire_roundtrips() {
    let gs = nodes(8);
    let kr = Keyring::new(&gs);
    let req = witness_req(&kr, &gs[0], nf(7));
    assert_eq!(WitnessRequest::decode(&mut &req.encode()[..]).unwrap(), req);

    for resp in [
        WitnessResponse::Accepted { recorder: gs[1].clone(), recorder_sig: vec![1, 2, 3] },
        WitnessResponse::Refused { reason: WitnessRefusal::AlreadyWitnessed },
        WitnessResponse::Refused { reason: WitnessRefusal::NotOnCommittee },
    ] {
        assert_eq!(WitnessResponse::decode(&mut &resp.encode()[..]).unwrap(), resp);
    }
}
