//! Rostro hardening tests.
//!
//! Each test in this file exercises one of the six hardenings (A-F) added on top of
//! upstream `polkadot-ckb-merkle-mountain-range` v0.8.1. The naming convention is
//! `test_rostro_<letter>_<scenario>`.
//!
//! See `/tmp/security-audit-mmr-lib.md` for the full audit and
//! `/tmp/mmr-lib-vendor-report.md` for the per-hardening writeup.

use super::{MergeNumberHash, NumberHash};
use crate::{
    helper::is_canonical_mmr_size,
    leaf_index_to_mmr_size,
    util::{MemMMR, MemStore},
    Error, MerkleProof,
};

// ---------------------------------------------------------------------------
// Hardening B: empty `leaves` is rejected at the verify / calculate_root entry
// ---------------------------------------------------------------------------

#[test]
fn test_rostro_b_verify_rejects_empty_leaves() {
    // Build a real, valid MMR/root/proof, then call `verify` with an empty leaves vec.
    // Upstream would have run all the way through `calculate_peaks_hashes` and could
    // produce `Ok(true)` if the proof items happened to bag to `root`. We must return
    // `Ok(false)` (verification failed) without even consulting the proof.
    let store = MemStore::default();
    let mut mmr = MemMMR::<_, MergeNumberHash>::new(0, &store);
    let positions: Vec<u64> = (0u32..7)
        .map(|i| mmr.push(NumberHash::from(i)).unwrap())
        .collect();
    let root = mmr.get_root().expect("get root");
    let proof = mmr.gen_proof(vec![positions[3]]).expect("gen proof");
    mmr.commit().expect("commit");

    let result = proof.verify(root, Vec::new()).expect("verify");
    assert!(!result, "empty leaves must verify as false");
}

#[test]
fn test_rostro_b_calculate_root_rejects_empty_leaves() {
    // The lower-level `calculate_root` path also rejects empty leaves with an explicit
    // error, so callers that chose `calculate_root` over `verify` cannot smuggle an
    // empty-leaves proof through.
    let proof: MerkleProof<NumberHash, MergeNumberHash> =
        MerkleProof::new(7, vec![NumberHash::from(0)]);
    let err = proof.calculate_root(Vec::new()).unwrap_err();
    assert_eq!(err, Error::GenProofForInvalidLeaves);
}

// ---------------------------------------------------------------------------
// Hardening C: `mmr_size` is validated to be canonical at the verify entry
// ---------------------------------------------------------------------------

#[test]
fn test_rostro_c_canonical_mmr_size_helper() {
    // Canonical MMR sizes are 0, 1, 3, 4, 7, 8, 10, 11, 15, 16, ...
    // (i.e. exactly the values returned by `leaf_index_to_mmr_size(n)` plus 0).
    for n in 0..16u64 {
        let s = leaf_index_to_mmr_size(n);
        assert!(is_canonical_mmr_size(s), "leaf_index_to_mmr_size({}) = {} should be canonical", n, s);
    }
    assert!(is_canonical_mmr_size(0));

    // Non-canonical sizes that fall between canonical ones must be rejected.
    for s in [2u64, 5, 6, 9, 12, 13, 14] {
        assert!(!is_canonical_mmr_size(s), "{} should NOT be canonical", s);
    }

    // Boundary: `u64::MAX` and other 2^63-leaf-implying sizes must reject.
    // The earlier `>` (vs `>=`) bug let the round-trip wrap-and-equal `u64::MAX`,
    // silently affirming canonicality on a value that overflows downstream math.
    assert!(!is_canonical_mmr_size(u64::MAX), "u64::MAX must NOT be canonical");
}

#[test]
fn test_rostro_c_verify_rejects_non_canonical_mmr_size() {
    // mmr_size = 2 is non-canonical (the canonical sizes around it are 1 and 3).
    // Upstream would have silently normalized this to mmr_size = 1 inside `get_peaks`
    // and continued. We must reject it as `CorruptedProof` before any proof math runs.
    let proof: MerkleProof<NumberHash, MergeNumberHash> =
        MerkleProof::new(2, vec![NumberHash::from(0)]);
    let err = proof
        .calculate_root(vec![(0, NumberHash::from(0))])
        .unwrap_err();
    assert_eq!(err, Error::CorruptedProof);
}

// ---------------------------------------------------------------------------
// Hardening A: Hyperbridge-attack input is rejected by BOTH the line-680 check
// and the new redundant count check
// ---------------------------------------------------------------------------

#[test]
fn test_rostro_a_hyperbridge_attack_input_rejected() {
    // The Hyperbridge attack pattern: claim a leaf at position 1 inside an mmr_size = 1
    // MMR (whose only valid leaf position is 0). Upstream's single line-680
    // `if !leaves.is_empty()` check catches this. With the Rostro count-based check
    // also enabled, both layers fire — the test is that we get `CorruptedProof`.
    //
    // We construct: leaves = [(1, h_attacker)], mmr_size = 1, proof = [forged_root].
    // mmr_size = 1 is canonical so hardening C won't pre-empt this.
    let forged_root = NumberHash::from(0xdeadbeefu32);
    let attacker_leaf_hash = NumberHash::from(0xfeedfaceu32);
    let proof: MerkleProof<NumberHash, MergeNumberHash> =
        MerkleProof::new(1, vec![forged_root.clone()]);

    let result = proof.verify(forged_root.clone(), vec![(1, attacker_leaf_hash)]);
    // Upstream: would Err(CorruptedProof) here only because of line 680.
    // Rostro: same Err(CorruptedProof), but BOTH layers (emptiness + count) catch it,
    // so removing either in a future regression still leaves the other in place.
    assert_eq!(result.unwrap_err(), Error::CorruptedProof);
}

#[test]
fn test_rostro_a_two_leaves_one_past_last_peak() {
    // Build a real 3-leaf MMR (mmr_size = 4, peaks = [2, 3]). Take a real proof for
    // leaf 0, but also pass a forged leaf at position 4 (which has height 0 — i.e. a
    // valid LEAF position in larger MMRs — but is past every peak of mmr_size=4).
    // Upstream catches this via line 680; we test that we still error.
    let store = MemStore::default();
    let mut mmr = MemMMR::<_, MergeNumberHash>::new(0, &store);
    let positions: Vec<u64> = (0u32..3)
        .map(|i| mmr.push(NumberHash::from(i)).unwrap())
        .collect();
    let root = mmr.get_root().expect("get root");
    let proof = mmr.gen_proof(vec![positions[0]]).expect("gen proof");
    mmr.commit().expect("commit");

    // pos = 4 is height 0 (passes the "no internal-node positions" pre-check) but
    // is past every peak of mmr_size = 4 (peaks = [2, 3]). The line-680 emptiness
    // check catches this; the new count check is a redundant second layer.
    let attacker_leaves = vec![
        (positions[0], NumberHash::from(0)),
        (4, NumberHash::from(0xdeadbeefu32)),
    ];
    let err = proof.verify(root, attacker_leaves).unwrap_err();
    assert_eq!(err, Error::CorruptedProof);
}

// ---------------------------------------------------------------------------
// Hardening D: bounds-check the peaks_pos[i] indexer in calculate_root_with_new_leaf
// ---------------------------------------------------------------------------

#[test]
fn test_rostro_d_calculate_root_with_new_leaf_empty_peaks() {
    // The degenerate case: `new_mmr_size = 0` makes `get_peaks(new_mmr_size).is_empty()`.
    // Upstream `peaks_pos[0]` would panic with index-out-of-bounds; we must reject with
    // `CorruptedProof`.
    //
    // To reach the bounded-loop branch we need `next_height > pos_height` for `new_pos`.
    // The simplest such position is `new_pos = 1`: pos_height_in_tree(1) = 0,
    // pos_height_in_tree(2) = 1, so next_height > pos_height — we enter the bounded
    // branch where the panic vector lives.
    let store = MemStore::default();
    let mut mmr = MemMMR::<_, MergeNumberHash>::new(0, &store);
    let _pos0 = mmr.push(NumberHash::from(0)).expect("push");
    let proof = mmr.gen_proof(vec![0]).expect("gen proof");
    mmr.commit().expect("commit");

    let result = proof.calculate_root_with_new_leaf(
        vec![(0, NumberHash::from(0))],
        /* new_pos = */ 1,
        NumberHash::from(99),
        /* new_mmr_size = */ 0, // degenerate: peaks_pos is empty
    );
    assert!(result.is_err(), "expected error for new_mmr_size=0, got {:?}", result);
}

#[test]
fn test_rostro_d_calculate_root_with_new_leaf_pos_past_every_peak() {
    // Stronger version of the bounds-check test: `new_mmr_size` is non-empty but
    // `new_pos` is past every peak position. Pre-Rostro the loop walks `i` off the
    // end of `peaks_pos`. Post-Rostro: Err(CorruptedProof).
    let store = MemStore::default();
    let mut mmr = MemMMR::<_, MergeNumberHash>::new(0, &store);
    let _pos0 = mmr.push(NumberHash::from(0)).expect("push");
    let proof = mmr.gen_proof(vec![0]).expect("gen proof");
    mmr.commit().expect("commit");

    // new_pos = 1 enters the bounded branch (next_height = 1 > 0 = pos_height).
    // new_mmr_size = 1 ⇒ peaks_pos = [0]. new_pos = 1 is past peak 0; the loop walks
    // off the end of peaks_pos pre-Rostro.
    let result = proof.calculate_root_with_new_leaf(
        vec![(0, NumberHash::from(0))],
        1,
        NumberHash::from(99),
        1,
    );
    assert!(result.is_err(), "expected error for new_pos past last peak, got {:?}", result);
}

// ---------------------------------------------------------------------------
// Hardening F: duplicate-position leaves with mismatched hashes are rejected
// ---------------------------------------------------------------------------

#[test]
fn test_rostro_f_duplicate_position_mismatched_hashes_rejected() {
    // Build a real proof for leaf 0. Pass two leaves at position 0: the real one and
    // an attacker-supplied second copy with a different hash. Upstream `dedup_by`
    // silently keeps the first and drops the second; we must error.
    let store = MemStore::default();
    let mut mmr = MemMMR::<_, MergeNumberHash>::new(0, &store);
    let positions: Vec<u64> = (0u32..3)
        .map(|i| mmr.push(NumberHash::from(i)).unwrap())
        .collect();
    let root = mmr.get_root().expect("get root");
    let proof = mmr.gen_proof(vec![positions[0]]).expect("gen proof");
    mmr.commit().expect("commit");

    let leaves = vec![
        (positions[0], NumberHash::from(0)),
        (positions[0], NumberHash::from(0xdeadbeefu32)), // mismatched hash
    ];
    let err = proof.verify(root, leaves).unwrap_err();
    assert_eq!(err, Error::GenProofForInvalidLeaves);
}

#[test]
fn test_rostro_f_duplicate_position_matching_hashes_allowed() {
    // Two entries at the same position with the SAME hash is benign duplicate input
    // (e.g. caller batched the same query twice). We collapse it silently rather than
    // erroring — the contract is "duplicate position with conflicting hash is malformed,
    // duplicate position with agreeing hash is just sloppy input."
    let store = MemStore::default();
    let mut mmr = MemMMR::<_, MergeNumberHash>::new(0, &store);
    let positions: Vec<u64> = (0u32..3)
        .map(|i| mmr.push(NumberHash::from(i)).unwrap())
        .collect();
    let root = mmr.get_root().expect("get root");
    let proof = mmr.gen_proof(vec![positions[0]]).expect("gen proof");
    mmr.commit().expect("commit");

    let leaves = vec![
        (positions[0], NumberHash::from(0)),
        (positions[0], NumberHash::from(0)), // same hash
    ];
    let ok = proof.verify(root, leaves).expect("verify");
    assert!(ok);
}

// ---------------------------------------------------------------------------
// Hardening E: smoke test that valid proofs still verify true
// (the real test for E is "no behavior change on valid input"; we sample a few
//  shapes including a bagged-rhs proof to make sure the explicit-break replacement
//  didn't break anything).
// ---------------------------------------------------------------------------

#[test]
fn test_rostro_e_valid_proof_with_bagged_rhs_still_verifies() {
    // A 5-leaf MMR exercises the rhs-bag code path because peaks = [6, 9, 10] and a
    // proof for leaf 0 doesn't visit peak 9 / 10 — they get bagged into a single rhs
    // proof item. Upstream relied on `else { break }` in the empty-leaves branch to
    // exit the for-loop on this case; we replaced that with a tracked-break pattern
    // that runs the same post-condition checks. Verify that valid proofs still pass.
    let store = MemStore::default();
    let mut mmr = MemMMR::<_, MergeNumberHash>::new(0, &store);
    let positions: Vec<u64> = (0u32..5)
        .map(|i| mmr.push(NumberHash::from(i)).unwrap())
        .collect();
    let root = mmr.get_root().expect("get root");
    let proof = mmr.gen_proof(vec![positions[0]]).expect("gen proof");
    mmr.commit().expect("commit");

    let ok = proof
        .verify(root, vec![(positions[0], NumberHash::from(0))])
        .expect("verify");
    assert!(ok);
}
