use super::*;
use rostro_poseidon_bn254::{hash_leaf, id_commitment};

fn leaf(n: u64) -> Fr {
    // A realistic leaf: hash_leaf(id_commitment(s), expiry, scope).
    let p = params();
    let idc = id_commitment(&p, Fr::from(n));
    hash_leaf(&p, idc, Fr::from(1000u64 + n), Fr::from(7u64))
}

#[test]
fn empty_tree_root_is_empty_root() {
    let t = MembershipTree::new(8);
    let p = params();
    assert_eq!(t.root(), empty_root(&p));
    assert_eq!(t.occupied_nodes(), 0);
}

#[test]
fn insert_changes_root_and_path_verifies() {
    let mut t = MembershipTree::new(8);
    let p = params();
    let empty = t.root();

    let l = leaf(1);
    let idx = t.insert(l).unwrap();
    assert_ne!(t.root(), empty, "root must move on insert");

    // The authentication path recomputes the current root: exactly the
    // inclusion relation the circuit will enforce.
    let path = t.path(idx);
    assert_eq!(root_from_path(&p, l, idx, &path), t.root());

    // A wrong leaf at the same position does not.
    assert_ne!(root_from_path(&p, leaf(999), idx, &path), t.root());
}

#[test]
fn remove_restores_empty_root_and_clears_storage() {
    let mut t = MembershipTree::new(8);
    let p = params();
    let idx = t.insert(leaf(1)).unwrap();
    assert_ne!(t.root(), empty_root(&p));
    assert!(t.occupied_nodes() > 0);

    t.remove(idx);
    assert_eq!(t.root(), empty_root(&p), "removing the only leaf empties the tree");
    assert_eq!(t.occupied_nodes(), 0, "removal clears nodes back to sparse");
}

#[test]
fn removal_matches_fresh_tree_without_that_leaf() {
    // Insert A@0 and B@1, remove A: root must equal a tree that only ever
    // held B at index 1 (same position, otherwise the path differs).
    let mut t = MembershipTree::new(8);
    let a = t.insert(leaf(1)).unwrap();
    let b = t.insert(leaf(2)).unwrap();
    assert_eq!((a, b), (0, 1), "deterministic allocation");
    t.remove(a);

    let p = params();
    let empties = empty_roots(&p);
    let mut reference = MemoryStore::new();
    let ref_root = update(&mut reference, &p, &empties, b, leaf(2));

    assert_eq!(t.root(), ref_root);
}

#[test]
fn free_list_reuses_slots() {
    let mut t = MembershipTree::new(8);
    let i0 = t.insert(leaf(1)).unwrap();
    let i1 = t.insert(leaf(2)).unwrap();
    assert_eq!((i0, i1), (0, 1));
    t.remove(i0);
    // Next insert reuses slot 0 rather than advancing to index 2.
    let i2 = t.insert(leaf(3)).unwrap();
    assert_eq!(i2, 0, "freed slot is reused");
}

#[test]
fn root_history_tracks_recent_and_evicts() {
    let mut t = MembershipTree::new(3);
    let r_empty = t.root();
    t.insert(leaf(1));
    let r1 = t.root();
    t.insert(leaf(2));
    let r2 = t.root();

    assert!(t.history().contains(&r_empty));
    assert!(t.history().contains(&r1));
    assert!(t.history().contains(&r2));
    assert_eq!(t.history().latest(), Some(r2));

    // Overflow the cap-3 ring: the oldest (empty) root drops out.
    t.insert(leaf(3));
    t.insert(leaf(4));
    assert!(!t.history().contains(&r_empty), "oldest root evicted");
    assert!(t.history().contains(&t.root()));
}

#[test]
fn distinct_leaves_distinct_positions_independent_paths() {
    let mut t = MembershipTree::new(8);
    let p = params();
    let mut indices = alloc::vec::Vec::new();
    let leaves: alloc::vec::Vec<Fr> = (0..8).map(leaf).collect();
    for l in &leaves {
        indices.push(t.insert(*l).unwrap());
    }
    // Every inserted leaf still proves against the final root.
    for (l, idx) in leaves.iter().zip(indices.iter()) {
        let path = t.path(*idx);
        assert_eq!(root_from_path(&p, *l, *idx, &path), t.root());
    }
}
