//! Integration tests for the pallet's storage-backed membership tree
//! (Task 3a). These exercise the *pallet* logic that the standalone
//! `rostro-membership-tree` unit tests do not: the storage-backed
//! `NodeStore` (Fr ↔ bytes through runtime storage), the free-list slot
//! allocator, the root-history ring, and the empty-root fallback. The tree
//! math itself is trusted from the crate; here we assert the pallet
//! reproduces a reference `MemoryStore` computation through real storage.

use rostro_sparse_merkle::poseidon::PoseidonHasher;
use rostro_sparse_merkle::{empty_root, empty_roots, update, MemoryStore};
use rostro_poseidon_bn254::{fr_to_bytes_le, hash_leaf, id_commitment, PoseidonField as Fr};
use sp_runtime::BuildStorage;
use zk_pki_runtime::{Runtime, ZkPki};

fn ext() -> sp_io::TestExternalities {
    frame_system::GenesisConfig::<Runtime>::default()
        .build_storage()
        .unwrap()
        .into()
}

/// An arbitrary but realistic leaf value.
fn leaf(n: u64) -> Fr {
    let p = PoseidonHasher::new();
    hash_leaf(&p, id_commitment(&p, Fr::from(n)), Fr::from(1000u64), Fr::from(1u64))
}

#[test]
fn empty_root_before_any_insert() {
    ext().execute_with(|| {
        let p = PoseidonHasher::new();
        let empty = fr_to_bytes_le(&empty_root(&p));
        assert_eq!(ZkPki::membership_root(), empty);
        assert!(ZkPki::membership_root_recent(&empty));
        assert!(!ZkPki::membership_root_recent(&[0u8; 32]));
    });
}

#[test]
fn pallet_tree_matches_reference_and_reuses_slots() {
    ext().execute_with(|| {
        let p = PoseidonHasher::new();
        let empties = empty_roots(&p);

        // Insert two leaves at deterministic indices 0 and 1.
        let (l0, l1) = (leaf(1), leaf(2));
        assert_eq!(ZkPki::membership_insert(l0), Some(0));
        assert_eq!(ZkPki::membership_insert(l1), Some(1));

        // The pallet root (built through storage) matches a fresh reference
        // tree holding the same two leaves at the same indices.
        let mut reference = MemoryStore::new();
        update(&mut reference, &p, &empties, 0, l0);
        let ref_root = update(&mut reference, &p, &empties, 1, l1);
        assert_eq!(ZkPki::membership_root(), fr_to_bytes_le(&ref_root));
        assert!(ZkPki::membership_root_recent(&fr_to_bytes_le(&ref_root)));

        // Remove index 0: root must equal a reference holding only l1 at 1.
        ZkPki::membership_remove(0);
        let mut reference2 = MemoryStore::new();
        let ref_root2 = update(&mut reference2, &p, &empties, 1, l1);
        assert_eq!(ZkPki::membership_root(), fr_to_bytes_le(&ref_root2));

        // The freed slot 0 is reused before the high-water mark advances.
        assert_eq!(ZkPki::membership_insert(leaf(3)), Some(0));

        // A superseded root is still accepted from the recent-root ring.
        assert!(ZkPki::membership_root_recent(&fr_to_bytes_le(&ref_root)));
    });
}

#[test]
fn remove_only_leaf_restores_empty_root() {
    ext().execute_with(|| {
        let p = PoseidonHasher::new();
        let idx = ZkPki::membership_insert(leaf(42)).unwrap();
        assert_ne!(ZkPki::membership_root(), fr_to_bytes_le(&empty_root(&p)));
        ZkPki::membership_remove(idx);
        assert_eq!(ZkPki::membership_root(), fr_to_bytes_le(&empty_root(&p)));
    });
}

#[test]
fn freshness_set_bump_remove_track_root() {
    ext().execute_with(|| {
        let p = PoseidonHasher::new();
        let empty = fr_to_bytes_le(&empty_root(&p));
        assert_eq!(ZkPki::freshness_root(), empty);

        ZkPki::freshness_set(0, 10);
        let r10 = ZkPki::freshness_root();
        assert_ne!(r10, empty);

        // Bump the same index to a later epoch: root changes, old stays recent.
        ZkPki::freshness_set(0, 20);
        assert_ne!(ZkPki::freshness_root(), r10);
        assert!(ZkPki::freshness_root_recent(&r10));

        // Remove clears it back to the empty root.
        ZkPki::freshness_remove(0);
        assert_eq!(ZkPki::freshness_root(), empty);
    });
}

#[test]
fn freshness_leaf_is_the_epoch_value() {
    ext().execute_with(|| {
        let p = PoseidonHasher::new();
        let empties = empty_roots(&p);
        ZkPki::freshness_set(3, 42);
        // The freshness leaf at index 3 is Fr::from(42): the circuit reads it
        // and checks `>= current_epoch` directly, no Poseidon over the value.
        let mut reference = MemoryStore::new();
        let ref_root = update(&mut reference, &p, &empties, 3, Fr::from(42u64));
        assert_eq!(ZkPki::freshness_root(), fr_to_bytes_le(&ref_root));
    });
}

#[test]
fn epoch_advances_with_blocks() {
    ext().execute_with(|| {
        // EPOCH_LENGTH_BLOCKS = 14_400.
        assert_eq!(ZkPki::current_epoch(), 0);
        frame_system::Pallet::<Runtime>::set_block_number(14_400);
        assert_eq!(ZkPki::current_epoch(), 1);
        frame_system::Pallet::<Runtime>::set_block_number(14_400 * 7 + 5);
        assert_eq!(ZkPki::current_epoch(), 7);
        // Initial freshness window is current + FRESHNESS_INITIAL_EPOCHS (7).
        assert_eq!(ZkPki::initial_fresh_until_epoch(), 14);
    });
}
