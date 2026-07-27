use super::*;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use rostro_membership_circuit::{groth16 as circuit_groth16, MembershipCircuit};
use rostro_sparse_merkle::poseidon::PoseidonHasher;
use rostro_sparse_merkle::{authentication_path, empty_roots, update, MemoryStore, DEPTH};
use rostro_poseidon_bn254::{
    fr_to_bytes_le, hash_leaf, id_commitment, nullifier as poseidon_nullifier,
    PoseidonField as F,
};
use std::collections::HashSet;

const GUARD_ID: &[u8] = b"guard-A";
const EPOCH: u64 = 15;
const ANCHOR: u64 = 4000;
const SCOPE: u64 = 1;

struct MockChain {
    m_root: [u8; 32],
    f_root: [u8; 32],
    epoch: u64,
    anchor_ok: bool,
}
impl ChainView for MockChain {
    fn membership_root_recent(&self, r: &[u8; 32]) -> bool {
        *r == self.m_root
    }
    fn freshness_root_recent(&self, r: &[u8; 32]) -> bool {
        *r == self.f_root
    }
    fn current_epoch(&self) -> u64 {
        self.epoch
    }
    fn anchor_recent(&self, _a: u64) -> bool {
        self.anchor_ok
    }
    fn scope(&self) -> u64 {
        SCOPE
    }
}

#[derive(Default)]
struct Nulls(HashSet<[u8; 32]>);
impl NullifierStore for Nulls {
    fn is_spent(&self, n: &[u8; 32]) -> bool {
        self.0.contains(n)
    }
    fn mark_spent(&mut self, n: [u8; 32]) {
        self.0.insert(n);
    }
}

/// Build a valid proof for `session_pubkey` against `GUARD_ID`, plus the
/// matching request and the roots the chain should accept.
fn build(
    pk: &circuit_groth16::ProvingKey<ark_bn254::Bn254>,
    rng: &mut StdRng,
    session_pubkey: &[u8],
) -> (HandshakeRequest, [u8; 32], [u8; 32]) {
    let p = PoseidonHasher::new();
    let empties = empty_roots(&p);
    let index = 5u64;

    let s = F::from(987_654_321u64);
    let expiry = F::from(5000u64);
    let scope = F::from(SCOPE);
    let idc = id_commitment(&p, s);
    let m_leaf = hash_leaf(&p, idc, expiry, scope);
    let mut m_store = MemoryStore::new();
    let m_root = update(&mut m_store, &p, &empties, index, m_leaf);
    let m_path = authentication_path(&m_store, &empties, index).to_vec();

    let fresh_until = F::from(20u64);
    let mut f_store = MemoryStore::new();
    let f_root = update(&mut f_store, &p, &empties, index, fresh_until);
    let f_path = authentication_path(&f_store, &empties, index).to_vec();

    let n = poseidon_nullifier(&p, s, F::from(EPOCH));
    let challenge = derive_challenge(GUARD_ID, ANCHOR, session_pubkey);
    let session_commit = derive_session_commit(session_pubkey);

    let circuit = MembershipCircuit {
        membership_root: Some(m_root),
        freshness_root: Some(f_root),
        nullifier: Some(n),
        current_epoch: Some(F::from(EPOCH)),
        anchor_block: Some(F::from(ANCHOR)),
        scope: Some(scope),
        challenge: Some(challenge),
        session_pubkey: Some(session_commit),
        s: Some(s),
        expiry_block: Some(expiry),
        fresh_until_epoch: Some(fresh_until),
        index_bits: Some((0..DEPTH).map(|i| (index >> i) & 1 == 1).collect()),
        membership_path: Some(m_path),
        freshness_path: Some(f_path),
    };
    let proof = circuit_groth16::prove(pk, circuit, rng).expect("prove");

    let req = HandshakeRequest {
        proof: circuit_groth16::serialize_proof(&proof),
        membership_root: fr_to_bytes_le(&m_root),
        freshness_root: fr_to_bytes_le(&f_root),
        nullifier: fr_to_bytes_le(&n),
        current_epoch: EPOCH,
        anchor_block: ANCHOR,
        session_pubkey: session_pubkey.to_vec(),
    };
    (req, fr_to_bytes_le(&m_root), fr_to_bytes_le(&f_root))
}

/// One heavy setup/prove, then every accept + reject scenario reuses it.
#[test]
fn handshake_end_to_end() {
    let mut rng = StdRng::seed_from_u64(7);
    let (pk, vk) = circuit_groth16::setup(&mut rng);

    let session_pk = vec![0x11u8; 32];
    let (req, m_root, f_root) = build(&pk, &mut rng, &session_pk);
    let chain = MockChain { m_root, f_root, epoch: EPOCH, anchor_ok: true };

    // Accept: valid proof issues a session keyed by the session pubkey.
    let mut nulls = Nulls::default();
    let session = verify_handshake(&vk, &req, GUARD_ID, &chain, &mut nulls).expect("accepted");
    assert_eq!(session.session_pubkey, session_pk);
    assert_eq!(session.expires_epoch, EPOCH);
    assert_eq!(session.nullifier, req.nullifier);

    // Replay: the nullifier is now spent.
    assert_eq!(
        verify_handshake(&vk, &req, GUARD_ID, &chain, &mut nulls),
        Err(HandshakeError::NullifierSpent),
    );

    // Relay to another guard: the reconstructed challenge differs, proof fails.
    assert_eq!(
        verify_handshake(&vk, &req, b"guard-B", &chain, &mut Nulls::default()),
        Err(HandshakeError::ProofInvalid),
    );

    // Unknown membership root: rejected before any pairing.
    let mut bad = req.clone();
    bad.membership_root = [9u8; 32];
    assert_eq!(
        verify_handshake(&vk, &bad, GUARD_ID, &chain, &mut Nulls::default()),
        Err(HandshakeError::UnknownMembershipRoot),
    );

    // Tampered nullifier (chain sees it unspent, but the proof's public input
    // no longer matches): proof fails.
    let mut tampered = req.clone();
    tampered.nullifier = fr_to_bytes_le(&F::from(424_242u64));
    assert_eq!(
        verify_handshake(&vk, &tampered, GUARD_ID, &chain, &mut Nulls::default()),
        Err(HandshakeError::ProofInvalid),
    );

    // Wrong epoch and stale anchor are cheap rejects.
    let wrong_epoch = MockChain { m_root, f_root, epoch: EPOCH + 1, anchor_ok: true };
    assert_eq!(
        verify_handshake(&vk, &req, GUARD_ID, &wrong_epoch, &mut Nulls::default()),
        Err(HandshakeError::EpochMismatch),
    );
    let stale = MockChain { m_root, f_root, epoch: EPOCH, anchor_ok: false };
    assert_eq!(
        verify_handshake(&vk, &req, GUARD_ID, &stale, &mut Nulls::default()),
        Err(HandshakeError::StaleAnchor),
    );

    // A session key the proof was not built for reconstructs a different
    // session commitment, so the proof fails.
    let mut other_key = req.clone();
    other_key.session_pubkey = vec![0x22u8; 32];
    assert_eq!(
        verify_handshake(&vk, &other_key, GUARD_ID, &chain, &mut Nulls::default()),
        Err(HandshakeError::ProofInvalid),
    );

    // Stateful manager: admit records a session, replay is rejected, and an
    // epoch rollover prunes both the spent set and the expired session.
    let mut mgr = HandshakeSessions::new();
    let issued = mgr.admit(&vk, &req, GUARD_ID, &chain).expect("admit");
    assert_eq!(mgr.session_count(), 1);
    assert_eq!(
        mgr.live(&session_pk, EPOCH).map(|s| s.nullifier),
        Some(issued.nullifier),
    );
    assert_eq!(
        mgr.admit(&vk, &req, GUARD_ID, &chain),
        Err(HandshakeError::NullifierSpent),
    );
    // The session is not live in a later epoch.
    assert!(mgr.live(&session_pk, EPOCH + 1).is_none());
    // Rolling the manager into the next epoch (this admit fails EpochMismatch
    // on the old proof, but prunes first) drops the stale session.
    let next = MockChain { m_root, f_root, epoch: EPOCH + 1, anchor_ok: true };
    assert_eq!(
        mgr.admit(&vk, &req, GUARD_ID, &next),
        Err(HandshakeError::EpochMismatch),
    );
    assert_eq!(mgr.session_count(), 0);
}
