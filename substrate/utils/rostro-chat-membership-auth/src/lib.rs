//! Guard-side verifier for the dotwave chat anonymous-membership handshake.
//!
//! A phone sends a Groth16 membership proof plus its public inputs and the
//! session public key. The guard:
//!   1. cheaply rejects claims that don't match chain state (unknown root,
//!      wrong epoch, stale anchor, spent nullifier) before doing any pairing;
//!   2. reconstructs the two guard-bound public inputs from its own node id
//!      and the wire session key, so a proof made for another guard or lifted
//!      to another session key fails verification;
//!   3. verifies the proof against the pinned verifying key;
//!   4. spends the per-epoch nullifier and issues a session keyed by the
//!      session public key (the guard never learns the cert).
//!
//! This is the cryptographic core only. The node supplies the [`ChainView`]
//! (via runtime API) and the [`NullifierStore`] / session map, and owns the
//! RPC surface. Keeping this Apache and node-agnostic keeps the GPL node thin
//! and lets the whole verify path be tested with real proofs.
//!
//! See DOTWAVE-CHAT-ANON-MEMBERSHIP-AUTH section 4.4 / Phase 2.

// Re-exported so the node can name the verifying-key type without depending
// on ark-groth16 / ark-bn254 directly.
pub use ark_bn254::Bn254;
pub use ark_groth16::VerifyingKey;

use ark_bn254::Fr;
use rostro_membership_circuit::groth16;
use rostro_poseidon_bn254::{fr_from_canonical_bytes_le, hash_to_field_bn254};
use std::collections::{HashMap, HashSet};

/// Domain tag for the handshake challenge field element. The phone and the
/// guard must derive it identically.
pub const DOMAIN_CHALLENGE: &[u8] = b"rostro-chat-handshake-challenge-v1";
/// Domain tag for the session-key commitment field element.
pub const DOMAIN_SESSION_PK: &[u8] = b"rostro-chat-session-pubkey-v1";

/// What the phone sends with a membership proof.
#[derive(Clone, Debug)]
pub struct HandshakeRequest {
    /// Compressed Groth16 proof bytes.
    pub proof: Vec<u8>,
    /// `R_m` the proof was built against (canonical field-element bytes).
    pub membership_root: [u8; 32],
    /// `R_f` the proof was built against.
    pub freshness_root: [u8; 32],
    /// The per-epoch nullifier N.
    pub nullifier: [u8; 32],
    /// The epoch the proof commits to (nullifier + freshness check).
    pub current_epoch: u64,
    /// The recent block the expiry check anchors to.
    pub anchor_block: u64,
    /// The actual session public key (e.g. an Ed25519 key); the guard binds
    /// the proof to it and later checks per-drop signatures against it.
    pub session_pubkey: Vec<u8>,
}

/// Chain state the guard validates the proof's claims against. The node
/// implements this over the runtime API (recent-root windows, current epoch,
/// the scope constant, and a recent-anchor policy).
pub trait ChainView {
    fn membership_root_recent(&self, root: &[u8; 32]) -> bool;
    fn freshness_root_recent(&self, root: &[u8; 32]) -> bool;
    fn current_epoch(&self) -> u64;
    fn anchor_recent(&self, anchor_block: u64) -> bool;
    fn scope(&self) -> u64;
}

/// Node-local set of spent nullifiers (one session per cert per epoch). A
/// prunable per-epoch structure in the node; this trait is the seam.
pub trait NullifierStore {
    fn is_spent(&self, nullifier: &[u8; 32]) -> bool;
    fn mark_spent(&mut self, nullifier: [u8; 32]);
}

/// Distinguishable rejection reasons (ordered cheap-to-expensive: the pairing
/// runs only after every cheap check passes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeError {
    /// The proof bytes or a public field did not decode.
    Malformed,
    /// `membership_root` is not the current or a recent R_m.
    UnknownMembershipRoot,
    /// `freshness_root` is not the current or a recent R_f.
    UnknownFreshnessRoot,
    /// The proof's epoch does not match the chain's current epoch.
    EpochMismatch,
    /// `anchor_block` is outside the accepted recent-anchor window.
    StaleAnchor,
    /// This nullifier was already spent this epoch.
    NullifierSpent,
    /// The Groth16 proof failed verification (also fires when the proof was
    /// made for a different guard or session key, since those are folded into
    /// the reconstructed public inputs).
    ProofInvalid,
}

/// A session the guard issues on a successful handshake. The guard stores it
/// keyed by `session_pubkey` and admits cheap per-drop signatures against it
/// until `expires_epoch` passes. The cert is never learned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedSession {
    pub session_pubkey: Vec<u8>,
    pub nullifier: [u8; 32],
    /// The session is valid for the epoch it proved freshness in.
    pub expires_epoch: u64,
}

/// The handshake challenge field element: binds the guard's node id, the
/// anchor block, and the session key. A proof made for a different guard id
/// or session key reconstructs to a different challenge and fails to verify.
pub fn derive_challenge(guard_node_id: &[u8], anchor_block: u64, session_pubkey: &[u8]) -> Fr {
    let mut buf = Vec::with_capacity(DOMAIN_CHALLENGE.len() + guard_node_id.len() + 8 + session_pubkey.len());
    buf.extend_from_slice(DOMAIN_CHALLENGE);
    buf.extend_from_slice(guard_node_id);
    buf.extend_from_slice(&anchor_block.to_le_bytes());
    buf.extend_from_slice(session_pubkey);
    hash_to_field_bn254(&buf)
}

/// The session-key commitment field element bound into the proof.
pub fn derive_session_commit(session_pubkey: &[u8]) -> Fr {
    let mut buf = Vec::with_capacity(DOMAIN_SESSION_PK.len() + session_pubkey.len());
    buf.extend_from_slice(DOMAIN_SESSION_PK);
    buf.extend_from_slice(session_pubkey);
    hash_to_field_bn254(&buf)
}

/// Verify a membership handshake and, on success, return the session to store.
///
/// `guard_node_id` is this node's identity; it is folded into the challenge so
/// the proof is non-relayable to other guards.
pub fn verify_handshake(
    vk: &VerifyingKey<Bn254>,
    req: &HandshakeRequest,
    guard_node_id: &[u8],
    chain: &impl ChainView,
    nullifiers: &mut impl NullifierStore,
) -> Result<AcceptedSession, HandshakeError> {
    // 1. Cheap chain checks first — never pair on a claim the chain rejects.
    if !chain.membership_root_recent(&req.membership_root) {
        return Err(HandshakeError::UnknownMembershipRoot);
    }
    if !chain.freshness_root_recent(&req.freshness_root) {
        return Err(HandshakeError::UnknownFreshnessRoot);
    }
    if req.current_epoch != chain.current_epoch() {
        return Err(HandshakeError::EpochMismatch);
    }
    if !chain.anchor_recent(req.anchor_block) {
        return Err(HandshakeError::StaleAnchor);
    }
    if nullifiers.is_spent(&req.nullifier) {
        return Err(HandshakeError::NullifierSpent);
    }

    // 2. Reconstruct the guard-bound public inputs from our own node id and the
    //    wire session key. The phone cannot choose these.
    let challenge = derive_challenge(guard_node_id, req.anchor_block, &req.session_pubkey);
    let session_commit = derive_session_commit(&req.session_pubkey);

    // 3. Assemble the 8 public inputs in the circuit's fixed order.
    let membership_root = fr_from_canonical_bytes_le(&req.membership_root)
        .ok_or(HandshakeError::Malformed)?;
    let freshness_root = fr_from_canonical_bytes_le(&req.freshness_root)
        .ok_or(HandshakeError::Malformed)?;
    let nullifier = fr_from_canonical_bytes_le(&req.nullifier)
        .ok_or(HandshakeError::Malformed)?;
    let public = [
        membership_root,
        freshness_root,
        nullifier,
        Fr::from(req.current_epoch),
        Fr::from(req.anchor_block),
        Fr::from(chain.scope()),
        challenge,
        session_commit,
    ];

    // 4. Verify the proof.
    let proof = groth16::deserialize_proof(&req.proof).ok_or(HandshakeError::Malformed)?;
    if !groth16::verify(vk, &public, &proof) {
        return Err(HandshakeError::ProofInvalid);
    }

    // 5. Spend the nullifier and issue the session.
    nullifiers.mark_spent(req.nullifier);
    Ok(AcceptedSession {
        session_pubkey: req.session_pubkey.clone(),
        nullifier: req.nullifier,
        expires_epoch: req.current_epoch,
    })
}

impl NullifierStore for HashSet<[u8; 32]> {
    fn is_spent(&self, n: &[u8; 32]) -> bool {
        self.contains(n)
    }
    fn mark_spent(&mut self, n: [u8; 32]) {
        self.insert(n);
    }
}

/// Node-local handshake state: live sessions keyed by session public key, plus
/// the spent nullifiers for the current epoch. Since the nullifier is
/// per-epoch (`N = Poseidon(s, epoch)`), the spent set is cleared on epoch
/// rollover, and a session is dropped once its epoch has passed. This is the
/// only state the node has to hold for the anonymous path; the cert is never
/// stored or learned.
#[derive(Default)]
pub struct HandshakeSessions {
    sessions: HashMap<Vec<u8>, AcceptedSession>,
    spent: HashSet<[u8; 32]>,
    epoch: u64,
}

impl HandshakeSessions {
    pub fn new() -> Self {
        Self::default()
    }

    /// Verify a handshake and, on success, record the session keyed by its
    /// session public key. Prunes epoch-stale state first.
    pub fn admit(
        &mut self,
        vk: &VerifyingKey<Bn254>,
        req: &HandshakeRequest,
        guard_node_id: &[u8],
        chain: &impl ChainView,
    ) -> Result<AcceptedSession, HandshakeError> {
        self.roll_to(chain.current_epoch());
        let session = verify_handshake(vk, req, guard_node_id, chain, &mut self.spent)?;
        self.sessions
            .insert(session.session_pubkey.clone(), session.clone());
        Ok(session)
    }

    /// A live session for `session_pubkey` at `current_epoch`, if any. The
    /// per-drop admission path looks sessions up here (then checks the drop's
    /// Ed25519 signature against the key, outside this crate).
    pub fn live(&self, session_pubkey: &[u8], current_epoch: u64) -> Option<&AcceptedSession> {
        self.sessions
            .get(session_pubkey)
            .filter(|s| s.expires_epoch >= current_epoch)
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// On epoch advance, clear the epoch-scoped nullifier set and drop expired
    /// sessions.
    fn roll_to(&mut self, current_epoch: u64) {
        if current_epoch != self.epoch {
            self.spent.clear();
            self.sessions.retain(|_, s| s.expires_epoch >= current_epoch);
            self.epoch = current_epoch;
        }
    }
}

#[cfg(test)]
mod tests;
