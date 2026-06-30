//! Witnessed nullifier spend: committee selection, signed spend records, and
//! the per-epoch reconcilable accumulator.
//!
//! This is the pure, node-agnostic core of the `chat-spend-witness` workstream
//! (see docs/CHAT-SPEND-WITNESS.md). It closes the round-robin bypass on the
//! anonymous membership handshake: instead of a guard recording a spend only in
//! its own RAM (which a member can sidestep by hitting each guard once), the
//! spend is witnessed by a committee the verifier cannot choose, co-signed, and
//! gossiped.
//!
//! Phase 1 is everything that needs no networking and no node key:
//!   * [`committee`] — deterministic HRW committee selection over the on-chain
//!     guard set, excluding the verifier;
//!   * [`SpendRecord`] + [`verify_record`] — the two-sided signed record and its
//!     threshold (`t`-of-`k`) verification;
//!   * [`SpendAccumulator`] — the per-epoch spent set with an order-independent
//!     root so committee members can reconcile.
//!
//! Signing stays in the node binary (capability locality): this crate only
//! builds the canonical signing payloads and verifies signatures through the
//! [`SpendSigVerify`] seam. The node implements that seam over its real node
//! key; tests implement it over a mock keyring.

use ark_bn254::Fr;
use codec::{Decode, Encode};
use rostro_poseidon_bn254::{
    fr_from_canonical_bytes_le, fr_to_bytes_le, hash_node, hash_to_field_bn254, PoseidonConfig,
};
use std::collections::{BTreeMap, BTreeSet, HashSet};

/// Opaque node identity (e.g. a libp2p peer id's bytes). Matches the
/// `guard_node_id: &[u8]` the handshake verifier already threads through.
pub type NodeId = Vec<u8>;

/// Domain-separation tag for the HRW committee score.
pub const HRW_DST: &[u8] = b"rostro-chat-spend-hrw-v1";
/// Domain tag for the verifier signature payload.
pub const DOMAIN_SPEND_VERIFIER: &[u8] = b"rostro-chat-spend-verifier-v1";
/// Domain tag for the recorder signature payload.
pub const DOMAIN_SPEND_RECORDER: &[u8] = b"rostro-chat-spend-recorder-v1";
/// Accumulator fold seed, distinct from every Poseidon role domain so a spend
/// accumulator root can never be reinterpreted as a leaf/node/nullifier.
pub const SPEND_ACC_DOMAIN: u64 = 0x5350_4e44; // "SPND"

// ───────────────────────────── signature seam ──────────────────────────────

/// Verifies a signature by `signer` over `msg`. The node implements this over
/// its node key; the crate stays free of a concrete signature dependency, and
/// the private-key half lives only in the binary that owns the capability.
pub trait SpendSigVerify {
    fn verify(&self, signer: &[u8], msg: &[u8], sig: &[u8]) -> bool;
}

/// Canonical bytes the verifier signs: "I verified a valid membership proof
/// producing nullifier `n` at epoch `e` under membership root `r`".
pub fn verifier_sig_payload(nullifier: &[u8; 32], epoch: u64, membership_root: &[u8; 32]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(DOMAIN_SPEND_VERIFIER.len() + 32 + 8 + 32);
    buf.extend_from_slice(DOMAIN_SPEND_VERIFIER);
    buf.extend_from_slice(nullifier);
    buf.extend_from_slice(&epoch.to_le_bytes());
    buf.extend_from_slice(membership_root);
    buf
}

/// Canonical bytes a recorder signs: it binds the verifier identity too, so a
/// counter-signature collected for one verifier can't be replayed under another.
pub fn recorder_sig_payload(
    nullifier: &[u8; 32],
    epoch: u64,
    membership_root: &[u8; 32],
    verifier: &[u8],
) -> Vec<u8> {
    let mut buf =
        Vec::with_capacity(DOMAIN_SPEND_RECORDER.len() + 32 + 8 + 32 + verifier.len());
    buf.extend_from_slice(DOMAIN_SPEND_RECORDER);
    buf.extend_from_slice(nullifier);
    buf.extend_from_slice(&epoch.to_le_bytes());
    buf.extend_from_slice(membership_root);
    buf.extend_from_slice(verifier);
    buf
}

// ───────────────────────────── committee (HRW) ─────────────────────────────

/// HRW score for `node` on `(nullifier, epoch)`, as a big-endian 32-byte key so
/// "highest weight" is a plain `Ord` over the array. The score is a uniform
/// field element, so selection is uniform over the guard set and unsteerable by
/// the verifier (the nullifier is the member's secret-derived value).
fn hrw_score(node: &[u8], nullifier: &[u8; 32], epoch: u64) -> [u8; 32] {
    let mut buf = Vec::with_capacity(HRW_DST.len() + node.len() + 32 + 8);
    buf.extend_from_slice(HRW_DST);
    buf.extend_from_slice(node);
    buf.extend_from_slice(nullifier);
    buf.extend_from_slice(&epoch.to_le_bytes());
    let mut be = fr_to_bytes_le(&hash_to_field_bn254(&buf));
    be.reverse(); // compare as a big-endian integer
    be
}

/// The committee for `(nullifier, epoch)`: the `k` highest-HRW-weight nodes of
/// `guard_set`, excluding `verifier`. Deterministic and independent of the order
/// `guard_set` is given in; ties break on node id so the order is total. Every
/// node computes the same committee because the guard set is consensus state.
pub fn committee(
    nullifier: &[u8; 32],
    epoch: u64,
    guard_set: &[NodeId],
    k: usize,
    verifier: &[u8],
) -> Vec<NodeId> {
    let mut scored: Vec<([u8; 32], NodeId)> = guard_set
        .iter()
        .filter(|n| n.as_slice() != verifier)
        .map(|n| (hrw_score(n, nullifier, epoch), n.clone()))
        .collect();
    // Highest score first; tie-break on node id (descending) for a total order.
    scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
    scored.into_iter().take(k).map(|(_, n)| n).collect()
}

/// Whether `node` is on the committee for `(nullifier, epoch)`. A recorder uses
/// this to decide if it should counter-sign a spend it is asked to witness.
pub fn is_committee_member(
    node: &[u8],
    nullifier: &[u8; 32],
    epoch: u64,
    guard_set: &[NodeId],
    k: usize,
    verifier: &[u8],
) -> bool {
    committee(nullifier, epoch, guard_set, k, verifier)
        .iter()
        .any(|c| c.as_slice() == node)
}

/// The per-epoch guard set the committee is selected over. The node implements
/// this over the RNS `guard_set()` runtime API, read at the membership-epoch
/// anchor block so every node sees the same set; tests implement it over a fixed
/// set. Keeping it a seam lets the node-side committee path be exercised without
/// a runtime client, and guarantees the node path cannot diverge from the pure
/// [`committee`] selection.
pub trait GuardSetSource {
    fn guard_set(&self, epoch: u64) -> Vec<NodeId>;
}

/// Select the committee for `(nullifier, epoch)` over the set `source` yields for
/// that epoch. A thin wrapper over [`committee`]: the node reads the guard set
/// from chain and calls exactly this, so its result is identical to the pure
/// selection given the same set.
pub fn committee_for(
    source: &impl GuardSetSource,
    nullifier: &[u8; 32],
    epoch: u64,
    k: usize,
    verifier: &[u8],
) -> Vec<NodeId> {
    committee(nullifier, epoch, &source.guard_set(epoch), k, verifier)
}

// ───────────────────────────── spend record ────────────────────────────────

/// A recorder's counter-signature on a spend.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct RecorderSig {
    pub recorder: NodeId,
    pub sig: Vec<u8>,
}

/// A witnessed spend: the verifier's claim plus the committee counter-signatures
/// that admit it. A record with `t` valid distinct recorder signatures is the
/// session's admission ticket.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct SpendRecord {
    pub nullifier: [u8; 32],
    pub epoch: u64,
    pub membership_root: [u8; 32],
    pub verifier: NodeId,
    pub verifier_sig: Vec<u8>,
    pub recorders: Vec<RecorderSig>,
}

/// Why a spend record was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpendRecordError {
    /// The verifier signature did not verify over the verifier payload.
    BadVerifierSig,
    /// The verifier is not in the guard set.
    VerifierNotGuard,
    /// A recorder equals the verifier (a guard cannot witness its own spend).
    VerifierIsRecorder,
    /// A recorder is not on the committee `(nullifier, epoch)` selects.
    RecorderNotInCommittee,
    /// The same recorder appears twice.
    DuplicateRecorder,
    /// A recorder signature did not verify over the recorder payload.
    BadRecorderSig,
    /// Fewer than `t` valid distinct recorder signatures.
    ThresholdNotMet { have: usize, need: usize },
}

/// Verify a spend record against the guard set under threshold `t`-of-`k`.
///
/// Checks, in order: the verifier is a guard and its signature is valid; every
/// recorder is on the committee the nullifier selects, is distinct, is not the
/// verifier, and signed correctly; and at least `t` recorder signatures are
/// valid. Returns the count of valid recorder signatures on success.
pub fn verify_record(
    rec: &SpendRecord,
    guard_set: &[NodeId],
    k: usize,
    t: usize,
    sig: &impl SpendSigVerify,
) -> Result<usize, SpendRecordError> {
    if !guard_set.iter().any(|g| g.as_slice() == rec.verifier.as_slice()) {
        return Err(SpendRecordError::VerifierNotGuard);
    }
    let vpayload = verifier_sig_payload(&rec.nullifier, rec.epoch, &rec.membership_root);
    if !sig.verify(&rec.verifier, &vpayload, &rec.verifier_sig) {
        return Err(SpendRecordError::BadVerifierSig);
    }

    let expected = committee(&rec.nullifier, rec.epoch, guard_set, k, &rec.verifier);
    let expected: HashSet<&[u8]> = expected.iter().map(|n| n.as_slice()).collect();

    let rpayload =
        recorder_sig_payload(&rec.nullifier, rec.epoch, &rec.membership_root, &rec.verifier);
    let mut seen: HashSet<&[u8]> = HashSet::new();
    let mut valid = 0usize;
    for rs in &rec.recorders {
        if rs.recorder.as_slice() == rec.verifier.as_slice() {
            return Err(SpendRecordError::VerifierIsRecorder);
        }
        if !expected.contains(rs.recorder.as_slice()) {
            return Err(SpendRecordError::RecorderNotInCommittee);
        }
        if !seen.insert(rs.recorder.as_slice()) {
            return Err(SpendRecordError::DuplicateRecorder);
        }
        if !sig.verify(&rs.recorder, &rpayload, &rs.sig) {
            return Err(SpendRecordError::BadRecorderSig);
        }
        valid += 1;
    }
    if valid < t {
        return Err(SpendRecordError::ThresholdNotMet { have: valid, need: t });
    }
    Ok(valid)
}

// ───────────────────────────── accumulator ─────────────────────────────────

/// Why an accumulator insert was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccumulatorError {
    /// The 32 bytes are not a canonical `Fr` (validate-at-handoff on the wire).
    NonCanonical,
}

/// The per-epoch spent-nullifier set with an order-independent root.
///
/// Nullifiers arrive in different orders at different nodes via gossip, so the
/// root must depend only on the set, not insertion order. Backing the set with a
/// `BTreeSet` and folding in sorted order gives exactly that: two nodes with the
/// same set produce the same root, so a root mismatch is a precise signal that
/// one node is missing entries, and [`SpendAccumulator::difference`] says which.
///
/// Cleared and replaced empty on epoch rollover (the nullifier bakes in the
/// epoch, so nothing carries over); the node keeps the prior epoch's set for a
/// short trailing overlap. That lifecycle is wired in a later phase.
#[derive(Clone, Debug, Default)]
pub struct SpendAccumulator {
    set: BTreeSet<[u8; 32]>,
}

impl SpendAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a nullifier, rejecting a non-canonical encoding. Returns whether
    /// it was newly inserted.
    pub fn insert(&mut self, nullifier: [u8; 32]) -> Result<bool, AccumulatorError> {
        if fr_from_canonical_bytes_le(&nullifier).is_none() {
            return Err(AccumulatorError::NonCanonical);
        }
        Ok(self.set.insert(nullifier))
    }

    pub fn contains(&self, nullifier: &[u8; 32]) -> bool {
        self.set.contains(nullifier)
    }

    pub fn len(&self) -> usize {
        self.set.len()
    }

    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    /// Iterate the spent nullifiers in canonical sorted order.
    pub fn iter(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.set.iter()
    }

    /// Order-independent commitment to the current set. Folds the sorted
    /// elements through the canonical 2-to-1 Poseidon node hash from a distinct
    /// domain seed. Pass a `&PoseidonConfig` built once via `params()`.
    pub fn root(&self, params: &PoseidonConfig<Fr>) -> [u8; 32] {
        let mut acc = Fr::from(SPEND_ACC_DOMAIN);
        for n in &self.set {
            // Canonical by construction: every member passed `insert`.
            let f = fr_from_canonical_bytes_le(n)
                .expect("accumulator only holds canonical nullifiers");
            acc = hash_node(params, acc, f);
        }
        fr_to_bytes_le(&acc)
    }

    /// Nullifiers in `self` that `other` is missing. A node sends these to a peer
    /// whose root differs to bring it into sync.
    pub fn difference(&self, other: &SpendAccumulator) -> Vec<[u8; 32]> {
        self.set.difference(&other.set).copied().collect()
    }
}

// ───────────────────────────── spend store ─────────────────────────────────

/// The node's per-epoch set of witnessed spends: the full [`SpendRecord`]s keyed
/// by nullifier, plus the reconcilable accumulator root over them. The records
/// (not just the nullifiers) are held because a peer that is missing one must
/// receive the signed record to validate it before merging.
///
/// Self-pruning on epoch rollover, like the accumulator: a new epoch produces
/// different nullifiers, so the prior epoch's records can never match and are
/// dropped wholesale.
#[derive(Clone, Debug, Default)]
pub struct SpendStore {
    epoch: u64,
    records: BTreeMap<[u8; 32], SpendRecord>,
    acc: SpendAccumulator,
}

impl SpendStore {
    pub fn new(epoch: u64) -> Self {
        Self { epoch, records: BTreeMap::new(), acc: SpendAccumulator::new() }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn contains(&self, nullifier: &[u8; 32]) -> bool {
        self.records.contains_key(nullifier)
    }

    pub fn get(&self, nullifier: &[u8; 32]) -> Option<&SpendRecord> {
        self.records.get(nullifier)
    }

    /// Insert a record the caller has already validated. Returns whether it was
    /// newly inserted. Rejects a non-canonical nullifier at the wire boundary
    /// (via the accumulator), and ignores a record whose epoch is not this
    /// store's epoch (a stale-epoch record can never belong here).
    pub fn insert(&mut self, record: SpendRecord) -> Result<bool, AccumulatorError> {
        if record.epoch != self.epoch {
            return Ok(false);
        }
        if self.records.contains_key(&record.nullifier) {
            return Ok(false);
        }
        self.acc.insert(record.nullifier)?;
        self.records.insert(record.nullifier, record);
        Ok(true)
    }

    /// The reconcilable root over the current record set. Two nodes with the same
    /// set of nullifiers produce the same root regardless of arrival order.
    pub fn root(&self, params: &PoseidonConfig<Fr>) -> [u8; 32] {
        self.acc.root(params)
    }

    /// Drop everything and adopt `epoch` if it differs (epoch rollover). A no-op
    /// if already on `epoch`.
    pub fn roll_to(&mut self, epoch: u64) {
        if epoch != self.epoch {
            self.records.clear();
            self.acc = SpendAccumulator::new();
            self.epoch = epoch;
        }
    }

    /// Up to `max` records to hand a peer in a sync response.
    pub fn records_for_sync(&self, max: usize) -> Vec<SpendRecord> {
        self.records.values().take(max).cloned().collect()
    }
}

// ───────────────────────────── sync wire types ─────────────────────────────

/// Cap on records returned in one [`SpendSyncResponse::Mismatch`]. Bounds the
/// response payload; the initiator reconciles the remainder on later ticks.
pub const MAX_SPEND_RECORDS_PER_RESPONSE: usize = 4096;

/// Initiator -> responder: "for epoch `epoch`, my spend-set root is `root`".
/// Sent on `/rostro/chat-spend/1`.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct SpendSyncRequest {
    pub epoch: u64,
    pub root: [u8; 32],
}

/// Responder -> initiator.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum SpendSyncResponse {
    /// Roots agree for the epoch; the two stores are in sync, nothing to send.
    Match,
    /// Roots differ for the same epoch; here are the responder's records (bounded
    /// to [`MAX_SPEND_RECORDS_PER_RESPONSE`]) for the initiator to validate and
    /// merge what it is missing.
    Mismatch { records: Vec<SpendRecord> },
    /// The responder is on a different epoch than the request (a boundary skew);
    /// the initiator must not merge these as same-epoch records, and should retry
    /// once epochs realign.
    EpochSkew { epoch: u64 },
}

#[cfg(test)]
mod tests;
