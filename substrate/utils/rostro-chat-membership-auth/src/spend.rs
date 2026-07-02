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
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::OnceLock;

/// Process-global canonical Poseidon params. The instance is a deterministic
/// constant, but its Grain-LFSR / MDS derivation is expensive, so build it once.
fn cached_params() -> &'static PoseidonConfig<Fr> {
    static PARAMS: OnceLock<PoseidonConfig<Fr>> = OnceLock::new();
    PARAMS.get_or_init(rostro_poseidon_bn254::params)
}

/// Opaque node identity (e.g. a libp2p peer id's bytes). Matches the
/// `guard_node_id: &[u8]` the handshake verifier already threads through.
pub type NodeId = Vec<u8>;

/// Domain-separation tag for the HRW committee score.
pub const HRW_DST: &[u8] = b"rostro-chat-spend-hrw-v1";
/// Domain tag for the verifier signature payload. v2: the payload commits to
/// the session public key (CHAT-SESSION-TICKET.md), so a v1 signature can
/// never validate a v2 record.
pub const DOMAIN_SPEND_VERIFIER: &[u8] = b"rostro-chat-spend-verifier-v2";
/// Domain tag for the recorder signature payload (v2, see above).
pub const DOMAIN_SPEND_RECORDER: &[u8] = b"rostro-chat-spend-recorder-v2";
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
/// producing nullifier `n` at epoch `e` under membership root `r`, authorizing
/// session key `s`". Committing to the session key is what makes the witnessed
/// record a portable admission ticket: without it, a signature could be reused
/// to graft a different session key onto the same witnessed nullifier.
pub fn verifier_sig_payload(
    nullifier: &[u8; 32],
    epoch: u64,
    membership_root: &[u8; 32],
    session_pubkey: &[u8],
) -> Vec<u8> {
    let mut buf =
        Vec::with_capacity(DOMAIN_SPEND_VERIFIER.len() + 32 + 8 + 32 + session_pubkey.len());
    buf.extend_from_slice(DOMAIN_SPEND_VERIFIER);
    buf.extend_from_slice(nullifier);
    buf.extend_from_slice(&epoch.to_le_bytes());
    buf.extend_from_slice(membership_root);
    buf.extend_from_slice(session_pubkey);
    buf
}

/// Canonical bytes a recorder signs: it binds the verifier identity too, so a
/// counter-signature collected for one verifier can't be replayed under another.
pub fn recorder_sig_payload(
    nullifier: &[u8; 32],
    epoch: u64,
    membership_root: &[u8; 32],
    verifier: &[u8],
    session_pubkey: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        DOMAIN_SPEND_RECORDER.len() + 32 + 8 + 32 + verifier.len() + session_pubkey.len(),
    );
    buf.extend_from_slice(DOMAIN_SPEND_RECORDER);
    buf.extend_from_slice(nullifier);
    buf.extend_from_slice(&epoch.to_le_bytes());
    buf.extend_from_slice(membership_root);
    buf.extend_from_slice(verifier);
    buf.extend_from_slice(session_pubkey);
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
/// that admit it. A record with `t` valid distinct recorder signatures IS the
/// session's admission ticket: it names the authorized `session_pubkey`, both
/// signature payloads commit to it, and any guard can validate the whole thing
/// against the current guard set (CHAT-SESSION-TICKET.md).
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct SpendRecord {
    pub nullifier: [u8; 32],
    pub epoch: u64,
    pub membership_root: [u8; 32],
    /// The Ed25519 session key the witnessed handshake authorized (32 bytes;
    /// length-checked in [`verify_record`], validate-at-handoff).
    pub session_pubkey: Vec<u8>,
    pub verifier: NodeId,
    pub verifier_sig: Vec<u8>,
    pub recorders: Vec<RecorderSig>,
}

/// Why a spend record was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpendRecordError {
    /// `session_pubkey` is not 32 bytes (shape check at the wire boundary;
    /// whether it is a VALID Ed25519 point is the drop-verification's concern).
    BadSessionKey,
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
    if rec.session_pubkey.len() != 32 {
        return Err(SpendRecordError::BadSessionKey);
    }
    if !guard_set.iter().any(|g| g.as_slice() == rec.verifier.as_slice()) {
        return Err(SpendRecordError::VerifierNotGuard);
    }
    let vpayload = verifier_sig_payload(
        &rec.nullifier,
        rec.epoch,
        &rec.membership_root,
        &rec.session_pubkey,
    );
    if !sig.verify(&rec.verifier, &vpayload, &rec.verifier_sig) {
        return Err(SpendRecordError::BadVerifierSig);
    }

    let expected = committee(&rec.nullifier, rec.epoch, guard_set, k, &rec.verifier);
    let expected: HashSet<&[u8]> = expected.iter().map(|n| n.as_slice()).collect();

    let rpayload = recorder_sig_payload(
        &rec.nullifier,
        rec.epoch,
        &rec.membership_root,
        &rec.verifier,
        &rec.session_pubkey,
    );
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
    /// Session-pubkey -> nullifier index for portable-ticket admission: a
    /// guard that never saw the handshake looks the drop's session key up
    /// here (CHAT-SESSION-TICKET.md 2.2). Same lifetime as `records`.
    by_session: BTreeMap<Vec<u8>, [u8; 32]>,
    acc: SpendAccumulator,
}

impl SpendStore {
    pub fn new(epoch: u64) -> Self {
        Self {
            epoch,
            records: BTreeMap::new(),
            by_session: BTreeMap::new(),
            acc: SpendAccumulator::new(),
        }
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

    /// The record whose witnessed handshake authorized `session_pubkey`, if
    /// any — the portable-ticket admission lookup.
    pub fn get_by_session(&self, session_pubkey: &[u8]) -> Option<&SpendRecord> {
        self.by_session.get(session_pubkey).and_then(|n| self.records.get(n))
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
        self.by_session.insert(record.session_pubkey.clone(), record.nullifier);
        self.records.insert(record.nullifier, record);
        Ok(true)
    }

    /// The reconcilable root over the current record set. Two nodes with the same
    /// set of nullifiers produce the same root regardless of arrival order.
    pub fn root(&self, params: &PoseidonConfig<Fr>) -> [u8; 32] {
        self.acc.root(params)
    }

    /// The reconcilable root using process-global cached Poseidon params. The
    /// node calls this on the hot reconciliation path so it never builds the
    /// (expensive) params per request or depends on the Poseidon types itself.
    pub fn root_cached(&self) -> [u8; 32] {
        self.root(cached_params())
    }

    /// Drop everything and adopt `epoch` if it differs (epoch rollover). A no-op
    /// if already on `epoch`.
    pub fn roll_to(&mut self, epoch: u64) {
        if epoch != self.epoch {
            self.records.clear();
            self.by_session.clear();
            self.acc = SpendAccumulator::new();
            self.epoch = epoch;
        }
    }

    /// Up to `max` records to hand a peer in a sync response.
    pub fn records_for_sync(&self, max: usize) -> Vec<SpendRecord> {
        self.records.values().take(max).cloned().collect()
    }

    /// The stored record for `record`'s nullifier if it differs from `record`.
    /// A same-nullifier conflict is the signal for equivocation detection (two
    /// distinct valid records for one nullifier should not exist).
    pub fn conflict(&self, record: &SpendRecord) -> Option<SpendRecord> {
        match self.records.get(&record.nullifier) {
            Some(existing) if existing != record => Some(existing.clone()),
            _ => None,
        }
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

// ───────────────────────────── witness handshake ───────────────────────────

/// A verifier's request to a committee member to witness a spend. It is the
/// verifier's half of a [`SpendRecord`] (no recorder signatures yet). The
/// recorder validates it, refuses if it has already witnessed this nullifier this
/// epoch, and otherwise returns its counter-signature.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct WitnessRequest {
    pub nullifier: [u8; 32],
    pub epoch: u64,
    pub membership_root: [u8; 32],
    pub verifier: NodeId,
    pub verifier_sig: Vec<u8>,
    /// The membership proof and the remaining public inputs, so the recorder can
    /// re-verify the spend is genuine before counter-signing (the genuine-request
    /// filter). The verifier is the guard the proof's challenge is bound to, so
    /// the recorder verifies with `verifier` as the guard id. A tampered field
    /// just makes the proof fail, so these need no separate signature.
    pub proof: Vec<u8>,
    pub freshness_root: [u8; 32],
    pub anchor_block: u64,
    pub session_pubkey: Vec<u8>,
}

impl WitnessRequest {
    /// Reconstruct the handshake request the proof was made for, so the recorder
    /// can re-verify it (with `verifier` as the guard id).
    pub fn handshake_request(&self) -> crate::HandshakeRequest {
        crate::HandshakeRequest {
            proof: self.proof.clone(),
            membership_root: self.membership_root,
            freshness_root: self.freshness_root,
            nullifier: self.nullifier,
            current_epoch: self.epoch,
            anchor_block: self.anchor_block,
            session_pubkey: self.session_pubkey.clone(),
        }
    }
}

/// A committee member's reply to a [`WitnessRequest`].
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum WitnessResponse {
    /// The recorder witnessed the spend and counter-signed.
    Accepted { recorder: NodeId, recorder_sig: Vec<u8> },
    /// The recorder declined; `reason` says why.
    Refused { reason: WitnessRefusal },
}

/// Why a recorder refused to witness a spend.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum WitnessRefusal {
    /// The request's epoch is not the recorder's current epoch.
    EpochMismatch,
    /// The verifier is not in the guard set.
    VerifierNotGuard,
    /// The verifier signature did not verify.
    BadVerifierSig,
    /// This recorder is not on the committee for `(nullifier, epoch)`.
    NotOnCommittee,
    /// This recorder already witnessed this nullifier this epoch (the honest-side
    /// double-sign refusal, the heart of the round-robin defence).
    AlreadyWitnessed,
    /// The membership root is not current or recent on this recorder's chain
    /// view. Set by the node's chain check, not by [`validate_witness`].
    StaleRoot,
    /// The membership proof did not verify against the recorder's chain view: a
    /// bogus request. Repeated bogus requests from a verifier get it quarantined.
    BadProof,
}

/// A recorder's per-epoch set of witnessed nullifiers. A recorder counter-signs a
/// given nullifier at most once per epoch, so a member who round-robins to many
/// verifiers cannot collect a second valid committee quorum: every verifier maps
/// the nullifier to the same committee, and these recorders refuse the repeat.
///
/// Self-pruning on epoch rollover, like the spent set.
#[derive(Clone, Debug, Default)]
pub struct RecorderState {
    epoch: u64,
    witnessed: HashSet<[u8; 32]>,
    /// Per-verifier count of bogus (proof-invalid) requests this epoch — the
    /// flood signal. A verifier exceeding the node's threshold gets quarantined.
    bad_requests: HashMap<NodeId, u32>,
}

impl RecorderState {
    pub fn new(epoch: u64) -> Self {
        Self { epoch, witnessed: HashSet::new(), bad_requests: HashMap::new() }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn has_witnessed(&self, nullifier: &[u8; 32]) -> bool {
        self.witnessed.contains(nullifier)
    }

    /// Record that this recorder has counter-signed `nullifier` this epoch.
    pub fn mark_witnessed(&mut self, nullifier: [u8; 32]) {
        self.witnessed.insert(nullifier);
    }

    /// Count a bogus request from `verifier`, returning its running total this
    /// epoch. The caller quarantines the verifier once the total crosses its
    /// flood threshold.
    pub fn record_bad_request(&mut self, verifier: &[u8]) -> u32 {
        let c = self.bad_requests.entry(verifier.to_vec()).or_insert(0);
        *c = c.saturating_add(1);
        *c
    }

    pub fn bad_request_count(&self, verifier: &[u8]) -> u32 {
        self.bad_requests.get(verifier).copied().unwrap_or(0)
    }

    /// Drop the per-epoch state and adopt `epoch` if it differs (rollover).
    pub fn roll_to(&mut self, epoch: u64) {
        if epoch != self.epoch {
            self.witnessed.clear();
            self.bad_requests.clear();
            self.epoch = epoch;
        }
    }
}

/// Validate a witness request from the recorder's side: right epoch, the verifier
/// is a guard with a valid signature, this recorder is on the committee, and the
/// nullifier is unseen this epoch. Pure; the caller does chain checks (root
/// recency) and, on `Ok`, marks the nullifier witnessed and counter-signs.
pub fn validate_witness(
    req: &WitnessRequest,
    my_node_id: &[u8],
    guard_set: &[NodeId],
    k: usize,
    sig: &impl SpendSigVerify,
    recorder_state: &RecorderState,
) -> Result<(), WitnessRefusal> {
    if req.epoch != recorder_state.epoch {
        return Err(WitnessRefusal::EpochMismatch);
    }
    if !guard_set.iter().any(|g| g.as_slice() == req.verifier.as_slice()) {
        return Err(WitnessRefusal::VerifierNotGuard);
    }
    let payload = verifier_sig_payload(
        &req.nullifier,
        req.epoch,
        &req.membership_root,
        &req.session_pubkey,
    );
    if !sig.verify(&req.verifier, &payload, &req.verifier_sig) {
        return Err(WitnessRefusal::BadVerifierSig);
    }
    if !is_committee_member(my_node_id, &req.nullifier, req.epoch, guard_set, k, &req.verifier) {
        return Err(WitnessRefusal::NotOnCommittee);
    }
    if recorder_state.has_witnessed(&req.nullifier) {
        return Err(WitnessRefusal::AlreadyWitnessed);
    }
    Ok(())
}

// ───────────────────────────── quarantine ──────────────────────────────────

/// Per-epoch set of node identities quarantined for provable misbehaviour
/// (equivocation today; bogus-request flooding later). A quarantined node's
/// signatures are treated as worthless, so it cannot help mint a session even if
/// HRW still selects it onto a committee.
///
/// Self-pruning on epoch rollover. A persistent / reputation-weighted quarantine
/// and the un-quarantine path are governance, deferred.
#[derive(Clone, Debug, Default)]
pub struct QuarantineSet {
    epoch: u64,
    quarantined: HashSet<NodeId>,
}

impl QuarantineSet {
    pub fn new(epoch: u64) -> Self {
        Self { epoch, quarantined: HashSet::new() }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn is_quarantined(&self, node: &[u8]) -> bool {
        self.quarantined.contains(node)
    }

    /// Quarantine `node`. Returns whether it was newly added.
    pub fn quarantine(&mut self, node: NodeId) -> bool {
        self.quarantined.insert(node)
    }

    pub fn len(&self) -> usize {
        self.quarantined.len()
    }

    pub fn is_empty(&self) -> bool {
        self.quarantined.is_empty()
    }

    pub fn roll_to(&mut self, epoch: u64) {
        if epoch != self.epoch {
            self.quarantined.clear();
            self.epoch = epoch;
        }
    }

    /// Whether `record` is still admissible under this quarantine: its verifier is
    /// not quarantined, and at least `t` of its recorder signatures are from
    /// non-quarantined recorders (a quarantined signer's signature is worthless,
    /// so it does not count toward the threshold).
    pub fn admits(&self, record: &SpendRecord, t: usize) -> bool {
        if self.is_quarantined(&record.verifier) {
            return false;
        }
        let valid = record
            .recorders
            .iter()
            .filter(|r| !self.is_quarantined(&r.recorder))
            .count();
        valid >= t
    }
}

/// The recorders that counter-signed the *same* nullifier for two *different*
/// verifiers: provable equivocation. An honest recorder refuses the second
/// witness request for a nullifier (its [`RecorderState`] is keyed by nullifier
/// alone), so appearing in two records for that nullifier under different
/// verifiers means it double-signed. Returns empty unless `a` and `b` are a
/// genuine same-nullifier, different-verifier conflict.
pub fn equivocators(a: &SpendRecord, b: &SpendRecord) -> Vec<NodeId> {
    if a.nullifier != b.nullifier || a.verifier == b.verifier {
        return Vec::new();
    }
    let bset: HashSet<&[u8]> = b.recorders.iter().map(|r| r.recorder.as_slice()).collect();
    a.recorders
        .iter()
        .filter(|r| bset.contains(r.recorder.as_slice()))
        .map(|r| r.recorder.clone())
        .collect()
}

#[cfg(test)]
mod tests;
