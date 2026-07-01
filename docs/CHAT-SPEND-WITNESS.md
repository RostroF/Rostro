# Witnessed Nullifier Spend

**Workstream:** `chat-spend-witness`
**Branch:** `chat-spend-witness-v0`
**Status:** Phase 0 (spec lock). Mainnet-targeted, off on testnet until activated.

## 0. Problem

The anonymous chat membership handshake admits a session when a member presents a
valid Groth16 membership proof. To bound abuse, each session burns a per-epoch
nullifier `N = Poseidon(s, epoch)`, "one session per cert per epoch".

Today that spent-nullifier set is a node-local `HashSet` inside `HandshakeSessions`
(`substrate/utils/rostro-chat-membership-auth/src/lib.rs`). It is never shared. A
guard verifies a proof, issues a session, and the spend stays in that guard's RAM.

Because the nullifier value is identical at every guard for a given cert and epoch
(`N` is not guard-bound; only the proof *challenge* is), a member can round-robin
across the guard set and obtain one session per guard. With `G` guards the per-epoch
rate limit becomes `G x` the intended ceiling, and the amplification grows with
decentralisation, which is backwards.

The asymmetry behind the bug: membership leaves and TTL ride consensus, so every
guard agrees on them; the nullifier spend never touches consensus, so no two guards
agree on it. Identity state is global, rate-limit state is local. This workstream
makes the spend a witnessed act so the rate-limit state becomes global too, without
putting a transaction on the login path.

## 1. Design

A spend is recorded by a committee the verifier cannot choose, co-signed, and
gossiped. The verifier issues a session only after a threshold of the committee
counter-signs. The committee is selected over the guard set defined below.

### 1.1 The guard set (RNS NODE records)

The committee is selected over a consensus-agreed, sybil-resistant set of guard node
identities. That set is sourced from RNS (the Rostro Name Service), not from the
validator set: guards and relays are ordinary non-validator nodes.

Every node already has a free ed25519 libp2p identity (its PeerId, the key it signs
onion forwards with and the `guard_node_id` the handshake challenge binds). What was
missing is an *agreed, sybil-resistant set* of those identities; a free-to-mint key
gives neither agreement nor sybil resistance on its own. RNS supplies both:

- **Enrolment.** A node is registered into its owner's RNS entry under a new `NODE`
  record (a fresh `RecordType` alongside `CHAT`/`MESSAGE`/`VALIDATOR`): a 32-byte
  libp2p ed25519 key, validated to exactly 32 bytes the way `CHAT` is. Distinct from
  `VALIDATOR` (a validator *stash account*, and these are non-validators) and from
  `CHAT` (a messaging address). New purpose, new record.
- **Agreed + enumerable.** RNS is on-chain, so every node reads the same set. The set is
  read at the **finalized head** (current RNS membership, NOT an epoch-locked snapshot):
  verifier and recorders agree because they read the same finalized state, and the set
  changes only via RNS enrol/expire (slow, consensus-agreed). Guard churn
  (connect/disconnect) is liveness, absorbed by `t`-of-`k`, and never affects membership.
- **Sybil gate.** Holding an RNS name costs, so guard-set membership costs. Policy is
  **one `NODE` record per name**: each guard identity costs a name, so an attacker must
  buy names in proportion to the committee weight they want, which preserves the
  honest-majority assumption HRW rests on. Owner accountability (every node traces to an
  RNS owner) feeds the Phase 5 quarantine.

The guard's committee identity is its libp2p node key, the same key used for onion
forwarding and the handshake challenge. One universal node identity, published in RNS.

RNS exposes per-name `lookup` today but no global enumeration, so Phase 2a adds an
index over `NODE` records and a `guard_set()` runtime API (see the build plan).

### 1.2 Deterministic committee

For nullifier `N` in epoch `E`:

```
committee(N, E) = top-k  HRW(node, N || E)  over the on-chain guard set,
                  excluding the verifier
```

HRW = highest-random-weight (rendezvous) hashing. Properties:

- **Agreed by all nodes.** The guard set is consensus state, so every node computes
  the same committee for a given `N`.
- **Unsteerable by the verifier.** `N = Poseidon(s, epoch)` is derived from the
  member's secret `s`, so the verifier has no freedom to land a friendly recorder.
- **Verifier excluded.** A guard can never be its own witness; a record with
  `verifier == recorder` is invalid by rule.

The committee is a single fixed serialisation point per `N`. This converts an
eventually-consistent gossip race (which an attacker can sprint through during the
propagation window) into a one-committee chokepoint the attacker cannot relocate.

### 1.3 Signed spend record

```
SpendRecord {
    nullifier:       N,
    epoch:           E,
    membership_root: R,                         // root the proof verified against
    verifier:        V,
    verifier_sig:    sig_V(N || E || R),        // "I verified a valid proof producing N"
    recorders:       [W, ...],
    recorder_sigs:   { sig_W(N || E || R || V), ... },   // "I am N's recorder, N was unseen, admitted"
}
```

Both identities are in the record, so the network knows who did the verification and
who did the witnessing. That is the accountability requirement and the basis for
equivocation detection (1.6).

### 1.4 Threshold admission

The verifier issues a session only after collecting `t` of `k` recorder signatures.
That threshold set is the session's admission ticket and is embedded in the session
object, so any other node the member later talks to can be shown the spend was
properly witnessed.

**Default `k = 3`, `t = 2` (2-of-3). Config-bindable.**

- `k` (committee size) gives redundancy: 2-of-3 tolerates one offline recorder.
- `t` (threshold) is squeezed between two opposing pressures:
  - down, for liveness: survive `d` offline members needs `t <= k - d`.
  - up, for safety: resist `c` colluding members. Strict Byzantine double-decision
    safety needs `k >= 3c + 1` and `t >= (k + c + 1) / 2`, i.e. 3-of-4 to tolerate
    one colluder outright.
- 2-of-3 tolerates one offline recorder for liveness, but its double-spend safety
  holds only when all three are honest. A colluding recorder can leak one extra
  session. We accept that because the cheat is **provable equivocation** (1.6): the
  colluder self-incriminates and is quarantined, and the leaked session is bounded by
  the session lifetime and per-session rate limit. Detection-and-punishment over
  prevention. `k`/`t` stay parameters, so dialling to 3-of-4 later is config, not a
  redesign.

### 1.5 Epoch scoping and self-pruning

`N` bakes in the epoch, so at epoch rollover every entry refers to a stale epoch and
the same cert produces a different `N`. The set is therefore dropped and replaced
empty at rollover, O(1), no per-entry bookkeeping.

The governing clock is the **zkpki membership epoch**: `EPOCH_LENGTH_BLOCKS = 14_400`
blocks x 6s = 24 hours (`current_epoch() = block_number / EPOCH_LENGTH_BLOCKS`). It is
distinct from the 1-hour Sassafras consensus epoch and from the 7-epoch (7-day)
freshness grant.

The boundary is a **hard cutover**, not a grace window: a proof built for a lapsed
epoch is rejected with a clear, actionable error (`-32005`, "epoch rolled; rebuild for
the current epoch") and the client rebuilds the proof for the current epoch (~1s prove,
once per 24h). A grace window would only move the boundary problem to the end of the
window; the clean cutover keeps it at the boundary. (Decision: hard cutover over a
trailing-overlap window, to avoid the dual-epoch spent-state and a managed
cross-boundary double-spend window.)

The set is held as a per-epoch Merkle accumulator with a root, so committee members
can compare roots and reconcile missing entries cheaply (a plain set cannot be diffed).

### 1.6 Equivocation detection and quarantine

- **Double-signing recorder.** A recorder that counter-signs two records for the same
  `N` in one epoch self-incriminates: both records gossip, and any node can see `W`
  signed `N` twice. This is cryptographically provable equivocation, the same
  primitive consensus slashes for double-signing.
- **Bogus-record flood.** Every spend request carries the member's membership proof
  (something only the real member can produce), so a committee member validates the
  request is genuine before recording. A verifier that submits more than `X` bad
  records inside a timeout is flooding.
- **Quarantine.** Either case triggers a quarantine vote that drops the offender from
  committee eligibility and `/rostro/chat-spend/1` peering. Governance of the vote
  (tally authority, dispute path, un-quarantine) is scoped in Phase 5.

### 1.7 What stays off-chain

The spend lives in node RAM, gossips between nodes, and prunes per epoch. It never
hits consensus. It borrows consensus only for the two things that genuinely need
global agreement and already are global: the membership root (to verify the proof)
and the guard registry (to compute the committee). Zero extrinsics on the login path,
which was the property the anonymous path was built to preserve.

## 2. Placement

- Pure logic (`SpendRecord` and payloads, HRW `committee()`, threshold verifier,
  per-epoch accumulator) extends the existing Apache-2.0 util crate
  `substrate/utils/rostro-chat-membership-auth`, alongside the `NullifierStore` /
  `HandshakeSessions` code it replaces. No new crate.
- **Signing stays in the node binary.** The util crate exposes pure build/verify
  functions; `gemini-node` holds the node key and performs the signatures. Privileged
  capability code stays where the capability lives; `gemini-node`'s footprint stays
  thin.
- Transport is a dedicated libp2p protocol `/rostro/chat-spend/1`, separate from
  message-bucket gossip. No second purpose on a channel built for one purpose.
- The guard-set source is RNS runtime/pallet work, separate from the Apache util
  core: a new `NODE` `RecordType` in `rns-types`/`rns-resolvers`, an enumeration index
  over `NODE` records, and a `guard_set()` method on the RNS runtime API
  (`rns-runtime-api`). Each guard's committee identity is its libp2p node key, unified
  with onion forwarding and the handshake challenge.

## 3. Parameters

| Param | Default | Notes |
|---|---|---|
| `k` committee size | 3 | config-bindable |
| `t` threshold | 2 | config-bindable; 2-of-3 + quarantine posture |
| guard-set source | RNS `NODE` records | on-chain; read at the finalized head (current set, not epoch-locked) |
| nodes per RNS name | 1 | sybil gate: guard count tied to name count |
| epoch | 24h (`EPOCH_LENGTH_BLOCKS = 14_400`) | the nullifier rate-limit clock |
| epoch boundary | hard cutover | lapsed-epoch proof rejected with a clear error (`-32005`); client rebuilds |
| quarantine threshold | `FLOOD_THRESHOLD` (10) bad proofs / epoch | per-verifier; quarantines flooders |

## 4. Build plan and gates

Each gate is a hard checkpoint. Work does not pass a gate until its criteria are green
and reviewed.

**Phase 0 - Spec lock + worktree.** This doc; worktree
`/home/coder/Rostro-chat-spend-witness` on `chat-spend-witness-v0`.
*Gate:* spec approved; worktree + branch exist.

**Phase 1 - Types + committee (pure, no networking).** `SpendRecord`, signature
payloads, HRW `committee()`, threshold verifier, per-epoch accumulator with root.
*Gate:* unit tests green: committee determinism (same `N` -> same committee across
simulated node sets), verifier-exclusion, signature validation, t-of-k accept/reject,
accumulator-root reconciliation. KATs for HRW.

**Phase 2a - RNS guard-set source.** Add a `NODE` `RecordType` (32-byte libp2p
ed25519 key, validated like `CHAT`), one per RNS name. Maintain an index over `NODE`
records and expose `guard_set()` on the RNS runtime API. `guard_set()` enumerates the
current RNS `NODE` records.
*Gate:* a node registered into its owner's RNS entry appears in `guard_set()`; a name
without a `NODE` record does not; a second `NODE` record on a name is rejected.

**Phase 2b - Node reads set + computes committee.** Thin wiring: the node reads
`guard_set()` at the finalized head and computes committees via the Phase 1
`committee()`. (The guard set is current RNS membership, not an epoch-locked snapshot;
churn is liveness, absorbed by `t`-of-`k`.)
*Gate:* node-computed committee matches the Phase 1 pure tests against that set.

**Phase 3 - Spend-record gossip.** `/rostro/chat-spend/1` carrying records +
accumulator-root reconciliation. Receive -> validate (sigs, committee membership,
recent root, epoch) -> insert -> re-gossip.
*Gate (lab):* multi-node rig; a record injected at one node reaches all; forged /
malformed rejected; accumulator roots converge.

**Phase 4 - Verifier + recorder wiring (the cutover).** Verifier path in
`do_authenticate_membership`: after Groth16 verify, compute committee, collect `t`
recorder sigs, then issue session embedding the record. Recorder path: validate,
check-unseen, counter-sign, gossip, refuse second sign for same `N`. Remove the
local-only admission (single cutover, no coexistence).
*Gate (lab):* round-robin test - one cert hitting all `G` guards gets exactly ONE
session; every further attempt refused by the committee.

**Phase 5 - Equivocation detection + quarantine.** Detect double-signing recorder
(provable) and bogus-record flood (genuine-request filter: committee re-checks the
proof). Quarantine vote drops the offender. Scope quarantine governance here.
*Gate (lab):* injected double-signer detected + quarantined; injected garbage flood
quarantined; honest nodes unaffected.

**Phase 6 - Rollover + liveness hardening.** Hard cutover at the epoch boundary
(clear `-32005` error; no grace window). Guard set read at the finalized head (not an
epoch-start anchor, which a pruned node cannot serve). One-recorder-offline is
tolerated by `t`-of-`k` (the verifier collects from whoever answers); a freshly
*enrolled* node is not committee-eligible until its RNS record is finalized, by which
point it is synced; connect/disconnect is liveness, never membership.
*Gate (lab):* rollover clears cleanly (hard cutover, clear error); admission survives
one offline committee member; a churning guard does not desync committees.

**Phase 7 - Integration + activation gate + merge.** End-to-end behind `membership_vk`;
mainnet-targeted, testnet stays off. Residuals documented.
*Gate:* full E2E on the rig with auth activated in a test config: round-robin
defeated, equivocation punished, liveness under churn. Then `--no-ff` merge to
rostro-main.

## 5. Residual risks (documented, not solved here)

- A full committee partition can briefly yield two sessions; bounded, and requires
  simultaneous failures.
- Sybil resistance rests on RNS name cost plus the one-`NODE`-per-name policy. An
  attacker with many names still buys committee weight in proportion, so RNS name
  pricing is load-bearing here (ties to RNS genesis pricing).
- The guard set is read at the finalized head, so it tracks RNS enrol/expire within
  a few blocks of finality. A targeted committee-grind (registering node-ids that rank
  onto a specific nullifier's committee) is bounded by RNS cost + honest-majority; an
  epoch-length activation delay would defeat it outright but at a 24h onboarding cost,
  so it is deferred unless grinding proves worthwhile.
- HRW security rests on an honest-majority, sybil-resistant guard set, the same
  assumption the validator set already carries.
- Quarantine governance (tally authority, dispute, un-quarantine) needs its own small
  design; surfaced in Phase 5.
- 2-of-3 leaks at most one extra session to a colluding recorder before quarantine;
  accepted by the detection-over-prevention posture, reversible via `k`/`t` config.
