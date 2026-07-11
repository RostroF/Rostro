# Consensus key lifecycle: forced rotation, lineage, offences, and the PQ finality ratchet

**Status:** workstream 1 (session-rotation-v0) DONE — merged 5602fc6417, star-proven, lab on spec 103, rotation proven on production config 2026-07-04. Workstream 2 (pq-finality-v0) IN BUILD since 2026-07-05 (worktree `/home/coder/Rostro-pq-finality/`); scheme locked, Phase 0 (vendor + hybrid-sig leaf) landed.
**Date:** 2026-07-03.
**Context:** continuation of the GRANDPA-key thread: [[KEYSTORE-AUDIT]] → [[VALIDATOR-CHANNEL-CERT]] (landed 753c022f4c) → [[PQ-TRANSPORT]] (landed 27e4e56634). Motivating question from the user: why does a finality juror hold a never-expiring key, and why isn't rotation forced with the key history tracked so long-range attacks die?

## 1. The problem

The GRANDPA key is a validator's juror credential: finality is a bundle of
2/3+ individual signatures over the on-chain-registered authority set, and
the justification (that signature bundle) is the portable proof of finality
that sync, warp-sync, the watchdog, and any light client verify.

As of rostro-main a979268fcb the gemini runtime runs the raw testbed
configuration:

| Knob | Value | Consequence |
|---|---|---|
| `SessionPeriod` | `u32::MAX` (lib.rs:268) | keys NEVER rotate; authority set frozen at genesis |
| `SessionManager` | `()` | no set changes (NPoS staking not yet wired) |
| `KeyOwnerProof` | `sp_core::Void` (lib.rs:295) | equivocation unprovable on-chain |
| `EquivocationReportSystem` | `()` (lib.rs:296) | double-signing is free |
| `MaxSetIdSessionEntries` | `0` (lib.rs:294) | no set-id → session history for proofs |

Two distinct attack classes against immortal finality keys:

1. **Long-range / posterior corruption (classical).** A validator who served
   in era N, exited, and unbonded still holds a key that validly signs era-N
   votes forever, with nothing left at stake. Collect 2/3 of an old set's
   keys and you forge a perfectly verifying justification for an alternate
   history. Key *tracking* alone cannot stop this for a from-genesis syncer:
   the attacker forges the tracking too, on their fork. The chain defines the
   keys and the keys define the chain.
2. **Q-day history forgery (quantum).** Every historical authority public key
   sits on-chain forever. A CRQC recovers secrets from public keys, so at
   Q-day every retired ed25519 GRANDPA key in history becomes forgeable and
   the finalized past is rewritable. **No rotation or deletion scheme fixes
   this**, because the public key is the leak. Only PQ signatures on votes
   do. This is the authenticity sibling of the [[PQ-TRANSPORT]]
   harvest-now-decrypt-later finding: transport confidentiality is now
   hybrid-PQ; finality authenticity is the remaining quantum surface, and it
   is the one artifact verified years after signing.

## 2. Design: the double ratchet, transposed to consensus

Signal's double ratchet = a fast one-way chain (forward secrecy via key
*destruction*) + a slow fresh-entropy chain (post-compromise *healing*).
Transposed to publicly verifiable signing:

- **Fast chain** = forward-secure / key-evolving signatures: secret evolves
  one-way under a fixed registered public key, old secrets destroyed. This is
  the piece that kills classical long-range attacks, and the asymmetry is
  favorable: long-range needs exactly the *old* keys that forward security
  destroys. (A thief can still run the ratchet forward; that is handled by
  detection + healing, below.)
- **Slow chain** = forced re-registration of a fresh key each era. The
  healing gear. Substrate already roots this outside the ratchet: `set_keys`
  is authorized by the account/stash key, not the session key, so a stolen
  GRANDPA key does not control rotation and a cold account key evicts the
  thief at the next era.
- **Neither chain works without the other two organs:**
  - **Lineage** (on-chain key history): enables cross-set equivocation
    proofs, fresh-key enforcement, and the canary below.
  - **Offences**: equivocation with teeth, plus the **retired-key canary**:
    once rotation is forced and lineage recorded, any signature from a
    retired key over a current-scope preimage is *definitionally* evidence of
    compromise, submittable by anyone, the signature is the proof. Leaked old
    keys become self-incriminating instead of silently dangerous.

Hardware notes (mainnet, [[KEYSTORE-AUDIT]] F3/F4, recorded here so the scope
boundary is explicit):

- Commodity TPM silicon has **no ed25519/EdDSA** (registry lists
  `TPM_ALG_EDDSA`; Infineon/STMicro/Nuvoton/PTT/fTPM ship RSA + P-256/384).
  F3 is therefore *sealing*, not in-chip signing: the key blob is
  PCR-policy-bound ciphertext at rest, plaintext only in the RAM of a
  correctly measured running node. Sealing kills offline theft (stolen disk,
  backup, exited validator's key file), not runtime RAM extraction.
- TPM2 needs **no human interaction** for policy-gated keys (PCR policy =
  unattended unseal; standard headless pattern). Person-presence is a
  FIDO/WebAuthn property, not TPM2.
- A TPM **monotonic counter** in the sealing policy makes ratchet regression
  physically impossible (blobs sealed to counter < N are dead ciphertext) and
  is the same primitive as F4's anti-equivocation watermark. One counter
  enforces both "never sign period N twice" and "never sign period < N
  again". This is what turns KES's honor-system "delete" into an enforced
  operation, and it is what makes stateful signing operable by non-experts
  (low-barrier north star) if we ever choose a stateful scheme.

## 3. Workstream 1: session-rotation-v0 (testnet-gating)

Worktree `/home/coder/Rostro-session-rotation/`, branch `session-rotation-v0`
off rostro-main a979268fcb. **No wire break anywhere in it**: runtime logic
only, deployable to the live lab cluster via the proven set_code path
([[FORKLESS-UPGRADES]]) as spec 103, continuous history.

- **P0 — real rotation machinery.** Finite `SessionPeriod` (**4h = 2400
  blocks**), `pallet_session::historical` wired, `MaxSetIdSessionEntries`
  nonzero, `KeyOwnerProof` = real historical membership proof. The validator
  *set* stays fixed (`SessionManager` stays `()`; NPoS staking is its own
  future workstream) but keys actually rotate at session boundaries and
  GRANDPA set_ids advance. Nothing on the star has ever exercised an
  authority-set change; P0 makes that a routine event.
- **P1 — lineage pallet** (new purpose = new pallet,
  `pallet-rostro-key-lineage`): records `(validator, grandpa_key,
  era_range)` permanently; rejects `set_keys` re-registering any previously
  seen key (the fresh-key primitive); enforces the forced-rotation deadline:
  a key older than **K = 7 eras** (era = the 24h `membership_epoch`)
  disables the validator from the next set. Hard cutover, no grace window;
  re-entry is automatic on a fresh `set_keys`, which is also the
  post-compromise healing path. One liveness floor: if enforcement would
  produce an *empty* authority set the previous set is kept and an alarm
  event emitted — an empty GRANDPA set is unrecoverable chain death, not a
  hard cutover. **Design point RESOLVED (2026-07-03): forced rotation stays
  on account-signed `set_keys`; chained self-rotation rejected.** Deciding
  reason: the slow chain's job is post-compromise healing, which requires
  entropy from *outside* the ratchet — certifying the next key with the
  current key roots the slow chain in the fast chain, so a thief of the
  current key owns every future key. The account key stays in design B
  anyway (as "recovery root"), so B only moves the account-key touch from a
  weekly routine to incident response. Also: `set_keys` already exists with
  a proof-of-possession check, so A adds zero new registration surface,
  where B's session-key-signed extrinsic would be a second Config-bindable
  verifier of the same input. The cadence cost of A is one account-key
  signature per ≤7 days, signable offline. Mainnet ergonomics refinement
  (recorded, not P1): a scoped rotation-proxy capability — a hot key that
  can *only* call `set_keys`, revocable by the cold account key — gives B's
  automation without B's healing loss; belongs to the low-barrier installer
  workstream. Mechanically, P1 lands as one surgical vendored seam
  (`pallet_session::Config::KeyProvenance`, a note-and-veto hook inside the
  `set_keys` transaction — the only point that sees every registration
  path) plus the new pallet, which is both the provenance hook and the
  session manager under `NoteHistoricalRoot`.
- **P2 — offences.** Wire grandpa `EquivocationReportSystem` into a real
  offence sink; add the retired-key canary offence (signature from a
  lineage-retired key over a GRANDPA-domain preimage scoped after
  retirement). Testnet consequence = disable + permanent record; sink shaped
  so staking slashing plugs in later.
- **P3 — star proof + deploy. PROVEN on the live 5-node star 2026-07-03**
  (`scripts/star-scenarios/session-rotation-01-lifecycle.sh`, full PASS,
  finalized #266 at teardown): live rotation with finality riding through
  the set_id bump (lineage recorded retirement at set 1, successor active
  at set 2); canary evidence from a leaked retired key accepted from a
  non-validator reporter, owner disabled with reason Offence and excluded
  from the next set; healing via fresh `set_keys` re-entry; deadline-miss
  exclusion at the era boundary (eve, reason DeadlineMissed, key retired
  on drop-out) with finality continuing on 4 authorities; validator
  channel certs + heartbeats flowing across every set change. Two
  bootstrap gaps found and fixed on the way: (a) the star/dev/local
  genesis never populated `pallet_session`, so GRANDPA authorities now
  flow through session genesis (`on_genesis_session` initializes
  pallet_grandpa) — without this, rotation was structurally inert on any
  chain from these specs; (b) live chains whose genesis predates session
  ownership bootstrap via root-only `force_roster` (register fresh keys
  FIRST, then force the roster — see
  rostro-testnet-lab/playbooks/07-session-rotation-bootstrap.sh). The
  proof ran under the scenario-only `lab-fast-lifecycle` runtime feature
  (25-block sessions/eras); production constants are untouched. Spec 103
  set_code to the lab chain lands the machinery in a safe holding state
  (empty roster = genesis authorities persist) until the 07 bootstrap
  runs. Spend-committee behaviour under a rotated set remains to be
  observed organically on the lab chain (it reads live authority state
  the same way the channel does; the channel is now rotation-proven).

### 3.0.1 NPoS cutover (spec 106) — roster is now staking-elected

The fixed-roster era described above ended with the NPoS wiring
(docs/NPOS.md): `KeyLineage` no longer captures/freezes a roster and the
root-only `force_roster` bootstrap call is gone. The pallet's session-manager
seat is unchanged, but each session it now asks `Config::ElectedSet`
(pallet-staking) for the intended set; staking answers at era boundaries and
`None` mid-era, where KeyLineage re-feeds its `PlannedSet` (the last election
result) so key-age enforcement still runs every session and healed validators
re-enter without waiting out the era. Everything else in this document —
fresh-key primitive, lineage records, canary, deadline, healing, the
liveness floor — is unchanged. Sessions themselves are now sassafras-epoch
-driven (~1h) rather than 4h `PeriodicSessions`, and `set_keys` registers a
`{ sassafras, grandpa }` bundle with a two-signature proof-of-possession
tuple (the GRANDPA reuse ban applies to the grandpa key only).

### 3.1 Operational invariant: rotation keys must be node-*readable*

Surfaced deploying spec 103 to the lab cluster 2026-07-04, and load-bearing
for every privilege-dropped deployment (mainnet validators run the node as an
unprivileged uid under the supervisor, distinct from whoever inserts keys).

A validator arms itself for the new authority set **without a restart**: the
GRANDPA client re-resolves its local voting key from the keystore on every
set change (`local_authority_id` → `keystore.has_keys`), so a freshly
registered key is picked up automatically at its activation boundary — *iff
the node process can read the key file*. The failure mode is silent and
asymmetric: `LocalKeystore::has_keys` opens the key file and its caller
discards any error (`.ok()`), so a key file that **exists but is unreadable**
by the node (e.g. inserted as root, mode 0600, while the node runs as another
uid) is indistinguishable from an absent key. The node becomes a non-voter
with no log line. On a set at or near its 2/3 threshold (the lab's 2-of-2 has
zero slack) one silently-non-voting validator stalls finality at the
handover block; larger sets with slack mask it, which is exactly why the P3
star proof (5 validators, and run without privilege drop) never caught it.

Invariant, therefore: **the rotation runbook inserts the new GRANDPA key
readable by the node uid** — insert as that uid, or `chown` the key file to
it before the activation boundary — and adds **no restart step**. Confirmed
2026-07-04 by a 2-of-2 fast-lifecycle reproduction: a node-readable insert
with no restart armed the voter at the set change and finality rode straight
through. As defence-in-depth against the silent case, the keystore now emits
a loud warning when a key file exists but cannot be opened (was swallowed);
this is client-side, so it ships via the node-binary release path, not
`set_code`.

## 4. Workstream 2: pq-finality-v0 (wire break, NOT testnet-gating)

Worktree `/home/coder/Rostro-pq-finality/`, branch `pq-finality-v0` off
rostro-main 5daa9f4865. **Scheme LOCKED 2026-07-05: hybrid dual-signature
per vote, ed25519 + SLH-DSA-SHA2-128s** (FIPS 205 final, RustCrypto
`slh-dsa` 0.1.0 vendored per VENDOR.md exactly as `ml-kem` was).
Rationale: stateless (no state-reuse grenade for operators, which matters
until F4 hardware exists), same hybrid philosophy as [[PQ-TRANSPORT]]
(classical security survives a lattice/hash-scheme break, PQ security
survives Shor). Cost accepted: 7920-byte hybrid vote signature (64 ed25519 + 7856
SLH-DSA), ~250 KB justifications at 32 authorities; the `s` (small)
variant halves size + verifies ~2.7x faster than `f` at the cost of
~170 ms signing (once per slot, slack) — chosen for validator SCALE
(a justification is one sig PER validator, verified by EVERY node;
~5.4 MB at 700 validators vs ~11.8 MB for `f`). The
stateful XMSS-style KES alternative is ~6x smaller but carries the state
grenade until the F4 watermark exists; fat and safe wins v0.

Phase 0 LANDED: vendored `slh-dsa` 0.1.0 (one surgical Cargo.toml change —
upstream's `signature 2.3.0-pre.4` pre-release pin can never co-resolve
with stable `signature 2.x`, relaxed to `>=2.0, <3`; KATs prove behavior
unchanged) + `substrate/utils/rostro-hybrid-sig`: both-must-verify hybrid
leaf, FIPS 205 context string as the domain channel with the identical
`M'` framing on the ed25519 half, deterministic signing (no RNG in the
voter hot path), ed25519-strict-first verify order. NIST ACVP
SLH-DSA-SHA2-128s vectors pinned in-crate (the vendored tarball's ACVP
sample skips that set; provenance + filter procedure in the test file).

Phases: vendor `slh-dsa` + KATs (mirror the ml-kem playbook, wire sizes
pinned) → signing crate → grandpa client + primitives surgery (signature
variant through `rostro-multi-key`, **era binding in the vote preimage**,
justification format) → node-side era-key destruction at rollover with the
F3 sealing hook stubbed. Lands as a **sanctioned chain-reset event** (wire
breaks are resets, per the multikey precedent); the testnet absorbs one
planned reset pre-mainnet.

## 5. Sequencing and gating

- Camino testnet genesis gates on **workstream 1 only**.
- pq-finality-v0 lands mid-testnet as a planned reset, or at worst is
  mainnet-genesis material. Decided 2026-07-03: do not gate testnet on it.
- Relation to [[KEYSTORE-AUDIT]]: workstream 1 generalizes F2 (rotation) to
  the GRANDPA key with lineage + offences; F3 (sealing + measured boot) and
  F4 (signer split + watermark) remain mainnet items and are the hardware
  enforcement layer for the ratchet's deletion discipline.
- The from-genesis weak-subjectivity anchor (how old a justification a fresh
  syncer trusts) remains load-bearing until pq-finality + enforced deletion
  land; today that anchor is the canonical-files gate + watchdog. State this
  in operator docs rather than leaving it implicit.

## 6. What this does NOT change

- Sassafras/bandersnatch block-production keys: separate lifecycle, separate
  future thread (rotation there interacts with ticket submission timing).
- The validator channel: cert issuance reads the keystore and
  `grandpa_authorities()` live per epoch, so key rotation should be
  transparent to it (P3 verifies).
- Chat/DR, node-identity, watchdog keys: already separate key material by
  design, untouched.
