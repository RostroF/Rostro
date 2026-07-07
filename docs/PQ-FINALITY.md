# PQ finality: hybrid vote-signature surgery (pq-finality-v0, build spec)

**Status:** build spec for the surgery phases. Phase 0 (vendor + hybrid leaf) LANDED (4ebd6ffbb3).
**Date:** 2026-07-05.
**Context:** workstream 2 of [[CONSENSUS-KEY-LIFECYCLE]] §4. Scheme locked: hybrid ed25519 + SLH-DSA-SHA2-128s per vote, both-must-verify, via `rostro-hybrid-sig`. This doc is the surgery map + resolved design decisions, from a full-tree survey 2026-07-05.

## 0. The one-line finding

The authority signature is bound to ed25519 at exactly ONE place:
`app_crypto!(ed25519, GRANDPA)` in
`substrate/primitives/consensus/grandpa/src/lib.rs:45-48`. Everything
downstream (`AuthoritySignature`, `SignedMessage`, `Commit`,
`GrandpaJustification`, equivocation proofs, warp fragments, the
key-lineage canary) is a type alias over that and follows automatically,
PROVIDED the replacement keeps `RuntimeAppPublic::verify` + `Codec` +
`Clone + Eq`. The `finality-grandpa` 0.16.3 round machine (registry dep)
bounds signatures by `Clone + Eq` only — no size assumptions.

## 1. Resolved design decisions

- **D1 — AuthorityId becomes the 64-byte hybrid pubkey** (ed25519 32 ||
  SLH 32), signature the 7920-byte hybrid. One key, one registry; no
  parallel SLH authority list (two Config-bindable verifiers of one input
  = attack surface, per standing rule). Consumers hardcoding `[u8;32]`
  are ours and get fixed (§3).
- **D2 — new sp-core-level scheme module, not a patched ed25519.**
  `sp_core`-style `hybrid` module (Pair/Public/Signature + CryptoTypeId
  `b"rhyb"`) wrapping `rostro-hybrid-sig`, then the one-line swap to
  `app_crypto!(hybrid, GRANDPA)`. Keystore gains a `hybrid_sign` method
  (the trait is ours); `sign_message` at primitives lib.rs:521 switches
  from `ed25519_sign` to it. Keystore file format: 96-byte secret under
  the existing `gran` key type — rotation playbooks unchanged except key
  length.
- **D3 — deterministic keygen from one 32-byte seed.** `Pair::from_seed`
  derives the ed25519 half by the existing path and the three 16-byte
  SLH seeds (sk_seed, sk_prf, pk_seed) via HKDF-SHA256 expansion of the
  same seed with distinct info strings. Chain-spec
  `authority_keys_from_seed` and the rotation playbook stay one-seed.
- **D4 — era binding rides set_id; no new preimage field.**
  `localized_payload = (msg, round, set_id)` already scopes every vote to
  an authority set, sessions advance set_id, and the lineage pallet
  records activation/retirement set_ids per key. Era→set_id is the
  lineage pallet's existing mapping; adding a redundant era field to the
  vote preimage would be a second source of truth. The spec's "era
  binding" requirement is satisfied by lineage set_id records + the
  canary's strictly-greater rule.
- **D5 — the validator-channel cert signs with the ed25519 HALF of the
  hybrid key** (new keystore method `hybrid_sign_ed25519_component`, or
  the cert module extracts via the hybrid public). Rationale: the cert
  is transport authentication (active-attack-only exposure, lowest
  urgency row of the PQ-TRANSPORT table) and the handshake payload has a
  512-byte budget a 17KB cert would destroy. `ChannelCert.authority_pubkey`
  becomes the 64-byte hybrid id (set-membership check input), signature
  stays 64B ed25519 over the cert domain. PQ-hardening the channel cert
  is a named follow-up, not this workstream.
  **SUPERSEDED (pq-channel-auth-v0, 2026-07-06)**: the named follow-up
  landed. The cert is hybrid-signed by BOTH components (`/v3` cert
  domain via the FIPS 205 context), the `chnl` channel key is itself
  hybrid, and handshakes carry hybrid signatures (`/v5`, protocol
  `/rostro/validator-channel-handshake/5`, 20 KiB caps). The 512-byte
  budget rationale died with it — the handshake was already ~1.4 KB
  after the ML-KEM flight, and at one handshake per pair per session
  the ~17 KB hybrid payload is noise. `hybrid_sign_ed25519_component`
  was removed from the keystore/sp-core/leaf; the replacement seam is
  `rostro_hybrid_sign_with_domain`, which refuses the finality-vote
  domain so a cert or handshake signature can never double as a vote.
- **D6 — runtime verifies hybrid in-runtime (RISC-V), no host function
  yet.** Equivocation `check_equivocation_proof` and the lineage canary
  verify are rare extrinsic paths; SLH-DSA verify is pure no_std Rust.
  If RVM-interpreted verify proves too slow in P3 measurement, a host
  function is the recorded escape hatch.
- **D7 — network caps**: GRANDPA notification protocol max 1 MiB →
  4 MiB. At 128s (7920 B/sig) a 32-authority catch-up is ~0.5 MiB, so
  4 MiB is generous headroom for the testnet set. **At mainnet scale
  this cap MUST be raised**: a ~700-validator justification is ~5.4 MiB
  and a catch-up ~11 MiB (see §5 scale analysis). Warp proof cap stays
  8 MiB.

## 2. Phases

- **P1 — primitives + keystore**: `sp_core::hybrid` module (wraps
  rostro-hybrid-sig; fixed-size Public 64 / Signature 7920 via
  CryptoBytes), keystore `hybrid_sign` + ed25519-component signing,
  `app_crypto!(hybrid, GRANDPA)` swap, `sign_message` funnel. Unit
  proof: sign/verify roundtrip through LocalKeystore, justification
  encode/decode with hybrid sigs.
- **P2 — node + runtime consumers**: the §3 landmine list (validator
  channel cert, active-authority-set, chain-spec seeding, session-key
  decode), D7 cap raise, runtime type re-plumb, lineage pallet mock/tests
  to hybrid. RISC-V runtime build MUST pass (never-skip rule).
- **P3 — star proof + reset**: DONE 2026-07-05 (**at parameter set
  128f**, before the 128s re-cut — see §5),
  `scripts/star-scenarios/pq-finality-01-hybrid-lifecycle.sh` on a live
  5-validator star + observer (lab-fast). PROVEN green: (1) hybrid
  genesis finality — hybrid votes carry consensus from block 0; (2)
  justification size on the wire — 69054-byte (128f) / 86306-byte (128f,
  5-set) stored set-change justification read via `chain_getBlock`; (3)
  live rotation + the retired-key reaper destroying the retired hybrid
  secret while sparing the live successor (fast-chain destruction, F3
  seal-hook stubbed); (4) hybrid canary accepted via in-runtime verify,
  reported by a non-validator; (5) catch-up past the old 1 MiB cap after
  a node restart, no size errors (the D7 raise, live). The 128s re-cut
  (§5) is mechanical (parameter swap; unit + ACVP-KAT + pallet-grandpa
  equivocation + RISC-V-release all green) and preserves the consensus
  mechanism; a confirming star re-run at 128s is recommended but not yet
  done.

  Two findings surfaced by the run, both recorded:
  - **~~Node-config: validators must run `--pool-type single-state`.~~
    RETRACTED 2026-07-06 — this was a TEST-HARNESS ARTIFACT, not a
    fork-aware bug.** The original theory (fork-aware's combined essential
    task tears the node down under sustained hybrid gossip) was WRONG. A
    multi-day root-cause (sp_core-level instrumentation, drop-site
    backtraces, task_manager patient-zero tracing) proved: the crashes
    correlated 1:1 with prometheus `AddrInUse` port conflicts, i.e. a
    PREVIOUS run's local star nodes still alive when the next run started
    (a node can outlive the misleading "Essential task failed. Shutting
    down service." log, which fires on any completion incl. graceful
    shutdown). Two node-sets sharing the fixed dev node-keys (`0x…01`–`05`)
    means identical libp2p peer IDs on one chain → collision → the
    teardown race. Root cause: `TaskStop`-ing scenario runs mid-flight
    bypassed the cleanup trap, leaving colliding nodes. In a CLEAN
    environment, **default fork-aware passes the full hybrid lifecycle**,
    confirmed across 3 consecutive runs (incl. the uninstrumented shipping
    binary), zero `AddrInUse`, zero real crashes. fedora (remote lab host,
    `--chain local`) ruled out: no foreign peer IDs in any run. **Decision:
    default `fork-aware`** (upstream's invested pool); no override, no
    patch. Lesson: verify a clean process/port environment before
    instrumenting code.
  - **Warp sync is blocked by Sassafras, orthogonal to PQ.** A warping
    observer fails at target-block import
    (`SassafrasApi::current_epoch: UnknownBlock`) upstream of any GRANDPA
    warp proof, because warp skips the ancestor blocks carrying epoch
    descriptors. Hybrid-justification-over-warp is therefore unproven
    in-lab pending Sassafras warp-target support (its own workstream); it
    is NOT a pq-finality defect. Scenario phase 6 records this as a NOTE
    and only fails if the Sassafras blocker is absent.

## 3. Landmine list (from the survey; fix in P2)

| Site | Issue |
|---|---|
| `primitives/consensus/grandpa/src/lib.rs:45-48, 521` | the binding + `ed25519_sign` funnel (P1) |
| `client/keystore/src/local.rs:246-252` | fixed 64-byte return; add hybrid path (P1) |
| `client/consensus/grandpa/src/lib.rs:734` | 1 MiB notification cap vs 1.1 MiB catch-ups (D7) |
| `client/consensus/grandpa/src/warp_proof.rs:61` | 8 MiB proof cap → ~14 fragments/proof (accepted, D7) |
| `bin/gemini-node/src/validator_channel.rs:198-215, 272, 295` | `[u8;32]` authority pubkey; cert `sig.0` 64B from GRANDPA key (D5) |
| `utils/rostro-validator-channel/src/lib.rs:372-377` | `ChannelCert{authority_pubkey:[u8;32], signature:[u8;64]}` (D5) |
| `bin/gemini-node/src/active_authority_set.rs:72-77` | `authority_id_to_bytes -> [u8;32]` + assertion → 64B |
| `bin/gemini-node/src/chain_spec.rs:30-63` (+rostro-node mirror) | seed → GrandpaId derivation (D3) |
| `frame/rostro-key-lineage` mock.rs:144-146, tests.rs | concrete ed25519 fixtures → hybrid (pallet logic itself is alias-clean) |
| `utils/rostro-multi-key` | UNTOUCHED — transaction sigs are a different thread (PQ-SIGNATURES.md); GRANDPA never routes through it |

## 4. What does NOT change

`localized_payload`, `check_message_signature`, `check_equivocation_proof`,
`GrandpaJustification` structure, all `communication/` verification loops,
warp fragment verification, and the lineage canary's verify call — all
scheme-agnostic through the alias. `finality-grandpa` stays a registry dep.
Sassafras/bandersnatch untouched. Account signatures (RostroSignature)
untouched. Justification persistence grows ~270× per artifact but is
written once per 512 blocks (~1 KB/block amortized, accepted in the
scheme decision).

## 5. Scheme re-cut: 128f → 128s (2026-07-05, post-P3)

P3 proved the mechanism at **SLH-DSA-SHA2-128f**. The user then flagged
that mainnet validator count is likely ~700 (not the ≤32 the sizing
assumed), where the non-aggregatable hash-based signature bloats
justifications. Measured on-box (`rostro-hybrid-sig/tests/param_bench.rs`,
run `--release --ignored --nocapture`):

| set | sig | sign | verify | just @700 (full) | verify-all @700 |
|---|---|---|---|---|---|
| 128f | 17088 B | 8 ms | 0.47 ms | ~11.8 MiB | ~330 ms |
| **128s** | **7856 B** | 170 ms | **0.17 ms** | **~5.4 MiB** | **~120 ms** |
| 192s | 16224 B | 476 ms | 0.40 ms | ~11.2 MiB | ~280 ms |

**128s chosen.** A justification carries one signature per validator and
every node verifies all of them, so size + verify speed are the
bottlenecks; per-validator signing (once per 6 s slot) is slack. 128s
halves the size and verifies ~2.7x faster, paid for entirely by slower
signing (170 ms, 2.8% of a slot). 192s is strictly worse for our profile
except NIST security category (3 vs 1); category 1 (~2^128) is accepted.

**Bonus — parity-scale-codec vendor REVERTED.** At 128f the hybrid vote
(17152 B) exceeded parity-scale-codec's 16 KiB `decode_vec_chunked`
element ceiling, forcing the P2 vendor patch. At 128s the vote is 7920 B,
back under the ceiling, so the vendor + `[patch.crates-io]` entry were
removed and the workspace uses registry `parity-scale-codec 3.7.5`
unmodified. One fewer vendored crate to carry.

**Still open at ~700-1000 scale** (not solved by 128s alone): the D7
notification cap (4 MiB) must rise to ~16 MiB, and even 128s is ~5.4 MiB
per justification. If that is still too heavy, the remaining levers are
committee finality (a signing subset), recursive-proof compression of the
justification (constant size, dovetails with the execution-proof
direction), or ML-DSA-65 (~2.3x smaller than 128s but re-couples finality
to the transport/keyring lattice family). Deferred decision; 128s is the
right floor for hash-based assumption diversity.

## 6. Validator-count ceiling under the network caps (128s)

The binding constraint is the GRANDPA **notification protocol cap**, and
the largest message on it is the **catch-up** — it aggregates a round's
prevotes AND precommits (`finality_grandpa::CatchUp` = `Vec<SignedPrevote>`
+ `Vec<SignedPrecommit>`), so at full participation it is **2N**
signatures. Each signed-vote entry is 8020 B (36 B vote target + 7920 B
hybrid signature + 64 B hybrid id). Therefore:

```
catch-up bytes ≈ 2 · N · 8020
N_max(cap) ≈ cap / 16040
```

| Notification cap | Max validators (catch-up bound) | justification at that N |
|---|---|---|
| **4 MiB (current, D7)** | **~261** | 2.0 MiB |
| 8 MiB | ~522 | 4.0 MiB |
| 12 MiB | ~784 | 6.0 MiB |
| 16 MiB | ~1045 | 8.0 MiB |
| 32 MiB | ~2091 | 16.0 MiB |

Secondary ceilings (not the tightest, but hard): the warp-proof fragment
cap (8 MiB) bounds a single justification (N·8020) → **~1045 validators**;
the libp2p response cap `MAX_RESPONSE_SIZE` (16 MiB) → ~2091.

Concretely: the **current 4 MiB cap tops out at ~260 validators.** For the
~700 mainnet target, a catch-up is ~10.7 MiB and a justification ~5.4 MiB,
so the notification cap must go to **~12 MiB** (warp cap OK). For ~1000,
catch-up ~15.3 MiB and justification ~7.6 MiB → notification cap ~16 MiB
and the warp cap needs a nudge too. So **~1000 validators is roughly the
architectural ceiling** with cap bumps alone; beyond that needs committee
finality or recursive-proof compression (§5).

## 7. Version decision: 128s is v1; v2 is a post-Q-day contingency

**128s ships as the v1 finality-vote scheme.** The whole design is a
hybrid (ed25519 + SLH-DSA), both-must-verify, precisely so that no single
cryptographic break forces a scramble:

- **If SPHINCS+/hash-based falls first** (unexpected — its only surface is
  SHA-2 preimage resistance, the most conservative assumption in the PQ
  portfolio), the ed25519 half still holds pre-Q-day, and v2 swaps the PQ
  component to a lattice scheme (ML-DSA-65) — which also happens to be
  ~2.3x smaller, easing the §6 ceiling.
- **If Dilithium/lattice falls first** (the live cryptanalysis target;
  SIKE and Rainbow, both NIST finalists, fell classically in 2022), then
  our choice of hash-based for finality is vindicated and v1 needs no
  change — while the *transport* (ML-KEM) and *account keyring* (ML-DSA)
  threads, which ARE lattice, are the ones that would pivot. Finality
  being on a different family than everything else is the whole point of
  the monoculture argument (§5 / PQ-TRANSPORT).

Either way we are hedged: the family that breaks first tells us which
layers to migrate, and the hybrid construction buys the migration window.
v2 is a contingency to be triggered by cryptanalysis, not a scheduled
milestone. The `app_crypto!(rostro_hybrid, GRANDPA)` seam + the
`rostro-hybrid-sig` leaf make a component swap a bounded change (one
parameter or one scheme, re-pin wire sizes, fresh KATs — as this very
128f→128s re-cut demonstrated end to end).
