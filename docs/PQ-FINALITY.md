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
  - **Node-config: validators must run `--pool-type single-state`.** The
    default fork-aware txpool's combined essential task (a 5-way
    `tokio::select` over listener/revalidation/import-sink/dropped-monitor/
    metrics) tears the node down if any sub-stream ends, and does so
    reproducibly ~15 min into sustained hybrid gossip (17 KB sigs ≈ 100x
    classical GRANDPA bandwidth). Single-state has no such combined-select
    and rides the load through the full lifecycle. This is a real
    mainnet concern — fork-aware would crashloop validators under hybrid
    load — and a candidate for the node default, flagged for decision.
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
