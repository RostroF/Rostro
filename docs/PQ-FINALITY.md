# PQ finality: hybrid vote-signature surgery (pq-finality-v0, build spec)

**Status:** build spec for the surgery phases. Phase 0 (vendor + hybrid leaf) LANDED (4ebd6ffbb3).
**Date:** 2026-07-05.
**Context:** workstream 2 of [[CONSENSUS-KEY-LIFECYCLE]] §4. Scheme locked: hybrid ed25519 + SLH-DSA-SHA2-128f per vote, both-must-verify, via `rostro-hybrid-sig`. This doc is the surgery map + resolved design decisions, from a full-tree survey 2026-07-05.

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
  SLH 32), signature the 17152-byte hybrid. One key, one registry; no
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
  4 MiB (catch-up messages carry up to 2×32 sigs ≈ 1.1 MiB, exceeding
  the current cap; commits ≈ 544 KB fit but without margin). Warp proof
  cap stays 8 MiB (≈14 set-handoff fragments per proof instead of
  thousands: more round-trips on warp sync, functionally intact;
  revisit only if warp sync UX degrades on the lab).

## 2. Phases

- **P1 — primitives + keystore**: `sp_core::hybrid` module (wraps
  rostro-hybrid-sig; fixed-size Public 64 / Signature 17152 via
  CryptoBytes), keystore `hybrid_sign` + ed25519-component signing,
  `app_crypto!(hybrid, GRANDPA)` swap, `sign_message` funnel. Unit
  proof: sign/verify roundtrip through LocalKeystore, justification
  encode/decode with hybrid sigs.
- **P2 — node + runtime consumers**: the §3 landmine list (validator
  channel cert, active-authority-set, chain-spec seeding, session-key
  decode), D7 cap raise, runtime type re-plumb, lineage pallet mock/tests
  to hybrid. RISC-V runtime build MUST pass (never-skip rule).
- **P3 — star proof + reset**: fresh genesis (wire break = the sanctioned
  reset), 3-validator star: finality through set changes with hybrid
  votes, justification sizes measured on the wire, catch-up after a
  restarted node (exercises the raised cap), equivocation + canary
  submission with hybrid proofs, era rollover key destruction (node-side
  deletion of the retired hybrid secret; F3 sealing hook stubbed), warp
  sync across ≥2 set changes. Then lab deployment decision.

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
