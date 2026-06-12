# Camino testnet bringup — handoff

**Last touched:** 2026-05-15
**Branch:** `rostro-main`
**HEAD:** `a57c3f245b` (rostro-trace: adapt to vendored plonky3 0.5.1 FriParameters API)

This document is the working state for the **Camino testnet bringup** thread. Pick up here when you come back.

---

## Where we left off

`rostro-main` is now the actual main. All historical branch work has been merged in. The chain binary (`rostro-node`) builds:

```bash
SKIP_WASM_BUILD=1 cargo check -p rostro-node
# Finished `dev` profile, only warnings
```

This session was about three things, in order:

1. **Audit hardening of RostroVM** (Tier 2 crypto intrinsics) — done, landed via the `vm-research` merge.
2. **Merging the branch landscape into `rostro-main`** so we have a real main to build from — done, both `phase8e/personhood-pallet` and `vm-research` are merged in as `--no-ff` merge commits; pre-existing `rostro-trace` build break (vendored plonky3 API drift) fixed.
3. **The Camino testnet integration work** — not started. This document tells you what's next.

---

## Camino testnet — what it is

Per the session conversation:

- **Camino is the public testnet** (per CLAUDE.md it replaces Paseo in the lineage).
- **Closed beta**: invited node operators run validators.
- **Multiple validators**: 3 local nodes are the immediate target (the 64GB RAM upgrade unlocks this — see `dev_machine_ram_upgrade` memory).
- **Faucet**: testnet has a fountain so beta users can mint tokens.
- **RVM as runtime executor**: WASM is sunset for the runtime; RISC-V/RVM is the chosen path. Camino is the proof point that "RVM-runtime works for consensus."
- **No smart contracts at launch**: this was the explicit call — Camino runtime-only; contract execution is a v0.2+ question.

---

## Locked architectural decisions (this session)

These are settled; don't re-litigate unless something material changes:

1. **RVM gas anchor:** 1 RVM gas ≈ 1 ns of native work on the audit reference machine. The substrate `Weight` adapter multiplies by 1000 at the runtime boundary (substrate Weight = picoseconds, RVM gas = nanoseconds). One conversion constant in one place. See [substrate/external/rostrovm/polkavm/src/rostro_intrinsic_gas.rs](../substrate/external/rostrovm/polkavm/src/rostro_intrinsic_gas.rs) header.

2. **msg_len hard cap:** 4 MiB. Any blake2b / keccak / ed25519 ecalli with `msg_len > MAX_INTRINSIC_MSG_LEN` is rejected with the existing memory-access-failure code path.

3. **secp256k1_recover policy:** Strict Ethereum-compat — reject high-s (`s > n/2`) via `Signature::normalize_s().is_some()`; reject `recovery_id > 1` (the SEC1 x-reduced bit). Matches Ethereum's ECRECOVER + EIP-2 / BIP-146.

4. **Ed25519 backing crate:** `ed25519-zebra` 4.2.0 (Zcash Foundation ZIP-215 reference impl, dual MIT/Apache-2.0). Replaced `ed25519-compact` (MIT-only, malleability-permissive). ZIP-215 enforces s < L canonicality + deterministic cofactored verify equation.

5. **No `catch_unwind` wraps** on Tier 2 native bodies. The verify-path panic audit across all 7 crypto crates (ed25519-zebra, curve25519-dalek, k256, blake2, sha3, fips204, p521) showed no panic vectors on adversarial-but-well-formed input. Substrate's `sp-panic-handler` stays the appropriate outer boundary.

6. **Smart contracts: not in v0.1.0.** Camino is runtime-only. Contracts deferred to a later milestone where the contract-execution sandbox can be properly hardened (subprocess isolation, restricted ecalli set, etc.). v0.1.0 = no adversarial bytecode in the consensus path.

7. **Apache-2.0 zone placement:** New RVM-integration crates go under `substrate/utils/` with the `rostro-*` prefix. `substrate/client/` is the GPL3 zone — don't put new Rostro work there.

8. **`rostro-trace` is the secret-sauce execution-proof pipeline** (tensor-DA-as-PCS), not a VM-test tool. `rostro-node` depends on it. Don't remove it.

---

## Camino bringup work list (unsequenced)

You decide the order. No time estimates — those were rejected as a framing.

### Branch + workspace setup
- [ ] Create the Camino integration branch off `rostro-main`. Name TBD (`phase9/rvm-runtime` or `camino/integration` or whatever fits your naming).
- [ ] Add `substrate/external/rostrovm/` to the workspace's `exclude` list if not already covered. (Verify — it might already be; check `Cargo.toml` after the vm-research merge.)

### New Apache-2.0 zone crates (under `substrate/utils/`)
- [ ] `rostro-executor` — implements substrate's executor trait against polkavm. Module loading, instance creation, run loop, trap → substrate-error mapping, gas → Weight conversion.
- [ ] `rostro-runtime-builder` — substrate-wasm-builder analog. Build-script crate that cross-compiles a runtime crate to the PVM target via nested `cargo build`.

### PVM toolchain wiring
- [ ] Settle the PVM target spec the runtime cross-compiles to (polkavm has a target spec; pick the right one for runtime use, not contract use).
- [ ] Confirm `rust-src` is present (CLAUDE.md says it's already required for the PolkaVM target).
- [ ] Build flags / linker args matching what polkavm-derive expects.

### Host function bindings (`sp-io::*` → PVM ecalli)
The big one. Categories:
- [ ] Storage: `set`, `get`, `clear`, `read`, `exists`, `root`, child-storage variants, prefix iter, append.
- [ ] Hashing: `blake2_128`, `blake2_256`, `twox_64`, `twox_128`, `twox_256`, `keccak_256`, `sha2_256`.
- [ ] Crypto: `ed25519_verify`, `sr25519_verify`, `ecdsa_verify`, `secp256k1_ecdsa_recover`. (For ed25519 and secp256k1, route through the existing Tier 2 intrinsics so you get ZIP-215 + strict-mode rejections for free.)
- [ ] Allocator: malloc / free shim against PVM sbrk.
- [ ] Logging / misc: `print_utf8`, `print_hex`, `panic_handler`, `runtime_version`.
- [ ] Trie family: `blake2_256_ordered_root`, `keccak_256_ordered_root` (if used by stake/auth pallets in the chosen pallet set).
- [ ] Offchain family: usually only if validators do offchain work that touches sp-io via the runtime path. Skip if not.

### Camino runtime crate
- [ ] Pick the runtime crate name (probably `camino-runtime`, modeled after the existing `gemini-runtime`).
- [ ] Pallet inventory — DECISION OPEN, see below.
- [ ] Cargo.toml: PVM target, polkavm-derive on runtime side for `polkavm_export` of dispatch entry points, `polkavm_import` for host fns.
- [ ] All pallet deps must compile to PVM target (no_std clean).
- [ ] Build pipeline produces a PVM blob the executor can load.

### Node binary
- [ ] Service code that wires `rostro-executor`. CLI flag if both executors should be selectable; RVM-only if you're committing.
- [ ] Genesis state spec for Camino: chain ID, initial validators, sudo key, faucet account funding.

### Consensus + networking
- [ ] **Consensus choice:** Aura (simpler, suitable for closed-beta 3-validator setup) or Sassafras (the locked production design but heavier bringup). DECISION OPEN.
- [ ] Bootnode setup. Per `[Phase Gemini]` memory: `rostro.org` DNS bootnode for the post-laptop phase.
- [ ] Validator key management (each validator generates + holds its own session keys).
- [ ] Network handshake: ChaCha20-Poly1305 + Noise XX per-session FS (locked). The Signal Double Ratchet at gossip layer is v0.2, NOT Camino-v0.1.

### Faucet
- [ ] Pre-funded sudo account or dedicated faucet account in genesis.
- [ ] HTTP endpoint (or simple RPC method) — takes destination + transfers fixed amount.
- [ ] Rate-limit per IP / per dest if you want it; probably fine to skip for closed beta.

### Test plan (the deliverable Camino is)
- [ ] 3 local validators peer deterministically.
- [ ] Block production observed (block height advances).
- [ ] Block import / finality on all 3.
- [ ] Tx submission via RPC produces finalized state change.
- [ ] Faucet endpoint works end-to-end.
- [ ] Closed-beta operators can run a node from a documented setup (script + README).

### Pre-existing work to mine first (not committed; survey)
- [ ] `/home/coder/jar/grey/` — Wei Tang's grey/javm. Per memory `[Wei Tang collaboration & attribution]`, blessed, Apache-2.0 adoptable. If he already wrote a substrate-runtime-on-PVM executor or anything close, that saves work. Worth grepping before writing `rostro-executor` from scratch. Reminder from memory `[feedback_rostrovm_worktree_location]`: don't pull in his microkernel angle — Rostro wants faster VMs, not a supercomputer.

---

## Open decisions blocking the bringup

These need a call before some of the work-list items can be started:

1. **Camino integration branch name + base.** Probably off `rostro-main`. Name your call.

2. **Camino runtime pallet inventory.** Two shapes were on the table:
   - **Minimal:** `frame_system` + `pallet_balances` + `pallet_sudo` + `pallet_timestamp` + consensus pallet (Aura or Sassafras). Lowest-risk for a launch; PoP/BTOW/RNS land in a later round.
   - **Headline:** all of the above + `pallet_rostro_personhood`, `rostro-multi-key`-using accounts, RNS pallets, ZK-PKI verifier pallet, Sassafras deps. Higher risk; every heavy pallet's host-fn surface needs to work end-to-end.
   - **Hybrid:** minimal core first, pull in PoP/BTOW second.

3. **Consensus pallet choice for Camino.** Aura (simple PoA, validators take turns by index) vs Sassafras (locked production design — Ring VRF anonymous slot assignment, heavier).

4. **Survey grey/javm before writing rostro-executor, or write from scratch?** Worth ~a day of survey if you think Wei already has substrate-on-PVM machinery we could lean on (without adopting his microkernel angle).

---

## Open audit items deferred to post-testnet polish

These are tracked in [docs/SECURITY-AUDIT-TIER2-INTRINSICS.md](SECURITY-AUDIT-TIER2-INTRINSICS.md) — not blockers for Camino but should land before Rostro mainnet.

- **A8 (timing side-channels):** Gas table currently anchored on AVERAGE measured native runtime; should re-anchor on WORST-CASE + 10% headroom for audit-defensibility. Plus separate concern about same crypto crates being used by off-chain validator code with secret keys. See memory `audit_a8_timing_followup`.
- **A9 (Goldilocks intrinsic ABI canonicality contract):** Design call — document the contract vs. canonicalize-in-body vs. add `*_canonical` variants. Affects PoP STARK verifier ergonomics + STARK bench numbers.
- **A12 pallet layer:** Small-order Ed25519 pubkey rejection at identity-binding sites. Three known binding sites in the main tree:
  - `substrate/utils/rostro-multi-key/src/lib.rs` (BTOW Ed25519 raw 32-byte pubkey)
  - `substrate/frame/pallet-rostro-personhood/` (`mint_pop`'s `bound_account`)
  - `~/Polkadot/pns-pallets/` (RNS owner-key registration, currently out-of-repo)

  Fix recipe: precompute 8 small-order encodings as `const [[u8; 32]; 8]`, reject by exact byte-match at each binding site (8 byte-array compares, ns-scale).

---

## What's running in CI today

After this session's work, `cargo test -p polkavm --test kat_vectors` runs 13 Known Answer Tests across:
- blake2b_256 (empty + "abc")
- keccak_256 (empty + "abc")
- ed25519_verify (RFC 8032 Test 1 + Test 2 + tamper-rejection)
- secp256k1_recover (positive vector + high-s rejection + recovery_id=2 rejection)
- goldilocks_mul / add / sub (boundary cases)
- poseidon2_perm (deadbeef state, non-zero modification check)

`examples/verify_audit_a1_a2.rs` validates A1/A2/A11 mitigations end-to-end (gas accounting + cap + strict secp256k1 rejections). `examples/test_crypto.rs` runs the 13-workload AGREE matrix across all 6 VM backends.

These are the live regression-tests for the audit work. If they break, the audit posture has drifted.

---

## Branch landscape on origin

| Branch | Purpose |
|---|---|
| `rostro-main` | Real main. Where Camino integration should branch from. |
| `phase8e/personhood-pallet` | Fully merged into rostro-main; preserved for history / cherry-pick. |
| `vm-research` | Fully merged into rostro-main; preserved for history / cherry-pick. |
| `phase2/fingerprint-registry` | Fully contained in phase8e (which is now in rostro-main). No standalone value. |
| `phase1-5/rns-wiring`, `tier0/api-fork-poc` | At rostro-main exactly, no diverging work. |
| `stage3/plonky3-base`, `stage4/*`, `stage5/solochain` | Historical superseded stages. Behind rostro-main. |
| `polkadot-sdk-baseline` | Upstream Polkadot SDK tracking branch. **Never merge into rostro-main.** |
| `stable2603` | Substrate upstream stable backport. **Never merge into rostro-main.** |

---

## Files to read first when picking this up

In order of usefulness for re-orienting:

1. This file.
2. [docs/SECURITY-AUDIT-TIER2-INTRINSICS.md](SECURITY-AUDIT-TIER2-INTRINSICS.md) — full Tier 2 audit memo with A1-A13 + statuses. Closed items have their rationale documented.
3. [substrate/external/rostrovm/polkavm/src/rostro_intrinsic_gas.rs](../substrate/external/rostrovm/polkavm/src/rostro_intrinsic_gas.rs) — gas table; the runtime-integration ×1000 note is in the header.
4. [substrate/external/rostrovm/polkavm/tests/kat_vectors.rs](../substrate/external/rostrovm/polkavm/tests/kat_vectors.rs) — the live KAT regression suite.
5. `git log --oneline --graph rostro-main -20` — see how the merge picture looks.

## Relevant memory pointers

The `/home/coder/.claude/projects/-home-coder-Rostro/memory/MEMORY.md` index has the live state. Highest-relevance entries for this thread:

- `phase_gemini` — Camino's predecessor; bootnode + handshake decisions
- `low_barrier_north_star` — installer-driven setup story for closed-beta operators
- `btow_chain_side_progress` — current state of `rostro-multi-key`
- `rostrovm_design_locked` — what RVM is + isn't
- `rostrovm_h1_tier2_outcome` — VM optimization arc that landed
- `audit_a8_timing_followup` — A8 reframing pending
- `working_primitives` — what real working code exists out-of-repo (paseo-node, pns-pallets, dotwave)
- `secret_sauce` — rostro-trace's actual role (tensor-DA-as-PCS); internal only

Linked: [[phase_gemini]], [[phase_star]], [[network_vs_binary_lineage]], [[rostrovm_design_locked]], [[rostrovm_h1_tier2_outcome]], [[audit_a8_timing_followup]], [[btow_chain_side_progress]], [[crypto_stack_v1]], [[wei_tang_collaboration]], [[grey_jar_local]], [[feedback_client_dir_gpl3]], [[feedback_workspace_vs_runtime]], [[dev_machine_ram_upgrade]], [[testnet_scope]], [[low_barrier_north_star]], [[secret_sauce]], [[lab/build-invocation]], [[lab/phase-h-outcome-20260525]].
