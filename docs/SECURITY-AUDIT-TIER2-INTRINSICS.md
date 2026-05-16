# Security audit: RostroVM Tier 2 intrinsics

**Audit date:** 2026-05-15
**Scope:** Native precompile bodies and dispatch wiring added in Phase 1, 2, and 3 of the RostroVM optimization arc — `ROSTRO_INTRINSIC_*` IDs 100-103 (goldilocks), 110 (dilithium), 111 (p521), 120 (blake2b), 121 (keccak), 122 (ed25519), 123 (secp256k1_recover), 130 (poseidon2).
**Reviewers:** ProdigalWon + Claude
**Status:**
- A1 + A2 + A6 + A7 + A10 + A11 + A12 + A13 mitigations LANDED 2026-05-15 (see "Implementation status" below).
- A3 + A4 + A5 + A8 are pass / defense-in-depth.
- A9 (Goldilocks ABI contract) remains OPEN — design call deferred for separate session.

---

## TL;DR

Two consensus-critical issues need fixes before any of these intrinsics can be wired into a runtime that serves untrusted bytecode:

- **A1 (Critical, DoS):** All `ecalli` instructions cost **1 gas** under the naive cost model, regardless of which intrinsic runs. `ecrecover` is ~159 µs of native work for 1 gas; a malicious blob can overshoot a 6 s block deadline by 2,600× using a fraction of its gas budget.
- **A2 (Critical, DoS):** `blake2b_256`, `keccak_256`, and `ed25519_verify` accept unbounded `msg_len` and scale linearly with input size. Compounds A1.

The remaining surface (aliasing, fail-path state, native FFI, determinism, panic propagation) is mostly clean — those findings are recorded below as either passing or as defense-in-depth items.

---

## A1 — `ecalli` charges 1 gas regardless of native intrinsic cost (Critical, DoS)

**Where:** `polkavm/src/gas.rs:103` (`CostModel::naive()` sets `ecalli: 1`), `polkavm/src/interpreter.rs:2900-3104` (FAST_OP_ECALLI dispatch arms perform no per-intrinsic charge), `rostro-vm-bench/src/runners/polkavm_runner.rs:48-208` (JIT-path host dispatch likewise charges nothing).

**Threat model:**
- Adversary submits a runtime extrinsic (or a shop sidecar blob) that contains a tight loop calling one of the heavy intrinsics.
- Validator runs the blob during block production / import. Per-instruction gas accounting passes (one ecalli = one gas, well under budget), but wall-clock runs orders of magnitude over the block deadline.
- Result: block production missed, chain liveness degraded; if many validators are affected, finality stalls.

**Numbers from our own bench harness (RVM-INT, 2026-05-15):**

| ID | Intrinsic | Native runtime | Gas charged | Effective ns/gas | Vs. `add_64` (~1 ns/gas) |
|---|---|---|---|---|---|
| 100 | goldilocks_mul | ~2 ns | 1 | ~2 | 2× |
| 101 | goldilocks_add | ~1 ns | 1 | ~1 | 1× |
| 102 | goldilocks_sub | ~1 ns | 1 | ~1 | 1× |
| 103 | goldilocks_inv | TBD | 1 | TBD | TBD |
| 110 | dilithium_verify | ~135 µs | 1 | ~135,000 | **~135,000×** |
| 111 | p521_ecdsa_verify | TBD (>100 µs) | 1 | TBD | TBD |
| 120 | blake2b_256 (1 KB) | ~17 µs | 1 | ~17,000 | **~17,000×** + linear in msg_len |
| 121 | keccak_256 (1 KB) | ~18 µs | 1 | ~18,000 | **~18,000×** + linear in msg_len |
| 122 | ed25519_verify | ~48 µs | 1 | ~48,000 | **~48,000×** + linear in msg_len |
| 123 | secp256k1_recover | ~159 µs | 1 | ~159,000 | **~159,000×** |
| 130 | poseidon2_perm | ~1 µs | 1 | ~1,000 | ~1,000× |

**Both backends affected:**
- **Interpreter:** `FAST_OP_ECALLI` arm dispatches the native body inline, then `offset += 1`. The standard ecalli gas (1 unit, stamped on the basic block via `gas_visitor`) is the only charge.
- **JIT:** the bench harness's `dispatch_rostro_intrinsic` (`polkavm_runner.rs:48`) likewise runs the native body without any gas deduction. The JIT's ecalli trampoline only charges the standard 1-unit cost via the per-block cost.

**Fix vector:** introduce a Rostro-owned gas table for IDs 100-1023, deduct the intrinsic-specific cost in **both** the FAST_OP_ECALLI arm and the JIT runner's dispatch *before* running the native body. If gas underflows, set the trap interrupt and exit the loop — same path as `NotEnoughGas` already wired for the standard cost. Calibration approach is in the "Gas calibration" section below.

---

## A2 — Variable-length inputs (`msg_len`) have no upper bound (Critical, DoS)

**Where:** `polkavm/src/interpreter.rs:2989-3050` (blake2b, keccak, ed25519 dispatch arms), `rostro-vm-bench/src/runners/polkavm_runner.rs` (same dispatch arms).

**Threat model:** Even with A1 fixed via a flat per-intrinsic gas charge, `blake2b_256`, `keccak_256`, and `ed25519_verify` scale linearly with `msg_len` (and ed25519's `msg` is hashed inside `pk.verify()`). A 1 GB `msg_len` (within a 1 GB guest memory limit) is ~1 GB of native hashing for the same 1 gas charge.

**Fix vector:**
- **Hard cap.** Reject `msg_len > MAX_INTRINSIC_MSG_LEN` (suggest 4 MB, well above any realistic Rostro use case) at dispatch entry, before any work.
- **Per-byte gas.** Charge `base_gas + per_byte_gas * msg_len` so the cost scales with the work. Per-byte rate calibrated against `blake2b` / `keccak` native throughput.

Both should ship; the hard cap is the backstop for the per-byte calculation in case `per_byte_gas * msg_len` overflows.

---

## A3 — Borrow/aliasing pattern correctness (Pass)

**Where:** All FAST_OP_ECALLI dispatch arms with output buffers (blake2b, keccak, ecrecover, poseidon2).

**Audit:** Read input → drop immutable borrow → compute into stack-local owned buffer → take mutable borrow for output → copy. Pattern is correct in all four cases. The `ecrecover` arm's `out_pk: [u8; 64]` stack buffer and the hashing arms' `hash: [u8; 32]` stack buffers de-couple the borrow lifetimes by construction.

**Defense-in-depth note:** Consider marking each arm with a `// SAFETY/aliasing: …` one-liner so future contributors don't break the pattern when refactoring.

---

## A4 — Fail-path state consistency (Pass with caveats)

**Where:** All FAST_OP_ECALLI dispatch arms.

**Audit:**
- All arms use `(|| -> Option<u64> { ... })().unwrap_or(fail_code)` idiom; partial work that fails on the second borrow (mutable output) does NOT leave the output buffer in a half-written state because the stack-local buffer is the staging area.
- However, **CPU is already spent** on the native crypto by the time the output write fails. Combined with A1 (gas), this creates a free-work vector where a guest deliberately passes a bad output pointer to extract crypto results "for free" — except you can't actually exfiltrate the result if you don't have a valid output pointer.
- **Aliasing of `failure code` between transient memory faults and semantic failure:** ed25519 and ecrecover both return `0` for "memory access failed" AND "signature did not verify." A guest cannot distinguish these. For consensus this is fine (both reduce to "verify failed"). For debugability, separating them via a second return register would help — out of scope for this audit.

---

## A5 — Native crate TCB (Pass)

**Where:** `polkavm/Cargo.toml`.

**Audit:**
- All crypto deps use `default-features = false` (✓): `fips204`, `p521`, `ed25519-compact`, `k256`, `blake2`, `sha3`. No surprise feature toggles slip into builds.
- `cargo tree` on the polkavm crate shows zero `-sys` / FFI / asm crates — pure Rust transitively. No C-binding escape surface.
- `fips204` does pull `getrandom` (via `libc`) due to the `default-rng` feature. We only call verify, which doesn't need entropy, so `getrandom` is dead code at the call boundary. Could be eliminated by switching to `fips204` features that don't pull RNG — minor hygiene item.

**Conclusion:** Adding the precompiles did NOT introduce native-FFI risk to the TCB.

---

## A6 — Determinism across validator builds (Audit-and-pin)

**Risk:** If two validators build with different feature flags or different versions of `k256` / `ed25519-compact` / `fips204`, edge-case behavior could diverge → chain fork.

**Mitigations already in place:**
- `Cargo.lock` is checked in; all version resolutions are fixed.
- `default-features = false` on all crypto deps prevents accidental feature drift.

**Mitigation LANDED 2026-05-15:** `polkavm/tests/kat_vectors.rs` runs as part of `cargo test` for the polkavm crate. 13 KAT assertions across blake2b, keccak, ed25519, secp256k1_recover, goldilocks, and poseidon2 — each tied to a spec-published vector (RFC 8032 for Ed25519, RFC 7693 / RustCrypto for blake2, FIPS 202 / Ethereum for Keccak, k256+EIP-2 for secp256k1) or to a documented audit-time library output (where multiple parameterizations exist in the wild and the spec is ambiguous).

Includes negative-case KATs (`kat_ed25519_verify_rejects_tampered_msg`, `kat_secp256k1_recover_rejects_high_s`, `kat_secp256k1_recover_rejects_recid_2`) — these verify that A10/A11/A12 input-validation rejections are still firing.

Dilithium and P-521 KATs are deferred until their service fixtures are extracted (the workload-level AGREE matrix is the proxy until then). Recorded as a follow-up.

**Status:** CLOSED.

---

## A7 — Panic propagation from native body to host (CLOSED 2026-05-15)

**Risk:** If a native body panics (e.g., a RustCrypto crate hits an internal assertion on adversarial input), the panic unwinds through the interpreter into the host. In a substrate-runtime context this is caught by `sp-panic-handler` (workspace `panic = "unwind"` is required for that). The runtime call fails; the node stays up. The remaining concern is *cross-validator behavioral divergence* — if validator A's library panics on input X and B's doesn't, they apply different state changes.

**Audit findings:** Verify-path-scoped scan across each crypto crate's call graph:

| Crate | Verify-path operations | Findings | Verdict |
|---|---|---|---|
| `ed25519-zebra` 4.2.0 | `VerificationKey::try_from`, `verify` | All ops return `Option`/`Choice`/`Result`. No unguarded unwrap/panic. | SAFE |
| `curve25519-dalek` 4.1.3 | `CompressedEdwardsY::decompress`, `Scalar::from_canonical_bytes`, `vartime_double_scalar_mul_basepoint`, `mul_by_cofactor`, `is_identity` | Asserts/unwraps exist but ONLY in Elligator, basepoint table construction, and test code — none in the actual verify path. | SAFE |
| `k256` 0.13.4 / `ecdsa` 0.16.9 | `Signature::from_slice`, `RecoveryId::from_byte`, `recover_from_prehash` | `R.unwrap()` (ecdsa-0.16.9/src/recovery.rs:305) is guarded by `R.is_none()` check at line 301. `r.invert()` operates on a scalar guaranteed nonzero by `Signature::from_scalars`' check at lib.rs:254. | SAFE |
| `blake2` 0.10.6 | `Blake2b::<U32>::new`, `update`, `finalize` | Asserts/unwraps are all in `with_params` (we use plain `new()`, not that path). | SAFE |
| `sha3` 0.10.9 | `Keccak256::new`, `update`, `finalize` | `debug_assert_eq!(block.len() % 8, 0)` (state.rs:43) — debug-only, no production panic. The `try_into().unwrap()` on the next line is invariant-protected: the surrounding chunks-of-8 loop guarantees `b.len() == 8` by construction. | SAFE |
| `fips204` 0.4.6 | `ml_dsa_65::PublicKey::try_from_bytes`, `verify` | All `expect()` calls reference static spec parameters (L, tau, omega = ML-DSA-65 constants), not user input. "Cannot fail; L is static parameter" annotations confirm. | SAFE |
| `p521` 0.13.3 / `ecdsa` 0.16.9 | `verify_prehash` (same generic ecdsa impl as k256) | All `panic!()` in test harness (Wycheproof blob runner) or `#[test]` functions. None in production verify path. | SAFE |

**Decision: no `catch_unwind` wraps.** All verify paths return errors via `Result`/`Option` discipline on adversarial-but-well-formed input. Wrapping would add 5-10 ns per heavy intrinsic call AND introduce a behavior choice that doesn't help: substrate's `sp-panic-handler` already catches genuine panics at the outer runtime boundary; an inner wrap would just shift WHERE the same outcome is produced, not change what validators see.

**Defense-in-depth, kept:** `sp-panic-handler` at the substrate-runtime boundary. Cross-validator behavioral consistency is enforced by the Cargo.lock pin + the audit's snapshot semantics.

**Caveat — this is a snapshot.** The audit holds against current versions; any dep version bump invalidates it. A6 (KAT corpus) is the active line of defense against behavioral drift through dep upgrades — re-running KAT vectors after every bump catches behavioral changes even when no explicit panic is involved.

**Status:** CLOSED.

---

## A9 — Goldilocks intrinsic ABI canonicality contract is undocumented (Medium)

**Where:** `polkavm/src/interpreter.rs:4631-4707` (native bodies).

**Audit:**
- `goldilocks_add_native` and `goldilocks_sub_native` deliberately return non-canonical values in `[0, 2^64)`, matching the `gp` reference crate's convention. The comment at `interpreter.rs:4654-4655` states this for `add` but **does not state it at the intrinsic's ABI surface** (the ID constant, the dispatch arm, or `rostro_intrinsics::*` re-export).
- `goldilocks_mul_native` and `goldilocks_inv_native` canonicalize implicitly (mul reduces the full 128-bit product; inv multiplies through `x^(p-2)`).
- Inputs are NEVER canonicalized at the boundary — any u64 is accepted as a "field element."

**Injection vector:** if a caller (e.g., the Plonky3 STARK verifier on-chain) compares field elements with raw `u64 ==` instead of `canonical(a) == canonical(b)`, an attacker can supply non-canonical values such that `a ≠ b` byte-wise but `a ≡ b (mod p)`. A proof that should fail can pass, or vice versa.

**Severity:** Medium. Not a direct chain-halt; it's a verifier-soundness foot-gun. Severity rises to Critical if any consensus-affecting caller (e.g., the PoP STARK verifier mint path) commits the bug.

**Mitigation options** (deferred — design call, not auto-fixable):
1. Document the ABI contract loudly at `rostro_intrinsics::*` and in each native body's docstring; add a `canonicalize(x: u64) -> u64` helper in the same module.
2. Canonicalize inputs inside `add_native` / `sub_native`. Adds ~2 ns/op, ~5-10% slowdown on STARK-heavy workloads.
3. Canonicalize on a SEPARATE `*_canonical` variant; let high-perf STARK callers keep the fast path, force consensus-affecting callers onto the safe path.

**Status:** OPEN. Recorded; awaiting design decision (the choice affects PoP verifier ergonomics + STARK bench numbers).

---

## A10 — Ed25519 signature malleability accepted (Medium-High)

**Where:** `polkavm/src/interpreter.rs:4694-4699` (`rostro_ed25519_verify`), backed by `ed25519-compact` 2.2.0.

**Audit:** `ed25519-compact`'s verify (`ed25519.rs:239-255`):
1. Uses `(expected_r - GeP3::from(r)).has_small_order()` — the **cofactored** equation. Accepts up to 8 valid (R, s) pairs per (message, pubkey) because the order-8 cofactor group is consumed by the `has_small_order` check.
2. Does NOT check `s < L` (group order). `(R, s)` and `(R, s + L)` both verify because `s ≡ s + L (mod L)` in the verification equation. Doubles the malleability count to ~16 sigs per message.

**Injection vector:** any chain code that uses a signature as a uniqueness key (replay protection, deduplication, "signature-as-nonce") accepts multiple "distinct" signatures for the same logical sign event. Cross-component divergence is also a risk: if dotwave (or any other Rostro client) uses `ed25519-dalek` strict-verify, and the chain accepts cofactored, the same byte string can produce different verify outcomes across the two components.

**Reference:** Henry de Valence's "It's 255:19AM. Do you know what your validators are doing?" (2020) — the canonical write-up of the ed25519 cross-implementation problem. ZIP-215 is the consensus spec that resolved it for Zcash; `ed25519-zebra` (Zcash Foundation, MIT/Apache-2.0) is the reference implementation.

**Severity:** Medium-High. Critical if Rostro uses ed25519 sigs as nonces (currently planned: BTOW uses Ed25519 as an SS58 scheme — needs review).

**Mitigation:** Switched from `ed25519-compact` to `ed25519-zebra` 4.2.0 (Zcash Foundation, dual MIT/Apache-2.0). ZIP-215 verify enforces `s < L` canonicality and a deterministic cofactored verify equation `[8](R - R') == 0`. The malleability vector is closed — any byte-distinct sig that previously verified via the `s + L` or cofactor-group equivalent now fails.

**Sig-as-nonce grep (2026-05-15):** substrate/frame doesn't use signature-as-nonce anywhere — tx pool dedupes by `(account, nonce)`, multisig by `call_hash`, im-online by `session_key + block_number`. So A10's severity downgrades from "replay-attack surface" to "cross-impl determinism + defense-in-depth." Still load-bearing for the latter; ZIP-215 makes the verify outcome a deterministic function of the input bytes across all conforming validator implementations.

**Status:** CLOSED via Path 2 (dep swap).

---

## A11 — secp256k1 ECDSA recovery accepts high-s and non-Ethereum recovery_id (Medium-High)

**Where:** `polkavm/src/interpreter.rs:4712-4729` (`rostro_secp256k1_recover`), backed by `k256` 0.13.4.

**Audit:**
- `k256::ecdsa::VerifyingKey::recover_from_prehash` (via `ecdsa-0.16.9/src/recovery.rs:281-316`) does NOT call `normalize_s()` and does NOT reject `s > n/2`. EIP-2 (Ethereum's signature malleability fix, 2017) requires this rejection; Bitcoin Core enforces it via BIP-146.
- `RecoveryId::from_byte` accepts all 4 values in `{0, 1, 2, 3}`. The `2/3` bit signals "r was x-reduced" (the original `r` value was larger than the curve order). Ethereum's ECRECOVER precompile only accepts v ∈ {0, 1} (mapping to 27/28 in legacy encoding); accepting 2/3 produces a different pubkey for the same `(hash, r, s)` byte string vs. Ethereum.

**Injection vectors:**
1. **Intra-chain malleability.** `(hash, r, s, 0)` and `(hash, r, n-s, 1)` both recover valid (but different!) pubkeys. Same payload, two valid sigs. Replay attack on any sig-as-nonce path.
2. **Cross-chain divergence with Ethereum.** A signature byte string that's REJECTED by Ethereum's ECRECOVER (high-s, or recovery_id 2/3) is ACCEPTED here. If Rostro ever processes an Ethereum-signed message (cross-chain bridge, signed-msg auth, etc.), the divergent outcome is a chain-fork vector at the policy layer.

**Severity:** Medium-High. Critical for any future ETH-bridge surface; currently Medium for pure-Rostro consensus.

**Mitigation (LOCKED 2026-05-15, implementation in this commit):** strict Ethereum-compat rejection. Wrap `recover_from_prehash` with pre-checks:
- `recovery_id` byte must be `0` or `1` — reject `2`, `3`.
- `s` must satisfy `s ≤ n/2` (low-s). `Signature::normalize_s()` returns `Some(normalized)` iff the original was high-s; reject if `Some`.

Matches Ethereum's ECRECOVER policy + EIP-2.

**Status:** IMPLEMENTED in this commit.

---

## A12 — Small-order Ed25519 pubkeys verify arbitrary signatures (High if used as identity)

**Where:** `polkavm/src/interpreter.rs:4694-4699` (`rostro_ed25519_verify`).

**Audit:** `PublicKey::from_slice` in `ed25519-compact` (`ed25519.rs:29-36`) checks ONLY length (32 bytes). It does NOT validate that the bytes decode to a valid Edwards point, and does NOT reject the 8 small-order points on the curve (the identity point, the 4-torsion points, the 8-torsion points).

If `pk` is a small-order point, the cofactored verification equation reduces to `s*B = R` (the `h*A` term vanishes under cofactor multiplication because `A` has small order). Any `(R, s)` satisfying `s*B = R` verifies — and there are infinitely many such pairs (pick any `s`, compute `R = s*B`).

**Injection vector:** an attacker submits a "signed" message with a small-order pubkey + a self-crafted `(R, s)` that satisfies `s*B = R`. The signature "verifies." If the chain treats the pubkey as an identity (account binding, PoP claim, validator key, etc.), the attacker has produced a forged identity-bearing signature.

**Severity:** HIGH. Most Rostro paths plan to bind pubkeys to identities (BTOW SS58 accounts, validator keys, PoP `bound_account`).

**Mitigation:** Path 2 (ed25519-zebra) — partially closed at the VM layer.

ZIP-215 *standardizes verify behavior on small-order pubkeys* — the outcome is deterministic across all conforming validators, so consensus is preserved. But ZIP-215 does NOT *reject* small-order pubkeys at the verify primitive; it explicitly accepts them, leaving the rejection to the application layer where pubkey-to-identity binding happens.

**For Rostro, this means:** any pallet that binds an Ed25519 pubkey to an identity (BTOW SS58 account binding, PoP `bound_account`, validator registration, RNS owner key, etc.) MUST reject small-order pubkeys at the binding boundary. Identity-binding code should call something like `is_small_order_ed25519(pk_bytes)` and refuse the binding if true. This is a separate, pallet-layer concern.

**Status:**
- VM-layer (verify primitive): CLOSED via Path 2. Verify is now deterministic across implementations.
- Pallet-layer (identity binding): **OPEN** — the relevant pallets EXIST in the main Rostro tree and currently perform no small-order Ed25519 pubkey rejection. Audit follow-up to be tracked in the main repo, not here. Known binding sites:
  - `substrate/utils/rostro-multi-key/src/lib.rs` — `RostroSigner::Ed25519(ed25519::Public)` accepts any 32-byte pubkey (Solana/Cosmos-style raw address derivation per BTOW Option-C).
  - `substrate/frame/pallet-rostro-personhood/` — `bound_account` is committed to as an AIR public input by `mint_pop`; the SS58 it binds to must be backed by a real key, which for Ed25519-derived accounts means the underlying pubkey must reject the 8 small-order points.
  - `~/Polkadot/pns-pallets/` (RNS) — owner-key registration. Same concern applies for any Ed25519 owner-key path.

  Fix sketch when the pallet-side audit runs: add an `is_low_order_ed25519(pk: &[u8; 32]) -> bool` helper (decode via `ed25519_zebra::VerificationKey::try_from` + check torsion, or precompute the 8 small-order encodings and reject by exact match — the second is cheaper, 8 byte-array compares). Wire at every identity-binding extrinsic entry point.

  **vm-research is the wrong tree to land this fix in** — the intrinsic surface is now ZIP-215-deterministic, which is all VM-research can offer. The application-layer rejection happens where identity binding happens, in the main Rostro repo.

---

## A13 — `ed25519-compact` is MIT-only, not Apache-2.0 compatible (License hygiene)

**Where:** `polkavm/Cargo.toml` line 91-93.

**Audit:** Rostro's stated license posture is Apache-2.0 across the surviving tree (per `CLAUDE.md`). `ed25519-compact` is licensed MIT-only (`Cargo.toml::license = "MIT"`). MIT is compatible *for use* in an Apache-2.0 project, but the NOTICE accumulation gets more complex than dual MIT/Apache-2.0 deps (which we have for `k256`, `blake2`, `sha3`, `fips204`).

**Recommendation:** switch to `ed25519-zebra` (Zcash Foundation, MIT OR Apache-2.0) — aligns the license posture with the rest of the crypto deps AND closes A10/A12 for free.

**Status:** CLOSED. `ed25519-zebra` 4.2.0 (dual MIT/Apache-2.0) replaces `ed25519-compact` (MIT-only). License posture now uniform across all Tier 2 crypto deps.

---

## A8 — Timing side channels (Out-of-scope for chain consensus, flag for host operators)

**Risk:** Non-constant-time crypto in `k256` (ECDSA verify and pubkey recovery historically have variable-time branches in pure-Rust BigInt impls) could leak information about ephemeral secrets if any host code processes private keys near these intrinsics.

**Audit:**
- For chain consensus, this is N/A — all inputs are public, all outputs are public.
- For any future "operator HSM sidecar" path (where a node holds a long-lived secret and processes user-supplied data near it), this becomes relevant.

**Recommendation:** Document the non-constant-time assumption in the intrinsic module docstring so future operators don't accidentally use these intrinsics in a side-channel-sensitive context.

---

## Gas calibration

Calibration uses three reference points before settling numbers:

1. **Measured native runtime** on this dev machine (Ryzen, WSL2, release build), via `examples/measure_intrinsic_native_cost.rs`. Each native body called directly, no VM, no dispatch overhead.
2. **Substrate weight equivalent**: substrate's weight unit is 1 picosecond on the reference machine (`WEIGHT_REF_TIME_PER_NANOS = 1_000`). Direct conversion: `weight = native_ns × 1000`.
3. **Ethereum precompile gas**: where an Ethereum equivalent exists.

### Measured native cost (ns/call on this machine)

```
goldilocks_mul/add/sub:           ~0.22 ns/call  (likely folded by optimizer; ALU latency)
goldilocks_inv:                    253.71 ns/call
poseidon2_permute:               1,020.49 ns/call
blake2b_256 (empty):               118.21 ns/call
blake2b_256 (64B):                 116.12 ns/call    (single block, no per-byte yet)
blake2b_256 (1KB):                 744.57 ns/call    (~0.61 ns/byte after base)
blake2b_256 (4MB):           3,006,127.54 ns/call    (~0.72 ns/byte at scale)
keccak_256 (empty):                311.27 ns/call
keccak_256 (64B):                  305.68 ns/call
keccak_256 (1KB):                2,253.08 ns/call    (~2.0 ns/byte after base)
keccak_256 (4MB):            8,747,519.36 ns/call    (~2.08 ns/byte at scale)
ed25519_verify (empty msg):     46,714.12 ns/call    (msg hashed inside; per-byte rate TBD)
secp256k1_recover:             158,108.24 ns/call
dilithium_verify (verify-only): ~135,000 ns/call    (workload-level, one verify per call)
p521_ecdsa_verify_prehash:     ~500,000 ns/call    (estimate from workload; TBD-confirm)
```

### Three-way comparison table

Anchor: **1 Rostro gas ≈ 1 ns native**, matching `CostModel::naive()` semantics for `add_64`.

| ID | Intrinsic | Native ns | Proposed Rostro gas | Substrate weight | Ethereum gas equiv |
|---|---|---|---|---|---|
| 100 | goldilocks_mul | <1 | **1** | 1,000 | n/a |
| 101 | goldilocks_add | <1 | **1** | 1,000 | n/a |
| 102 | goldilocks_sub | <1 | **1** | 1,000 | n/a |
| 103 | goldilocks_inv | 254 | **256** | 256,000 | n/a |
| 110 | dilithium_verify | ~135,000 | **150,000** | 150M | n/a |
| 111 | p521_ecdsa_verify | ~500,000 | **600,000** | 600M | n/a |
| 120 | blake2b_256 | 118 + 1/byte | **128 + 1/byte** | 128K + 1K/byte | n/a (BLAKE2F = 1 gas/round) |
| 121 | keccak_256 | 311 + 2/byte | **320 + 2/byte** | 320K + 2K/byte | KECCAK opcode = 30 + 6/word |
| 122 | ed25519_verify | 46,714 + per-byte msg | **50,000 + 1/byte msg** | 50M + 1K/byte | n/a (no native ed25519) |
| 123 | secp256k1_recover | 158,108 | **160,000** | 160M | **3,000** (53× cheaper) |
| 130 | poseidon2_perm | 1,020 | **1,024** | 1.024M | n/a |

Margins above measured cost (~10-15%) absorb (a) inter-machine variance among validators, (b) future dep upgrades that slightly change cost, (c) cache-cold vs warm difference.

### Sanity vs. Ethereum

Ethereum's reference: ~30M gas / ~1 second of native compute on reference machine → ~33 ns/gas. ECRECOVER at 3,000 gas = ~99 µs of expected native work; our measurement of `secp256k1_recover` is 158 µs (1.6× slower than Ethereum's anchor — `k256` pure-Rust vs. their reference `libsecp256k1`).

KECCAK as an opcode (not precompile): 30 gas + 6/word → 1 KB = 30 + 6×32 = 222 gas ≈ 7.3 µs of native compute on Ethereum's anchor. Our keccak_256 1 KB = 2.25 µs. Our impl is 3× faster than EVM's anchor.

Our anchor (1 gas ≈ 1 ns) is **30× tighter** than Ethereum's (1 gas ≈ 33 ns). Rostro gas numbers will look larger than EVM numbers in absolute terms but encode the same wall-clock budget.

### Block-budget sanity check

If we target ~1 s of host CPU per 6 s block (validator headroom) at our proposed costs:
- 1B gas budget → all-ecrecover scenario: 1B / 160K = ~6,250 ecrecovers/block.
- All-ed25519: 1B / 50K = ~20,000 verifies/block.
- All-poseidon2: 1B / 1024 = ~1M permutes/block (PoP STARK verify comfort).
- All-blake2b-1KB: 1B / 1152 = ~870K hashes/block.

These are all in the range a real validator can sustain without missing block deadlines.

### Variable-cost intrinsics: gas formula and msg_len cap

For `blake2b_256`, `keccak_256`, `ed25519_verify`, charge `base_gas + per_byte_gas * msg_len`. Reject `msg_len > MAX_INTRINSIC_MSG_LEN` at dispatch entry — proposed cap **4 MiB** (4 × 1024 × 1024). At 1 ns/byte, 4 MiB = 4 ms of native work; well under block deadline even if every gas-unit went to one call.

---

## Implementation status (A1 + A2 + A10 + A11 + A12 [VM-layer] + A13 landed)

Implemented in commit forthcoming on `vm-research`:

- **New module:** `polkavm/src/rostro_intrinsic_gas.rs` — `INTRINSIC_GAS` table (flat + per-byte) indexed by intrinsic ID; `MAX_INTRINSIC_MSG_LEN = 4 MiB`; `intrinsic_surplus_gas(id, msg_len) -> Option<i64>` helper. Module-level unit tests cover the lookup, cap rejection, and boundary cases.
- **Interpreter dispatch (`interpreter.rs:2900-3104`):** Each Tier 2 arm now charges its intrinsic-specific surplus over the standard 1-gas ecalli before running the native body. Variable-length intrinsics (blake2b, keccak, ed25519) reject `msg_len > MAX_INTRINSIC_MSG_LEN` with the existing memory-access failure code path (`1` for hashing, `0` for ed25519). Gas underflow during surplus charge calls `handle_gas_underflow`, mirroring the per-block underflow path.
- **JIT-runner dispatch (`runners/polkavm_runner.rs`):** Mirrors the interpreter logic via a new `DispatchOutcome { Ran, Unknown, OutOfGas }` enum + `charge_intrinsic_surplus` helper. Main run loop honors `OutOfGas` by aborting with the standard out-of-gas error — necessary because the ecrecover-style "function returns to host immediately after ecalli" pattern would otherwise let an uncharged call slip past the gas check.
- **A10 + A12 (VM-layer) + A13 dep swap:** `polkavm/Cargo.toml` now uses `ed25519-zebra` 4.2 (dual MIT/Apache-2.0) instead of `ed25519-compact` 2 (MIT-only). `rostro_ed25519_verify` (`interpreter.rs:4686-4733`) rewritten to use zebra's `VerificationKey::try_from + verify` API. ZIP-215 enforcement is internal to zebra; no wrapper checks needed. Single `curve25519-dalek 4.1.3` is shared between zebra (consensus) and the workspace's existing ed25519-dalek path (javm side) — `cargo tree -i curve25519-dalek` confirms no duplicate.
- **A11 strict secp256k1:** `rostro_secp256k1_recover` (`interpreter.rs:4734-4778`) rejects `recovery_id > 1` and high-s signatures via `Signature::normalize_s().is_some()`. Matches Ethereum ECRECOVER + EIP-2 / BIP-146.
- **Validation tooling:**
  - `examples/measure_intrinsic_native_cost.rs` — direct native-body timing (calibration anchor).
  - `examples/verify_audit_a1_a2.rs` — end-to-end VM check: confirms gas-charged amount matches the table on a successful call (ed25519 = 50,013 gas, ecrecover = 160,039 gas), gas underflow traps with "out of gas" on both INT and JIT, AND secp256k1_recover rejects recovery_id ∈ {2, 3} + high-s.
  - `examples/test_crypto.rs` — extended AGREE matrix now includes `ed25519_verify` and `ecrecover` workloads. All 13 workloads AGREE across all 6 backends — zebra (consensus side) vs. ed25519-compact (control side) match on the RFC 8032 test vector.

### Test outcomes

```
ed25519 RVM-INT  : gas_consumed = 50013  (table: 50_000 + ~13 dispatch instructions)
ecrecover RVM-INT: gas_consumed = 160039 (table: 160_000 + ~39 dispatch instructions)
ed25519 RVM-JIT  : gas_consumed = 50013
ecrecover RVM-JIT: gas_consumed = 160039

ecrecover @ 50K gas budget (INT): TRAPPED (out of gas) — A1 enforced
ecrecover @ 50K gas budget (JIT): TRAPPED (out of gas) — A1 enforced
```

## Mitigation implementation plan

Once the gas table is locked:

1. **New module:** `polkavm/src/rostro_intrinsics_gas.rs` exporting a `pub const INTRINSIC_GAS: [u32; 1024]` indexed by `ROSTRO_INTRINSIC_*` ID. (Per the "no cross-purpose files" rule, this lives separately from `gas.rs`, which is for opcodes — different abstraction layer.)
2. **Interpreter dispatch:** at the top of each FAST_OP_ECALLI arm for Tier 2 IDs, deduct `INTRINSIC_GAS[id]` from `self.gas`; if underflow, set `self.interrupt = InterruptKind::NotEnoughGas` and return. For variable-cost intrinsics (blake2b, keccak, ed25519), deduct `base + per_byte * msg_len` with a `msg_len <= MAX_INTRINSIC_MSG_LEN` precheck.
3. **JIT runner dispatch:** mirror in `polkavm_runner.rs::dispatch_rostro_intrinsic`. Helper returns `Result<(), ()>` to signal underflow; caller propagates as InterruptKind.
4. **Cost model integration:** add a `RostroCostModel` variant alongside `naive()` so the substrate-runtime side can opt into it via `Config::set_cost_model()`.
5. **Tests:** KAT corpus (A6) + per-intrinsic gas-cost assertions (assert that calling an intrinsic with insufficient gas traps; assert flat-cost calls consume exactly `INTRINSIC_GAS[id]`).
6. **Bench:** re-run `crypto_bench` with the new gas charges in place; numbers should be functionally identical (gas overhead is sub-ns per call, well below noise).

---

## Open follow-up items (post-mitigation)

In the **vm-research tree** (this repo):
- Add `SECURITY-AUDIT-TIER2-INTRINSICS-CHANGELOG.md` entry whenever a new intrinsic ID is added; require a gas calibration measurement before merging.
- Wire a CI job that diffs `INTRINSIC_GAS` against the calibration baseline and fails the PR if costs move >10% without an explicit re-calibration commit.
- Add KAT vectors as a separate test target so re-running them on every dep bump is one command.
- Revisit panic propagation (A7) — decide between `catch_unwind` wrap vs `panic = "abort"` discipline.
- A9 (Goldilocks ABI canonicality contract) — design call on document-only vs canonicalize-in-body.

In the **main Rostro tree** (separate audit pass, not vm-research's scope):
- A12 pallet layer — small-order Ed25519 pubkey rejection at `rostro-multi-key` (Ed25519 signer construction), `pallet-rostro-personhood` (`bound_account` ingest), and `~/Polkadot/pns-pallets/` (RNS owner-key registration). VM-layer ZIP-215 verify is deterministic but accepts small-order pks by design; identity-binding pallets are where rejection must live.
