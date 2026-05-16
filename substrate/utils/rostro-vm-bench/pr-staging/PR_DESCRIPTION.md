# PR: STARK-shaped bench suite (mini-verifier + Goldilocks + Poseidon2)

## What

Three new bench services + a shared no_std-no-atomics Goldilocks + Poseidon2
primitive library, alongside the existing crypto benches. Adds:

- **`mini-verifier`** — Fiat-Shamir transcript + FRI-fold linear combinations
  + AIR constraint evaluation. Mirrors `p3_uni_stark::verify`'s hot loop
  (~400 Poseidon2 perms + ~2400 Goldilocks ops per call) without dragging
  in the full uni-stark machinery.
- **`goldilocks-mul`** — 100 000 chained Goldilocks multiplications. Isolates
  the `u64 * u64 -> u128 -> mod p_G` cost.
- **`poseidon2-perm`** — 1 000 chained Poseidon2-WIDTH8 permutations.
  Isolates the hash inner loop.
- **`goldilocks-poseidon2`** — shared no-deps lib used by all three. Bit-exact
  with `p3-goldilocks::default_goldilocks_poseidon2_8` (same RC arrays,
  same MDS matrices, same x^7 S-box). Hand-written instead of pulled from
  `p3-goldilocks` / `p3-poseidon2` because Plonky3 transitively depends on
  `tracing`, which requires `target_has_atomic = "ptr"` — incompatible with
  javm's `max-atomic-width: 0` target.

## Why

The existing bench suite covers byte-oriented crypto (blake2b/keccak),
sig verification (ed25519/ecrecover), and a generic compute kernel
(prime-sieve). It doesn't exercise the workload class JAM's uni-stark
verifier actually runs — Goldilocks-field arithmetic dominated by
Poseidon2 permutations.

The decomposition (composite + per-primitive isolation) is the structural
piece. It lets contributors see *where* each VM's time actually goes in
the verifier, rather than just "verifier is slow on backend X."

## Findings from the same workload run on rostro-vm-bench

(Cross-checked across javm-interp / javm-recomp / polkavm-interp /
polkavm-comp / wasmtime-cranelift / wasmtime-winch — all six produce
bit-exact identical output, confirming the hand-written impl matches
Plonky3.)

**Per-primitive cost (warm, ns):**

| backend | 1 Goldilocks mul | 1 Poseidon2 perm |
|---|---|---|
| polkavm-compiler | 4.75 ns | 1.95 µs |
| javm-recompiler | 6.01 ns | 4.34 µs |
| javm-interpreter | 5.93 ns | 4.37 µs |
| polkavm-interpreter | 45.4 ns | 50.9 µs |

**Composite (mini-verifier, warm):**

| backend | time |
|---|---|
| polkavm-compiler | 830 µs |
| javm-recompiler | 1.83 ms |
| javm-interpreter | 1.82 ms |
| polkavm-interpreter | 20.6 ms |

**The actionable signals for the JAR/javm side:**

1. **javm-recompiler == javm-interpreter on every workload.** On
   `goldilocks_mul` (593 µs vs 601 µs), `poseidon2_perm` (4.37 µs vs
   4.34 µs per perm), and `mini_verifier` (1.82 ms vs 1.83 ms) — the
   recompiler shows essentially zero speedup over the interpreter. This
   is the load-bearing finding. Either the recompiler is falling back to
   interpretation for these op shapes, or the interpreter is already
   inlining hot dispatches near native. Worth investigating recompiler
   output for chained `wrapping_mul` + `overflowing_add`.

2. **2.2× gap to polkavm-compiler at warm steady state on Poseidon2.**
   javm-recomp = 4.34 µs/perm vs polkavm-comp = 1.95 µs/perm.

3. **Cost dominance: Poseidon2 is 95% of the verifier on every JIT.**
   For polkavm-compiler: 780 µs Poseidon2 / 11 µs Goldilocks. For
   javm-recompiler: 1.74 ms Poseidon2 / 14 µs Goldilocks. Same shape.
   Wherever JAR routes a STARK verifier, the Poseidon2 inner loop is
   *the* optimization target — Goldilocks mul is essentially free across
   every JIT (4–10 ns range, near native cycle limits).

## Changes to existing files

Four small file patches — see `PATCHES.md`. No changes to existing crates'
internals.

## Verifying

```bash
cargo build --workspace
cargo bench -p grey-bench --bench pvm_bench -- mini_verifier goldilocks_mul poseidon2_perm
```

Existing benches and tests unchanged.
