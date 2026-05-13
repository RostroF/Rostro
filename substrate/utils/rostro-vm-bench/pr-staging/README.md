# JAR/Grey PR staging — STARK-shaped bench suite

This directory contains a clean, self-contained contribution ready to drop
into [`jamisha/grey`](https://github.com/jamisha/grey) (Wei Tang's JAR/Grey
repo). Adds three benchmark services (`mini-verifier`, `goldilocks-mul`,
`poseidon2-perm`) plus their shared no_std-no-atomics primitive library
(`goldilocks-poseidon2`).

**Nothing in here depends on Rostro's bench harness, runners, or build
infrastructure.** Files are scoped to Wei's tree layout, naming convention,
and dep posture.

## Layout

```
pr-staging/services/benches/
├── goldilocks-poseidon2/   ← shared lib (no deps, no atomics)
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── field.rs        ← Goldilocks F_p arithmetic
│       └── poseidon2.rs    ← Poseidon2-WIDTH8 perm, bit-exact w/ p3
├── mini-verifier/           ← Plonky3 STARK-verifier-shaped composite
├── goldilocks-mul/          ← Goldilocks mul tight loop
└── poseidon2-perm/          ← Poseidon2 perm tight loop
```

These mirror the existing `services/benches/blake2b`, `ed25519` etc.
exactly — same Cargo.toml shape, same `lib.rs + main.rs + polkavm.rs`
layout, same `javm-builtins` shim, same `polkavm-derive` target gate.

## To apply to a JAR/Grey clone

```bash
cd /path/to/jar
git checkout -b stark-bench-suite

# Drop the four crates into place
cp -r /path/to/pr-staging/services/benches/* grey/services/benches/

# Apply the three small file patches documented in PATCHES.md:
#   1. Cargo.toml — workspace members
#   2. grey/crates/grey-bench/build.rs — register guest blobs
#   3. grey/crates/grey-bench/src/lib.rs — blob accessors
#   4. grey/crates/grey-bench/benches/pvm_bench.rs — wire criterion groups

# Verify
cargo build --workspace
cargo bench -p grey-bench --bench pvm_bench
```

## What this contributes to JAR/Grey

- **A STARK-shaped workload** (mini-verifier) that exposes JAM-relevant
  perf characteristics. The current bench suite (blake2b, ed25519,
  ecrecover, keccak, prime-sieve) doesn't touch the FRI-fold + transcript
  pattern that JAM's uni-stark verifier hot-loops in.

- **Decomposed primitives** (goldilocks-mul, poseidon2-perm) that let
  per-primitive costs be read directly. Composite + decomposed lets
  contributors see exactly where each VM's time goes.

- **A reusable hand-written Goldilocks + Poseidon2** (the shared lib) that
  doesn't pull in `tracing` / `serde` / `rand`. Plonky3's crates depend on
  `tracing` which requires `target_has_atomic = "ptr"` — incompatible
  with javm's `max-atomic-width: 0`. Bit-exact with `p3-goldilocks::default_goldilocks_poseidon2_8`
  (same RC arrays, same MDS matrices, same x^7 S-box).

See `PR_DESCRIPTION.md` for the cross-VM findings these benches surface.
