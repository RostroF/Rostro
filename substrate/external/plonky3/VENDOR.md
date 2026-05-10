# Vendored Plonky3

## Source

- Upstream: <https://github.com/Plonky3/Plonky3>
- Pinned rev: `b638013721b7c9c07b171cb79a47366c928fb550`
- Pinned date: 2026-05-07
- License: MIT OR Apache-2.0 (both LICENSE files preserved)

## Why vendored

The Rostro runtime enforces file integrity via Merkle-trie checking at boot.
Every file that participates in execution must be present in the trie; git
or `[patch]` deps that fetch outside the repo are invisible to the
enforcement layer. Vendoring the source into the repo is the only path
that satisfies this constraint.

The vendor is also a deliberate freeze. The Plonky3 surface used by
Rostro's PoP and execution-proof pipelines must be auditable as a static
snapshot. Tracking upstream master would re-open audit boundaries on every
sync and is incompatible with the project's risk posture (see
`feedback_no_upstream_to_polkadot.md` — same principle applied across
the dep graph).

## Scope

18 of upstream's 39 crates were vendored. The selection covers everything
the PoP path uses (LogUp + Poseidon2 hash + STARK over Goldilocks) and
nothing else. If a future feature needs an excluded crate, re-vendor that
crate at this same rev or a deliberately-chosen newer one — do not
mix-and-match revs.

### Vendored

- `air` — AIR trait + symbolic builder + DebugConstraintBuilder
- `batch-stark` — multi-AIR proof on top of uni-stark + lookup
- `challenger` — Fiat-Shamir transcript
- `commit` — PCS trait
- `dft` — DFT primitives (FRI)
- `field` — Field traits + helpers
- `fri` — FRI commitment scheme
- `goldilocks` — Goldilocks field (`p = 2^64 - 2^32 + 1`)
- `lookup` — LogUp argument + InteractionBuilder
- `matrix` — Trace matrix layouts
- `maybe-rayon` — Optional rayon parallelism
- `merkle-tree` — Merkle-tree commitment
- `poseidon1` — Poseidon (legacy)
- `poseidon2` — Poseidon2 permutation primitive
- `poseidon2-air` — Generic Poseidon2 AIR (NOT used by PoP — see Rostro
  policy below)
- `symmetric` — Sponge / hash interfaces
- `uni-stark` — Univariate STARK prover/verifier
- `util` — Bit-reversal + log2 + serialization helpers

### Excluded

- `baby-bear`, `koala-bear`, `mersenne-31`, `monty-31`, `bn254`, `circle`
  — alternate fields and Circle STARK (Goldilocks-only here)
- `keccak`, `keccak-air`, `sha256`, `blake3`, `blake3-air`, `monolith`,
  `rescue` — alternate hashes (Poseidon2-only here)
- `mds` — extra MDS matrices not used by Goldilocks Poseidon2-WIDTH-8
- `whir`, `multilinear-util`, `zk-codes` — alternate IOPs / ZK encoding
- `examples`, `field-testing` — non-production
- `poseidon1-air` — only `poseidon2-air` shipped

## Workspace isolation

This directory is its own Cargo workspace (`Cargo.toml` here, with
`[workspace] members = [...]`). The Rostro root workspace at
`/home/coder/Rostro/Cargo.toml` does NOT list these crates as members.
Rostro crates that need a Plonky3 dep declare a path entry pointing at
this subtree (e.g.,
`p3-lookup = { path = "../../external/plonky3/lookup" }`).

The two-workspace split keeps the dep stacks from colliding. Plonky3
master uses `edition = "2024"`, sha2 0.11, hashbrown 0.17, itertools 0.14,
rand 0.10, thiserror 2.0 — all newer than Substrate's pins. Both
workspaces resolve their own dep tree.

## Modification policy

**Vendored code = no design changes** (per `feedback_vendored_code_no_design_changes.md`).
"Permission to copy" is not permission to add features. The audit
boundary is the diff against upstream rev `b638013`. If a Rostro change
becomes necessary (e.g., a soundness fix or an integration shim), commit
it as a separate file under `substrate/external/plonky3/rostro-patches/`
rather than editing the vendored sources in place — that way the diff
remains visible and reviewable.

## Re-vendoring

When a new rev is needed:

1. Open a new branch.
2. Update the rev pin in this VENDOR.md.
3. Re-run the file copy (the same 18 crates) at the new rev.
4. Update Plonky3's inner `Cargo.toml` `[workspace.dependencies]`
   versions if they bumped (see upstream's `Cargo.toml` for the
   `[workspace.package]` version field).
5. Re-run all Rostro tests; expect breakage in any code that uses
   APIs that changed in the upstream interval.

Re-vendoring is a deliberate, high-friction event. There is no automatic
sync.
