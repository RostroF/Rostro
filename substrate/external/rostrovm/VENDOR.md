# Vendored polkavm — basis for RostroVM

## Source

- Upstream: <https://github.com/koute/polkavm>
- Pinned version: **0.32.0** (downloaded from crates.io)
- Vendored date: 2026-05-11
- License: MIT OR Apache-2.0 (preserved per crate)
- Original copyright: Jan Bujak, Parity Technologies

## Why vendored

Per `rostrovm_design_locked.md` (2026-05-11), Rostro's chain runtime VM and
shop sidecar VM are both built on a polkavm fork that will eventually be
rebranded RostroVM. Vendoring at a pinned commit gives us:

1. **Static snapshot for audit.** Every byte of the VM that ships in
   gemini-node and the shop sidecar is in this tree. No fetch-at-build.
2. **Sovereign optimization surface.** We add the predecode-flatten
   interpreter port, cross-platform abstractions, reentrant host functions,
   instance pooling, Plonky3 host functions, and JIT super-ops here.
3. **Decoupled from upstream cadence.** Polkavm churn at the API level is
   smaller than wasmtime's, but still real. Pinning insulates us.

## Crates

The vendored set is the full polkavm runtime workspace:

| Crate | LOC (approx) | Role |
|---|---|---|
| `polkavm` | ~28k | Top-level engine, JIT compiler, sandbox, gas |
| `polkavm-common` | ~12k | Shared types, instruction set, blob format |
| `polkavm-assembler` | ~5k | Per-arch JIT instruction assembly |
| `polkavm-linker` | ~25k | RISC-V ELF → polkavm blob linker |
| `polkavm-linux-raw` | ~3k | Direct Linux syscall layer (Linux-only — RostroVM cross-platform abstraction layer will replace this) |
| `polkavm-derive` | ~0.1k | Procedural macro for `#[polkavm_export]` etc. |
| `polkavm-derive-impl` | ~0.5k | Macro implementation |
| `polkavm-derive-impl-macro` | ~0.1k | Macro shim |

Total: ~74k LOC.

## Workspace structure

This directory is a **standalone Cargo workspace**, excluded from the
parent Rostro workspace. The vendored crates inter-reference each other
via crates.io version specs — within the standalone workspace, cargo
resolves them as workspace members (path-dep equivalent).

External consumers (e.g. `rostro-vm-bench`, `gemini-runtime`) consume
this tree via path-dep into `substrate/external/rostrovm/polkavm`.

## Upstream sync policy

We do NOT track upstream master. Polkavm 0.32.0 is the current pin.
Re-sync to a deliberately-chosen newer version when:

- An upstream CVE fix matters to us (cherry-pick if surgical, full re-vendor if structural)
- Upstream lands a feature we want to adopt rather than reimplement
- Quarterly review identifies drift that's becoming costly to maintain

Re-vendor procedure:
1. Identify target upstream version (or commit)
2. Diff our local additions vs the target — call out conflicts
3. Re-vendor the target into a fresh `substrate/external/rostrovm-NEW/`
4. Re-apply our additions
5. Bench against current version to verify no perf regression
6. Atomic swap, single commit per the cross-purpose-files principle

## What's RostroVM-specific (added or modified vs upstream 0.32.0)

(Empty initially — this section grows as we accumulate optimizations.)

| Change | Where | Justification | Tier |
|---|---|---|---|
| (NOTE: this table missed the 2026-05 H1/Tier-2 arc — dispatch rewrite + intrinsics 100-130. See memory/docs for that history.) | | | |
| P-256 ECDSA verify intrinsic (`ROSTRO_INTRINSIC_P256_ECDSA_VERIFY = 112`) | `polkavm/src/interpreter.rs`, `polkavm/src/lib.rs`, `polkavm/Cargo.toml`, `polkavm/tests/kat_vectors.rs` | EcdsaP256 signature-variant verify at native speed (245 µs vs 13.8 ms interpreted, 1.0x native); RFC 6979 §A.2.5 KAT | Tier 2 |
| Mixed pinned/symbolic import indexing | `polkavm-linker/src/program_from_elf.rs` (`check_imports_and_assign_indexes`) | Upstream refused blobs mixing pinned-index imports with symbolic ones, making it impossible for a substrate-built runtime (symbolic sp_io imports) to call a reserved-index intrinsic. Symbolic imports now auto-assign below the reserved base (100), deterministic by symbol; reaching the base is a hard error (prevents silent intrinsic-range collision). | Tier 2 enabler |
| Default guest stack 8 KiB → 1 MiB | `polkavm-linker/src/program_from_elf.rs` (`Config::default`) | Upstream's 8 KiB default is smart-contract heritage; chain-runtime guests doing real crypto overflow it (k256 recovery traps, ML-DSA needs ~256 KiB) and a stack-overflow trap in consensus code is a liveness bug. Link-time only — existing blobs unaffected; `min_stack_size!` still raises per-blob. | Safety default |
| SLH-DSA-SHA2-128s verify intrinsic (`ROSTRO_INTRINSIC_SLHDSA_128S_VERIFY = 113`) | `polkavm/src/interpreter.rs`, `lib.rs`, `Cargo.toml` (path-dep on vendored `slh-dsa`), `tests/kat_vectors.rs` | Finality-vote scheme; worst measured interpreted ratio (450x, hash-dominated). Intrinsic = 183 µs, 0.99x native. Same vendored crate rostro-hybrid-sig trusts. | Tier 2 |
| BLS12-381 primitive intrinsics (`PAIRING_CHECK = 114`, `G1_MSM = 115`, `G2_MSM = 116`; caps `MAX_BLS_PAIRS = 8`, `MAX_BLS_MSM = 2048`) | same files; ark-bls12-381/-ec/-ff/-serialize 0.5.0 deps | Ethereum-precompile-shaped primitives composing into Groth16 verify, BLS sig verify, KZG opening checks (ring-VRF building block) without freezing any proof system into the node. Checked deserialization (curve + subgroup) — inputs consensus-adversarial. pairing_check(2) = 1.37 ms, 0.96x native vs 115 ms interpreted. | Tier 2 |
| CurveHooks-surface intrinsics (`MULTI_MILLER_LOOP = 117`, `FINAL_EXP = 118`, `BANDERSNATCH_TE_MSM = 119`, `TE_MUL_PROJECTIVE = 124`, `SW_MSM = 125`, `SW_MUL_PROJECTIVE = 126`, `G1_MUL_PROJECTIVE = 127`, `G2_MUL_PROJECTIVE = 128`; 115/116 flipped to unchecked deser; `MAX_BLS_MSM` 2048 → 8192; `MAX_MUL_PROJECTIVE_LIMBS = 8`) | `polkavm/src/interpreter.rs`, `lib.rs`, `Cargo.toml` (+ ark-ed-on-bls12-381-bandersnatch 0.5.0), `tests/kat_vectors.rs` | Completes native coverage of the ark-bls12-381-ext (6 methods) + ark-ed-on-bls12-381-bandersnatch-ext (4 methods) CurveHooks surfaces — the ring-VRF/Sassafras verify path. Hooks contract = caller-validated points, so curve-op arms deserialize UNCHECKED (garbage in = deterministic garbage out, no panic; 114 stays checked for standalone adversarial verification). Two findings baked into ABI: bandersnatch SW points are 65 B (2-bit SW flags overflow the 255-bit field's spare bit), and ark's G1 `mul_projective` GLV path panics above 4 limbs — the G1 arm fails closed there instead of inheriting a node-killing panic. | Tier 2 |
| Restored polkavm-linker dev-deps + `[patch.crates-io]` graph closure (standalone workspace root; mirrored in the parent workspace) | `polkavm-linker/Cargo.toml`, workspace `Cargo.toml`/`Cargo.lock` | crates.io tarball normalization stripped upstream's versionless path dev-deps (the linker's test module never compiled here: now 71/71) AND left inter-crate version edges resolving to PRISTINE registry copies — registry polkavm-assembler and a second polkavm-common were in the shipped graph, breaking this file's "every byte is in this tree" premise. Both workspaces now force all polkavm-family edges to vendored paths. Also: upstream YANKED polkavm 0.32.0 from crates.io. | Coherence |

## Pre-existing constraints carried forward

- **Generic sandbox is "experimental" upstream.** We accept this designation
  and own the production hardening per the locked design (separate workstream
  S1).
- **Linux sandbox excluded from RostroVM use.** Cross-platform requirement
  rules out the zygote-worker model. We always run in Generic.
- **JIT compiler is x86-64 + Linux only in upstream 0.32.0.** Cross-platform
  abstraction layer (workstream U2) addresses this.
