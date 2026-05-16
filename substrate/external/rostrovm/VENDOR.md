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
| (none yet) | | | |

## Pre-existing constraints carried forward

- **Generic sandbox is "experimental" upstream.** We accept this designation
  and own the production hardening per the locked design (separate workstream
  S1).
- **Linux sandbox excluded from RostroVM use.** Cross-platform requirement
  rules out the zygote-worker model. We always run in Generic.
- **JIT compiler is x86-64 + Linux only in upstream 0.32.0.** Cross-platform
  abstraction layer (workstream U2) addresses this.
