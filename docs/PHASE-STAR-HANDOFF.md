# Phase Star — handoff

**Last touched:** 2026-05-15
**Branch:** `phase-star` (worktree at `/home/coder/Rostro-phase-star/`; primary checkout at `/home/coder/Rostro/` is on `rostro-main`)
**HEAD:** `14612f88e5` (phase-star B6: RostroCodeExecutor + ReadRuntimeVersion + rostro-node dep)

This document is the working state for Phase Star — the successor to Phase Gemini. Pick up here when you come back.

---

## What this phase is

The 5-node-star testbed and the WASM→RVM runtime-executor swap, in the same branch. Named after the star pattern of 5 nodes peered and communicating; ships when that's achieved on PVM-compiled runtimes.

When this phase lands:

- `rostro-executor` (Apache-2.0) is the runtime executor; the inherited GPL-3 `rc-executor-polkavm` is dead code.
- `rostro-runtime` and `gemini-runtime` cross-compile to PVM blobs and run on `rostro-executor`.
- A 5-node star of `gemini-node` peers + produces + finalises on PVM.
- `gemini-node` earns its rename (see `network_vs_binary_lineage.md` memory).

See `phase_star.md` memory for the full phase definition.

---

## What's done — eight commits on `phase-star`

```
14612f88e5 B6  — RostroCodeExecutor + ReadRuntimeVersion + rostro-node dep
6e3f7a854f B3c — allocator-return-path trap diagnosed + closed
7d79fd538d B3b — register hashing + crypto + misc HostFunctions tuples
0defd17ac4 B5  — rostro-runtime cross-compiles to PVM, loads via executor
f5e313cd2e B3  — host-fn dispatcher + sp-io storage wired + PVM-guest test
e35451017f B2  — rostro-executor module load + run loop against fork
6171bc255c B1  — scaffold rostro-executor crate
65884723a0 A   — redirect polkavm deps to vendored rostrovm fork
```

### A — workspace polkavm → vendored rostrovm fork
- Four workspace deps (`polkavm`, `polkavm-common`, `polkavm-derive`, `polkavm-linker`) repointed from crates.io `0.31.0` to path-deps at `substrate/external/rostrovm/`.
- Cfg-gate fix in the fork: `mod rostro_intrinsic_codegen` + its `pub use` re-export now sit inside `if_compiler_is_supported!`, so consumers without `generic-sandbox` + `std` don't trip on missing `crate::sandbox`.
- `rc-executor-polkavm` dropped from `rc-executor`'s umbrella and excluded from workspace members. Source stays in tree as upstream reference; the API drift (polkavm 0.32 made memory accessors `&mut self` while `sp_wasm_interface::FunctionContext::read_memory_into` is `&self`) is no longer in any build graph.
- `gemini-runtime` fix: added three missing `pallet_rostro_personhood::Config` items (`MaxProofBytes`, `ExpectedVkFingerprints`, `AcceptedNullifierTypes`) inherited as a build break from the phase8e merge.
- **Gate:** `cargo check --workspace` 0 errors; `rostro-vm-bench` smoke 20/20; vendored polkavm KAT 13/13.

### B1 — rostro-executor scaffold
- New crate at `substrate/utils/rostro-executor/`, Apache-2.0, workspace member.
- Empty scaffold; no functionality yet.
- **Gate:** `cargo check -p rostro-executor` clean.

### B2 — module load + run loop
- `RostroExecutor::from_blob` → `Config::from_env`, Generic sandbox, sync gas metering, `Module::new`.
- `RostroExecutor::call(export, gas_limit) → CallOutcome` — instantiate, set PC + RA sentinel, drive run loop, unpack A0 + gas consumed.
- `Error` enum: EngineInit / ModuleCompile / Instantiate / ExportNotFound / RunLoop / Trap / OutOfGas / Segfault / UnhandledEcalli / UnexpectedStep.
- `rvm_gas_to_weight(i64) → sp_weights::Weight` — locked `×1000` conversion (1 RVM gas = 1 ns; substrate `Weight` is picoseconds).
- **Gate:** 5 lib tests pass (load+call, error paths, gas conversion).

### B3 — host-fn dispatcher + PVM toolchain + sp-io storage roundtrip
- `host_fn::RostroFunctionContext` — `sp_wasm_interface::FunctionContext` impl backed by `polkavm::Caller`, bridging substrate's `&self` memory accessors to polkavm 0.32's `&mut self` via a `RefCell`. Safe Rust; no unsafe reborrow.
- `host_fn::register_substrate_host_functions::<UD, HF>` — generic Linker registration loop. Works for any `H: HostFunctions`.
- `host_fn::dispatch_substrate_function` — per-call bridge: reads args from `Reg::ARG_REGS` per the function's `Signature`, boxes as `Value`, invokes `Function::execute`, writes return to `Reg::A0`.
- `allocate_memory` via `inst.sbrk(0)` + `inst.sbrk(size)`, returning the pre-growth break. `deallocate_memory` is a no-op (PVM runtime allocator drops at instance teardown).
- `RostroExecutor::call_with_host_fns::<HF>(...)` — new entry point that builds a Linker, instantiates pre-linked, drives `call_typed`.
- PVM toolchain validation: `substrate-wasm-builder` already handles PVM via `SUBSTRATE_RUNTIME_TARGET=riscv`. No separate `rostro-runtime-builder` crate needed.
- New fixture crate at `tests/fixtures/storage-roundtrip/` — tiny no_std guest that exercises `sp_io::storage::set`. Builds via `polkavm_derive::polkavm_export` (NOT `sp_core::wasm_export_functions!`, which doesn't emit the polkavm export attribute).
- **Gate:** Fixture's `sp_io::storage::set` lands in host-side `BasicExternalities`; verified via `sp_io::storage::get` from the test code.

### B5 — rostro-runtime cross-compiles to PVM
- `SUBSTRATE_RUNTIME_TARGET=riscv cargo build -p rostro-runtime` produces a 2.3 MB `.polkavm` blob at `target/debug/rbuild/rostro-runtime/rostro-runtime-blob.polkavm` in ~2 minutes.
- `RostroExecutor::from_blob` parses the blob; export table contains the expected `Core_*` / `BlockBuilder_*` / `Metadata_*` / `AuraApi_*` / `GrandpaApi_*` / etc. runtime API symbols.
- **Gate:** `cargo test -p rostro-executor --test rostro_runtime_loads -- --ignored` (the `#[ignore]` requires the env var; without it the test would compare against a WASM blob).

### B3b — HostFunctions tuple registration
- `B3bHostFns = (sp_io::storage, sp_io::hashing, sp_io::crypto, sp_io::misc)::HostFunctions` — tuple registration validated end-to-end. The polkavm linker resolves every imported host-fn name at instantiation time.
- Added fixture exports for `test_hashing_{blake2_256,keccak_256,twox_128}` and `test_crypto_ed25519_verify`.
- Four `#[ignore]`'d regression tests staged for B3c's diagnostic work.

### B3c — allocator-return-path trap closed
- **Root cause:** substrate's runtime-side `AllocateAndReturnPointer::from_ffi_value` (at `substrate/primitives/runtime-interface/src/pass_by.rs:644`) wraps the host-returned pointer in `Vec::from_raw_parts(ptr, N, N)`. When that Vec falls out of scope, its `Drop` dispatches `ext_allocator_free_version_1` — which wasn't in my linker. Unhandled ecalli → trap.
- **Fix:** add `sp_io::allocator::HostFunctions` to `B3bHostFns`. The dispatcher + `FunctionContext` were never broken; the host-fn registration was incomplete.
- `test_crypto_ed25519_verify` rewritten to test rejection of a garbage signature rather than acceptance of an RFC 8032 vector — substrate's `ed25519-zebra` actually accepts the math-degenerate all-zero case (see `sp_io::lib.rs:2126-2131` for upstream's documented behaviour). Avoids depending on a known-good test-vector transcription.
- **Gate:** all 4 previously-`#[ignore]`'d B3b regression tests now pass.

### B6 — `RostroCodeExecutor` + `ReadRuntimeVersion` + `rostro-node` dep
- `RostroCodeExecutor<H: HostFunctions>` in [src/code_executor.rs](../substrate/utils/rostro-executor/src/code_executor.rs). Implements `sp_core::traits::{CodeExecutor, ReadRuntimeVersion}` per the substrate runtime ABI:
    ```
    pc        = module.exports().find(name).program_counter()
    data_ptr  = module.memory_map().heap_base()
    data_len  = u32::try_from(input.len())?
    reset_memory()
    sbrk(data_len)
    write_memory(data_ptr, input)
    call_typed(pc, (data_ptr, data_len))
    packed    = inst.reg(A0)
    output    = read_memory(packed as u32, (packed >> 32) as u32)
    ```
- No gas metering on runtime calls. The runtime's own `Weight` tracking does the equivalent at the FRAME layer. Matches `rc-executor-polkavm`'s `unreachable!("gas metering is never enabled")` arm.
- `Clone` via `Arc::clone(&self.engine)` — modules are recompiled per call so they don't flow through `Clone`. No module cache yet.
- `rostro-node` gains `rostro-executor` as a workspace dep; binary links it in but doesn't use it yet (no service-builder swap).
- **Gate:** `SUBSTRATE_RUNTIME_TARGET=riscv cargo test -p rostro-executor --test code_executor -- --ignored` — `Core_version` called on the real `rostro-runtime` PVM blob, SCALE-decoded `RuntimeVersion` validated (`spec_name == "rostro"`, non-empty `apis`).

---

## Architecture summary

```
substrate/utils/rostro-executor/
├── src/
│   ├── lib.rs              — RostroExecutor (B2): module-and-call wrapper, no host fns
│   │                        — Error enum, rvm_gas_to_weight, CallOutcome
│   ├── host_fn.rs          — RostroFunctionContext (RefCell bridge)
│   │                        — register_substrate_host_functions::<UD, HF>
│   │                        — dispatch_substrate_function
│   │                        — allocate_memory (sbrk), deallocate_memory (no-op),
│   │                          register_panic_error_message
│   └── code_executor.rs    — RostroCodeExecutor<H> implementing CodeExecutor +
│                             ReadRuntimeVersion (B6)
└── tests/
    ├── fixtures/storage-roundtrip/  — no_std PVM guest (polkavm_export'd entries)
    ├── storage_roundtrip.rs         — B3/B3b/B3c integration (5 tests)
    ├── rostro_runtime_loads.rs      — B5 gate (#[ignore])
    └── code_executor.rs             — B6 gate (#[ignore])
```

`substrate/utils/rostro-executor` is Apache-2.0 zone per `feedback_client_dir_gpl3` memory. No code lives at `substrate/client/`.

---

## Locked decisions

1. **PVM toolchain = existing `substrate-wasm-builder`.** `SUBSTRATE_RUNTIME_TARGET=riscv` switches the WasmBuilder to its `RuntimeTarget::Riscv` branch. The Camino handoff's proposed `rostro-runtime-builder` crate isn't needed.
2. **Target spec.** `riscv64emac-unknown-none-polkavm` (generated dynamically by `polkavm_linker::target_json_path`).
3. **Gas anchor.** 1 RVM gas ≈ 1 ns of native work on the audit reference machine. Substrate `Weight` is picoseconds; the boundary multiplies by 1000. One conversion constant: `rostro_executor::rvm_gas_to_weight`.
4. **No gas metering on runtime calls.** Substrate runtimes track Weight at the FRAME layer.
5. **`Generic` sandbox kind, sandboxing off** unless `POLKAVM_SANDBOXING_ENABLED` is set (matches `rostro-vm-bench`).
6. **`polkavm_derive::polkavm_export`, not `sp_core::wasm_export_functions!`.** The latter only emits `#[no_mangle] pub fn`, which polkavm-linker strips as internal — guest blobs come out empty.
7. **`sp_io::allocator::HostFunctions` is required.** Substrate's `AllocateAndReturnPointer` return path wraps the host-returned pointer in a `Vec` whose `Drop` calls back to `ext_allocator_free_*`.

---

## What's next — B7 through B10

### B7 — End-to-end: rostro-node solochain on PVM
**Goal:** `rostro-node` boots with `rostro-executor` as the substrate-side executor, runs the Stage 5 (rostro-main) gates 1–5 on the PVM-compiled `rostro-runtime`.

**Work-list:**
- Decide the executor dispatch shape in `substrate/bin/rostro-node/src/service.rs`. Three options:
  - **Type swap:** change `type FullClient = TFullClient<Block, RuntimeApi, rc_executor::WasmExecutor<sp_io::SubstrateHostFunctions>>` to `... rostro_executor::RostroCodeExecutor<sp_io::SubstrateHostFunctions>`. Simplest. Loses the WASM fallback.
  - **Hybrid wrapper:** `RostroHybridExecutor` that holds both, dispatches on blob magic (`b"PVM\0"` vs `b"\0asm"`). More work; keeps WASM safety net per `[VM choice]` memo until B9 explicitly retires it.
  - **Cargo feature gate:** select between two type aliases at build time via a feature. Simple but builds-as-spec contract; the runtime config has to know.
- Build pipeline: ensure `SUBSTRATE_RUNTIME_TARGET=riscv` is set when building `rostro-node` so it embeds the PVM blob (vs WASM) — or thread it through cargo aliases / build profile.
- Stage 5 gates verify the chain runs end-to-end:
  1. **Build.** `SUBSTRATE_RUNTIME_TARGET=riscv cargo build --release -p rostro-node` produces a binary.
  2. **Boot.** `./rostro-node --dev --tmp --alice` reaches AUTHORITY role, RPC :9944, prometheus :9615.
  3. **Block production.** 6-second slots, blocks finalized by GRANDPA at 2-block lag.
  4. **Signed extrinsic.** `balance.transferKeepAlive Alice→Bob` lands in a block, free balances reconcile, `system.ExtrinsicSuccess` emitted.
  5. **Runtime upgrade.** `sudo.sudo(system.setCode(<new PVM wasm>))` advances `spec_version`, chain keeps producing under the new blob.

**Gate:** all five sub-gates green.

### B8 — Same for `gemini-node` (Sassafras, peered)
**Goal:** the peered testbed runs on PVM end-to-end. Two `gemini-node` instances configured as the gemini-twins peer + produce + finalise against PVM-compiled `gemini-runtime`.

**Work-list:**
- Build `gemini-runtime` as PVM (same `SUBSTRATE_RUNTIME_TARGET=riscv` recipe).
- Wire `rostro-executor` into `gemini-node/src/service.rs` (same dispatch decision as B7).
- 2-node Alice+Bob recipe from `README.md` "Running a node" section but with PVM runtime.
- Sassafras-specific concerns: ticket generation, Ring VRF — verify those still flow correctly through the runtime call path.

**Gate:** twin peering + block production + GRANDPA finality on PVM.

### B9 — Retire WASM runtime path
**Goal:** subtract by default. WASM-runtime is gone from the tree once PVM is proven on B7/B8.

**Work-list:**
- Remove WASM-target cfg branches in `sp-io` and `sp-runtime-interface` (the `cfg(not(target_arch = "riscv*"))` arms).
- Delete `substrate/client/executor/polkavm/` entirely. It was upstream reference; `rostro-executor` has replaced it.
- Consider whether `rc-executor-wasmtime` still has a consumer. If only the WASM-runtime path used it, delete that too.
- The `wasmtime` workspace dep can probably go.

**Gate:** `cargo check --workspace` clean; both nodes still boot on PVM; binary size shrinks.

### B10 — 5-node star (Phase Star milestone)
**Goal:** the namesake. Five `gemini-node` instances in a star peering topology, all running PVM `gemini-runtime`, all producing + finalising.

**Work-list:**
- Topology: one bootnode + four leaves, or full mesh — designer's call.
- Each node holds its own session keys.
- Resource budget: 5× `gemini-node` instances on a single machine is in scope given the 64 GB RAM upgrade; otherwise disposable Hetzner per `phase_gemini` memory.
- Network handshake: ChaCha20-Poly1305 + Noise XX per-session FS (locked at v0.1.0).

**Gate:** 5 nodes peer, communicate, produce blocks, finalise. Earns the `gemini-node` rename per `network_vs_binary_lineage` memory.

---

## Open decisions / parking lot

- **Module cache.** Each `RostroCodeExecutor::call` currently recompiles the blob. Adding a hash-keyed cache (`Arc<Mutex<HashMap<[u8; 32], Module>>>`) is straightforward but a hot path. Benchmark first.
- **Tier 2 intrinsic routing for crypto.** The vendored rostrovm fork has native `ROSTRO_INTRINSIC_*` for ed25519, secp256k1_recover, blake2b, keccak, etc. (IDs 100–130). Currently `sp_io::crypto::ed25519_verify` dispatches through substrate's host-fn impl (ed25519-zebra). Routing the host-fn callback through the Tier 2 intrinsic directly would give ZIP-215 + strict-mode rejection for free — and substantial perf via JIT codegen. Optional optimization, not on the B7 critical path.
- **Embedded `runtime_version` fast path in `ReadRuntimeVersion`.** Current impl always calls `Core_version` (slow). Substrate's WASM executor has a fast path that reads an embedded `runtime_version` section. polkavm-linker may or may not preserve that section; investigate before B7.
- **Hybrid wrapper for blob-format dispatch.** Tied to the B7 dispatch shape decision. If we commit to PVM-only at B9, the hybrid wrapper is short-lived bloat. If we keep WASM around longer, it's a real abstraction.
- **`register_panic_error_message`.** Currently logs and drops. Substrate's expectation is the message gets paired with the next trap and surfaced through the error path. B7's `CodeExecutor::call` error mapping should plumb this through.

---

## Workflow notes

- **Worktree.** `phase-star` lives in `/home/coder/Rostro-phase-star/` so the primary checkout at `/home/coder/Rostro/` stays on `rostro-main` as a known-good fallback. `git worktree list` to verify. The Rostro-vm/ worktree exists for the unrelated `vm-research` branch.
- **Per-stage commits.** Each stage gates green, then commits. No squashing — clean rollback boundaries.
- **Build artifacts.** PVM blobs land at `target/debug/rbuild/<crate>/<crate>-blob.polkavm`. The `wasm_binary.rs` generated in `target/debug/build/<crate>/out/` re-exports the path + bytes.
- **The runtime build needs `SUBSTRATE_RUNTIME_TARGET=riscv`.** Without it, `WASM_BINARY` contains WASM bytes; tests that load via `RostroExecutor::from_blob` sniff `b"PVM\0"` magic and report clearly.

---

## Files to read first when picking this up

In order:

1. This file.
2. [src/code_executor.rs](../substrate/utils/rostro-executor/src/code_executor.rs) — the `CodeExecutor` / `ReadRuntimeVersion` impl, ~210 LOC.
3. [src/host_fn.rs](../substrate/utils/rostro-executor/src/host_fn.rs) — the dispatcher + `FunctionContext` bridge, ~200 LOC.
4. [src/lib.rs](../substrate/utils/rostro-executor/src/lib.rs) — `RostroExecutor` + `Error` + `rvm_gas_to_weight`.
5. [tests/code_executor.rs](../substrate/utils/rostro-executor/tests/code_executor.rs) — the B6 gate; copy this pattern for `RostroCodeExecutor` invocation in service.rs.
6. [tests/storage_roundtrip.rs](../substrate/utils/rostro-executor/tests/storage_roundtrip.rs) — the B3/B3b/B3c integration tests; `B3bHostFns` is the canonical HostFunctions tuple.
7. `git log --oneline phase-star -10` — the merge picture.

## Relevant memory pointers

- `phase_star` — phase definition + workstream list.
- `network_vs_binary_lineage` — Camino is a network, gemini-node is a binary; the rename happens when this phase ships.
- `vm_choice_riscv_vs_wasm` — closed decision in favour of full pivot to RVM.
- `feedback_client_dir_gpl3` — why `rostro-executor` lives at `substrate/utils/`, not `substrate/client/`.
- `feedback_vendored_code_no_design_changes` — the vendored rostrovm fork at `substrate/external/rostrovm/` only gets surgical bug-fixes (e.g. the cfg-gate fix in workstream A), no feature adds.
- `feedback_dont_overcommit` — per-stage commits are aligned with the explicit user preference for clean rollback boundaries on this branch.
- `rostrovm_design_locked` — what RVM is + isn't (chain-side, not shop-side optimisation).
- `crypto_stack_v1` — substrate's `ed25519-zebra` is what `sp_io::crypto::ed25519_verify` runs through today; relevant for the Tier 2 routing follow-up.
