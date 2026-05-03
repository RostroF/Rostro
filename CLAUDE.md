# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with
code in this repository.

## Repository Overview

This is the **Rostro** repository — runtime and node infrastructure for the
Rostro network family:

- **Rostro** — production mainnet
- **Canaria** — canary network (replaces Kusama in the lineage)
- **Camino** — public testnet (replaces Paseo in the lineage)

The repository is a fork of the Polkadot SDK with the relay-chain, parachain,
bridge, and EVM-compatibility surfaces removed. What remains is the Substrate
framework, FRAME, and the consensus and client primitives needed for a
sovereign chain. License posture is Apache-2.0 across the surviving tree.

## Tree Layout

- `substrate/` — Substrate framework, FRAME pallets, consensus/client/network
  primitives, test utilities. The framework name "Substrate" is preserved as
  domain vocabulary.
- `docs/` — process documentation (audit, backport, release).
- `scripts/` — build and CI helpers.
- `docker/` — container build configuration.

Removed during the cull (do not look for them): `cumulus/`, `polkadot/`,
`bridges/`, `templates/`, `umbrella/`, `prdoc/`, `Plan.toml`, all parachain
runtimes, and `substrate/frame/revive` (PolkaVM-based EVM compatibility).

## Rust Toolchain

Stable Rust toolchain. Nightly only required for `cargo +nightly fmt`. The
`rust-src` component is required for the PolkaVM build target. The
`wasm32v1-none` target is required to compile WASM runtimes.

## Build Commands

```bash
# Check or clippy the workspace (skips time-intensive WASM runtime build)
SKIP_WASM_BUILD=1 cargo check --workspace --all-targets --all-features
SKIP_WASM_BUILD=1 cargo clippy --workspace --all-targets --all-features

# revive/fixtures was culled, but if any leftover ref re-emerges, this skips it
SKIP_PALLET_REVIVE_FIXTURES=1 cargo check --workspace --all-targets
```

## Testing

```bash
cargo test --workspace --profile testnet
```

## Formatting

```bash
cargo +nightly fmt
taplo format --config .config/taplo.toml
```

## Architecture

### Runtime vs Node

Substrate separates **runtime** (on-chain logic, compiled to WASM) from
**node** (off-chain client):

- Runtime code lives under `*/runtime/` and must be `no_std` compatible.
- Node/client code lives under `*/client/`.

### FRAME Pallets

Pallets are modular runtime components in `substrate/frame/`. Each pallet has
a `Config` trait, optional storage items, dispatchables, events, and errors,
and uses `frame_support` macros (`#[pallet::*]`).

The `frame-*` and `pallet-*` naming is preserved as domain vocabulary.
Net-new Rostro pallets (forthcoming: personhood, name service, hardware
attestation, recall, strikes, bicameral, ranked-vote, milestone treasury) use
the `pallet-rostro-*` namespace.

### Consensus

Sassafras (`pallet-sassafras` + `sp-consensus-sassafras` + `sc-consensus-sassafras`)
is the production block-production scheme. Anonymous slot assignment via
Ring VRF gives collusion resistance the cert layer cannot provide.

GRANDPA is the finality layer.

BABE primitives and client (`sp-consensus-babe`, `sc-consensus-babe`,
`pallet-babe`) remain in the tree as library types — `substrate-test-runtime`
bakes BABE into its construct_runtime, and 39 substrate test crates depend
on it transitively. BABE is never instantiated as the production block
producer.

### Key Directories

- `substrate/primitives/` — `sp-*` core types shared across the codebase.
- `substrate/frame/support/` — `frame_support` macros and runtime helpers.
- `substrate/frame/system/` — `frame_system` — the foundational pallet.
- `substrate/client/` — `sc-*` client/node-side code.
- `substrate/utils/merkle-mountain-range/` — vendored MMR with **Rostro
  hardenings (A–F)** in `tests/test_rostro_hardenings.rs`. These are
  Hyperbridge-class fix tests that have been written and pass; do not
  remove them when refactoring.

## Code Style

- **Indentation**: tabs.
- **Line width**: 100 characters max.
- **Panickers**: avoid `unwrap()`; if used, add a proof comment ending with
  `; qed`.
- **Unsafe code**: requires an explicit safety justification.
- **Comments**: write none by default. Only write a comment when the *why* is
  non-obvious. Don't restate what the code does.

## License

Apache-2.0 across the surviving tree. Original Parity Technologies copyright
is preserved per Apache-2.0 NOTICE requirements; do not remove upstream
attribution. New code carries Rostro Foundation copyright alongside, not
replacing, upstream attribution.

## Out-of-Repo Working Primitives

Several Rostro components live outside this repo and will be grafted in
during the runtime integration phase:

- `~/Polkadot/paseo-node/` — solochain wiring harness with the working
  pallets (PNS, ZK-PKI, Secret Squirrel messaging) running against Aura +
  Grandpa + Sudo. Becomes the basis for `camino-runtime`.
- `~/Polkadot/pki/` — hardware-attestation PKI implementation (`zk-pki-*`
  crates, ink! trust-chain contracts).
- `~/Polkadot/zkpki-circuits/` — circom circuit (`mime_wrap.circom`).
- `~/Polkadot/zkpki-verifier-lab/` — Rust Groth16 verifier (ark-groth16,
  ark-bn254).
- `~/Polkadot/zkpki-pallet-lab/` — standalone FRAME pallet (Stage 4a,
  mock-runtime tests passing).
- `~/Polkadot/pns-pallets/` — Polkadot Name Service (6 pallets).
- `~/Polkadot/dotwave/` — Flutter + Rust mobile super-app.

When working in this Rostro repo, do **not** modify those out-of-repo
working primitives unless explicitly asked. Their CLAUDE.md restricts cross-
contamination.


