# Contributing to Rostro

The Rostro project is open to outside contributions under Apache-2.0.

## Scope

This repository contains the runtime and node infrastructure for the Rostro
network family (Rostro mainnet, Canaria canary, Camino testnet). Contributions
are welcome on:

- Runtime correctness, including the proof-of-personhood, governance,
  consensus, staking, and treasury pallets.
- Node and client improvements (networking, RPC, transaction pool, executor).
- Cryptographic primitives — including hardenings of inherited Substrate code
  that are tracked under `test_rostro_*` test names.
- Documentation, including in-code module-level docs and the public-facing
  Rostro Foundation site.

## How

1. Open an issue describing the work before opening a PR for non-trivial
   changes. This avoids duplicate effort and surfaces design questions early.
2. Fork the repository, branch from the most recent default branch, and open
   a pull request when the change is ready.
3. PRs need to pass CI (currently `cargo check --workspace --all-targets`,
   `cargo clippy --workspace`, and `cargo +nightly fmt --check`).
4. Security-sensitive findings go to **security@rostro.org**, not a public
   pull request — see [SECURITY.md](./SECURITY.md).

## Ground rules

1. **No `--force` pushes** to shared branches. If you need to rebase, do it
   in your own fork.
2. **Branches are short-lived and prefixed with a moniker** (e.g.,
   `tony-add-x-pallet`, `wei-polkavm-graft`).
3. **All modifications go through pull request review.** No direct commits to
   the default branch.
4. **No `--no-verify` on commits or pushes.** If pre-commit hooks fail, fix
   the underlying issue.
5. **Preserve upstream attribution.** Substrate and Polkadot SDK code carries
   Parity Technologies copyright; do not strip it. Add the Rostro Foundation
   copyright alongside, do not replace.

## Style

- Tabs for indentation, 100-character soft line limit (matches upstream
  Substrate convention).
- Avoid `unwrap()` in production paths. If used, add a proof comment ending
  with `; qed`.
- Unsafe code requires an explicit safety justification in the same module.
- Default to writing no comments — well-named identifiers do most of the
  documentation work. Comments are for non-obvious *why* (hidden constraints,
  workarounds, surprising invariants).

## Licensing

By submitting a contribution, you agree that your contribution is licensed
under Apache-2.0 and that you have the right to submit it under that license.
The Rostro Foundation does not require a separate CLA.

## Code of Conduct

See [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md). Briefly: be honest, be
specific, and engage with the technical work rather than the people doing it.
