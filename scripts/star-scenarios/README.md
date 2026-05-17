# Phase Star — canonical-files gate scenarios

End-to-end scenarios exercising the Phase 7 v2 canonical-files network-edge gate
on the 5-node star. Each scenario sets up a specific state, runs the star for a
bounded time, asserts via per-node log greps, then tears down.

## Prerequisites

Build both binaries first:

```
SUBSTRATE_ENABLE_POLKAVM=1 cargo build --release -p gemini-node -p rostro-supervisor
```

The scenarios use the binaries at `target/release/gemini-node` and
`target/release/rostro-supervisor`. Override via `GEMINI_NODE` and
`ROSTRO_SUPERVISOR` env vars if needed.

## Scenarios

| # | Script | What it verifies |
|---|---|---|
| 01 | `01-all-clean.sh` | All 5 nodes boot, every node logs `verified canonical`, attest passes pairwise, blocks finalize. |
| 02 | `02-healable-drift.sh` | One node has a tampered binary + has the canonical bytes available in its `--canonical-files-dir`. Node heals via the local dir, exits 90, supervisor swaps, fresh child boots clean, rejoins the star. |
| 03 | `03-unhealable-drift.sh` | One node has a tampered binary and NO canonical bytes available. Verifier emits `FOUNDATION FILESET MISMATCH`, node fail-stops. Other 4 continue. |

## Deferred scenarios

The following are planned but require additional tooling beyond v0:

| # | Why deferred |
|---|---|
| 04 — mid-run-drift | Needs an SRT-extrinsic submitter (subxt or similar) to publish a new canonical file mid-run and observe drift propagation across peers. |
| 05 — adversarial-probe | Needs a standalone fake-peer (libp2p client outside the gemini-node binary) that opens `/rostro/canonical-attest/1` with a deliberately-wrong claimed_root to exercise the ban path. |

Both land once the asker-side broadcast infrastructure (Piece 2c follow-up for
heal-fetch client) is in place.

## How each scenario reports

* Exit 0 on success.
* Exit 1 on assertion failure with a diagnostic dump of the relevant log
  fragment.
* The per-node logs are preserved under `.star/<name>/run.log` after the script
  exits so you can inspect by hand.
