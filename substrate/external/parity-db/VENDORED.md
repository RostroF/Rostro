# parity-db (vendored)

Vendored copy of the upstream `parity-db` crate. Rostro's only on-disk
storage backend (RocksDb was stripped — see commits `3dc5bc26ee` and
`af6cb7498c` plus `docs/PARITYDB-EVALUATION.md`).

## Pin

| Field | Value |
|---|---|
| Upstream | <https://github.com/paritytech/parity-db> |
| Crates.io | <https://crates.io/crates/parity-db> |
| Version | **0.4.12** |
| License | MIT OR Apache-2.0 (both license files preserved as upstream ships them) |
| Fetched | 2026-05-30 |
| Source | Cargo registry tarball (bit-identical to the published 0.4.12) |

## Local modifications

**None.** This commit is copy-only — see
[[feedback_vendored_code_no_design_changes]]. Any future patch (CVE
fix, instrumentation, Rostro-specific tuning) lands as its own focused
commit with a one-line entry in the "Local modifications" table below.

| Date | Commit | Change | Reason |
|------|--------|--------|--------|

## Why vendored

Per [[feedback_sovereign_chain_vendored_is_ours]] — Rostro ships
parity-db, so any CVE in parity-db is Rostro's bug. With the crate
vendored we can patch immediately rather than waiting for an upstream
release. Per [[feedback_no_upstream_to_polkadot]] we don't rely on
upstream landing our fixes; we vendor and keep our patches as
competitive advantages.

## Updating to a new upstream version

1. Determine the target version. Read upstream's `CHANGELOG.md` since
   the pinned version above and identify which changes Rostro wants
   and which to skip ([[feedback_dependabot_as_intel_feed]]).
2. Re-fetch the source for that version (cargo registry tarball or
   `git clone` + checkout the tag).
3. `cp -a` the new source into this dir, **preserving the
   `VENDORED.md` file** (this file).
4. Re-apply any Rostro-local patches from the "Local modifications"
   table by hand or via a saved patch series.
5. Update the **Pin** table above with the new version + fetch date.
6. Rebuild + run the rc-state-db recovery tests (46/46 pass on the
   pinned version).
7. Run the paritydb-torture sweep at least once if upstream changed
   the commit-log / recovery / index format — those are the failure
   modes we tested in the original evaluation.
