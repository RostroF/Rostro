# Forkless Updates

How Rostro evolves without tearing down the network: two on-chain
paths, both ordinary extrinsics, both leaving every node's ParityDB
intact. No genesis re-derivation, ever, outside of standing up a brand
new chain.

| What changes            | Vehicle                                        | First proven |
|-------------------------|------------------------------------------------|--------------|
| Runtime logic (`:code`) | `sudo(System::set_code(blob))`                 | 2026-07-02, gemini dev chain, spec 100 → 101 |
| Node binary + manifests | `sudo(CanonicalFiles::register_file(path, h))` | 2026-07-02, register + boot-gate enforcement E2E |

`sudo` is the testnet stand-in for the SRT threshold origin
(`SrtOrigin = EnsureRoot`, see `substrate/runtime/gemini/src/lib.rs`).
Production replaces the signer, not the mechanism.

## 1. Runtime upgrades (set_code)

The runtime is a RISC-V blob executed by RostroVM. An upgrade is a
storage write: the new blob replaces `:code` at a block boundary, the
executor instantiates it for the next block, and no process restarts.

**Per-upgrade recipe (lab: `playbooks/06-runtime-upgrade.sh` in
`rostro-testnet-lab`):**

1. Bump `spec_version` in `substrate/runtime/gemini/src/lib.rs`.
   Substrate requires a strict increase; same-version submissions fail
   with `SpecVersionNeedsToIncrease`.
2. `SUBSTRATE_RUNTIME_TARGET=riscv cargo build --release -p gemini-runtime`
   → blob at `target/release/rbuild/gemini-runtime/gemini-runtime-blob.polkavm`.
3. Submit via `lab-sudo set-code <blob> --expect-spec-version <N>`
   (lab tool, `rostro-testnet-lab/scripts/extrinsic-tests/probe-bin`).
   It zstd-compresses the blob into the `sp-maybe-compressed-blob`
   envelope, submits `sudo_unchecked_weight(set_code)`, waits for
   finalization, checks `Sudo::Sudid` for the inner result, and polls
   until the node reports the new version.
4. Success = `System::CodeUpdated` emitted, `spec_version` flipped on
   every node, finality still advancing, zero process restarts.

### Compression is mandatory, not an optimization

The raw gemini blob is ~4.6 MB. The transaction pool accepts it (the
runtime's `BlockLength` ceiling is 5 MiB), but the block author's
default size limit (`sc-basic-authorship` `DEFAULT_BLOCK_SIZE_LIMIT`,
4 MiB + 512) is stricter. A raw-blob set_code therefore enters the
pool and is **silently never included**: every authoring round logs
`HitBlockSizeLimit`, the submitter's watch hangs forever, and no error
surfaces anywhere. Compressed (~2.0 MB, ~2.4x) it fits everywhere.
`lab-sudo` compresses by default and hard-fails at submit time if a
compressed payload would still exceed the proposer limit; if the
compressed runtime ever nears 4 MiB, single-extrinsic upgrades are
over and that limit needs a deliberate decision.

Two related sharp edges, learned the hard way:

- **Stuck-tx shadowing.** An immortal tx stuck in the pool blocks any
  retry from the same signer with `Priority is too low (N vs N)`.
  Flush by restarting the node (pool is in-memory) or bump the tip.
- **Executor decompression** (fixed 2026-07-02). `RostroCodeExecutor`
  fed fetched bytes straight to the PVM engine. A compressed blob
  failed `can_set_code` with `FailedToExtractRuntimeVersion`; worse, a
  compressed `:code` would have bricked block execution after a
  "successful" upgrade. `call_inner` now decompresses the
  `sp-maybe-compressed-blob` envelope at the single seam shared by
  `CodeExecutor::call`, `RuntimeVersionOf` and `ReadRuntimeVersion`
  (`substrate/utils/rostro-executor/src/code_executor.rs`). Raw
  `PVM\0` blobs (the genesis posture) pass through borrowed at zero
  cost. Note: the executor has no module cache (parked open decision,
  see PHASE-STAR-HANDOFF), so a compressed `:code` pays a per-call
  decompress until that lands.

## 2. Canonical-file updates (register_file)

`pallet-rostro-canonical-files` is a live registry, not a genesis
constant. The boot verifier (`gemini-node/src/file_check.rs`) reads
the registry at the **current chain head**, so a `register_file` at
block N re-baselines every node's expectations from that point on.
Old DBs stay valid because the change is just a storage write.

**Ordering rule (hard): publish bytes before flipping the registry.**
The heal path can only fetch bytes that exist somewhere. The lab
update flow (`playbooks/05-update-canonical.sh`):

1. Build + `release-sign.sh` → gemini-node, rostro-supervisor,
   manifest.txt, manifest.txt.sig (the manifest covers both binaries,
   so partial deploys create sig-vs-disk drift that release-verify
   rejects; ship the set together).
2. Push new bytes to every node's `/opt/rostro/canonical/` (heal
   source) while the old chain keeps running.
3. `lab-sudo register-file` for gemini-node, manifest.txt,
   manifest.txt.sig. Running nodes are now formally drifted; existing
   gossip connections persist (the attest gate fires at connect time).
4. Rolling restart, observer first, bootnode last. Two modes:
   manual install (deterministic), or `--via-heal`, which leaves the
   old binary in place so boot-time file_check detects the mismatch,
   heals from the local canonical cache, exits 90, and the supervisor
   rotates the new binary in. The second mode is the production
   self-update path and should be exercised regularly.

Proven behavior worth knowing: a node restarted while the registry
names a file it does not have **fail-stops by design** with a
"FOUNDATION FILESET MISMATCH" error unless a heal source is
configured. Registering hashes for not-yet-distributed files bricks
restarts until the bytes are published; see the ordering rule.

## 3. Lab workflow

Genesis is derived exactly once per network.
`03-deploy-canonical.sh` and `03b-deploy-watchdog-v0.2.sh` refuse to
run against a standing chain unless passed `--force-genesis`; routine
iteration goes through 05 (binaries) and 06 (runtime). The historical
wipe-ParityDB-every-rebuild loop was an artifact of re-deriving
genesis per deploy and is retired.

## 4. Production rollout design (converged, not yet implemented)

Design record from 2026-07-02, to be built as pallet work that itself
ships via set_code on the standing lab chain:

- Registry entries become staged pairs:
  `(active, pending: Option<(hash, promote_at_era)>)`.
  `register_file(path, hash, window_eras)` sets the pending slot; the
  gate accepts either hash during the window; promotion happens at the
  era boundary. `window_eras = 0` is the SRT emergency cutover.
- **Update buckets.** Each validator derives a private update slot,
  `VRF(sk, pending_hash) mod window_eras`, using its Sassafras key.
  Secret so the network's restart schedule cannot be attacked;
  provable after the fact for track-record accountability;
  re-randomized every release by deriving from the pending hash.
  Community nodes use the same scheme from their node key (no
  anonymity requirement, load-spreading only).
- **Enforcement.** The scheduler lives inside the canonical binary,
  so ignoring your bucket means running non-canonical bytes, which
  the attestation gate already catches. The hard deadline is the era
  boundary: nodes still attesting the old hash are excluded from the
  next validator election (never ejected mid-era; the maximum
  staleness overhang is one era). Past the deadline, non-compliant
  nodes are quarantined to the heal protocol until they match.
- **No operator-side "update now" lever exists on any network.** The
  lab's immediate-update posture works only because sudo is the chain
  authority there and bytes are pushed by hand.

## 5. Open items

- Trusted release pipeline: hash + sign + submit tooling beyond the
  lab (`rostro-client` v0 charter).
- Pending/deadline/quarantine pallet work (section 4).
- Auto-updater in the watchdog layer: watch the registry, heal-fetch
  inside the bucket window, swap at a session boundary.
- Module cache in `rostro-executor` (amortize per-call decompress +
  compile).
- `spec_version` bump automation for high-cadence lab upgrades.
