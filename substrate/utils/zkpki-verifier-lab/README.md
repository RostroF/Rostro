# zkpki-verifier-lab

Stage 3 research environment for the on-chain Groth16 verifier of the
mime-wrap circuit.

Standalone crate, not integrated into `pns-node` or `pki`. Built from
the same artifacts produced by `zkpki-circuits/` (the Stage 1 circuit
lab). The symlinks in `fixtures/` point to that sibling directory —
if its build dir moves, update the symlinks.

## What's in here

Two surfaces in the same crate root:

1. **Production-path verify** — `verify_proof` + VK serialize / load
   helpers. This is the kernel the eventual Substrate pallet's
   extrinsic will call. Uses only `ark-groth16` + `ark-bn254` +
   `ark-serialize`; no ark-circom, no wasmer, no file I/O. Shaped
   to copy-paste into a `no_std` pallet.

2. **Fixture generation** — `generate_sample_proof` uses ark-circom
   end-to-end (loads zkey, runs witness calc via wasm, produces a
   Groth16 proof) so tests and the benchmark have fresh valid inputs
   without JSON-format gymnastics. std-only, never ships.

## How to run

```bash
# From repo root
cd /home/coder/Polkadot/zkpki-verifier-lab

# Prereq: the Stage 1 circuit has been built in ../zkpki-circuits/
ls -la fixtures/    # should show symlinks to mime_wrap.{wasm,r1cs} + mime_wrap_final.zkey

# Round-trip smoke test (generate proof → verify → tamper-reject)
cargo test --release -- --nocapture

# Criterion benchmark — measures verify_proof latency only
cargo bench
```

## Pass criteria

The lab is "passing" when all of these hold:

1. `cargo test --release` completes without panics
2. Valid proof verifies (`ok == true`)
3. Tampered public input rejected (`ok == false`)
4. VK serialize → deserialize round-trip keeps verification correct
5. Criterion benchmark reports a per-verify wall-clock time
6. That time × 1_000_000 (WU/ms conversion) fits within a reasonable
   fraction (< 10%) of a Substrate block's weight budget

## Next stage — what to port to the pallet

After this lab passes, the extract-to-pallet is:
- Copy `verify_proof`, `serialize_vk`, `deserialize_vk` into the pallet crate
- Strip the `anyhow` dep (use `DispatchError` / `Result<bool, ()>`)
- Store the prepared VK in pallet storage (or as a runtime constant)
- Expose a `verify_mime_wrap_proof(origin, proof_bytes, public_inputs)`
  extrinsic that calls into it
- Benchmark with `frame-benchmarking` to generate weight constants
