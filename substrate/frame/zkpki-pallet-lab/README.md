# zkpki-pallet-lab

**Stage 4a** of the zkpki PoC — a standalone FRAME pallet that verifies
mime_wrap Groth16 proofs and tracks consumed (bucket, nonce) pairs for
replay prevention.

Not integrated into `pns-node` yet. Once the mock-runtime integration
tests pass cleanly, the pallet source can be copy-pasted into a new
`pns-node/pallets/zkpki-mime-wrap/` directory without semantic change.

## What this lab validates

Five integration tests, all against a mock runtime, using real
Groth16 proofs produced at test-setup time via ark-circom:

1. **register_commitment_succeeds_once** — ceremony-time storage
   works; double-registration is rejected.
2. **verify_and_record_happy_path** — a valid proof verifies, the
   (bucket, nonce) gets recorded, the event fires.
3. **replay_rejected** — second attempt with same (bucket, nonce) is
   rejected even with a still-valid proof.
4. **tampered_otp_rejected** — flipping one bit of user_otp makes the
   proof no longer match public inputs; pairing check fails cleanly.
5. **missing_commitment_rejected / missing_vk_rejected** — the two
   setup prerequisites are enforced.

## Prerequisites

- Stage 1 circuit artifacts must be built at
  `../zkpki-circuits/build/mime_wrap.r1cs` and
  `../zkpki-circuits/build/mime_wrap_js/mime_wrap.wasm`. If you haven't,
  run `cd ../zkpki-circuits && npm run compile` first.
- Rust 1.85+ (edition 2024).
- Polkadot SDK deps fetch from git (stable2603 branch) on first build —
  expect 10-20 min of initial dependency compile time.

## Running

```bash
cd /home/coder/Polkadot/zkpki-pallet-lab
cargo test --release -- --nocapture
```

Expected: 5 tests pass, ~30-90 seconds total (each test generates a
fresh Groth16 proof during setup).

## Scope for 4a (explicit non-goals)

- **No attestation-chain verification in the pallet.** The mime_wrap
  pallet only handles Groth16 verify + replay state. Attestation
  (Android Keystore chain → Google root) lives in a separate
  pallet / the HIP pipeline.
- **No frame-benchmarking weight constants.** Weights are stub
  `Weight::from_parts(N, 0)` values. Real weights land in Stage 4b.
- **No on-chain key revocation / release.** Re-enrollment requires a
  release flow that's deferred to a later stage.
- **No on-chain nonce pruning.** `ConsumedNonces` will grow
  unboundedly in 4a; `on_idle`-based pruning is a 4b concern.
- **No in-Rust vs snarkjs VK format negotiation.** The lab uses
  in-Rust `circuit_specific_setup` for VKs, same workaround as the
  Stage 3 verifier lab. Production path resolution is backlogged.

## Next stages

- **4b**: graft the pallet into pns-node's runtime; add
  frame-benchmarking weights.
- **4c**: dotwave computes commitment at ceremony, submits; sign flow
  produces proof, submits to running node; real-hardware replay test.
