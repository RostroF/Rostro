# pallet-proof-verifier

Generic on-chain Plonky3 STARK verifier pallet for Rostro.

## Role in the architecture

Three downstream workloads consume this pallet, all building on the same
Plonky3/FRI/Goldilocks infrastructure:

1. **Execution proofs** — validators verify that a block's state
   transition was computed correctly without re-executing. Targets
   ~10–50 ms verify time vs seconds of re-execution.
2. **Light-client checkpoints** (BEEFY-equivalent) — aggregate K-of-N
   validator signatures into a single STARK proof that mobile light
   clients verify in 50–300 ms. Replaces BLS12-381 BEEFY aggregation
   with a post-quantum-secure scheme.
3. **Validator-side hip-check** — hardware-attestation continuity
   proven in Plonky3 instead of Groth16/BN254 (validator hardware can
   run FRI provers; mobile cannot, so mobile keeps Groth16 for v1).

## Configuration commitments

Per `crypto_stack_v1.md`:

- **Field**: Goldilocks (`p3-goldilocks`, 64-bit prime, well-established)
- **Extension**: `BinomialExtensionField<Goldilocks, 2>` (~128-bit security)
- **In-circuit hash**: Poseidon2 (FRI-friendly, circuit-efficient)
- **Out-of-circuit hash**: Keccak (NIST SHA-3, transparent)
- **Proof system**: uni-stark + TwoAdicFriPcs
- **PQ posture**: hash-based, transparent setup, no curve assumption,
  post-quantum-secure by construction

## Surface

The pallet is verifier-only. Proof generation happens off-chain
(validator daemons, operator services).

Each circuit family registers its verifying-key blob via
`register_verifier(verifying_key, circuit_family)` (gated on
`Config::RegistrarOrigin`, typically root or governance). Subsequent
proofs reference the key by its Blake2b-256 hash via
`verify_proof(key_hash, proof, public_inputs)`.

## Status

**v0.1 — wiring scaffold.** The `verify_proof` extrinsic currently
performs storage lookup + event emission but does not yet invoke the
Plonky3 verifier. Real cryptographic verification dispatched per
`circuit_family` lands in a follow-up commit, alongside the first
concrete circuit (most likely the validator-side hip-check or
light-client checkpoint, whichever is wired up first).

## Audit lineage

Plonky3 itself has been audited by Least Authority for Polygon
(report: <https://github.com/Plonky3/Plonky3/blob/main/audits/>).

Rostro-specific extensions to this pallet (circuit dispatch, on-chain
verifier integration) require a separate pre-mainnet audit.

## License

Apache-2.0. See [`LICENSE-APACHE`](../../../LICENSE-APACHE) at the
repository root.
