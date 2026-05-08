# Vendored test fixtures

Three large binary artifacts the verifier-lab consumes for its
ark-circom-driven proof generation paths:

- `mime_wrap.r1cs` (~21 MB) — circom-compiled R1CS constraints
- `mime_wrap.wasm` (~660 KB) — circom witness generator
- `mime_wrap_final.zkey` (~51 MB) — Groth16 trusted setup ceremony output

These are intentionally **not committed** to git: the zkey + r1cs are
build output of the `zkpki-circuits/` circom project, the wasm is the
witness-generation companion. Together they're ~72 MB of binary data
that doesn't belong in source control.

To run the verifier-lab tests that exercise proof generation
(`zkpki-verifier-lab` integration tests, `zkpki-pallet-lab` proof-
verification tests), drop the three artifacts into this directory.
On the foundation build host they live at
`~/Polkadot/zkpki-circuits/build/{mime_wrap.r1cs,mime_wrap_final.zkey,mime_wrap_js/mime_wrap.wasm}`
(per the working-primitives layout).

The verify-side path (`verify_proof` and the FRAME pallet's
`verify_and_record` extrinsic) does **not** require these files —
it only takes the proof + public inputs + prepared verifying key as
arguments. The fixtures are dev-side proof minting only.
