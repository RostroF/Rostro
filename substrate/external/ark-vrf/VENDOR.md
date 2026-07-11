# Vendored: ark-vrf

- **Upstream**: `ark-vrf` 0.1.1 from crates.io (MIT, Davide Galassi),
  <https://github.com/davxy/ark-vrf>.
- **Vendored**: 2026-07-10, exact copy of the registry tarball (normalized
  manifest; `data/` test vectors and SRS included) plus the deviations
  below.
- **Why**: the bandersnatch VRF suite is the Sassafras/ring-VRF substrate.
  Vendoring pins the exact bytes we ship and carries the Rostro engine
  switch: the suite's curves become the HOOKED ext types, so every group
  operation routes through `RostroCurveHooks` — RVM ecalli intrinsics
  in-guest, plain-arkworks transmute natively. See
  `docs/RVM-VERIFY-INTRINSICS.md` §6 (W3).
- **Consumers**: `sp-core` (feature `bandersnatch-experimental`),
  `rostro-kzg-srs`. Both consume the suite types, so the switch is
  transparent to their code.

## Deviation table

| Change | Where | Justification |
|---|---|---|
| Suite affine → `rostro_curve_hooks::EdwardsAffine` (ext bandersnatch, `RostroCurveHooks`) | `src/suites/bandersnatch.rs` (`impl Suite`) | The engine switch. Field types, constants, serialization identical to plain; byte-equality pinned by the vendored vector tests + `rostro-guest-crypto/tests/ring_equality.rs`. |
| Ring pairing → `rostro_curve_hooks::Bls12_381` (ext BLS12-381, `RostroCurveHooks`) | `src/suites/bandersnatch.rs` (`impl RingSuite`) | Routes the ring-proof KZG backend (MSM, Miller loop, final exponentiation) through the hooks — the era-boundary `verifier_key` build becomes native in-guest. |
| `data_to_point` maps on the PLAIN config, coordinate-copies into the hooked type | `src/suites/bandersnatch.rs` | The ext config cannot implement ark-ec's `Elligator2Config` (orphan rule: foreign trait, foreign type — a local type argument does not make `BandersnatchConfig<RostroCurveHooks>` local). Elligator2 is pure field arithmetic with no group ops, so the hooks have nothing to accelerate; same DST, same constants, byte-identical output. |
| Manifest: optional `ark-bls12-381-ext`, `ark-ed-on-bls12-381-bandersnatch-ext`, `rostro-curve-hooks` (path) deps wired into the `bandersnatch`/`std` features | `Cargo.toml` | Dependencies for the switch. `rostro-curve-hooks` is deliberately free of sp-* deps so no cycle forms through `sp-core → ark-vrf → hooks`. |

## Sync policy

Upstream moves slowly and this copy carries a semantic deviation — do NOT
blind-sync. On upstream release: diff `src/`, port relevant fixes, re-run
the vendored vector tests (`cargo test -p ark-vrf --features
bandersnatch,ring,test-vectors`) and the byte-equality suite, and update
this table.
