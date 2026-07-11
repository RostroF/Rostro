# RVM Verify Intrinsics: Origin, the Era-Boundary Livelock, Benchmarks, Work Done, Roadmap

Status: living document. Written 2026-07-10 on branch `p256-bench-v0`
(commits `11c159e1b7`, `b10ae65bba`, `ef091ec3c7`; W1 landed same day as a
fourth commit). Not merged, not pushed.

## 1. Origin

Camino is everyone's first exposure to Rostro, and P-256 is the signing key
of the hardware-attestation world: TPM2, StrongBox, and the zkpki/PoP stack
all speak it. The open decision was how the future
`RostroSignature::EcdsaP256` variant verifies: in-runtime (pure `set_code`,
zero new consensus surface) or at native speed via node-side code.

The deciding constraint is the threat model. Chain-side P-256 is verify-only:
message, signature, and public key are all consensus-public, and signing
happens inside device silicon. Nothing secret ever enters the computation,
which frees the implementation from constant-time discipline and, more
importantly, means the only question is cost.

The first benchmark answered it. RustCrypto p256 verify, RVM interpreter,
executor-mirrored configuration:

| workload | time |
|---|---|
| native verify_prehash | ~236 µs |
| RVM interpreted EC verify (floor) | ~13.8 ms (58x) |
| RVM in-guest SHA-256 (297 B) | 64 µs |
| RVM call overhead (noop) | 0.11 µs |

Two conclusions fell out. First, the digest path is irrelevant (sp_io host
hash vs in-guest soft hash differ by noise); the EC scalar math is the whole
cost. Second, 58x is the honest price of interpreting bignum arithmetic on an
already heavily tuned interpreter. The dispatch-loop work from 2026-05 (H1,
monomorphization, the Tier-2 arc) was all present in these numbers. There is
no dispatch trick left that recovers two orders of magnitude; only native
execution does.

The session was then scoped to RVM only: make the VM right, with no coupling
to testnet or worktree timelines.

## 2. The mechanism: intrinsics are opt-in

RostroVM has a reserved ecalli range (`100..1023`). When a guest executes
`ecalli N` with N in that range, the interpreter's `FAST_OP_ECALLI` arm
dispatches inline to a native body in the node binary: no run-loop exit, one
dispatch plus the native work, operands borrowed zero-copy from guest memory.

The critical property, stated bluntly because it was the source of a real
misunderstanding: **an intrinsic fires only where the guest binary contains
the ecalli instruction.** Guest code opts in at compile time via
`polkavm_import(index = N)`. A node full of intrinsics changes nothing about
a runtime blob that never emits them; every instruction of ordinary compiled
code still executes in the interpreter at interpreter speed. The bench
fixtures hit native numbers because their guest code literally calls the
intrinsics. Capability is not deployment.

This mechanism predates this branch (goldilocks, Dilithium, P-521, blake2b,
keccak, ed25519, secp256k1-recover, poseidon2 landed in the 2026-05 arc,
with the security audit and KAT regime in
`docs/SECURITY-AUDIT-TIER2-INTRINSICS.md`). What this branch adds is new
entries, and the two pieces of linker infrastructure that make intrinsics
reachable from real substrate runtimes at all (section 5).

## 3. The era-boundary livelock

An NPoS proof-of-concept (separate thread) merged this RVM and froze at an
era boundary. The diagnosis, confirmed against this branch's benchmarks:

- `pallet-sassafras::update_ring_verifier` calls
  `ring_ctx.verifier_key(&pks)` (frame/sassafras/src/lib.rs:551 → 561, via
  sp_core::bandersnatch → ark-vrf).
- That is plain arkworks compiled to RISC-V. No ecalli anywhere. Every
  instruction interprets.
- Building the ring verifier key is MSM-shaped work over BLS12-381 G1, the
  same family as the pairing rows below (measured 57-80x interpreted).
- ~65 ms native x ~75x ≈ 4.8 s, against a 4 s era-boundary deadline. The
  chain freezes.

"Does having an intrinsics-capable RVM in the node, by itself, fix the era
boundary?" **No.** The intrinsics (114-116) are the necessary native halves;
the runtime-side marshalling that emits the ecalli calls is unwritten. That
work is section 6.

## 4. Benchmarks

Environment: WSL2 dev box, same-session A/B (WSL2 drifts 5-15% across days;
treat these as directional and re-baseline before comparing new work).
Harnesses mirror `RostroCodeExecutor` exactly: interpreter backend, sp_io
host functions registered, input at heap_base, status in A0. Gas metering
off, matching the current no-gas-surcharge policy for intrinsics.
Reproduce with:

```
cargo run --release -p rostro-p256-rvm-bench --bin p256-rvm-bench
cargo run --release -p rostro-cipher-rvm-bench --bin cipher-rvm-bench
```

Full verify-class matrix (native / RVM interpreted / RVM intrinsic):

| cipher | native | interpreted | intrinsic | interp x | intrinsic x |
|---|---|---|---|---|---|
| ed25519 (zebra, ZIP-215) | 31 µs | 2.44 ms | 35 µs | 78x | 1.1x |
| sr25519 (schnorrkel) | 33 µs | 2.45 ms | none | 74x | n/a |
| secp256k1 recover (k256) | 159 µs | 22.3 ms | 161 µs | 140x | 1.0x |
| P-256 (ID 112) | 236 µs | 13.8 ms | 245 µs | 58x | 1.0x |
| P-521 (ID 111) | 1.16 ms | 94.7 ms | 1.16 ms | 82x | 1.0x |
| ML-DSA-65 (ID 110) | 138 µs | 7.6 ms | 139 µs | 55x | 1.0x |
| SLH-DSA-SHA2-128s (ID 113) | 184 µs | 83.0 ms | 183 µs | 450x | 0.99x |
| BLS12-381 single pairing | 1.02 ms | 61-73 ms | n/a | 57-71x | n/a |
| BLS12-381 pairing_check(2) (ID 114) | 1.43 ms | 114.7 ms | 1.37 ms | 80x | 0.96x |

Reading notes:

- **Every intrinsic is at native speed** (0.96-1.1x). The mechanism
  generalizes across curve arithmetic, lattice, hash-based, and pairing
  workloads without cipher-shaped surprises.
- **SLH-DSA's 450x is an outlier for a reason**: its verification is
  thousands of SHA-256 compressions, and hash-dominated code pays the
  interpreter tax twice, since native gets SHA-NI hardware while the guest
  runs soft SHA. It is the finality-vote scheme, so its intrinsic is
  mandatory if hybrid-signature verification ever moves in-runtime.
- **The pairing rows are the ring-VRF/Groth16 cost model.** One pairing at
  ~61-73 ms interpreted puts any proof verification or ring construction
  firmly in intrinsic-only territory. The livelock arithmetic in section 3
  is this row applied to MSM work.
- **Caveat on the classical rows**: substrate runtimes normally verify
  ed25519/sr25519/ecdsa through sp_io host functions (`ext_crypto_*`),
  which are already native. Those interpreted numbers apply only to
  in-guest verification outside sp_io. The intrinsics' unique value is the
  ciphers sp_io never covered: P-256, P-521, ML-DSA, SLH-DSA, and the
  BLS12-381 primitives.
- The interpreted ecrecover (22.3 ms) independently reproduces the 2026-05
  vm-research measurement (22.1 ms), anchoring the two harness generations
  to each other.

## 5. Work done on this branch

Three commits, each a closed loop.

### `11c159e1b7`: intrinsics + linker enablers

New intrinsics (all Tier-2 pattern: zero-copy `borrow_bytes`, shared
pure-bytes native body, KAT):

| ID | intrinsic | ABI (registers) |
|---|---|---|
| 112 | P-256 ECDSA verify (prehash) | A0=vk (33B compressed SEC1), A1=sig (64B r‖s), A2=prehash ptr, A3=len → A0=1/0 |
| 113 | SLH-DSA-SHA2-128s verify | A0=pk (32B), A1=msg ptr, A2=msg len, A3=sig (7856B), A4=ctx ptr, A5=ctx len → A0=1/0 |
| 114 | BLS12-381 pairing check | A0=pairs (n x 288B: G1‖G2 uncompressed), A1=n ≤ 8 → A0=1 iff product is GT identity |
| 115 | BLS12-381 G1 MSM | A0=points (n x 96B), A1=scalars (n x 32B Fr), A2=n ≤ 2048, A3=out (96B) → A0=1/0 |
| 116 | BLS12-381 G2 MSM | as 115 with 192B points/out |

Design decisions that matter:

- **Primitives, not monoliths, for BLS.** pairing-check + MSM compose into
  Groth16 verification, BLS signature verification, and KZG opening checks
  (the ring-VRF building block) without baking any proof system into the
  node binary. Proof-system evolution stays a `set_code` matter.
- **SLH-DSA path-deps the same vendored `slh-dsa` crate** the node's hybrid
  finality verifier (rostro-hybrid-sig) trusts, so intrinsic and verifier
  cannot diverge.
- **No gas surcharge on new arms** (standing directive: gas policy lands
  with the VM-optimization pass). Operand caps bound worst-case native work
  until then.
- **Checked deserialization on 114-116** (on-curve + subgroup), reflecting
  consensus-adversarial inputs. NOTE: section 6 revises 115/116 to
  unchecked to match the CurveHooks contract and its cost model; 114 stays
  checked.

Linker enablers, both load-bearing:

- **Mixed pinned/symbolic import indexing.** Upstream refused blobs mixing
  pinned-index imports (intrinsics) with symbolic ones (sp_io host
  functions), which made it impossible for any substrate-built runtime to
  call any intrinsic. The vm-research bench services never noticed because
  they do not import sp_io. Now symbolic imports auto-assign the lowest
  free indices below the reserved base (100), deterministically by symbol;
  reaching the base is a hard error, because an auto-assigned import inside
  the reserved range would be silently swallowed by intrinsic dispatch.
- **Default guest stack 8 KiB → 1 MiB.** The 8 KiB default was
  smart-contract heritage. Chain-runtime guests doing real cryptography
  overflow it (k256 recovery lincomb traps; ML-DSA needs ~256 KiB), and a
  stack-overflow trap in consensus code is a liveness bug that surfaces
  only on the deepest-recursing input. Link-time only: existing blobs are
  unaffected; `polkavm_derive::min_stack_size!` still raises per-blob.

KATs went 15 → 18: RFC 6979 §A.2.5 for P-256 (plus tamper negatives),
SLH-DSA self-consistency anchor (deterministic FIPS 205 seeds and
deterministic sign; ACVP vector extraction tracked like Dilithium's), and
mathematically pinned BLS anchors (bilinearity with corrupt-point
fail-closed; 2G+3G=5G MSM in both groups).

### `b10ae65bba`: benchmark fixtures + harnesses

Bench-only crates under `substrate/utils/rostro-executor/tests/fixtures/`
(`p256-bench{,-harness}`, `cipher-bench{,-harness}`), never shipped. The
cipher fixture deliberately declares no stack size: its deep verifiers
running on the new 1 MiB default is the end-to-end proof of that default.

Guest-build gotchas documented in code, paid for once:

- Unused deps do not link: a fixture that never calls sp_io needs
  `extern crate sp_io;` or the blob has no panic handler and no allocator.
- Intrinsic imports need stub host functions registered at instantiation
  (import resolution is strict); the interpreter intercepts the ecalli
  inline, so the stubs never execute.
- polkavm-derive rejects doc comments on `extern` import blocks.

### `ef091ec3c7`: test infrastructure + supply-chain coherence

Chasing two "pre-existing test failures" surfaced two vendoring defects,
both artifacts of crates.io tarball normalization:

- **The linker's test suite had never compiled in the vendored tree**:
  upstream's versionless path dev-deps are stripped at publish. Restored;
  71/71 pass, running against the modified import-indexing and
  stack-default code.
- **The dependency graph was not closed over the vendored sources.** The
  vendored crates inter-reference by crates.io version spec, so those edges
  resolved to pristine registry copies: both lockfiles carried a registry
  `polkavm-assembler` and a second registry `polkavm-common`. The shipped
  node was linking VM bytes not present in this tree (violating VENDOR.md's
  audit premise), and polkavm's integration tests exercised the pristine
  linker rather than ours. `[patch.crates-io]` tables in both workspace
  roots now force every polkavm-family edge to vendored paths; the parent
  lockfile has zero registry polkavm-family entries. Also learned: upstream
  yanked polkavm 0.32.0 from crates.io, so fresh resolution of those edges
  was going to break eventually regardless.

Validated under the closed graph: linker 71/71, KATs 18/18, full cipher
matrix green, and a complete `SUBSTRATE_ENABLE_POLKAVM=1
SUBSTRATE_RUNTIME_TARGET=riscv` release build of gemini-node.

Remaining environment-gated tests (dynamic paging needs userfaultfd; zygote
sandbox and JIT-backend tests never enumerate on WSL2) are covered by the
bare-metal runbook: `rostro-testnet-lab/notes/rvm-baremetal-test-runbook-20260710.md`,
with a transfer bundle at `rostro-testnet-lab/binaries/p256-bench-v0.bundle`.

### W1 commit: CurveHooks-surface completion

Eight new intrinsics complete native coverage of both ext-crate hooks
surfaces (ark-bls12-381-ext, 6 methods; ark-ed-on-bls12-381-bandersnatch-ext,
4 methods), so W2's `RostroCurveHooks` never falls back to interpreted
arkworks:

| ID | intrinsic | ABI (registers) |
|---|---|---|
| 117 | BLS12-381 multi Miller loop | A0=pairs (n x 288B G1‖G2), A1=n ≤ 8, A2=out (576B Fq12) → A0=1/0 |
| 118 | BLS12-381 final exponentiation | A0=in (576B Fq12), A1=out (576B) → A0=1/0 (0 incl. the non-invertible zero input) |
| 119 | Bandersnatch TE MSM | A0=points (n x 64B), A1=scalars (n x 32B Fr), A2=n ≤ 8192, A3=out (64B) |
| 124 | Bandersnatch TE mul_projective | A0=base (64B), A1=limbs (LE u64), A2=n_limbs ≤ 8, A3=out (64B) |
| 125 | Bandersnatch SW MSM | as 119 with 65B points |
| 126 | Bandersnatch SW mul_projective | as 124 with 65B points |
| 127 | BLS12-381 G1 mul_projective | as 124 with 96B points; n_limbs ≤ 4 (GLV guard, below) |
| 128 | BLS12-381 G2 mul_projective | as 124 with 192B points |

Plus the planned revisions: 115/116 flipped to unchecked deserialization
(and `msm_unchecked`, matching the hooks defaults), `MAX_BLS_MSM` 2048 →
8192 with hook-side chunking beyond (MSM is additive; chunked results are
bit-identical). 114 stays checked — it is the standalone adversarial
verifier, not a hooks backing.

The open `mul_projective` question is settled: dedicated intrinsics, not
MSM-of-1. MSM scalars are canonical mod-r Fr; `mul_projective` takes raw
integer limbs and is used on cofactor-uncleared points, where `k` and
`k mod r` act differently. The KAT pins this with a 5-limb (2^256 + 7)
scalar against ark's own `mul_bigint`.

Two ABI-shaping findings, both caught by KATs:

- **Bandersnatch SW points are 65 bytes, not 64.** The 2-bit SW
  serialization flags do not fit the single spare bit of the 255-bit base
  field, so arkworks appends a flag byte (TE flags are 1 bit and fit; TE
  stays 64B).
- **ark's G1 `mul_projective` is a node-killing panic surface.**
  ark-bls12-381 0.5 GLV-overrides G1 (only G1: G2 and both bandersnatch
  forms use the default double-and-add), converting limbs to Fr via
  `from_sign_and_limbs`, which `assert!`s limbs.len() ≤ 4 and reduces
  mod r. The intrinsic mirrors plain arkworks bit-for-bit where it is
  defined (≤ 4 limbs — byte equality is the consensus gate) and fails
  closed at 5+ instead of inheriting the panic.

KATs 18 → 25: split-path Miller+final-exp equals ark's one-shot `pairing()`
byte-for-byte AND final-exponentiates the bilinearity pair set to the GT
identity; bandersnatch 2G+3G=5G in both forms; every `mul_projective` arm
against `mul_bigint` on identical limbs; the G1 GLV guard; off-curve input
under unchecked deserialization is deterministic and panic-free; bad limb
counts fail closed. Linker suite still 71/71; full cipher matrix and the
riscv gemini-node release build re-validated under the closed graph.

## 6. Next steps: settle runtime crypto for ALL ciphers (Backend B, generalized)

Two decisions shape this section. First: no host-function shim (Backend A)
as an interim; the seam is built once, backed by intrinsics directly, so
nothing is written twice. Second: the scope is not "fix the bandersnatch
ring build." It is **settle how runtime code reaches every cipher on
Rostro**, so that no future workstream re-litigates this per cipher and no
future pallet accidentally ships an interpreted verify.

### The settlement mechanism: one facade crate

`rostro-guest-crypto` (name working): the single crate through which
runtime code touches cryptography. Per cipher it dispatches to the best
correct backend per target:

| cipher / op | runtime backend | native/test backend |
|---|---|---|
| ed25519, sr25519, ecdsa-k1 verify/recover | sp_io host functions (`ext_crypto_*`, already native, established ABI) | same |
| common hashes (blake2b, keccak, sha2, twox) | sp_io host functions | same |
| P-256 verify | ecalli 112 | p256 crate |
| P-521 verify | ecalli 111 | p521 crate |
| ML-DSA-65 verify | ecalli 110 | fips204 crate |
| SLH-DSA-128s verify | ecalli 113 | vendored slh-dsa crate |
| secp256k1 recover (outside sp_io contexts) | ecalli 123 | k256 crate |
| BLS12-381 pairing check / MSM / miller / final-exp | ecalli 114-118 | ark-bls12-381 |
| bandersnatch (ed-on-bls12-381) TE/SW MSM + mul | new ecalli IDs (from 119, 124+) | ark-ed-on-bls12-381-bandersnatch |
| goldilocks / poseidon2 (STARK path) | ecalli 100-103, 130 | gp / plonky3 |

The arkworks story rides the same crate: `RostroCurveHooks` implements BOTH
`ark_bls12_381_ext::CurveHooks` AND
`ark_ed_on_bls12_381_bandersnatch_ext::CurveHooks`, marshalling into the
facade's ecalli paths. That covers the ring build (BLS MSM), ring VRF
per-ticket verification (inner-curve ops + pairing), and any future
Groth16/KZG verifier, with one hooks type.

Policy, to be enforced by convention and review (and a CI grep once the
facade exists): **runtime code does not depend on raw crypto crates for
verify paths; it goes through the facade.** That is what "settled" means —
the next cipher decision is a facade entry plus an intrinsic, not an
architecture discussion.

Single-source-of-truth requirement: the facade's native fallbacks must be
bit-equal to the intrinsic bodies. Where practical they call the same
vendored crates the node's intrinsic bodies use (slh-dsa already
demonstrates the pattern); differential tests pin the rest.

### Work plan

- **W1, RVM intrinsic completion — DONE 2026-07-10 (see section 5).** Add `multi_miller_loop =
  117` and `final_exponentiation = 118` (the hooks API needs the pairing
  split; pairing_check stays for standalone adversarial verification). Add
  the bandersnatch inner-curve set per the ed-on-bls12-381-bandersnatch-ext
  hooks surface (TE MSM, SW MSM, projective muls; IDs from the free slots
  119, 124+). Flip 115/116 to unchecked deserialization: the hooks contract
  is caller-validated points (its own defaults call `msm_unchecked`),
  garbage in is deterministic garbage out with no panic, exactly as if the
  guest ran arkworks itself, and subgroup-checking 2048 points would cost
  on the order of the MSM and eat the win. Raise `MAX_BLS_MSM` to 8192,
  chunk beyond in the hooks (MSM is additive; chunked results are
  bit-identical). KATs for every new arm (miller+final-exp composes to
  `pairing()`; inner-curve MSM known answers). Decide whether
  `mul_projective` (raw `&[u64]` limbs) routes through MSM-of-1 or needs
  its own intrinsic.
- **W2, the facade — DONE 2026-07-10 (see below).** `rostro-guest-crypto` with the full
  cipher table above: `cfg(target_env = "polkavm")` marshals to ecalli
  (canonical uncompressed wire format), sp_io-backed ops delegate to sp_io
  on both targets, everything else falls back to the reference crates
  natively. `RostroCurveHooks` for both ext curves. Differential test
  battery: facade-native equals facade-guest equals raw-crate, per cipher.
- **W3, vendor ark-vrf + curve switch — DONE 2026-07-10 (see below).** Vendor `ark-vrf
  0.1.1` (w3f-ring-proof only if it binds the engine anywhere; it receives
  `S::Pairing`, so it should not). Functional diff: the one associated-type
  line becomes `ark_bls12_381_ext::Bls12_381<RostroCurveHooks>`, the suite
  curve becomes the hooked bandersnatch, plus generics threading.
  sp_core::bandersnatch repoints to the vendored path. The
  consensus-critical gate is a test, not an assumption: ring artifacts
  (`verifier_key(&pks)`, VRF outputs) from the hooked stack must equal
  plain ark-vrf's byte-for-byte, natively and in-guest (the ext types are
  repr-transparent, so this should hold trivially, and everything stands
  on it).
- **W4, executor stubs + proofs (~half session).** Register stub host
  functions in rostro-executor for every intrinsic import symbol (one
  generic registration for the reserved range, not per-cipher stubs). Two
  fixture proofs: (a) ring-bench building `verifier_key(&pks)` at the PoC
  ring size — success is three numbers, ~65 ms native / ~70 ms in-guest
  hooked / ~4.8 s in-guest plain, the middle one being the era boundary
  fixed; (b) facade-bench exercising every facade entry in-guest and
  asserting intrinsic-speed ratios, so cipher coverage is regression-tested
  as a set, not anecdotally.
- **W5, NPoS thread (separate ownership).** Rebuild the runtime against the
  switched sp-core, `set_code` onto an intrinsics-capable node,
  era-boundary stress on the farm.

Deployment invariants:

- **Node before runtime.** A runtime emitting ecalli 115 does not
  instantiate on a node without the intrinsics and stubs (import resolution
  fails): a hard, loud cutover, not a silent slow path. The reverse is
  safe: an old runtime on a new node just interprets.
- **Byte equality is the consensus gate.** Any divergence between the
  hooked and plain construction of ring artifacts is a consensus split;
  the W3/W4 equality tests are the non-negotiable acceptance criteria.

### W2 landing: `rostro-guest-crypto`

`substrate/utils/rostro-guest-crypto` (Apache-2.0, no_std): the facade
crate per the table above. `verify::*` covers P-256/P-521/ML-DSA-65/
SLH-DSA-128s/secp256k1-recover/BLS pairing-check plus sp_io delegations
(ed25519, sr25519, ecdsa, hashes); `hooks::RostroCurveHooks` implements
both ext-crate CurveHooks traits. On `target_env = "polkavm"` operations
marshal to the ecalli intrinsics (`src/ecalli.rs` pins the canonical
import symbols the executor stubs must match); natively the hooks
replicate the ext defaults via transmute-delegation and the verify fns
call the same reference crates the intrinsic bodies use. Over-cap inputs
chunk (MSM additive, Miller loop multiplicative over pairs); over-cap
`mul_projective` limb counts fall back to in-guest plain arkworks
(preserving ark's own semantics, including its G1 GLV panic).

Goldilocks/Poseidon2 deliberately not surfaced yet: no runtime consumer,
and their native halves live only in the VM crate — they join with their
first consumer.

Test battery, all three legs:
- facade-native == raw crate, and hooked == plain arkworks byte-equality
  (pairing, MSM G1/G2/TE/SW, mul_projective ×4):
  `rostro-guest-crypto/tests/differential.rs`, 12/12.
- facade-guest == facade-native inside the real interpreter:
  `rostro-executor/tests/fixtures/facade-test{,-harness}` — 16 guest
  cases, every facade entry executed in-guest against natively computed
  expected bytes, including a 10-pair multi-pairing that exercises the
  Miller-loop chunking path. Run:
  `cargo run --release -p rostro-facade-rvm-test`.

Harness gotcha, paid once: the harness must `sbrk(input_len)` before
writing input at `heap_base` — without it the guest allocator's arena
overlaps the input region and the first in-guest `Vec` allocation
corrupts it (exports that never allocate keep passing, which disguises
the cause).

### W3 landing: vendored ark-vrf on the hooked curves

`substrate/external/ark-vrf` (0.1.1, MIT, VENDOR.md carries the deviation
table). Three deviations, all in `suites/bandersnatch.rs` + the manifest:
the suite affine becomes the hooked ext bandersnatch, the ring pairing
becomes the hooked ext BLS12-381, and `data_to_point` runs Elligator2 on
the PLAIN config then coordinate-copies into the hooked type — the ext
config cannot implement ark-ec's `Elligator2Config` (orphan rule: a local
type argument does not make a foreign generic type local), and the map is
pure field arithmetic with nothing for hooks to accelerate. The workspace
`ark-vrf` pin repoints to the vendored path, so `sp-core` (feature
`bandersnatch-experimental`) and `rostro-kzg-srs` ride the switch with
zero code changes.

Layering: `RostroCurveHooks` moved into its own crate
`substrate/utils/rostro-curve-hooks` (ark-only deps, plus the curve-op
ecalli imports 115-119/124-128) because `sp-core → ark-vrf → hooks`
must not cycle back through sp-io. The facade re-exports it as
`rostro_guest_crypto::hooks` — the import path for runtime code is
unchanged; verify-class ecalli imports (110-114, 123) stay in the facade
so each import symbol is declared in exactly one crate.

The consensus gate, tested not assumed:
- `rostro-guest-crypto/tests/ring_equality.rs` — hooked vs plain
  (upstream registry 0.1.0 as the reference; 0.1.0 → 0.1.1 is
  docs/formatting only): public keys, hash-to-curve input points (pins
  the Elligator2 deviation), VRF outputs + hashes, IETF proofs, ring
  proof params (URS generation itself runs group ops through the hooks),
  ring verifier keys, ring commitments — all byte-equal; ring proofs
  verify across stacks in both directions.
- The vendored crate's own suite tests run on the hooked engine: 30/30
  incl. `vectors_process` for ietf/pedersen/ring — the hooked stack
  reproduces the upstream-published test vectors.

In-guest equality and the era-boundary timing proof land with W4's
fixtures (same fixture work).

## 7. Deliberately not done

- **Gas surcharges for the new intrinsics**: deferred to the
  VM-optimization pass by standing decision; operand caps bound the
  interim.
- **Fusion / threaded dispatch / CPUID handler experiments**: deprioritized.
  The dispatch loop is at I-cache saturation (an empty scaffold costs
  2.5-3%; a prior arm-addition experiment regressed 14/15 workloads), and
  the measured 55-450x gaps are closed by intrinsics, not dispatch tricks.
  The remaining structural interpreter item is the flat memory
  architecture (roadmap Phase 3, locked, still unbuilt).
- **Blob-hash recognition ("transparent substitution")**: rejected. We
  control the runtime build, so explicit opt-in via pinned imports is
  simpler, auditable, and already proven.
