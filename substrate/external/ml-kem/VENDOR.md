# Vendored ml-kem

## Source

- Upstream: <https://github.com/RustCrypto/KEMs/tree/master/ml-kem>
- Pinned version: `0.3.2` (crates.io tarball, verbatim)
- Pinned date: 2026-07-03
- License: Apache-2.0 OR MIT (both LICENSE files preserved)

## What it is

Pure-Rust ML-KEM (FIPS 203 final, formerly Kyber), no_std-capable, no
unsafe (`unsafe_code = "deny"` in its own lints). Rostro uses exactly one
parameter set: **ML-KEM-768**, as the post-quantum component of the
X25519 + ML-KEM-768 hybrid key agreement for transport handshakes (see
`docs/PQ-TRANSPORT.md` and `substrate/utils/rostro-hybrid-kex`).

## Why vendored

Sovereign-chain principle: a consensus-adjacent cryptographic primitive we
ship is ours to audit, freeze, and patch — a CVE in it is our issue, not
upstream's. The vendor is a deliberate snapshot with a stable audit
boundary; we do not track upstream releases automatically. Dependabot-style
signals about newer ml-kem releases are intel to evaluate, not a queue.

Registry-resolved dependencies of this crate (`module-lattice`,
`hybrid-array`, `kem`, `sha3`, `rand_core`) remain on crates.io,
version-locked via the workspace `Cargo.lock`. `module-lattice` is shared
foundation with RustCrypto's `ml-dsa`, which is the planned Phase-2
signature vendor — same audit surface serves both.

## Local modifications

`src/` is untouched. Two surgical changes to `tests/wycheproof.rs` only
(both marked in-file with "Rostro vendor change"):

1. Vector path: upstream loads Wycheproof vectors from a repo-root git
   submodule (`../thirdparty/wycheproof/`), which neither the crates.io
   tarball nor this vendor has. The path now points at the locally
   vendored `tests/wycheproof-vectors/`.
2. Parameter-set scope: only the ML-KEM-768 vector files are vendored
   (~2.7 MB; all four suites — full, keygen-seed, semi-expanded-decaps,
   encaps). Rostro ships exactly one parameter set, so the ML-KEM-512 and
   ML-KEM-1024 test invocations were removed rather than carrying 5.3 MB
   of vectors for code we never instantiate. The test macros themselves
   are untouched; restoring 512/1024 is a vector download plus reverting
   the invocation block.

Vector source: <https://github.com/C2SP/wycheproof> `main`,
`testvectors_v1/mlkem_768_*.json`, fetched 2026-07-03.

Stripped (registry packaging artifacts only, not source):
`.cargo_vcs_info.json`, `Cargo.toml.orig`, `Cargo.lock`.

## Known-answer tests

The crates.io tarball **excludes** upstream's NIST ACVP KAT files
(`tests/key-gen.*`, `tests/encap-decap.*` are in the manifest exclude
list). KAT coverage for the vendored code therefore lives in
`substrate/utils/rostro-hybrid-kex` (NIST ACVP ML-KEM-768 vectors for
keygen, encapsulation, and implicit-rejection decapsulation, pinned in CI).
The upstream `tests/wycheproof.rs` suite is retained and runs in-crate.

## Re-vendor procedure

1. Download the target tarball: `https://static.crates.io/crates/ml-kem/ml-kem-<ver>.crate`
2. Extract over this directory; strip the registry artifacts listed above.
3. Re-apply any local modifications recorded in this file (currently none).
4. Run the KAT suite: `cargo test -p rostro-hybrid-kex` — the NIST vectors
   must pass unchanged. A KAT failure on re-vendor means upstream changed
   behavior; stop and investigate, do not update the vectors.
