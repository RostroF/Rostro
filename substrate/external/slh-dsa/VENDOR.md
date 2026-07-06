# Vendored slh-dsa

## Source

- Upstream: <https://github.com/RustCrypto/signatures/tree/master/slh-dsa>
- Pinned version: `0.1.0` (crates.io tarball, verbatim; sha256
  `069c0368c5352eeea0134fa9bfd45feb28c5c5412719b2db81c12c784adb1aef`)
- Pinned date: 2026-07-05
- License: Apache-2.0 OR MIT (both LICENSE files preserved)

## What it is

Pure-Rust SLH-DSA (FIPS 205 final, formerly SPHINCS+), no_std-capable,
stateless hash-based signatures. Released 2024-08-18, five days after FIPS
205 finalized; the 0.1.0 changelog records the draft→final migration.
Rostro uses exactly one parameter set: **SLH-DSA-SHA2-128s** (small-
signature variant, 32-byte public key, 7856-byte signature), as the
post-quantum component of the ed25519 + SLH-DSA hybrid finality-vote
signature (docs/CONSENSUS-KEY-LIFECYCLE.md workstream 2, pq-finality-v0;
companion crate `substrate/utils/rostro-hybrid-sig`).

The `s` (small) variant is chosen over `f` for validator SCALE: a
justification carries one signature per validator and EVERY node verifies
ALL of them, so signature size and verify speed dominate while
per-validator signing (once per slot) is slack. Measured (see
rostro-hybrid-sig `tests/param_bench.rs`): `s` is ~2.2x smaller (7856 vs
17088 B) and verifies ~2.7x faster than `f`, paid for by slower signing
(~170 ms vs ~8 ms, trivially inside a 6 s slot). At ~700 validators this
is a ~5.4 MB justification vs ~11.8 MB for `f`.

Why 0.1.0 and not 0.2.0-rc.x: 0.1.0 is the stable release with two years of
soak, and it sits on the sha2 0.10 / rand_core 0.6 dependency generation the
rest of the workspace already uses. The 0.2.0 RC line is an all-RC stack
(digest 0.11, signature 3.0-rc, rand_core 0.10). Re-evaluate when 0.2.0 is
stable, on the Dependabot-as-intel policy, not as a queue item.

Signing mode note: `try_sign_with_context(msg, ctx, opt_rand)` with
`opt_rand = None` is the FIPS 205 deterministic variant; passing a
randomizer is the hedged variant. The FIPS 205 `ctx` context string is the
domain-separation channel and rostro-hybrid-sig always sets it.

## Why vendored

Sovereign-chain principle: a consensus-critical cryptographic primitive we
ship is ours to audit, freeze, and patch — a CVE in it is our issue, not
upstream's. This one will eventually sit under finality votes, the single
most durable signature artifact the chain produces. Snapshot with a stable
audit boundary; we do not track upstream automatically.

Registry-resolved dependencies (`hybrid-array 0.2.0-rc.8`,
`signature 2.3.0-pre.4`, `sha2`, `sha3`, `hmac`, `digest`, `typenum`,
`zerocopy`, `rand_core`) remain on crates.io, version-locked via the
workspace `Cargo.lock`. The two pre-release pins are what upstream 0.1.0
shipped with; they are frozen by the lock like everything else.

## Local modifications

`tests/` is byte-identical to the crates.io tarball. Two surgical changes
(all marked in-file with "Rostro vendor change"):

1. `signature` version requirement `"2.3.0-pre.4"` → `">=2.0, <3"`.
   Upstream shipped 0.1.0 pinned to a pre-release of the `signature`
   trait crate. Cargo cannot unify a pre-release caret requirement with
   the stable `signature 2.x` that everything else in the workspace
   resolves (`ed25519` → `signature ^2`), so the crate was unbuildable
   alongside ed25519-dalek/-zebra in any workspace. The traits used
   (`Signer`, `RandomizedSigner`, `KeypairRef`, `SignatureEncoding`,
   `Error`) are all present and identical in stable 2.x; behavior is
   pinned by the ACVP + SPHINCS+ reference KATs, which must pass
   unchanged against the relaxed resolution.
2. `no_std` gate inverted upstream: `src/lib.rs` had
   `#![cfg_attr(not(feature = "alloc"), no_std)]`, i.e. enabling `alloc`
   linked `std` — fatal for the RISC-V runtime build, which needs
   alloc-without-std. Changed to unconditional `#![no_std]` with
   `extern crate alloc` (alloc-gated) + `extern crate std` (test-gated),
   and added `use alloc::{vec, vec::Vec}` imports (alloc-gated, marked)
   to the seven files whose alloc-gated items reference `Vec`/`vec!`:
   `signature_encoding.rs`, `wots.rs`, `xmss.rs`, `hypertree.rs`,
   `fors.rs`, `signing_key.rs`, `verifying_key.rs`. No logic touched;
   behavior re-pinned by the full KAT surface after the change.

Stripped (registry packaging artifacts only, not source):
`.cargo_vcs_info.json`, `Cargo.toml.orig`.

## Known-answer tests

Unlike ml-kem, this tarball INCLUDES its test vectors:

- `tests/known_answer_tests.rs` — SPHINCS+ reference-implementation KATs
  for ALL twelve parameter sets, including our SLH-DSA-SHA2-128s
  (`test_kat_sha2_128s`). Slow by nature (hash-based signing); run in
  release.
- `tests/acvp_*.rs` — NIST ACVP demo-sample vectors. Coverage is a
  parameter-set SAMPLE chosen upstream: keyGen DOES include SHA2-128s,
  but sigGen/sigVer do NOT (they cover 192s/256f/SHAKE sets).

Because the in-crate ACVP sample skips SHA2-128s for sigGen/sigVer, the
official NIST ACVP vectors for exactly that parameter set are pinned in
`substrate/utils/rostro-hybrid-sig` (same division of labor as
rostro-hybrid-kex carrying the ML-KEM-768 ACVP vectors). Source and filter
procedure are recorded in that crate.

## Re-vendor procedure

1. Download the target tarball: `https://static.crates.io/crates/slh-dsa/slh-dsa-<ver>.crate`
2. Extract over this directory; strip the registry artifacts listed above.
3. Re-apply local modifications recorded in this file (currently none).
4. Run both KAT suites in release:
   `cargo test --release -p slh-dsa --test known_answer_tests --test acvp_keygen --test acvp_sig --test acvp_ver`
   and `cargo test --release -p rostro-hybrid-sig` — the NIST vectors must
   pass unchanged. A KAT failure on re-vendor means upstream changed
   behavior; stop and investigate, do not update the vectors.

Toolchain quirk (why the `--test` flags): a bare `cargo test -p slh-dsa`
also builds the lib's own `cfg(test)` harness, which trips the crate's
`#![deny(missing_docs)]` on an undocumented internal test macro
(`src/util.rs` `gen_test`) — newer rustc extended the missing_docs lint to
macros after upstream's release. Running the integration test targets
builds the lib without `cfg(test)` and keeps `src/` byte-identical instead
of patching vendored source for a test-only lint.
