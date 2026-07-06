# Vendored parity-scale-codec

## Source

- Upstream: <https://github.com/paritytech/parity-scale-codec>
- Pinned version: `3.7.5` (crates.io tarball, verbatim; sha256
  `799781ae679d79a948e13d4824a40970bfa500058d245760dd857301059810fa`)
- Pinned date: 2026-07-05
- License: Apache-2.0

## What it is

THE wire-format crate: SCALE encode/decode for every on-chain type,
network message, and storage value in the stack. Vendored via
`[patch.crates-io]` (not a plain workspace path dep) because registry
crates — `finality-grandpa` above all — also depend on it, and two codec
builds in one tree would split the `Codec` trait impls across types.
`parity-scale-codec-derive` stays on the registry, unmodified.

## Why vendored

pq-finality-v0: the hybrid (ed25519 + SLH-DSA-SHA2-128f) finality vote
made `SignedMessage`/`SignedPrevote`/`SignedPrecommit` ~17.2 KiB inline,
and upstream's chunked `Vec` decoding **const-asserts every element type
fits `INITIAL_PREALLOCATION` (16 KiB)** — a compile-time wall against any
element larger than 16 KiB, which fires only at codegen (release builds),
not `cargo check`. Sovereign-chain principle applies doubly to the wire
crate: it is ours to audit, freeze, and patch.

## Local modifications

One surgical change to `src/codec.rs` (`decode_vec_chunked`, marked
in-file with "Rostro vendor change"):

1. Removed the `const { assert!(INITIAL_PREALLOCATION >= size_of::<T>()) }`
   and replaced the chunk-length computation with an explicitly clamped
   form: ZSTs keep chunk length 1 (upstream behavior), sub-16-KiB types
   keep `INITIAL_PREALLOCATION / size` (upstream behavior), and
   oversized types now decode one element per chunk instead of failing
   to compile. The assert's purpose was to prevent a zero chunk length
   (infinite decode loop); the `.max(1)` clamp preserves that guarantee
   for every size. Memory-exhaustion resistance is unchanged: chunking
   still bounds each allocation to ≤16 KiB-per-chunk granularity and the
   `on_before_alloc_mem` input hook still fires per chunk.

Also appended an empty `[workspace]` table to `Cargo.toml` (standalone
package consumed via `[patch.crates-io]`; not a member of the enclosing
workspace) and stripped registry packaging artifacts
(`.cargo_vcs_info.json`, `Cargo.toml.orig`).

## Verification

Upstream's own test suite runs in-place (`cargo test` inside this
directory — the crate is its own workspace) and must pass unchanged,
including the large-`Vec` chunking tests around `INITIAL_PREALLOCATION`.
Known exception: the `decode_with_mem_tracking_ui` trybuild test is a
rustc-diagnostic SNAPSHOT and fails identically on the pristine tarball
under rustc 1.94 (message-format drift, verified 2026-07-05) — a UI
mismatch there is toolchain noise, not a behavior signal.
Consumer-side behavior is pinned by the pallet-grandpa hybrid
equivocation fixtures and the rostro-validator-channel wire-size pins.

## Re-vendor procedure

1. Download the target tarball:
   `https://static.crates.io/crates/parity-scale-codec/parity-scale-codec-<ver>.crate`
2. Extract over this directory; strip the registry artifacts listed above.
3. Re-apply the local modifications recorded in this file (check whether
   upstream has lifted the 16 KiB element ceiling; if so the codec.rs
   change can be dropped).
4. Run the in-place test suite + `cargo test -p pallet-grandpa
   -p rostro-validator-channel` — all must pass unchanged.
