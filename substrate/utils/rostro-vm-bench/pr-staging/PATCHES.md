# Patches to existing JAR/Grey files

Three small surgical changes to existing files. Plus copying the four
crate dirs from `pr-staging/services/benches/`.

## 1. `Cargo.toml` (workspace)

Add four entries under `[workspace] members`. Adjacent to the existing
`grey/services/benches/*` entries:

```diff
 members = [
     "grey/crates/grey",
     ...
     "grey/services/benches/blake2b",
     "grey/services/benches/ecrecover",
     "grey/services/benches/ed25519",
+    "grey/services/benches/goldilocks-mul",
+    "grey/services/benches/goldilocks-poseidon2",
     "grey/services/benches/keccak",
+    "grey/services/benches/mini-verifier",
+    "grey/services/benches/poseidon2-perm",
     "grey/services/benches/prime-sieve",
     ...
 ]
```

## 2. `grey/crates/grey-bench/build.rs`

Add three guest-build pairs (the shared `goldilocks-poseidon2` lib is
NOT a guest-build target — it compiles transitively when the services
are built):

```diff
 fn main() {
     let javm_ecrecover = build_javm::build("../../services/benches/ecrecover", "bench-ecrecover");
     let pvm_ecrecover = build_pvm::build("../../services/benches/ecrecover");
     ...
     let javm_keccak = build_javm::build("../../services/benches/keccak", "bench-keccak");
     let pvm_keccak = build_pvm::build("../../services/benches/keccak");
+    let javm_mini_verifier =
+        build_javm::build("../../services/benches/mini-verifier", "bench-mini-verifier");
+    let pvm_mini_verifier = build_pvm::build("../../services/benches/mini-verifier");
+    let javm_goldilocks_mul =
+        build_javm::build("../../services/benches/goldilocks-mul", "bench-goldilocks-mul");
+    let pvm_goldilocks_mul = build_pvm::build("../../services/benches/goldilocks-mul");
+    let javm_poseidon2_perm =
+        build_javm::build("../../services/benches/poseidon2-perm", "bench-poseidon2-perm");
+    let pvm_poseidon2_perm = build_pvm::build("../../services/benches/poseidon2-perm");
     let service_blob =
         build_javm::build_service("../../services/samples/sample-service", "sample-service");

     let out_dir = std::env::var("OUT_DIR").unwrap();
     std::fs::write(
         format!("{out_dir}/guest_blobs.rs"),
         format!(
             "const GREY_ECRECOVER_BLOB: &[u8] = include_bytes!(\"{}\");\n\
              ...
              const GREY_KECCAK_BLOB: &[u8] = include_bytes!(\"{}\");\n\
              const POLKAVM_KECCAK_BLOB: &[u8] = include_bytes!(\"{}\");\n\
+             const GREY_MINI_VERIFIER_BLOB: &[u8] = include_bytes!(\"{}\");\n\
+             const POLKAVM_MINI_VERIFIER_BLOB: &[u8] = include_bytes!(\"{}\");\n\
+             const GREY_GOLDILOCKS_MUL_BLOB: &[u8] = include_bytes!(\"{}\");\n\
+             const POLKAVM_GOLDILOCKS_MUL_BLOB: &[u8] = include_bytes!(\"{}\");\n\
+             const GREY_POSEIDON2_PERM_BLOB: &[u8] = include_bytes!(\"{}\");\n\
+             const POLKAVM_POSEIDON2_PERM_BLOB: &[u8] = include_bytes!(\"{}\");\n\
              const SAMPLE_SERVICE_BLOB: &[u8] = include_bytes!(\"{}\");\n",
             javm_ecrecover.display(),
             ...
             javm_keccak.display(),
             pvm_keccak.display(),
+            javm_mini_verifier.display(),
+            pvm_mini_verifier.display(),
+            javm_goldilocks_mul.display(),
+            pvm_goldilocks_mul.display(),
+            javm_poseidon2_perm.display(),
+            pvm_poseidon2_perm.display(),
             service_blob.display(),
         ),
     )
     .unwrap();
 }
```

## 3. `grey/crates/grey-bench/src/lib.rs`

Add accessor functions for the new blobs (following the existing
`grey_keccak_blob` / `polkavm_keccak_blob` pattern):

```rust
pub fn grey_mini_verifier_blob() -> &'static [u8] {
    GREY_MINI_VERIFIER_BLOB
}
pub fn polkavm_mini_verifier_blob() -> &'static [u8] {
    POLKAVM_MINI_VERIFIER_BLOB
}
pub fn grey_goldilocks_mul_blob() -> &'static [u8] {
    GREY_GOLDILOCKS_MUL_BLOB
}
pub fn polkavm_goldilocks_mul_blob() -> &'static [u8] {
    POLKAVM_GOLDILOCKS_MUL_BLOB
}
pub fn grey_poseidon2_perm_blob() -> &'static [u8] {
    GREY_POSEIDON2_PERM_BLOB
}
pub fn polkavm_poseidon2_perm_blob() -> &'static [u8] {
    POLKAVM_POSEIDON2_PERM_BLOB
}
```

## 4. `grey/crates/grey-bench/benches/pvm_bench.rs`

Add three bench functions and register them in the `criterion_group!` list:

```rust
fn bench_mini_verifier(c: &mut Criterion) {
    bench_standard(c, "mini_verifier", grey_mini_verifier_blob(), polkavm_mini_verifier_blob());
}
fn bench_goldilocks_mul(c: &mut Criterion) {
    bench_standard(c, "goldilocks_mul", grey_goldilocks_mul_blob(), polkavm_goldilocks_mul_blob());
}
fn bench_poseidon2_perm(c: &mut Criterion) {
    bench_standard(c, "poseidon2_perm", grey_poseidon2_perm_blob(), polkavm_poseidon2_perm_blob());
}
```

```diff
 criterion_group!(
     benches,
     bench_fib,
     bench_hostcall,
     bench_sort,
     bench_sieve,
     bench_blake2b,
     bench_keccak,
     bench_ed25519,
-    bench_ecrecover
+    bench_ecrecover,
+    bench_mini_verifier,
+    bench_goldilocks_mul,
+    bench_poseidon2_perm
 );
```

That's all four files of changes to existing JAR/Grey code.
