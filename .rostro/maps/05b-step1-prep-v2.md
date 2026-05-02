# Step 1 Prep v2: Per-Pallet Plan for Test Files, Cargo Features, and Implicit Identifiers

This document supplements `04-step1-prep.md` (which covered production-source
rewrites only) for **7 of the remaining 15 pallets** — the moderate/hard subset.
The remaining 8 "easy" pallets are handled in a parallel agent's
`05a-step1-prep-v2.md`. Pallets `migrations` and `atomic-swap` are already done
and out of scope.

## Overview

The atomic-swap proof-of-concept revealed three classes of work the original
prep doc did not list. This v2 doc fills those gaps for each of the seven
pallets in scope.

**Total work in this batch.** 13 test/mock/benchmarking files audited across 7
pallets (one pallet — mixnet — has no mock or test file in the repo, all-up
runtime testing is done in the parent kitchensink). Each pallet needs at minimum:
(a) the `frame = ...` line removed from both `[dependencies]` and (where present)
`[dev-dependencies]`; (b) explicit per-crate `features = ["derive"]` ensured on
`codec` (and confirmed on `scale-info`); (c) a rewrite of every test/mock/bench
file that uses `frame::testing_prelude::*` or `frame::benchmarking::prelude::*`
to explicit imports; (d) any implicit-prelude identifier in production source
(e.g. `blake2_256`, `TrailingZeroInput`, `One`) given an explicit `use`; and
(e) every `frame/std`, `frame/runtime-benchmarks`, `frame/try-runtime` flag in
`[features]` expanded to per-crate equivalents.

**Patterns shared across this batch.**

- **`codec/derive`**: 5 of 7 already explicit. `multisig` and `merkle-mountain-range`
  declare `codec = { workspace = true }` with no `features = ["derive"]` — they
  inherit `derive` transitively today via `frame`'s `codec` dep. Add it explicitly.
- **`scale-info/derive`**: All 7 already declare `features = ["derive"]`
  explicitly — no change needed.
- **`blake2_256` is the most-frequent implicit prod identifier** (proxy and
  multisig both use it). Both also use `TrailingZeroInput`. These were missed by
  the original prep doc.
- **`One::one()`**: used in `merkle-mountain-range/src/lib.rs` and
  `safe-mode/src/benchmarking.rs`. Resolves to `sp_arithmetic::traits::One`,
  pulled in via `frame::prelude::*` → `frame::arithmetic::*`. After rewrite,
  add `use sp_arithmetic::traits::One;` (or pull `Saturating, One` together
  from `sp_runtime::traits` since `sp_runtime::traits::One` is just a re-export).
- **Test files use `frame::testing_prelude::*`** in 6 of 7 pallets. The shared
  rewrite recipe (per pallet, with file-specific tweaks):
  ```rust
  use frame_support::{
      assert_err, assert_noop, assert_ok, construct_runtime, derive_impl,
      ord_parameter_types, parameter_types,
      traits::{ConstU32, ConstU64, Contains, Everything /* etc, file-specific */},
  };
  use frame_system::{self, mocking::MockBlock /* or MockBlockU32 */, EnsureSignedBy};
  use sp_io::TestExternalities as TestState;          // alias used in mocks
  use sp_runtime::{traits::BadOrigin, BuildStorage};  // BuildStorage for `.build_storage()`
  ```
- **`frame::benchmarking::prelude::*`** (used by 4 of 7 pallets' benchmarking files)
  rewrites to:
  ```rust
  use frame_benchmarking::v2::*;                       // benchmarks, benchmark, block, etc.
  use frame_benchmarking::{whitelisted_caller, v1::account, BenchmarkError};
  use frame_support::traits::UnfilteredDispatchable;
  use frame_system::RawOrigin;
  // plus the same prelude::* set from production rewrites (BlockNumberFor, etc.)
  use frame_support::pallet_prelude::*;
  use frame_system::pallet_prelude::*;
  ```
- **`frame::deps::*` escape-hatches**: `merkle-mountain-range/src/mock.rs` uses
  `frame::deps::frame_support::derive_impl`; mmr's `tests.rs` uses
  `frame::deps::sp_core::{offchain::*, H256}`; `mmr/benchmarking.rs` uses
  `frame::deps::frame_support::traits::OnInitialize`. All resolve to the obvious
  underlying paths after rewrite.
- **`runtime-benchmarks` requires adding `frame-benchmarking` as an explicit
  dep** for each pallet that has a `benchmarking.rs`. Currently the `frame`
  umbrella's `runtime-benchmarks` feature drags it in transitively. Going
  forward, add `frame-benchmarking = { workspace = true, optional = true }`
  to `[dependencies]` and gate it via the `runtime-benchmarks` feature. Of the
  7 pallets, 4 have `benchmarking.rs`: `proxy`, `multisig`, `safe-mode`,
  `merkle-mountain-range`.

**Pallets where rewrite is more than a 5-line `use` change** (need human eyes):

- **multisig** — `migrations.rs` has the unusual `#[frame::storage_alias]` macro
  and `frame::traits::WrapperKeepOpaque` trait-object usage in a real
  OnRuntimeUpgrade migration. Two `try-runtime`-gated lines reference
  `frame::try_runtime::TryRuntimeError`. Five distinct rewrite sites.
- **merkle-mountain-range** — 5 distinct prod files (`lib.rs`, `mmr/mod.rs`,
  `mmr/mmr.rs`, `mmr/storage.rs`, `default_weights.rs`/`weights.rs`) each
  touched, plus `mock.rs`/`tests.rs`/`benchmarking.rs` all use unusual
  `frame::deps::*` paths. The `use frame::traits;` (bare module import) in
  `mmr/mod.rs` is a quirk worth re-checking after rewrite.
- **proxy** — `lib.rs:840` uses `blake2_256` implicitly (missed by 04 prep doc),
  `lib.rs:841` uses `TrailingZeroInput`. Trait bound at line 156 references
  `frame::traits::InstanceFilter<...>`. Tests file has its own
  `impl frame::traits::InstanceFilter for ProxyType` (also a trait-object
  usage). Three rewrite sites in `tests.rs` alone.
- **paged-list** — `tests.rs` imports `frame::prelude::storage::{StorageAppender,
  StoragePrefixedContainer}` (NOT `frame::testing_prelude::*` standalone); the
  `runtime::prelude::storage` path used in `paged_list.rs` is the most
  umbrella-specific path in this batch.

**Surprises vs. the original prep doc.**

- **proxy implicit `blake2_256` + `TrailingZeroInput`**: 04 prep does NOT call
  these out for `pallet-proxy`. They are real (`lib.rs:840-841`) and will fail
  to compile if not added.
- **multisig implicit `blake2_256` + `TrailingZeroInput`**: same omission;
  `lib.rs:336, 646-647, 671` — three call sites.
- **mmr implicit `One::one()`**: `lib.rs:99` calls `.saturating_sub(One::one())`.
  Resolves through `frame::arithmetic::*` to `sp_arithmetic::traits::One`.
  04 prep does not flag it (focuses on `Hash` only).
- **safe-mode benchmarking `One::one()`**: `benchmarking.rs:163, 198` use
  `One::one()` and `frame_benchmarking::v2::*` provides only macros, not the
  `One` trait. `frame::benchmarking::prelude::*` includes `crate::prelude::*`
  which transitively pulls in `sp_arithmetic::traits::One`. Add it explicitly
  in the rewrite.
- **paged-list `frame::prelude::storage::*` in tests.rs**: 04 prep prep maps
  this only in `paged_list.rs`. The same path appears at the top of
  `tests.rs:24-27` and the rewrite there is to `frame_support::storage::*`.
- **mmr `frame::deps::sp_core::H256` in tests.rs**: not flagged by 04 prep
  (which only audited prod code). Maps to `sp_core::H256`. Adding `sp-core`
  to `[dev-dependencies]` is needed unless it's already pulled via the
  production `[dependencies]` rewrite, which it is for mmr.

---

## 1. `pallet-node-authorization`

### 1.1 Test file inventory

| File:line                | Path / use                                                            |
|--------------------------|------------------------------------------------------------------------|
| `src/mock.rs:23`         | `use frame::testing_prelude::*;`                                       |
| `src/mock.rs:25`         | `frame_system::mocking::MockBlock<Test>` (already explicit)            |
| `src/mock.rs:30`         | `System: frame_system,` (already explicit)                             |
| `src/mock.rs:35`         | `#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]`     |
| `src/mock.rs:36`         | `impl frame_system::Config for Test` (already explicit)                |
| `src/mock.rs:63`         | `frame_system::GenesisConfig::<Test>::default().build_storage()`       |
| `src/tests.rs:22`        | `use frame::testing_prelude::*;`                                       |
| `src/weights.rs:24`      | `use frame::weights_prelude::*;`                                       |

Identifiers actually used from the testing_prelude in `mock.rs`:
`construct_runtime`, `derive_impl`, `ord_parameter_types`, `ConstU32`,
`EnsureSignedBy`, `BuildStorage` (via `.build_storage()`), `TestState` (alias).

Identifiers used from the testing_prelude in `tests.rs`:
`assert_noop`, `assert_ok`, `assert_eq` (built-in), `BadOrigin`, plus values
re-exported from `super::*`/`mock::*` (`RuntimeOrigin`, `BTreeSet`,
`PeerId`/`pallet_node_authorization::*`).

### 1.2 Cargo feature gaps

- `codec = { features = ["derive"], workspace = true }` — already explicit, no change.
- `scale-info = { features = ["derive"], workspace = true }` — already explicit.
- No `runtime-benchmarks` feature exists today (no `benchmarking.rs`).
- `try-runtime` already only gates `frame/try-runtime`.

### 1.3 Implicit identifier scan (production code)

Production source: `src/lib.rs`, `src/weights.rs`. Greps for the candidate set
returned only the explicit `OpaquePeerId` (already in the `frame::deps::sp_core`
import block) — no implicit identifiers found. The 04 prep doc's rewrite plan
(`use sp_core::OpaquePeerId as PeerId; use sp_io; use sp_runtime::traits::StaticLookup;`)
is sufficient.

### 1.4 Proposed `Cargo.toml`

```toml
[dependencies]
codec = { features = ["derive"], workspace = true }
# REMOVE: frame = { workspace = true, features = ["runtime"] }
# ADD:
frame-support = { workspace = true }
frame-system = { workspace = true }
log = { workspace = true }
scale-info = { features = ["derive"], workspace = true }
sp-core = { workspace = true }
sp-io = { workspace = true }
sp-runtime = { workspace = true }

[dev-dependencies]
# (none — mock+tests use the same crates as [dependencies], plus nothing new)

[features]
default = ["std"]
std = [
    "codec/std",
    "frame-support/std",
    "frame-system/std",
    "log/std",
    "scale-info/std",
    "sp-core/std",
    "sp-io/std",
    "sp-runtime/std",
]
try-runtime = [
    "frame-support/try-runtime",
    "frame-system/try-runtime",
    "sp-runtime/try-runtime",
]
```

### 1.5 Proposed test-file rewrites

```rust
// src/mock.rs:23
// BEFORE: use frame::testing_prelude::*;
// AFTER:
use frame_support::{
    construct_runtime, derive_impl, ord_parameter_types,
    traits::ConstU32,
};
use frame_system::EnsureSignedBy;
use sp_io::TestExternalities as TestState;
use sp_runtime::BuildStorage;
```

```rust
// src/tests.rs:22
// BEFORE: use frame::testing_prelude::*;
// AFTER:
use frame_support::{assert_noop, assert_ok};
use sp_runtime::traits::BadOrigin;
```

```rust
// src/weights.rs:24
// BEFORE: use frame::weights_prelude::*;
// AFTER:
use core::marker::PhantomData;
use frame_support::{
    traits::Get,
    weights::{constants::{ParityDbWeight, RocksDbWeight}, Weight},
};
```

### 1.6 Risk notes

- `BTreeSet` is `alloc::collections::btree_set::BTreeSet`, already
  `use`-imported at the top of `lib.rs`; `tests.rs` references it via
  `use super::*;` so no new import needed.
- `RuntimeOrigin`, `Test`, `NodeAuthorization` are all from `mock::*` —
  no churn. Five-line `use`-block change in tests.rs, four-line change in
  mock.rs.

---

## 2. `pallet-proxy`

### 2.1 Test file inventory

| File:line                | Path / use                                                            |
|--------------------------|------------------------------------------------------------------------|
| `src/tests.rs:25`        | `use frame::testing_prelude::*;`                                       |
| `src/tests.rs:27`        | `frame_system::mocking::MockBlock<Test>`                               |
| `src/tests.rs:38`        | `#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]`     |
| `src/tests.rs:45`        | `#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig)]`  |
| `src/tests.rs:82`        | `impl frame::traits::InstanceFilter<RuntimeCall> for ProxyType`        |
| `src/tests.rs:127, 270, 290, 303` | `BlakeTwo256` (from prelude → sp_runtime::traits)             |
| `src/tests.rs:131`       | `BlockNumberProvider = frame_system::Pallet<Test>`                     |
| `src/tests.rs:135`       | `use frame_system::Call as SystemCall;` (already explicit)             |
| `src/tests.rs:139`       | `frame_system::Error<Test>` (already explicit)                         |
| `src/tests.rs:141`       | `pub fn new_test_ext() -> TestState` (alias)                           |
| `src/tests.rs:142`       | `frame_system::GenesisConfig::<Test>::default().build_storage()`       |
| `src/tests.rs:149`       | `let mut ext = TestState::new(t);`                                     |
| `src/tests.rs:155, 292, 310` | `frame_system::Pallet::<Test>::*` (already explicit)               |
| `src/tests.rs:258`       | `H256::zero()`                                                         |
| `src/benchmarking.rs:25-27` | `use frame::benchmarking::prelude::{account, benchmarks, impl_test_function, whitelisted_caller, BenchmarkError, RawOrigin};` |
| `src/weights.rs:69`      | `use frame::weights_prelude::*;`                                       |

Identifiers actually used from `frame::testing_prelude::*` in `tests.rs`:
`construct_runtime`, `derive_impl`, `parameter_types`, `ConstU32`, `Contains`,
`assert_ok`, `assert_noop`, `MockBlock` (re-exported via `frame_system::mocking::*`),
`TestState` (alias for `sp_io::TestExternalities`), `BuildStorage`,
`BlakeTwo256`, `H256`, `Encode`, `Decode`, `DecodeWithMemTracking`,
`MaxEncodedLen`, `scale_info` (path), `Box`/`vec`/`Vec` from `alloc`.

Identifiers actually used from `frame::benchmarking::prelude::*` in
`benchmarking.rs`: `account`, `benchmarks` (the v1 macro!), `impl_test_function`,
`whitelisted_caller`, `BenchmarkError`, `RawOrigin`. Also `BlockNumberFor`,
`BalanceOf` (via `super::*`) and `Lookup::unlookup`.

### 2.2 Cargo feature gaps

- `codec = { features = ["max-encoded-len"], workspace = true }` — note this
  pallet uses **`max-encoded-len`** but **NOT explicitly `derive`**. Production
  code uses `#[derive(Encode, Decode, MaxEncodedLen, ...)]` extensively, which
  requires `codec/derive`. Today `codec`'s `derive` feature is pulled in
  transitively via `frame`'s codec dep. Update to:
  `codec = { features = ["derive", "max-encoded-len"], workspace = true }`.
  **This is the single Cargo gap most likely to silently break.**
- `scale-info = { features = ["derive"], workspace = true }` — already explicit.
- Need to add `frame-benchmarking` as optional dep for `benchmarking.rs` once
  `frame` is removed.
- Also add `sp-io` (for `TestExternalities` in tests) and `sp-core` (for `H256`
  in tests) — neither is currently in either `[dependencies]` or
  `[dev-dependencies]`, both arrive transitively today.

### 2.3 Implicit identifier scan (production code)

Production source: `src/lib.rs`, `src/weights.rs`.

| Identifier         | File:line          | Resolves to                                |
|--------------------|--------------------|---------------------------------------------|
| `blake2_256`       | `lib.rs:840`       | `sp_io::hashing::blake2_256` (function) — **MISSED by 04 prep** |
| `TrailingZeroInput`| `lib.rs:841`       | `sp_runtime::traits::TrailingZeroInput` (in 04 prep's prelude rewrite already) |
| `Hash` (trait)     | `lib.rs:45, 187`   | `sp_runtime::traits::Hash` — 04 prep has it |
| `BlockNumberProvider` | `lib.rs:51`     | `sp_runtime::traits::BlockNumberProvider` — 04 prep has it |
| `StaticLookup`     | `lib.rs:53`        | `sp_runtime::traits::StaticLookup` — 04 prep has it |
| `Hash::Output`     | `lib.rs:45, 562`   | trait method on `T::CallHasher`             |

**Add to the 04 prep `lib.rs` rewrite**: `use sp_io::hashing::blake2_256;`.

### 2.4 Proposed `Cargo.toml`

```toml
[dependencies]
codec = { features = ["derive", "max-encoded-len"], workspace = true }   # ADD "derive"
# REMOVE: frame = { workspace = true, features = ["runtime"] }
# ADD:
frame-benchmarking = { optional = true, workspace = true }
frame-support = { workspace = true }
frame-system = { workspace = true }
scale-info = { features = ["derive"], workspace = true }
sp-io = { workspace = true }
sp-runtime = { workspace = true }

[dev-dependencies]
pallet-balances = { default-features = true, workspace = true }
pallet-utility = { default-features = true, workspace = true }
# ADD:
sp-core = { default-features = true, workspace = true }   # for H256 in tests.rs

[features]
default = ["std"]
std = [
    "codec/std",
    "frame-benchmarking?/std",
    "frame-support/std",
    "frame-system/std",
    "scale-info/std",
    "sp-io/std",
    "sp-runtime/std",
]
runtime-benchmarks = [
    "frame-benchmarking/runtime-benchmarks",
    "frame-support/runtime-benchmarks",
    "frame-system/runtime-benchmarks",
    "pallet-balances/runtime-benchmarks",
    "pallet-utility/runtime-benchmarks",
    "sp-runtime/runtime-benchmarks",
]
try-runtime = [
    "frame-support/try-runtime",
    "frame-system/try-runtime",
    "pallet-balances/try-runtime",
    "pallet-utility/try-runtime",
    "sp-runtime/try-runtime",
]
```

### 2.5 Proposed test-file rewrites

```rust
// src/tests.rs:25
// BEFORE: use frame::testing_prelude::*;
// AFTER:
use frame_support::{
    assert_noop, assert_ok, construct_runtime, derive_impl, parameter_types,
    traits::{ConstU32, Contains},
};
use frame_system::mocking::MockBlock;
use sp_core::H256;
use sp_io::TestExternalities as TestState;
use sp_runtime::{traits::BlakeTwo256, BuildStorage};
// codec derives are pulled via #[derive(Encode, Decode, ...)] which need
// codec & scale_info in scope; the existing `use scale_info::TypeInfo;` (or
// the `scale_info::TypeInfo` qualified path in line 70) already covers it.
```

```rust
// src/tests.rs:82
// BEFORE: impl frame::traits::InstanceFilter<RuntimeCall> for ProxyType {
// AFTER:  impl frame_support::traits::InstanceFilter<RuntimeCall> for ProxyType {
```

```rust
// src/benchmarking.rs:25-27
// BEFORE
use frame::benchmarking::prelude::{
    account, benchmarks, impl_test_function, whitelisted_caller, BenchmarkError, RawOrigin,
};
// AFTER
use frame_benchmarking::{
    impl_test_function, v1::{account, benchmarks}, whitelisted_caller, BenchmarkError,
};
use frame_system::RawOrigin;
// (`benchmarks` is the v1 macro — note v1::benchmarks; if this pallet's
// benchmarks are v2 syntax, pull `frame_benchmarking::v2::*` instead.
// Actual file uses `benchmarks!` macro syntax → v1.)
```

```rust
// src/weights.rs:69
// BEFORE: use frame::weights_prelude::*;
// AFTER:
use core::marker::PhantomData;
use frame_support::{
    traits::Get,
    weights::{constants::{ParityDbWeight, RocksDbWeight}, Weight},
};
```

### 2.6 Risk notes

- The `tests.rs:82` `impl frame::traits::InstanceFilter<RuntimeCall>` is a
  trait-object usage in a test-only `ProxyType` enum. After rewrite,
  `frame_support::traits::InstanceFilter` must be in scope — added via the new
  use block.
- `tests.rs` has many `frame_system::Pallet::<Test>::set_block_number(...)`
  calls (lines 292, 310, etc.). No change needed; already explicit.
- `tests.rs:70` references `scale_info::TypeInfo` directly — needs
  `scale-info` in `[dev-dependencies]`. It's currently transitive via
  `frame`. Verify after edit; may need to add to `[dev-dependencies]`.
  (`scale-info` is in `[dependencies]`, so it surfaces in dev too — should
  be fine.)
- The 04 prep's lib.rs rewrite **must add** `use sp_io::hashing::blake2_256;`
  — without it, `lib.rs:840` is a compile error.

---

## 3. `pallet-multisig`

### 3.1 Test file inventory

| File:line                | Path / use                                                            |
|--------------------------|------------------------------------------------------------------------|
| `src/tests.rs:24`        | `use frame::{prelude::*, runtime::prelude::*, testing_prelude::*};`    |
| `src/tests.rs:26`        | `frame_system::mocking::MockBlockU32<Test>` (note **U32** variant)     |
| `src/tests.rs:36`        | `#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]`     |
| `src/tests.rs:44`        | `#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig)]`  |
| `src/tests.rs:51`        | `impl Contains<RuntimeCall> for TestBaseCallFilter` (Contains trait)   |
| `src/tests.rs:62`        | `parameter_types!` macro                                               |
| `src/tests.rs:73`        | `type MaxSignatories = ConstU32<3>;`                                   |
| `src/tests.rs:80`        | `pub fn new_test_ext() -> TestState`                                   |
| `src/tests.rs:81`        | `frame_system::GenesisConfig::<Test>::default().build_storage()`       |
| `src/tests.rs:88`        | `let mut ext = TestState::new(t);`                                     |
| `src/tests.rs:117, 146, 154, 182, 193, 203, 215, 235, 246` | `Weight::zero()`        |
| `src/migrations.rs:21`   | `use frame::prelude::*;`                                               |
| `src/migrations.rs:26`   | `frame::traits::WrapperKeepOpaque`                                     |
| `src/migrations.rs:28`   | `#[frame::storage_alias]`                                              |
| `src/migrations.rs:39, 72` | `frame::try_runtime::TryRuntimeError` (try-runtime gated)            |
| `src/migrations.rs:46`   | `use frame::traits::ReservableCurrency as _;`                          |
| `src/benchmarking.rs:23` | `use frame::benchmarking::prelude::*;`                                 |
| `src/weights.rs:70`      | `use frame::weights_prelude::*;`                                       |

Identifiers used from testing_prelude in `tests.rs`: `construct_runtime`,
`derive_impl`, `parameter_types`, `ConstU32`, `Contains`, `assert_ok`,
`assert_noop`, `MockBlockU32` (specifically — comes from `frame_system::mocking`),
`TestState`, `BuildStorage`, `Weight`, plus `Box`/`vec`/`Vec` (`alloc`/`std`).
Note this file ALSO has `use frame::{prelude::*, runtime::prelude::*, testing_prelude::*};`
— the prelude/runtime::prelude segments are redundant in a tests file (the
testing_prelude already includes both) and can be dropped.

Identifiers used from benchmarking::prelude in `benchmarking.rs`: `account`,
`benchmarks` (v1 macro), `whitelisted_caller`, `RawOrigin`, plus prelude
identifiers `BlockNumberFor`, `BalanceOf` etc.

### 3.2 Cargo feature gaps

- `codec = { workspace = true }` — **MISSING `features = ["derive"]`** despite
  heavy `#[derive(Encode, Decode, ...)]` use in `lib.rs`. Currently inherits
  via `frame`'s codec. Add: `codec = { features = ["derive"], workspace = true }`.
- `scale-info = { features = ["derive"], workspace = true }` — already explicit.
- Add `frame-benchmarking` as optional dep.
- Need `sp-io` and `sp-runtime` in `[dependencies]` (for `TryRuntimeError`,
  `BlockNumberProvider`, `BoundedVec`, `TrailingZeroInput`, `blake2_256`).

### 3.3 Implicit identifier scan (production code)

Production source: `src/lib.rs`, `src/migrations.rs`, `src/weights.rs`.

| Identifier             | File:line                       | Resolves to                              |
|------------------------|---------------------------------|------------------------------------------|
| `blake2_256`           | `lib.rs:336, 646, 671`          | `sp_io::hashing::blake2_256` — **MISSED by 04 prep** |
| `TrailingZeroInput`    | `lib.rs:647`                    | `sp_runtime::traits::TrailingZeroInput` — 04 prep has it |
| `BlockNumberProvider`  | `lib.rs:81`                     | `sp_runtime::traits::BlockNumberProvider` — 04 prep has it |
| `WrapperKeepOpaque`    | `migrations.rs:26`              | `frame_support::traits::WrapperKeepOpaque` — 04 prep has it |
| `OnRuntimeUpgrade`     | `migrations.rs:37`              | `frame_support::traits::OnRuntimeUpgrade` — in prelude |
| `TryRuntimeError`      | `migrations.rs:39, 72`          | `sp_runtime::TryRuntimeError` — 04 prep has it |

**Add to the 04 prep `lib.rs` rewrite**: `use sp_io::hashing::blake2_256;`.

### 3.4 Proposed `Cargo.toml`

```toml
[dependencies]
codec = { features = ["derive"], workspace = true }   # ADD "derive"
# REMOVE: frame = { workspace = true, features = ["runtime"] }
# ADD:
frame-benchmarking = { optional = true, workspace = true }
frame-support = { workspace = true }
frame-system = { workspace = true }
scale-info = { features = ["derive"], workspace = true }
sp-io = { workspace = true }
sp-runtime = { workspace = true }

# third party
log = { workspace = true }

[dev-dependencies]
pallet-balances = { default-features = true, workspace = true }

[features]
default = ["std"]
std = [
    "codec/std",
    "frame-benchmarking?/std",
    "frame-support/std",
    "frame-system/std",
    "log/std",
    "scale-info/std",
    "sp-io/std",
    "sp-runtime/std",
]
runtime-benchmarks = [
    "frame-benchmarking/runtime-benchmarks",
    "frame-support/runtime-benchmarks",
    "frame-system/runtime-benchmarks",
    "pallet-balances/runtime-benchmarks",
    "sp-runtime/runtime-benchmarks",
]
try-runtime = [
    "frame-support/try-runtime",
    "frame-system/try-runtime",
    "pallet-balances/try-runtime",
    "sp-runtime/try-runtime",
]
```

### 3.5 Proposed test-file rewrites

```rust
// src/tests.rs:24
// BEFORE: use frame::{prelude::*, runtime::prelude::*, testing_prelude::*};
// AFTER:
use frame_support::{
    assert_noop, assert_ok, construct_runtime, derive_impl, parameter_types,
    traits::{ConstU32, Contains},
    weights::Weight,
};
use frame_system::mocking::MockBlockU32;
use sp_io::TestExternalities as TestState;
use sp_runtime::BuildStorage;
// (drop redundant `prelude::*` and `runtime::prelude::*` — testing_prelude
// already pulled them in; nothing else in tests.rs needs them.)
```

```rust
// src/migrations.rs:21
// BEFORE
use frame::prelude::*;
type OpaqueCall<T> = frame::traits::WrapperKeepOpaque<<T as Config>::RuntimeCall>;
#[frame::storage_alias]
// (try-runtime gated):
fn pre_upgrade() -> Result<Vec<u8>, frame::try_runtime::TryRuntimeError> { ... }
// (line 46):
use frame::traits::ReservableCurrency as _;
fn post_upgrade(_state: Vec<u8>) -> Result<(), frame::try_runtime::TryRuntimeError> { ... }

// AFTER
use frame_support::pallet_prelude::*;
use frame_support::storage_alias;            // for #[storage_alias] attribute
use frame_system::pallet_prelude::*;
type OpaqueCall<T> = frame_support::traits::WrapperKeepOpaque<<T as Config>::RuntimeCall>;
#[storage_alias]
// (try-runtime gated):
fn pre_upgrade() -> Result<Vec<u8>, sp_runtime::TryRuntimeError> { ... }
// (line 46):
use frame_support::traits::ReservableCurrency as _;
fn post_upgrade(_state: Vec<u8>) -> Result<(), sp_runtime::TryRuntimeError> { ... }
```

```rust
// src/benchmarking.rs:23
// BEFORE: use frame::benchmarking::prelude::*;
// AFTER:
use frame_benchmarking::{v1::{account, benchmarks}, whitelisted_caller, BenchmarkError};
use frame_support::{pallet_prelude::*, traits::UnfilteredDispatchable};
use frame_system::{pallet_prelude::*, RawOrigin};
// (this file uses v1 `benchmarks!` macro syntax — confirm before rewrite.)
```

```rust
// src/weights.rs:70
// BEFORE: use frame::weights_prelude::*;
// AFTER:
use core::marker::PhantomData;
use frame_support::{
    traits::Get,
    weights::{constants::{ParityDbWeight, RocksDbWeight}, Weight},
};
```

### 3.6 Risk notes

- `#[frame::storage_alias]` → `#[storage_alias]` (or `#[frame_support::storage_alias]`).
  The macro is path-sensitive at parse time; using the bare form requires
  `use frame_support::storage_alias;` to be in scope. **Confirm post-edit
  that the macro expansion still finds `frame_support` (not `frame`).**
- The OnRuntimeUpgrade hooks `pre_upgrade`/`post_upgrade` are gated behind
  `#[cfg(feature = "try-runtime")]` — both lines (39 and 72) must change
  in lockstep.
- `migrations.rs:46` rewrites `use frame::traits::ReservableCurrency as _;`
  to `use frame_support::traits::ReservableCurrency as _;` — verify the
  trait method `unreserve` (line 57) still resolves through the explicit
  import.
- Production lib.rs has three `blake2_256` call sites — add ONE
  `use sp_io::hashing::blake2_256;` near the top of `lib.rs`.

---

## 4. `pallet-safe-mode`

### 4.1 Test file inventory

| File:line                       | Path / use                                                                  |
|----------------------------------|-----------------------------------------------------------------------------|
| `src/mock.rs:25-28`              | `use frame::{testing_prelude::*, traits::{InsideBoth, InstanceFilter, IsInVec}};` |
| `src/mock.rs:30`                 | `#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]`          |
| `src/mock.rs:31, 38, 39, 41, etc` | direct field types: `H256`, `BlakeTwo256`, `IdentityLookup<...>`           |
| `src/mock.rs:53`                 | `type MaxConsumers = ConstU32<16>;`                                          |
| `src/mock.rs:65`                 | `#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig)]`        |
| `src/mock.rs:67`                 | `type ExistentialDeposit = ConstU64<2>;`                                     |
| `src/mock.rs:128-135`            | proxy `ConstU64`/`ConstU32` constants + `BlakeTwo256`                        |
| `src/mock.rs:141`                | `impl Contains<RuntimeCall>`                                                  |
| `src/mock.rs:150`                | `parameter_types!`                                                            |
| `src/mock.rs:172`                | `impl SafeModeNotify` (uses pallet's own trait — already `super::*`)         |
| `src/mock.rs:186`                | `ord_parameter_types!`                                                        |
| `src/mock.rs:200, 201, 202, 203` | `EnsureSignedBy<...>`                                                        |
| `src/mock.rs:209`                | `frame_system::mocking::MockBlock<Test>`                                     |
| `src/mock.rs:211`                | `construct_runtime!`                                                          |
| `src/mock.rs:225`                | `pub fn new_test_ext() -> TestExternalities`  (note: NOT alias `TestState`)  |
| `src/mock.rs:226, 239`           | `build_storage()` / `TestExternalities::new(t)`                              |
| `src/tests.rs:25`                | `use frame::{testing_prelude::*, traits::Currency};`                         |
| `src/tests.rs:33-44, 90-99, 116, 143, etc.` | `assert_err!`, `assert_ok!`, `assert_noop!`                       |
| `src/tests.rs:34, 42, 55, 141, 144` | `call_transfer().dispatch(RuntimeOrigin::signed(0))` — needs `Dispatchable` |
| `src/tests.rs:243-251`           | `DispatchError::BadOrigin`                                                    |
| `src/benchmarking.rs:21`         | `use frame::benchmarking::prelude::*;`                                       |
| `src/benchmarking.rs:23`         | `#[benchmarks(where T::Currency: fungible::Mutate<T::AccountId>)]` (v2)      |
| `src/benchmarking.rs:163, 198`   | `One::one()`                                                                  |
| `src/weights.rs:70`              | `use frame::weights_prelude::*;`                                              |

Identifiers used from `frame::testing_prelude::*` in mock.rs: `derive_impl`,
`construct_runtime`, `parameter_types`, `ord_parameter_types`, `Everything`,
`ConstU32`, `ConstU64`, `Contains`, `MockBlock`, `TestExternalities` (the
deprecated alias name — see `frame/src/lib.rs:337-338` for the deprecation
notice. mock.rs uses both `TestExternalities` (line 225, 239) — recommend
sticking with `sp_io::TestExternalities` and dropping the alias hop.) Plus
`H256`, `BlakeTwo256`, `IdentityLookup`, `Encode`, `Decode`, `DecodeWithMemTracking`,
`MaxEncodedLen`, `Debug`, `TypeInfo`, `EnsureSignedBy`, `BuildStorage`,
`scale_info::TypeInfo`. From `traits::*`: `InsideBoth`, `InstanceFilter`,
`IsInVec` (explicit).

Identifiers used from `frame::testing_prelude::*` in tests.rs: `assert_err`,
`assert_ok`, `assert_noop`, `Dispatchable` (for `.dispatch()`), `DispatchError`,
plus values from `mock::*`. From `traits::*`: `Currency` (explicit).

Identifiers used from `frame::benchmarking::prelude::*` in benchmarking.rs:
`benchmarks` (v2 macro), `benchmark`, `block`, `BenchmarkError`,
`whitelisted_caller`, `account`, `RawOrigin`, `impl_benchmark_test_suite`,
`UnfilteredDispatchable`, plus prelude identifiers `BlockNumberFor`, `Get`,
`Saturating`, `One` (from arithmetic).

### 4.2 Cargo feature gaps

- `codec = { features = ["derive"], workspace = true }` — already explicit.
- `scale-info = { features = ["derive"], workspace = true }` — already explicit.
- Add `frame-benchmarking` as optional dep.
- Add `sp-io` and `sp-runtime` to `[dependencies]` (for `BlockNumberFor`,
  `Saturating`, `IdentityLookup`).
- Add `sp-core` to `[dev-dependencies]` (for `H256` in mock.rs).
- The `docify` dep stays.

### 4.3 Implicit identifier scan (production code)

Production source: `src/lib.rs`, `src/weights.rs`. No implicit identifiers
beyond what 04 prep covers (the `Saturating`, `EnsureOrigin`, etc. in lib.rs
are all in `frame_support::pallet_prelude::*`/`frame_system::pallet_prelude::*`).

The only nuance: `lib.rs:611, 625, 629, 633, 638` reference `frame::traits::SafeMode`/
`SafeModeError`. 04 prep already maps these to `frame_support::traits::*`.

### 4.4 Proposed `Cargo.toml`

```toml
[dependencies]
codec = { features = ["derive"], workspace = true }
docify = { workspace = true }
# REMOVE: frame = { workspace = true, features = ["runtime"] }
# ADD:
frame-benchmarking = { optional = true, workspace = true }
frame-support = { workspace = true }
frame-system = { workspace = true }
pallet-balances = { optional = true, workspace = true }
pallet-proxy = { optional = true, workspace = true }
pallet-utility = { optional = true, workspace = true }
scale-info = { features = ["derive"], workspace = true }
sp-arithmetic = { workspace = true }   # for One trait in benchmarking
sp-io = { workspace = true }
sp-runtime = { workspace = true }

[dev-dependencies]
pallet-balances = { default-features = true, workspace = true }
pallet-proxy = { default-features = true, workspace = true }
pallet-utility = { default-features = true, workspace = true }
sp-core = { default-features = true, workspace = true }   # ADD: for H256, BlakeTwo256
sp-io = { default-features = true, workspace = true }      # ADD: for TestExternalities

[features]
default = ["std"]
std = [
    "codec/std",
    "frame-benchmarking?/std",
    "frame-support/std",
    "frame-system/std",
    "pallet-balances?/std",
    "pallet-proxy?/std",
    "pallet-utility?/std",
    "scale-info/std",
    "sp-arithmetic/std",
    "sp-io/std",
    "sp-runtime/std",
]
runtime-benchmarks = [
    "frame-benchmarking/runtime-benchmarks",
    "frame-support/runtime-benchmarks",
    "frame-system/runtime-benchmarks",
    "pallet-balances/runtime-benchmarks",
    "pallet-proxy/runtime-benchmarks",
    "pallet-utility/runtime-benchmarks",
    "sp-runtime/runtime-benchmarks",
]
try-runtime = [
    "frame-support/try-runtime",
    "frame-system/try-runtime",
    "pallet-balances?/try-runtime",
    "pallet-proxy?/try-runtime",
    "pallet-utility?/try-runtime",
    "sp-runtime/try-runtime",
]
```

### 4.5 Proposed test-file rewrites

```rust
// src/mock.rs:25-28
// BEFORE
use frame::{
    testing_prelude::*,
    traits::{InsideBoth, InstanceFilter, IsInVec},
};
// AFTER
use frame_support::{
    construct_runtime, derive_impl, ord_parameter_types, parameter_types,
    traits::{ConstU32, ConstU64, Contains, Everything, InsideBoth, InstanceFilter, IsInVec},
};
use frame_system::{mocking::MockBlock, EnsureSignedBy};
use sp_core::H256;
use sp_io::TestExternalities;
use sp_runtime::{traits::{BlakeTwo256, IdentityLookup}, BuildStorage};
```

```rust
// src/tests.rs:25
// BEFORE: use frame::{testing_prelude::*, traits::Currency};
// AFTER:
use frame_support::{
    assert_err, assert_noop, assert_ok,
    traits::Currency,
};
use sp_runtime::{traits::Dispatchable, DispatchError};
// (DispatchError covers `DispatchError::BadOrigin` references in tests.rs:243+.)
```

```rust
// src/benchmarking.rs:21
// BEFORE: use frame::benchmarking::prelude::*;
// AFTER:
use frame_benchmarking::{v2::*, BenchmarkError, whitelisted_caller, v1::account};
use frame_support::{pallet_prelude::*, traits::UnfilteredDispatchable};
use frame_system::{pallet_prelude::*, RawOrigin};
use sp_arithmetic::traits::One;       // for `One::one()` at lines 163, 198
use sp_runtime::traits::Saturating;
```

```rust
// src/weights.rs:70 — same recipe as #2.
```

### 4.6 Risk notes

- **`mock.rs` uses `TestExternalities` (deprecated alias)** at lines 225 and
  239, while almost every other pallet uses the `TestState` alias. The
  `frame::testing_prelude` aliases `sp_io::TestExternalities as TestState`
  but ALSO re-exports the original name as `TestExternalities` (deprecated).
  Rewrite to `sp_io::TestExternalities` directly.
- **`docify::export`** annotations on tests (e.g. `tests.rs:274, 292`) require
  the `docify` dep to remain — already in `[dependencies]`, untouched.
- **`fungible::Mutate<T::AccountId>`** in `benchmarking.rs:23` uses the
  `fungible` module brought in via `frame::prelude::*` → `frame::token::*` →
  `frame_support::traits::tokens::fungible`. The 04 prep's lib.rs rewrite
  pulls in `frame_support::traits::fungible::{...}` already; benchmarking.rs
  uses `super::*` → inherits `fungible` via lib.rs's `use frame_support::traits::fungible::...`
  PROVIDED that the lib.rs rewrite uses the `fungible::self` form (i.e.
  `traits::fungible::{self, hold::{Inspect, Mutate}}`). 04 prep's safe-mode
  rewrite (line 1421-1426) does this correctly.
- `mock.rs:172` `impl SafeModeNotify` references the pallet's own trait — no
  change needed, comes via `super::*`.

---

## 5. `pallet-mixnet`

### 5.1 Test file inventory

**No test, mock, or benchmarking file in this pallet** — only `src/lib.rs`.
Mixnet is exercised by integration tests in the parent runtime (kitchensink),
not by an in-pallet test module.

| File:line             | Path / use                                                          |
|-----------------------|----------------------------------------------------------------------|
| `src/lib.rs:30-36`    | `use frame::{deps::{sp_io::{self, MultiRemovalResults}, sp_runtime}, prelude::*};` |
| `src/lib.rs:175`      | `#[frame::pallet(dev_mode)]`                                         |
| `src/lib.rs:549`      | `impl<T: Config> sp_runtime::BoundToRuntimeAppPublic for Pallet<T>`  |

### 5.2 Cargo feature gaps

- `codec = { features = ["derive", "max-encoded-len"], workspace = true }` —
  both already explicit.
- `scale-info = { features = ["derive"], workspace = true }` — explicit.
- `serde = { features = ["derive"], workspace = true }` — explicit.
- No `runtime-benchmarks` feature in current Cargo.toml; nothing to update there.

### 5.3 Implicit identifier scan (production code)

| Identifier              | File:line               | Resolves to                                       |
|-------------------------|-------------------------|---------------------------------------------------|
| `BoundToRuntimeAppPublic` | `lib.rs:549`           | `sp_runtime::BoundToRuntimeAppPublic` — already in 04 prep's `use sp_runtime;` (or fully-qualified path) |
| `EstimateNextSessionRotation` | `lib.rs:197`       | `frame_support::traits::EstimateNextSessionRotation` — in `frame_support::pallet_prelude::*`? **No** — it's in `frame_support::traits::*`, re-exported via prelude wildcard → `frame_support::pallet_prelude::*`. Verify; if missing, add `use frame_support::traits::EstimateNextSessionRotation;`. |
| `OneSessionHandler`     | (in trait bound, see 04 prep) | `frame_support::traits::OneSessionHandler`     |
| `CreateBare`            | `lib.rs:182` (Config bound) | `frame_system::offchain::CreateBare` — re-exported via `frame::prelude::*` → `frame_system::offchain::*`. After rewrite, add `use frame_system::offchain::CreateBare;`. |
| `RuntimeAppPublic`      | `lib.rs:38`             | `sp_application_crypto::RuntimeAppPublic` — already explicit `use sp_application_crypto::RuntimeAppPublic;` |
| `sp_io::hashing::twox_64` | `lib.rs:168`           | already qualified; no change                       |

The 04 prep already adds `use sp_io::{self, MultiRemovalResults};` and the
`use sp_runtime;` extern alias (or qualified `sp_runtime::BoundToRuntimeAppPublic`).
**Adds for mixnet beyond 04 prep:** `use frame_system::offchain::CreateBare;`
(needed for the `Config: ... + CreateBare<Call<Self>>` bound at lib.rs:182).

### 5.4 Proposed `Cargo.toml`

```toml
[dependencies]
codec = { features = ["derive", "max-encoded-len"], workspace = true }
# REMOVE: frame = { workspace = true, features = ["runtime"] }
# ADD:
frame-support = { workspace = true }
frame-system = { workspace = true }
log = { workspace = true }
scale-info = { features = ["derive"], workspace = true }
serde = { features = ["derive"], workspace = true }
sp-application-crypto = { workspace = true }
sp-io = { workspace = true }
sp-mixnet = { workspace = true }
sp-runtime = { workspace = true }

[features]
default = ["std"]
std = [
    "codec/std",
    "frame-support/std",
    "frame-system/std",
    "log/std",
    "scale-info/std",
    "serde/std",
    "sp-application-crypto/std",
    "sp-io/std",
    "sp-mixnet/std",
    "sp-runtime/std",
]
try-runtime = [
    "frame-support/try-runtime",
    "frame-system/try-runtime",
    "sp-runtime/try-runtime",
]
```

### 5.5 Proposed test-file rewrites

**None — pallet has no test files.**

### 5.6 Risk notes

- The `dev_mode` argument to `#[frame::pallet(dev_mode)]` passes through
  unchanged: `#[frame_support::pallet(dev_mode)]`.
- `EstimateNextSessionRotation` import: if the macro expansion of
  `#[pallet::config]` references it through `frame_support::pallet_prelude::*`,
  no extra import is needed; otherwise add `use frame_support::traits::EstimateNextSessionRotation;`.
  Confirm post-edit.
- `CreateBare` is a fairly recent addition (replaced older `SendTransactionTypes`
  pattern); the `Config: frame_system::Config + CreateBare<Call<Self>>` bound
  at line 182 needs `CreateBare` in scope. Add explicit
  `use frame_system::offchain::CreateBare;`.
- This is the simplest pallet of the seven — only one file to edit.

---

## 6. `pallet-mmr` (`merkle-mountain-range`)

### 6.1 Test file inventory

| File:line                       | Path / use                                                                  |
|----------------------------------|-----------------------------------------------------------------------------|
| `src/mock.rs:21-24`              | `use crate::{frame_system::DefaultConfig, primitives::{Compact, LeafDataProvider}};` (note — pulls `frame_system` from `crate::*` re-export) |
| `src/mock.rs:25`                 | `use codec::{Decode, Encode};`                                                |
| `src/mock.rs:26-30`              | `use frame::{deps::frame_support::derive_impl, prelude::{frame_system, frame_system::config_preludes::TestDefaultConfig}, testing_prelude::*};` |
| `src/mock.rs:32`                 | `type Block = MockBlock<Test>;` (note — bare name from prelude)              |
| `src/mock.rs:34`                 | `construct_runtime!`                                                          |
| `src/mock.rs:42`                 | `#[derive_impl(TestDefaultConfig)]`                                            |
| `src/mock.rs:50, 51`             | `Keccak256` (from prelude → sp_runtime::traits)                              |
| `src/mock.rs:71`                 | `parameter_types!`                                                            |
| `src/tests.rs:18`                | `use crate::{mock::*, *};`                                                    |
| `src/tests.rs:22-28`             | `use frame::{deps::sp_core::{offchain::{testing::TestOffchainExt, OffchainDbExt, OffchainWorkerExt}, H256}, testing_prelude::*};` |
| `src/tests.rs:30`                | `pub(crate) fn new_test_ext() -> TestState`                                   |
| `src/tests.rs:31`                | `frame_system::GenesisConfig::<Test>::default().build_storage()`              |
| `src/tests.rs:34-37`             | `TestOffchainExt::with_offchain_db`, `OffchainDbExt::new`, `OffchainWorkerExt::new` |
| `src/tests.rs:42, 55, 122, 141` | `H256::repeat_byte`, `H256` parsing                                          |
| `src/tests.rs:59`                | `type BlockNumber = BlockNumberFor<Test>;`                                    |
| `src/tests.rs:723-728`           | `<Test as frame_system::Config>::BlockHashCount::get()` (already explicit)    |
| `src/benchmarking.rs:23-26`      | `use frame::{benchmarking::prelude::v1::benchmarks_instance_pallet, deps::frame_support::traits::OnInitialize};` |
| `src/default_weights.rs:21`      | `use frame::{deps::frame_support::weights::constants::*, weights_prelude::*};` |
| `src/weights.rs:70`              | `use frame::weights_prelude::*;`                                              |

Identifiers used from `frame::testing_prelude::*` in mock.rs: `construct_runtime`,
`parameter_types`, `MockBlock`, `Encode`/`Decode` (derive macros — also from
`codec`), `Keccak256` (from sp_runtime::traits), `Vec` (from alloc/std).

Identifiers used from `frame::testing_prelude::*` in tests.rs: `assert_eq!`
(built-in), `Vec`, `BlockNumberFor` (from frame_support::pallet_prelude or
frame_system::pallet_prelude), `Weight`, plus values from `mock::*` and
`super::*`. **No assertion macros are used directly (the file uses bare
`assert_eq!` and `assert!`).**

Identifiers used from `frame::benchmarking::prelude::v1` in benchmarking.rs:
`benchmarks_instance_pallet`, `impl_benchmark_test_suite` (likely transitively
included).

### 6.2 Cargo feature gaps

- `codec = { workspace = true }` — **MISSING `features = ["derive"]`**. Used
  via `#[derive(Encode, Decode, ...)]` in mock.rs and lib.rs. Add explicit.
- `scale-info = { features = ["derive"], workspace = true }` — already explicit.
- Add `frame-benchmarking` as optional dep.
- Need `sp-core`, `sp-io`, `sp-runtime` (already analyzed in 04 prep).

### 6.3 Implicit identifier scan (production code)

Production source: `src/lib.rs`, `src/mmr/mod.rs`, `src/mmr/mmr.rs`,
`src/mmr/storage.rs`, `src/default_weights.rs`, `src/weights.rs`.

| Identifier         | File:line          | Resolves to                                  |
|--------------------|---------------------|----------------------------------------------|
| `One::one()`       | `lib.rs:99`         | `sp_arithmetic::traits::One` — **MISSED by 04 prep** |
| `Saturating::saturating_sub` | `lib.rs:99` | `sp_arithmetic::traits::Saturating` — in prelude already |
| `Hash` (trait)     | `lib.rs:145`, `mmr/mmr.rs:68` | `sp_runtime::traits::Hash` — 04 prep has it |
| `PhantomData`      | `lib.rs:91, 112`    | `core::marker::PhantomData` — in prelude     |
| `BlockNumberFor`   | `lib.rs:95, 115`    | in prelude                                   |
| `Weight`, `Get`    | `lib.rs:122`, `mmr/...` | in prelude                              |

**Add to the 04 prep `lib.rs` rewrite**: `use sp_arithmetic::traits::One;`
(or `use sp_runtime::traits::One;` since it's re-exported there).

### 6.4 Proposed `Cargo.toml`

```toml
[dependencies]
codec = { features = ["derive"], workspace = true }   # ADD "derive"
# REMOVE: frame = { workspace = true, features = ["runtime"] }
# ADD:
frame-benchmarking = { optional = true, workspace = true }
frame-support = { workspace = true }
frame-system = { workspace = true }
log = { workspace = true }
scale-info = { features = ["derive"], workspace = true }
sp-arithmetic = { workspace = true }    # for One trait in lib.rs
sp-core = { workspace = true }
sp-io = { workspace = true }
sp-mmr-primitives = { workspace = true }
sp-runtime = { workspace = true }

[dev-dependencies]
itertools = { workspace = true }
sp-tracing = { default-features = true, workspace = true }
# (sp-core, sp-io, sp-runtime already in [dependencies], surface in dev too.)

[features]
default = ["std"]
std = [
    "codec/std",
    "frame-benchmarking?/std",
    "frame-support/std",
    "frame-system/std",
    "log/std",
    "scale-info/std",
    "sp-arithmetic/std",
    "sp-core/std",
    "sp-io/std",
    "sp-mmr-primitives/std",
    "sp-runtime/std",
]
runtime-benchmarks = [
    "frame-benchmarking/runtime-benchmarks",
    "frame-support/runtime-benchmarks",
    "frame-system/runtime-benchmarks",
    "sp-runtime/runtime-benchmarks",
]
try-runtime = [
    "frame-support/try-runtime",
    "frame-system/try-runtime",
    "sp-runtime/try-runtime",
]
```

### 6.5 Proposed test-file rewrites

```rust
// src/mock.rs:26-30
// BEFORE
use frame::{
    deps::frame_support::derive_impl,
    prelude::{frame_system, frame_system::config_preludes::TestDefaultConfig},
    testing_prelude::*,
};
// AFTER
use frame_support::{construct_runtime, derive_impl, parameter_types};
use frame_system::{self, config_preludes::TestDefaultConfig, mocking::MockBlock};
use sp_runtime::traits::Keccak256;
// (`crate::frame_system::DefaultConfig` at line 22 now resolves through
// `crate::*` re-exporting `frame_system` from prelude — alternatively, change
// line 22 to `use frame_system::DefaultConfig;`.)
```

```rust
// src/tests.rs:22-28
// BEFORE
use frame::{
    deps::sp_core::{
        offchain::{testing::TestOffchainExt, OffchainDbExt, OffchainWorkerExt},
        H256,
    },
    testing_prelude::*,
};
// AFTER
use frame_support::weights::Weight;          // for Weight in line 40
use frame_system::pallet_prelude::BlockNumberFor;   // for line 59
use sp_core::{
    offchain::{testing::TestOffchainExt, OffchainDbExt, OffchainWorkerExt},
    H256,
};
use sp_io::TestExternalities as TestState;
use sp_runtime::BuildStorage;
```

```rust
// src/benchmarking.rs:23-26
// BEFORE
use frame::{
    benchmarking::prelude::v1::benchmarks_instance_pallet,
    deps::frame_support::traits::OnInitialize,
};
// AFTER
use frame_benchmarking::v1::{benchmarks_instance_pallet, impl_benchmark_test_suite};
use frame_support::traits::OnInitialize;
use frame_system::pallet_prelude::BlockNumberFor;
```

```rust
// src/default_weights.rs:21
// BEFORE: use frame::{deps::frame_support::weights::constants::*, weights_prelude::*};
// AFTER:
use core::marker::PhantomData;
use frame_support::{
    traits::Get,
    weights::{constants::{ParityDbWeight, RocksDbWeight, *}, Weight},
};
```

```rust
// src/weights.rs:70 — same recipe.
```

### 6.6 Risk notes

- **`crate::frame_system::DefaultConfig` import in mock.rs:22**: relies on
  `frame_system` being re-exported from `crate::*` (via `frame::prelude::*`).
  After rewrite, `lib.rs` will instead `use frame_system::pallet_prelude::*`
  which does NOT bring the `frame_system` module into scope at the crate root.
  **Fix**: either change `mock.rs:22` to `use frame_system::DefaultConfig;`
  (preferred), or add `pub use frame_system;` at the top of `lib.rs`.
- **`MockBlock` in mock.rs:32**: bare reference, comes from `frame_system::mocking::*`
  via testing_prelude. Rewrite imports `frame_system::mocking::MockBlock` directly.
- **Two weights files** (`weights.rs` and `default_weights.rs`) both need
  the same template rewrite — easy to miss one.
- **`benchmarks_instance_pallet`**: this is a v1 macro (instance-aware).
  Confirm `frame_benchmarking::v1::benchmarks_instance_pallet` is exported.
  Per `substrate/frame/benchmarking/src/v1.rs:1969-1970`, it is.
- The mmr `tests.rs` uses `frame_system::Pallet::<Test>::block_number()` etc.
  many times — already explicit.

---

## 7. `pallet-paged-list`

### 7.1 Test file inventory

| File:line                       | Path / use                                                                  |
|----------------------------------|-----------------------------------------------------------------------------|
| `src/mock.rs:23`                 | `use frame::testing_prelude::*;`                                              |
| `src/mock.rs:25`                 | `frame_system::mocking::MockBlock<Test>`                                      |
| `src/mock.rs:28`                 | `construct_runtime!`                                                          |
| `src/mock.rs:36`                 | `#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]`            |
| `src/mock.rs:40`                 | `type Lookup = IdentityLookup<Self::AccountId>;`                              |
| `src/mock.rs:45`                 | `parameter_types!`                                                            |
| `src/mock.rs:64`                 | `pub fn new_test_ext() -> TestState`                                          |
| `src/mock.rs:65`                 | `frame_system::GenesisConfig::<Test>::default().build_storage().unwrap()`     |
| `src/tests.rs:24-27`             | `use frame::{prelude::storage::{StorageAppender, StoragePrefixedContainer}, testing_prelude::*};` |
| `src/tests.rs:32, 42, 52, etc.`  | `test_closure(|| { PagedList::* })` (no assertion macros — uses `assert_eq!`/`assert!`/`assert_ne!`) |

Identifiers used from `frame::testing_prelude::*` in mock.rs: `construct_runtime`,
`derive_impl`, `parameter_types`, `MockBlock`, `IdentityLookup`, `TestState`,
`BuildStorage`. `crate::Instance2` is from the pallet's own `pub use`.

Identifiers used from `frame::testing_prelude::*` in tests.rs: `Vec`, plus
`StorageAppender` and `StoragePrefixedContainer` (explicit from `prelude::storage::*`).
**No assertion macros from frame_support are used** — only built-in `assert_eq!`,
`assert!`, `assert_ne!`.

### 7.2 Cargo feature gaps

- `codec = { features = ["derive"], workspace = true }` — already explicit.
- `scale-info = { features = ["derive"], workspace = true }` — already explicit.
- No `benchmarking.rs` — no `frame-benchmarking` dep needed (the
  `runtime-benchmarks` feature today expands only to `frame/runtime-benchmarks`,
  which becomes `frame-support/runtime-benchmarks` + `frame-system/runtime-benchmarks`).
- Need `sp-runtime` in `[dependencies]` for `IdentityLookup`, `BuildStorage`
  in mock.rs.
- Need `sp-io` (already in 04 prep).

### 7.3 Implicit identifier scan (production code)

Production source: `src/lib.rs`, `src/paged_list.rs`. Greps for the candidate
set returned only `StorageList`, `StorageAppender`, `StoragePrefixedContainer`,
`StorageInstance` — all already explicit in the existing `use` blocks. The
04 prep doc covers them correctly (rewrite to `frame_support::storage::*` and
`frame_support::traits::StorageInstance`).

No additional implicit identifiers found. (The pallet does NOT use
`blake2_256`, `One`, `TrailingZeroInput`, or any hashing primitives — it's a
pure storage-layer pallet.)

### 7.4 Proposed `Cargo.toml`

```toml
[dependencies]
codec = { features = ["derive"], workspace = true }
docify = { workspace = true }
# REMOVE: frame = { workspace = true, features = ["runtime"] }
# ADD:
frame-support = { workspace = true }
frame-system = { workspace = true }
scale-info = { features = ["derive"], workspace = true }
sp-io = { workspace = true }
sp-metadata-ir = { optional = true, workspace = true }
sp-runtime = { workspace = true }

[features]
default = ["std"]

std = [
    "codec/std",
    "frame-support/std",
    "frame-system/std",
    "scale-info/std",
    "sp-io/std",
    "sp-metadata-ir/std",
    "sp-runtime/std",
]

runtime-benchmarks = [
    "frame-support/runtime-benchmarks",
    "frame-system/runtime-benchmarks",
    "sp-runtime/runtime-benchmarks",
]

try-runtime = [
    "frame-support/try-runtime",
    "frame-system/try-runtime",
    "sp-runtime/try-runtime",
]

frame-metadata = ["sp-metadata-ir"]
```

### 7.5 Proposed test-file rewrites

```rust
// src/mock.rs:23
// BEFORE: use frame::testing_prelude::*;
// AFTER:
use frame_support::{construct_runtime, derive_impl, parameter_types};
use frame_system::mocking::MockBlock;
use sp_io::TestExternalities as TestState;
use sp_runtime::{traits::IdentityLookup, BuildStorage};
```

```rust
// src/tests.rs:24-27
// BEFORE
use frame::{
    prelude::storage::{StorageAppender, StoragePrefixedContainer},
    testing_prelude::*,
};
// AFTER
use frame_support::storage::{StorageAppender, StoragePrefixedContainer};
// (no assertion macros are used; `Vec` comes via `crate::*`/`alloc`.)
```

### 7.6 Risk notes

- The `runtime::prelude::storage` path in `paged_list.rs:32` is the
  most umbrella-specific path in this batch. Rewrite to
  `frame_support::storage::{StorageAppender, StorageList, StoragePrefixedContainer}`
  per 04 prep §11.4. Confirm by reading
  `substrate/frame/support/src/storage/mod.rs` once before the mass edit
  (the 04 prep's risk note already calls this out).
- The `prelude::storage::*` segment in `tests.rs:24` is the same path —
  resolves identically.
- **No benchmarking file** ⇒ no `frame-benchmarking` dep. The
  `runtime-benchmarks` feature still exists in Cargo.toml because the macro
  expansions of `#[pallet::*]` produce `#[cfg(feature = "runtime-benchmarks")]`
  branches that the runtime hosting the pallet may want to gate. Keep the
  feature, just point at `frame-support`/`frame-system`/`sp-runtime`.
- `crate::Instance2` is auto-generated by the `#[pallet::pallet]` macro in
  this instance-aware pallet. No changes needed for that.

---

## Cross-cutting checklist for this batch

When applying rewrites pallet-by-pallet, run through this once per pallet:

1. [ ] Remove `frame = ...` from `[dependencies]`.
2. [ ] Remove `frame = ...` from `[dev-dependencies]` if present (none of this
   batch's 7 pallets has `frame` in `[dev-dependencies]`, but verify before
   PR).
3. [ ] Add `codec = { features = ["derive"], ... }` if currently missing
   (multisig, mmr).
4. [ ] Add `frame-benchmarking = { optional = true, workspace = true }` if
   pallet has `benchmarking.rs` (proxy, multisig, safe-mode, mmr).
5. [ ] Add `sp-arithmetic` if pallet uses `One::one()` (mmr lib.rs;
   safe-mode benchmarking.rs).
6. [ ] Add `sp-core`/`sp-io`/`sp-runtime` per the per-pallet table.
7. [ ] Update `[features].std` / `runtime-benchmarks` / `try-runtime` lists
   per the per-pallet Cargo.toml block.
8. [ ] Replace `#[frame::pallet]` → `#[frame_support::pallet]` (and
   `#[frame::storage_alias]` → `#[storage_alias]` in multisig migrations.rs).
9. [ ] Replace every `frame::*` `use` per the per-pallet rewrite tables.
10. [ ] Add `use sp_io::hashing::blake2_256;` to lib.rs of proxy and multisig
    (the 04 prep doc's gap).
11. [ ] Add `use sp_arithmetic::traits::One;` (or via `sp_runtime::traits::One`)
    where needed.
12. [ ] Verify the test/mock file's deprecated `TestExternalities` alias
    references (safe-mode mock.rs uses it directly — fix to
    `sp_io::TestExternalities`).
13. [ ] `cargo check -p pallet-<name> --no-default-features` and again with
    each combination of `runtime-benchmarks`/`try-runtime` enabled.
14. [ ] `cargo test -p pallet-<name>` — confirms the test-file rewrites
    compile.
