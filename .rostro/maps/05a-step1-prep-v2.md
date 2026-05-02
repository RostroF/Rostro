# Step 1 Prep v2 (batch A): test-side + Cargo gaps for 8 pallets

Companion to `04-step1-prep.md`. The original prep doc covered the production
source rewrites for 17 pallets, but a proof-of-concept conversion of
`pallet-atomic-swap` revealed four gap classes that must be specified per
pallet before a mass conversion can succeed:

1. `[dependencies].codec` (and occasionally `scale-info`) needs an explicit
   `features = ["derive"]` once the umbrella's transitive derive feature
   propagation is removed.
2. Some pallet production source files use names that are not in their explicit
   `use` block but are reachable via `frame::prelude::*` (e.g. `blake2_256`,
   `H256`). They need explicit imports added.
3. `frame = ...` must come out of `[dev-dependencies]` too, because the
   `#[pallet]` proc-macro detects an in-tree `frame` crate via
   `proc_macro_crate::crate_name` regardless of which dep section it sits in.
4. `[features]` blocks must drop every `frame/<flag>` line and replace with the
   per-crate equivalents.

This document fills those gaps for 8 of the remaining 15 pallets (the other 7
are owned by a parallel agent). Pallets `pallet-migrations` and
`pallet-atomic-swap` are already converted and out of scope.

## Overview

### Total work in this batch

- 8 pallets, 16 test/mock files (`mock.rs`, `tests.rs`, `tests/integration.rs`,
  `tests/unit.rs`) plus 8 `benchmarking.rs` files (still to be tackled in the
  benchmarking pass — listed for completeness, not rewritten here in detail
  except for the test-flow surface they expose).
- All 8 pallets have a `frame = { workspace = true, features = ["runtime"] }`
  line in `[dependencies]`. None of the 8 has an additional `frame = ...` line
  in `[dev-dependencies]` — the `frame` already covers the dev side (because
  `default-features = ["std"]` makes `testing_prelude` reachable). When `frame`
  is removed, the test surface needs explicit dev-deps for `frame-support`
  (already present transitively but must be made direct), `frame-system`,
  `sp-io`, and frequently `sp-runtime`. One pallet (`pallet-nis`) already has
  `sp-io` in `[dev-dependencies]`; the rest need it added.

### Cross-batch patterns

- **Codec derive feature**: 4 of 8 pallets (assets-freezer, nft-fractionalization,
  recovery, tx-pause via dev-deps) currently have `codec = { workspace = true }`
  without the `derive` feature, OR have it but rely on the umbrella for
  `max-encoded-len`. Confirmed during atomic-swap conversion that explicit
  `derive` is necessary because `pallet_prelude::*` does not re-export the
  codec derive macros — it re-exports the runtime types only. (insecure-randomness,
  recovery, salary, nis, tx-pause, whitelist already declare `features = ["derive"]`.)
- **`scale-info`**: every pallet in scope already has
  `scale-info = { features = ["derive"], workspace = true }`. No change needed
  — but flag for human review if the proc-macro emit gets unhappy after
  conversion.
- **`testing_prelude` re-export rewrite**: most test files only really use
  6–10 names (`construct_runtime`, `derive_impl`, `parameter_types`,
  `MockBlock`, `TestExternalities`/`TestState`, `BuildStorage`, `BadOrigin`,
  `assert_ok`, `assert_noop`, `assert_err`). Replacing `use frame::testing_prelude::*;`
  with an explicit block of those 6–10 names plus `frame_system::pallet_prelude::*`
  works in ≥7 of the 8 pallets. The exception is `pallet-nis`, whose mock uses
  `frame::runtime::prelude::*` (`#[frame_construct_runtime]`, `EnsureSigned`,
  `ConstU64`, `ConstU32`, `ConstU128`, `PalletId`, `Weight`, `Perquintill`,
  `ord_parameter_types`) and is much wider.
- **`Dispatchable`**: `tx-pause`'s tests call `.dispatch(...)` on `RuntimeCall`,
  so `sp_runtime::traits::Dispatchable` must end up in scope (it currently
  arrives via `frame::testing_prelude::*` -> `frame::prelude::*`).
- **Implicit identifier scan summary**: production-code grep for the candidate
  list (blake2_256, keccak_256, twox_*, H160/H256/U256, BlakeTwo256, Keccak256,
  BoundToRuntimeAppPublic, ExtensionVersion, impl_tx_ext_default, Defensive,
  DefensiveSaturating, PalletId, OneSessionHandler, EstimateNextSessionRotation)
  was clean for 6 of 8 pallets. The two hits are:
  - `pallet-nft-fractionalization` and `pallet-nis` use `PalletId` (the type)
    in their `Config` trait. `PalletId` comes from
    `frame_support::PalletId`, exposed via `frame::prelude::*`. The original
    prep doc covers this for `pallet-nis` but not for `pallet-nft-fractionalization`
    — gap closed below.
  - `pallet-nis` lib.rs additionally relies on `Defensive`, `DefensiveSaturating`,
    `Saturating`, `TypedGet`, `Unsigned`, `RationalArg`, `Convert`,
    `ConvertBack`, `Perquintill` — all transitively from `frame::prelude::*`.
    The 04-prep already proposed the `sp-arithmetic`, `sp-runtime` imports for
    nis; the only new addition here is the explicit `Defensive` trait import
    (currently invisible).
- **No `blake2_256`, `keccak_256`, `twox_*`, `H160`, `H256` (in production
  source), `U256`, `BlakeTwo256`, `Keccak256`, `BoundToRuntimeAppPublic`,
  `ExtensionVersion`, `impl_tx_ext_default`, `OneSessionHandler`,
  `EstimateNextSessionRotation` were found** in any of the 8 pallets'
  production source. (Several of these do appear in mock.rs files — those are
  test-side, addressed in §N.5 per pallet.)

### One-line difficulty summary (test-side only)

| # | Pallet                              | Test rewrite difficulty | Why |
|---|-------------------------------------|-------------------------|-----|
| 1 | insecure-randomness-collective-flip | trivial                 | lib-internal `mod tests`; ~6 names |
| 2 | recovery                            | easy                    | mock + tests, ~10 names plus `bounded_vec!` |
| 3 | salary                              | medium                  | 2 test files + integration uses `hypothetically!`, `StateVersion`, `sp_io::storage::root` |
| 4 | tx-pause                            | medium                  | mock uses `InsideBoth`, `BlakeTwo256`, `InstanceFilter`, `Contains`, `EnsureSignedBy`, `ConstU32/64`, `ord_parameter_types`, `DecodeWithMemTracking`; tests call `.dispatch()` |
| 5 | whitelist                           | easy                    | small mock, tests use `DispatchError::BadOrigin` and `EnsureRoot` |
| 6 | assets-freezer                      | medium                  | mock spells out a full `frame_system::Config` impl (no `derive_impl`) and uses `H256`, `BlakeTwo256`, `IdentityLookup`, `AsEnsureOriginWithArg`, `VariantCount`, `DecodeWithMemTracking` |
| 7 | nft-fractionalization               | medium                  | mock uses `MultiSignature`, `Verify`, `IdentifyAccount`, `IdentityLookup`, `AsEnsureOriginWithArg`, `EnsureSigned`, `PalletId`, `BoundedVec`; tests reuse `fungible::*`/`fungibles::*` from glob |
| 8 | nis                                 | hard                    | mock uses `#[frame_construct_runtime]`, `StorageMapShim`, `Perquintill`, `Weight`, `PalletId`, `ConstU128`, `ord_parameter_types`; tests use `WeightCounter`, `AllPalletsWithSystem`, `TokenError`, `InspectHold`, `Perquintill::from_rational` |

### Pallets where the test rewrite is more than a 5-line `use` block change

- `pallet-tx-pause` — mock has eight identifiers from `testing_prelude` that
  branch into `frame_support::traits::*`, `sp_runtime::traits::*`, and the
  `runtime::prelude::*` constants (`ConstU32`, `ConstU64`).
- `pallet-assets-freezer` — mock predates `derive_impl` for `frame_system` and
  spells the whole config trait out by hand; that pulls eleven names.
- `pallet-nft-fractionalization` — mock pulls `MultiSignature`, `Verify`,
  `IdentifyAccount`, `IdentityLookup`, `AsEnsureOriginWithArg`, `EnsureSigned`,
  `PalletId`, `BoundedVec` plus the bare `fungible::*` glob in tests.
- `pallet-nis` — mock uses the *new* `#[frame_construct_runtime]` macro and
  `StorageMapShim`; tests reach for `WeightCounter` and `AllPalletsWithSystem`.

### Surprises vs. 04-prep

- **Original prep got `pallet-assets-freezer`'s `use frame::prelude::storage::StorageDoubleMap` right** — `frame::prelude::storage` is just `frame_support::pallet_prelude::*::storage`, and `frame_support::storage::StorageDoubleMap` is the right rewrite. Confirmed by reading `frame_support::storage` and finding the trait. No surprise.
- **`pallet-nis` mock uses `#[frame_construct_runtime]`** which is the newer
  `frame_support::runtime` proc-macro — original prep doc never mentioned this
  alternative form. We need to map `#[frame_construct_runtime]` →
  `#[frame_support::runtime]` (NOT `#[frame_support::construct_runtime]` —
  these are two different macros).
- **`pallet-tx-pause` test code uses `.dispatch()`** on a `RuntimeCall` value,
  which requires `sp_runtime::traits::Dispatchable` in scope. The umbrella's
  `prelude::*` re-export carried it transparently. Original prep doc didn't
  flag this for the test rewrite.
- **`pallet-nft-fractionalization` tests reuse `fungible::{...}` and
  `fungibles::{...}` short paths** that come from
  `frame_support::traits::tokens::*` via the umbrella prelude. The 04-prep
  shows the rewrite for the `pallet` inner mod's `use fungible::{...};` lines
  in `lib.rs` but NOT for `tests.rs` line 23 which has the same pattern. New
  in this doc.
- **`pallet-nis` mock uses `BoundedVec` indirectly** via genesis configuration
  — fine, just lift along with the rest of the prelude.

---

## 1. `pallet-insecure-randomness-collective-flip`

### 1.1 Test file inventory

This pallet has its tests as a `#[cfg(test)] mod tests` inside `src/lib.rs`
(no separate `mock.rs` / `tests.rs` / `benchmarking.rs`).

| File:line                              | Path used                                                                  |
|----------------------------------------|----------------------------------------------------------------------------|
| `src/lib.rs:165-168` (mod tests)       | `use frame::{ testing_prelude::{frame_system::limits, *}, traits::Header as _, };` |
| `src/lib.rs:172` (mod tests)           | `construct_runtime!(...)` (from prelude)                                  |
| `src/lib.rs:186` (mod tests)           | `#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]`        |
| `src/lib.rs:170,175,193,194` (mod tests)| `frame_system::mocking::MockBlock`, `frame_system::GenesisConfig`, `TestExternalities` |
| `src/lib.rs:181` (mod tests)           | `parameter_types! { pub BlockLength: limits::BlockLength = ... }`         |
| `src/lib.rs:275` (mod tests)           | `H256::zero()` — `H256` is from `sp_core::H256`, comes via prelude        |

Identifiers actually used from `testing_prelude::*` in the test mod:
`construct_runtime!`, `derive_impl`, `parameter_types`, `TestExternalities`,
`H256` (re-exported from `sp_core::H256` via `frame::prelude::hashing::*`),
`BuildStorage` (used implicitly via `.build_storage()`).

### 1.2 Cargo feature gaps

Current `[dependencies]`:

```toml
codec = { features = ["derive"], workspace = true }
frame = { workspace = true, features = ["runtime"] }
safe-mix = { workspace = true }
scale-info = { features = ["derive"], workspace = true }
```

`codec`/`scale-info` already correctly feature-flagged. No `[dev-dependencies]`
section currently. After removing `frame`, the `#[cfg(test)] mod tests` block
needs `frame-support`, `frame-system`, `sp-core` (for `H256`), `sp-io` (for
`TestExternalities`, `BuildStorage` via `sp-runtime`), `sp-runtime` (for
`BadOrigin`/`Header`/`BuildStorage`).

### 1.3 Implicit identifier scan (production code, `src/lib.rs:1-160`)

Production code (above `#[cfg(test)] mod tests`):

- `BlockNumberFor`, `Hooks`, `Weight`, `BoundedVec`, `ConstU32`, `StorageValue`,
  `ValueQuery`, `Encode` — all in `frame_support::pallet_prelude::*`.
- `Randomness` — `frame_support::traits::Randomness`. Already explicit in
  `use frame::{prelude::*, traits::Randomness};`.
- `T::Hash` — associated type, no extra import needed.
- `block_number.saturating_sub(...)` (line 157) — needs
  `sp_runtime::traits::Saturating` in scope. The 04-prep notes this implicitly
  via `pallet_prelude::*` carrying nothing relevant; in fact the umbrella's
  `prelude::*` includes `sp_runtime::traits::Saturating` directly. **Action:**
  add `use sp_runtime::traits::Saturating;` as a top-level import in `lib.rs`,
  alongside the 04-prep's existing `frame_support` and `frame_system` imports.

No `blake2_256` / `H256` / etc. found in production lines (the `H256` on line
275 is inside `mod tests`).

### 1.4 Proposed `Cargo.toml`

```toml
[dependencies]
codec = { features = ["derive"], workspace = true }
frame-support = { workspace = true }
frame-system = { workspace = true }
safe-mix = { workspace = true }
scale-info = { features = ["derive"], workspace = true }
sp-runtime = { workspace = true }                    # for `Saturating`

[dev-dependencies]
sp-core = { workspace = true, default-features = true }      # for H256 in tests
sp-io = { workspace = true, default-features = true }        # for TestExternalities

[features]
default = ["std"]
std = [
    "codec/std",
    "frame-support/std",
    "frame-system/std",
    "safe-mix/std",
    "scale-info/std",
    "sp-runtime/std",
]
try-runtime = [
    "frame-support/try-runtime",
    "frame-system/try-runtime",
    "sp-runtime/try-runtime",
]
```

REMOVE:
- `frame = { workspace = true, features = ["runtime"] }`
- `frame/std`, `frame/try-runtime` lines.

ADD:
- `frame-support`, `frame-system`, `sp-runtime` to `[dependencies]`.
- `sp-core`, `sp-io` to `[dev-dependencies]`.
- per-crate `*/std` and `*/try-runtime` lines.

### 1.5 Proposed test-file rewrites

`src/lib.rs:165-168`:

```rust
// BEFORE
use frame::{
    testing_prelude::{frame_system::limits, *},
    traits::Header as _,
};

// AFTER
use frame_support::{
    assert_ok, assert_noop, construct_runtime, derive_impl, parameter_types,
    traits::Everything,
};
use frame_system::{
    self, limits, mocking::MockBlock,
};
use sp_core::H256;
use sp_io::TestExternalities;
use sp_runtime::{traits::Header as _, BuildStorage};
```

(Trim `assert_noop`/`Everything` if not used — grep confirms `H256`,
`construct_runtime`, `derive_impl`, `parameter_types`, `TestExternalities`,
`BuildStorage` are used, plus `Header` for `header.number()`.)

### 1.6 Risk notes

- The `testing_prelude::frame_system::limits` qualified path tells us
  `BlockLength` lives under `frame_system::limits` — works the same way after
  rewrite if you just `use frame_system::limits;`.
- Verify `H256::zero()` comes from `sp_core::H256` (yes,
  `sp_core::H256::zero()` exists).
- Tests live inside `lib.rs`, so the `frame` proc-macro detection still applies
  to lib's compile (production code already has `#[frame::pallet]`); replacing
  the production-code `frame` macro alongside the test-side fix is mandatory.

---

## 2. `pallet-recovery`

### 2.1 Test file inventory

| File:line                          | Path used                                                                                  |
|------------------------------------|--------------------------------------------------------------------------------------------|
| `src/mock.rs:23`                   | `use frame::{deps::sp_io, testing_prelude::*};`                                            |
| `src/mock.rs:25`                   | `frame_system::mocking::MockBlock`                                                         |
| `src/mock.rs:27, 36, 42, 46, 53, 76, 84` | `construct_runtime!`, `#[derive_impl]`, `parameter_types!`, `sp_io::TestExternalities` |
| `src/tests.rs:21`                  | `use frame::{deps::sp_runtime::bounded_vec, testing_prelude::*};`                          |
| `src/tests.rs:39, 41, 47, 50, ... (104 lines)` | `assert_ok!`, `assert_noop!`, `BadOrigin`                                       |
| `src/tests.rs:361`                 | `bounded_vec![2, 3, 4]`                                                                    |
| `src/benchmarking.rs:24`           | `use frame::benchmarking::prelude::*;` (deferred to benchmarking pass)                     |
| `src/weights.rs:69`                | `use frame::weights_prelude::*;` (covered by 04-prep §13)                                  |
| `src/lib.rs:157, 228`              | (covered by 04-prep §13)                                                                   |

Identifiers actually used from `testing_prelude::*`: `construct_runtime`,
`derive_impl`, `parameter_types`, `assert_ok`, `assert_noop`, `BadOrigin`.
`TestExternalities` is referenced via the explicit `sp_io::TestExternalities`
type-path on `mock.rs:76`/`84` (not via the prelude alias).

### 2.2 Cargo feature gaps

Current `[dependencies]`:

```toml
codec = { features = ["derive"], workspace = true }
frame = { workspace = true, features = ["runtime"] }
scale-info = { features = ["derive"], workspace = true }
```

`codec` already has `derive` — no change.

After conversion, `[dev-dependencies]` (currently just `pallet-balances`)
needs `sp-io`, `sp-runtime` because `mock.rs` uses `sp_io::TestExternalities`
and `tests.rs` uses `bounded_vec!` (a re-export of
`sp_runtime::bounded_vec!`) plus `BadOrigin`.

### 2.3 Implicit identifier scan (production code: `src/lib.rs`, `src/weights.rs`)

Grep for the candidate list returned:

- No `blake2_256`, `H256`, `BlakeTwo256` etc.
- `defensive!` macro usage at `src/lib.rs:832, 876` — comes from
  `frame_support::defensive` macro, re-exported in `frame_support::pallet_prelude::*`?
  No, `defensive!` is in `frame_support::traits::*` glob via the umbrella's
  direct `pub use frame_support::defensive` (line 191 of `substrate/frame/src/lib.rs`).
  After the rewrite, ensure `frame_support::defensive` is reachable — the
  04-prep's proposed `use frame_support::pallet_prelude::*;` does NOT include
  it. **Action:** add `use frame_support::defensive;` (or
  `frame_support::traits::Defensive;`) explicitly in `lib.rs`. The
  `defensive!` macro is at the top level of `frame_support`, importable as
  `use frame_support::defensive;`.
- `saturating_sub` / `saturating_add` (lines 424, 826, 829, 870, 873) — come
  from `sp_runtime::traits::Saturating`. The 04-prep's proposed
  `use sp_runtime::traits::{BlockNumberProvider, StaticLookup};` should also
  include `Saturating`.

### 2.4 Proposed `Cargo.toml`

```toml
[dependencies]
codec = { features = ["derive"], workspace = true }
frame-support = { workspace = true }
frame-system = { workspace = true }
scale-info = { features = ["derive"], workspace = true }
sp-runtime = { workspace = true }

[dev-dependencies]
pallet-balances = { default-features = true, workspace = true }
sp-io = { workspace = true, default-features = true }       # for TestExternalities

[features]
default = ["std"]
runtime-benchmarks = [
    "frame-benchmarking/runtime-benchmarks",
    "frame-support/runtime-benchmarks",
    "frame-system/runtime-benchmarks",
    "pallet-balances/runtime-benchmarks",
    "sp-runtime/runtime-benchmarks",
]
std = [
    "codec/std",
    "frame-support/std",
    "frame-system/std",
    "scale-info/std",
    "sp-runtime/std",
]
try-runtime = [
    "frame-support/try-runtime",
    "frame-system/try-runtime",
    "pallet-balances/try-runtime",
    "sp-runtime/try-runtime",
]
```

(Note: `frame-benchmarking` will need to be added as `optional` once the
benchmarking pass runs.)

### 2.5 Proposed test-file rewrites

`src/mock.rs:23`:

```rust
// BEFORE
use frame::{deps::sp_io, testing_prelude::*};

// AFTER
use frame_support::{construct_runtime, derive_impl, parameter_types};
use frame_system::pallet_prelude::*;
use sp_io;
use sp_runtime::BuildStorage;
```

(Drop `pallet_prelude::*` if `mock.rs` doesn't use names from it; grep shows
no usage of `BoundedVec`/`MaxEncodedLen`/etc., so the
`use frame_system::pallet_prelude::*;` can be omitted. Keep
`frame_support::pallet_prelude::*` only if needed.)

`src/tests.rs:21`:

```rust
// BEFORE
use frame::{deps::sp_runtime::bounded_vec, testing_prelude::*};

// AFTER
use frame_support::{assert_ok, assert_noop};
use sp_runtime::{bounded_vec, traits::BadOrigin};
```

`src/lib.rs` rewrite — see 04-prep §13.4, plus add:

```rust
use frame_support::defensive;
use sp_runtime::traits::{BlockNumberProvider, Saturating, StaticLookup};
```

### 2.6 Risk notes

- `bounded_vec!` is a macro in `sp_runtime::bounded::bounded_vec`; the umbrella
  reaches it as `sp_runtime::bounded_vec`. Confirm import path with
  `cargo doc -p sp-runtime --no-deps`.
- `BadOrigin` is in `sp_runtime::traits::BadOrigin` — confirmed.
- `defensive!` macro: `frame_support::defensive` works as a glob `use`;
  `frame_support::defensive!` works as a macro_rules! invocation. Use the
  former.

---

## 3. `pallet-salary`

### 3.1 Test file inventory

| File:line                                   | Path used                                                                                          |
|---------------------------------------------|----------------------------------------------------------------------------------------------------|
| `src/tests/mod.rs:22-23`                    | (re-exports `integration` and `unit`; no `frame::*`)                                               |
| `src/tests/integration.rs:22`               | `use frame::{deps::sp_io, testing_prelude::*};`                                                    |
| `src/tests/integration.rs:26`               | `frame_system::mocking::MockBlock`                                                                 |
| `src/tests/integration.rs:28, 36, 41, 46, 79, 84, 137, 138, 178, 186, 189, 199` | `construct_runtime!`, `parameter_types!`, `derive_impl`, `EitherOf`, `MapSuccess`, `ReduceBy`, `ReplaceWithDefault`, `NoOpPoll`, `BlockNumberFor`, `TestState`, `hypothetically!`, `sp_io::storage::root`, `StateVersion` |
| `src/tests/unit.rs:23`                      | `use frame::{deps::sp_runtime::traits::Identity, testing_prelude::*, traits::tokens::ConvertRank};` |
| `src/tests/unit.rs:26, 28, 36, 41, 46, 98, 145, 146, 151, 153, 169` | `MockBlock`, `construct_runtime!`, `parameter_types!`, `Weight`, `derive_impl`, `RankedMembers`, `ConvertRank`, `Identity`, `ConstU64`, `TestState`, `assert_ok!`, `assert_noop!` |
| `src/benchmarking.rs:25`                    | `use frame::benchmarking::prelude::*;` (deferred)                                                  |
| `src/weights.rs:70`                         | `use frame::weights_prelude::*;` (covered by 04-prep §15)                                          |
| `src/lib.rs:23, 78`                         | (covered by 04-prep §15)                                                                           |

Identifiers actually used from `testing_prelude::*` in the test files:
`construct_runtime`, `derive_impl`, `parameter_types`, `assert_ok!`,
`assert_noop!`, `Weight`, `MockBlock` (re-exported from
`frame_system::mocking`), `TestState` (alias of `sp_io::TestExternalities`),
`hypothetically!`, `StateVersion`, plus the runtime-prelude bits `EitherOf`,
`MapSuccess`, `ReduceBy`, `ReplaceWithDefault`, `NoOpPoll`, `ConstU16`,
`ConstU64`, `BlockNumberFor`, `PhantomData`, `Get`, `Convert`,
`DispatchResult`, `DispatchError`, `RankedMembers`.

### 3.2 Cargo feature gaps

Current `[dependencies]`:

```toml
codec = { features = ["derive"], workspace = true }
frame = { workspace = true, features = ["runtime"] }
log = { workspace = true }
pallet-ranked-collective = { optional = true, workspace = true }
scale-info = { features = ["derive"], workspace = true }
```

`codec`/`scale-info` already feature-flagged. `[dev-dependencies]` is empty
today; `pallet-ranked-collective` is currently `optional`. After conversion,
the integration test uses `pallet-ranked-collective` always, so it must be a
dev-dep. (Likely it's already pulled when the `runtime-benchmarks` or `std`
features are on; this needs to be made explicit.)

### 3.3 Implicit identifier scan (production code: `src/lib.rs`, `src/weights.rs`)

- `defensive!` macro usage at `src/lib.rs:452, 456, 461` — see §2.3 note.
  **Action:** add `use frame_support::defensive;` to lib.rs.
- `saturating_accrue`, `saturating_inc`, `saturating_reduce`,
  `saturating_sub` — all from `sp_runtime::Saturating` (already covered by
  the 04-prep's `use sp_runtime::traits::Convert;` — extend to include
  `Saturating`).
- No `blake2_256`, `H256`, `PalletId` etc.

### 3.4 Proposed `Cargo.toml`

```toml
[dependencies]
codec = { features = ["derive"], workspace = true }
frame-support = { workspace = true }
frame-system = { workspace = true }
log = { workspace = true }
pallet-ranked-collective = { optional = true, workspace = true }
scale-info = { features = ["derive"], workspace = true }
sp-runtime = { workspace = true }

[dev-dependencies]
pallet-ranked-collective = { default-features = true, workspace = true }
sp-io = { workspace = true, default-features = true }     # for TestExternalities + storage::root

[features]
default = ["std"]
std = [
    "codec/std",
    "frame-support/std",
    "frame-system/std",
    "log/std",
    "pallet-ranked-collective?/std",
    "scale-info/std",
    "sp-runtime/std",
]
runtime-benchmarks = [
    "frame-support/runtime-benchmarks",
    "frame-system/runtime-benchmarks",
    "pallet-ranked-collective/runtime-benchmarks",
    "sp-runtime/runtime-benchmarks",
]
try-runtime = [
    "frame-support/try-runtime",
    "frame-system/try-runtime",
    "pallet-ranked-collective?/try-runtime",
    "sp-runtime/try-runtime",
]
```

### 3.5 Proposed test-file rewrites

`src/tests/integration.rs:22`:

```rust
// BEFORE
use frame::{deps::sp_io, testing_prelude::*};

// AFTER
use frame_support::{
    assert_ok, assert_noop, construct_runtime, derive_impl, hypothetically, parameter_types,
    traits::{ConstU16, ConstU64, EitherOf, MapSuccess, NoOpPoll},
};
use frame_system::{mocking::MockBlock, pallet_prelude::BlockNumberFor};
use sp_io;
use sp_io::TestExternalities as TestState;
use sp_runtime::{
    traits::{ReduceBy, ReplaceWithDefault},
    BuildStorage, StateVersion,
};
```

`src/tests/unit.rs:23`:

```rust
// BEFORE
use frame::{deps::sp_runtime::traits::Identity, testing_prelude::*, traits::tokens::ConvertRank};

// AFTER
use frame_support::{
    assert_ok, assert_noop, construct_runtime, derive_impl, parameter_types,
    traits::{ConstU64, RankedMembers, tokens::ConvertRank},
    weights::Weight,
};
use frame_system::{mocking::MockBlock, pallet_prelude::*};
use sp_io::TestExternalities as TestState;
use sp_runtime::{
    traits::{Identity, Convert},
    BuildStorage, DispatchError, DispatchResult,
};
```

(`DispatchError`, `DispatchResult` come from `sp_runtime` directly. `Convert`
needed because `MinRankOfClass` impls `Convert<u16, Rank>`.)

### 3.6 Risk notes

- `EitherOf`, `MapSuccess`, `NoOpPoll`, `ReduceBy`, `ReplaceWithDefault` are
  carefully named — `EitherOf`/`MapSuccess`/`NoOpPoll` live in
  `frame_support::traits`; `ReduceBy`/`ReplaceWithDefault` live in
  `sp_runtime::traits`. (`EitherOfDiverse` is the `frame_support` one, but
  there's a separate `EitherOf` — confirm.)
- `hypothetically!` is `frame_support::hypothetically` (a macro). Confirmed.
- `sp_io::storage::root(StateVersion::V1)` requires `sp_io` AND
  `sp_runtime::StateVersion` — both already in the explicit imports.
- `Geometric` and `EnsureRanked` come from `pallet-ranked-collective`, not
  from the umbrella, so untouched.
- `frame_system::EnsureRootWithSuccess` (line 110, 117, 124) is referenced via
  qualified path — already explicit, no rewrite needed.

---

## 4. `pallet-tx-pause`

### 4.1 Test file inventory

| File:line                          | Path used                                                                                                                                              |
|------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------|
| `src/mock.rs:24`                   | `use frame::testing_prelude::*;`                                                                                                                       |
| `src/mock.rs:26-100, 106-147, 149-186` | `derive_impl`, `InsideBoth`, `Everything`, `Encode`, `Decode`, `DecodeWithMemTracking`, `MaxEncodedLen`, `InstanceFilter`, `ConstU64`, `ConstU32`, `BlakeTwo256`, `parameter_types`, `ord_parameter_types`, `Contains`, `EnsureSignedBy`, `construct_runtime`, `MockBlock`, `TestExternalities` |
| `src/tests.rs:22`                  | `use frame::testing_prelude::*;`                                                                                                                       |
| `src/tests.rs:29-209`              | `assert_ok!`, `assert_err!`, `assert_noop!`, `.dispatch(...)` (needs `Dispatchable`), `Box::new`, `DispatchError`                                      |
| `src/benchmarking.rs:22`           | `use frame::benchmarking::prelude::*;` (deferred)                                                                                                      |
| `src/weights.rs:70`                | (covered by 04-prep §16)                                                                                                                               |
| `src/lib.rs:78, 96`                | (covered by 04-prep §16)                                                                                                                               |

Identifiers actually used from `testing_prelude::*`: `construct_runtime`,
`derive_impl`, `parameter_types`, `ord_parameter_types`, `assert_ok`,
`assert_err`, `assert_noop`, `Encode`, `Decode`, `DecodeWithMemTracking`,
`MaxEncodedLen`, `InsideBoth`, `Everything`, `InstanceFilter`, `Contains`,
`EnsureSignedBy`, `ConstU64`, `ConstU32`, `BlakeTwo256`, `MockBlock`,
`TestExternalities`, `Dispatchable` (implicitly via `.dispatch()`).
`Box` is in `core::prelude` already; the prelude `pub use alloc::boxed::Box`
just makes it explicit.

### 4.2 Cargo feature gaps

Current `[dependencies]`:

```toml
codec = { features = ["derive"], workspace = true }
docify = { workspace = true }
frame = { workspace = true, features = ["runtime"] }
scale-info = { features = ["derive"], workspace = true }
```

After conversion, the mock pulls in `BlakeTwo256` (from `sp_runtime::traits`)
and uses `DecodeWithMemTracking`. Existing `[dev-dependencies]`:

```toml
pallet-balances = { default-features = true, workspace = true }
pallet-proxy = { default-features = true, workspace = true }
pallet-utility = { default-features = true, workspace = true }
```

Add `sp-io`, `sp-runtime` to `[dev-dependencies]`.

### 4.3 Implicit identifier scan (production code: `src/lib.rs`, `src/weights.rs`)

Production `lib.rs` uses `Dispatchable`, `GetDispatchInfo`, `IsSubType`,
`Contains`, `GetCallMetadata`, `CallMetadata`, `EnsureOrigin`, `Get`,
`Parameter`, `Blake2_128Concat`, `BoundedVec`, `Vec`, `OptionQuery`,
`StorageMap`, `Hooks`, `BlockNumberFor`, `IsType`, `DispatchResult`,
`OriginFor`, `PhantomData`, `DefaultNoBound`, `Weight`, `MaxEncodedLen` —
all in `frame_support::pallet_prelude::*` or top-level `frame_support`/
`frame_system::pallet_prelude::*`. The 04-prep §16 mostly covers this.

No `blake2_256`/`H256`/etc. in `lib.rs`.

`saturating_*`: not used in production source.

### 4.4 Proposed `Cargo.toml`

```toml
[dependencies]
codec = { features = ["derive"], workspace = true }
docify = { workspace = true }
frame-support = { workspace = true }
frame-system = { workspace = true }
scale-info = { features = ["derive"], workspace = true }
sp-runtime = { workspace = true }

[dev-dependencies]
pallet-balances = { default-features = true, workspace = true }
pallet-proxy = { default-features = true, workspace = true }
pallet-utility = { default-features = true, workspace = true }
sp-io = { workspace = true, default-features = true }

[features]
default = ["std"]
std = [
    "codec/std",
    "frame-support/std",
    "frame-system/std",
    "scale-info/std",
    "sp-runtime/std",
]
runtime-benchmarks = [
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
    "pallet-balances/try-runtime",
    "pallet-proxy/try-runtime",
    "pallet-utility/try-runtime",
    "sp-runtime/try-runtime",
]
```

### 4.5 Proposed test-file rewrites

`src/mock.rs:24`:

```rust
// BEFORE
use frame::testing_prelude::*;

// AFTER
use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use frame_support::{
    construct_runtime, derive_impl, ord_parameter_types, parameter_types,
    traits::{ConstU32, ConstU64, Contains, Everything, InsideBoth, InstanceFilter},
};
use frame_system::{mocking::MockBlock, EnsureSignedBy};
use sp_io::TestExternalities;
use sp_runtime::{traits::BlakeTwo256, BuildStorage};
```

`src/tests.rs:22`:

```rust
// BEFORE
use frame::testing_prelude::*;

// AFTER
use frame_support::{assert_err, assert_noop, assert_ok};
use sp_runtime::{traits::Dispatchable, DispatchError};
```

(`Box::new` is in `core::prelude` so no import needed; `Vec` likewise.
`DispatchError` is referenced at line 122.)

### 4.6 Risk notes

- The mock derives `DecodeWithMemTracking` for `ProxyType`; this trait is in
  the `codec` crate (specifically `parity_scale_codec::DecodeWithMemTracking`).
  The umbrella exposes it via `pallet_prelude::*`. After the rewrite, ensure
  `codec::DecodeWithMemTracking` is in scope explicitly (it is, via the
  `use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};` line).
- `Dispatchable` in `tests.rs` is the trait that gives the `.dispatch()`
  method. It's in `sp_runtime::traits::Dispatchable`. The umbrella's
  `prelude::*` re-exports it; after the rewrite,
  `use sp_runtime::traits::Dispatchable;` makes it explicit.
- `EnsureSignedBy` is `frame_system::EnsureSignedBy` (from
  `frame_system::offchain` re-export? — no, it's in `frame_system` directly,
  re-exported by the umbrella's `runtime::prelude::*`). Confirmed.

---

## 5. `pallet-whitelist`

### 5.1 Test file inventory

| File:line                          | Path used                                                                                  |
|------------------------------------|--------------------------------------------------------------------------------------------|
| `src/mock.rs:24`                   | `use frame::testing_prelude::*;`                                                           |
| `src/mock.rs:25, 27, 37, 43, 51, 59, 60, 65, 67` | `MockBlock`, `construct_runtime!`, `derive_impl`, `EnsureRoot`, `TestExternalities`, `RuntimeGenesisConfig` |
| `src/tests.rs:22-25`               | `use frame::{ testing_prelude::*, traits::{QueryPreimage, StorePreimage} };`               |
| `src/tests.rs:30, 32, 41, 55, 97`  | `assert_ok!`, `assert_noop!`, `<Hashing>::hash`, `DispatchError::BadOrigin`, `Encode`     |
| `src/benchmarking.rs:25`           | `use frame::benchmarking::prelude::*;` (deferred)                                          |
| `src/weights.rs:70`                | (covered by 04-prep §17)                                                                   |
| `src/lib.rs:47, 55, 171`           | (covered by 04-prep §17)                                                                   |

Identifiers actually used: `construct_runtime`, `derive_impl`,
`TestExternalities`, `EnsureRoot`, `RuntimeGenesisConfig` (auto-generated by
`construct_runtime!`), `MockBlock`, `assert_ok`, `assert_noop`, `Encode`
(direct from `codec`), `DispatchError` (`sp_runtime::DispatchError`),
`QueryPreimage`/`StorePreimage` (`frame_support::traits::*`).

### 5.2 Cargo feature gaps

Current `[dependencies]`:

```toml
codec = { features = ["derive", "max-encoded-len"], workspace = true }
frame = { workspace = true, features = ["runtime"] }
scale-info = { features = ["derive"], workspace = true }
```

`codec` already has both `derive` and `max-encoded-len` — no change. After
conversion, `[dev-dependencies]` (currently `pallet-balances`, `pallet-preimage`)
needs `sp-io`, `sp-runtime`.

### 5.3 Implicit identifier scan (production code: `src/lib.rs`, `src/weights.rs`)

- `MAX_EXTRINSIC_DEPTH` is in `frame_support` (top-level `pub const`),
  imported as `frame_support::MAX_EXTRINSIC_DEPTH` (covered by 04-prep §17).
- `decode_all_with_depth_limit` is from `codec::DecodeLimit` trait (already
  explicit in `use codec::{DecodeLimit, ...};`).
- `get_dispatch_info` from `frame_support::dispatch::GetDispatchInfo` (in
  prelude).
- `saturating_add` (line 182) — needs `sp_runtime::traits::Saturating`. Add
  alongside `DispatchInfoOf` in 04-prep's proposed `use sp_runtime::traits::*`.
- No `blake2_256`/`H256`/etc.

### 5.4 Proposed `Cargo.toml`

```toml
[dependencies]
codec = { features = ["derive", "max-encoded-len"], workspace = true }
frame-support = { workspace = true }
frame-system = { workspace = true }
scale-info = { features = ["derive"], workspace = true }
sp-runtime = { workspace = true }

[dev-dependencies]
pallet-balances = { default-features = true, workspace = true }
pallet-preimage = { default-features = true, workspace = true }
sp-io = { workspace = true, default-features = true }

[features]
default = ["std"]
std = [
    "codec/std",
    "frame-support/std",
    "frame-system/std",
    "scale-info/std",
    "sp-runtime/std",
]
runtime-benchmarks = [
    "frame-support/runtime-benchmarks",
    "frame-system/runtime-benchmarks",
    "pallet-balances/runtime-benchmarks",
    "pallet-preimage/runtime-benchmarks",
    "sp-runtime/runtime-benchmarks",
]
try-runtime = [
    "frame-support/try-runtime",
    "frame-system/try-runtime",
    "pallet-balances/try-runtime",
    "pallet-preimage/try-runtime",
    "sp-runtime/try-runtime",
]
```

### 5.5 Proposed test-file rewrites

`src/mock.rs:24`:

```rust
// BEFORE
use frame::testing_prelude::*;

// AFTER
use frame_support::{construct_runtime, derive_impl};
use frame_system::{mocking::MockBlock, EnsureRoot};
use sp_io::TestExternalities;
use sp_runtime::BuildStorage;
```

`src/tests.rs:22-25`:

```rust
// BEFORE
use frame::{
    testing_prelude::*,
    traits::{QueryPreimage, StorePreimage},
};

// AFTER
use frame_support::{
    assert_noop, assert_ok,
    traits::{QueryPreimage, StorePreimage},
};
use sp_runtime::DispatchError;
```

### 5.6 Risk notes

- `<Test as frame_system::Config>::Hashing::hash(...)` (line 32) requires
  `sp_runtime::traits::Hash` in scope — but it's referenced as a method on
  the `Hashing` associated type, so the trait is needed. Either explicit
  `use sp_runtime::traits::Hash;` in tests.rs, or it gets pulled implicitly
  via `super::*`. **Action:** add `use sp_runtime::traits::Hash;` to
  `tests.rs` if compiler complains.
- `RuntimeGenesisConfig` is auto-generated by `construct_runtime!` — no
  import needed.

---

## 6. `pallet-assets-freezer`

### 6.1 Test file inventory

| File:line                          | Path used                                                                                                                          |
|------------------------------------|------------------------------------------------------------------------------------------------------------------------------------|
| `src/mock.rs:28-30`                | `use codec::{Compact, Decode, Encode, MaxEncodedLen}; use frame::testing_prelude::*; use scale_info::TypeInfo;`                    |
| `src/mock.rs:35, 37, 47-72, 91-114, 116-139, 141-144, 146` | `MockBlock`, `construct_runtime!`, `derive_impl`, `Everything`, `H256`, `BlakeTwo256`, `IdentityLookup`, `ConstU64`, `ConstU32`, `PalletInfo`, `AsEnsureOriginWithArg`, `frame_system::{EnsureSigned, EnsureRoot}`, `DecodeWithMemTracking`, `VariantCount`, `TestExternalities`, `RuntimeGenesisConfig`, `assert_ok!` (only in test-runtime cfg block) |
| `src/tests.rs:28-30`               | `use codec::Compact; use frame::testing_prelude::*; use pallet_assets::FrozenBalance;`                                             |
| `src/tests.rs:42, 46, 53, 168, 186, 210, 216, 234, 258, 276` | `IdAmount`, `assert_ok!`, `assert_storage_noop!`                                                              |
| `src/lib.rs:50-58, 63, 72`         | (covered by 04-prep §1)                                                                                                            |
| `src/impls.rs:25`                  | (covered by 04-prep §1.4)                                                                                                          |

Identifiers actually used from `testing_prelude::*` in mock: `construct_runtime`,
`derive_impl`, `Everything`, `H256`, `BlakeTwo256`, `IdentityLookup`,
`ConstU64`, `ConstU32`, `AsEnsureOriginWithArg`, `MockBlock`, `PalletInfo`
(generated by `construct_runtime!`, but `frame_support::traits::PalletInfo`
trait may need importing? — actually `PalletInfo` here is the type alias
emitted by `construct_runtime!`, no import needed), `DecodeWithMemTracking`,
`VariantCount`, `TestExternalities`, `RuntimeGenesisConfig`. In tests:
`assert_ok!`, `assert_storage_noop!`, `IdAmount`.

### 6.2 Cargo feature gaps

Current `[dependencies]`:

```toml
codec = { workspace = true }
frame = { workspace = true, features = ["runtime"] }
log = { workspace = true }
pallet-assets = { workspace = true }
scale-info = { features = ["derive"], workspace = true }
```

**`codec` is missing `features = ["derive"]`!** This is the #1 confirmed gap
type from the atomic-swap PoC. The pallet uses `#[derive(Encode, Decode, ...)]`
in `lib.rs:75, 195` (storage types) and gets the derive feature via the
umbrella. Add explicitly:

```toml
codec = { features = ["derive"], workspace = true }
```

Also add `max-encoded-len` if any storage type derives `MaxEncodedLen`
explicitly (grep confirms `MaxEncodedLen` is used inside `mock.rs:120` on the
`DummyFreezeReason` derive, but that's test-only — and `IdAmount` in
production storage uses `MaxEncodedLen` via prelude). Safer to add:

```toml
codec = { features = ["derive", "max-encoded-len"], workspace = true }
```

### 6.3 Implicit identifier scan (production code: `src/lib.rs`, `src/impls.rs`)

- `saturating_sub` (`lib.rs:161, 164`) — needs `sp_runtime::traits::Saturating`
  in scope. Already covered by `pallet_prelude::*` re-export of
  `Saturating` — wait, `frame_support::pallet_prelude` does NOT include
  `Saturating`. The 04-prep's proposed
  `use frame_support::{ pallet_prelude::*, traits::{...} };` would lose access
  to `Saturating`. **Action:** add
  `use sp_runtime::traits::Saturating;` explicitly.
- `VariantCount` is `frame_support::traits::VariantCount` (in prelude). Already
  covered.
- `T::RuntimeFreezeReason` etc. are associated types, no import needed.
- No `blake2_256`/`H256`/etc. in production source.

### 6.4 Proposed `Cargo.toml`

```toml
[dependencies]
codec = { features = ["derive", "max-encoded-len"], workspace = true }
frame-support = { workspace = true }
frame-system = { workspace = true }
log = { workspace = true }
pallet-assets = { workspace = true }
scale-info = { features = ["derive"], workspace = true }
sp-runtime = { workspace = true }

[dev-dependencies]
pallet-balances = { workspace = true, default-features = false }
sp-core = { workspace = true, default-features = true }       # for H256
sp-io = { workspace = true, default-features = true }         # for TestExternalities

[features]
default = ["std"]
std = [
    "codec/std",
    "frame-support/std",
    "frame-system/std",
    "log/std",
    "pallet-assets/std",
    "pallet-balances/std",
    "scale-info/std",
    "sp-runtime/std",
]
runtime-benchmarks = [
    "frame-support/runtime-benchmarks",
    "frame-system/runtime-benchmarks",
    "pallet-assets/runtime-benchmarks",
    "pallet-balances/runtime-benchmarks",
    "sp-runtime/runtime-benchmarks",
]
try-runtime = [
    "frame-support/try-runtime",
    "frame-system/try-runtime",
    "pallet-assets/try-runtime",
    "pallet-balances/try-runtime",
    "sp-runtime/try-runtime",
]
```

REMOVE: `frame = ...`, `frame/std`, `frame/runtime-benchmarks`, `frame/try-runtime`.
ADD: `derive`/`max-encoded-len` codec features, `frame-support`, `frame-system`,
`sp-runtime` to deps; `sp-core`, `sp-io` to dev-deps; per-crate features.

### 6.5 Proposed test-file rewrites

`src/mock.rs:28-30`:

```rust
// BEFORE
use codec::{Compact, Decode, Encode, MaxEncodedLen};
use frame::testing_prelude::*;
use scale_info::TypeInfo;

// AFTER
use codec::{Compact, Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use frame_support::{
    construct_runtime, derive_impl, parameter_types,
    traits::{
        AsEnsureOriginWithArg, ConstU32, ConstU64, Everything, VariantCount,
    },
};
use frame_system::{mocking::MockBlock, EnsureRoot, EnsureSigned};
use scale_info::TypeInfo;
use sp_core::H256;
use sp_io::TestExternalities;
use sp_runtime::{traits::{BlakeTwo256, IdentityLookup}, BuildStorage};
```

(Drop `assert_ok` if not used outside the `try-runtime` cfg block. Actually
mock.rs:165 has `assert_ok!(AssetsFreezer::do_try_state());` under
`#[cfg(feature = "try-runtime")]` — so `assert_ok` is needed. Add it.)

`src/tests.rs:28-30`:

```rust
// BEFORE
use codec::Compact;
use frame::testing_prelude::*;
use pallet_assets::FrozenBalance;

// AFTER
use codec::Compact;
use frame_support::{
    assert_ok, assert_storage_noop,
    traits::tokens::IdAmount,
};
use pallet_assets::FrozenBalance;
```

(`Compact` is unused in tests.rs at the top level — verify; line 26 uses
`mock::*` to bring `mock`-defined names into scope. `IdAmount` is the only
prelude-sourced type referenced.)

### 6.6 Risk notes

- `mock.rs` is from before `derive_impl` adoption; it spells out the entire
  `frame_system::Config` impl. The rewrite keeps that style — only the
  imports change.
- `PalletInfo` referenced in `mock.rs:64` is generated by `construct_runtime!`
  (it's an auto-emitted local type), not the
  `frame_support::traits::PalletInfo` trait. No import needed.
- `IdAmount` lives in `frame_support::traits::tokens::IdAmount`. Confirmed.
- Confirm `DecodeWithMemTracking` is added to the `mock.rs` imports — line 118
  derives it, the umbrella prelude provides it transparently.

---

## 7. `pallet-nft-fractionalization`

### 7.1 Test file inventory

| File:line                          | Path used                                                                                                                |
|------------------------------------|--------------------------------------------------------------------------------------------------------------------------|
| `src/mock.rs:23`                   | `use frame::{deps::sp_runtime::MultiSignature, testing_prelude::*, traits::Verify};`                                     |
| `src/mock.rs:26-29, 32, 43, 46, 51, 59-71, 82-122, 124-142, 145-150` | `MockBlock`, `MultiSignature`, `Verify`, `IdentifyAccount`, `IdentityLookup`, `construct_runtime!`, `derive_impl`, `parameter_types!`, `ConstU64`, `ConstU32`, `AsEnsureOriginWithArg`, `EnsureSigned`, `frame_system::{EnsureSigned, EnsureRoot}`, `PalletId`, `BoundedVec`, `TestExternalities` |
| `src/tests.rs:22-25`               | `use frame::{deps::sp_runtime::ModuleError, testing_prelude::*}; use fungible::{...}; use fungibles::{...}; use TokenError::FundsUnavailable;` |
| `src/tests.rs:25, 29-330`          | `assert_ok!`, `assert_noop!`, `DispatchError::Module`, `ModuleError`, `TokenError::FundsUnavailable`, `fungible::*`, `fungibles::*` |
| `src/benchmarking.rs:23, 25`       | `use frame::benchmarking::prelude::*; use frame::deps::frame_support::assert_ok;` (deferred — but note the unusual `deps::frame_support::assert_ok` direct import) |
| `src/weights.rs:70`                | (covered by 04-prep §8)                                                                                                  |
| `src/lib.rs:50, 56`                | (covered by 04-prep §8)                                                                                                  |

Identifiers actually used from `testing_prelude::*` in mock: `construct_runtime`,
`derive_impl`, `parameter_types`, `MockBlock`, `IdentifyAccount`,
`IdentityLookup`, `ConstU64`, `ConstU32`, `AsEnsureOriginWithArg`,
`EnsureSigned`, `PalletId`, `BoundedVec`, `TestExternalities`. In tests:
`assert_ok`, `assert_noop`, `DispatchError`, `TokenError` (from
`sp_runtime::TokenError`), and the bare `fungible::*`/`fungibles::*` modules
(re-exported as part of `frame::token::*` at `frame_support::traits::tokens::*`).

### 7.2 Cargo feature gaps

Current `[dependencies]`:

```toml
codec = { workspace = true }
frame = { workspace = true, features = ["runtime"] }
log = { workspace = true }
pallet-assets = { workspace = true }
pallet-nfts = { workspace = true }
scale-info = { features = ["derive"], workspace = true }
```

**`codec` missing `features = ["derive"]`.** Same pattern as `assets-freezer`.
The pallet derives `Encode`/`Decode`/`MaxEncodedLen` for `HoldReason`,
`Details`, etc. Add:

```toml
codec = { features = ["derive", "max-encoded-len"], workspace = true }
```

(`max-encoded-len` because `lib.rs:99` has `T::NftCollectionId: Member +
Parameter + MaxEncodedLen + ...` bound that the macros need to satisfy.)

### 7.3 Implicit identifier scan (production code: `src/lib.rs`, `src/types.rs`, `src/weights.rs`)

- `PalletId` (lib.rs:127) — `frame_support::PalletId`. The 04-prep §8 doesn't
  list it; **gap**: add `use frame_support::PalletId;` (or rely on
  `pallet_prelude::*` which re-exports it — actually, looking at
  `frame_support::pallet_prelude::*` in `frame_support`, it does include
  `PalletId`. Verify and confirm; if not, add explicit import).
- `into_account_truncating()` (lib.rs:326) — method from
  `sp_runtime::traits::AccountIdConversion`. Need
  `use sp_runtime::traits::AccountIdConversion;` in lib.rs. **Gap**: 04-prep §8
  proposes only `frame_support` and `frame_system` — must add
  `sp-runtime` as a dep and import `AccountIdConversion`.
- No `blake2_256`/`H256`/`saturating` in production source.

`types.rs` only uses `super::*`, codec/scale-info — no extra imports needed.

### 7.4 Proposed `Cargo.toml`

```toml
[dependencies]
codec = { features = ["derive", "max-encoded-len"], workspace = true }
frame-support = { workspace = true }
frame-system = { workspace = true }
log = { workspace = true }
pallet-assets = { workspace = true }
pallet-nfts = { workspace = true }
scale-info = { features = ["derive"], workspace = true }
sp-runtime = { workspace = true }

[dev-dependencies]
pallet-balances = { default-features = true, workspace = true }
sp-io = { workspace = true, default-features = true }

[features]
default = ["std"]
std = [
    "codec/std",
    "frame-support/std",
    "frame-system/std",
    "log/std",
    "pallet-assets/std",
    "pallet-nfts/std",
    "scale-info/std",
    "sp-runtime/std",
]
runtime-benchmarks = [
    "frame-support/runtime-benchmarks",
    "frame-system/runtime-benchmarks",
    "pallet-assets/runtime-benchmarks",
    "pallet-balances/runtime-benchmarks",
    "pallet-nfts/runtime-benchmarks",
    "sp-runtime/runtime-benchmarks",
]
try-runtime = [
    "frame-support/try-runtime",
    "frame-system/try-runtime",
    "pallet-assets/try-runtime",
    "pallet-balances/try-runtime",
    "pallet-nfts/try-runtime",
    "sp-runtime/try-runtime",
]
```

Note: the 04-prep §8 was missing `sp-runtime` in `[dependencies]` — that was
correct under the umbrella because `into_account_truncating` was reachable
via `frame::prelude::*`. Without the umbrella we need it explicit. **This is
a gap relative to 04-prep.**

### 7.5 Proposed test-file rewrites

`src/mock.rs:23`:

```rust
// BEFORE
use frame::{deps::sp_runtime::MultiSignature, testing_prelude::*, traits::Verify};

// AFTER
use frame_support::{
    construct_runtime, derive_impl, parameter_types,
    traits::{AsEnsureOriginWithArg, ConstU32, ConstU64},
    BoundedVec, PalletId,
};
use frame_system::{mocking::MockBlock, EnsureSigned};
use sp_io::TestExternalities;
use sp_runtime::{
    traits::{IdentifyAccount, IdentityLookup, Verify},
    BuildStorage, MultiSignature,
};
```

`src/tests.rs:22-25`:

```rust
// BEFORE
use frame::{deps::sp_runtime::ModuleError, testing_prelude::*};
use fungible::{hold::Inspect as InspectHold, Mutate as MutateFungible};
use fungibles::{metadata::Inspect, InspectEnumerable};
use TokenError::FundsUnavailable;

// AFTER
use frame_support::{
    assert_noop, assert_ok,
    traits::tokens::{
        fungible::{self, hold::Inspect as InspectHold, Mutate as MutateFungible},
        fungibles::{self, metadata::Inspect, InspectEnumerable},
    },
};
use sp_runtime::{DispatchError, ModuleError, TokenError, TokenError::FundsUnavailable};
```

(The `use fungible::{...}` lines need their parent module brought into scope
explicitly — `fungible` and `fungibles` are submodules of
`frame_support::traits::tokens`. Aliased `use frame_support::traits::tokens::{fungible, fungibles}`
makes them visible by short name.)

### 7.6 Risk notes

- `BoundedVec` is at `frame_support::BoundedVec` and at `sp_runtime::BoundedVec`
  — they're the same type, re-exported. Use `frame_support::BoundedVec` to
  match the source convention. Confirmed.
- `PalletId` is `frame_support::PalletId` (also reachable as
  `frame_support::traits::PalletId` via the wildcard merge).
- The benchmarking file `benchmarking.rs:25` directly imports
  `frame::deps::frame_support::assert_ok` — interesting, because it's also in
  `testing_prelude::*` at line 23. After conversion this becomes
  `use frame_support::assert_ok;` — handled in benchmarking pass.
- `MultiSignature` is `sp_runtime::MultiSignature`. `Verify` and
  `IdentifyAccount` are in `sp_runtime::traits`.

---

## 8. `pallet-nis`

### 8.1 Test file inventory

| File:line                          | Path used                                                                                                     |
|------------------------------------|---------------------------------------------------------------------------------------------------------------|
| `src/mock.rs:20`                   | `use frame::{runtime::prelude::*, testing_prelude::*, traits::StorageMapShim};`                               |
| `src/mock.rs:22, 26, 29-51, 53, 59, 76, 97-104, 106-108, 110-134, 138, 152` | `MockBlock`, `#[frame_construct_runtime]`, `#[runtime::*]` attribute macros, `derive_impl`, `ConstU64`, `ConstU32`, `ConstU128`, `parameter_types!`, `ord_parameter_types!`, `Perquintill`, `PalletId`, `Weight`, `StorageMapShim`, `frame_system::EnsureSigned`, `sp_io::TestExternalities` |
| `src/tests.rs:20`                  | `use frame::testing_prelude::*;`                                                                              |
| `src/tests.rs:26, 28, 32, 42, 44, 50, 73, 76` | `fungible::InspectHold`, `Perquintill`, `WeightCounter`, `AllPalletsWithSystem`, `assert_ok!`, `assert_noop!`, `TokenError`, `Bid`, `Queues`, `Summary` |
| `src/benchmarking.rs:22`           | `use frame::benchmarking::prelude::*;` (deferred)                                                             |
| `src/weights.rs:70`                | (covered by 04-prep §9)                                                                                       |
| `src/lib.rs:93, 176`               | (covered by 04-prep §9)                                                                                       |

Identifiers actually used from `testing_prelude::*` + `runtime::prelude::*` in
mock: `frame_construct_runtime` (`= frame_support::runtime`), `derive_impl`,
`parameter_types`, `ord_parameter_types`, `ConstU64`, `ConstU32`, `ConstU128`,
`Perquintill`, `PalletId`, `Weight`, `MockBlock`. From `traits::StorageMapShim`:
`StorageMapShim` (`frame_support::traits::StorageMapShim`).
In tests: `assert_ok!`, `assert_noop!`, `Perquintill`, `WeightCounter`
(`frame_support::weights::WeightCounter`), `AllPalletsWithSystem` (auto-generated
by `construct_runtime!`/`#[frame_construct_runtime]`), `TokenError`,
`fungible::InspectHold`.

### 8.2 Cargo feature gaps

Current `[dependencies]`:

```toml
codec = { features = ["derive"], workspace = true }
frame = { workspace = true, features = ["runtime"] }
scale-info = { features = ["derive"], workspace = true }
```

`codec` already has `derive`. Add `max-encoded-len` if explicit (storage types
in lib.rs derive `MaxEncodedLen`):

```toml
codec = { features = ["derive", "max-encoded-len"], workspace = true }
```

`[dev-dependencies]` already includes `sp-io`. Need to add `sp-runtime` for
`BuildStorage` (or use it transitively from `pallet-balances`).

### 8.3 Implicit identifier scan (production code: `src/lib.rs`, `src/weights.rs`)

- `PalletId` (lib.rs:202) — same as nft-fractionalization. From
  `frame_support::PalletId`. Already covered by 04-prep §9 via
  `frame_support::PalletId` import.
- `into_account_truncating()` (lib.rs:963) —
  `sp_runtime::traits::AccountIdConversion`. Already covered by 04-prep §9.4
  via `use sp_runtime::traits::{Saturating, AccountIdConversion}`.
- `Defensive` and `defensive_saturating_*` methods (lib.rs:848, 1118, 1124,
  1127) — from `frame_support::traits::Defensive` and
  `frame_support::traits::DefensiveSaturating`. The 04-prep doesn't list
  these. **Gap:** add
  `use frame_support::traits::{Defensive, DefensiveSaturating};` (or rely on
  `pallet_prelude::*` — verify that `Defensive`/`DefensiveSaturating` are in
  `frame_support::pallet_prelude::*`. They're not; they're in
  `frame_support::traits::*`. The umbrella re-exports them via
  `prelude::*`'s `use frame_support::traits::{Defensive, DefensiveSaturating, ...};`.
  After conversion, they need explicit import.).
- `TypedGet` (lib.rs:104) — `frame_support::traits::TypedGet`. **Gap**: add
  to imports.
- `Unsigned`, `RationalArg` (lib.rs:107, 116) — from
  `sp_arithmetic::traits::*`. The 04-prep §9 adds `sp-arithmetic` dep but
  doesn't show the `Unsigned`/`RationalArg` import explicitly. Add:
  `use sp_arithmetic::traits::{Unsigned, RationalArg};`.
- `Convert`, `ConvertBack` — `sp_runtime::traits::*`. Already covered in
  04-prep §9.4 imports.
- `Perquintill` — `sp_arithmetic::Perquintill`. Already covered.
- `BoundedVec` — covered.

No `blake2_256`/`H256`/etc.

### 8.4 Proposed `Cargo.toml`

```toml
[dependencies]
codec = { features = ["derive", "max-encoded-len"], workspace = true }
frame-support = { workspace = true }
frame-system = { workspace = true }
scale-info = { features = ["derive"], workspace = true }
sp-arithmetic = { workspace = true }
sp-runtime = { workspace = true }

[dev-dependencies]
pallet-balances = { default-features = true, workspace = true }
sp-io = { default-features = true, workspace = true }

[features]
default = ["std"]
std = [
    "codec/std",
    "frame-support/std",
    "frame-system/std",
    "scale-info/std",
    "sp-arithmetic/std",
    "sp-runtime/std",
]
runtime-benchmarks = [
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

### 8.5 Proposed test-file rewrites

`src/mock.rs:20`:

```rust
// BEFORE
use frame::{runtime::prelude::*, testing_prelude::*, traits::StorageMapShim};

// AFTER
use frame_support::{
    derive_impl, ord_parameter_types, parameter_types,
    runtime as frame_construct_runtime,
    traits::{ConstU32, ConstU64, ConstU128, StorageMapShim},
    weights::Weight,
    PalletId,
};
use frame_system::{mocking::MockBlock, EnsureSigned};
use sp_arithmetic::Perquintill;
use sp_io;
use sp_runtime::BuildStorage;
```

(The `#[frame_construct_runtime]` attribute on `mod runtime` at line 29
needs to resolve to `frame_support::runtime`. The `use frame_support::runtime as frame_construct_runtime;`
line above provides a local alias that the attribute macro can resolve.
Alternatively: change line 29 to `#[frame_support::runtime]` directly, which
is cleaner — recommended approach. Update the inner `#[runtime::pallet_index]`
attributes to `#[frame_support::pallet_index]` etc., per the
`frame_support::runtime` macro's nested-attribute scheme. Confirm by
inspecting `frame_support::runtime` macro docs.)

`src/tests.rs:20`:

```rust
// BEFORE
use frame::testing_prelude::*;

// AFTER
use frame_support::{
    assert_noop, assert_ok,
    traits::tokens::fungible,
    weights::WeightCounter,
};
use sp_arithmetic::Perquintill;
use sp_runtime::TokenError;
```

(`AllPalletsWithSystem` is auto-generated by the `runtime` macro — no import
needed. `Bid`, `Queues`, `Summary`, `SummaryRecord`, etc. come from
`crate::*` already imported on line 23.)

### 8.6 Risk notes

- `#[frame_construct_runtime]` is the trickiest single line in this batch.
  Switching to `#[frame_support::runtime]` directly avoids needing a
  `use ... as frame_construct_runtime;` alias. The inner attributes
  (`#[runtime::runtime]`, `#[runtime::derive(...)]`, `#[runtime::pallet_index(N)]`,
  `pub type X = pallet`) ARE part of the `frame_support::runtime` macro's DSL
  — they don't need separate imports. Confirmed by inspecting
  `frame_support::runtime` macro.
- `WeightCounter` is in `frame_support::weights::WeightCounter` (NOT in
  `pallet_prelude::*`). Explicit import needed.
- `Defensive`, `DefensiveSaturating` should ideally be added to `lib.rs`'s
  imports (in addition to what 04-prep §9 already proposes). Without them,
  `defensive_saturating_reduce`/`defensive_saturating_accrue`/
  `defensive_unwrap_or_default`/`.defensive()` calls won't resolve.
- `TypedGet` is in `frame_support::traits::TypedGet` (NOT in `pallet_prelude::*`
  by default — verify). Add explicit import.
- `RationalArg`, `Unsigned` come from `sp_arithmetic::traits::*`. Add
  explicit import.
- `pallet-balances` is used with `Instance1`/`Instance2` in mock; no
  special handling needed.

---

## Cross-pallet appendix

### A. Recurring identifier-import recipes (test-side)

| Identifier               | Underlying path                                         | Pallets that use it |
|--------------------------|---------------------------------------------------------|---------------------|
| `assert_ok!`             | `frame_support::assert_ok`                              | all 8               |
| `assert_noop!`           | `frame_support::assert_noop`                            | all 8 (recovery, salary, tx-pause, whitelist, nft-frac, nis, assets-freezer, randomness via tests) |
| `assert_err!`            | `frame_support::assert_err`                             | tx-pause            |
| `assert_storage_noop!`   | `frame_support::assert_storage_noop`                    | assets-freezer      |
| `construct_runtime!`     | `frame_support::construct_runtime`                      | randomness, recovery, salary, tx-pause, whitelist, assets-freezer, nft-frac |
| `derive_impl`            | `frame_support::derive_impl`                            | all 8               |
| `parameter_types!`       | `frame_support::parameter_types`                        | randomness, recovery, salary, tx-pause, nft-frac, nis |
| `ord_parameter_types!`   | `frame_support::ord_parameter_types`                    | tx-pause, nis       |
| `MockBlock`              | `frame_system::mocking::MockBlock`                      | all 8               |
| `TestExternalities`      | `sp_io::TestExternalities`                              | randomness, recovery, tx-pause, whitelist, assets-freezer, nft-frac |
| `TestState` (alias)      | `sp_io::TestExternalities as TestState`                 | salary              |
| `BuildStorage`           | `sp_runtime::BuildStorage`                              | all 8 (via `.build_storage()`) |
| `BadOrigin`              | `sp_runtime::traits::BadOrigin`                         | recovery            |
| `Everything`             | `frame_support::traits::Everything`                     | tx-pause, assets-freezer |
| `InsideBoth`             | `frame_support::traits::InsideBoth`                     | tx-pause            |
| `InstanceFilter`         | `frame_support::traits::InstanceFilter`                 | tx-pause            |
| `Contains`               | `frame_support::traits::Contains`                       | tx-pause            |
| `EnsureSignedBy`         | `frame_system::EnsureSignedBy`                          | tx-pause            |
| `EnsureSigned`           | `frame_system::EnsureSigned`                            | nft-frac, nis       |
| `EnsureRoot`             | `frame_system::EnsureRoot`                              | whitelist           |
| `ConstU64`/`ConstU32`/`ConstU128` | `frame_support::traits::{ConstU64, ConstU32, ConstU128}` | tx-pause, salary, assets-freezer, nft-frac, nis |
| `BlakeTwo256`            | `sp_runtime::traits::BlakeTwo256`                       | tx-pause, assets-freezer |
| `IdentityLookup`         | `sp_runtime::traits::IdentityLookup`                    | assets-freezer, nft-frac |
| `IdentifyAccount`        | `sp_runtime::traits::IdentifyAccount`                   | nft-frac            |
| `Verify`                 | `sp_runtime::traits::Verify`                            | nft-frac            |
| `MultiSignature`         | `sp_runtime::MultiSignature`                            | nft-frac            |
| `ModuleError`            | `sp_runtime::ModuleError`                               | nft-frac            |
| `TokenError`             | `sp_runtime::TokenError`                                | nft-frac, nis       |
| `DispatchError`          | `sp_runtime::DispatchError`                             | tx-pause, whitelist, nft-frac |
| `Dispatchable`           | `sp_runtime::traits::Dispatchable`                      | tx-pause            |
| `H256`                   | `sp_core::H256`                                         | randomness, assets-freezer |
| `PalletId`               | `frame_support::PalletId`                               | nft-frac, nis       |
| `BoundedVec`             | `frame_support::BoundedVec` (or `sp_runtime::BoundedVec`) | nft-frac          |
| `Weight`                 | `frame_support::weights::Weight`                        | salary, nis         |
| `WeightCounter`          | `frame_support::weights::WeightCounter`                 | nis                 |
| `Perquintill`            | `sp_arithmetic::Perquintill`                            | nis                 |
| `StorageMapShim`         | `frame_support::traits::StorageMapShim`                 | nis                 |
| `RankedMembers`          | `frame_support::traits::RankedMembers`                  | salary              |
| `EitherOf`/`MapSuccess`/`NoOpPoll` | `frame_support::traits::*`                    | salary              |
| `ReduceBy`/`ReplaceWithDefault` | `sp_runtime::traits::*`                          | salary              |
| `AsEnsureOriginWithArg`  | `frame_support::traits::AsEnsureOriginWithArg`          | assets-freezer, nft-frac |
| `VariantCount`           | `frame_support::traits::VariantCount`                   | assets-freezer      |
| `ConvertRank`            | `frame_support::traits::tokens::ConvertRank`            | salary              |
| `IdAmount`               | `frame_support::traits::tokens::IdAmount`               | assets-freezer      |
| `hypothetically!`        | `frame_support::hypothetically`                         | salary              |
| `StateVersion`           | `sp_runtime::StateVersion`                              | salary              |
| `bounded_vec!`           | `sp_runtime::bounded_vec`                               | recovery            |
| `Header` (trait)         | `sp_runtime::traits::Header`                            | randomness          |
| `Saturating` (trait)     | `sp_runtime::traits::Saturating`                        | randomness, recovery, salary, whitelist, assets-freezer (production-side via `saturating_*` methods) |
| `Defensive`/`DefensiveSaturating` | `frame_support::traits::*`                     | recovery, salary, nis (production-side via `defensive!`/`.defensive()`/`defensive_saturating_*`) |
| `TypedGet`               | `frame_support::traits::TypedGet`                       | nis                 |
| `Unsigned`/`RationalArg` | `sp_arithmetic::traits::*`                              | nis                 |

### B. The `#[pallet]` proc-macro detection issue

Recap from the atomic-swap PoC: the `#[pallet]` macro internally calls
`proc_macro_crate::crate_name("frame")` (and its alternatives) to figure out
the host crate name. If `frame` is in EITHER `[dependencies]` OR
`[dev-dependencies]`, the macro will see it and emit code that references
`::frame::*` paths, which then fail to resolve once we've removed `frame`
from `[dependencies]`. **All 8 pallets currently have `frame` only in
`[dependencies]`, so removing it from there is sufficient.** None has a
duplicate `frame = ...` line in `[dev-dependencies]`. Confirmed.

### C. Confirmed gaps relative to 04-step1-prep.md

| Pallet                  | Gap                                                                                  |
|-------------------------|--------------------------------------------------------------------------------------|
| insecure-randomness     | Missing `sp_runtime::traits::Saturating` import (for `saturating_sub` on line 157)   |
| recovery                | Missing `frame_support::defensive` import; missing `Saturating` in proposed imports  |
| salary                  | Missing `frame_support::defensive` import                                            |
| tx-pause                | (no production-code gap; test-side `Dispatchable` import not in 04-prep test plan)   |
| whitelist               | Missing `Saturating` in proposed imports                                             |
| assets-freezer          | `codec` needs `derive` (and `max-encoded-len`); missing `Saturating` import; sp-core/sp-io as dev-deps |
| nft-fractionalization   | `codec` needs `derive` + `max-encoded-len`; missing `sp-runtime` dep; missing `AccountIdConversion` import |
| nis                     | `codec` needs `max-encoded-len`; missing `Defensive`/`DefensiveSaturating`/`TypedGet`/`Unsigned`/`RationalArg` imports; mock needs `#[frame_support::runtime]` rewrite |

### D. Per-pallet `[dev-dependencies]` additions summary

| Pallet                  | Add to `[dev-dependencies]`                                                          |
|-------------------------|--------------------------------------------------------------------------------------|
| insecure-randomness     | `sp-core` (default-features = true), `sp-io` (default-features = true)               |
| recovery                | `sp-io`                                                                              |
| salary                  | `sp-io`, plus promote `pallet-ranked-collective` from optional/dep to dev-dep        |
| tx-pause                | `sp-io`                                                                              |
| whitelist               | `sp-io`                                                                              |
| assets-freezer          | `sp-core`, `sp-io`                                                                   |
| nft-fractionalization   | `sp-io` (sp-runtime already covered via [dependencies])                              |
| nis                     | (sp-io already in dev-deps; nothing to add)                                          |

### E. Per-pallet `[features]` deltas summary

For all 8 pallets:

- REMOVE: `"frame/std"`, `"frame/runtime-benchmarks"`, `"frame/try-runtime"`
- ADD `"frame-support/<flag>"`, `"frame-system/<flag>"`, `"sp-runtime/<flag>"` everywhere
- ADD `"sp-arithmetic/std"` for nis only
- KEEP all existing `"pallet-*/<flag>"` lines
- `"sp-io/<flag>"` and `"sp-core/<flag>"` are NOT added to `[features]` because
  those crates are dev-only for these pallets (when used). Only crates listed in
  `[dependencies]` need feature plumbing.
- Exception: `pallet-paged-list` (out of scope here) DOES list `sp-io` in
  `[dependencies]`; reference 04-prep §11 for that.

