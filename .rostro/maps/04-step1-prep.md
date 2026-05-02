# Step 1 Prep: Per-Pallet Plan to Replace `frame` Umbrella With Explicit Deps

Source data: `polkadot-sdk-frame` re-export map at `substrate/frame/src/lib.rs` plus
production-source greps of all 17 affected pallets (mock/test/benchmarking files
deferred to a follow-up).

## Overview

### Umbrella re-export map (from `substrate/frame/src/lib.rs`)

The `frame` crate is a thin re-exporter. Every public path it exposes maps to a
real underlying crate. Keep this table next to you while reading the per-pallet
sections; every "AFTER" rewrite below comes from this table.

| `frame::*` path                      | Resolves to                                                                 |
|--------------------------------------|------------------------------------------------------------------------------|
| `frame::pallet`                      | `frame_support::pallet` (proc-macro)                                         |
| `frame::storage_alias`               | `frame_support::storage_alias`                                               |
| `frame::pallet_macros::*`            | `frame_support::{derive_impl, pallet, pallet_macros::*}`                     |
| `frame::prelude` (sub-items below)   | aggregate of several crates                                                  |
| `frame::prelude::frame_system`       | `frame_system` (the crate)                                                   |
| `frame::prelude::*` from `frame_support::pallet_prelude::*` | `BoundedVec`, `BoundedSlice`, `ConstU32`, `Decode`, `DispatchResult`, `Encode`, `Hooks`, `IsType`, `MaxEncodedLen`, `Member`, `OptionQuery`, `Parameter`, `RuntimeDebug`, `StorageDoubleMap`, `StorageMap`, `StorageValue`, `StorageVersion`, `TypeInfo`, `ValueQuery`, `Weight`, `Get`, `ConstU*`, `PhantomData`, `Twox64Concat`, `Blake2_128Concat`, `OriginFor`, `EnsureOrigin`, `Pays`, etc. |
| `frame::prelude::*` from `frame_support::dispatch::*` | `GetDispatchInfo`, `PostDispatchInfo`                                |
| `frame::prelude::*` from `frame_support::traits::*` | `Contains`, `Defensive`, `DefensiveSaturating`, `EitherOf`, `EstimateNextSessionRotation`, `Everything`, `InsideBoth`, `InstanceFilter`, `IsSubType`, `MapSuccess`, `NoOpPoll`, `OnRuntimeUpgrade`, `OneSessionHandler`, `PalletInfoAccess`, `RankedMembers`, `RankedMembersSwapHandler`, `VariantCount`, `VariantCountOf`, `PalletId`, `defensive`, `defensive_assert` |
| `frame::prelude::*` from `frame_system::pallet_prelude::*` | `BlockNumberFor`, `OriginFor`, `HeaderFor`, `EnsureRoot`, `EnsureSigned`, `ensure_signed`, `ensure_root`, `ensure_none`, etc. |
| `frame::prelude::*` from `frame_system::offchain::*` | `SendTransactionTypes`, `CreateInherent`, `Signer`, etc.                   |
| `frame::prelude::*` from `super::derive::*` | `Encode`, `Decode`, `Debug`, `CloneNoBound`, `DebugNoBound`, `DefaultNoBound`, `EqNoBound`, `OrdNoBound`, `PartialEqNoBound`, `PartialOrdNoBound`, `TypeInfo`, `serde::{Serialize, Deserialize}` |
| `frame::prelude::*` from `super::hashing::*` | from `sp_core::{hashing::*, H160, H256, H512, U256, U512}`, `sp_runtime::traits::{BlakeTwo256, Hash, Keccak256}` |
| `frame::prelude::*` from `crate::transaction::*` | `frame_support::traits::{CallMetadata, GetCallMetadata}`, `sp_runtime::{generic::ExtensionVersion, impl_tx_ext_default, traits::{AsTransactionAuthorizedOrigin, DispatchTransaction, TransactionExtension, ValidateResult}, transaction_validity::{InvalidTransaction, ValidTransaction}}` |
| `frame::prelude::*` from `super::account::*` | `frame_support::traits::{AsEnsureOriginWithArg, ChangeMembers, EitherOfDiverse, InitializeMembers}`, `sp_runtime::traits::{IdentifyAccount, IdentityLookup}` |
| `frame::prelude::*` from `super::arithmetic::*` | `sp_arithmetic::{traits::*, *}` (PerThing, Perbill, Permill, Perquintill, FixedU128, etc.) |
| `frame::prelude::*` from `super::token::*` | `frame_support::traits::tokens::{currency, fungible, fungibles, imbalance, nonfungible, nonfungible_v2, nonfungibles, nonfungibles_v2, pay, AssetId, BalanceStatus, DepositConsequence, ExistenceRequirement, Fortitude, Pay, Precision, Preservation, Provenance, WithdrawConsequence, WithdrawReasons}`, `frame_support::traits::OnUnbalanced` |
| `frame::prelude::*` runtime traits   | `sp_runtime::traits::{AccountIdConversion, BlockNumberProvider, Bounded, Convert, ConvertBack, DispatchInfoOf, Dispatchable, ReduceBy, ReplaceWithDefault, SaturatedConversion, Saturating, StaticLookup, TrailingZeroInput}` |
| `frame::prelude::*` bounded          | `sp_runtime::{BoundedSlice, BoundedVec}`                                     |
| `frame::prelude::*` error types      | `sp_runtime::{BoundToRuntimeAppPublic, DispatchErrorWithPostInfo, DispatchResultWithInfo, TokenError}` |
| `frame::traits::*`                   | `frame_support::traits::*` and `sp_runtime::traits::*` (wildcard merged)     |
| `frame::derive::*`                   | `codec::{Decode, Encode}`, `core::fmt::Debug`, `frame_support::{CloneNoBound, DebugNoBound, DefaultNoBound, EqNoBound, OrdNoBound, PartialEqNoBound, PartialOrdNoBound}`, `scale_info::TypeInfo`, `serde::{Serialize, Deserialize}` |
| `frame::hashing::*`                  | `sp_core::{hashing::*, H160, H256, H512, U256, U512}`, `sp_runtime::traits::{BlakeTwo256, Hash, Keccak256}` |
| `frame::token::*`                    | `frame_support::traits::tokens::*` (subset listed above)                     |
| `frame::arithmetic::*`               | `sp_arithmetic::{traits::*, *}`                                              |
| `frame::weights_prelude::*`          | `core::marker::PhantomData`, `frame_support::{traits::Get, weights::{constants::{ParityDbWeight, RocksDbWeight}, Weight}}`, `frame_system` |
| `frame::try_runtime::TryRuntimeError`| `sp_runtime::TryRuntimeError` (gated `try-runtime` or `test`)                |
| `frame::runtime::prelude::*`         | re-exports above plus `frame_executive`, `frame_support::construct_runtime`, `frame_support::runtime`, `frame_support::derive_impl`, `frame_support::{ord_parameter_types, parameter_types}`, `frame_support::genesis_builder_helper::{build_state, get_preset}`, `frame_support::traits::{ConstBool, ConstI*, ConstU*}`, `frame_support::weights::{FixedFee, NoFee}`, `frame_system::{EnsureNever, EnsureNone, EnsureRoot, EnsureRootWithSuccess, EnsureSigned, EnsureSignedBy}`, `sp_version::{create_runtime_str, runtime_version, RuntimeVersion, NativeVersion}`, `sp_api::impl_runtime_apis`, `sp_core::OpaqueMetadata`, `sp_genesis_builder::*`, `sp_inherents::*`, `sp_keyring::Sr25519Keyring`, `sp_runtime::{ApplyExtrinsicResult, ExtrinsicInclusionMode}` |
| `frame::runtime::prelude::storage::{StorageAppender, StorageList, StoragePrefixedContainer}` | (in fact lives at `frame_support::storage::*` — accessed via the runtime prelude wildcard re-exporting `frame_support::pallet_prelude::*`; really `frame_support::storage`) |
| `frame::deps::*`                     | direct re-export of `frame_support`, `frame_system`, `sp_arithmetic`, `sp_core`, `sp_io`, `sp_runtime`, `codec`, `scale_info`, `frame_executive`, `sp_api`, `sp_block_builder`, etc. |
| `frame::deps::sp_io`                 | `sp_io`                                                                      |
| `frame::deps::sp_core`               | `sp_core`                                                                    |
| `frame::deps::sp_runtime`            | `sp_runtime`                                                                 |
| `frame::deps::frame_support`         | `frame_support`                                                              |
| `frame::testing_prelude::*`          | `frame_support::{assert_*, ensure, hypothetically*, storage_alias, StorageNoopGuard}`, `frame_support::traits::Everything`, `frame_system::{mocking::*, RunToBlockHooks}`, `sp_io::TestExternalities as TestState`, `sp_runtime::{traits::BadOrigin, StateVersion}`. Also includes everything in `prelude` and `runtime::prelude`. (Test-side only — out of scope for production pallets.) |

Implication for `[features]`: today's `frame/std`, `frame/runtime-benchmarks`,
`frame/try-runtime` flags must be expanded to the per-crate `*/std`,
`*/runtime-benchmarks`, `*/try-runtime` of every explicit dep added.

### One-line per-pallet difficulty summary

| # | Pallet                                  | Difficulty | Notes (one line)                                                                 |
|---|-----------------------------------------|------------|----------------------------------------------------------------------------------|
| 1 | assets-freezer                          | easy       | prelude + tokens traits, single import block; uses `frame::try_runtime::TryRuntimeError` (gated). |
| 2 | atomic-swap                             | easy       | prelude + Currency/ReservableCurrency only.                                       |
| 3 | insecure-randomness-collective-flip     | easy       | prelude + `traits::Randomness` only.                                              |
| 4 | merkle-mountain-range                   | medium     | hits `frame::traits::Hash`, `frame::deps::{sp_core::offchain, sp_io}`, `frame::deps::frame_support::weights::constants` in `default_weights.rs`. |
| 5 | migrations                              | trivial    | already uses explicit `frame_support`/`frame_system`/`sp_*`; just drop `frame` from Cargo.toml + flip `weights.rs` to `frame_support::weights_prelude` equivalent. |
| 6 | mixnet                                  | medium     | uses `frame::deps::{sp_io, sp_runtime}`, plus prelude. Has `dev_mode` pallet attr. |
| 7 | multisig                                | medium     | imports `frame::traits::WrapperKeepOpaque`, `frame::traits::ReservableCurrency`, `frame::try_runtime::TryRuntimeError` and `#[frame::storage_alias]` inside `migrations.rs`. |
| 8 | nft-fractionalization                   | easy       | prelude only; specific token traits brought in inside the `#[frame::pallet]` mod.|
| 9 | nis                                     | easy       | prelude + token traits brought in directly (`fungible`, `nonfungible`, `tokens`).|
|10 | node-authorization                      | easy       | prelude + `frame::deps::{sp_core::OpaquePeerId, sp_io}`.                          |
|11 | paged-list                              | medium     | uses `frame::runtime::prelude::storage::{StorageAppender, StorageList, StoragePrefixedContainer}`, `frame::deps::sp_io`, `frame::traits::StorageInstance`, and `frame::deps::frame_support::storage::StorageList` doc-link. |
|12 | proxy                                   | easy       | prelude + Currency/InstanceFilter/ReservableCurrency, plus inline `frame::traits::{InstanceFilter as _, OriginTrait as _}` and trait bound `frame::traits::InstanceFilter<...>`. |
|13 | recovery                                | easy       | prelude + Currency/ReservableCurrency.                                            |
|14 | safe-mode                               | medium     | uses `frame::traits::{SafeMode, SafeModeError}` (these come from `frame_support::traits`), plus fungible::hold imports inside prelude path. |
|15 | salary                                  | easy       | prelude + tokens traits (`GetSalary`, `Pay`, `PaymentStatus`).                    |
|16 | tx-pause                                | easy       | prelude + `traits::{TransactionPause, TransactionPauseError}`.                    |
|17 | whitelist                               | easy       | prelude + `traits::{QueryPreimage, StorePreimage}`, plus a single `frame::deps::frame_support::MAX_EXTRINSIC_DEPTH` reference. |

Eleven of seventeen are "easy" — a 3-line Cargo.toml swap and a 2-block `use`
rewrite. Six need a couple of additional fix-up sites (a bound, a one-off
`frame::deps::*` path, or a `frame::traits::SomeTrait` trait-object usage).
None require a design call.

---

## 1. `pallet-assets-freezer`

### 1.1 `frame::*` usage inventory (production code)

| File:line                                                          | Path used                                            |
|--------------------------------------------------------------------|------------------------------------------------------|
| `src/lib.rs:50-58`                                                 | `use frame::{prelude::*, traits::{fungibles::{Inspect, InspectFreeze, MutateFreeze}, tokens::{DepositConsequence, Fortitude, IdAmount, Preservation, Provenance, WithdrawConsequence}}}` |
| `src/lib.rs:63` (cfg `try-runtime`)                                | `use frame::try_runtime::TryRuntimeError`            |
| `src/lib.rs:72`                                                    | `#[frame::pallet]`                                   |
| `src/impls.rs:25`                                                  | `use frame::prelude::storage::StorageDoubleMap`      |

Identifiers actually used from `frame::prelude::*`: `BoundedVec`, `BoundedSlice`, `Hooks`,
`BlockNumberFor`, `DispatchResult`, `IsType`, `Member`, `MaxEncodedLen`, `Parameter`,
`VariantCount`, `ensure!`, `StorageDoubleMap` (via `prelude::storage::`), plus `OptionQuery`/
`ValueQuery`/`StorageMap` style names from the `pallet_prelude`.

### 1.2 Required underlying crates

`frame_support`, `frame_system`, `sp_runtime` (for `TryRuntimeError` and bounded types and
`StaticLookup`), and (for benchmarking only later) `frame_benchmarking`.

### 1.3 Proposed `[dependencies]` replacement

```toml
# REMOVE:
# frame = { workspace = true, features = ["runtime"] }

# ADD:
frame-support = { workspace = true }
frame-system = { workspace = true }
sp-runtime = { workspace = true }
```

(`pallet-assets`, `codec`, `scale-info`, `log` are already explicit; leave them.)

### 1.4 Proposed `use` rewrites

```rust
// BEFORE
use frame::{
    prelude::*,
    traits::{
        fungibles::{Inspect, InspectFreeze, MutateFreeze},
        tokens::{DepositConsequence, Fortitude, IdAmount, Preservation, Provenance, WithdrawConsequence},
    },
};
#[cfg(feature = "try-runtime")]
use frame::try_runtime::TryRuntimeError;
#[frame::pallet]

// AFTER
use frame_support::{
    pallet_prelude::*,
    traits::{
        fungibles::{Inspect, InspectFreeze, MutateFreeze},
        tokens::{DepositConsequence, Fortitude, IdAmount, Preservation, Provenance, WithdrawConsequence},
    },
};
use frame_system::pallet_prelude::*;
#[cfg(feature = "try-runtime")]
use sp_runtime::TryRuntimeError;
#[frame_support::pallet]
```

In `src/impls.rs:25`:

```rust
// BEFORE: use frame::prelude::storage::StorageDoubleMap;
// AFTER:  use frame_support::storage::StorageDoubleMap;
```

### 1.5 Risk notes

`frame::prelude::storage::StorageDoubleMap` is the cute path the umbrella exposes; it's
literally `frame_support::storage::StorageDoubleMap`. Confirm that the trait is the
trait, not the macro-generated storage type alias.

### 1.6 `[features]` adjustments

```toml
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

Tests/mocks/benchmarking: `mock.rs`, `tests.rs` use `frame::testing_prelude` and need
the same explicit-crate rewrite later.

---

## 2. `pallet-atomic-swap`

### 2.1 `frame::*` usage inventory

| File:line                  | Path                                                                  |
|---------------------------|------------------------------------------------------------------------|
| `src/lib.rs:53-56`        | `use frame::{prelude::*, traits::{BalanceStatus, Currency, ReservableCurrency}}` |
| `src/lib.rs:168`          | `#[frame::pallet]`                                                      |

Identifiers from `frame::prelude::*`: `PhantomData`, `DispatchResult`, `BlockNumberFor`,
`MaxEncodedLen`, `IsType`, `Parameter`, `ensure!`, `TypeInfo`/`Encode`/`Decode` derives via
`derive::*`, `OriginFor`, `OptionQuery`/`ValueQuery`/`StorageMap`, `Hooks`. (`BalanceStatus`
is `frame_support::traits::tokens::BalanceStatus`, accessible directly under
`frame_support::traits` thanks to its glob re-export.)

### 2.2 Required underlying crates

`frame_support`, `frame_system`, `sp_runtime` (for `BoundedVec`/`StaticLookup` if any —
this pallet needs neither, but consistent inclusion of `sp-runtime` is harmless and
matches the prelude semantics).

### 2.3 Proposed `[dependencies]` replacement

```toml
# REMOVE:
# frame = { workspace = true, features = ["runtime"] }

# ADD:
frame-support = { workspace = true }
frame-system = { workspace = true }
sp-runtime = { workspace = true }
```

### 2.4 Proposed `use` rewrites

```rust
// BEFORE
use frame::{
    prelude::*,
    traits::{BalanceStatus, Currency, ReservableCurrency},
};
#[frame::pallet]

// AFTER
use frame_support::{
    pallet_prelude::*,
    traits::{tokens::BalanceStatus, Currency, ReservableCurrency},
};
use frame_system::pallet_prelude::*;
#[frame_support::pallet]
```

(Note: `BalanceStatus` lives in `frame_support::traits::tokens`; the umbrella's
wildcard merge makes `frame::traits::BalanceStatus` work without the `tokens::`
hop, so we add the `tokens::` segment in the rewrite.)

### 2.5 Risk notes

None. Pure prelude + currency traits.

### 2.6 `[features]` adjustments

```toml
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

Tests in `src/tests.rs` use the testing_prelude — handle in follow-up.

---

## 3. `pallet-insecure-randomness-collective-flip`

### 3.1 `frame::*` usage inventory

| File:line               | Path                                                  |
|-------------------------|--------------------------------------------------------|
| `src/lib.rs:74`         | `use frame::{prelude::*, traits::Randomness};`        |
| `src/lib.rs:86`         | `#[frame::pallet]`                                    |

(Lines 45, 47, 165 are doc-comments / test-mod; line 165 is inside `mod tests` and
out of scope.)

Identifiers actually used: `BlockNumberFor`, `Hooks`, `Weight`, `BoundedVec`, `ConstU32`,
`StorageValue`, `ValueQuery`, `Randomness` (trait), `OriginFor`/`DispatchResult` not used.
Encodes used via `codec::Encode` directly.

### 3.2 Required underlying crates

`frame_support`, `frame_system`. (Already has `codec`, `scale-info`, `safe-mix`.)

### 3.3 Proposed `[dependencies]` replacement

```toml
# REMOVE:
# frame = { workspace = true, features = ["runtime"] }

# ADD:
frame-support = { workspace = true }
frame-system = { workspace = true }
```

### 3.4 Proposed `use` rewrites

```rust
// BEFORE
use frame::{prelude::*, traits::Randomness};
#[frame::pallet]

// AFTER
use frame_support::{pallet_prelude::*, traits::Randomness};
use frame_system::pallet_prelude::*;
#[frame_support::pallet]
```

### 3.5 Risk notes

The `Randomness` here is `frame_support::traits::Randomness` (yes, the deprecated/
insecure one). No surprise.

### 3.6 `[features]` adjustments

```toml
std = [
    "codec/std",
    "frame-support/std",
    "frame-system/std",
    "safe-mix/std",
    "scale-info/std",
]
try-runtime = [
    "frame-support/try-runtime",
    "frame-system/try-runtime",
]
```

---

## 4. `pallet-mmr` (merkle-mountain-range)

### 4.1 `frame::*` usage inventory

| File:line                       | Path                                                                 |
|---------------------------------|----------------------------------------------------------------------|
| `src/lib.rs:64`                 | `use frame::prelude::*;`                                             |
| `src/lib.rs:147`                | `#[frame::pallet]`                                                   |
| `src/default_weights.rs:21`     | `use frame::{deps::frame_support::weights::constants::*, weights_prelude::*};` |
| `src/weights.rs:70`             | `use frame::weights_prelude::*;`                                     |
| `src/mmr/mod.rs:23`             | `use frame::traits;`                                                 |
| `src/mmr/mmr.rs:30`             | `use frame::prelude::*;`                                             |
| `src/mmr/mmr.rs:68`             | bound `H: frame::traits::Hash`                                        |
| `src/mmr/storage.rs:28-34`      | `use frame::{deps::{sp_core::offchain::StorageKind, sp_io::{offchain, offchain_index}}, prelude::*};` |

Identifiers used from prelude: `BlockNumberFor`, `Hooks`, `Weight`, `Vec`, `BoundedVec`,
`ConstU*`, `StorageMap`, `StorageValue`, `ValueQuery`, `OptionQuery`, plus storage-hasher
identifiers, `DispatchError`. From `frame::traits`: `Hash` (= `sp_runtime::traits::Hash`).

### 4.2 Required underlying crates

`frame_support`, `frame_system`, `sp_core`, `sp_io`, `sp_runtime`. (Plus `sp_mmr_primitives`
which is already explicit.)

### 4.3 Proposed `[dependencies]` replacement

```toml
# REMOVE:
# frame = { workspace = true, features = ["runtime"] }

# ADD:
frame-support = { workspace = true }
frame-system = { workspace = true }
sp-core = { workspace = true }
sp-io = { workspace = true }
sp-runtime = { workspace = true }
```

### 4.4 Proposed `use` rewrites

```rust
// src/lib.rs
// BEFORE
use frame::prelude::*;
#[frame::pallet]
// AFTER
use frame_support::pallet_prelude::*;
use frame_system::pallet_prelude::*;
#[frame_support::pallet]
```

```rust
// src/default_weights.rs:21
// BEFORE
use frame::{deps::frame_support::weights::constants::*, weights_prelude::*};
// AFTER
use core::marker::PhantomData;
use frame_support::{
    traits::Get,
    weights::{constants::{ParityDbWeight, RocksDbWeight, *}, Weight},
};
```

```rust
// src/weights.rs:70
// BEFORE: use frame::weights_prelude::*;
// AFTER:
use core::marker::PhantomData;
use frame_support::{traits::Get, weights::{constants::{ParityDbWeight, RocksDbWeight}, Weight}};
```

```rust
// src/mmr/mod.rs:23
// BEFORE: use frame::traits;
// AFTER:  use sp_runtime::traits;   // only `Hash` is consumed below
```

```rust
// src/mmr/mmr.rs
// BEFORE
use frame::prelude::*;
// (later)  H: frame::traits::Hash,
// AFTER
use frame_support::pallet_prelude::*;
use frame_system::pallet_prelude::*;
// (later)  H: sp_runtime::traits::Hash,
```

```rust
// src/mmr/storage.rs:28-34
// BEFORE
use frame::{
    deps::{
        sp_core::offchain::StorageKind,
        sp_io::{offchain, offchain_index},
    },
    prelude::*,
};
// AFTER
use frame_support::pallet_prelude::*;
use frame_system::pallet_prelude::*;
use sp_core::offchain::StorageKind;
use sp_io::{offchain, offchain_index};
```

### 4.5 Risk notes

- `weights_prelude` re-exports `frame_system` itself (the crate). If anything in
  `default_weights.rs` references `frame_system::Pallet` or similar via the wildcard,
  add `use frame_system;` (extern alias) explicitly. A grep of those files shows
  none currently — verify after edit.
- `frame::traits::Hash` is `sp_runtime::traits::Hash` (the umbrella merges
  `frame_support::traits::*` and `sp_runtime::traits::*`; `Hash` only exists in the
  latter, so the rewrite is unambiguous).

### 4.6 `[features]` adjustments

```toml
std = [
    "codec/std",
    "frame-support/std",
    "frame-system/std",
    "log/std",
    "scale-info/std",
    "sp-core/std",
    "sp-io/std",
    "sp-mmr-primitives/std",
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
```

Tests/benchmarking/mock will need the same rewrite later.

---

## 5. `pallet-migrations`

### 5.1 `frame::*` usage inventory

Production source already uses explicit crates. The `frame` workspace dep is in
Cargo.toml but the only `frame::` reference in production code is the
`weights.rs` macro template:

| File:line                         | Path                                              |
|-----------------------------------|---------------------------------------------------|
| `src/weights.rs:70`               | `use frame::weights_prelude::*;`                  |

Everything else (`src/lib.rs`, `src/migrations.rs`) already uses
`frame_support::*`, `frame_system::*`, `sp_core`, `sp_io`, `sp_runtime` directly.

### 5.2 Required underlying crates

`frame_support`, `frame_system`, `sp_core`, `sp_io`, `sp_runtime` — **all already
explicit** in this Cargo.toml. The `frame = ...` line is essentially dead weight
at the production-code level (only `weights.rs` references it).

### 5.3 Proposed `[dependencies]` replacement

```toml
# REMOVE:
# frame = { workspace = true, features = ["runtime"] }

# (no additions needed — frame-support, frame-system, sp-core, sp-io, sp-runtime
# are already declared)
```

### 5.4 Proposed `use` rewrites

```rust
// src/weights.rs:70
// BEFORE: use frame::weights_prelude::*;
// AFTER:
use core::marker::PhantomData;
use frame_support::{traits::Get, weights::{constants::{ParityDbWeight, RocksDbWeight}, Weight}};
```

No other rewrites in production code.

### 5.5 Risk notes

This pallet is the cleanest of the bunch. Only sanity-check is whether
`frame-benchmarking` (which is currently `optional`) has a benchmarking.rs path
that uses `frame::benchmarking::prelude::*`; that gets handled in the
benchmarking-pass later.

### 5.6 `[features]` adjustments

Drop every `frame/*` flag — the equivalents already exist for the underlying crates.

```toml
std = [
    "codec/std",
    "frame-benchmarking?/std",
    "frame-support/std",
    "frame-system/std",
    "log/std",
    "scale-info/std",
    "sp-core/std",
    "sp-io/std",
    "sp-runtime/std",
]
runtime-benchmarks = [
    "frame-benchmarking/runtime-benchmarks",
    "frame-support/runtime-benchmarks",
    "frame-system/runtime-benchmarks",
    "sp-runtime/runtime-benchmarks",
]
try-runtime = [
    "frame-executive/try-runtime",
    "frame-support/try-runtime",
    "frame-system/try-runtime",
    "sp-runtime/try-runtime",
]
```

---

## 6. `pallet-mixnet`

### 6.1 `frame::*` usage inventory

| File:line             | Path                                                                  |
|-----------------------|------------------------------------------------------------------------|
| `src/lib.rs:30-36`    | `use frame::{deps::{sp_io::{self, MultiRemovalResults}, sp_runtime}, prelude::*};` |
| `src/lib.rs:175`      | `#[frame::pallet(dev_mode)]`                                          |
| `src/lib.rs:549`      | `impl<T: Config> sp_runtime::BoundToRuntimeAppPublic for Pallet<T>` (already explicit `sp_runtime`) |

Identifiers from prelude: `BoundedVec`, `BlockNumberFor`, `EstimateNextSessionRotation`,
`Get`, `MaxEncodedLen`, `Encode`/`Decode`/`TypeInfo`/`DecodeWithMemTracking` (codec direct),
`StorageValue`, `ValueQuery`, `Hooks`, `DispatchResult`, `OriginFor`, `OneSessionHandler`
(from `frame_support::traits` via prelude).

### 6.2 Required underlying crates

`frame_support`, `frame_system`, `sp_io`, `sp_runtime`. (`sp_application_crypto`,
`sp_mixnet`, `serde` already explicit.)

### 6.3 Proposed `[dependencies]` replacement

```toml
# REMOVE:
# frame = { workspace = true, features = ["runtime"] }

# ADD:
frame-support = { workspace = true }
frame-system = { workspace = true }
sp-io = { workspace = true }
sp-runtime = { workspace = true }
```

### 6.4 Proposed `use` rewrites

```rust
// BEFORE
use frame::{
    deps::{
        sp_io::{self, MultiRemovalResults},
        sp_runtime,
    },
    prelude::*,
};
#[frame::pallet(dev_mode)]

// AFTER
use frame_support::pallet_prelude::*;
use frame_system::pallet_prelude::*;
use sp_io::{self, MultiRemovalResults};
use sp_runtime;
#[frame_support::pallet(dev_mode)]
```

(The `use sp_runtime;` line is redundant if you reference `sp_runtime::*` paths
fully; in this file `sp_runtime::BoundToRuntimeAppPublic` is referenced in an
`impl` block — keeping the bare `use sp_runtime;` is a no-op once the crate is a
direct dep, so simply remove that line.)

### 6.5 Risk notes

- `dev_mode` argument passes through unchanged; `frame_support::pallet(dev_mode)`
  is valid syntax.
- `MultiRemovalResults` is at `sp_io::MultiRemovalResults` — confirmed.

### 6.6 `[features]` adjustments

```toml
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

---

## 7. `pallet-multisig`

### 7.1 `frame::*` usage inventory

| File:line                             | Path                                                                |
|---------------------------------------|---------------------------------------------------------------------|
| `src/lib.rs:53-56`                    | `use frame::{prelude::*, traits::{Currency, ReservableCurrency}};`  |
| `src/lib.rs:141`                      | `#[frame::pallet]`                                                  |
| `src/migrations.rs:21`                | `use frame::prelude::*;`                                            |
| `src/migrations.rs:26`                | `type OpaqueCall<T> = frame::traits::WrapperKeepOpaque<...>`        |
| `src/migrations.rs:28`                | `#[frame::storage_alias]`                                           |
| `src/migrations.rs:39, 72` (`try-runtime`) | `frame::try_runtime::TryRuntimeError`                          |
| `src/migrations.rs:46`                | `use frame::traits::ReservableCurrency as _;`                       |
| `src/weights.rs:70`                   | `use frame::weights_prelude::*;`                                    |

Prelude identifiers used: `BoundedVec`, `BlockNumberFor` (also redefined as a project
local type from `BlockNumberProvider`), `BlockNumberProvider`, `MaxEncodedLen`, `IsType`,
`StorageVersion`, `Hooks`, `DispatchResult`, `DispatchResultWithPostInfo`,
`DispatchErrorWithPostInfo`, `OriginFor`, `ensure!`, `Weight`.

### 7.2 Required underlying crates

`frame_support`, `frame_system`, `sp_runtime` (for `TryRuntimeError`,
`BoundedVec`, `BlockNumberProvider`).

### 7.3 Proposed `[dependencies]` replacement

```toml
# REMOVE:
# frame = { workspace = true, features = ["runtime"] }

# ADD:
frame-support = { workspace = true }
frame-system = { workspace = true }
sp-runtime = { workspace = true }
```

### 7.4 Proposed `use` rewrites

```rust
// src/lib.rs
// BEFORE
use frame::{
    prelude::*,
    traits::{Currency, ReservableCurrency},
};
#[frame::pallet]
// AFTER
use frame_support::{
    pallet_prelude::*,
    traits::{Currency, ReservableCurrency},
};
use frame_system::pallet_prelude::*;
#[frame_support::pallet]
```

```rust
// src/migrations.rs
// BEFORE
use frame::prelude::*;
type OpaqueCall<T> = frame::traits::WrapperKeepOpaque<<T as Config>::RuntimeCall>;
#[frame::storage_alias]
// (try-runtime gated)
fn pre_upgrade() -> Result<Vec<u8>, frame::try_runtime::TryRuntimeError> { ... }
use frame::traits::ReservableCurrency as _;

// AFTER
use frame_support::pallet_prelude::*;
use frame_system::pallet_prelude::*;
type OpaqueCall<T> = frame_support::traits::WrapperKeepOpaque<<T as Config>::RuntimeCall>;
#[frame_support::storage_alias]
// (try-runtime gated)
fn pre_upgrade() -> Result<Vec<u8>, sp_runtime::TryRuntimeError> { ... }
use frame_support::traits::ReservableCurrency as _;
```

```rust
// src/weights.rs:70 — same recipe as #4 above
use core::marker::PhantomData;
use frame_support::{traits::Get, weights::{constants::{ParityDbWeight, RocksDbWeight}, Weight}};
```

### 7.5 Risk notes

- `WrapperKeepOpaque` is `frame_support::traits::WrapperKeepOpaque` — confirmed
  (it is in `frame_support::traits::*` glob, which is what `frame::traits` re-exports).
- `#[frame::storage_alias]` macro = `frame_support::storage_alias` (confirmed at
  `frame/src/lib.rs:149`).

### 7.6 `[features]` adjustments

```toml
std = [
    "codec/std",
    "frame-support/std",
    "frame-system/std",
    "log/std",
    "scale-info/std",
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

---

## 8. `pallet-nft-fractionalization`

### 8.1 `frame::*` usage inventory

| File:line                | Path                                  |
|--------------------------|---------------------------------------|
| `src/lib.rs:50`          | `use frame::prelude::*;`              |
| `src/lib.rs:51`          | `use frame_system::Config as SystemConfig;` (already explicit) |
| `src/lib.rs:56`          | `#[frame::pallet]`                    |
| `src/weights.rs:70`      | `use frame::weights_prelude::*;`      |

Inside the `#[frame::pallet] pub mod pallet { ... }` block, the body imports
sub-paths via `use fungible::*;`, `use fungibles::*;`, `use nonfungibles_v2::*;`.
Those names come from `frame::prelude::*`'s re-export of `frame::token::*` (==
`frame_support::traits::tokens::*`).

`src/types.rs` only uses `super::*` plus codec/scale-info — no direct `frame::`
references.

### 8.2 Required underlying crates

`frame_support`, `frame_system`. (`scale-info`, `codec` already explicit.)

### 8.3 Proposed `[dependencies]` replacement

```toml
# REMOVE:
# frame = { workspace = true, features = ["runtime"] }

# ADD:
frame-support = { workspace = true }
frame-system = { workspace = true }
```

### 8.4 Proposed `use` rewrites

```rust
// src/lib.rs
// BEFORE
use frame::prelude::*;
use frame_system::Config as SystemConfig;
#[frame::pallet]
// AFTER
use frame_support::pallet_prelude::*;
use frame_system::{pallet_prelude::*, Config as SystemConfig};
#[frame_support::pallet]
```

Inside the inner `pub mod pallet { ... }` body (around lines 60–67), the
existing `use fungible::{...};`, `use fungibles::{...};`, `use nonfungibles_v2::{...};`
lines need a single-line origin change at the top of the inner module:

```rust
// BEFORE (implicit via `use super::*;` then prelude re-exports)
use fungible::{ ... };
use fungibles::{ ... };
use nonfungibles_v2::{ ... };

// AFTER (resolve via frame_support traits paths)
use frame_support::traits::tokens::{
    fungible::{
        hold::Mutate as HoldMutateFungible, Inspect as InspectFungible, Mutate as MutateFungible,
    },
    fungibles::{
        metadata::{MetadataDeposit, Mutate as MutateMetadata},
        Create, Destroy, Inspect, Mutate,
    },
    nonfungibles_v2::{Inspect as NonFungiblesInspect, Transfer},
};
```

```rust
// src/weights.rs:70 — same as #4
```

### 8.5 Risk notes

- Make sure the `fungible::Inspect as FunInspect` rename used in `types.rs` keeps
  working; it does, since `types.rs` does `use super::*;` and the renamed import
  will reach there.
- Storage layout etc. is untouched.

### 8.6 `[features]` adjustments

```toml
std = [
    "codec/std",
    "frame-support/std",
    "frame-system/std",
    "scale-info/std",
]
runtime-benchmarks = [
    "frame-support/runtime-benchmarks",
    "frame-system/runtime-benchmarks",
]
try-runtime = [
    "frame-support/try-runtime",
    "frame-system/try-runtime",
]
```

---

## 9. `pallet-nis`

### 9.1 `frame::*` usage inventory

| File:line                 | Path                                  |
|---------------------------|---------------------------------------|
| `src/lib.rs:93`           | `use frame::prelude::*;`              |
| `src/lib.rs:176`          | `#[frame::pallet]`                    |
| `src/weights.rs:70`       | `use frame::weights_prelude::*;`      |

Identifiers used from prelude: `BoundedVec`, `BlockNumberFor`, `MaxEncodedLen`,
`Hooks`, `DispatchResult`, `DispatchError`, `Get`, `OriginFor`, `Encode`/`Decode`/
`TypeInfo`, `StorageMap`, `StorageValue`, `Blake2_128Concat`, `ValueQuery`, `Saturating`,
`PalletId`, `Perquintill` (from `arithmetic::*`).

After prelude, the `pallet` body adds:

```rust
use fungible::{Balanced as FunBalanced, Inspect as FunInspect, Mutate as FunMutate, MutateHold as FunMutateHold};
use nonfungible::{Inspect as NftInspect, Transfer as NftTransfer};
use tokens::{Balance, Restriction::*};
```

These names come from `frame::token::*` (= `frame_support::traits::tokens::*`).

### 9.2 Required underlying crates

`frame_support`, `frame_system`, `sp_runtime` (for `BoundedVec`, `Saturating`,
`Perquintill`/`sp_arithmetic::Perquintill` re-export).

### 9.3 Proposed `[dependencies]` replacement

```toml
# REMOVE:
# frame = { workspace = true, features = ["runtime"] }

# ADD:
frame-support = { workspace = true }
frame-system = { workspace = true }
sp-arithmetic = { workspace = true }   # for Perquintill
sp-runtime = { workspace = true }
```

### 9.4 Proposed `use` rewrites

```rust
// src/lib.rs
// BEFORE
use frame::prelude::*;
use fungible::{ ... };
use nonfungible::{ ... };
use tokens::{ ... };
#[frame::pallet]
// AFTER
use frame_support::{
    pallet_prelude::*,
    traits::tokens::{
        fungible::{
            Balanced as FunBalanced, Inspect as FunInspect, Mutate as FunMutate,
            MutateHold as FunMutateHold,
        },
        nonfungible::{Inspect as NftInspect, Transfer as NftTransfer},
        Balance, Restriction::*,
    },
    PalletId,
};
use frame_system::pallet_prelude::*;
use sp_arithmetic::Perquintill;
use sp_runtime::{traits::{Saturating, AccountIdConversion}, BoundedVec};
#[frame_support::pallet]
```

```rust
// src/weights.rs:70 — same as #4
```

### 9.5 Risk notes

`Perquintill` and `sp_arithmetic::*` come through `frame::arithmetic::*` /
`frame::prelude::*`. After the rewrite, ensure both are referenced from
`sp_arithmetic`. Numerics like `FixedU128` should also come from `sp_arithmetic`.

### 9.6 `[features]` adjustments

```toml
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
    "sp-runtime/runtime-benchmarks",
]
try-runtime = [
    "frame-support/try-runtime",
    "frame-system/try-runtime",
    "sp-runtime/try-runtime",
]
```

---

## 10. `pallet-node-authorization`

### 10.1 `frame::*` usage inventory

| File:line               | Path                                                                     |
|-------------------------|---------------------------------------------------------------------------|
| `src/lib.rs:52-55`      | `use frame::{deps::{sp_core::OpaquePeerId as PeerId, sp_io}, prelude::*};` |
| `src/lib.rs:61`         | `#[frame::pallet]`                                                        |
| `src/weights.rs:24`     | `use frame::weights_prelude::*;`                                          |

Identifiers used from prelude: `Vec`, `BTreeSet` (codec), `Hooks`, `BlockNumberFor`,
`StaticLookup`, `OriginFor`, `DispatchResult`, `ensure!`, `StorageMap`, `StorageValue`,
`ValueQuery`, `Blake2_128Concat`, `Get`, `Encode`/`Decode`/`TypeInfo`.

### 10.2 Required underlying crates

`frame_support`, `frame_system`, `sp_core`, `sp_io`, `sp_runtime` (for `StaticLookup`).

### 10.3 Proposed `[dependencies]` replacement

```toml
# REMOVE:
# frame = { workspace = true, features = ["runtime"] }

# ADD:
frame-support = { workspace = true }
frame-system = { workspace = true }
sp-core = { workspace = true }
sp-io = { workspace = true }
sp-runtime = { workspace = true }
```

### 10.4 Proposed `use` rewrites

```rust
// src/lib.rs
// BEFORE
use frame::{
    deps::{sp_core::OpaquePeerId as PeerId, sp_io},
    prelude::*,
};
#[frame::pallet]
// AFTER
use frame_support::pallet_prelude::*;
use frame_system::pallet_prelude::*;
use sp_core::OpaquePeerId as PeerId;
use sp_io;
use sp_runtime::traits::StaticLookup;
#[frame_support::pallet]
```

```rust
// src/weights.rs:24 — same as #4
```

### 10.5 Risk notes

`type AccountIdLookupOf<T> = <<T as frame_system::Config>::Lookup as StaticLookup>::Source;`
is at `src/lib.rs:59` — it depends on `StaticLookup` being in scope (added above).

### 10.6 `[features]` adjustments

```toml
std = [
    "codec/std",
    "frame-support/std",
    "frame-system/std",
    "scale-info/std",
    "sp-core/std",
    "sp-io/std",
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
```

---

## 11. `pallet-paged-list`

### 11.1 `frame::*` usage inventory

| File:line                          | Path                                                                                                     |
|------------------------------------|----------------------------------------------------------------------------------------------------------|
| `src/lib.rs:35` (doc-link)         | `frame::deps::frame_support::storage::StorageList`                                                       |
| `src/lib.rs:74`                    | `use frame::{prelude::*, traits::StorageInstance};`                                                      |
| `src/lib.rs:77`                    | `#[frame::pallet]`                                                                                       |
| `src/paged_list.rs:29-34`          | `use frame::{deps::sp_io, prelude::*, runtime::prelude::storage::{StorageAppender, StorageList, StoragePrefixedContainer}, traits::{Get, StorageInstance}};` |
| `src/paged_list.rs:63, 66, 86` (doc) | `frame::deps::sp_io::storage::*`, `frame::deps::frame_support::storage::StorageList::Appender`         |

(Lines 410, 431 are inside `#[cfg(test)] mod test` — out of scope.)

Identifiers used: `Vec`, `MaxEncodedLen`, `FullCodec`, `Encode`, `Decode`, `EncodeLike`,
`StorageInstance`, `StorageAppender`, `StorageList`, `StoragePrefixedContainer`,
`Get`, `PhantomData`, `sp_io::storage::{get, set, append, clear, exists}`.

### 11.2 Required underlying crates

`frame_support`, `frame_system`, `sp_io`, `sp_runtime` (for `BoundedVec` if any —
actually `paged-list` doesn't use it, but harmless). Also `sp-metadata-ir`
already optional.

The `StorageAppender`, `StorageList`, `StoragePrefixedContainer` types live at
`frame_support::storage::*` (the umbrella's `runtime::prelude::storage` is just a
glob re-export from there via `frame_support::pallet_prelude::*` → which doesn't
itself include them. They actually surface via the runtime prelude's wildcard
re-export of `frame_support` storage). Verify after edit by reading the
`frame_support::storage` module — for the rewrite, point them at
`frame_support::storage::{StorageAppender, StorageList, StoragePrefixedContainer}`.

### 11.3 Proposed `[dependencies]` replacement

```toml
# REMOVE:
# frame = { workspace = true, features = ["runtime"] }

# ADD:
frame-support = { workspace = true }
frame-system = { workspace = true }
sp-io = { workspace = true }
```

### 11.4 Proposed `use` rewrites

```rust
// src/lib.rs:74-77
// BEFORE
use frame::{prelude::*, traits::StorageInstance};
#[frame::pallet]
// AFTER
use frame_support::{pallet_prelude::*, traits::StorageInstance};
use frame_system::pallet_prelude::*;
#[frame_support::pallet]
```

```rust
// src/paged_list.rs:29-34
// BEFORE
use frame::{
    deps::sp_io,
    prelude::*,
    runtime::prelude::storage::{StorageAppender, StorageList, StoragePrefixedContainer},
    traits::{Get, StorageInstance},
};
// AFTER
use frame_support::{
    pallet_prelude::*,
    storage::{StorageAppender, StorageList, StoragePrefixedContainer},
    traits::{Get, StorageInstance},
};
use sp_io;
```

Doc-comments at lines 35, 63, 66, 86 referencing `frame::deps::*` paths can be
updated to `frame_support::storage::*` and `sp_io::storage::*`.

### 11.5 Risk notes

- The `runtime::prelude::storage::*` path is the most umbrella-specific path in
  the whole 17-pallet set. It resolves to `frame_support::storage::*`. Confirm by
  checking `frame_support`'s `lib.rs` once before the mass edit.
- `paged-list` does NOT need `sp_runtime` or `sp_core` based on grep.

### 11.6 `[features]` adjustments

```toml
std = [
    "codec/std",
    "frame-support/std",
    "frame-system/std",
    "scale-info/std",
    "sp-io/std",
    "sp-metadata-ir/std",
]
runtime-benchmarks = [
    "frame-support/runtime-benchmarks",
    "frame-system/runtime-benchmarks",
]
try-runtime = [
    "frame-support/try-runtime",
    "frame-system/try-runtime",
]
```

---

## 12. `pallet-proxy`

### 12.1 `frame::*` usage inventory

| File:line                 | Path                                                                       |
|---------------------------|----------------------------------------------------------------------------|
| `src/lib.rs:38-41`        | `use frame::{prelude::*, traits::{Currency, InstanceFilter, ReservableCurrency}};` |
| `src/lib.rs:123`          | `#[frame::pallet]`                                                         |
| `src/lib.rs:156`          | trait bound `+ frame::traits::InstanceFilter<<Self as Config>::RuntimeCall>` |
| `src/lib.rs:999`          | `use frame::traits::{InstanceFilter as _, OriginTrait as _};`              |
| `src/weights.rs:69`       | `use frame::weights_prelude::*;`                                           |

Identifiers from prelude: `BoundedVec`, `BlockNumberProvider`, `Hash`, `MaxEncodedLen`,
`StaticLookup`, `IsType`, `DispatchResult`, `DispatchResultWithPostInfo`, `DispatchError`,
`OriginFor`, `Hooks`, `Encode`/`Decode`/`TypeInfo`, `StorageMap`, `StorageVersion`,
`ensure!`, `Twox64Concat`/`Blake2_128Concat`, `Weight`.

### 12.2 Required underlying crates

`frame_support`, `frame_system`, `sp_runtime`.

### 12.3 Proposed `[dependencies]` replacement

```toml
# REMOVE:
# frame = { workspace = true, features = ["runtime"] }

# ADD:
frame-support = { workspace = true }
frame-system = { workspace = true }
sp-runtime = { workspace = true }
```

### 12.4 Proposed `use` rewrites

```rust
// src/lib.rs
// BEFORE
use frame::{
    prelude::*,
    traits::{Currency, InstanceFilter, ReservableCurrency},
};
#[frame::pallet]
// (later in trait bound)
+ frame::traits::InstanceFilter<<Self as Config>::RuntimeCall>
// (line 999)
use frame::traits::{InstanceFilter as _, OriginTrait as _};

// AFTER
use frame_support::{
    pallet_prelude::*,
    traits::{Currency, InstanceFilter, OriginTrait, ReservableCurrency},
};
use frame_system::pallet_prelude::*;
use sp_runtime::traits::{BlockNumberProvider, Hash, StaticLookup};
#[frame_support::pallet]
// trait bound becomes
+ frame_support::traits::InstanceFilter<<Self as Config>::RuntimeCall>
// line 999 becomes
use frame_support::traits::{InstanceFilter as _, OriginTrait as _};
```

```rust
// src/weights.rs:69 — same as #4
```

### 12.5 Risk notes

- `frame::traits::InstanceFilter` is `frame_support::traits::InstanceFilter` (it
  is in `frame_support::traits::*`, not `sp_runtime::traits::*`). Same for
  `OriginTrait`.
- The pallet defines a project-local `BlockNumberFor<T>` (line 50) using
  `BlockNumberProvider` — `BlockNumberProvider` must remain in scope after the
  rewrite (covered above).

### 12.6 `[features]` adjustments

```toml
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

(Adjust to match the existing dev/optional dep list of the file.)

---

## 13. `pallet-recovery`

### 13.1 `frame::*` usage inventory

| File:line                 | Path                                                          |
|---------------------------|----------------------------------------------------------------|
| `src/lib.rs:157-160`      | `use frame::{prelude::*, traits::{Currency, ReservableCurrency}};` |
| `src/lib.rs:228`          | `#[frame::pallet]`                                            |
| `src/weights.rs:69`       | `use frame::weights_prelude::*;`                              |

Identifiers from prelude: `BoundedVec`, `BlockNumberProvider`, `StaticLookup`, `IsType`,
`MaxEncodedLen`, `DispatchResult`, `DispatchResultWithPostInfo`, `DispatchError`,
`OriginFor`, `Hooks`, `Encode`/`Decode`/`TypeInfo`, `StorageMap`, `StorageDoubleMap`,
`StorageVersion`, `Twox64Concat`/`Blake2_128Concat`, `ValueQuery`/`OptionQuery`,
`ensure!`, `Weight`.

### 13.2 Required underlying crates

`frame_support`, `frame_system`, `sp_runtime`.

### 13.3 Proposed `[dependencies]` replacement

```toml
# REMOVE:
# frame = { workspace = true, features = ["runtime"] }

# ADD:
frame-support = { workspace = true }
frame-system = { workspace = true }
sp-runtime = { workspace = true }
```

### 13.4 Proposed `use` rewrites

```rust
// src/lib.rs
// BEFORE
use frame::{
    prelude::*,
    traits::{Currency, ReservableCurrency},
};
#[frame::pallet]
// AFTER
use frame_support::{
    pallet_prelude::*,
    traits::{Currency, ReservableCurrency},
};
use frame_system::pallet_prelude::*;
use sp_runtime::traits::{BlockNumberProvider, StaticLookup};
#[frame_support::pallet]
```

```rust
// src/weights.rs:69 — same as #4
```

### 13.5 Risk notes

None.

### 13.6 `[features]` adjustments

```toml
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
    "sp-runtime/runtime-benchmarks",
]
try-runtime = [
    "frame-support/try-runtime",
    "frame-system/try-runtime",
    "pallet-balances/try-runtime",
    "sp-runtime/try-runtime",
]
```

---

## 14. `pallet-safe-mode`

### 14.1 `frame::*` usage inventory

| File:line                       | Path                                                                                  |
|---------------------------------|---------------------------------------------------------------------------------------|
| `src/lib.rs:75-81`              | `use frame::{prelude::{fungible::hold::{Inspect, Mutate}, *}, traits::{fungible, CallMetadata, GetCallMetadata, SafeModeNotify}};` |
| `src/lib.rs:89`                 | `#[frame::pallet]`                                                                    |
| `src/lib.rs:611, 625, 629, 633, 638` | `frame::traits::SafeMode`, `frame::traits::SafeModeError`                        |
| `src/weights.rs:70`             | `use frame::weights_prelude::*;`                                                      |

Identifiers used from prelude: `BlockNumberFor`, `MaxEncodedLen`, `IsType`, `Get`,
`EnsureOrigin`, `OriginFor`, `Hooks`, `DispatchResult`, `Saturating`, `Encode`/`Decode`/
`TypeInfo`, `StorageMap`, `StorageValue`, `Twox64Concat`/`Blake2_128Concat`,
`ValueQuery`/`OptionQuery`, `Weight`, `ensure!`.

### 14.2 Required underlying crates

`frame_support`, `frame_system`, `sp_runtime`.

### 14.3 Proposed `[dependencies]` replacement

```toml
# REMOVE:
# frame = { workspace = true, features = ["runtime"] }

# ADD:
frame-support = { workspace = true }
frame-system = { workspace = true }
sp-runtime = { workspace = true }
```

### 14.4 Proposed `use` rewrites

```rust
// src/lib.rs:75-81
// BEFORE
use frame::{
    prelude::{
        fungible::hold::{Inspect, Mutate},
        *,
    },
    traits::{fungible, CallMetadata, GetCallMetadata, SafeModeNotify},
};
#[frame::pallet]
// AFTER
use frame_support::{
    pallet_prelude::*,
    traits::{
        fungible::{
            self,
            hold::{Inspect, Mutate},
        },
        CallMetadata, GetCallMetadata, SafeModeNotify,
    },
};
use frame_system::pallet_prelude::*;
use sp_runtime::traits::Saturating;
#[frame_support::pallet]
```

```rust
// src/lib.rs:611-638 (impl block)
// BEFORE: impl<T: Config> frame::traits::SafeMode for Pallet<T> { ... }
//         frame::traits::SafeModeError
// AFTER:  impl<T: Config> frame_support::traits::SafeMode for Pallet<T> { ... }
//         frame_support::traits::SafeModeError
```

```rust
// src/weights.rs:70 — same as #4
```

### 14.5 Risk notes

- Confirm `SafeMode`/`SafeModeError`/`SafeModeNotify` all live in
  `frame_support::traits::*` — they do (not in `sp_runtime::traits`).
- The somewhat unusual nested `prelude::{fungible::hold::{Inspect, Mutate}, *}`
  pattern flattens correctly into `frame_support::traits::tokens::fungible::hold`.

### 14.6 `[features]` adjustments

```toml
std = [
    "codec/std",
    "frame-support/std",
    "frame-system/std",
    "pallet-balances?/std",
    "pallet-proxy?/std",
    "pallet-utility?/std",
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
    "pallet-balances?/try-runtime",
    "pallet-proxy?/try-runtime",
    "pallet-utility?/try-runtime",
    "sp-runtime/try-runtime",
]
```

---

## 15. `pallet-salary`

### 15.1 `frame::*` usage inventory

| File:line                 | Path                                                                  |
|---------------------------|------------------------------------------------------------------------|
| `src/lib.rs:23-26`        | `use frame::{prelude::*, traits::tokens::{GetSalary, Pay, PaymentStatus}};` |
| `src/lib.rs:78`           | `#[frame::pallet]`                                                    |
| `src/weights.rs:70`       | `use frame::weights_prelude::*;`                                      |

Identifiers from prelude: `PhantomData`, `BlockNumberFor`, `Get`, `IsType`, `Pays`,
`OriginFor`, `DispatchResult`, `DispatchResultWithPostInfo`, `DispatchError`, `Hooks`,
`Encode`/`Decode`/`TypeInfo`, `StorageMap`, `StorageValue`, `Blake2_128Concat`,
`ValueQuery`/`OptionQuery`, `Weight`, `ensure!`, `Convert`, `RankedMembers` (the trait,
from `frame_support::traits::*`).

### 15.2 Required underlying crates

`frame_support`, `frame_system`, `sp_runtime` (for `Convert`).

### 15.3 Proposed `[dependencies]` replacement

```toml
# REMOVE:
# frame = { workspace = true, features = ["runtime"] }

# ADD:
frame-support = { workspace = true }
frame-system = { workspace = true }
sp-runtime = { workspace = true }
```

### 15.4 Proposed `use` rewrites

```rust
// src/lib.rs
// BEFORE
use frame::{
    prelude::*,
    traits::tokens::{GetSalary, Pay, PaymentStatus},
};
#[frame::pallet]
// AFTER
use frame_support::{
    pallet_prelude::*,
    traits::{
        tokens::{GetSalary, Pay, PaymentStatus},
        RankedMembers,
    },
};
use frame_system::pallet_prelude::*;
use sp_runtime::traits::Convert;
#[frame_support::pallet]
```

```rust
// src/weights.rs:70 — same as #4
```

### 15.5 Risk notes

`RankedMembers` is in `frame_support::traits::*` (re-exported into the umbrella prelude).

### 15.6 `[features]` adjustments

```toml
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
    "sp-runtime/runtime-benchmarks",
]
try-runtime = [
    "frame-support/try-runtime",
    "frame-system/try-runtime",
    "sp-runtime/try-runtime",
]
```

---

## 16. `pallet-tx-pause`

### 16.1 `frame::*` usage inventory

| File:line              | Path                                                                       |
|------------------------|----------------------------------------------------------------------------|
| `src/lib.rs:78-81`     | `use frame::{prelude::*, traits::{TransactionPause, TransactionPauseError}};` |
| `src/lib.rs:96`        | `#[frame::pallet]`                                                         |
| `src/weights.rs:70`    | `use frame::weights_prelude::*;`                                           |

Identifiers used: `Vec`, `BoundedVec`, `BlockNumberFor`, `IsType`, `Get`, `OriginFor`,
`DispatchResult`, `Hooks`, `MaxEncodedLen`, `Encode`/`Decode`/`TypeInfo`, `StorageMap`,
`Twox64Concat`, `OptionQuery`/`ValueQuery`, `Weight`, `ensure!`, `GetCallMetadata`,
`CallMetadata` (the latter two come from `frame::prelude::*` via `transaction::*`
re-export).

### 16.2 Required underlying crates

`frame_support`, `frame_system`, `sp_runtime`.

### 16.3 Proposed `[dependencies]` replacement

```toml
# REMOVE:
# frame = { workspace = true, features = ["runtime"] }

# ADD:
frame-support = { workspace = true }
frame-system = { workspace = true }
sp-runtime = { workspace = true }
```

### 16.4 Proposed `use` rewrites

```rust
// src/lib.rs:78-81
// BEFORE
use frame::{
    prelude::*,
    traits::{TransactionPause, TransactionPauseError},
};
#[frame::pallet]
// AFTER
use frame_support::{
    pallet_prelude::*,
    traits::{CallMetadata, GetCallMetadata, TransactionPause, TransactionPauseError},
};
use frame_system::pallet_prelude::*;
#[frame_support::pallet]
```

```rust
// src/weights.rs:70 — same as #4
```

### 16.5 Risk notes

`CallMetadata` and `GetCallMetadata` come from the prelude's `transaction::*` re-export
(`frame_support::traits::{CallMetadata, GetCallMetadata}`). They're consumed at lines
281, 285 of `src/lib.rs` — must remain in scope after the rewrite.

### 16.6 `[features]` adjustments

```toml
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

---

## 17. `pallet-whitelist`

### 17.1 `frame::*` usage inventory

| File:line               | Path                                                                                  |
|-------------------------|---------------------------------------------------------------------------------------|
| `src/lib.rs:47-50`      | `use frame::{prelude::*, traits::{QueryPreimage, StorePreimage}};`                    |
| `src/lib.rs:55`         | `#[frame::pallet]`                                                                    |
| `src/lib.rs:171`        | `frame::deps::frame_support::MAX_EXTRINSIC_DEPTH`                                     |
| `src/weights.rs:70`     | `use frame::weights_prelude::*;`                                                      |

Identifiers from prelude: `Box`, `Encode`, `DecodeLimit`, `FullCodec`, `IsType`,
`OriginFor`, `DispatchResult`, `DispatchResultWithPostInfo`, `DispatchError`,
`MaxEncodedLen`, `Hooks`, `StorageMap`, `Twox64Concat`/`Blake2_128Concat`,
`OptionQuery`/`ValueQuery`, `Weight`, `ensure!`, `DispatchInfoOf`.

### 17.2 Required underlying crates

`frame_support`, `frame_system`, `sp_runtime`.

### 17.3 Proposed `[dependencies]` replacement

```toml
# REMOVE:
# frame = { workspace = true, features = ["runtime"] }

# ADD:
frame-support = { workspace = true }
frame-system = { workspace = true }
sp-runtime = { workspace = true }
```

### 17.4 Proposed `use` rewrites

```rust
// src/lib.rs
// BEFORE
use frame::{
    prelude::*,
    traits::{QueryPreimage, StorePreimage},
};
#[frame::pallet]
// (later)  frame::deps::frame_support::MAX_EXTRINSIC_DEPTH

// AFTER
use frame_support::{
    pallet_prelude::*,
    traits::{QueryPreimage, StorePreimage},
};
use frame_system::pallet_prelude::*;
use sp_runtime::traits::DispatchInfoOf;
#[frame_support::pallet]
// (later)
frame_support::MAX_EXTRINSIC_DEPTH
```

```rust
// src/weights.rs:70 — same as #4
```

### 17.5 Risk notes

`MAX_EXTRINSIC_DEPTH` is a `pub const` in the root of `frame_support`. Confirm by
checking `frame_support` lib.rs once.

### 17.6 `[features]` adjustments

```toml
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

---

## Common patterns appendix (mechanizable)

These patterns cover ~80% of the work. Apply them with a script, then handle the
per-pallet outliers listed above by hand.

### P1 — `#[frame::pallet]` attribute

15 of 17 pallets have a single `#[frame::pallet]` (mixnet has
`#[frame::pallet(dev_mode)]`, paged-list has `#[frame::pallet]`, all preserved).

```text
sed -E 's/#\[frame::pallet(\([^)]*\))?\]/#[frame_support::pallet\1]/'
```

Affects: assets-freezer, atomic-swap, insecure-randomness-collective-flip,
merkle-mountain-range, mixnet, multisig, nft-fractionalization, nis,
node-authorization, paged-list, proxy, recovery, safe-mode, salary, tx-pause,
whitelist (16 of 17; migrations has none).

### P2 — `use frame::{prelude::*, traits::{...}};`

13 pallets use a variant of:

```rust
use frame::{
    prelude::*,
    traits::{ /* one or more trait identifiers */ },
};
```

Standard rewrite:

```rust
use frame_support::{
    pallet_prelude::*,
    traits::{ /* same identifiers, re-categorized below */ },
};
use frame_system::pallet_prelude::*;
// + sp_runtime imports for: BlockNumberProvider, StaticLookup, Saturating,
//   Convert, BlakeTwo256, Hash, etc. iff used in body.
```

The `traits::{...}` block survives intact almost always — `frame::traits` =
`frame_support::traits::*` ∪ `sp_runtime::traits::*` (wildcard merge in the
umbrella). The collisions in practice are:
- `Hash` (only in `sp_runtime::traits`) → `sp_runtime::traits::Hash`
- `BalanceStatus` (in `frame_support::traits::tokens::BalanceStatus`)
- `BlockNumberProvider`, `StaticLookup`, `Saturating`, `Convert`,
  `AccountIdConversion` → `sp_runtime::traits::*`
- Everything else in the surveyed pallets is in `frame_support::traits::*`
  (`Currency`, `ReservableCurrency`, `InstanceFilter`, `Randomness`,
  `OriginTrait`, `QueryPreimage`, `StorePreimage`, `TransactionPause`,
  `TransactionPauseError`, `SafeMode`, `SafeModeError`, `SafeModeNotify`,
  `CallMetadata`, `GetCallMetadata`, `WrapperKeepOpaque`, `RankedMembers`,
  `StorageInstance`, `GetSalary`, `Pay`, `PaymentStatus`, `Inspect`/`Mutate`/
  `MutateFreeze`/`InspectFreeze` and friends under `tokens::*`).

### P3 — `use frame::weights_prelude::*;` in `weights.rs`

11 pallets contain exactly one line at the top of `weights.rs`:

```rust
// BEFORE
use frame::weights_prelude::*;

// AFTER
use core::marker::PhantomData;
use frame_support::{
    traits::Get,
    weights::{constants::{ParityDbWeight, RocksDbWeight}, Weight},
};
```

Affects: merkle-mountain-range/`weights.rs`, migrations, multisig,
nft-fractionalization, nis, node-authorization (slightly different line number),
proxy, recovery, safe-mode, salary, tx-pause, whitelist. (And
merkle-mountain-range/`default_weights.rs` adds `weights::constants::*` glob —
expand to `weights::constants::{ParityDbWeight, RocksDbWeight, *}`.)

### P4 — `frame::try_runtime::TryRuntimeError` (gated)

```text
// BEFORE: frame::try_runtime::TryRuntimeError
// AFTER:  sp_runtime::TryRuntimeError
```

Affects: assets-freezer (`src/lib.rs:63`), multisig (`src/migrations.rs:39, 72`).
Gated under `cfg(feature = "try-runtime")` or `cfg(test)`.

### P5 — `#[frame::storage_alias]`

Single occurrence: multisig `src/migrations.rs:28`.

```text
// BEFORE: #[frame::storage_alias]
// AFTER:  #[frame_support::storage_alias]
```

### P6 — `frame::deps::sp_io`, `frame::deps::sp_core`, `frame::deps::frame_support`

Always replace with the bare crate name (`sp_io`, `sp_core`, `frame_support`)
once the crate is added as an explicit dep. Affects mixnet, node-authorization,
merkle-mountain-range/storage.rs, paged-list, whitelist.

### P7 — `frame::traits::Hash` and other `sp_runtime::traits::*` items used as types

Hash, BlockNumberProvider, StaticLookup, Saturating, Convert, AccountIdConversion
— rewrite to `sp_runtime::traits::<X>`.

### P8 — Cargo.toml

Universal recipe: drop `frame = { workspace = true, features = ["runtime"] }`,
add the explicit subset from §1.2/§2.2/etc. The almost-always-needed three are
`frame-support`, `frame-system`, `sp-runtime`. Add `sp-io` and/or `sp-core` only
when a `frame::deps::sp_io` / `frame::deps::sp_core` reference exists.

### P9 — `[features]` blocks

Universal recipe — replace each occurrence of `"frame/<flag>"` with the matching
`"<crate>/<flag>"` for every dep added. Always include the trio
`frame-support/<flag>`, `frame-system/<flag>`, `sp-runtime/<flag>` (where each
flag is one of `std`, `runtime-benchmarks`, `try-runtime`).

`runtime-benchmarks` blocks: keep the existing `pallet-*` lines (e.g.
`pallet-balances/runtime-benchmarks`) — they're orthogonal.

### Coverage summary

Patterns P1+P2+P3+P8+P9 alone fully convert: atomic-swap, insecure-randomness-
collective-flip, recovery, salary, tx-pause, whitelist (modulo P7 sp_runtime
trait additions). P1+P2+P3+P6+P8+P9 cover node-authorization. P5+P4 are
single-pallet fix-ups. The only manual-thinking pallet is **paged-list** (P11
above, the `runtime::prelude::storage::*` path needs verification), and even
that is a 1-line decision once `frame_support::storage` re-exports are confirmed.

Test/mock/benchmarking files in every pallet still reference `frame::testing_prelude`,
`frame::benchmarking::prelude`, etc. — those are deferred to a follow-up pass and
share the same patterns; expect ~2× this list of edit sites when that pass runs.
