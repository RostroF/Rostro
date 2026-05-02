# Config Trait Coupling Map

Scope: `pub trait Config` declarations in `substrate/frame/*/src/lib.rs` and
`cumulus/pallets/*/src/lib.rs`. `frame_system::Config` (and its trivial
extensions like `Sized`, `CreateBare<Call<Self>>`) is treated as universal and
NOT counted as cross-pallet coupling. `frame_system::Config<...>` constraints
that bind associated types (e.g. `RuntimeCall`, `RuntimeOrigin`, `OnSetCode`)
are also treated as universal.

Total pallets analyzed (lib.rs, with a Config trait): 92
- substrate/frame: 82 pallets with a `pub trait Config`
- cumulus/pallets: 10 pallets with a `pub trait Config`

Pallets whose Config has at least one non-frame_system supertrait OR a
cross-pallet associated-type bound: 16

Out-of-scope notes:
- `pallet-staking` and `pallet-staking-async` define `Config` in
  `src/pallet/mod.rs`, not `src/lib.rs`, so they are excluded by the scope rule
  even though their lib.rs files exist.
- `pallet-honzon` has no `pub trait Config` in its lib.rs.
- `frame-support`, `frame-executive`, `frame-benchmarking`, `pallet-examples`,
  `frame-try-runtime`, `pallet-metadata-hash-extension`,
  `pallet-session-benchmarking` (cumulus) etc. contain only doc-comment Config
  examples or no pallet-style Config at all.

## 1. Per-pallet table (only pallets with cross-pallet coupling)

### pallet-assets-freezer
- File: `substrate/frame/assets-freezer/src/lib.rs:77`
- Supertraits beyond frame_system: `pallet_assets::Config<I>`
- Cross-pallet associated-type bounds: none (extension pallet, intentionally tightly coupled).

### pallet-assets-holder
- File: `substrate/frame/assets-holder/src/lib.rs:68-70`
- Supertraits beyond frame_system: `pallet_assets::Config<I, Holder = Pallet<Self, I>>`
- Cross-pallet associated-type bounds: none beyond the supertrait constraint.

### pallet-aura
- File: `substrate/frame/aura/src/lib.rs:86`
- Supertraits beyond frame_system: `pallet_timestamp::Config`
- Cross-pallet associated-type bounds: `type SlotDuration: Get<<Self as pallet_timestamp::Config>::Moment>`.

### pallet-authority-discovery
- File: `substrate/frame/authority-discovery/src/lib.rs:48`
- Supertraits beyond frame_system: `pallet_session::Config`
- Cross-pallet associated-type bounds: none (only uses universal AccountId).

### pallet-babe
- File: `substrate/frame/babe/src/lib.rs:124`
- Supertraits beyond frame_system: `pallet_timestamp::Config` (note: uses
  `#[pallet::disable_frame_system_supertrait_check]`, so frame_system is
  pulled in transitively through timestamp).
- Cross-pallet associated-type bounds: `type ExpectedBlockTime: Get<Self::Moment>` where `Self::Moment` is `<Self as pallet_timestamp::Config>::Moment`.

### pallet-beefy-mmr
- File: `substrate/frame/beefy-mmr/src/lib.rs:116`
- Supertraits beyond frame_system: `pallet_mmr::Config + pallet_beefy::Config`
  (also uses `disable_frame_system_supertrait_check`).
- Cross-pallet associated-type bounds: `type BeefyAuthorityToMerkleLeaf: Convert<<Self as pallet_beefy::Config>::BeefyId, Vec<u8>>`.

### pallet-bounties
- File: `substrate/frame/bounties/src/lib.rs:276`
- Supertraits beyond frame_system: `pallet_treasury::Config<I>`
- Cross-pallet associated-type bounds: `type OnSlash: OnUnbalanced<pallet_treasury::NegativeImbalanceOf<Self, I>>`.

### pallet-child-bounties
- File: `substrate/frame/child-bounties/src/lib.rs:153-155`
- Supertraits beyond frame_system: `pallet_treasury::Config + pallet_bounties::Config`
- Cross-pallet associated-type bounds: none direct, but `BalanceOf<Self>` is
  derived from `pallet_treasury::Config` indirectly.

### pallet-meta-tx
- File: `substrate/frame/meta-tx/src/lib.rs:108-117`
- Supertraits beyond frame_system: none beyond frame_system. The
  `frame_system::Config<RuntimeCall: ..., RuntimeOrigin: ...>` constraint binds
  system associated types (universal).
- Cross-pallet associated-type bounds: none. (Skip — clean.)

### pallet-origin-restriction
- File: `substrate/frame/origin-restriction/src/lib.rs:135-142`
- Supertraits beyond frame_system: `pallet_transaction_payment::Config + Send + Sync`
- Cross-pallet associated-type bounds: none direct, but uses `T::WeightToFee`,
  `T::LengthToFee` which come from the txn-payment supertrait.

### pallet-people
- File: `substrate/frame/people/src/lib.rs:177-197`
- Supertraits beyond frame_system: none. The long supertrait declaration is
  purely a `frame_system::Config<RuntimeOrigin: ..., RuntimeCall: ...>`
  constraint. (Skip — clean by the rule used here.)

### pallet-root-offences
- File: `substrate/frame/root-offences/src/lib.rs:85-90`
- Supertraits beyond frame_system: `pallet_staking::Config + pallet_session::Config<ValidatorId = <Self as frame_system::Config>::AccountId> + pallet_session::historical::Config`
- Cross-pallet associated-type bounds: `type ReportOffence: ReportOffence<..., IdentificationTuple<Self>, ...>` (uses `IdentificationTuple` derived from `pallet_session::historical`).

### pallet-tips
- File: `substrate/frame/tips/src/lib.rs:136`
- Supertraits beyond frame_system: `pallet_treasury::Config<I>`
- Cross-pallet associated-type bounds: `type OnSlash: OnUnbalanced<NegativeImbalanceOf<Self, I>>` where `NegativeImbalanceOf` is a tips-local alias built from `pallet_treasury::Config`.

### cumulus aura-ext
- File: `cumulus/pallets/aura-ext/src/lib.rs:60`
- Supertraits beyond frame_system: `pallet_aura::Config`
- Cross-pallet associated-type bounds: none in trait body (empty Config), but
  pallet impl directly references `pallet_aura::Authorities::<T>::get()` and
  `<T as pallet_aura::Config>::MaxAuthorities`.

### cumulus ah-ops
- File: `cumulus/pallets/ah-ops/src/lib.rs:71-75`
- Supertraits beyond frame_system: `pallet_balances::Config<Balance = u128> + pallet_timestamp::Config<Moment = u64>` plus a constrained
  `frame_system::Config<AccountData = AccountData<u128>, AccountId = AccountId32>`.
- Cross-pallet associated-type bounds: none direct in trait body — `Currency`
  is declared with abstract `Mutate/MutateHold/...` traits — but the
  `Balance = u128` and `Moment = u64` literal-locking on sibling pallet Configs
  hard-codes the integration.

### cumulus solo-to-para
- File: `cumulus/pallets/solo-to-para/src/lib.rs:33-35`
- Supertraits beyond frame_system: `parachain_system::Config + pallet_sudo::Config`
- Cross-pallet associated-type bounds: none direct, but pallet impl calls
  `parachain_system::Pallet::<T>::schedule_code_upgrade(...)`.

## 2. Top offenders

By non-frame_system supertrait count (3+ or concrete cross-pallet types):

1. **pallet-root-offences** — 3 sibling supertraits:
   `pallet_staking::Config`, `pallet_session::Config<ValidatorId = AccountId>`,
   `pallet_session::historical::Config`. Plus uses `IdentificationTuple<Self>`
   from `pallet_session::historical` in `OffenceHandler` and `ReportOffence`
   bounds.

2. **pallet-child-bounties** — 2 sibling supertraits but both substantive
   (`pallet_treasury::Config + pallet_bounties::Config`). It pulls in the
   entire treasury+bounties type lattice solely to read `BalanceOf` and call
   bounties' curator/payout APIs.

3. **pallet-beefy-mmr** — 2 sibling supertraits (`pallet_mmr::Config + pallet_beefy::Config`) AND a concrete cross-pallet associated-type bound on
   `pallet_beefy::Config::BeefyId`. Disables frame_system supertrait check.

4. **cumulus ah-ops** — 2 sibling supertraits with **value-locked equality
   bounds** (`Balance = u128`, `Moment = u64`, `AccountData<u128>`,
   `AccountId32`). Hard-coupling, not just trait coupling.

5. **cumulus solo-to-para** — 2 sibling supertraits across runtime layers
   (`parachain_system::Config + pallet_sudo::Config`).

6. **pallet-bounties** — 1 sibling supertrait (`pallet_treasury::Config<I>`)
   plus a concrete cross-pallet type reference: `OnUnbalanced<pallet_treasury::NegativeImbalanceOf<Self, I>>` in the `OnSlash`
   associated type. Direct path coupling.

Honorable mentions with single sibling supertraits (still coupling, but lower
impact): pallet-aura, pallet-babe, pallet-tips, pallet-assets-freezer,
pallet-assets-holder, pallet-authority-discovery, pallet-origin-restriction,
cumulus aura-ext.

## 3. Good examples (clean Configs)

These pallets have **only** `frame_system::Config` (or a trivially universal
extension) as supertrait and use only abstract traits in associated-type
bounds. They are templates for refactoring:

1. **pallet-balances** (`substrate/frame/balances/src/lib.rs:252`) — pure
   `frame_system::Config`. All interfaces (`OnUnbalanced`, `Get`, `StoredMap`,
   `fungible::hold::DoneSlash`) are abstract traits, no sibling pallet Configs
   referenced.

2. **pallet-treasury** (`substrate/frame/treasury/src/lib.rs:217`) — pure
   `frame_system::Config`. Uses `Currency`, `OnUnbalanced`, `EnsureOrigin`,
   `Pay`, `ConversionFromAssetBalance`, `BlockNumberProvider` — all abstract.
   This is the canonical clean example.

3. **pallet-asset-conversion** (`substrate/frame/asset-conversion/src/lib.rs:112`) —
   pure `frame_system::Config`. Talks to assets via abstract `fungibles::*`
   traits (`Inspect`, `Mutate`, `AccountTouch`, `Balanced`, `Refund`) instead
   of `pallet_assets::Config`.

4. **pallet-asset-rate** (`substrate/frame/asset-rate/src/lib.rs:104`) — tiny
   and clean. `Currency: Inspect<Self::AccountId>`, abstract `EnsureOrigin`s,
   parameterized `AssetKind`.

5. **pallet-nft-fractionalization** (`substrate/frame/nft-fractionalization/src/lib.rs:80`) —
   pure `frame_system::Config`. References assets and NFTs only via abstract
   `fungible::*`, `fungibles::*`, and `nonfungibles_v2::*` traits.

6. **pallet-asset-rewards** (`substrate/frame/asset-rewards/src/lib.rs:221`) —
   pure `frame_system::Config`, uses `fungibles::Inspect/Mutate/MutateFreeze`
   only.

7. **pallet-nomination-pools** (`substrate/frame/nomination-pools/src/lib.rs:1666`) —
   pure `frame_system::Config`, talks to staking via the abstract
   `StakeStrategy` adapter trait, not `pallet_staking::Config`. Strong
   refactor template for slim staking-adjacent pallets.

8. **pallet-fast-unstake** (`substrate/frame/fast-unstake/src/lib.rs:171`) —
   pure `frame_system::Config`, uses abstract `StakingInterface` trait instead
   of importing `pallet_staking::Config`.

9. **pallet-delegated-staking** (`substrate/frame/delegated-staking/src/lib.rs:191`) —
   pure `frame_system::Config`, uses `StakingUnchecked` abstract interface.

## 4. Refactor candidates (concrete suggestions)

### pallet-bounties → drop `pallet_treasury::Config<I>`
Currently couples to treasury solely for: a) `BalanceOf<Self, I>`, b) the
treasury account id, c) `pallet_treasury::NegativeImbalanceOf` in `OnSlash`,
d) a few constants like `MaxApprovals`. Replace with:
- Add `type Currency: Currency<Self::AccountId> + ReservableCurrency<Self::AccountId>` directly on bounties' Config (mirroring treasury's own).
- Replace `OnSlash: OnUnbalanced<pallet_treasury::NegativeImbalanceOf<Self, I>>`
  with `OnSlash: OnUnbalanced<NegativeImbalanceOf<Self::Currency, Self::AccountId>>`
  built locally.
- Add `type TreasuryAccount: Get<Self::AccountId>` for the pot address; the
  runtime wires it to `pallet_treasury::Pallet::<T>::account_id()`.

### pallet-child-bounties → drop both supertraits
Replace `pallet_treasury::Config + pallet_bounties::Config` with:
- `type Currency: ReservableCurrency<...>` (same as bounties).
- `type ParentBounty: ChildBountyManagerProvider<...>` — invert the existing
  `ChildBountyManager` trait so child-bounties calls into parent bounties via
  an abstract handle, rather than via concrete `pallet_bounties::Pallet::<T>`.
- A `type TreasuryAccount: Get<Self::AccountId>`.

### pallet-tips → drop `pallet_treasury::Config<I>`
Tips uses treasury only for: balance type, treasury account, and currency
imbalance type. Same pattern as bounties: introduce its own `type Currency`,
local `NegativeImbalanceOf`, and a `TreasuryAccount: Get<AccountId>`. After
this refactor the bounties / child-bounties / tips trio becomes peer pallets
funded *by the runtime wiring* rather than statically welded to treasury.

### pallet-root-offences → drop concrete pallet supertraits
Currently pulls in `pallet_staking::Config`, `pallet_session::Config<ValidatorId = AccountId>`, and `pallet_session::historical::Config` to assemble
`IdentificationTuple<T>`. Replace with abstract bindings on its Config:
- `type FullIdentification: Parameter`
- `type FullIdentificationOf: Convert<Self::AccountId, Option<Self::FullIdentification>>`
- `type EraInfo: pallet_staking::EraInfo<...>` *or* a thin local trait
  `ActiveEraProvider`.
The `OffenceHandler` and `ReportOffence` bounds then reference local types
instead of cross-pallet aliases.

### pallet-beefy-mmr → drop direct beefy/mmr Configs
Replace `pallet_mmr::Config + pallet_beefy::Config` supertraits with:
- `type Hashing: ...` + `type LeafData: ...` (abstract MMR provider).
- `type BeefyAuthorityId: Parameter + ...` declared directly on the Config
  rather than read via `<Self as pallet_beefy::Config>::BeefyId`.
- `type AuthoritySetProvider: BeefyAuthoritySetProvider<...>` — a new abstract
  trait (mirrors pallet-nomination-pools' use of `StakeStrategy`).

### pallet-aura / pallet-babe → drop `pallet_timestamp::Config` supertrait
Both pallets need only `Moment` (and Aura also `MinimumPeriod`/derived
`SlotDuration`). Replace with:
- `type Moment: AtLeast32BitUnsigned + Parameter + ...`
- `type Time: Time<Moment = Self::Moment>` (existing abstract trait in
  `frame_support::traits`).
- `type SlotDuration: Get<Self::Moment>` (already exists for Aura).
This removes the timestamp pallet from being a static prerequisite; runtimes
without `pallet_timestamp` could still wire compatible providers.

### pallet-authority-discovery → drop `pallet_session::Config` supertrait
The pallet only needs the active validator-id list. Replace with
`type ValidatorIdProvider: ValidatorSet<Self::AccountId>` (existing abstract
trait used by pallet-im-online). The runtime continues to wire
`pallet_session::Pallet::<T>` as the implementor.

### pallet-assets-freezer / pallet-assets-holder → keep, but split
These are intentional extension pallets for `pallet-assets`. The coupling is
load-bearing rather than incidental, so flag them as **acceptable** but
document that they should never be required by other (non-assets) pallets.
The `Holder = Pallet<Self, I>` constraint in assets-holder is self-referential
and fine.

### pallet-origin-restriction → drop `pallet_transaction_payment::Config`
Only needs `WeightToFee` and `LengthToFee`. Replace with:
- `type WeightToFee: WeightToFee<Balance = BalanceOf<Self>>`
- `type LengthToFee: WeightToFee<Balance = BalanceOf<Self>>`
declared directly on the Config (no supertrait).

### cumulus ah-ops → narrow value-locked equality bounds
`pallet_balances::Config<Balance = u128>` and `pallet_timestamp::Config<Moment = u64>` are extreme: they hard-code numeric widths into a sibling pallet's
generics. Replace with local generic associated types
(`type Balance: Balance + From<u64> + Into<u128>`) and `type Moment: Parameter + AtLeast32BitUnsigned`. Keep the runtime in charge of wiring concrete u128/u64.

### cumulus solo-to-para → drop `parachain_system::Config + pallet_sudo::Config`
Use only:
- `type SudoOrigin: EnsureOrigin<Self::RuntimeOrigin>` (replaces sudo).
- `type CodeUpgradeScheduler: ScheduleCodeUpgrade` — a 1-method abstract trait
  that the runtime implements via a closure over `parachain_system::Pallet`.

### cumulus aura-ext → drop `pallet_aura::Config`
Replace with `type AuraAuthoritiesProvider: Get<BoundedVec<AuthorityId, MaxAuthorities>>` so the cumulus extension treats the aura pallet as a black
box authority source instead of a structural prerequisite.
