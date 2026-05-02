# Concrete-Type Cross-Pallet Usage Map

Scope: `substrate/frame/*/src/` and `cumulus/pallets/*/src/`. Excludes `mock.rs`,
`tests.rs`, `tests/`, `benchmarking*`, `runtimes/`, `rpc/`, `examples/`, `runtime-api/`,
`fuzzer/`, `integration-tests`, `dev-node/`, `precompiles/`, `ui-tests/`, `migrations/`
(intra-pallet), `remote-tests`. `Config` and `WeightInfo` imports are NOT violations.

A "violation" here means: a pallet reaches into another pallet's `Pallet`, `Call`,
`Event`, `Error`, storage struct, or internal helper directly, instead of going
through a trait that the producer pallet exposes.

---

## 1. Violations (by consumer pallet)

### pallet-aura
- `pallet_timestamp::Pallet as Timestamp` (substrate/frame/aura/src/lib.rs:130) — re-aliases the `Timestamp` pallet inside its own module.
- `pallet_timestamp::Pallet::<T>::get()` (substrate/frame/aura/src/lib.rs:339) — fetches the current Unix time directly off the `pallet-timestamp::Pallet` instead of via `UnixTime` trait.

### pallet-grandpa
- `pallet_session::Pallet::<T>::current_index()` (substrate/frame/grandpa/src/lib.rs:646) — direct concrete read of session index, bypasses any abstraction.
- `pallet_authorship::Pallet::<T>::author()` (substrate/frame/grandpa/src/equivocation.rs:180) — concrete fetch of block author for offence reporter.

### pallet-babe
- `pallet_session::Pallet<T>::current_index()` (substrate/frame/babe/src/lib.rs:1083) — same pattern as grandpa.
- `pallet_authorship::Pallet<T>::author()` (substrate/frame/babe/src/equivocation.rs:167) — same pattern.

### pallet-beefy
- `pallet_session::Pallet::<T>::current_index()` (substrate/frame/beefy/src/lib.rs:718) — same pattern as grandpa.
- `pallet_authorship::Pallet::<T>::author()` (substrate/frame/beefy/src/equivocation.rs:338) — same pattern.

### pallet-beefy-mmr
- `use pallet_mmr::{primitives::AncestryProof, LeafDataProvider, NodesUtils, ParentNumberAndHash}` (substrate/frame/beefy-mmr/src/lib.rs:46) — pulls concrete primitive types from `pallet-mmr`.
- `impl pallet_mmr::primitives::OnNewRoot for DepositBeefyDigest` (substrate/frame/beefy-mmr/src/lib.rs:70) — implements pallet-mmr's hook trait directly.
- `pallet_mmr::Pallet::<T>::is_ancestry_proof_optimal(...)` (substrate/frame/beefy-mmr/src/lib.rs:196).
- `pallet_mmr::Pallet::<T>::block_num_to_leaf_count(...)` (substrate/frame/beefy-mmr/src/lib.rs:230).
- `pallet_mmr::Pallet::<T>::verify_ancestry_proof(...)` (substrate/frame/beefy-mmr/src/lib.rs:246) — three direct calls into `pallet-mmr`'s helper functions; no trait wraps these.

### pallet-bounties (consumer of pallet-treasury)
- `type BalanceOf<T,I> = pallet_treasury::BalanceOf<T,I>` (substrate/frame/bounties/src/lib.rs:122) — re-uses treasury's concrete balance alias.
- `type PositiveImbalanceOf<T,I> = pallet_treasury::PositiveImbalanceOf<T,I>` (substrate/frame/bounties/src/lib.rs:124).
- `pallet_treasury::NegativeImbalanceOf<Self,I>` (substrate/frame/bounties/src/lib.rs:335).
- `pallet_treasury::Error::<T,I>::InsufficientPermission` (substrate/frame/bounties/src/lib.rs:475, 512, 941) — three sites returning treasury's concrete `Error` variant.
- `impl pallet_treasury::SpendFunds<T,I> for Pallet<T,I>` (substrate/frame/bounties/src/lib.rs:1163) — implements treasury's hook trait (treasury's `SpendFunds` is a public trait, so this is the proper coupling pattern, not a violation in itself; the `Error` and `BalanceOf` re-exports are the real issue).

### pallet-child-bounties (consumer of pallet-bounties + pallet-treasury)
- `use pallet_bounties::BountyStatus` (substrate/frame/child-bounties/src/lib.rs:85) — concrete enum from another pallet.
- `pub type BalanceOf<T> = pallet_treasury::BalanceOf<T>` (substrate/frame/child-bounties/src/lib.rs:91).
- `pub type BountiesError<T> = pallet_bounties::Error<T>` (substrate/frame/child-bounties/src/lib.rs:92) — concrete `Error` re-export.
- `pub type BountyIndex = pallet_bounties::BountyIndex` (substrate/frame/child-bounties/src/lib.rs:93).
- `pallet_bounties::Pallet::<T>::bounty_account_id(parent_bounty_id)` (substrate/frame/child-bounties/src/lib.rs:300, 936) — direct helper-fn call.
- `pallet_bounties::Pallet::<T>::calculate_curator_deposit(bounty_fee)` (substrate/frame/child-bounties/src/lib.rs:850).
- `pallet_bounties::Bounties::<T>::get(bounty_id)` (substrate/frame/child-bounties/src/lib.rs:885) — direct read of pallet-bounties storage map.
- `impl pallet_bounties::ChildBountyManager<...> for Pallet<T>` (substrate/frame/child-bounties/src/lib.rs:969) — implements bounties' trait (this is the legit hook).

### pallet-tips (consumer of pallet-treasury)
- `pub type BalanceOf<T,I> = pallet_treasury::BalanceOf<T,I>` (substrate/frame/tips/src/lib.rs:90).
- `pub type NegativeImbalanceOf<T,I> = pallet_treasury::NegativeImbalanceOf<T,I>` (substrate/frame/tips/src/lib.rs:91).
- `pallet_treasury::Pallet::<T,I>::pot()` (substrate/frame/tips/src/lib.rs:573) — direct call to the treasury's pot helper.

### pallet-staking (consumer of pallet-session + pallet-authorship)
- `<pallet_session::Pallet<T>>::report_offence(...)` (substrate/frame/staking/src/lib.rs:956) — direct call into pallet-session.
- `<pallet_session::Pallet<T>>::validators()` (substrate/frame/staking/src/lib.rs:960) — direct read of session pallet's validator list.
- `<pallet_session::historical::Pallet<T>>::prune_up_to(up_to)` (substrate/frame/staking/src/lib.rs:964) — reaches into session's historical sub-pallet.
- `use pallet_session::historical` + `pallet_session::historical::IdentificationTuple<T>` (substrate/frame/staking/src/pallet/impls.rs:37, 1741, 1756) — concrete tuple type.
- `impl pallet_session::SessionManager<T::AccountId> for Pallet<T>` (substrate/frame/staking/src/pallet/impls.rs:1651) — proper trait impl (not a violation).
- `impl pallet_authorship::EventHandler<...> for Pallet<T>` (substrate/frame/staking/src/pallet/impls.rs:1730) — proper trait impl.

### pallet-staking-async-ah-client (consumer of pallet-session + pallet-authorship)
- `pub use pallet_session::SessionInterface` (substrate/frame/staking-async/ah-client/src/lib.rs:102) — re-exports session's public trait (OK; trait).
- `use pallet_session::{historical, SessionManager}` (substrate/frame/staking-async/ah-client/src/lib.rs:179) — uses `historical` module concretely; `SessionManager` is a trait.
- `Fallback: pallet_session::SessionManager<...> + pallet_authorship::EventHandler<...>` (substrate/frame/staking-async/ah-client/src/lib.rs:259, 265) — trait bounds, OK.
- `<Self as pallet_session::SessionManager<_>>::new_session/start/end_session` (substrate/frame/staking-async/ah-client/src/lib.rs:802, 819, 823) — calls through trait casts (trait, OK).

### pallet-root-offences (consumer of pallet-session)
- `use pallet_session::historical::IdentificationTuple` (substrate/frame/root-offences/src/lib.rs:33) — concrete tuple type.
- `<pallet_session::Pallet<T> as frame_support::traits::ValidatorSet<...>>::session_index()` (substrate/frame/root-offences/src/lib.rs:227) — fully-qualified trait call but still names `pallet_session::Pallet` concretely; should ideally take a `ValidatorSet` impl via a Config bound.

### pallet-bounties (migration code) — pallet_bounties::* (self-references in migrations) — excluded.

### pallet-assets-holder (consumer of pallet-assets)
- `use pallet_assets::BalanceOnHold` (substrate/frame/assets-holder/src/impl_fungibles.rs:26).
- `pallet_assets::Pallet::<T,I>::total_issuance` (impl_fungibles.rs:71)
- `pallet_assets::Pallet::<T,I>::minimum_balance` (impl_fungibles.rs:75)
- `pallet_assets::Pallet::<T,I>::total_balance` (impl_fungibles.rs:79)
- `pallet_assets::Pallet::<T,I>::balance` (impl_fungibles.rs:83)
- `pallet_assets::Pallet::<T,I>::reducible_balance` (impl_fungibles.rs:92)
- `pallet_assets::Pallet::<T,I>::can_deposit` (impl_fungibles.rs:101)
- `pallet_assets::Pallet::<T,I>::can_withdraw` (impl_fungibles.rs:109)
- `pallet_assets::Pallet::<T,I>::asset_exists` (impl_fungibles.rs:113)
- `pallet_assets::Pallet::<T,I>::handle_dust` (impl_fungibles.rs:140)
- `pallet_assets::Pallet::<T,I>::write_balance` (impl_fungibles.rs:148)
- `pallet_assets::Pallet::<T,I>::set_total_issuance` (impl_fungibles.rs:152)
- `pallet_assets::Pallet::<T,I>::decrease_balance` (impl_fungibles.rs:163)
- `pallet_assets::Pallet::<T,I>::increase_balance` (impl_fungibles.rs:179) — 13 direct helper calls; the entire fungibles impl is a thin re-wiring of pallet-assets' inherent methods. Architecturally this is a "satellite" pallet but it's tightly coupled to the implementation of pallet-assets, not its trait surface.

### pallet-assets-freezer (consumer of pallet-assets)
- `use pallet_assets::FrozenBalance` (substrate/frame/assets-freezer/src/impls.rs:26) — implements pallet-assets' hook trait (OK pattern; trait).
- `pallet_assets::Pallet::<T,I>::total_issuance` (impls.rs:66)
- `pallet_assets::Pallet::<T,I>::minimum_balance` (impls.rs:70)
- `pallet_assets::Pallet::<T,I>::total_balance` (impls.rs:74)
- `pallet_assets::Pallet::<T,I>::balance` (impls.rs:78)
- `pallet_assets::Pallet::<T,I>::reducible_balance` (impls.rs:87)
- `pallet_assets::Pallet::<T,I>::can_deposit` (impls.rs:96)
- `pallet_assets::Pallet::<T,I>::can_withdraw` (impls.rs:104)
- `pallet_assets::Pallet::<T,I>::asset_exists` (impls.rs:108) — 8 direct calls; same coupling pattern as assets-holder.

### pallet-asset-conversion-tx-payment (consumer of pallet-transaction-payment + pallet-asset-conversion)
- `use pallet_transaction_payment::{ChargeTransactionPayment, OnChargeTransaction}` (substrate/frame/transaction-payment/asset-conversion-tx-payment/src/lib.rs:54) — concrete extension type + trait. `ChargeTransactionPayment` is concrete.
- `pallet_transaction_payment::Pallet::<T>::compute_fee` (lib.rs:319) — direct fee computation.
- `pallet_transaction_payment::Pallet::<T>::compute_actual_fee` (lib.rs:370, 396) — twice.
- `pallet_transaction_payment::Pallet::<T>::deposit_fee_paid_event` (lib.rs:384) — pokes a public event-deposit helper.
- `use pallet_asset_conversion::{QuotePrice, SwapCredit}` (payment.rs:31) — these are pallet-asset-conversion's traits (OK).

### pallet-asset-tx-payment (consumer of pallet-transaction-payment)
- `use pallet_transaction_payment::OnChargeTransaction` (lib.rs:51) — trait, OK.
- `use pallet_transaction_payment::ChargeTransactionPayment` (lib.rs:333) — concrete extension.
- `pallet_transaction_payment::Pallet::<T>::compute_fee` (lib.rs:338).
- `pallet_transaction_payment::ChargeTransactionPayment::<T>::post_dispatch_details(...)` (lib.rs:395).
- `pallet_transaction_payment::Pre::Charge { ... }` (lib.rs:396) — constructs concrete enum variant from pallet-transaction-payment.
- `pallet_transaction_payment::Pallet::<T>::compute_actual_fee` (lib.rs:409).

### pallet-origin-restriction (consumer of pallet-transaction-payment)
- `use pallet_transaction_payment::OnChargeTransaction` (substrate/frame/origin-restriction/src/lib.rs:64) — trait, OK.

### pallet-revive (revive evm fees)
- `use pallet_transaction_payment::{Config as TxConfig, MultiplierUpdate, NextFeeMultiplier, Pallet as TxPallet, TxCreditHold}` (substrate/frame/revive/src/evm/fees.rs:38) — pulls in the concrete `Pallet` aliased as `TxPallet`, `NextFeeMultiplier` (concrete storage), and `TxCreditHold`. This is significant cross-pallet coupling.

### cumulus-pallet-aura-ext (consumer of pallet-aura)
- `type Aura<T> = pallet_aura::Pallet<T>` (cumulus/pallets/aura-ext/src/lib.rs:48) — alias for the concrete sibling pallet.
- `pallet_aura::Authorities::<T>::get()` (cumulus/pallets/aura-ext/src/lib.rs:70, 110) — direct read of pallet-aura's `Authorities` storage.
- `pallet_aura::CurrentSlot::<T>::get()` (cumulus/pallets/aura-ext/src/consensus_hook.rs:94) — direct storage read.

### cumulus-pallet-xcmp-queue (consumer of pallet-message-queue)
- `use pallet_message_queue::OnQueueChanged` (cumulus/pallets/xcmp-queue/src/lib.rs:75) — trait, OK.

### cumulus-pallet-collator-selection (consumer of pallet-session + pallet-authorship)
- `use pallet_session::SessionManager` (cumulus/pallets/collator-selection/src/lib.rs:118) — trait, OK.
- `impl pallet_authorship::EventHandler<...> for Pallet<T>` (cumulus/pallets/collator-selection/src/lib.rs:941) — trait impl, OK.

### cumulus-pallet-ah-ops (consumer of pallet-balances + pallet-utility) — major violator
- `use pallet_balances::{AccountData, BalanceLock, Reasons as LockReasons}` (cumulus/pallets/ah-ops/src/lib.rs:54) — three concrete types from pallet-balances.
- `pub type BalanceOf<T> = <T as pallet_balances::Config>::Balance` (lib.rs:62) — Config bound on consumer.
- `pallet_balances::Pallet::<T>::ensure_upgraded(from)` (lib.rs:468) — calls a private-ish helper.
- `pallet_balances::Locks::<T>::get(from)` (lib.rs:482) — direct storage read.
- `pallet_balances::Freezes::<T>::get(from)` (lib.rs:489) — direct storage read.
- `pallet_balances::Holds::<T>::get(from)` (lib.rs:498) — direct storage read.
- `pallet_utility::derivative_account_id(...)` (lib.rs:665, 671) — direct standalone helper from pallet-utility.

---

## 2. Most-violated pallets (reached into concretely)

These are the pallets whose internals are pulled in directly by other pallets.
Counts approximate non-test, non-trait references.

| Producer pallet              | Consumers pulling concrete types                                                                                       | ~refs |
|------------------------------|------------------------------------------------------------------------------------------------------------------------|-------|
| **pallet-assets**            | pallet-assets-holder, pallet-assets-freezer                                                                            | ~22   |
| **pallet-transaction-payment** | pallet-asset-tx-payment, pallet-asset-conversion-tx-payment, pallet-revive (evm/fees.rs), pallet-origin-restriction | ~15   |
| **pallet-session**           | pallet-grandpa, pallet-babe, pallet-beefy, pallet-staking, pallet-root-offences, pallet-staking-async-ah-client     | ~10   |
| **pallet-bounties**          | pallet-child-bounties (heavy)                                                                                          | ~8    |
| **pallet-balances**          | cumulus-pallet-ah-ops                                                                                                  | ~7    |
| **pallet-treasury**          | pallet-bounties, pallet-tips, pallet-child-bounties                                                                    | ~7    |
| **pallet-authorship**        | pallet-grandpa, pallet-babe, pallet-beefy, pallet-im-online (trait), pallet-staking (trait)                          | ~5    |
| **pallet-mmr**               | pallet-beefy-mmr                                                                                                       | ~4    |
| **pallet-aura**              | cumulus-pallet-aura-ext                                                                                                | ~3    |
| **pallet-timestamp**         | pallet-aura                                                                                                            | ~2    |
| **pallet-utility**           | cumulus-pallet-ah-ops                                                                                                  | ~2    |

These pallets need to expose proper trait surfaces so consumers stop reaching past them.

---

## 3. Worst-coupled consumers (pallets reaching into 2+ producers concretely)

| Consumer pallet                              | Producers consumed concretely                                              |
|----------------------------------------------|----------------------------------------------------------------------------|
| **pallet-child-bounties**                    | pallet-bounties (Pallet, Error, BountyIndex, BountyStatus, Bounties storage), pallet-treasury (BalanceOf) |
| **pallet-bounties**                          | pallet-treasury (BalanceOf, PositiveImbalanceOf, NegativeImbalanceOf, Error) |
| **cumulus-pallet-ah-ops**                    | pallet-balances (Locks, Freezes, Holds storage; AccountData; BalanceLock; Reasons; ensure_upgraded), pallet-utility (derivative_account_id) |
| **pallet-grandpa**                           | pallet-session (Pallet::current_index), pallet-authorship (Pallet::author) |
| **pallet-babe**                              | pallet-session, pallet-authorship                                          |
| **pallet-beefy**                             | pallet-session, pallet-authorship                                          |
| **pallet-revive (evm/fees.rs)**              | pallet-transaction-payment (Pallet, NextFeeMultiplier, TxCreditHold, MultiplierUpdate) |
| **pallet-asset-conversion-tx-payment**       | pallet-transaction-payment (Pallet, ChargeTransactionPayment), pallet-asset-conversion (traits — OK) |
| **pallet-asset-tx-payment**                  | pallet-transaction-payment (Pallet, ChargeTransactionPayment, Pre enum)    |
| **pallet-tips**                              | pallet-treasury (BalanceOf, NegativeImbalanceOf, Pallet::pot)              |
| **pallet-staking**                           | pallet-session (Pallet::report_offence, validators; historical), pallet-authorship (trait) |
| **cumulus-pallet-aura-ext**                  | pallet-aura (Pallet, Authorities & CurrentSlot storage)                    |
| **pallet-beefy-mmr**                         | pallet-mmr (Pallet methods + primitives)                                   |

The top three (`pallet-child-bounties`, `pallet-bounties`, `cumulus-pallet-ah-ops`) reach
multiple producers in load-bearing ways and are the most coupled in this tree.

---

## 4. Suggested abstractions (top 5 wins)

### A. pallet-assets-holder / pallet-assets-freezer → `pallet_assets::Pallet::<T,I>::*`
~22 inherent-method calls reproduce pallet-assets' fungibles surface verbatim.
**Suggested fix:** Have `pallet-assets` expose a public type alias for its fungibles
implementation (it already implements `fungibles::Inspect` / `Mutate` / `Unbalanced`),
and let satellite pallets delegate via a trait-bound generic, e.g.
`type AssetsImpl: fungibles::Mutate<T::AccountId, AssetId=..., Balance=...>`.
Both satellite pallets would then call `T::AssetsImpl::balance(asset, who)` instead
of `pallet_assets::Pallet::<T,I>::balance(asset, who)`. This unblocks swapping the
underlying assets implementation (e.g. for an alternate storage layout or an XCM-backed
asset registry).

### B. pallet-transaction-payment helper-fn dependency → `FeeQuoter` trait
Both `asset-tx-payment` and `asset-conversion-tx-payment` (and revive's evm/fees) call
`pallet_transaction_payment::Pallet::<T>::compute_fee` / `compute_actual_fee`,
plus construct `Pre::Charge` and call `ChargeTransactionPayment::post_dispatch_details`
directly. **Suggested fix:** introduce a `FeeQuoter` trait in
`frame_support::traits::tokens::fee` (or `pallet-transaction-payment::FeeQuoter`) with
`compute_fee`, `compute_actual_fee`, and a sealed `commit_fee` /
`refund_fee` pair. Consumers take `T::FeeQuoter: FeeQuoter` and stop knowing about
`Pre::Charge` (an internal enum). pallet-transaction-payment's `Pallet` would simply
implement the trait. This is also what pallet-revive's evm/fees would use instead of
importing `Pallet as TxPallet, NextFeeMultiplier, TxCreditHold` directly.

### C. pallet-session direct concrete reads → `SessionInfo` trait + pre-existing `ValidatorSet`
Five consensus/staking pallets call `pallet_session::Pallet::<T>::current_index()` and
`validators()`. `frame_support::traits::ValidatorSet::session_index()` already covers
some of this — but consumers (grandpa, babe, beefy, staking) still hardcode
`pallet_session::Pallet`. **Suggested fix:** Bound a `T::SessionInfo:
ValidatorSet<AccountId> + SessionIndex` directly in their `Config`, so their
`session_index()` calls go through `T::SessionInfo`, never naming `pallet_session`.
Also surface a `HistoricalProofs` trait to wrap `pallet_session::historical` so staking
no longer needs `use pallet_session::historical::IdentificationTuple`.

### D. pallet-authorship `Pallet::<T>::author()` → `FindAuthor`/`Author` trait
grandpa, babe, beefy each call `pallet_authorship::Pallet::<T>::author()` directly.
**Suggested fix:** Bound `T::FindAuthor: frame_support::traits::FindAuthor<...>` (this
trait already exists) in those three Configs and replace the call. pallet-authorship
already implements `FindAuthor` for its `Pallet`, so the runtime composition is the
same — but the consumer no longer names pallet-authorship in its source.

### E. pallet-bounties / pallet-treasury concrete coupling → `BountyManager` + canonical `BalanceOf` import
`pallet-bounties` re-exports `pallet_treasury::BalanceOf`/`PositiveImbalanceOf`/
`NegativeImbalanceOf`, and returns `pallet_treasury::Error::InsufficientPermission`
from three sites. `pallet-child-bounties` re-exports `pallet_bounties::Error` and
calls `pallet_bounties::Pallet::<T>::bounty_account_id` /
`calculate_curator_deposit` and reads `pallet_bounties::Bounties::<T>` storage.
**Suggested fix:** (1) move `BalanceOf` aliases to a shared
`frame_support::traits::tokens::treasury` module so both bounties and tips can derive
them off `T::Currency` rather than re-exporting treasury's. (2) Define a
`pallet_bounties::BountyManager` trait (analogous to bounties' existing
`ChildBountyManager`) with `bounty_account_id`, `calculate_curator_deposit`,
`get_bounty(id) -> Option<BountyInfo>`. child-bounties takes `T::BountyManager:
BountyManager`. (3) Replace `pallet_treasury::Error::InsufficientPermission` returns
with bounties' own `Error::InsufficientPermission`. This unblocks running bounties
on a non-treasury sovereign-account model.

### Honorable mentions
- **cumulus-pallet-ah-ops → pallet-balances storage**: ah-ops reads `Locks`/`Freezes`/`Holds`
  directly. The `LockableCurrency` / `MutateFreeze` / `MutateHold` traits already cover
  iterating these sets via their `*locks_for(who)` / `*holds_for(who)` accessors —
  `pallet-balances` should expose those (some are already there, e.g. `holds`)
  so ah-ops drops the three storage imports.
- **cumulus-pallet-aura-ext → pallet-aura `Authorities`/`CurrentSlot`**: aura should
  expose `pub fn authorities() -> Vec<...>` and `pub fn current_slot() -> Slot` on a
  small `AuraInfo` trait that aura-ext bounds in its Config. Currently aura-ext
  reads aura's storage directly, which means an alternate aura implementation cannot
  be substituted under aura-ext.
- **pallet-beefy-mmr → pallet-mmr `Pallet::*` methods**: pallet-mmr should expose an
  `MmrAncestry` trait wrapping `is_ancestry_proof_optimal`, `block_num_to_leaf_count`,
  `verify_ancestry_proof` so beefy-mmr no longer reaches into mmr's `Pallet`.
