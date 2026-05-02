# Cargo.toml Pallet Dependency Map

Scope: pallet-level Cargo.toml dependency graph for the polkadot-sdk fork at `/home/coder/Rostro/`.
Edge filter: dependencies whose package starts with `pallet-`, `frame-`, or `sp-`, plus the `frame` umbrella meta-crate (`polkadot-sdk-frame`) and any path-deps pointing inside a known pallet root.
`[dependencies]` only — `[dev-dependencies]` are reported separately per pallet but excluded from the in/out-degree graph.

Total pallet crates parsed: 119 (plus 1 umbrella).
Substrate frame: 99 crates (counts the substrate/frame meta `polkadot-sdk-frame`). Cumulus pallets: 10. Cumulus parachain pallets: 3. Bridge modules: 7.

Note on scope: `find -maxdepth 2` was used, so nested helper crates (e.g. `staking-async/rc-client`, `staking-async/ah-client`, `staking/runtime-api`, `examples/*`, `revive/fixtures`) are NOT individually parsed but DO appear as edges where parent pallets depend on them. This keeps the graph focused on top-level pallet crates.

## 1. Adjacency list

Format: `crate (out-deg): comma-separated dep list`. dev-deps shown on a sub-line where present.

### substrate/frame

- `frame-benchmarking` (10): frame-support, frame-support-procedural, frame-system, sp-api, sp-application-crypto, sp-core, sp-io, sp-runtime, sp-runtime-interface, sp-storage
  - dev: sp-externalities, sp-keystore, sp-state-machine
- `frame-election-provider-support` (8): frame-election-provider-solution-type, frame-support, frame-system, sp-arithmetic, sp-core, sp-npos-elections, sp-runtime, sp-std
  - dev: sp-io, sp-npos-elections
- `frame-executive` (7): frame-support, frame-system, frame-try-runtime, sp-core, sp-io, sp-runtime, sp-tracing
  - dev: pallet-balances, pallet-transaction-payment, sp-core, sp-inherents, sp-io, sp-version
- `frame-metadata-hash-extension` (3): frame-support, frame-system, sp-runtime
  - dev: frame-metadata, sp-api, sp-tracing, sp-transaction-pool
- `frame-support` (18): frame-metadata, frame-support-procedural, sp-api, sp-arithmetic, sp-core, sp-crypto-hashing-proc-macro, sp-debug-derive, sp-genesis-builder, sp-inherents, sp-io, sp-metadata-ir, sp-runtime, sp-staking, sp-state-machine, sp-std, sp-tracing, sp-trie, sp-weights
  - dev: frame-system, sp-crypto-hashing, sp-timestamp
- `frame-system` (6): frame-support, sp-core, sp-io, sp-runtime, sp-version, sp-weights
  - dev: sp-externalities, sp-tracing
- `frame-try-runtime` (3): frame-support, sp-api, sp-runtime
- `pallet-alliance` (9): frame-benchmarking, frame-support, frame-system, pallet-collective, pallet-identity, sp-core, sp-crypto-hashing, sp-io, sp-runtime
  - dev: pallet-balances, pallet-collective, sp-crypto-hashing
- `pallet-asset-conversion` (8): frame-benchmarking, frame-support, frame-system, sp-api, sp-arithmetic, sp-core, sp-io, sp-runtime
  - dev: pallet-assets, pallet-balances
- `pallet-asset-rate` (5): frame-benchmarking, frame-support, frame-system, sp-core, sp-runtime
  - dev: pallet-balances, sp-core, sp-io
- `pallet-asset-rewards` (9): frame-benchmarking, frame-support, frame-system, sp-api, sp-arithmetic, sp-core, sp-io, sp-runtime, sp-std
  - dev: pallet-assets, pallet-assets-freezer, pallet-balances
- `pallet-assets` (5): frame-benchmarking, frame-support, frame-system, sp-core, sp-runtime
  - dev: pallet-balances, sp-io
- `pallet-assets-freezer` (2): frame, pallet-assets
  - dev: pallet-balances
- `pallet-assets-holder` (5): frame-benchmarking, frame-support, frame-system, pallet-assets, sp-runtime
  - dev: pallet-balances, sp-core, sp-io
- `pallet-atomic-swap` (1): frame
  - dev: pallet-balances
- `pallet-aura` (6): frame-support, frame-system, pallet-timestamp, sp-application-crypto, sp-consensus-aura, sp-runtime
  - dev: sp-core, sp-io
- `pallet-authority-discovery` (6): frame-support, frame-system, pallet-session, sp-application-crypto, sp-authority-discovery, sp-runtime
  - dev: pallet-balances, sp-core, sp-io
- `pallet-authorship` (3): frame-support, frame-system, sp-runtime
  - dev: sp-core, sp-io
- `pallet-babe` (13): frame-benchmarking, frame-support, frame-system, pallet-authorship, pallet-session, pallet-timestamp, sp-application-crypto, sp-consensus-babe, sp-core, sp-io, sp-runtime, sp-session, sp-staking
  - dev: frame-election-provider-support, pallet-balances, pallet-offences, pallet-staking, pallet-staking-reward-curve, sp-core, sp-tracing
- `pallet-bags-list` (9): frame-benchmarking, frame-election-provider-support, frame-support, frame-system, pallet-balances, sp-core, sp-io, sp-runtime, sp-tracing
  - dev: frame-benchmarking, frame-election-provider-support, pallet-balances, sp-core, sp-io, sp-tracing
- `pallet-balances` (5): frame-benchmarking, frame-support, frame-system, sp-core, sp-runtime
  - dev: frame-support, pallet-transaction-payment, sp-io
- `pallet-beefy` (8): frame-support, frame-system, pallet-authorship, pallet-session, sp-consensus-beefy, sp-runtime, sp-session, sp-staking
  - dev: frame-election-provider-support, pallet-balances, pallet-offences, pallet-staking, pallet-staking-reward-curve, pallet-timestamp, sp-core, sp-io, sp-staking, sp-state-machine, sp-tracing
- `pallet-beefy-mmr` (12): frame-benchmarking, frame-support, frame-system, pallet-beefy, pallet-mmr, pallet-session, sp-api, sp-consensus-beefy, sp-core, sp-io, sp-runtime, sp-state-machine
  - dev: pallet-balances, sp-staking
- `pallet-bounties` (7): frame-benchmarking, frame-support, frame-system, pallet-treasury, sp-core, sp-io, sp-runtime
  - dev: pallet-assets, pallet-balances
- `pallet-broker` (7): frame-benchmarking, frame-support, frame-system, sp-api, sp-arithmetic, sp-core, sp-runtime
  - dev: sp-io, sp-tracing
- `pallet-child-bounties` (8): frame-benchmarking, frame-support, frame-system, pallet-bounties, pallet-treasury, sp-core, sp-io, sp-runtime
  - dev: pallet-balances
- `pallet-collective` (6): frame-benchmarking, frame-support, frame-system, sp-core, sp-io, sp-runtime
  - dev: pallet-balances
- `pallet-contracts` (10): frame-benchmarking, frame-support, frame-system, pallet-balances, pallet-contracts-proc-macro, pallet-contracts-uapi, sp-api, sp-core, sp-io, sp-runtime
  - dev: pallet-balances, pallet-contracts-fixtures, pallet-insecure-randomness-collective-flip, pallet-proxy, pallet-timestamp, pallet-utility, sp-keystore, sp-tracing
- `pallet-conviction-voting` (5): frame-benchmarking, frame-support, frame-system, sp-io, sp-runtime
  - dev: pallet-balances, sp-core
- `pallet-core-fellowship` (8): frame-benchmarking, frame-support, frame-system, pallet-ranked-collective, sp-arithmetic, sp-core, sp-io, sp-runtime
- `pallet-dap` (4): frame-benchmarking, frame-support, frame-system, sp-runtime
  - dev: pallet-balances, sp-core, sp-io
- `pallet-dap-satellite` (4): frame-benchmarking, frame-support, frame-system, sp-runtime
  - dev: pallet-balances, pallet-dap, sp-core, sp-io
- `pallet-delegated-staking` (5): frame-support, frame-system, sp-io, sp-runtime, sp-staking
  - dev: frame-election-provider-support, pallet-balances, pallet-nomination-pools, pallet-staking, pallet-staking-reward-curve, pallet-timestamp, sp-core, sp-tracing
- `pallet-democracy` (6): frame-benchmarking, frame-support, frame-system, sp-core, sp-io, sp-runtime
  - dev: pallet-balances, pallet-preimage, pallet-scheduler
- `pallet-derivatives` (7): frame-benchmarking, frame-support, frame-system, sp-core, sp-io, sp-runtime, sp-std
  - dev: pallet-balances, sp-tracing
- `pallet-dummy-dim` (8): frame-benchmarking, frame-support, frame-system, sp-api, sp-arithmetic, sp-core, sp-io, sp-runtime
  - dev: pallet-people
- `pallet-election-provider-multi-block` (10): frame-benchmarking, frame-election-provider-support, frame-support, frame-system, sp-arithmetic, sp-core, sp-io, sp-npos-elections, sp-runtime, sp-std
  - dev: frame-benchmarking, pallet-balances, sp-io, sp-tracing
- `pallet-election-provider-multi-phase` (9): frame-benchmarking, frame-election-provider-support, frame-support, frame-system, sp-arithmetic, sp-core, sp-io, sp-npos-elections, sp-runtime
  - dev: frame-benchmarking, pallet-balances, sp-tracing
- `pallet-elections-phragmen` (8): frame-benchmarking, frame-support, frame-system, sp-core, sp-io, sp-npos-elections, sp-runtime, sp-staking
  - dev: pallet-balances, sp-core, sp-tracing
- `pallet-examples` (11): pallet-default-config-example, pallet-dev-mode, pallet-example-authorization-tx-extension, pallet-example-basic, pallet-example-frame-crate, pallet-example-kitchensink, pallet-example-offchain-worker, pallet-example-single-block-migrations, pallet-example-split, pallet-example-tasks, pallet-example-view-functions
- `pallet-fast-unstake` (7): frame-benchmarking, frame-election-provider-support, frame-support, frame-system, sp-io, sp-runtime, sp-staking
  - dev: pallet-balances, pallet-staking, pallet-staking-reward-curve, pallet-timestamp, sp-core, sp-tracing
- `pallet-glutton` (7): frame-benchmarking, frame-support, frame-system, sp-core, sp-inherents, sp-io, sp-runtime
- `pallet-grandpa` (12): frame-benchmarking, frame-support, frame-system, pallet-authorship, pallet-session, sp-application-crypto, sp-consensus-grandpa, sp-core, sp-io, sp-runtime, sp-session, sp-staking
  - dev: frame-benchmarking, frame-election-provider-support, pallet-balances, pallet-offences, pallet-staking, pallet-staking-reward-curve, pallet-timestamp, sp-keyring, sp-tracing
- `pallet-identity` (5): frame-benchmarking, frame-support, frame-system, sp-io, sp-runtime
  - dev: pallet-balances, sp-core, sp-keystore
- `pallet-im-online` (9): frame-benchmarking, frame-support, frame-system, pallet-authorship, sp-application-crypto, sp-core, sp-io, sp-runtime, sp-staking
  - dev: pallet-balances, pallet-session
- `pallet-indices` (6): frame-benchmarking, frame-support, frame-system, sp-core, sp-io, sp-runtime
  - dev: pallet-balances
- `pallet-insecure-randomness-collective-flip` (1): frame
- `pallet-lottery` (4): frame-benchmarking, frame-support, frame-system, sp-runtime
  - dev: frame-support-test, pallet-balances, sp-core, sp-io
- `pallet-membership` (6): frame-benchmarking, frame-support, frame-system, sp-core, sp-io, sp-runtime
- `pallet-message-queue` (8): frame-benchmarking, frame-support, frame-system, sp-arithmetic, sp-core, sp-io, sp-runtime, sp-weights
  - dev: frame-support, sp-crypto-hashing, sp-tracing
- `pallet-meta-tx` (7): frame-benchmarking, frame-support, frame-system, sp-core, sp-io, sp-runtime, sp-std
  - dev: pallet-balances, pallet-transaction-payment, pallet-verify-signature, sp-keyring, sp-keystore
- `pallet-migrations` (7): frame, frame-benchmarking, frame-support, frame-system, sp-core, sp-io, sp-runtime
  - dev: frame-executive, sp-tracing
- `pallet-mixnet` (3): frame, sp-application-crypto, sp-mixnet
- `pallet-mmr` (2): frame, sp-mmr-primitives
  - dev: sp-tracing
- `pallet-multi-asset-bounties` (6): frame-benchmarking, frame-support, frame-system, sp-core, sp-io, sp-runtime
  - dev: pallet-balances, pallet-preimage, pallet-utility
- `pallet-multisig` (1): frame
  - dev: pallet-balances
- `pallet-nft-fractionalization` (3): frame, pallet-assets, pallet-nfts
  - dev: pallet-balances
- `pallet-nfts` (6): frame-benchmarking, frame-support, frame-system, sp-core, sp-io, sp-runtime
  - dev: pallet-balances, sp-keystore
- `pallet-nis` (1): frame
  - dev: pallet-balances, sp-io
- `pallet-node-authorization` (1): frame
- `pallet-nomination-pools` (8): frame-support, frame-system, pallet-balances, sp-core, sp-io, sp-runtime, sp-staking, sp-tracing
  - dev: pallet-balances, sp-tracing
- `pallet-offences` (4): frame-support, frame-system, sp-runtime, sp-staking
  - dev: sp-core, sp-io
- `pallet-origin-restriction` (8): frame-benchmarking, frame-support, frame-system, pallet-transaction-payment, sp-arithmetic, sp-core, sp-io, sp-runtime
- `pallet-paged-list` (2): frame, sp-metadata-ir
- `pallet-parameters` (5): frame-benchmarking, frame-support, frame-system, sp-core, sp-runtime
  - dev: pallet-balances, pallet-example-basic, sp-io
- `pallet-people` (7): frame-benchmarking, frame-support, frame-system, sp-arithmetic, sp-core, sp-io, sp-runtime
- `pallet-preimage` (6): frame-benchmarking, frame-support, frame-system, sp-core, sp-io, sp-runtime
  - dev: pallet-balances, sp-core
- `pallet-proxy` (1): frame
  - dev: pallet-balances, pallet-utility
- `pallet-ranked-collective` (7): frame-benchmarking, frame-support, frame-system, sp-arithmetic, sp-core, sp-io, sp-runtime
- `pallet-recovery` (1): frame
  - dev: pallet-balances
- `pallet-referenda` (6): frame-benchmarking, frame-support, frame-system, sp-arithmetic, sp-io, sp-runtime
  - dev: pallet-balances, pallet-preimage, pallet-scheduler, sp-core
- `pallet-remark` (6): frame-benchmarking, frame-support, frame-system, sp-core, sp-io, sp-runtime
- `pallet-revive` (16): frame-benchmarking, frame-support, frame-system, pallet-revive-fixtures, pallet-revive-proc-macro, pallet-revive-uapi, pallet-transaction-payment, sp-api, sp-arithmetic, sp-consensus-aura, sp-consensus-babe, sp-consensus-slots, sp-core, sp-io, sp-runtime, sp-version
  - dev: pallet-balances, pallet-proxy, pallet-revive-fixtures, pallet-timestamp, pallet-utility, sp-keystore, sp-state-machine, sp-tracing
- `pallet-root-offences` (7): frame-support, frame-system, pallet-session, pallet-staking, sp-core, sp-runtime, sp-staking
  - dev: frame-election-provider-support, pallet-balances, pallet-staking-reward-curve, pallet-timestamp, sp-io
- `pallet-root-testing` (4): frame-support, frame-system, sp-io, sp-runtime
- `pallet-safe-mode` (4): frame, pallet-balances, pallet-proxy, pallet-utility
  - dev: pallet-balances, pallet-proxy, pallet-utility
- `pallet-salary` (2): frame, pallet-ranked-collective
- `pallet-sassafras` (6): frame-benchmarking, frame-support, frame-system, sp-consensus-sassafras, sp-io, sp-runtime
  - dev: sp-core, sp-crypto-hashing
- `pallet-scheduler` (6): frame-benchmarking, frame-support, frame-system, sp-io, sp-runtime, sp-weights
  - dev: pallet-preimage, sp-core
- `pallet-scored-pool` (4): frame-support, frame-system, sp-io, sp-runtime
  - dev: pallet-balances
- `pallet-session` (11): frame-support, frame-system, pallet-balances, pallet-timestamp, sp-core, sp-io, sp-runtime, sp-session, sp-staking, sp-state-machine, sp-trie
- `pallet-society` (6): frame-benchmarking, frame-support, frame-system, sp-arithmetic, sp-io, sp-runtime
  - dev: frame-support-test, pallet-balances, sp-crypto-hashing
- `pallet-staking` (10): frame-benchmarking, frame-election-provider-support, frame-support, frame-system, pallet-authorship, pallet-session, sp-application-crypto, sp-io, sp-runtime, sp-staking
  - dev: frame-benchmarking, frame-election-provider-support, frame-support, pallet-bags-list, pallet-balances, pallet-staking-reward-curve, pallet-timestamp, sp-core, sp-npos-elections, sp-tracing
- `pallet-staking-async` (11): frame-benchmarking, frame-election-provider-support, frame-support, frame-system, pallet-staking-async-rc-client, sp-application-crypto, sp-core, sp-io, sp-npos-elections, sp-runtime, sp-staking
  - dev: frame-benchmarking, frame-support, pallet-bags-list, pallet-balances, sp-tracing
- `pallet-state-trie-migration` (6): frame-benchmarking, frame-support, frame-system, sp-core, sp-io, sp-runtime
  - dev: pallet-balances, sp-tracing
- `pallet-statement` (7): frame-support, frame-system, sp-api, sp-core, sp-io, sp-runtime, sp-statement-store
- `pallet-sudo` (5): frame-benchmarking, frame-support, frame-system, sp-io, sp-runtime
- `pallet-timestamp` (7): frame-benchmarking, frame-support, frame-system, sp-inherents, sp-runtime, sp-storage, sp-timestamp
  - dev: sp-io
- `pallet-tips` (7): frame-benchmarking, frame-support, frame-system, pallet-treasury, sp-core, sp-io, sp-runtime
  - dev: pallet-balances, sp-storage
- `pallet-transaction-payment` (5): frame-benchmarking, frame-support, frame-system, sp-io, sp-runtime
  - dev: pallet-balances
- `pallet-transaction-storage` (8): frame-benchmarking, frame-support, frame-system, pallet-balances, sp-inherents, sp-io, sp-runtime, sp-transaction-storage-proof
  - dev: sp-transaction-storage-proof
- `pallet-treasury` (6): frame-benchmarking, frame-support, frame-system, pallet-balances, sp-core, sp-runtime
  - dev: pallet-utility, sp-io
- `pallet-tx-pause` (1): frame
  - dev: pallet-balances, pallet-proxy, pallet-utility
- `pallet-uniques` (4): frame-benchmarking, frame-support, frame-system, sp-runtime
  - dev: pallet-balances, sp-io
- `pallet-utility` (6): frame-benchmarking, frame-support, frame-system, sp-core, sp-io, sp-runtime
  - dev: pallet-balances, pallet-collective, pallet-root-testing, pallet-timestamp
- `pallet-verify-signature` (6): frame-benchmarking, frame-support, frame-system, sp-io, sp-runtime, sp-weights
- `pallet-vesting` (4): frame-benchmarking, frame-support, frame-system, sp-runtime
  - dev: pallet-balances, sp-io
- `pallet-whitelist` (1): frame
  - dev: pallet-balances, pallet-preimage
- `polkadot-sdk-frame` (23): frame-benchmarking, frame-executive, frame-support, frame-system, frame-system-benchmarking, frame-system-rpc-runtime-api, frame-try-runtime, sp-api, sp-arithmetic, sp-block-builder, sp-consensus-aura, sp-consensus-grandpa, sp-core, sp-genesis-builder, sp-inherents, sp-io, sp-keyring, sp-offchain, sp-runtime, sp-session, sp-storage, sp-transaction-pool, sp-version

### cumulus/pallets

- `cumulus-pallet-aura-ext` (7): frame-support, frame-system, pallet-aura, pallet-timestamp, sp-application-crypto, sp-consensus-aura, sp-runtime
  - dev: sp-core, sp-io, sp-keyring, sp-state-machine, sp-trie, sp-version
- `cumulus-pallet-dmp-queue` (5): frame-benchmarking, frame-support, frame-system, sp-io, sp-runtime
  - dev: sp-core, sp-tracing
- `cumulus-pallet-parachain-system` (16): frame-benchmarking, frame-support, frame-system, pallet-message-queue, sp-api, sp-consensus-babe, sp-core, sp-crypto-hashing, sp-externalities, sp-inherents, sp-io, sp-runtime, sp-state-machine, sp-std, sp-trie, sp-version
  - dev: frame-executive, sp-api, sp-consensus-slots, sp-crypto-hashing, sp-keyring, sp-tracing, sp-version
- `cumulus-pallet-session-benchmarking` (5): frame-benchmarking, frame-support, frame-system, pallet-session, sp-runtime
- `cumulus-pallet-solo-to-para` (4): frame-support, frame-system, pallet-sudo, sp-runtime
- `cumulus-pallet-weight-reclaim` (6): frame-benchmarking, frame-support, frame-system, sp-io, sp-runtime, sp-trie
- `cumulus-pallet-xcm` (4): frame-support, frame-system, sp-io, sp-runtime
- `cumulus-pallet-xcmp-queue` (7): frame-benchmarking, frame-support, frame-system, pallet-message-queue, sp-core, sp-io, sp-runtime
  - dev: frame-support, pallet-balances, sp-core
- `pallet-ah-ops` (11): frame-benchmarking, frame-support, frame-system, pallet-balances, pallet-timestamp, pallet-utility, sp-application-crypto, sp-core, sp-io, sp-runtime, sp-std
- `pallet-collator-selection` (8): frame-benchmarking, frame-support, frame-system, pallet-authorship, pallet-balances, pallet-session, sp-runtime, sp-staking
  - dev: pallet-aura, pallet-timestamp, sp-consensus-aura, sp-io, sp-runtime, sp-tracing

### cumulus/parachains/pallets

- `cumulus-ping` (3): frame-support, frame-system, sp-runtime
- `pallet-collective-content` (5): frame-benchmarking, frame-support, frame-system, sp-core, sp-runtime
  - dev: sp-io
- `staging-parachain-info` (3): frame-support, frame-system, sp-runtime

### bridges/modules

- `pallet-bridge-beefy` (5): frame-support, frame-system, sp-core, sp-runtime, sp-std
  - dev: pallet-beefy-mmr, pallet-mmr, sp-consensus-beefy, sp-io
- `pallet-bridge-grandpa` (6): frame-benchmarking, frame-support, frame-system, sp-consensus-grandpa, sp-runtime, sp-std
  - dev: sp-core, sp-io
- `pallet-bridge-messages` (6): frame-benchmarking, frame-support, frame-system, sp-runtime, sp-std, sp-trie
  - dev: pallet-balances, pallet-bridge-grandpa, sp-core, sp-io
- `pallet-bridge-parachains` (6): frame-benchmarking, frame-support, frame-system, pallet-bridge-grandpa, sp-runtime, sp-std
  - dev: sp-core, sp-io
- `pallet-bridge-relayers` (9): frame-benchmarking, frame-support, frame-system, pallet-bridge-grandpa, pallet-bridge-messages, pallet-bridge-parachains, pallet-transaction-payment, sp-arithmetic, sp-runtime
  - dev: pallet-balances, pallet-utility, sp-core, sp-io
- `pallet-xcm-bridge-hub` (6): frame-support, frame-system, pallet-bridge-messages, sp-core, sp-runtime, sp-std
  - dev: pallet-balances, pallet-xcm-bridge-hub-router, sp-io
- `pallet-xcm-bridge-hub-router` (6): frame-benchmarking, frame-support, frame-system, sp-core, sp-runtime, sp-std
  - dev: sp-io

## 2. In-degree top 20

How many pallet crates (in our scan, umbrella excluded) list each crate as a `[dependencies]` entry. The top entries are foundational (sp-runtime, frame-support, frame-system); below them are the candidates worth splitting into trait-only crates so consumers stop pulling the full implementation through Cargo.

| Rank | Crate | In-deg | Note |
|---:|---|---:|---|
| 1 | `sp-runtime` | 102 | foundational — every runtime-side pallet pulls it; not splittable |
| 2 | `frame-support` | 101 | foundational — macros + Pallet types; some refactor potential but not a typical 'trait-only split' |
| 3 | `frame-system` | 99 | foundational — every pallet's Config: frame_system::Config |
| 4 | `frame-benchmarking` | 76 | behind `runtime-benchmarks` feature; already optional in most pallets |
| 5 | `sp-io` | 66 | host functions; needed widely |
| 6 | `sp-core` | 60 | primitives; needed widely |
| 7 | `sp-arithmetic` | 18 | math types; light |
| 8 | `frame` | 17 | polkadot-sdk-frame umbrella — pulls a LARGE bag of frame/sp deps; 17 pallets use it (see Sec 4) |
| 9 | `sp-staking` | 15 | trait-ish primitives; the right home for staking traits |
| 10 | `sp-std` | 14 | deprecated alias of core; should be removed |
| 11 | `sp-api` | 13 | runtime API decl macros |
| 12 | `sp-application-crypto` | 11 | crypto helpers |
| 13 | `pallet-session` | 9 | TRAIT-CANDIDATE: 9 consumers, see Sec 4 |
| 14 | `pallet-balances` | 9 | TRAIT-CANDIDATE: 9 consumers, often via fee/Currency trait, see Sec 4 |
| 15 | `sp-inherents` | 6 | inherent data types |
| 16 | `pallet-authorship` | 6 | TRAIT-CANDIDATE: 6 consumers — `FindAuthor` is a trait that already exists in frame-support |
| 17 | `frame-election-provider-support` | 6 | election trait crate — already trait-only by design |
| 18 | `sp-session` | 5 | session traits |
| 19 | `pallet-timestamp` | 5 | TRAIT-CANDIDATE: 5 consumers — Time/UnixTime traits live here |
| 20 | `sp-npos-elections` | 5 | npos election primitives |

## 3. Out-degree top 20

Number of pallet/frame/sp dependencies declared by each pallet. These are the kitchen-sink pallets whose Cargo graph alone can dominate compile time for any runtime that depends on them.

| Rank | Crate | Out-deg | Note |
|---:|---|---:|---|
| 1 | `polkadot-sdk-frame` | 23 | META-CRATE — the substrate/frame/Cargo.toml. Pulls the full frame/sp surface as a re-export bundle for downstream `frame = { features = ["runtime"] }` users. |
| 2 | `frame-support` | 18 | core macro+types crate; out-deg of 18 means support itself imports a wide sp-* surface — every pallet inherits this transitively. |
| 3 | `pallet-revive` | 16 | PolkaVM-based contracts pallet; pulls 3 consensus primitive crates (sp-consensus-aura, sp-consensus-babe, sp-consensus-slots) — suspicious for a contracts pallet; see Sec 4. |
| 4 | `cumulus-pallet-parachain-system` | 16 | parachain system runtime — heavy by design; pulls sp-state-machine, sp-trie, sp-externalities, etc. |
| 5 | `pallet-babe` | 13 | BABE consensus pallet; pulls pallet-authorship + pallet-session + pallet-timestamp. |
| 6 | `pallet-beefy-mmr` | 12 | depends on pallet-beefy + pallet-mmr + pallet-session — see Sec 4. |
| 7 | `pallet-grandpa` | 12 | GRANDPA finality; pulls authorship + session. |
| 8 | `pallet-examples` | 11 | META — substrate/frame/examples/Cargo.toml is a workspace of example pallets, not a real pallet (excluded from boundary findings). |
| 9 | `pallet-session` | 11 | session pallet; pulls pallet-balances + pallet-timestamp + sp-trie + sp-state-machine — see Sec 4. |
| 10 | `pallet-staking-async` | 11 | fork of staking; pulls pallet-staking-async-rc-client. |
| 11 | `pallet-ah-ops` | 11 | Asset Hub ops migration helper; pulls pallet-balances + pallet-timestamp + pallet-utility. |
| 12 | `frame-benchmarking` | 10 | benchmarking crate — its own out-deg is high but it's universally optional. |
| 13 | `pallet-contracts` | 10 | Wasm contracts; pulls pallet-balances + revive-uapi + sp-api. |
| 14 | `pallet-election-provider-multi-block` | 10 | election; pulls election-provider-support + sp-npos-elections. |
| 15 | `pallet-staking` | 10 | core staking; pulls authorship + session + sp-staking. |
| 16 | `pallet-alliance` | 9 |  |
| 17 | `pallet-asset-rewards` | 9 |  |
| 18 | `pallet-bags-list` | 9 |  |
| 19 | `pallet-election-provider-multi-phase` | 9 |  |
| 20 | `pallet-im-online` | 9 |  |

Full dep lists for top-15 out-degree pallets:

- `polkadot-sdk-frame` (23): frame-benchmarking, frame-executive, frame-support, frame-system, frame-system-benchmarking, frame-system-rpc-runtime-api, frame-try-runtime, sp-api, sp-arithmetic, sp-block-builder, sp-consensus-aura, sp-consensus-grandpa, sp-core, sp-genesis-builder, sp-inherents, sp-io, sp-keyring, sp-offchain, sp-runtime, sp-session, sp-storage, sp-transaction-pool, sp-version
- `frame-support` (18): frame-metadata, frame-support-procedural, sp-api, sp-arithmetic, sp-core, sp-crypto-hashing-proc-macro, sp-debug-derive, sp-genesis-builder, sp-inherents, sp-io, sp-metadata-ir, sp-runtime, sp-staking, sp-state-machine, sp-std, sp-tracing, sp-trie, sp-weights
- `pallet-revive` (16): frame-benchmarking, frame-support, frame-system, pallet-revive-fixtures, pallet-revive-proc-macro, pallet-revive-uapi, pallet-transaction-payment, sp-api, sp-arithmetic, sp-consensus-aura, sp-consensus-babe, sp-consensus-slots, sp-core, sp-io, sp-runtime, sp-version
- `cumulus-pallet-parachain-system` (16): frame-benchmarking, frame-support, frame-system, pallet-message-queue, sp-api, sp-consensus-babe, sp-core, sp-crypto-hashing, sp-externalities, sp-inherents, sp-io, sp-runtime, sp-state-machine, sp-std, sp-trie, sp-version
- `pallet-babe` (13): frame-benchmarking, frame-support, frame-system, pallet-authorship, pallet-session, pallet-timestamp, sp-application-crypto, sp-consensus-babe, sp-core, sp-io, sp-runtime, sp-session, sp-staking
- `pallet-beefy-mmr` (12): frame-benchmarking, frame-support, frame-system, pallet-beefy, pallet-mmr, pallet-session, sp-api, sp-consensus-beefy, sp-core, sp-io, sp-runtime, sp-state-machine
- `pallet-grandpa` (12): frame-benchmarking, frame-support, frame-system, pallet-authorship, pallet-session, sp-application-crypto, sp-consensus-grandpa, sp-core, sp-io, sp-runtime, sp-session, sp-staking
- `pallet-examples` (11): pallet-default-config-example, pallet-dev-mode, pallet-example-authorization-tx-extension, pallet-example-basic, pallet-example-frame-crate, pallet-example-kitchensink, pallet-example-offchain-worker, pallet-example-single-block-migrations, pallet-example-split, pallet-example-tasks, pallet-example-view-functions
- `pallet-session` (11): frame-support, frame-system, pallet-balances, pallet-timestamp, sp-core, sp-io, sp-runtime, sp-session, sp-staking, sp-state-machine, sp-trie
- `pallet-staking-async` (11): frame-benchmarking, frame-election-provider-support, frame-support, frame-system, pallet-staking-async-rc-client, sp-application-crypto, sp-core, sp-io, sp-npos-elections, sp-runtime, sp-staking
- `pallet-ah-ops` (11): frame-benchmarking, frame-support, frame-system, pallet-balances, pallet-timestamp, pallet-utility, sp-application-crypto, sp-core, sp-io, sp-runtime, sp-std
- `frame-benchmarking` (10): frame-support, frame-support-procedural, frame-system, sp-api, sp-application-crypto, sp-core, sp-io, sp-runtime, sp-runtime-interface, sp-storage
- `pallet-contracts` (10): frame-benchmarking, frame-support, frame-system, pallet-balances, pallet-contracts-proc-macro, pallet-contracts-uapi, sp-api, sp-core, sp-io, sp-runtime
- `pallet-election-provider-multi-block` (10): frame-benchmarking, frame-election-provider-support, frame-support, frame-system, sp-arithmetic, sp-core, sp-io, sp-npos-elections, sp-runtime, sp-std
- `pallet-staking` (10): frame-benchmarking, frame-election-provider-support, frame-support, frame-system, pallet-authorship, pallet-session, sp-application-crypto, sp-io, sp-runtime, sp-staking

## 4. Suspected boundary problems

Concrete cases where the Cargo edge looks like a leaky abstraction. Each row is `(consumer, dep, why-suspect)`. "Trait-only candidate" means the consumer almost certainly only uses one or two trait/type items from the dep, so a split would let the consumer compile without the full pallet body.

| Consumer | Suspect dep(s) | Why suspect |
|---|---|---|
| `pallet-session` | pallet-balances | session keys logic should not need a Currency. Likely only uses Currency to slash / hold a key-deposit. A trait-only `pallet-balances-traits` (or wider use of `fungible::*` from frame-support) would let session compile without balances. |
| `pallet-session` | pallet-timestamp | session probably only reads `Time::now()`. The `Time`/`UnixTime` trait already lives in `frame-support::traits::Time`. Pulling pallet-timestamp drags storage + extrinsic code into the compile graph. |
| `pallet-session` | sp-trie + sp-state-machine | These are heavy. Session likely needs them only for membership-proof verification (historical sessions). Splitting the proof types into a small `sp-session-proof` crate would let the simple session paths compile without state-machine. |
| `pallet-collator-selection` | pallet-balances | collator selection needs a deposit/Currency abstraction; `Currency`/`fungible::Mutate` is already a trait. A trait-only balances split (or just using fungible) drops a heavy edge. |
| `pallet-collator-selection` | pallet-session | collator-selection only needs to set/clear session keys via a SessionManager-like trait. The session pallet itself should not be a Cargo dep — only its trait crate. |
| `pallet-collator-selection` | pallet-authorship | needs `FindAuthor` — that trait already lives in frame-support::traits. Pulling pallet-authorship is redundant. |
| `pallet-bags-list` | pallet-balances | bags-list is a generic ordered-list pallet over a `Score`. The balances dep is almost certainly only present in the test/benchmark wiring leaking into `[dependencies]` — a textbook trait-only refactor target. |
| `pallet-treasury` | pallet-balances | treasury accumulates a pot via `Currency`/`fungible` — trait abstraction exists. Cargo edge to balances forces every treasury consumer to compile balances even when using a different fungible impl. |
| `pallet-bounties` | pallet-treasury | bounties uses treasury as the source of funds via `OnUnbalanced` and treasury accounts. A trait-only treasury (proposal/spend hooks as a trait crate) would let bounties decouple. |
| `pallet-child-bounties` | pallet-treasury | same as bounties — child-bounties extends bounties and only needs treasury hooks. |
| `pallet-tips` | pallet-treasury | tips uses treasury as fund sink — only needs the spend-on-unbalanced trait. |
| `pallet-alliance` | pallet-collective + pallet-identity | alliance composes a collective-typed origin and uses identity for member screening. A trait-only collective (just the origin/membership trait) and a trait-only identity (just `IdentityProvider`) would cut both. |
| `pallet-staking` | pallet-session | staking calls into session via `SessionInterface`-style traits. The trait crate should be `sp-session` only; the pallet-session Cargo edge forces full session compile into every staking consumer. |
| `pallet-staking` | pallet-authorship | staking needs `FindAuthor`/the current author for reward attribution — that's a frame-support trait. The pallet-authorship dep is almost certainly redundant. |
| `pallet-babe` | pallet-authorship | BABE pallet uses `FindAuthor` — same trait already in frame-support. Cargo edge to authorship is heavier than needed. |
| `pallet-babe` | pallet-session | BABE participates in session rotation via OneSessionHandler/SessionInterface — both are traits, not requiring the pallet-session crate. |
| `pallet-grandpa` | pallet-session | same pattern as babe: GRANDPA hooks via session traits, not pallet-session implementation. |
| `pallet-grandpa` | pallet-authorship | GRANDPA uses author info via the trait — Cargo edge to pallet-authorship is heavier than needed. |
| `pallet-im-online` | pallet-authorship | im-online attests author liveness — `FindAuthor` from frame-support is enough; full pallet-authorship not required. |
| `pallet-beefy-mmr` | pallet-beefy | beefy-mmr produces an MMR over BEEFY auth-set transitions. It mostly needs the auth-set type from beefy + the MMR trait. A small `bp-beefy` style trait crate would let beefy-mmr compile without the full pallet-beefy. |
| `pallet-beefy-mmr` | pallet-mmr | needs MMR insertion hook — trait abstraction (`OnNewRoot`/`MmrAppend`) already exists. Don't need the full pallet. |
| `pallet-beefy-mmr` | pallet-session | needs `OneSessionHandler` for rotation — trait, not the pallet. |
| `pallet-beefy` | pallet-session | same: OneSessionHandler trait. |
| `pallet-beefy` | pallet-authorship | FindAuthor trait. |
| `pallet-authority-discovery` | pallet-session | authority-discovery rotates with sessions via OneSessionHandler — trait edge only. |
| `pallet-nomination-pools` | pallet-balances | pools manages pooled stake via fungible — trait abstraction available; the Cargo edge to balances is implementation coupling. |
| `pallet-transaction-storage` | pallet-balances | tx-storage charges per-byte storage fees via Currency — trait edge only. |
| `pallet-contracts` | pallet-balances | contracts charges gas/deposits via Currency/fungible — already trait-abstracted; Cargo edge is implementation coupling. |
| `pallet-revive` | sp-consensus-aura + sp-consensus-babe + sp-consensus-slots | a contracts pallet has no business pulling THREE consensus primitive crates. Likely a precompile or block-info inspection that should go through frame-system or a tiny shim crate. Flagged as the most surprising edge in the top-out-degree set. |
| `pallet-revive` | pallet-transaction-payment | revive needs fee charging during contract calls — the trait `TransactionExtension`/`OnChargeTransaction` is the real surface; the pallet edge pulls the full tx-payment implementation. |
| `pallet-asset-rewards` | pallet-assets [dev-only via tests/freezer] | main `[dependencies]` is clean (sp-only); confirms the rewards pallet is decoupled from a concrete asset pallet — example of how the trait split looks when done right. |
| `pallet-nft-fractionalization` | pallet-assets + pallet-nfts | fractionalization composes NFT + fungible. The fungibles/nonfungibles traits in frame-support are the right surface — the pallet-level Cargo deps are heavier than the trait usage demands. |
| `pallet-assets-freezer` | pallet-assets | freezer is a side-extension: it needs the asset id type and the freeze-balance hook. A trait-only `pallet-assets-traits` crate would unblock other extension pallets too (assets-holder, nft-fractionalization). |
| `pallet-assets-holder` | pallet-assets | same shape as assets-freezer — extension pallet that wants the asset-id + a hook trait, not the full assets impl. |
| `pallet-bridge-relayers` | pallet-bridge-grandpa + pallet-bridge-messages + pallet-bridge-parachains + pallet-transaction-payment | relayers ties together the bridge stack but only needs the relay-payment hook from each. A `bp-bridge-traits` consolidating the relayer-reward trait would cut all four edges. |
| `pallet-xcm-bridge-hub` | pallet-bridge-messages | bridge-hub uses messages to send bridged XCMs — the `MessageDispatch` / `LaneId` trait surface is small; full pallet edge is heavier. |
| `pallet-ah-ops` | pallet-balances + pallet-timestamp + pallet-utility | this is an Asset Hub migration helper. Hard-coding three concrete pallets makes it un-portable. Should take traits + a Call enum. |
| `pallet-safe-mode` | pallet-balances + pallet-proxy + pallet-utility (via `frame` umbrella) | safe-mode pauses calls — should be defined over a generic Call filter, not glued to specific pallets. ALSO uses `frame = { features = ["runtime"] }` umbrella, which silently drags ~20 frame/sp crates into the build. |
| `pallet-recovery` | frame umbrella | single-dep `frame`. Looks tidy but actually pulls the entire polkadot-sdk-frame meta-crate (out-deg 23) — every recovery rebuild touches that whole graph. |
| `pallet-tx-pause` | frame umbrella | same pattern — `frame` is the ONLY dep, but it expands to ~23 transitive frame/sp crates. |
| `pallet-multisig` | frame umbrella | same: only-`frame` dep style. Convenient but compile-cost-blind. |
| `pallet-proxy` | frame umbrella | same: only-`frame` dep style. |
| `pallet-whitelist` | frame umbrella | same: only-`frame` dep style. |
| `pallet-nis` | frame umbrella | same: only-`frame` dep style. |
| `pallet-paged-list` | frame umbrella | same: only-`frame` dep style — and paged-list is a generic data-structure pallet that should have ZERO heavy deps. |
| `pallet-mmr` | frame umbrella | MMR is a data-structure pallet — the frame umbrella here is overkill. |
| `pallet-atomic-swap` | frame umbrella | atomic-swap is small — single `frame` dep but full umbrella pulled. |
| `pallet-mixnet` | frame umbrella | mixnet via frame umbrella + 2 sp deps. |
| `pallet-node-authorization` | frame umbrella | small access-control pallet, frame umbrella is overkill. |
| `pallet-salary` | frame umbrella | via frame umbrella + pallet-ranked-collective. |
| `pallet-migrations` | frame umbrella + frame-support + frame-system + frame-benchmarking | duplicated dependency surface — both umbrella `frame` AND the individual frame-* crates listed. This is the worst-of-both: full umbrella explosion + explicit edges. |

Auto-detected pallets with more than 4 pallet-* / cumulus-pallet-* deps in `[dependencies]` (raw signal — many already covered above):


Pallets that depend on the `frame` (polkadot-sdk-frame) umbrella crate — each one transitively pulls ~23 frame/sp crates from a single line in their Cargo.toml:

- `pallet-assets-freezer` (2 listed deps; one of them is the `frame` umbrella)
- `pallet-atomic-swap` (1 listed deps; one of them is the `frame` umbrella)
- `pallet-insecure-randomness-collective-flip` (1 listed deps; one of them is the `frame` umbrella)
- `pallet-mmr` (2 listed deps; one of them is the `frame` umbrella)
- `pallet-migrations` (7 listed deps; one of them is the `frame` umbrella)
- `pallet-mixnet` (3 listed deps; one of them is the `frame` umbrella)
- `pallet-multisig` (1 listed deps; one of them is the `frame` umbrella)
- `pallet-nft-fractionalization` (3 listed deps; one of them is the `frame` umbrella)
- `pallet-nis` (1 listed deps; one of them is the `frame` umbrella)
- `pallet-node-authorization` (1 listed deps; one of them is the `frame` umbrella)
- `pallet-paged-list` (2 listed deps; one of them is the `frame` umbrella)
- `pallet-proxy` (1 listed deps; one of them is the `frame` umbrella)
- `pallet-recovery` (1 listed deps; one of them is the `frame` umbrella)
- `pallet-safe-mode` (4 listed deps; one of them is the `frame` umbrella)
- `pallet-salary` (2 listed deps; one of them is the `frame` umbrella)
- `pallet-tx-pause` (1 listed deps; one of them is the `frame` umbrella)
- `pallet-whitelist` (1 listed deps; one of them is the `frame` umbrella)

## 5. Umbrella crate analysis

Path: `/home/coder/Rostro/umbrella/Cargo.toml` (file is 2931 lines).
Crate name: `polkadot-sdk` (version 2603.0.0, this is the polkadot-sdk umbrella re-export crate).

Total `[dependencies.NAME]` table blocks: **380** (raw `grep -c` count).
Of those, the deps that pass our pallet/frame/sp filter: **209**. The remaining ~171 deps are crates outside our filter (binary-merkle-tree, bp-*, bridge-runtime-common, bridge-hub-common, cumulus-primitives-*, asset-test-utils, assets-common, polkadot-runtime-*, polkadot-node-*, polkadot-cli, sc-* client crates, snowbridge-*, xcm, xcm-builder, xcm-executor, etc.) — they all still contribute to compile cost when this umbrella is used.

Filtered breakdown (the 209 pallet/frame/sp deps):
- `pallet-*` / `cumulus-pallet-*` / `staging-parachain-info`: ~136
- `frame-*` (incl. `polkadot-sdk-frame`): ~17
- `sp-*`: ~54
- Other inside filter (e.g. `cumulus-ping`): ~2

Every dep is gated `optional = true`, with std propagation flags listed in `[features].std`. The crate is a pure re-export with no code of its own.

### Verdict

**Yes — this is exactly the kind of mass re-export that destroys compile times when used as a `[dependencies]` entry.** Even though every dep is `optional = true`, any downstream that turns on a non-trivial feature subset (e.g. enabling `std` + a runtime profile feature flag) will linearize ~136 pallet crates plus the frame/sp surface, AND the ~171 non-filtered deps (xcm-*, sc-*, polkadot-runtime-*, snowbridge-*, etc.) on top. Cargo computes the feature unification across the workspace, so a single consumer that names `polkadot-sdk` and asks for, say, `frame` + `runtime` features can pull dozens of crates that would otherwise stay un-built.

Concrete risks for the 25-minute compile time:

1. **The umbrella IS itself huge to type-check** when std is enabled — Cargo does not skip optional deps that are activated by ANY feature in the dependency graph. Workspace builds that touch even a small slice of polkadot-sdk through this crate will pay the full graph cost.
2. **The `polkadot-sdk-frame` (`frame`) sub-umbrella** is a separate, smaller umbrella exported from `substrate/frame/Cargo.toml` (out-deg 23 in our scan). 17 pallets in this fork use it directly (see Sec 4). Pallets that use `frame = { features = ["runtime"] }` in `[dependencies]` are paying a ~23-crate transitive bill from one line.
3. **Runtime crates** (the asset-hub / bridge-hub / kitchensink runtimes — not in this scan but consumers of the umbrella) typically import polkadot-sdk via the umbrella to avoid maintaining 100+ explicit Cargo edges. That is the primary place where this re-export bites compile time.

Recommendation for the refactor plan: treat the umbrella as a strict read-only convenience for application code, and for hot-path pallet crates **forbid both `polkadot-sdk` and `polkadot-sdk-frame` Cargo edges** — pallets should depend on the minimum frame-* / sp-* / sibling-pallet crates explicitly. Of the 17 pallets currently using the `frame` umbrella, every one is a candidate to be flipped back to explicit deps, with `pallet-migrations` being the single worst-case (uses BOTH the umbrella AND the explicit frame-* crates).
