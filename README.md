# Rostro

A hardware-anchored, democratically-governed blockchain. One certificate, one
vote. Built by the Rostro Foundation.

This repository contains the runtime and node infrastructure for the Rostro
network family:

- **Rostro** — production mainnet
- **Canaria** — canary network (real value, faster release cycle, breaks first)
- **Camino** — public testnet

## Lineage

Rostro is a hard fork of the Polkadot SDK with a deliberately reduced surface. The
relay-chain, parachain, bridge, and EVM-compatibility layers have been
removed. What remains is the Substrate framework, FRAME, and the consensus
and client primitives needed for a sovereign chain. Original Polkadot SDK
copyrights and per-file license declarations are preserved as authoritative;
this repository is a fork that restructures, prunes, and extends that work
for the Rostro network.

## License

Rostro's tree is split deliberately along Substrate's runtime/node boundary:

- **On-chain runtime (Apache-2.0).** All `sp-*` primitives, all
  `frame-*` and `pallet-*` runtime crates — 177 crates total — are
  Apache-2.0 (or MIT-0 for a small set of helpers). The on-chain WASM
  blob compiled from this tree is fully Apache-licensed. New Rostro pallets
  ship under Apache-2.0.
- **Off-chain node binary (GPL-3.0-or-later WITH Classpath-exception-2.0).**
  55 of the 60 `sc-*` substrate-client crates retain upstream Parity's
  GPL-3.0-or-later WITH Classpath-exception-2.0 declaration. The Classpath
  exception preserves the right to link these client crates with code under
  any other license — including the Apache-licensed runtime they execute.

See [NOTICE.md](./NOTICE.md) for the attribution map, the rationale behind
this split, the patent notice covering inventions used under license by
the Rostro Foundation, and the practical implications for downstream
consumers and forks. Full license texts: [LICENSE-APACHE](./LICENSE-APACHE),
[LICENSE-GPL3-CLASSPATH](./LICENSE-GPL3-CLASSPATH).

The license posture follows the spirit of the approach taken by Wei
(Bitarray GmbH) in [Grey](https://github.com/jarchain/jar/tree/master/grey),
adapted to Rostro's choice to retain (rather than rebuild) the Substrate
client layer.

## What's different

- **Sovereign chain only.** No relay chain, no parachain framework, no XCM,
  no Polkadot-Kusama or Snowbridge bridges. One chain.
- **Strip-mall operator architecture.** Operators register an RNS name and
  run their custom application logic in a private sidecar process hosting a
  second WASM blob; only canonical state changes reach chain via the
  `pallet-rostro-operator-state` pallet. Per-operator state is RNS-rooted and
  cryptographically isolated by `(rns_name, operator_account_id)` — re-
  registration of a lapsed name by anyone else cannot grant access to the
  previous registrant's state. Modify your shop, not the foundation.
- **Self-healing canonical binaries.** All Rostro nodes (validators, operators,
  ordinary participants) run foundation-canonical binaries enforced both at
  boot (hash check against the on-chain `pallet-rostro-canonical-files`
  registry) and at the network edge (peer-to-peer attestation). Drift
  triggers automatic heal — bytes-by-hash p2p fetch, atomic stage, exit-code
  swap-and-restart via a cross-platform supervisor — so foundation upgrades
  propagate without operator coordination and the Kusama-class "validators
  forgot to upgrade" failure mode goes away. Hardware-rooted attestation
  (TPM 2.0 / Strongbox) is the next layer that makes drift claims
  cryptographically unforgeable.
- **Hardware-attested proof of personhood.** Every economic and governance
  actor is bound to attested hardware (TPM 2.0 / Strongbox) and a verified
  identity document. One human, one certificate, one vote.
- **Sassafras consensus.** Anonymous slot assignment via Ring VRF — collusion
  resistance designed in, not bolted on.
- **Bicameral, ranked-choice, anonymous-by-construction governance.** Two
  chambers with staggered terms and term limits. No token-weighted voting.
  Ballot privacy is a cryptographic property, not a policy promise.
- **Milestone-first treasury.** No upfront grants. Ever. Working code, then
  payment.
- **State-rent + permissionless cleanup.** Every state-creating object carries
  an operator-paid deposit. When the namespace's RNS registration lapses or
  changes hands, anyone can call the permissionless `cleanup` extrinsic and
  collect the deposit residue — a built-in economic role that prevents
  RocksDB bloat without depending on any privileged janitor.

The full architectural commitments and motivations are in the project
whitepaper.

## Building

```sh
SKIP_WASM_BUILD=1 cargo check --workspace --all-targets
SKIP_WASM_BUILD=1 cargo clippy --workspace --all-targets
cargo +nightly fmt
```

Production builds use the standard cargo workflow. Specific build targets
(camino-runtime, canaria-runtime, rostro-runtime) will be added as the runtime
integration lands.

## Running the gemini testbed

`gemini-node` is the current testbed binary — Sassafras + GRANDPA consensus
over `gemini-runtime`. Two-node bring-up:

```sh
# Build
cargo build --release -p gemini-node

# Insert each validator's bandersnatch authority key into its keystore
./target/release/gemini-node insert-sassafras-key --suri "//Alice" --base-path /tmp/gemini-alice
./target/release/gemini-node insert-sassafras-key --suri "//Bob"   --base-path /tmp/gemini-bob

# Spin up Alice
ROSTRO_RPC_SHIELD=1 ./target/release/gemini-node \
  --chain local --base-path /tmp/gemini-alice --alice \
  --port 30334 --rpc-port 9934 --validator \
  --node-key 0000000000000000000000000000000000000000000000000000000000000001 \
  --no-mdns

# Spin up Bob, peering with Alice
ROSTRO_RPC_SHIELD=1 ./target/release/gemini-node \
  --chain local --base-path /tmp/gemini-bob --bob \
  --port 30335 --rpc-port 9935 --validator \
  --node-key 0000000000000000000000000000000000000000000000000000000000000002 \
  --bootnodes /ip4/127.0.0.1/tcp/30334/p2p/12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp \
  --no-mdns
```

The chain produces blocks at ~10/min (6s slot, sub-block finality). Validators
run a host-side ticket-generation worker that submits ring-VRF tickets on each
epoch transition, populating the on-chain ticket pool that drives Sassafras's
anonymous slot assignment.

### Code-enforced operational invariants

The binary refuses to run in any combination that would compromise security,
regardless of CLI flags or configuration files:

- **Validator role + non-loopback RPC binding → hard reject** at boot
  (no `--unsafe-rpc-external` escape hatch on validators).
- **Validator role + `--rpc-methods=unsafe` → hard reject** at boot.
- **Configured non-validator + on-chain authority key in active set →
  fail-stop crash** at the chain-state self-check (operator has been
  elected but binary won't author; halt before silent absence harms
  finality).

These are enforced by the binary itself, not by operator discipline. Polkadot
prints warnings; Rostro refuses.

### `ROSTRO_RPC_SHIELD=1`

Activates the `rostro-rpc-shield` defense-in-depth RPC middleware
(`substrate/utils/rostro-rpc-shield`, Apache-2.0). The shield reads the
on-chain `pallet-rostro-rpc-method-policy` registry — a SRT-gated table that
classifies each runtime API method as `PublicSafe`, `PublicGated`,
`LocalOnly`, or `Deny`. State_call dispatches are gated against this table;
runtime upgrades that add new methods ship the access policy in the same
upgrade, so the shield's allowlist stays coordinated with WASM hot-swaps.

The shield additionally provides per-/24 source rate limiting, escalating
penalty tracking on rate-limit exhaustion, and inflight cap enforcement —
patterned on the [snorkel](https://github.com/jarchain/snorkel) DNS
resolver's abuse-absorption layer.

### Topology, not just config

Validators do not expose public RPC. Public RPC is served by separate
non-validator nodes (or a future dedicated `rostro-rpc-node` role). This
separation is enforced by the binary's role checks and supported by future
role-binary builds; see `memory/low_barrier_north_star.md` and the validator
graduation rules in the project's prelaunch documentation.

## Contributing

Rostro is open to contributions under Apache-2.0. See [CONTRIBUTING.md](./CONTRIBUTING.md)
for the contribution flow. Security-sensitive issues should be reported per
[SECURITY.md](./SECURITY.md).

## Acknowledgements

Rostro inherits substantial work from the Substrate and Polkadot SDK
communities, and the post-cull PolkaVM acceleration draws on Wei's
Apache-licensed [Grey](https://github.com/jarchain/jar/tree/master/grey)
implementation. The Rostro Foundation is grateful to those contributors;
attributions are preserved in copyright headers throughout the source tree.
