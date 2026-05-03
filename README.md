# Rostro

A hardware-anchored, democratically-governed blockchain. One certificate, one
vote. Built by the Rostro Foundation.

This repository contains the runtime and node infrastructure for the Rostro
network family:

- **Rostro** — production mainnet
- **Canaria** — canary network (real value, faster release cycle, breaks first)
- **Camino** — public testnet

## Lineage

Rostro is a fork of the Polkadot SDK with a deliberately reduced surface. The
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
- **Strip-mall application layer.** Operators run their own application logic
  in PolkaVM contracts on top of a shared, hash-attested canonical runtime.
  Modify your shop, not the foundation.
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
