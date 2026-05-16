# Rostro

A sovereign blockchain where every actor is a verified human bound to attested
hardware. One certificate, one vote — anonymous by cryptography, not by policy.

*Rostro* means **face** in Spanish. The network sees the human face behind every
account without ever learning who you are.

Rostro is built around a simple commitment: the people who govern, validate, and
operate this network are unique human beings, each bound to a single trusted
device, and their participation is provable without revealing their identity.
Every other architectural choice follows from that commitment.

## The network family

| Network | Role |
|---|---|
| **Rostro** | production mainnet |
| **Canaria** | canary — real value, faster release cycle, breaks first |
| **Camino** | public testnet |

## Architectural commitments

### Hardware-anchored proof of personhood

Every economic and governance actor on Rostro binds two things: an **attested
device** — TPM 2.0 on PCs, Android Strongbox on phones — that proves its
identity and integrity to the chain, and a **verified identity document** — an
ICAO 9303 e-passport, NFC-read and cryptographically validated against the
issuing country's certificate authority.

The chain stores no biometrics, no document numbers, no personal data. Each
account holds a single per-AccountId certificate carrying a country seat
assignment and an adult / non-adult bit. **One human, one certificate.** Re-mint
requires explicit discard; nobody can hold two certs at once.

Verification is end-to-end zero-knowledge. The chain learns that you exist,
that you're an adult, and which seat you vote from. It never learns who you
are.

### Anonymous consensus

Sassafras (Ring VRF) assigns block slots anonymously. Validators cannot collude
on the next slot because no one — not even the validators themselves — knows in
advance who has it. Collusion resistance is designed in, not bolted on.
GRANDPA handles finality on top.

### Anonymous-by-construction governance

Two chambers with staggered terms and term limits: a country-fixed upper house
sourced from the same passport bundle that grants personhood, and a
round-robin lower house with non-repeating distribution and addition-paced
pruning of non-voters.

Voting is ranked-choice. **Ballot privacy is a cryptographic property of the
proof system itself**, not a policy promise layered on top of public votes.
No token-weighted plutocracy. One certificate, one vote.

### Strip-mall operator architecture

The chain provides shared infrastructure: consensus, peer discovery, identity,
canonical state, name service, messaging primitives. Applications — *shops* —
run as operator-supplied WASM blobs in a private sidecar process. **Modify
your shop, not the foundation.**

Operator state is rooted in the Rostro Name Service and cryptographically
isolated by `(rns_name, operator_account_id)`, so a lapsed RNS re-registration
by someone else cannot grant access to the previous holder's state. Per-shop
state is the operator's responsibility; the chain enforces the boundary.

### Self-healing canonical binaries

Every node — validator, operator, ordinary participant — runs a
foundation-canonical binary enforced at boot (hash check against an on-chain
registry) and at the network edge (peer-to-peer attestation). Drift triggers
automatic heal: bytes-by-hash p2p fetch, atomic stage, exit-code
swap-and-restart via a cross-platform supervisor.

Foundation upgrades propagate without operator coordination. The Kusama-class
*"validators forgot to upgrade"* failure mode is gone.

### Post-quantum by design

Zero-knowledge proofs across the personhood, messaging, and aggregation paths
use Plonky3 STARKs over Goldilocks — **no trusted setup**, no curve
cryptography in the verifier, post-quantum secure by construction.

Signature schemes default to Ed25519. P-256 is reserved for hardware that
doesn't support modern curves. The OPRF nullifier scheme is migration-ready
for lattice-based variants when post-quantum standards finalise.

### Milestone-first treasury

No upfront grants. Ever. **Working code, then payment.** The treasury is
governed by the same bicameral system that runs the chain — funding decisions
are anonymous-by-construction and ranked-choice, like every other governance
act. There is no foundation-discretionary slush fund.

### State-rent and permissionless cleanup

Every state-creating object — PoP cert, RNS name, contract record, operator
state — carries a deposit and an expiration. When state expires, **anyone**
can call the permissionless cleanup extrinsic and collect the deposit residue.
State growth is bounded by economic gravity rather than by privileged
janitors. RocksDB stays small without anyone being asked nicely.

### Code-enforced operational invariants

Rostro binaries refuse misconfiguration regardless of CLI flags or
configuration files. A validator wired to expose unsafe RPC hard-rejects at
boot. A node configured as a non-validator whose key shows up in the active
set crashes at the chain-state self-check before silent absence can harm
finality. **Polkadot prints warnings; Rostro refuses.**

The binary is the safety boundary, not the operator.

### Subtract by default

Rostro is a hard fork of the Polkadot SDK with the relay chain, parachain
framework, bridges, and EVM-compatibility surfaces removed. What remains is
the Substrate framework, FRAME, and the consensus and client primitives
needed for a sovereign chain — nothing more.

Some of what we kept got rebuilt. Some got pruned. Some got replaced with
primitives that previously lived in the Polkadot orbit but never quite fit.
The full architectural rationale lives in the project whitepaper.

### Low-barrier operation

The aspiration: **a ten-year-old should be able to run a Rostro node** via
the installer. The binary refuses misconfiguration; the installer handles
key generation, role selection, peer discovery, and updates. Validator role
carries a higher bar — stake, PoP, hardware attestation, operational track
record — because validating is operationally serious. Ordinary participation
is not.

## Lineage

Rostro is a hard fork of the Polkadot SDK. The relay-chain, parachain,
bridge, and EVM-compatibility layers have been removed; what remains is the
Substrate framework, FRAME, and the consensus and client primitives needed
for a sovereign chain. Original Polkadot SDK copyrights and per-file license
declarations are preserved as authoritative; this repository restructures,
prunes, and extends that work for the Rostro network.

## License

Rostro's tree splits cleanly along Substrate's runtime / node boundary:

- **On-chain runtime — Apache-2.0.** All `sp-*` primitives, all `frame-*` and
  `pallet-*` runtime crates — 177 crates total — are Apache-2.0 (or MIT-0
  for a small set of helpers). The on-chain WASM blob compiled from this
  tree is fully Apache-licensed. New Rostro pallets ship under Apache-2.0.
- **Off-chain node binary — GPL-3.0-or-later WITH Classpath-exception-2.0.**
  55 of the 60 `sc-*` Substrate-client crates retain upstream Parity's
  GPL-3.0-or-later WITH Classpath-exception-2.0 declaration. The Classpath
  exception preserves the right to link these client crates with code under
  any other license — including the Apache-licensed runtime they execute.

See [NOTICE.md](./NOTICE.md) for the attribution map, the rationale behind
this split, the patent notice covering inventions used under license by the
Rostro Foundation, and the practical implications for downstream consumers
and forks. Full license texts: [LICENSE-APACHE](./LICENSE-APACHE),
[LICENSE-GPL3-CLASSPATH](./LICENSE-GPL3-CLASSPATH).

The licence posture follows the spirit of the approach taken by Wei
(Bitarray GmbH) in [Grey](https://github.com/jarchain/jar/tree/master/grey),
adapted to Rostro's choice to retain (rather than rebuild) the Substrate
client layer.

## Building

```sh
SKIP_WASM_BUILD=1 cargo check --workspace --all-targets
SKIP_WASM_BUILD=1 cargo clippy --workspace --all-targets
cargo +nightly fmt
```

Production builds use the standard cargo workflow. Specific build targets
(`camino-runtime`, `canaria-runtime`, `rostro-runtime`) are added as the
runtime integration lands.

## Running a node

`gemini-node` is the current testbed binary — Sassafras + GRANDPA consensus
over `gemini-runtime`. Two-node bring-up:

```sh
cargo build --release -p gemini-node

# Insert each validator's bandersnatch authority key into its keystore.
./target/release/gemini-node insert-sassafras-key --suri "//Alice" --base-path /tmp/gemini-alice
./target/release/gemini-node insert-sassafras-key --suri "//Bob"   --base-path /tmp/gemini-bob

# Spin up Alice.
ROSTRO_RPC_SHIELD=1 ./target/release/gemini-node \
  --chain local --base-path /tmp/gemini-alice --alice \
  --port 30334 --rpc-port 9934 --validator \
  --node-key 0000000000000000000000000000000000000000000000000000000000000001 \
  --no-mdns

# Spin up Bob, peering with Alice.
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

`ROSTRO_RPC_SHIELD=1` activates the `rostro-rpc-shield` defense-in-depth RPC
middleware, which gates state-call dispatches against an on-chain
SRT-controlled allowlist of public-safe methods and applies per-/24 source
rate limiting. Validators additionally enforce **topology, not just
configuration** — public RPC is served by separate non-validator nodes; the
validator binary hard-rejects non-loopback RPC binding and unsafe RPC methods
at boot.

## Road to mainnet

**Camino testnet → Canaria canary → Rostro mainnet.**

Pre-launch items: Security Response Team bootstrap and threshold-signing
ceremony, RNS seed-list ratification mechanism, verifying-key trusted-setup
ceremony for the personhood circuits, governance bicameral bootstrap. See
the project's prelaunch documentation for the current state of each.

## Contributing

Rostro is open to contributions under Apache-2.0. See
[CONTRIBUTING.md](./CONTRIBUTING.md) for the contribution flow.
Security-sensitive issues should be reported per [SECURITY.md](./SECURITY.md).

## Acknowledgements

Rostro inherits substantial work from the Substrate and Polkadot SDK
communities, and the post-cull VM acceleration work draws on Wei's
Apache-licensed [Grey](https://github.com/jarchain/jar/tree/master/grey)
implementation. The Rostro Foundation is grateful to those contributors;
attributions are preserved in copyright headers throughout the source tree.
