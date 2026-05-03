# Rostro NOTICE

This file documents the license posture of the Rostro repository, the
attributions to upstream contributors, and the practical implications for
downstream consumers.

## Summary

Rostro is a fork of the [Polkadot SDK](https://github.com/paritytech/polkadot-sdk)
with the relay-chain, parachain, bridge, and EVM-compatibility layers
removed. What remains is split along Substrate's intentional runtime/node
license boundary.

| Layer | Crates | License | What ships in production |
|---|---|---|---|
| Runtime primitives (`sp-*`) | 62 | Apache-2.0 | Linked into the on-chain WASM blob |
| FRAME framework + pallets (`frame-*`, `pallet-*`) | 115 | Apache-2.0 (10 MIT-0) | Linked into the on-chain WASM blob |
| Substrate client / node (`sc-*`) | 55 | GPL-3.0-or-later WITH Classpath-exception-2.0 | Linked only into the off-chain validator/full-node binary |
| Substrate client / node (`sc-*`) | 5 | Apache-2.0 | Off-chain |

**The on-chain WASM runtime is 100% Apache-2.0 / MIT-0.** Zero GPL files
participate in any runtime build. Verified by SPDX-License-Identifier on
every source file under `substrate/primitives/` and `substrate/frame/`.

**The off-chain node binary is GPL-3.0-or-later WITH Classpath-exception-2.0**
in its substrate-client portions. The Classpath exception (added by Parity
to Substrate's GPL declaration) preserves the right to link these client
crates with code under any other license, which is what enables the
Apache-licensed runtime to be executed by the GPL-Classpath node without
contamination.

## Per-File Authority

Each source file carries an `SPDX-License-Identifier` header that is
**authoritative** for that file's license. Where a file's per-file SPDX
disagrees with the workspace `Cargo.toml` `license =` field for its crate,
the per-file SPDX wins.

The workspace-level `[workspace.package] license = "Apache-2.0"`
declaration in the root `Cargo.toml` reflects:

- The license under which Rostro Foundation contributors release new code
  to this repository.
- The default for any future crate that does not set its own `license`
  field.

It does **not** retroactively relicense the 55 `sc-*` crates whose own
`Cargo.toml` `license` field declares GPL-3.0-or-later WITH
Classpath-exception-2.0. Those crates retain their original Parity
declaration.

## Attribution

Rostro inherits substantial code from:

- **Parity Technologies (UK) Ltd.** — original authors of the Polkadot SDK
  and Substrate. Copyright preserved on all upstream-derived files. Original
  upstream repository: https://github.com/paritytech/polkadot-sdk.
- **The broader Substrate contributor community** — community contributions
  preserved with their copyright headers intact.
- **Wei (Bitarray GmbH)** — license-posture approach (`Apache surface
  expansion`) for the cull strategy, plus future PolkaVM acceleration
  work via [Grey](https://github.com/jarchain/jar/tree/master/grey)
  (Apache-2.0). Acknowledgement is forward-looking; the integration is
  scheduled post-rename.

The Rostro Foundation contributes:

- Restructuring, pruning, and packaging of the surviving tree for sovereign
  chain operation (this repository, branch `cull/v1` and successors).
- Net-new pallets implementing proof of personhood, hardware attestation,
  bicameral governance, milestone-first treasury, and related Rostro-
  specific functionality. All net-new code is released under Apache-2.0.
- Hardenings to upstream MMR/BEEFY against the Hyperbridge attack class
  (see `substrate/utils/merkle-mountain-range/src/tests/test_rostro_hardenings.rs`).
  These hardenings are Apache-2.0 contributions to the surviving Apache
  portions of the tree.

## Practical Implications for Downstream Consumers

If you are using Rostro:

- **You receive an Apache-2.0 on-chain runtime.** You may fork it,
  modify it, redistribute it, and combine it with code under any
  license, subject only to Apache-2.0's attribution and patent grant
  requirements.
- **You receive a node binary with GPL-Classpath portions.** If you
  redistribute the binary or modified node source, you must comply with
  GPL-3.0-or-later for those `sc-*` files. The Classpath exception
  permits you to link the binary with non-GPL code (such as the Apache
  runtime it executes) without that linked code being subject to the
  GPL.
- **Per-file SPDX is authoritative.** If you intend to extract specific
  files or subdirectories, consult each file's `SPDX-License-Identifier`
  header for its actual license terms.

## Practical Implications for Patent Holders

Apache-2.0 § 3 grants a patent license from contributors to recipients
covering only patents that read on the contributor's contribution.
GPL-3.0-or-later § 11 grants a similar but broader patent license.

Contributors to upstream Parity GPL-Classpath files are licensing patents
that read on their contributions to those files under GPL-3.0-or-later.
This applies to Parity Technologies and the upstream contributor community
for their work on the substrate-client crates — not to downstream forks
that merely redistribute those files unmodified.

The Rostro Foundation contributes net-new code under Apache-2.0 only.
Patents held by Rostro Foundation contributors that read on Rostro's
Apache-licensed contributions are licensed under Apache-2.0's patent grant.
**No Rostro Foundation patent is implicitly granted under GPL-3.0** by
virtue of this repository's structure, because Rostro Foundation is not
contributing modifications to the upstream GPL-Classpath files — those
files are preserved as-is from upstream.

## Patent Notice

The Rostro protocol incorporates inventions that are the subject of
patent applications and patents held by Rostro Foundation contributors.
The right to practice these inventions on the canonical Rostro chain
operated by the Rostro Foundation is licensed to the Foundation under
terms set out in separate written license agreements between the
inventor(s) and the Foundation.

Currently disclosed:

- **U.S. Provisional Patent Application 64/043,754**, filed
  April 19, 2026, by Anthony Czarnik:

  > "System and Method for Hardware-Anchored Blockchain-Native Public
  > Key Infrastructure with TPM Endorsement Key Sybil Resistance and
  > Continuous Hardware Integrity Verification"

  Covers the hardware-anchored certificate binding model, the
  use of TPM Endorsement Keys for Sybil resistance, the continuous
  hardware-integrity verification mechanism (the "hip check"), the
  Groth16-with-TOTP-nonce construction binding hardware attestation
  to on-chain operations, and the cross-platform unified hardware
  attestation architecture (TPM 2.0 / Strongbox / equivalent
  hardware secure elements). The patent is directed to the
  hardware-attestation layer of Rostro's proof-of-personhood
  architecture; identity-document attestation (ICAO Doc 9303 or
  equivalent) is implemented by Rostro using the public ICAO
  standard and is not within the scope of this patent.

  Licensed in perpetuity to the canonical Rostro chain operated by
  the Rostro Foundation. The license **does not extend to forks or
  derivative networks**; parties whose use of Rostro's source code
  would practice the claimed inventions outside the canonical chain
  operated by the Foundation should contact the patent holder to
  obtain a separate license.

This notice is informational. The legally operative terms of each
patent license are contained in the written license agreement between
the inventor(s) and the Rostro Foundation, available on request to
legal@rostro.org. Nothing in this notice modifies the source-code
license terms in LICENSE-APACHE or LICENSE-GPL3-CLASSPATH; it documents
a separate-and-additional patent license relevant to operation of the
canonical Rostro chain.

Patent disclosures will be updated as additional patents are filed,
issued, or licensed to the Foundation.

### Note on the Apache-2.0 § 3 Patent Grant Interaction

Source code contributed to this repository under Apache-2.0 is subject
to Apache-2.0 § 3, which grants a patent license from each contributor
to all recipients covering only "those patent claims licensable by
such Contributor that are **necessarily infringed by their
Contribution(s) alone or by combination of their Contribution(s) with
the Work** to which such Contribution(s) was submitted."

The patents disclosed above are directed to **systems and methods
that require physical hardware components and off-chain operations** —
specifically, attestation operations performed by genuine TPM 2.0
modules and analogous hardware secure elements, captured at issuance
time and re-verified continuously, in coordination with on-chain
verification logic. The source code published in this repository
implements the on-chain verification logic and supporting fixtures.

Running the on-chain code in this repository in isolation — for
example, against bypass-crypto test verifiers, against synthetic
attestation fixtures, or in any environment without genuine
hardware-attestation operations performed by real silicon — does
not practice the claims of the disclosed patent applications. The
full claimed system requires real hardware-attestation infrastructure
(genuine TPM Endorsement Keys, real measured-boot quotes, ongoing
hardware-integrity attestations), and the operational pairing of
real attested devices to issued certificates. Those off-chain
hardware components are not in this repository and are licensed
separately to the Rostro Foundation by written agreement.

Apache-2.0 § 3's "necessarily infringed" requirement therefore is
not understood to reach the disclosed patents on the basis of the
contributed source code alone. Downstream parties intending to
operate a network that performs the full claimed system — that is,
to issue and continuously verify hardware-anchored certificates
against real TPM Endorsement Keys for Sybil resistance — are
required to obtain a separate patent license.

**This structure is informational and not legal advice.** Operators,
forkers, and contributors should obtain their own legal counsel
before relying on the precise scope of the § 3 interaction or the
boundary between source-code contribution and patented system
operation. The Rostro Foundation will publish more detailed patent
license terms and companion documentation as the legal infrastructure
matures.

This file is an explanation of the license structure; it is not itself a
license. The actual licenses are in `LICENSE-APACHE` and
`LICENSE-GPL3-CLASSPATH`, supplemented by the per-file SPDX headers.

## Contact

Questions about this NOTICE or about the license posture should be
directed to legal@rostro.org (placeholder until the Rostro Foundation
infrastructure is live).
