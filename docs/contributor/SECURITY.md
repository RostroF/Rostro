# Security Policy

The Rostro Foundation takes security vulnerabilities seriously. This document
describes how to report a security issue and what to expect when you do.

## Reporting a Vulnerability

**Do not file a public issue for security-sensitive findings.**

Send a private report to **security@rostro.org** (placeholder until the
Foundation infrastructure is live; in the interim, contact the maintainers
listed in the project metadata).

Please include:

- A clear description of the issue and the conditions required to reproduce it.
- Affected components, networks (Rostro / Canaria / Camino), and version or
  commit hash where the issue is observable.
- Any proof-of-concept code, transcripts, or transaction hashes that
  demonstrate the issue.
- Your suggested severity rating and any mitigation you've identified.

We will acknowledge receipt within 72 hours and keep you updated on triage and
remediation progress.

## Responsible Disclosure

We ask that researchers:

- Initially report the issue only to us, not to anyone else.
- Give us a reasonable amount of time to fix the issue before disclosing
  publicly. Our default coordinated-disclosure window is 90 days from initial
  report; extensions are negotiated where remediation requires runtime
  upgrade, validator coordination, or upstream coordination with derived
  libraries.
- Avoid acting on or exploiting the vulnerability beyond what is required to
  demonstrate it.
- Avoid degrading the experience or availability of any Rostro network for
  other users during research.

## Scope

In scope for security reports:

- Bugs in the Rostro / Canaria / Camino runtimes that affect consensus,
  finality, accounting, governance, identity, or attestation correctness.
- Bugs in the node and client implementations that affect liveness, network
  health, or operator security.
- Bugs in the cryptographic primitives derived from upstream Substrate, where
  the bug is reachable from Rostro code paths.
- Bugs in the contract sandbox (PolkaVM) that allow operator contracts to
  escape the sandbox or violate the canonical runtime integrity attestations.

Out of scope:

- Issues that require physical access to a validator or operator's
  infrastructure beyond what the threat model already considers.
- Self-inflicted issues (e.g., deliberately misconfigured local nodes).
- Findings in third-party dependencies that have already been disclosed
  upstream and are tracked in their respective security channels.

## Bug Bounty

A coordinated bug-bounty program will be announced once the Rostro Foundation
governance is established and treasury funding is in place. Until then,
acknowledgements and reasonable financial recognition will be handled on a
case-by-case basis at Foundation discretion.

## Upstream Lineage

Rostro inherits substantial code from the Substrate and Polkadot SDK
communities. Issues that originate in upstream code paths still in use will
be coordinated with the relevant upstream maintainers when remediation
benefits both ecosystems. Original Parity Technologies copyright is preserved
in source files per Apache-2.0 NOTICE requirements.
