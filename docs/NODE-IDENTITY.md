# Node identity & quarantine registration — design (v1.0)

**Last touched:** 2026-06-12
**Status:** design record. **Choice A selected 2026-06-12**; the first
primitive (`rostro-node-identity`) lands on `chat-onion-v0`. The full
RNS registration + quarantine-gate wiring is deferred (scope boundary
below). Companions: [DOTWAVE-CHAT-METADATA-ANONYMITY.md](DOTWAVE-CHAT-METADATA-ANONYMITY.md)
(the onion, first consumer of node addressability) and
[DOTWAVE-CHAT-CRYPTO-ARCHITECTURE.md](DOTWAVE-CHAT-CRYPTO-ARCHITECTURE.md).

---

## Why this design exists now

The onion (Phase 4) needs to **seal to** and **verify** a specific node,
and to discover the legitimate node set. That turned out to be three
faces of a primitive the architecture had only sketched as a
placeholder. Designing it once settles all of them, and it is
**foundational** (validator/quarantine-gate infrastructure), not
chat-specific — so it gets its own design and its own crate, with the
chat-onion work depending on it.

## Grounded state (what the architecture diagram says today)

- A node connects but sits in **quarantine** until it passes gate checks.
- One gate: the node's **owner has registered that node under their
  canonical name** (a validator custom attribute). If the network
  cannot resolve *who registered this node*, it does not leave
  quarantine.
- The node identifier was a placeholder ("UID").
- A node **key** is well-motivated: signed replies give non-repudiation.

## Requirements (the four faces of one primitive)

1. **Gate resolution** — given a connecting node, the network resolves
   *which canonical name registered it* (a reverse lookup:
   node → owner-name). No answer ⇒ stays quarantined.
2. **Proof of possession** — the node must *prove* it is that node, not
   merely present a known identifier.
3. **Non-repudiation** — the node signs replies; verifiers check against
   the registered identity.
4. **Addressability** — a chain/RNS reader (e.g. the dotwave client) can
   derive an encryption key to seal an onion layer *to* the node.

---

## Decision — Choice A: the node identity **is** the node's ed25519 key

The node's identity is its existing **libp2p ed25519 node key**, whose
public half is embedded in its **peer id**. That single key covers all
four requirements via the **XEdDSA "convert once"** pattern already used
by the chat identity keys (`rostro-chat-primitives::identity_key`):

| Face | How the one ed25519 key serves it |
|---|---|
| **Gate resolution** | The owner registers the node's peer id (≡ ed25519 pubkey) in the validator attribute. The gate reverse-looks-up the *already-authenticated* peer id of the connecting node. |
| **Proof of possession** | **Free** — the libp2p **Noise** handshake the node performs on connect already proves it holds the private key for that peer id. No separate challenge. |
| **Non-repudiation** | The node signs replies with the node key; verifiers check against the registered ed25519 pubkey. |
| **Addressability** | The client converts the registered ed25519 pubkey → X25519 (Edwards→Montgomery, `ed25519_to_x25519_pubkey`) and seals the onion layer to it; the node unseals with the X25519 secret derived from its node-key seed (`ed25519_seed_to_x25519_secret`). The two pair by the XEdDSA invariant. |

So the node directory **and** the onion seal keys both fall straight out
of reading canonical state — no separate "onion key" artifact to publish
or rotate.

### Why A over B

**B (a dedicated node-identity key,** distinct from the transport key,
registered in the attribute) buys cleaner key separation and independent
rotation — but costs an extra **binding step** (the node must prove
`peer-id ↔ identity-key` linkage at gate time) and more registration
machinery, for no v1 benefit.

**A wins for v1 because:**
- **Zero new key material** — the node already has this key.
- **Proof of possession is free** — the Noise handshake already did it;
  the gate is a pure reverse lookup on an authenticated identifier.
- **Trivial gate check** — "is this connecting peer id registered under a
  canonical name?"
- **Furnishes the onion seal key by conversion** — no extra publication.
- **Consistent** with the one-key-many-roles pattern the chat identities
  already use (Signal's XEdDSA precedent), so the conversion is proven in
  this tree.

**B is the documented upgrade** if key-separation or independent
transport-key rotation later becomes a hard requirement.

### Security note (one key, sign + ECDH)

Using one ed25519 key for both signing and (converted) ECDH is the
**XEdDSA** construction (Signal). Ed25519 lives on the Edwards form of
Curve25519; X25519 on the Montgomery form; the map is canonical and
bijective. This is exactly what `rostro-chat-primitives::identity_key`
already does for user chat identities — so node identity reuses a proven,
in-tree pattern, not a novel construction.

---

## Registration shape

- **Forward**: the owner's canonical name's validator attribute →
  node ed25519 pubkey (peer id). Set by the owner.
- **Reverse**: node ed25519 pubkey → owner canonical name. Written at
  registration so the quarantine gate can resolve `node → owner` cheaply.
- **Multiplicity**: an owner may register several nodes; each node's
  pubkey reverse-maps to the owner's name.

## Scope boundary (what this record does **not** yet design)

Deferred, to be designed/built when reached:
- The RNS **registration extrinsics** for the validator attribute +
  reverse index.
- The quarantine-**gate reverse-lookup** implementation (consensus/
  gate-adjacent; core infra — handle deliberately).
- **Rotation / revocation** of a node identity (and how in-flight
  onion seals to a rotated key are handled).
- sr25519/Ristretto node keys — **out of scope**: Rostro node keys are
  ed25519, which the conversion handles.

**What lands first (this workstream):** the Apache-2.0
`rostro-node-identity` crate — the addressing + signing primitive:
`NodeIdentity` (ed25519 pubkey → verify + X25519 seal pubkey) and
`NodeSecret` (seed → sign + X25519 seal secret + identity). It is what
the onion needs to seal to a node and what the node needs to unseal;
the registration + gate wiring build on it later.

## Open decisions

1. Rotation/revocation story (and onion-seal grace across a rotation).
2. Whether the reverse index is a dedicated RNS record type or derived
   from the forward attribute at gate time.
