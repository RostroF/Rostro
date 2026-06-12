# dotwave ⇄ Rostro chat — end-to-end work plan to testnet

**Last touched:** 2026-06-10
**⚠️ Crypto layering here is SUPERSEDED** by
[DOTWAVE-CHAT-CRYPTO-ARCHITECTURE.md](DOTWAVE-CHAT-CRYPTO-ARCHITECTURE.md)
(the current plan of record + gated phases + Phase-2 grounding). This doc remains
useful for the **mission/threat-model** section and the original phase intent.
**Progress as of 2026-06-12:** Foundation + R1 + R2 + Phase-1 logic ✅; Phase 2 next.
**Status:** active execution plan. Supersedes the exploratory design tangents
from the 2026-06-09/10 sessions (SS58/multisig per-message signing, chain-as-MLS
delivery-service, pickup-key rework). Those are **dropped**.
**Source of truth:** the recorded design intent —
[[decentralized-chat-architecture]], [[chat-identity-separate-from-chain]],
[[mls-chat-first-demo-outcome]], [[canonical-files-gate-open-problems]] (#14–18),
the `rostro-chat-*` crate headers, and the chat commit series (`git log --grep=chat`).
Companion to [DOTWAVE-BRIDGE-TESTNET.md](DOTWAVE-BRIDGE-TESTNET.md) (the goal) and
[CAMINO-TESTNET-HANDOFF.md](CAMINO-TESTNET-HANDOFF.md) (chain/lab bringup).

---

## Mission & threat model (the north star — everything below serves this)

This platform is built so that **secrecy can be the difference between life and
death** — for a whistleblower, a journalist, or a deep-cover agent. The adversary
is assumed to be **nation-state grade**. That bar reorders the work:

- **Metadata is the kill vector, not just content.** For these users, *proof that
  they talked to a given person at a given time* is what gets them killed —
  more than the message body. Content secrecy (full Signal + sealed sender +
  no-log relays) is necessary but **not sufficient**. Hiding *who-talked-to-whom*
  is the headline requirement, and it is currently the **least-built** part of the
  stack. The one-hop onion (#14) and traffic-analysis resistance are therefore
  **core, not post-MVP hardening.**
- **Honesty over false comfort.** We do not promise more than the math delivers to
  people whose lives depend on it. Three frontiers are named explicitly so we build
  for them rather than paper over them:
  1. **Sender-from-entry-relay anonymity** — today the cert/admission check reveals
     the sender to the entry relay. The onion wrap (#14) must hide the original
     sender; reconciling that with anti-abuse is a real design problem, not a defer.
  2. **Traffic-analysis resistance** — a nation-state observing the network can
     correlate *timing and volume* even with content + addresses hidden. Defeating
     this needs **cover traffic / padding**, and likely a Tor/mixnet-grade transport
     for the phone↔node link (itself ISP-observable). This is where
     "nation-state-proof" is actually won or lost.
  3. **Device-seizure survival** — if the phone is taken, the local cache is the
     record. dotwave needs **encryption-at-rest, disappearing messages, and a
     duress/panic wipe.** A perfect network is worthless if the endpoint folds.

---

## Design invariants (non-negotiable — guard against re-drifting)

0. **No bots — every identity is a verified human.** Rostro is personhood-gated end
   to end (PoP + HW-attested cert), so there is no anonymous/bot tier. A messaging
   identity is *inherently* held by a verified human; there is no "open signup"
   decision to make. The cert/PoP sits upstream of messaging by construction.

1. **Chat identity is a separate Ed25519 key**, NOT the chain SS58. Linked to the
   user via an **RNS chat-identity record**, never by reinterpreting the SS58.
   (Ed25519 is required for the X25519/XEdDSA conversion sealed-sender needs; the
   SS58 may be any BTOW scheme.)
2. **The chain is oblivious to groups.** MLS membership lives entirely in tree
   state, never on-chain. Relays see only `(group_id, ciphertext)`. group_id is
   random 256-bit. Group *size* leak at the relay is accepted; identities are not.
3. **Sealed Sender is the outer layer**; DR (1:1) / MLS (groups) is the inner
   layer wrapped at the transport boundary. The node is dumb routing of encrypted
   blobs between authenticated endpoints — never a decryptor.
4. **Abuse control is composed, not invented** (and it's anti-*abuse-by-humans*,
   not anti-bot — see #0): zkpki **cert admission at the RPC** confirms a verified
   human is sending (already landed, `83a36dfb5e`) + **chain rate-limit per sender
   SS58** (escalating fees → mute → RNS-bar). No new gate. NOTE the tension with the
   mission: the cert check reveals the sender to the entry relay; the onion wrap
   (#14) must resolve this so abuse-control doesn't cost sender anonymity.
7. **Metadata-anonymity is a first-class guarantee, not polish.** Hiding
   who-talked-to-whom (onion + traffic-analysis resistance) and surviving device
   seizure are core deliverables, per the Mission section — not deferred hardening.
5. **XOR-stripe, n-of-n**, replicated for availability; **local-clock TTL** (block
   anchoring was dropped, `2c4494fc1b`); pickup keyed on recipient/group hash.
6. **Users don't run nodes.** The phone talks JSON-RPC to a node for both chain
   and chat; the node does libp2p/gossip/relay on its behalf.

## Current state (proven + just-added)

- **Node spine — proven & merged** (`46728ceb64` → `faf7c4beaa`, then Commits
  A–D + A.1): sealed-sender pairwise + XOR-stripe + ephemeral RAM store + pickup +
  `verify_sender`, bucket-routing, push-gossip, cross-node fetch, local-clock TTL,
  zkpki cert admission (currently **optional** at RPC). **Inner layer = plaintext.**
- **dotwave — just added (2026-06-10):** `rust_core/src/chat.rs` ports the proven
  send/recover flow (compiles + cross-compiles Android arm64); FRB bindings;
  polished Messages UI (conversation list + thread + compose + node-override).
  Chat identity = a separate on-device Ed25519 seed (aligned with invariant #1).
  `auth_*` cert params stubbed as the seam. **Inner still plaintext; identity not
  yet on RNS; cert not yet enforced.**

**Lab:** 2× Samsung (A = Alice, B = Bob) + 3 node laptops (LAN). Phones reach a
node laptop by RPC over the LAN (set per-phone via the in-app node setting).

---

## Phases

Sizes are relative effort (S/M/L). Each phase ends with a concrete lab test on the
2-phone / 3-node rig.

### Phase 0 — Prove the ported spine on real iron · S
The thing already built, validated on hardware.
- **dotwave:** `flutter build apk --debug`; install on both Samsungs; point each at
  a lab node (`ws://<lan-ip>:9944`).
- **Node:** run the 3-laptop relay set (subset of the Phase-Star star).
- **Lab test:** Alice (phone) → Bob (phone) pairwise message; shares stripe across
  the 3 nodes; Bob fetches + recovers; `verify_sender` shows Alice. auth=None,
  inner=plaintext (exactly the proven CLI path, now on phones).
- **Exit:** phone-to-phone round-trip through LAN nodes; UI renders the thread.

### Phase 1 — Real identity: RNS chat-identity record + name UX · M
Closes the `chat-identity-separate-from-chain` follow-up; retires the
libp2p-node-key-as-chat-identity demo concession.
- **Node/chain:** add the RNS **chat-identity record type**
  (`chat_identity_ed25519_pubkey`) on rns-resolvers; forward resolve
  name → chat pubkey, and reverse (account/chat-pubkey → name) for "who's this from."
- **dotwave:** persist the chat identity; **register the chat pubkey on the user's
  RNS record**; start conversations by `.rst` name (resolve → chat pubkey) instead
  of pasted hex; on receive, auto-resolve sender chat-pubkey → `.rst` (the
  bridge-doc "dotwave does this automatically").
- **Lab test:** `alice.rst` messages `bob.rst` by name; the thread header shows
  `bob.rst`; Bob sees `alice.rst` as sender. No hex anywhere in the UI.
- **Exit:** name-addressed messaging both directions; identity off the node key.

### Phase 2 — Verified-human send: enforce cert admission · M
Confirms a real (personhood-proven) human is sending — not anti-*bot* (there are no
bots, invariant #0) but the abuse-control gate. The seam already exists in
`chat.rs` + `verify_chat_auth`. ⚠️ Mission tension: this check reveals the sender to
the entry relay — Phase 3A (onion) must close that.
- **dotwave:** sign `blake2_256(CHAT_AUTH_DOMAIN ‖ envelope_bytes ‖ ts)` with the
  device's **HW-attested zkpki cert key** (StrongBox path dotwave already has for
  the ZK-PKI ceremony); fill `auth_thumbprint/ts/sig`. Requires a minted cert on
  the device (reuse the personhood/zkpki flow).
- **Node:** flip `verify_chat_auth` from optional → **required**; reject
  unauthenticated sends.
- **Lab test:** send from a cert-holding phone lands; a forged/uncerted send is
  rejected at the node.
- **Exit:** no unauthenticated send path remains.

### System messages — chain-event dispatcher (lands alongside Phase 1) · S
The chain can message a user. A chain event → a message addressed to the affected
user's mailbox, e.g. *"System: your validator went offline,"* *"System: name
renewal due."*
- **Node/chain:** the `chain-event-dispatcher` turns events into envelopes addressed
  to the user's chat mailbox, sealed to their chat key, **signed by a well-known
  System authority key** (chain/SRT) so the user can verify it's genuinely the
  system, not an impersonator. One-way notification — **no Double Ratchet needed**
  (no conversation); sealed-to-user + system-signed is enough.
- **dotwave:** render a distinct, un-spoofable **System** conversation (badge +
  verified-authority indicator); never allow a normal user to present as System.
- **Lab test:** stop a validator → the operator's phone receives a verified System
  message.

### Phase 3 — Real pairwise encryption: wire the Double Ratchet · L
The nearest "real E2E" unblock for 1:1. **Resolves the transport mismatch** the
`rostro-chat-dr` header records: it omits out-of-order/skipped-keys assuming an
in-order Noise substream, but the relay is store-and-forward and the phone is
RPC-only.
- **Re-scope (vs "full Signal out-of-order"):** because dotwave is the *durable*
  store and the relay is ephemeral, the phone reconstructs exact order from the DR
  header (`msg_num`/`dh_pub`). So we need a **client-side reorder buffer** (feed DR
  in order) + **bounded skipped-message keys** (Signal's own `MAX_SKIP` mechanism,
  which the chat crate omitted) only for the one residual case the ephemeral relay
  creates: a message that **TTL-expires before pickup** = a permanent gap the ratchet
  must survive. Not more than Signal; the durable client just does the reordering.
- **Crate `rostro-chat-dr`:** restore bounded skipped-key handling. (Sister
  `rostro-validator-channel` keeps its in-order assumption — change is chat-side.)
- **DECISION 2 — LOCKED: full X3DH, maximum secrecy from message one.** Use
  **one-time prekeys** (not X3DH-lite) so the very first message is forward-secret
  before any reply — required by the mission. Needs a **one-time-prekey supply**:
  each user publishes a batch; a sender consumes one per new conversation.
  *Open sub-decision (mine to default):* where prekeys live — leaning a dedicated
  prekey store/record refreshed by the client, not on-chain.
- **dotwave:** full-X3DH bootstrap using the recipient's **RNS-published X25519**
  chat key + a one-time prekey; first message carries the signed `HandshakePayload`;
  replace `inner_ciphertext = plaintext` with a DR `WireMessage`; **persist
  per-conversation `Session` state** (serialize + secure-store + survive app
  restart — losing it breaks the ratchet).
- **Lab test:** A↔B sustained thread, DH ratchet advancing; first message (B
  offline) is forward-secret; drop/reorder shares and confirm recovery; expire a
  message past TTL and confirm the thread survives the gap; kill+relaunch and confirm
  the session resumes.
- **Exit:** 1:1 is forward-secret from message one + post-compromise-secure E2E on
  mobile.

### Phase 3A — Metadata anonymity + device-seizure · L (CORE — the mission, not hardening)
Per the Mission section, hiding *who-talked-to-whom* and surviving device seizure
are first-class. **This is the hardest and most mission-critical remaining work.**
- **One-hop onion wrap (#14, Sphinx or lighter):** the entry relay sees the previous
  hop, not the original sender. **Reconcile with Phase 2** — where does the cert
  admission sit when the sender is hidden? (Likely: cert proven to a guard, path
  onion-wrapped beyond it.) This is the open design problem to solve, not defer.
- **Traffic-analysis resistance:** cover traffic / message padding to fixed sizes;
  evaluate a Tor/mixnet-grade transport for the phone↔node link (ISP-observable).
  Be explicit about residual risk where timing correlation isn't fully defeated.
- **dotwave device-seizure defenses:** encryption-at-rest for the local cache,
  **disappearing messages**, and a **duress/panic wipe**.
- **Lab test:** an observer on the lab LAN cannot link Alice→Bob from traffic;
  panic-wipe clears local state; padded sends are uniform on the wire.
- **Exit:** entry relay can't identify the sender; local device discloses nothing
  under seizure; residual traffic-analysis risk documented, not hidden.

### Phase 4 — Groups: MLS within the chain-oblivious constraint · L (likely fast-follow, not MVP)
Hardest; gated on mobile-state walls (#17/#18). Chain stays oblivious.
- **Crate `rostro-chat-mls`:** replace `openmls_memory_storage::MemoryStorage` with
  a **persistent `StorageProvider`** over secure storage (#18).
- **Ordering (off-chain, per invariant #2):** **single-committer/admin model** for
  the MVP — only the group admin issues Commits, sidestepping concurrent-commit
  conflicts. (Full concurrent reconciliation is later.)
- **Distribution:** publish member **KeyPackages** (RNS chat record or relay);
  route **Welcome** to new members over the relay (sealed); group send/fetch via
  `EnvelopeKind::Group` + `PickupKey::for_group` (already in the wire types).
- **Offline catch-up (#17):** fetch + process missed Commits to advance epoch
  before sending.
- **dotwave:** create group, add/remove member, group thread UI.
- **Lab test:** 3-member group across the 2 phones + 1 laptop client; add a 4th;
  remove a member and confirm they can't read post-removal messages (MLS FS).
- **Exit:** small admin-managed groups work E2E with removal forward-secrecy.

### Phase 5 — Productionization for public testnet · M (ongoing)
(Onion + device-seizure moved up to Phase 3A — they're mission-core.)
- **Chain rate-limit per SS58** (the other half of the abuse-control gate).
- **Relay selection policy** (#15) + **DHT/Kademlia tuning** (#16).
- **dotwave productionization:** background fetch / notifications, delivery + read
  states, key/session backup UX, error surfaces, multi-account.
- **Deploy:** public node endpoints; move the in-app default off the LAN override.

---

## Testnet (Camino) MVP line

Camino scope = **BTOW + Phase Star + chat**. The chat MVP for public testnet is
**Phases 0–3 + Phase 3A** (name-addressed, verified-human, forward-secret-from-send
**1:1**, **with metadata anonymity + device-seizure defenses**). Because the mission
is life-or-death privacy, **Phase 3A (onion + traffic-analysis + device-seizure) is
in the MVP, not deferred** — a 1:1 system that hides content but leaks who-talked-to-
whom is not shippable to the people this is for. **Groups (Phase 4)** remain a
**fast-follow** (MLS mobile state is known-hard; 1:1 is the proven spine). Where a
defense is partial at launch (e.g. timing-correlation residual), **say so in-app** —
honesty is a safety feature for these users.

## Open problems mapped to phases
| # | Problem | Phase |
|---|---|---|
| DR | in-order assumption vs store-and-forward relay | 3 |
| 14 | onion-routing protocol choice (sender anonymity to first relay) | **3A (core)** |
| — | traffic-analysis resistance (cover traffic / mixnet transport) | **3A (core)** |
| — | device-seizure (at-rest, disappearing, panic-wipe) | **3A (core)** |
| 15 | stripe relay selection (stable subset vs rotation) | 5 |
| 16 | DHT shape/tuning for chat scale | 5 |
| 17 | mobile MLS state sync after offline-for-blocks | 4 |
| 18 | MLS state backup/restore on lost/replaced device | 4 |

## Cross-cutting risks
- **Traffic-analysis vs a nation-state (Phase 3A)** is the highest-stakes unknown:
  timing/volume correlation may not be fully defeatable without mixnet-grade cover
  traffic. Treat any residual as a **disclosed limitation**, never a silent gap.
- **MLS mobile state (#17/#18)** is the biggest *feature* unknown — keep groups off
  the MVP critical path.
- **Cert availability on device (Phase 2)** depends on the zkpki/personhood mint
  flow being usable from dotwave in the lab.
- **DR session-state durability (Phase 3)** — a corrupted/lost ratchet is
  unrecoverable; treat persistence as load-bearing, not best-effort.
