# dotwave ⇄ Rostro chat — Phase 4: metadata anonymity (the onion) (v1.0)

**Last touched:** 2026-06-12
**Status:** active. Design locked in the 2026-06-12 thread; implementation
starting on `chat-onion-v0`. Companion to the plan of record
[DOTWAVE-CHAT-CRYPTO-ARCHITECTURE.md](DOTWAVE-CHAT-CRYPTO-ARCHITECTURE.md)
(Phase 4 there points here for the detail). Mission framing lives in
[DOTWAVE-CHAT-ROADMAP.md](DOTWAVE-CHAT-ROADMAP.md).

---

## Why this phase exists

For the users this platform is built for — a whistleblower, a journalist, a
deep-cover agent against a **nation-state adversary** — *proof that they talked
to a given person at a given time is what gets them killed*, more than the
message body. Phases 1–3+5 made the **content** secret, verified, hardware-bound,
and forward-secret. None of that hides **who-talked-to-whom**. That is this
phase, and the roadmap is explicit that it is **core, not post-MVP hardening**.

**Honesty over false comfort** is a safety feature here: where a defense is
partial, the app says so. We do not promise more than the math delivers to
people whose lives depend on it.

## Documented assumption: burner-grade opsec

We assume a life-or-death sender practises meatspace operational security — a
**burner phone / burner network connection** not attributable to their real
identity. This is the line between what software owns and what the operator
owns:

- **Software owns** the *cryptographic* split of who-from-where (the onion) and
  the *identity* layer (throwaway certs/names).
- **The operator owns** the *network attribution* of the physical device (the
  burner).

This is why we do **not** try to defeat a global-passive-adversary timing
correlation in software for v1. We build a strong one-hop onion, we disclose the
timing residual plainly, and we do not pretend the software is doing the burner's
job.

---

## What each observer learns *today* (post Phase 5, pre Phase 4)

| Observer | Learns today | Verdict |
|---|---|---|
| **Entry relay** | Sender's **cert→bound account**, sender **IP**, recipient **pickup key/bucket**, timing, size | The kill vector, fully exposed |
| Other stripe relays | Pickup key (recipient bucket), timing, share sizes | Recipient-side linkable |
| Fetch relay | Which pickup key fetches, when, from which IP | Recipient identified by correlation |
| LAN / ISP observer | Phone↔relay timing + volume | Timing correlation open |
| Chain | Nothing (no social graph) | Holds ✅ |

The entry relay alone can answer *"account A dropped into bucket B at T."* That
single fact is what this phase must break.

**Note on striping vs. bucket:** the XOR-stripe layer *distributes* shares for
availability; it does **not** anonymize. Every share carries the **same**
pickup key (derived from the recipient), and the bucket is a coarsening of that
key. The pickup key is the recipient-address metadata we must protect; striping
never hid it.

---

## The two axes (and the third residual)

Phase 4 splits cleanly into two independent anonymity problems plus one
disclosed residual:

### Axis 1 — Identity anonymity → throwaway rotation (no new crypto)

A sender (or recipient) uses a **fresh seed → fresh SS58 → fresh RNS name →
fresh HW-attested cert** as a disposable identity. This is *legal by
construction* and is the cleanest solution to the identity leak:

- The chat-admission cert attests *"a genuine secure element / real human is
  behind this drop"* — it is the **anti-abuse** gate, **not** the
  proof-of-personhood uniqueness gate. `verify_chat_auth` only checks the cert
  is `Active` and the signature matches `device_pubkey`; it never checks "is
  this the only cert this human holds." `self_discard_cert` exists; minting
  another is allowed.
- The certs carry **no real-world identifier** by design; ZK-PKI's whole purpose
  is to prove "I hold a valid HW-attested cert" without revealing *which*.
- PoP **uniqueness** (ICAO-doc/biometric stack, EK-dedup on the personhood
  capability) bites only for high-stakes roles (validating, governance), **not**
  for sending a chat message.

**Anti-abuse shifts to minting economics.** Because per-cert rate-limiting is
evadable by rotation, the real bound on abuse is the **cost of minting a cert**
(deposit + needing a genuine secure element). This is a tuning knob: cheap
enough that a journalist rotates freely, costly enough that a spammer can't mint
10,000 throwaways. **Decision to lock:** target mint cost / rate.

**Rotation granularity** (product decision, default mine): per-message is
maximal anonymity but maximal cost (an on-chain mint each time) and a tiny
anonymity set; **per-correspondent or per-session** is the sweet spot. Default:
per-correspondent throwaway, rotated on a cadence.

**Plumbing to confirm (not a blocker):** throwaway chat certs must be minted
**non-PoP** so they do **not** write the on-chain EK registry, and the minting
path must not leak a stable device identifier in a public extrinsic — else all
of one person's throwaways become correlatable as "same device," defeating the
rotation. Lean on the ZK-PKI proof for device unlinkability.

### Axis 2 — Network-origin anonymity → the one-hop onion (the hard part)

Rotation hides *who you are*; it does nothing about *where you connect from*.
The entry relay still sees your **IP** next to the destination bucket. (The
burner defangs the attribution of that IP; the onion defangs the *linkage* of IP
to destination.) The onion is what splits them:

```
sender → GUARD → RELAY-2 → (existing stripe fan-out → bucket subscribers)
```

- **Sender** wraps the drop in two nested seals and authenticates its
  **throwaway cert to the GUARD**.
- **GUARD** runs the anti-abuse check (cert `Active`), peels the **outer** seal,
  learns only *"forward this opaque blob to RELAY-2."* It sees the sender
  (cert + burner IP) but **not** the destination.
- **RELAY-2** receives the forwarded blob from the guard (a canonical-gated peer
  relay), peels the **inner** seal, learns the **destination bucket**, and hands
  off to the **existing** stripe-and-distribute machinery. It sees the
  destination but **not** the sender (it saw the guard, a peer relay).
- Relinking sender→bucket requires the **specific guard and relay-2 to collude**.

**Structural rule (load-bearing):** the onion hop sits **in front of** the
bucket/stripe layer, never woven into it. The guard must **never** be the relay
that injects into bucket routing — otherwise it would see sender *and* bucket and
the split collapses. This keeps the new node-side surface **narrow**: one new
operation, "guard forwards an opaque blob to relay-2."

**Where cert-auth sits — the roadmap's open question, answered:** *cert
admission sits at the guard; the path beyond it is onion-wrapped.* RELAY-2 does
not re-auth the sender; it accepts relay-to-relay forwards only from
canonical-gated peer relays, so the trust chain is
`client →(cert auth)→ guard →(canonical-gated peer)→ relay-2`. This composes with
the existing relay trust model; no new trust root.

### Resolved structure — the peeler *outside* gossipsub (2026-06-12)

The peel (the **one** key-using step) lives in a mechanism **beside**, not
inside, the secret-free gossipsub routing/sharding layer. Gossipsub gains only a
**public** "is this blob addressed to my own pickup? → hand it out" check; the
peeler holds the node's own key (choice A, `rostro-node-identity`), peels one
layer, and hands the result **back** to gossipsub. So the chat/gossipsub layer
holds **no secrets** (preserved); the node uses its own node-key only in that one
quarantined box. The onion thus coexists with the secret-free routing layer
instead of contaminating it.

```
THE MESSAGE  (nested seals, all built by the sender on-device)
   OUTER  ─ sealed to GUARD ──►  Forward{ next_hop: relay-2, inner: INNER }
              INNER  ─ sealed to RELAY-2 ──►  Deliver{ drop }
                         drop  ─ sealed to RECIPIENT ──►  the real message

THE FLOW
 PHONE              ┌── GUARD node ──────────┐    ┌── RELAY-2 node ────────┐   bucket    PHONE
 (sender)           │  GOSSIPSUB  (no key)    │    │  GOSSIPSUB  (no key)    │   peers  (recipient)
 wrap onion         │  ┌───────────────────┐  │    │  ┌───────────────────┐  │
 cert-auth          │  │ blob to MY pickup? │  │    │  │ blob to MY pickup? │  │
   │ OUTER          │  │  → hand out        │  │    │  │  → hand out        │  │
   └──────────────► │  └─────────┬─────────┘  │    │  └─────────┬─────────┘  │
                    │            ▼             │    │            ▼             │
                    │  ┌───────────────────┐  │    │  ┌───────────────────┐  │
                    │  │ ONION PEELER  🔑  │  │    │  │ ONION PEELER  🔑  │  │
                    │  │ (the ONLY secret) │  │    │  │ (the ONLY secret) │  │
                    │  │ peel → Forward    │  │    │  │ peel → Deliver    │  │
                    │  └─────────┬─────────┘  │    │  └─────────┬─────────┘  │
                    │            ▼             │INR │            ▼             │ shards
                    │  ┌───────────────────┐  │    │  ┌───────────────────┐  │ ┌──────┐
                    │  │ GOSSIPSUB: route  │  │    │  │ GOSSIPSUB: insert │  │ │fetch │
                    │  │ INNER to relay-2 ─┼──┼────┼─►│ envelope → stripe─┼──┼─►│  +   │
                    │  └───────────────────┘  │    │  │ + push to bucket  │  │ │decryp│
                    └─────────────────────────┘    │  └───────────────────┘  │ └──────┘
                                                    └─────────────────────────┘ (recipient
                                                                                  key only)

WHO LEARNS WHAT
   GUARD     : sender (cert+IP) + next hop = relay-2     ✗ NOT the recipient
   RELAY-2   : recipient bucket + the drop to inject     ✗ NOT the sender
   gossipsub : only the pickup keys it routes/shards by  ✗ holds no key, peels nothing
   → relinking sender→recipient needs the SPECIFIC guard AND relay-2 to collude.
```

**Build shape:** the peeler is its own component (holds `NodeSecret`, runs
`rostro_chat_onion::process_hop`); the stripe receive handler gains only the
public recognize-and-handoff; on `Deliver` the peeler calls the existing
stripe-and-distribute path (relay-2 becomes the apparent submitter — sender
gone); on `Forward` it emits the inner toward the next hop's bucket.

### Axis 3 — Timing / volume → cover traffic (disclosed residual, not v1)

Even with onion + burner, a global passive adversary can correlate *timing and
volume*. Defeating that needs cover traffic / mixnet-grade transport — out of v1
scope per the burner assumption. **v1 ships fixed-size padding** (cheap, we
control the wire format) and **discloses the residual in-app**. Full cover
traffic is a later hardening.

---

## Wire format — nested seal (one hop), not Sphinx

For a single hop with both relays under our canonical-gated trust model, full
Sphinx (fixed-size packets, per-hop MACs, bidirectional reply blocks, replay
caches) is overkill. We use a **nested seal** built on the existing
`rostro-chat-sealed-sender` primitive (per-message ephemeral X25519 ECDH +
HKDF-SHA256 + ChaCha20-Poly1305). Sphinx is the documented upgrade path if we
ever add hops.

Each relay publishes an **X25519 onion key** (derivable from / alongside its
existing node key). Construction:

```text
DROP        = the SealedEnvelope + bucket routing info relay-2 injects
DROP_padded = pad(DROP, FIXED_DROP_SIZE)          // size-correlation defense
INNER       = SealedSender.seal(relay2_onion_pub, DROP_padded)      // {eph, ct}
FORWARD     = SCALE{ next_hop: relay2_id, inner: INNER }
OUTER       = SealedSender.seal(guard_onion_pub, FORWARD)           // {eph, ct}
```

- Sender authenticates throwaway cert to the guard, sends `OUTER`.
- **Guard:** `unseal(guard_onion_secret, OUTER)` → `FORWARD` → forward `INNER`
  to `next_hop`. Guard cannot read `INNER` (sealed to relay-2's key).
- **Relay-2:** `unseal(relay2_onion_secret, INNER)` → `unpad` → `DROP` → inject
  into the existing stripe path. Relay-2 sees no sender material (the outer seal,
  with the sender's ephemeral, never reaches it).

Per-message ephemeral keys at every layer ⇒ no cross-message linkage; fixed
`FIXED_DROP_SIZE` ⇒ guard and relay-2 both see constant-size blobs.

## Selection rules (to lock during 4a)

- **Guard selection:** Tor-style — a **small stable guard set per identity**
  (reduces the "eventually you pick a malicious guard" exposure at the cost of
  concentrating trust). Re-evaluated per throwaway identity. *Alternative:
  random per-message (spreads trust, raises eventual-malicious-hit odds).*
  Default: stable small set.
- **Relay-2 selection:** random from the bucket-capable relay set, **distinct
  from the guard**, re-rolled per message.
- **Anti-abuse at the guard:** rate-limit per presented cert + the minting cost
  bound (Axis 1).

---

## In-app disclosures (honesty is a safety feature)

The app states, plainly, where defenses are partial:

- *"The relay you connect through can see that **a** message was sent from this
  connection at this time — never to whom. Use a connection not tied to your
  identity."* (the burner seam)
- *"A powerful adversary watching the whole network may correlate timing and
  message volume. This is not fully defeated."* (Axis 3 residual)
- Throwaway-identity status + rotation cadence surfaced, not hidden.

---

## Device-seizure defenses (Axis 4, app-side, lands in 4b)

Per the mission's third frontier — *the endpoint must survive seizure*:

- **Amnesiac reads** — consume-on-read; plaintext is transient (already the
  Phase-3 read shape: `chat_read_content` returns plaintext, never persists it).
- **Disappearing messages** — TTL on stored at-rest blobs + session state.
- **Duress / panic-wipe** — one action clears local state (keys, sessions,
  at-rest blobs). A perfect network is worthless if the endpoint folds.

---

## Phased plan with gates

### 4a — One-hop onion · L  ◀ **in progress**
- **Crate** `rostro-chat-onion`: nested-seal wrap + uniform per-hop `process_hop`
  (`Forward`/`Deliver`), sealed to relay `NodeIdentity`s, fixed-size padding.
  Pure crypto. ✅ 10/10 tests.
- **Crate** `rostro-node-identity` (choice A — a node's identity IS its ed25519
  key; sign/verify + XEdDSA seal key). ✅ 6/6 tests.
- **Node:** the peel lives in an isolated mechanism *outside* the secret-free
  gossipsub layer (see the diagram above). `chat_send_onion` (guard entry):
  cert-auth → peel with the node's own `NodeSecret` → `Deliver` injects the
  recipient envelope into the shared `stripe_and_distribute`; `Forward` is the
  relay-2 hand-off (slice 2). The node holds only its OWN key, only in the
  peeler.
- **dotwave:** wrap the drop as an onion (`OnionDeliverPayload` →
  `wrap_onion`); call `chat_send_onion`; client-side discovery; throwaway
  send-identity rotation (fresh seed/SS58/name/non-PoP cert).
- **GATE:** an observer on a single relay (guard *or* relay-2, not both) cannot
  link sender→bucket; cert-auth still enforced at the guard; basic chat
  unaffected; padded blobs uniform on the wire.

**Build status (2026-06-12) — node + client move in lockstep.** Implemented on
the `chat-onion-v0` worktree (rostro) plus the dotwave `rust_core`:
- **Slice 1a ✅** — node's own `NodeSecret` plumbed into the chat layer for the
  isolated peeler (`8cc137bf5e`). Comment corrected: chat holds no *user*
  secret; the node holds its own key only in the peeler.
- **Slice 1b ✅** — `chat_send_onion` peeler + the shared `stripe_and_distribute`
  helper (`405e4dbca6`). `Deliver` path complete; `Forward` stubbed for slice 2.
  The proven `send_envelope` left UNTOUCHED (zero-risk); the two converge on the
  helper once the onion path is fabric-proven.
- **Slice 1c ◀ next** — dotwave wraps a **1-hop** onion (`path = [guard]`) and
  calls `chat_send_onion`; fabric proof: phone → guard peels → delivers →
  recipient fetches + decrypts. First time the onion moves a message on real
  nodes.
- **Slice 2** — relay-2 recognise-and-handoff (the `Forward` path) for the full
  **2-hop** split.

### 4b — Device-seizure + disclosures · M
- **dotwave:** disappearing messages, duress/panic-wipe, the disclosure UX.
- **GATE:** seized locked device discloses nothing; panic-wipe clears state;
  residual timing risk stated in-app.

### FUTURE — cover traffic / mixnet transport
- Per the burner assumption, deferred. Documented as a known limitation until
  built.

---

## Non-inhibition (the standing rule)

This phase must **not** break basic chat (named, convenient) and must **not**
inhibit secure-messenger (dead-drop, throwaway, deniable). The onion is a
transport-layer wrapper in front of the existing stripe machinery; the throwaway
model is exactly the secure-messenger identity story. Two products, one
foundation.

## Open decisions to lock during 4a

1. Mint cost / rate for throwaway chat certs (anti-abuse vs. free rotation).
2. Stable-guard-set size vs. random-per-message guard.
3. `FIXED_DROP_SIZE` (cover the realistic envelope range without over-padding).
4. Confirm the non-PoP mint path leaks no stable device id in a public extrinsic.

---

**Critical path:** 4a (onion) is the hard, node-touching, mission-critical
piece. 4b (device-seizure) is app-side fast-follow. Cover traffic is the
disclosed-residual tail.
