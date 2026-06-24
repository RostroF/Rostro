# Dotwave Chat — Dead Drops

Status: **design locked, Phase 0** (spec only; no code yet)
Branches: engine `chat-deaddrop-v0` (Rostro, off `rostro-main`) · app `chat-dead-drops-v0` (dotwave, off `main`)
Depends on: chat onion transport, rns-chat typed CHAT/MESSAGE records, content-seal silicon seam — all on `rostro-main` / dotwave `main` as of this writing.

---

## 1. What a dead drop is

A **dead drop** is a chat message routed by an opaque **label** instead of by the
recipient's identity. The label carries no link to who the message is for; the
recipient recognizes drops addressed to a label they are polling for and unwraps
them with keys they already hold. After a single bootstrap message, the
conversation walks a sequence of **rotating return addresses** so that no
identity-linked label ever accumulates more than one message on the wire.

The point is **metadata privacy**: an observer (including relays) sees only a
field of uniform 32-byte routing keys and opaque ciphertext, with no handle that
says "these messages are for Bob" or even "these messages are the same
conversation."

### 1.1 Not to be confused with: the vestigial "dead-drop identity"

`rust_core/src/core.rs` (the `chat_publish_identity` path, ~L885–955) uses the
term "dead-drop" for a *different, unused* concept: a name registered with a
`CHAT` record but **no `MESSAGE` record** (content key omitted, exchanged
out-of-band). Per product intent **every registered name carries both `CHAT` and
`MESSAGE`**, so that branch (`inner_content_key.is_empty() => CHAT only`, and the
`has_message_key: false` plumbing) is dead code. It is unrelated to this feature
and is a **cleanup candidate** (remove the empty-content-key branch), tracked
separately — do not couple it to dead-drop messaging.

Our dead drop does **not** require Bob to lack a `MESSAGE` record. Bob has a
perfectly normal name. The unlinkability comes from Alice **not resolving** Bob's
name on-chain when she messages a callsign — she holds his content key from a
prior exchange (the existing `ferdie-send-to` out-of-band-key pattern).

---

## 2. Layer cake

A dead drop is the **normal sealed message** with the routing field swapped for a
label and a return address added to the innermost content. Three layers:

| Layer | Encrypted? | Carries | Who reads it |
|-------|-----------|---------|--------------|
| **Outermost — label** | No | A ≤32-byte routing selector (callsign or random) | The recipient, to claim the drop; relays, to shard it |
| **Middle — sealed sender** | Yes | Opaque ciphertext + sender's ephemeral pubkey | Only the holder of the recipient's static key |
| **Innermost — content** | Yes | Plaintext + **return address** | Only the recipient (hardware/content key) |

Key fact established by reading the code: **the transmitted middle layer already
carries zero recipient identity.** `SealedEnvelope`
(`substrate/utils/rostro-chat-primitives/src/envelope.rs:82`) holds only
`kind`, `outer_ciphertext`, the **sender's** `ephemeral_pubkey`, and
`message_id`. The recipient's pubkey is never in the envelope — it lives solely
in the routing field `OnionDeliverPayload.recipient_chat_pubkey`
(`substrate/utils/rostro-chat-onion/src/lib.rs:98`). So a dead drop does not
"strip" the envelope; it only replaces that one routing field.

---

## 3. Decision A — relays are dumb infra; they see only opaque pickup keys

The relay must not be able to tell a dead drop from a normal message. Today the
relay receives `recipient_chat_pubkey` and does the work itself: validate it as a
valid Edwards point, convert ed25519→x25519, then
`PickupKey::for_pairwise(x25519) = blake2_256(domain || x25519)`
(`substrate/bin/gemini-node/src/chat_rpc.rs` peel path, ~L894–910;
`descriptor.rs:158`). If dead drops carried a pre-hashed key while normal
messages carried an ed25519 pubkey, the relay could distinguish the two — which
defeats the blending.

**The fix: move the hash to the sender for *all* traffic.** `OnionDeliverPayload`
shrinks to carry a finished pickup key:

```rust
pub struct OnionDeliverPayload {
    pub pickup_key: [u8; 32],   // was: recipient_chat_pubkey: [u8; 32]
    pub envelope_bytes: Vec<u8>,
}
```

- **Normal send:** sender computes `PickupKey::for_pairwise(recipient_x25519)`
  (it already holds the x25519 — it just sealed to it).
- **Dead-drop send:** sender computes `PickupKey::for_deaddrop(label)` (new).
- **Relay:** shards `envelope_bytes` under `pickup_key`. No validation, no
  conversion, no hashing. It **cannot** distinguish the two paths.

Consequences:
- The curve-validate / convert / hash block at the peel seam is **deleted**
  (logic *subtracted* from the GPL3 node — aligns with the GPL3-footprint and
  code-quality north stars).
- Curve validation does not disappear; it **moves to the sender**, which already
  must convert the recipient's ed25519→x25519 to seal. Validation lands where the
  key is actually used cryptographically.
- This is a **hard cutover** of the normal wire format. No grace window, no
  variant coexistence — we are pre-testnet, GitHub mains are the source of truth,
  and there is no deployed network to migrate.

### 3.1 Why hashing the label is strictly better

Because `for_deaddrop` hashes, even a short human callsign like `pigballs`
becomes a 32-byte blake2 output **byte-indistinguishable from every normal
pairwise pickup key** in the store. The "short callsign stands out" tradeoff
disappears at the store/gossip layer — and, under Decision A (sender pre-hashes),
even at the exit relay. All three pickup-key sources — `for_pairwise`,
`for_deaddrop`, and raw-random return addresses (§5) — produce uniform 32-byte
values that mix in one keyspace.

```rust
// descriptor.rs, beside for_pairwise / for_group
pub const PICKUP_KEY_DEADDROP_DOMAIN: &[u8] = b"rostro/chat/pickup-key/deaddrop/v1";

impl PickupKey {
    /// Pickup key for a dead drop addressed to an opaque ≤32-byte label.
    pub fn for_deaddrop(label: &[u8]) -> Self {
        let mut input = Vec::with_capacity(PICKUP_KEY_DEADDROP_DOMAIN.len() + label.len());
        input.extend_from_slice(PICKUP_KEY_DEADDROP_DOMAIN);
        input.extend_from_slice(label);
        Self(blake2_256(&input))
    }
}
```

---

## 4. Two label classes

### 4.1 Standing callsigns
- Human-chosen string (`pigballs`) **or** a generated random ed25519-shaped
  string. Both are just bytes; the random form is for users who prefer an opaque
  token.
- Manual, **≤10** per user, **reusable until removed**.
- The conversational **front door**, exchanged offline.
- App polls `PickupKey::for_deaddrop(callsign)` for each.

### 4.2 Return addresses
- Auto-generated, ephemeral, **separate pool** (does **not** count against the 10).
- A return address **is a freshly-minted random 32-byte value used directly as a
  pickup key** — no hashing, never human-facing. Carried in the encrypted
  innermost content (§5). The recipient drops it straight into
  `OnionDeliverPayload.pickup_key` for replies.
- The conversation **rides these**, not the callsign.

---

## 5. Return address in the innermost content

The innermost (content-sealed) payload gains one field: a 32-byte
`return_pickup` minted by the sender. It is end-to-end encrypted to the recipient
— invisible to relays and to anyone who is not the recipient. On decrypt, the
recipient learns where to send replies.

The return address is **raw** (used directly as a pickup key), because it is
never typed by a human and never needs the callsign→uniform-key mapping that
`for_deaddrop` provides.

---

## 6. Ping-pong rotation

Each party keeps, **per thread**:

- `outbound_target` — the pickup key I send to. Set from the **last received**
  message's `return_pickup`.
- `inbound_current` — the return address I am advertising. I **mint a new one at
  the start of each of my turns** (a receive→send transition) and reuse it for the
  whole burst.
- `inbound_grace` — my ≤**3** most-recently-superseded return addresses, still
  polled to catch late/in-flight messages, then dropped.

Rule (the user's "ping-pong"): you keep sending to the same `outbound_target` for
as many messages as you like; when the peer responds, they hand you a new target,
and you switch new messages to it. You rotate your **own** inbound address once
per turn, not per message.

```
Alice                                   Bob
-----                                   ---
mint A1
send → for_deaddrop("pigballs")         poll for_deaddrop("pigballs")
  content.return_pickup = A1            collect opener, learn A1
                                        mint B1
  poll A1                       ←  send → A1   (burst of N, each return_pickup = B1)
collect, learn B1
mint A2
send → B1 (return_pickup = A2)  →       poll B1, learn A2
  A1 enters grace (3 rounds)            mint B2
                                ←  send → A2   (return_pickup = B2)
...                                     B1 enters grace (3 rounds)
```

**`pigballs` receives exactly one message, ever.** Everything after the opener
rides disposable, mutually-unlinkable return addresses.

`inbound_grace` bounds the poll set: at most ~4 of your own return addresses per
thread (current + 3 grace), plus ≤10 standing callsigns, plus your own identity
pickup key for normal messages.

---

## 7. Interaction with in-order delivery (self-hash chain)

In-order delivery (the in-seal `prev_self_hash` chain, already shipped) is
**orthogonal** to address rotation. The self-hash chain orders messages
**logically** within a thread; the pickup key is **transport** only. A thread's
messages chain by `prev_self_hash` regardless of which return address delivered
each one, and `orderThread` reassembles them by the chain, not by pickup key. The
implementer must keep these separate: rotating `outbound_target` must **not**
reset or fork the self-hash chain. A burst to one return address and the first
message to the next return address are consecutive links in the same chain.

---

## 8. Send / receive paths

### 8.1 Sender (dotwave `rust_core/src/chat.rs`)
- Normal send: compute `for_pairwise(recipient_x25519)`, set
  `OnionDeliverPayload.pickup_key` (was: pass the ed25519 pubkey for the relay to
  hash). Sealing path unchanged.
- New `chat_send_deaddrop(...)`: seal to the recipient's **real** keys (sealed
  sender + content/hardware — Alice holds them out-of-band), set
  `pickup_key = for_deaddrop(label)`, and write `return_pickup` into the content
  layer. The label is pure routing, fully decoupled from the crypto.

### 8.2 Recipient poll (dotwave `rust_core/src/chat.rs`, `chat_fetch` ~L1020)
- Today derives **one** pickup key from the user's seed and calls
  `chat_fetch_shares(pickup_hex, relay)`.
- Expand to fetch a **set** of pickup keys: own identity key + each standing
  callsign's `for_deaddrop` key + each live return address (current + grace) per
  thread. v0 may loop the existing RPC per key (set is small, ≲20); a batch RPC is
  a later optimization.

---

## 9. App state & UI

- **Two pools:** standing callsigns (≤10, persistent, manual) and return
  addresses (auto, ephemeral, per-thread). Distinct stores.
- **Ping-pong state machine** (§6) per thread, with 3-round grace retirement.
- **Thread binding:** return addresses map to a conversation so rotation and the
  self-hash chain (§7) stay coherent.
- **UI:** Message options → **Dead Drops** → **Callsigns**: add / remove a
  callsign, and a "generate random label" action. Claimed drops surface into the
  thread like any message; compose-to-callsign opens a thread keyed to a callsign.

---

## 10. Test tooling

- labtool: `deaddrop-send-to <label> <recipient_pubkey> <content_key> [count] ...`
  and `deaddrop-poll <label> ...`, mirroring `ferdie-send-to` but routing by
  `for_deaddrop(label)`.
- chat-rig (`scripts/run-chat-rig.sh`): 2 validators + 2 relays, the existing
  topology — no rig change needed.

---

## 11. Phased plan

- **Phase 0 — Spec + branches** *(this doc).*
- **Phase 1 — Wire cutover (engine).** `PickupKey::for_deaddrop` +
  `OnionDeliverPayload.pickup_key` + sender computes the hash + delete the
  peel-seam validate/convert/hash block. **Gate:** existing chat-rig regression —
  normal phone→ferdie 2-hop still delivers, no user-visible change.
- **Phase 2 — Dead-drop send/poll (engine).** `return_pickup` in content;
  `chat_send_deaddrop`; multi-key `chat_fetch`; labtool commands.
  **Gate:** single dead drop E2E on the rig.
- **Phase 3 — Pools + ping-pong (app state).** Two pools, rotation, 3-round
  grace, thread binding. **Gate:** 3-round ping-pong on the rig; assert
  `for_deaddrop("pigballs")` holds exactly 1 drop after the exchange.
- **Phase 4 — UI.** Dead Drops → Callsigns; claimed-drop surfacing; compose.
- **Phase 5 — Hardware proof.** S20, both directions.

---

## 12. Out of scope for v0 (flagged, not hidden)

- **Co-poll correlation.** Polling N pickup keys over one relay connection lets a
  malicious relay correlate them to one client. Dead drops still hide *who*, but
  not *that these labels share a poller*. Fix = poll diversity / per-label
  circuits. Follow-up workstream.
- **Exact grace counting** — whether "3 rounds" counts ping-pong cycles or
  individual turns. Pinned at Phase 3; does not affect architecture.
- **Vestigial CHAT-only "dead-drop identity"** cleanup (§1.1) — separate.

---

## 13. File touchpoints (anchors at time of writing)

| Change | File |
|--------|------|
| `for_deaddrop` + domain | `substrate/utils/rostro-chat-primitives/src/descriptor.rs` (~L154–171) |
| `OnionDeliverPayload.pickup_key` cutover | `substrate/utils/rostro-chat-onion/src/lib.rs:95` |
| Delete peel validate/convert/hash; use `pickup_key` | `substrate/bin/gemini-node/src/chat_rpc.rs` (~L894–910) |
| Drop send_envelope curve-validate (moves to sender) | `substrate/bin/gemini-node/src/chat_rpc.rs` (~L1210) |
| Sender computes pickup key; `chat_send_deaddrop`; `return_pickup` | `rust_core/src/chat.rs` (build/seal ~L820, send ~L910) |
| Multi-key poll | `rust_core/src/chat.rs` (`chat_fetch` ~L1020) |
| App state, pools, ping-pong, UI | dotwave `lib/` + `rust_core/src/` |
| labtool dead-drop commands | `rust_core/src/bin/labtool.rs` |
| (separate) vestigial CHAT-only cleanup | `rust_core/src/core.rs` (~L885–955) |
