# dotwave ⇄ Rostro — the mobile bridge to testnet

**Last touched:** 2026-06-09
**dotwave repo:** `/home/coder/Polkadot/dotwave` (branch `rostro-port-v0`)
**dotwave HEAD:** `d33e833` (port write path to typed against current Rostro + de-paseo)
**Chain:** `gemini-node` (gemini-runtime), `rostro-main`

This is a **known goal**, not a handoff of in-flight work. It states what dotwave
is *for* and what it must do to reach the Camino testnet. Companion to
[CAMINO-TESTNET-HANDOFF.md](CAMINO-TESTNET-HANDOFF.md) (chain/lab bringup) and
[PHASE-STAR-HANDOFF.md](PHASE-STAR-HANDOFF.md) (5-node + RVM).

---

## The mission

**Get Rostro and dotwave to testnet together.** dotwave is the **only mobile app
that gives a human access to Rostro** — it is the bridge to the infra. A person
without dotwave cannot reach the chain, their names, their personhood proof, or
their messages from a phone. So "ship the testnet" includes "ship dotwave," not
as an afterthought but as the front door.

Testnet (Camino) scope is **BTOW + Phase Star + chat** — governance is out. Two
of those three are things dotwave surfaces to the user.

## The two surfaces dotwave bridges (both over RPC to a node)

dotwave reaches Rostro by talking **JSON-RPC to a Rostro node** over localhost /
the operator's public endpoint. The phone does **not** run libp2p or join any
gossip mesh — the node does that on its behalf. Both surfaces below ride the
same RPC transport.

### 1. Chain ops — ✅ ported (committed `d33e833`)

Balances, RNS names, PoP / ZkPki certs. The write path is now on the **typed
`polkadot::tx()` macro** (codec-exact encoding), reads on the native
`rostro-client` crate.

> **Load-bearing lesson — do not undo.** dotwave depends on **crates.io
> subxt 0.50**, whose *dynamic* encoder mis-encodes Rostro's metadata (rejects
> the `AccountId32`-newtype and `Vec<u8>` shapes — "Cannot encode Struct into
> type ID …"). The Substrate-lineage subxt handles them; the crates.io one does
> not. **Use the typed macro, never `subxt::dynamic::tx`.** Refresh
> `src/polkadot_metadata.scale` from a live node when the runtime changes.

Proven on a live node: Balances transfer lands; sudo `set_official` finalizes;
`register` reaches dispatch. (`register` only fails to *complete* on `--dev`
because the gemini dev genesis never initializes the RNS registry —
`OfficialNotInitiated`, then `NotExist` for the missing TLD base node. That's a
chainspec/genesis item, not dotwave.)

### 2. Messaging — the next build

Rostro can send **encrypted messages between users and groups**. The user flow:

> A dotwave user signs an encrypted payload → Rostro shards it across nodes →
> the recipient collects the shards and decrypts locally on their dotwave app.

This is **not a pallet** — it is an off-chain layer living in
`substrate/utils/rostro-chat-*`, fronted by RPC on the node. Grounded mechanism:

| Stage | Where | What |
|---|---|---|
| Encrypt | on-device | MLS (groups, openmls/RFC 9420) or Double Ratchet (1:1) |
| Seal | on-device | Sealed Sender — ephemeral X25519 ECDH + HKDF + ChaCha20-Poly1305; the wire shows only an opaque blob |
| Sign | on-device | under the user's SS58 / Ed25519 identity |
| Send | RPC → node | `chat_send_envelope` ([chat_rpc.rs](../substrate/bin/gemini-node/src/chat_rpc.rs)) |
| Shard | node | `chat_stripe_protocol` stripes shares across relay nodes into the ephemeral `ShareStore`; `chat_rebalance` / `chat_anti_entropy` keep them distributed |
| Gate | node | `chat_admission` — canonical-files gate, on the general (non-validator) gossip channel |
| Pickup | RPC → node | recipient's dotwave fetches its shares (`by_pickup` index) |
| Decrypt | on-device | reassemble shares → MLS/DR decrypt locally |

Reference client: `substrate/bin/utils/rostro-chat-cli` (HTTP-RPC → node).

Node-side machinery (all in `gemini-node`): `chat_gossip_protocol`,
`chat_stripe_protocol`, `chat_fetch_protocol`, `chat_rebalance`,
`chat_anti_entropy`, `chat_admission`, `chat_bucket_cache`, `chat_rpc`.

Chat crates (`substrate/utils/`): `rostro-chat-primitives` (wire types +
verification), `rostro-chat-mls`, `rostro-chat-dr`, `rostro-chat-sealed-sender`,
`rostro-chat-ephemeral-store`, `rostro-chat-cli`.

## What the dotwave messaging build requires

1. **(a) Client crypto on mobile** — the `rostro-chat-mls` / `-dr` /
   `-sealed-sender` crates compiled into dotwave's `rust_core` (FRB) and run
   on-device. **This is the load-bearing unknown:** does **openmls 0.8** build
   for the Android/iOS targets, and do the chat crates cross-compile cleanly?
   Resolve this first — everything else is plumbing we've already proven.
2. **(b) Chat RPC integration** — call `chat_send_envelope` (send) and the
   pickup/fetch RPC (collect shares) against the node, plus the
   `ChatShareDescriptor` envelope/share handling.
3. **(c) Flutter chat UI** — conversation list, group + 1:1 threads, message
   compose/read, identity/keys.

## Status (2026-06-12) — live plan in [DOTWAVE-CHAT-CRYPTO-ARCHITECTURE.md](DOTWAVE-CHAT-CRYPTO-ARCHITECTURE.md)

- Chain ops: **done** (typed write path `d33e833`; reads native).
- Messaging: **well underway.** Transport ported into dotwave (`rust_core/chat.rs`)
  + Phase-0 round-trip proven locally; **R1** (RNS registry initialized at genesis)
  and **R2** (mixed validator/relay topology) done — `register` finalizes
  end-to-end; **Phase 1** (named identity — message by name, impersonation-resistant
  verified sender, one-step onboarding) logic complete (4 green `rust_core` tests).
- Next: **Phase 2 — cert-gated send** (fully grounded). Then hardware-bound content
  (P-256/P-384, encrypted-at-rest, biometric-gated). The openmls-on-mobile question
  is moot for the pairwise path (the crypto stack cross-compiled clean for arm64).

## Ground-truth pins

- Transport for *both* chain and chat = **JSON-RPC to a node.** The phone never
  joins libp2p; the node bridges it.
- Identity is **layered, not one shared key** (updated): the SS58 chain account
  (any BTOW scheme) · a SEPARATE Ed25519 chat key (sealed-sender outer, published
  in an RNS `PUBKEY1` record) · the mime-wrap cert (P-256, node admission) · the
  hardware content key (P-256 StrongBox / P-384 TPM). See
  [DOTWAVE-CHAT-CRYPTO-ARCHITECTURE.md](DOTWAVE-CHAT-CRYPTO-ARCHITECTURE.md).
- Token **RST**, TLD **`.rst`**, decimals **12**, SS58 prefix 42.
- Rostro runtime = **gemini-runtime** (`substrate/runtime/gemini/src/lib.rs`).
- dotwave write path = **typed macro only** (see the boxed lesson above).
