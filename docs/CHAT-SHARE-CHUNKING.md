# Chat share chunking cutover (XOR stripe → chunk split)

Status: **P0 + P1 IMPLEMENTED** on branch `chat-chunk-v0` (worktree
`/home/coder/Rostro-chat-chunk/`); P2 (dotwave) + P3 (lab proof)
pending. Sections below updated to as-built where the implementation
refined the original spec; deltas are marked **[as-built]**.
Spec date: 2026-07-03. Implementation: 2026-07-04.
Owner: prodigalwon.

## 1. Problem

Three defects in the shipped chat share layer, found together, fixed together:

**1a. Storage amplification.** `split_xor` produces N full-size shares
(each share = message length; n-1 CSPRNG noise, the last XORed). With
`DEFAULT_TOTAL_SHARES = 5` and `REPLICATION_FACTOR = 5`, a 25 KB message
costs the network **25 × 25 KB = 625 KB** of mlock'd relay RAM for the
3-day `CHAT_TTL_SECONDS`. Messages are ephemeral but sit in someone
else's RAM for 3 days; at product scale this exhausts relay share-store
budgets ~25x faster than the payload traffic justifies. The visible
failure mode is silent message loss once stores hit capacity
(`StoreRejection::CapacityExhausted`), not a crash: senders get `Stored`
from relays that still have room and the message quietly dies.

**1b. The stripe's confidentiality property is void as deployed.**
`stripe_and_distribute` (and the inlined copy in `chat_send_envelope`)
selects ONE peer set of `REPLICATION_FACTOR` bucket peers and sends
**every share to every selected peer**. Each of those relays holds all N
shares and can XOR them locally to recover the full envelope ciphertext.
We pay 25x storage for an information-theoretic property the fan-out
destroys. (stripe.rs docs specify disjoint per-share replica sets; the
implementation never did that.)

**1c. The per-share MAC is decorative.** Both distribution call sites
use `let mac_key = [0u8; 32];` (documented placeholder: the real key
needs the sender/recipient session secret, which the node structurally
does not have). And dotwave reassembles with unauthenticated
`combine_xor`, ignoring the tags entirely. Consequence: any storing
relay (or the peeling node) can corrupt a share undetectably-at-source;
the recipient sees only an end-to-end AEAD failure with no localization
and no targeted retry.

## 2. Why chunking is safe to adopt (threat analysis)

The striped payload is already a `SealedEnvelope`: sealed-sender AEAD
ciphertext, sender-signed inside. A contiguous slice of AEAD ciphertext
is computationally indistinguishable from random bytes to a relay, the
same as an XOR share appears. The only adversary who gains from XOR
striping over plain chunking is one who can break the symmetric AEAD
itself. Symmetric crypto at 256-bit is not meaningfully quantum-
threatened (Grover only); Rostro's PQ exposure is in key exchange,
addressed by the PQXDH workstream. The stripe therefore defends against
roughly nobody, at 5x storage, while the real constraint (relay RAM,
ephemerality) bites operators.

What a storing relay learns from one chunk, before vs after: pickup_key,
message_id, share_index, total_shares, expires_at, and ~L bytes of
pseudorandom payload (before) vs ~L/N bytes (after). Strictly less.
Message-size inference is unchanged in kind: share length revealed L
before; chunk length reveals ~L/N and total_shares, same information.

**Dropped property, named explicitly:** information-theoretic
all-or-nothing confidentiality against relay collusion. Post-cutover, a
coalition holding all chunks of a message has the ciphertext (still
AEAD-sealed, still sender-anonymous). Accepted: the shipped
implementation never delivered this property anyway (1b), and the AEAD
is the load-bearing confidentiality layer. If all-or-nothing is ever
wanted back, the tool is AONT-RS (package transform + split, ~1x total
size, computational); it slots into the same chunk pipeline. Not now.

## 3. Invariants preserved (the reasons this architecture exists)

- **Onion topology untouched.** Client still builds the route and seals
  layers to chosen node identities (guard, relay-2). Guard sees the
  sender's IP and an opaque packet, nothing else. Intermediate hops see
  nothing. The peeling node (relay-2) still performs distribution; the
  client never contacts bucket relays directly on send.
- **Fetch stays unauthenticated and anonymous.** Anyone knowing a
  pickup_key can fetch its shares; relays learn nothing about who
  fetched. MAC verification is local-only on the recipient device and
  produces no wire traffic. "Authenticated combine" authenticates the
  shares to the recipient, never the recipient to anyone.
- **Remediation is privacy-shaped** (see §4.6): retries are
  indistinguishable from ordinary fetches; corruption attribution never
  leaves the device.

## 4. Design

### 4.1 Chunk split (replaces XOR split)

`split_chunks(encoded_envelope, n)` cuts the SCALE-encoded envelope into
`n` contiguous pieces: chunks `0..n-2` of length `ceil(L/n)`, the last
chunk shorter. `combine_chunks` is concatenation in index order.
N stays fixed at `DEFAULT_TOTAL_CHUNKS = 5` for uniform network behavior
(size-adaptive N leaks more shape and complicates traffic analysis
uniformity for no RAM win; the win comes from chunks summing to 1x).

New file `chunk.rs` in `rostro-chat-primitives`; `stripe.rs` is deleted
in the same commit (new purpose = new file; single cutover; never two
combine paths alive at once).

### 4.2 Split and MAC move client-side

dotwave (and later rostro-client) performs: build + seal envelope →
encode → `split_chunks` → MAC each chunk (§4.3) → build complete
`ShareDescriptor`s → pack **prepared shares** into the onion Deliver
payload. This is affordable now because chunks sum to ~1x message size;
under XOR it would have been Nx through the onion (which is why
splitting was node-side to begin with).

The client can build complete descriptors because it selects the onion
route and therefore knows the peeling node's identity (`relay_pubkey`)
at build time, and it sets `expires_at = now + CHAT_TTL_SECONDS`
itself (relay-side `expiry_within_bounds` already tolerates
`MAX_TTL_SLOP_SECONDS` skew).

The peeling node's job shrinks to the one thing only it can do: peel,
map pickup_key → bucket, fan prepared shares out to bucket peers. It no
longer computes MACs (it has no key), assembles descriptors, or touches
an RNG for splitting.

### 4.3 MAC v2: real key, descriptor-bound

**Key derivation.** Per-conversation stripe-MAC secret, derived once at
session establishment from the same shared secret that roots the
conversation (X3DH today, PQXDH when P3 lands), domain-separated:

```
stripe_mac_secret = blake2_256("rostro/chat/stripe-mac-secret/v1"
                               || conversation_shared_secret)
per_message_key   = blake2_256("rostro/chat/share-mac-key/v2"
                               || stripe_mac_secret || message_id)
```

Both ends can derive this **before** decrypting anything (message_id
comes from the descriptor at fetch time; the conversation secret is
held per-contact). Forward secrecy is irrelevant here (integrity only),
so a static per-conversation secret is correct. The group path (MLS,
not yet wired) feeds its epoch secret into the same shape; the derive
function stays secret-source-agnostic as today.

**Tag preimage v2** binds the descriptor, not just bytes+index:

```
tag = blake2_256("rostro/chat/share-mac/v2" || key
                 || message_id || pickup_key
                 || share_index || total_shares
                 || expires_at_be || chunk_bytes)
```

Rationale: the client authors both descriptor and tag, so binding is
free, and it closes the peeling-node tampering surface. v1's
bytes+index preimage would let a malicious peeler rewrite `expires_at`
(TTL-shortening = censorship that looks like expiry) or `total_shares`
undetected. With v2 the entire path from the sender's device to the
recipient's device is reduced to drop-or-deliver-intact. `relay_pubkey`
stays outside the preimage: it is the distributing node's self-identity
stamp, not sender-asserted data.

### 4.4 Distribution: per-chunk disjoint replica sets

At the peeling node: shuffle bucket peers (OsRng, as today), partition
into per-chunk replica sets of `CHUNK_REPLICATION = 3` (parameter, see
§8), **disjoint across chunks when peer count allows**
(≥ N × R peers → fully disjoint; fewer → round-robin with minimal
overlap; degenerate small-network case → overlap accepted and the AEAD
still protects content). Storage per 25 KB message: 25 KB × 3 = 75 KB
(vs 625 KB today, 8.3x reduction), spread across up to 15 relays at
~5 KB each.

Availability shifts shape: today any 1 of 5 peers serves the whole
message; after, each chunk needs ≥1 live replica of its 3. With
p = per-relay unavailability over the TTL, message loss ≈ N·p³
(p=5% → ~0.06%). R is the dial; storage is linear in R.

### 4.5 Fetch: multi-peer aggregation (new required work)

Today's fetch assumes one relay holds all shares of a message (true only
because of bug 1b). With disjoint sets this breaks. The node-side
`chat_fetch_shares` handler must query multiple bucket peers for the
pickup_key and merge results, deduplicating on (message_id,
share_index). The client keeps calling one RPC; aggregation is
node-side. Fetch request shape on the relay wire is unchanged (same
`FetchRequest` by pickup_key), so a fetch that happens to be a retry is
indistinguishable from any other fetch.

### 4.6 Recipient verification + remediation rules

dotwave replaces `combine_xor` with authenticated reassembly: derive
per-message key, verify every chunk's v2 tag, concatenate in index
order, then proceed to the existing unseal/verify_sender pipeline.

Privacy constraints on what happens after a MAC failure (these are part
of the spec, not implementation detail):

1. **Retries ride the normal fetch shape.** On TamperedChunk or
   incomplete set, re-fetch is a standard pickup_key fetch against
   another peer, never a distinctive "give me chunk 3 of message X"
   request. A relay that corrupts chunks must gain no oracle telling it
   a live recipient fetched and cared.
2. **Attribution never leaves the device.** MAC failure conclusions
   ("relay Y served bad bytes") feed at most a local relay-preference
   list. No reporting, no on-chain complaint, no gossip: a public
   accusation about message X announces the accuser is X's recipient.
   (v0 ships without even the local preference list; see §8.)

### 4.7 Wire and API changes (hard cutover, no grace windows)

All changes land as one coordinated cutover per repo; old paths are
deleted in the same commit that adds new ones. Chat shares are
ephemeral (3-day TTL, RAM-only stores), so there is no data migration:
in-flight shares at rollout are lost, which is the accepted cost of a
pre-testnet wire break on an off-chain protocol.

| Surface | Change |
| --- | --- |
| `rostro-chat-primitives::chunk` (new) | `split_chunks`, `prepare_batch` (sender-device split+MAC pipeline), `PreparedShare`/`PreparedBatch` wire types, `validate_prepared_batch` (node handoff), `combine_chunks_authenticated`; `stripe.rs` deleted |
| `verify.rs` | v2 domains + descriptor-bound preimage (`mac_chunk`/`verify_chunk_mac`) + `derive_stripe_mac_secret`; v1 share-MAC fns deleted |
| `rostro-chat-onion` | **[as-built]** `OnionDeliverPayload` DELETED outright — the `Deliver` drop bytes ARE `PreparedBatch::encode()` and the onion crate stays payload-agnostic (no new dep). Onion-forward protocol `/2` → `/3`; `total_shares` removed from `OnionForwardRequest` + guard digest (domain → `onion-forward/v2`) since chunk counts ride inside the MAC-bound batch |
| Store protocol | `StoreRequest` shape unchanged (descriptor + bytes + tag); `/rostro/chat-stripe/1` → `/rostro/chat-chunk/1` (name says what it carries); node module renamed `chat_stripe_protocol.rs` → `chat_chunk_protocol.rs` |
| `chat_send_envelope` RPC | Replaced by `chat_send_prepared(batch_hex, auth_*)` — a single SCALE blob, so the cert-auth signature covers the EXACT batch bytes; envelope-accepting form deleted (no two verifiers of one input). `chat_send_onion` loses its `total_shares` param |
| `chat_fetch_shares` RPC | Same client shape; **[as-built]** aggregation trigger is now "any matched message incomplete", not "local view empty" (required under disjoint sets), with early stop on completeness; `MAX_FALLBACK_FETCH_PEERS` 3 → 8 |
| gemini-node | `stripe_and_distribute` (and its `send_envelope` inline copy) → ONE free fn `distribute_prepared`; zero-key MAC code deleted; disjoint replica partitioning (`peers[(i·R + j) % peer_count]` over an OsRng shuffle); success criterion is now "every chunk landed on ≥1 replica", not raw store-success count |
| `rostro-chat-cli` | **[as-built]** Tier-0 harness cut over: on-device `prepare_batch` on send, authenticated reassembly on fetch. Conversation secret = static-static X25519 between the two chat identities; `fetch` gains `--peer-pubkey` (see §8.4 resolution) |
| dotwave `rust_core` | (P2, pending) chunk+MAC on send (all three: direct, onion, dead-drop paths), authenticated reassembly on fetch, stripe-MAC secret in session state |
| bucket.rs docs | "Buckets are not shards" prose updated to chunk terminology |

**[as-built] Deferred to P3:** the `scripts/chat-scenarios/*` shell
scripts still speak `chat_send_envelope`/XOR and are updated with the
lab proof (they cannot run under the current no-lab constraint
anyway).

## 5. What gets deleted

`split_xor`, `combine_xor`, `combine_xor_authenticated`, `MIN_SHARES`/
`MAX_SHARES` (replaced by chunk-count bounds), the v1 MAC domains, the
zero-key call sites, and `stripe.rs` wholesale. The rostro-chat-mls
`full_crypto_stack` test is rewritten against the chunk pipeline (test
was right about the flow, wrong primitive underneath; commit message
will say so).

## 6. Dependencies and interactions

- **Node directory (flagged, not blocking).** Client-side descriptors
  assume the client knows the peeling node's pubkey, which it does
  today via configured `chat_node_identity` lookups. Real route
  *selection* needs the node-discovery directory; that is a separate
  prelaunch item. This cutover works with lab-configured routes.
- **PQXDH (P3b/P3c).** The stripe-MAC secret derives from the
  conversation shared secret; when PQXDH replaces X3DH the secret
  upgrades transparently (same derivation, stronger input).
- **Group messaging.** Unblocked, unchanged: group path will feed the
  MLS epoch secret into the same derive shape when wired.
- **rostro-client.** Tier-2 client inherits the same prepare-side code;
  keep the chunk+MAC+descriptor builder in `rostro-chat-primitives`
  (Apache-2.0, `substrate/utils/`) so both clients share it without
  touching GPL zones.

## 7. Work plan

Worktree: `/home/coder/Rostro-chat-chunk/` on branch `chat-chunk-v0`.
dotwave changes on a matching branch in the dotwave repo.

**P0 — primitives (Rostro).** `chunk.rs` (split/authenticated-combine +
edge cases: L < N, L = 0 rejected, index gaps, duplicate indices), MAC
v2 in `verify.rs`, delete `stripe.rs`, rewrite `full_crypto_stack`
round-trip, update bucket.rs prose. Pure-Rust, fully unit-testable, no
network. *Acceptance: crate tests green; grep proves no `split_xor` /
v1-domain references remain.*

**P1 — node (Rostro).** Onion payload v2 + protocol bumps,
`distribute_prepared` with disjoint partitioning, `chat_send_prepared`,
multi-peer fetch aggregation, delete zero-key sites. *Acceptance:
star-scenario send/fetch over 2-hop onion on the lab star; assert via
relay introspection that no single relay holds ≥ total_shares chunks of
one message when peer count allows disjointness.*

**P2 — dotwave.** Session-state stripe-MAC secret, prepare-side
(chunk+MAC+descriptors) for direct/onion/dead-drop sends, authenticated
reassembly, codegen → ndk build order per dotwave build notes.
*Acceptance: phone → star E2E send/receive both directions.*

**P3 — lab proof.** (a) RAM: measure aggregate share-store bytes for a
fixed message batch before/after, expect ~8x reduction at R=3. (b)
Corruption drill: flip one byte in one stored chunk on one relay
(lab-only diagnostics hook), verify recipient localizes the bad chunk,
retries within normal fetch shape, and recovers the message. (c)
Capacity: confirm store rejection behavior unchanged.

P0 has no coupling to P1/P2 and can land alone (crate-internal). P1 and
P2 are one wire cutover and must land together on the lab cluster
(rolling restart; register_file per forkless playbook if binaries are
canonical-gated by then).

## 8. Open decisions (resolved at go signal 2026-07-04 unless noted)

1. **`CHUNK_REPLICATION` = 3.** ADOPTED (defaults accepted with the
   go signal). Storage is linear in R; loss ≈ N·p^R.
2. **Fixed N=5 chunks.** ADOPTED; revisit only with measured traffic.
3. **Local relay-preference list: DEFERRED** post-cutover;
   retry-another-peer covers v0.
4. **Dead-drop first-contact edge — sharpened during P1, confirm in
   P2:** the recipient must know WHICH conversation secret to derive
   the MAC key from before combining. In dotwave the dead-drop label
   identifies the conversation (label ↔ contact mapping is device
   state), so the secret is known pre-combine; the raw pairwise
   pickup key is shared across senders, so there the client tries its
   per-contact secrets against the tags (small set, local-only). The
   Tier-0 CLI harness sidesteps this by taking `--peer-pubkey` and
   deriving a static-static X25519 conversation secret. P2 must
   confirm the first-message dead-drop bootstrap holds a shared
   secret on both ends (PQXDH P3b/P3c input).
