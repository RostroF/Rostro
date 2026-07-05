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

### 4.3 Per-chunk integrity checksum (keyless, descriptor-bound) — [as-built]

**Decision (2026-07-04):** the per-chunk integrity field is a **keyless
checksum**, not a keyed MAC. This section supersedes the original
"MAC v2, real key" design; the reasoning is recorded here because it is
the crux the whole workstream turned on.

**Why keyless.** A relay-unforgeable MAC needs a key the recipient can
derive *before reassembly* and relays cannot. In dotwave's actual model
there is no such key available uniformly: the chat is sealed-sender
dead-drops with no persistent session (Double Ratchet was reverted —
the "name ratchet" of rotating throwaway names + return addresses is
what provides forward secrecy and cover, see §3), so the only shared
secret is the sealed-sender ECDH, and its ephemeral lives *inside* the
chunked envelope (chicken-and-egg). The candidate fixes each had a
cost — a per-message MAC ephemeral re-anchors keying to the durable
identity key (against the name-ratchet direction); a label-derived key
covers only standing callsigns. More fundamentally, a keyed MAC would
not buy content security anyway: the envelope's sealed-sender AEAD +
sender Ed25519 signature already make content authenticity unforgeable
end-to-end, so a tampered chunk can only ever cause **denial**, never
accepted-forged content. A per-chunk MAC's entire value is
availability + diagnostics, and **availability is owned by the
bucket-subscription replication scheme**, not by client-side recovery.

So the field is exactly what it can honestly be: a checksum.

```
checksum = blake2_256("rostro/chat/chunk-checksum/v1"
                      || message_id || pickup_key
                      || share_index || total_shares
                      || expires_at_be || chunk_bytes)
```

**What it does:** detects and *localizes* accidental corruption — bit
rot in a relay's RAM, a truncated transfer, a mislabelled index/total/
expiry/pickup (all bound into the preimage). A mismatch tells the
recipient which chunk is unusable; it re-polls later (the bucket scheme
supplies a good copy). **What it does NOT do:** it is keyless, so any
relay can recompute a valid checksum over substituted bytes — it is no
defence against an adversarial relay and is **not a security boundary**.
It is named `checksum` (type `ChunkChecksum`, fns `checksum_chunk` /
`verify_chunk_checksum`, error `ChecksumError::Mismatch`) precisely so
no future reader mistakes a passing checksum for authentication — the
last two placeholder "MACs" (the zero-key stripe MAC) were exactly that
mistake. `relay_pubkey` stays outside the preimage: it is the
distributing node's self-identity stamp, filled per-relay, not
sender-authored.

**Deferred upgrade (if attribution is ever wanted).** A real,
relay-unforgeable MAC can return later WITHOUT re-anchoring to identity
keys or changing the wire preimage shape: the per-turn return-address
mint (which already seals a fresh `return_pickup` inside the previous
message's content) also mints a per-conversation `stripe_mac_secret`
and seals it the same way. MAC keying then rides the existing rotation
machinery — no session, no contact lookup at fetch time, identity keys
touched at most on the opener (already identity-addressed). The
descriptor-bound preimage above is forward-compatible: only the key
source would change (keyless → rotation-minted). Not now; the bucket
scheme + AEAD cover v0.

### 4.3a No client-side bad-copy recovery — [as-built]

The recipient does **not** keep alternative chunk copies or
trial-decrypt combinations. A chunk whose checksum fails, or a message
missing a chunk, is simply skipped and re-polled later. Availability
under a bad or missing copy is the **bucket-subscription replication
scheme's** responsibility (guards subscribe to buckets; replicas
propagate; a later poll resolves to a good copy). This keeps the client
simple and keeps the checksum honest — it localizes, it does not
recover.

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

dotwave replaces `combine_xor` with verified reassembly
(`combine_chunks_verified`): checksum every chunk, concatenate in index
order, then proceed to the existing unseal/verify_sender pipeline
(which is the authenticity gate).

Privacy constraints on what happens after a checksum failure or an
incomplete set (part of the spec, not implementation detail):

1. **Retries ride the normal fetch shape.** On `CorruptChunk` or
   incomplete set, re-poll is a standard pickup_key fetch, never a
   distinctive "give me chunk 3 of message X" request. A relay that
   corrupts chunks gains no oracle telling it a live recipient fetched
   and cared. (The recipient does not even retry eagerly — it re-polls
   on its normal cadence; §4.3a.)
2. **No attribution leaves the device.** The keyless checksum cannot
   attribute corruption to a relay anyway (it does not distinguish
   adversary from bit rot), and the client keeps no relay-preference
   list. Availability is the bucket scheme's job. Should the deferred
   real MAC land (§4.3), any attribution it enables stays on-device: a
   public accusation about message X announces the accuser is X's
   recipient.

### 4.7 Wire and API changes (hard cutover, no grace windows)

All changes land as one coordinated cutover per repo; old paths are
deleted in the same commit that adds new ones. Chat shares are
ephemeral (3-day TTL, RAM-only stores), so there is no data migration:
in-flight shares at rollout are lost, which is the accepted cost of a
pre-testnet wire break on an off-chain protocol.

| Surface | Change |
| --- | --- |
| `rostro-chat-primitives::chunk` (new) | `split_chunks`, `prepare_batch` (sender-device split+checksum pipeline), `PreparedShare`/`PreparedBatch` wire types, `validate_prepared_batch` (node handoff), `combine_chunks_verified`; `stripe.rs` deleted |
| `verify.rs` | **[as-built]** KEYLESS checksum: `checksum_chunk` / `verify_chunk_checksum` over the descriptor-bound preimage, `ChunkChecksum` / `CHUNK_CHECKSUM_LEN` / `CHUNK_CHECKSUM_DOMAIN`, `ChecksumError::Mismatch`. The keyed-MAC machinery (`ShareMacKey`, `mac_chunk`, `derive_stripe_mac_secret`, `derive_share_mac_key`, the v2 domains) is DELETED, not just the v1 fns — see §4.3 |
| `rostro-chat-onion` | **[as-built]** `OnionDeliverPayload` DELETED outright — the `Deliver` drop bytes ARE `PreparedBatch::encode()` and the onion crate stays payload-agnostic (no new dep). Onion-forward protocol `/2` → `/3`; `total_shares` removed from `OnionForwardRequest` + guard digest (domain → `onion-forward/v2`) since chunk counts ride inside the batch |
| Store protocol | `StoreRequest` shape unchanged (descriptor + bytes + checksum; the field was renamed `mac_tag` → `checksum`, SCALE-positional so wire-compatible); `/rostro/chat-stripe/1` → `/rostro/chat-chunk/1`; node module renamed `chat_stripe_protocol.rs` → `chat_chunk_protocol.rs` |
| `chat_send_envelope` RPC | Replaced by `chat_send_prepared(batch_hex, auth_*)` — a single SCALE blob, so the cert-auth signature covers the EXACT batch bytes; envelope-accepting form deleted (no two verifiers of one input). `chat_send_onion` loses its `total_shares` param |
| `chat_fetch_shares` RPC | Same client shape; **[as-built]** aggregation trigger is "any matched message incomplete" (for COMPLETENESS under disjoint sets, not bad-copy recovery — §4.3a), early stop on completeness; `MAX_FALLBACK_FETCH_PEERS` 3 → 8. Response DTO field `mac_tag_hex` → `checksum_hex` |
| gemini-node | `stripe_and_distribute` (and its `send_envelope` inline copy) → ONE free fn `distribute_prepared`; zero-key MAC code deleted; disjoint replica partitioning (`peers[(i·R + j) % peer_count]` over an OsRng shuffle); success criterion is now "every chunk landed on ≥1 replica", not raw store-success count |
| `rostro-chat-cli` | **[as-built]** Tier-0 harness cut over: on-device `prepare_batch` on send, verified reassembly on fetch. KEYLESS — no conversation secret, no `--peer-pubkey` (the earlier ECDH-keyed version is superseded by §4.3) |
| dotwave `rust_core` | (P2) chunk+checksum on send (all three: direct, onion, dead-drop paths), verified reassembly on fetch. No session/key state needed (keyless) |
| bucket.rs docs | "Buckets are not shards" prose updated to chunk terminology |

**[as-built] Deferred to P3:** the `scripts/chat-scenarios/*` shell
scripts still speak `chat_send_envelope`/XOR and are updated with the
lab proof (they cannot run under the current no-lab constraint
anyway).

## 5. What gets deleted

`split_xor`, `combine_xor`, `combine_xor_authenticated`, `MIN_SHARES`/
`MAX_SHARES` (replaced by chunk-count bounds), ALL keyed-MAC machinery
(both the v1 zero-key sites AND the interim v2 keyed design —
`ShareMacKey`, `mac_chunk`, `derive_stripe_mac_secret`,
`derive_share_mac_key`, every `share-mac*` domain), and `stripe.rs`
wholesale. The rostro-chat-mls
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
4. **Dead-drop first-contact keying — RESOLVED 2026-07-04 by going
   keyless (§4.3).** The question was "which conversation secret keys
   the per-chunk MAC, given the recipient may not know the sender at
   fetch time." Answer: none — the integrity field is a keyless
   checksum, so there is no keying to bootstrap. Content authenticity
   is the sealed-sender AEAD (which already handles first contact),
   and availability is the bucket scheme. The deferred real MAC, if
   ever wanted, keys off the rotation-minted `stripe_mac_secret`
   sealed inside the previous turn (§4.3), which sidesteps first
   contact the same way the return-address rotation already does.
5. **Bad-copy / missing-chunk recovery — RESOLVED 2026-07-04: not the
   client's job (§4.3a).** Guards subscribe to buckets and the
   bucket-subscription replication scheme supplies good copies; the
   client checksums, localizes, and re-polls, but keeps no alternative
   copies and does no trial-decrypt.

## 9. Addressing invariant (load-bearing; §3)

Routing keys are the ONLY identity-derived wire artifact, and only for
the opener. After first contact the name ratchet (rotating throwaway
RNS names + per-turn random return addresses) means no durable
identity key anchors accumulating linkable traffic — this is the cover
that Double Ratchet's removal was compensated by. No future change to
the checksum, keying, or fetch path may re-anchor addressing (or the
integrity field's keying) to durable identity keys without explicitly
revisiting this invariant. The keyless checksum honors it by
construction (it uses no keys at all); the deferred real MAC honors it
by keying off the rotation mint, never the identity key.
