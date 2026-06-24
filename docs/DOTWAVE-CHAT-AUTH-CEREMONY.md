# Rostro chat — authentication ceremony (node-local HIP session) (v1.0)

**Created:** 2026-06-14
**Status:** design locked; implementation starting. The auth ceremony that gates
the chat *drop* path (steps 1–2–6 of the chat flow: authenticate → drop onion →
retrieve). Companion to [DOTWAVE-CHAT-CRYPTO-ARCHITECTURE.md](DOTWAVE-CHAT-CRYPTO-ARCHITECTURE.md)
(layered crypto), [DOTWAVE-CHAT-METADATA-ANONYMITY.md](DOTWAVE-CHAT-METADATA-ANONYMITY.md)
(the onion + guard model), and [DOTWAVE-CHAT-FRONTEND-PLAN.md](DOTWAVE-CHAT-FRONTEND-PLAN.md)
(the dotwave client tracks).

---

## The problem

A client (mobile = StrongBox, desktop = TPM2.0) must prove to the node it drops
through that it holds an **Active, HW-attested zkpki cert** before that node will
admit a chat drop. The current `verify_chat_auth` is the weak version: a
self-asserted timestamp (±600 s), a cert `Active` check, and a signature over the
packet by the cert's device key. No node-issued/anchored challenge, **no
device-state freshness (HIP)**, and the chain can't tell the signature was
biometric-gated.

Re-running the heavy proof per message is a non-starter: it would cross the
secure-element boundary (biometric + OTP/HMAC) for *every* drop. So the ceremony
is **session-based** — one expensive crossing establishes a time-bounded session;
drops within it are cheap.

## What the ceremony must prove (to the guard, once per session)

Auth happens at the **guard** (the app's pinned entry node), which by the onion
design already learns the sender (`cert → bound_account`); the onion hides it from
relay-2 onward, the burner defangs the IP. The handshake proves to the guard:

1. **Real secure element** — the cert is HW-attested (StrongBox / TPM2).
2. **Human present, now** — the HIP-signing key is biometric-gated; producing the
   proof requires the human.
3. **Device healthy, now** — `verify_hip_proof_against_genesis` (drift detection
   vs the cert's enrolled `genesis_fingerprint`), not just "cert not revoked."
4. **Fresh** — a block-anchored nonce, not a self-asserted timestamp.

## Session — definition

A **node-local, time-bounded authorization** that lets one client drop messages
through one node without re-entering secure hardware per message.

- **Who/where:** one client (`cert` / `bound_account`) ↔ one node (its pinned
  guard). Per-node, **non-portable** — guards do not vouch for each other; connect
  to a different node and you re-handshake there.
- **Born from ONE expensive crossing — the handshake:** the biometric-gated HW key
  produces one fresh `CanonicalHipProof` over the block-anchored nonce. The node
  verifies (cert `Active` + HIP-vs-`genesis_fingerprint` + nonce fresh) and records
  the session in RAM. This is the *only* secure-element touch, biometric, and
  OTP/HMAC per session.
- **The cheap part — a session credential:** during the handshake the client
  generates a **software session keypair** (ordinary app memory, NOT the secure
  element); the HW handshake **authorizes its public half**. The node stores only
  the session pubkey. Subsequent drops carry a cheap **software signature under the
  session key** — no hardware crossing, no biometric, no OTP. Reconnects re-present
  the session key. The node holds only the public half, so it cannot forge drops.
- **Lifetime:** **W = 4 days** (`345,600 s`) on the node's **monotonic clock**, a
  **hard cap** — activity does NOT extend it. At expiry the client must re-handshake
  (one more biometric crossing). The node owns W and **returns the absolute expiry
  in the handshake response**, so the client re-handshakes proactively (~80%,
  ≈3.2 days) without hardcoding W. (A 4-day session slightly outlives the ~3-day
  relay message TTL.)
- **What we stop checking within the session:** human-presence and device-health
  are proven once and trusted for W; not re-proven per drop.
- **The tradeoff, stated plainly:** a device compromised *after* the handshake can
  send until W expires. **W bounds that blast radius.** The session key lives in app
  memory — that's the accepted cost of not doing per-drop. The secure element never
  signs a *message*; it signs the *handshake that authorizes the session key*.

## The block-anchored nonce — where it lives

Derived, not issued — no nonce store, no pending-challenge table.
- `nonce = H(recent_block_hash ‖ cert_thumbprint ‖ guard_node_id ‖ domain_tag)`
  (the existing `derive_pop_nonce` shape).
- **Source:** the chain, read-only. The node has the block; the client reads a
  recent block hash over RPC. Nothing is written to chain (no public liveness
  beacon — consistent with node-local sessions).
- **At generation:** baked into the HIP attestation challenge (StrongBox
  `setAttestationChallenge` / TPM quote `extraData`).
- **At verification:** the node re-derives it from the same public inputs and
  matches; checks the anchor block is recent in its own chain view.
- **`guard_node_id` binding:** ties the handshake to this node, so a captured
  handshake can't be replayed to a different guard.
- **Replay cache:** a small, ephemeral accepted-nonce cache (evicted past the
  freshness window). Belt-and-suspenders given per-drop binding needs the session
  key, which a handshake-replayer doesn't have.

## Cert & drift detection (resolved)

The chat admission cert is the **mime-wrap (StrongBox) / TPM2 HW-attestation cert**,
minted via `mint_cert` under a `pop_requirement: Required` template, which **requires
a HIP proof and records the `genesis_fingerprint`** ([zkpki-pallet
mint_cert](../substrate/frame/zkpki-pallet/src/lib.rs)). So **drift detection
(`verify_hip_proof_against_genesis`) is the default** — a device rooted after
enrollment is catchable. This cert is HW+HIP-attested but is **not** the
PoP-uniqueness gate (Axis 1: one standing cert, many throwaway *names*; uniqueness
is `mint_pop`, separate). The dev stub (`chat_mint_test_cert` → `register_root`)
records no `genesis_fingerprint`; in dev the node falls back to
`verify_hip_proof_internal` (internal consistency, no drift). Production requires
the genesis-bearing cert.

## Work plan (dependency-ordered)

**Tier 1 — prerequisites**
1. Add `zk_pki_hip` as a dependency of `gemini-node` (first node-side consumer of
   `verify_hip_proof_against_genesis`).
2. New additive runtime API `cert_hip_genesis(thumbprint) → Option<GenesisHardwareFingerprint>`
   (reads `CertRecordCold.genesis_fingerprint`). `cert_authentication` stays as-is.
3. Node-side nonce derivation (reuse `derive_pop_nonce`; read block hash via
   `HeaderBackend`) + an anchor-block freshness-window check.

**Tier 2 — the handshake**
4. RPC `chat_authenticate(cert_thumbprint, hip_proof, anchor_block, session_pubkey)`
   → `{ expiry, bound_account }`.
5. Handler: derive expected nonce → verify HIP (vs genesis, else internal) → cert
   `Active` → record session `{ bound_account, session_pubkey, established_at (mono),
   expiry = now + W }`.

**Tier 3 — session store**
6. In-RAM session map on `ChatRpc` (the `EphemeralShareStore` TTL-sweep pattern),
   monotonic-clock hard-cap eviction.

**Tier 4 — per-drop binding**
7. `send_onion` / `send_envelope` admit a drop when the session is live and the
   session-key signature verifies against the stored session pubkey. The full
   HW-auth path stays as the renewal/fallback.

**Tier 5 — later (Phase 2)**
8. Capture `user_authentication_required` on-chain at mint + expose it, so
   biometric-gating is on-chain-verifiable (today it's verified at mint and dropped).

**dotwave client slice (rides on top of Tiers 1–4):** read guard id (`chat_nodeInfo`)
+ recent block → derive nonce → generate HIP (StrongBox now; **TPM2.0 desktop is a
known later gap**) with the nonce baked in → generate a session keypair → call
`chat_authenticate`; store session key + expiry, pin the node, re-handshake at ~80%
W and on node-switch; sign drops with the session key.

## Scope note

Tiers 1–4 are **node/chain-side**; the dotwave slice is the smaller piece on top.
This is the agreed expansion past the earlier "mobile-app-only" scope.

## Deferred / open

- TPM2.0 desktop **client** (Android/StrongBox first; the chain side already has
  `CanonicalHipProof::Tpm2`).
- `user_authentication_required` on-chain (Tier 5).
- Dev-stub no-genesis policy: internal-only verification in dev; require the
  genesis-bearing cert in production.
