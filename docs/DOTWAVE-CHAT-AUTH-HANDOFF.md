# Chat auth ceremony — build state & handoff

**Created:** 2026-06-15
**Status:** node side COMPLETE & compile-verified; dotwave client foundation done;
3 client pieces remain (2 dev-buildable, 1 hardware-gated).
**Design of record:** [DOTWAVE-CHAT-AUTH-CEREMONY.md](DOTWAVE-CHAT-AUTH-CEREMONY.md)
(read that first for the *why*; this doc is the *where we are / how to resume*).
**Companions:** [DOTWAVE-CHAT-CRYPTO-ARCHITECTURE.md](DOTWAVE-CHAT-CRYPTO-ARCHITECTURE.md),
[DOTWAVE-CHAT-METADATA-ANONYMITY.md](DOTWAVE-CHAT-METADATA-ANONYMITY.md),
[DOTWAVE-CHAT-FRONTEND-PLAN.md](DOTWAVE-CHAT-FRONTEND-PLAN.md).

---

## TL;DR

We built the authentication gate for the chat **drop** path: a phone proves it
holds an Active, HW-attested cert on a healthy device via **one biometric+HIP
handshake**, which establishes a **node-local 4-day session**; messages then ride
a **cheap software session key** — no secure-element crossing per message.

- **Node side: 100% done, compiles** (`cargo check -p gemini-node`, riscv runtime).
- **Phone/dotwave side: foundation done** (the 4 interop-critical functions).
- **Left:** dart session manager (dev-buildable), onion-send wiring (dev-buildable),
  and the StrongBox HIP-generation step (**needs the S20**).

## The ceremony in one picture

```
PHONE (S20)                                    NODE ("guard")
1. make software session keypair
2. get node id + recent block            ──▶  answers
3. derive nonce = blake2_256(domain ‖ block_hash ‖ cert_thumbprint
                              ‖ guard_node_id ‖ session_pubkey)
4. 🔒 StrongBox HIP proof (fingerprint)   ← ONLY the phone can do this
   carrying that nonce
5. chat_authenticate{cert, hip, block, sessionkey} ─▶ cert Active? HIP healthy
                                                       vs enrolled genesis?
                                                       nonce fresh? → 4-day session
   ── session live ──
6. per msg: sign onion packet w/ session  ──▶  live session? cheap sig ok? → admit
   key (no chip, no fingerprint)               (chat_send_onion session path)
```

---

## Branches & commits

### Rostro repo (node/chain) — branch `chat-auth-ceremony-v0` (off `rostro-main`)
- `51025b4989` — design doc
- `7e98acca63` — **Tier 1**: `cert_hip_genesis` runtime API + `zk-pki-hip` dep on gemini-node
- `69768f09cd` — **Tier 2+3**: `chat_authenticate` RPC + handler + nonce derivation + in-RAM session store
- `7c0dbe3d0b` — **Tier 4**: `verify_session_drop` + session path on `chat_send_onion`

### dotwave repo — branch `chat-auth-client-v0` (off `chat-frontend-v0` / `rostro-port-v0`)
- `28e3145` — **chat-auth client foundation**: rust_core `chat_session` module + FRB
- (inherits the earlier chat-frontend work: `b1a6418` F0 bridge re-baseline · `09f7206`
  F1a typed CHAT/MESSAGE records + metadata regen · `f62affc` F1b ChatStore wiring ·
  `a006e8f` Step-1 admission-cert layer)

Both working trees are clean.

---

## What's built — file map

### Node (`gemini-node` + zkpki + runtime)
- **`cert_hip_genesis` runtime API** — `zkpki-primitives/src/runtime_api.rs` (trait),
  `zkpki-pallet/src/lib.rs` (`query_cert_hip_genesis`, reads `CertLookupCold.genesis_fingerprint`),
  `runtime/gemini/src/lib.rs` (the arm).
- **`gemini-node/src/chat_rpc.rs`** — the whole node ceremony:
  - constants: `CHAT_SESSION_NONCE_DOMAIN`, `CHAT_SESSION_DROP_DOMAIN`,
    `CHAT_SESSION_ANCHOR_WINDOW_BLOCKS` (10), `CHAT_SESSION_TTL_SECS` (4 days), `MAX_SESSIONS`.
  - `derive_session_nonce(...)` — the block-anchored nonce.
  - `ChatSession` + `SessionStore` (in-RAM, monotonic TTL, hard-cap eviction).
  - `do_authenticate(...)` + the `chat_authenticate` RPC method — the handshake.
  - `verify_session_drop(...)` — the cheap per-drop check.
  - `chat_send_onion` — two new trailing `Option` params (`session_cert_thumbprint_hex`,
    `session_sig_hex`); session path preferred, full cert-auth fallback.

### dotwave (`rust_core/src/chat_session.rs`)
- `chat_session_gen_keypair()` — software Ed25519 session key.
- `chat_session_prepare(node_rpc, cert_thumbprint, session_pubkey)` — fetch guard id +
  recent block, derive the nonce. **Caller bakes `nonce_hex` into the HIP attestation challenge.**
- `chat_session_authenticate(node_rpc, cert_thumbprint, hip_proof_hex, anchor_block, session_pubkey)`.
- `chat_session_sign_drop(session_seed, onion_packet)` — per-drop session signature.
- FRB bindings regenerated: `chatSessionGenKeypair/Prepare/Authenticate/SignDrop`.

---

## What's next (in order)

1. **Dart session manager** in `ChatStore` (dotwave `lib/services/chat_store.dart`) — *dev-buildable*.
   Persist the session keypair + expiry; pin the node; orchestrate
   `gen_keypair → prepare → [HIP] → authenticate`; re-handshake at ~80% of TTL and on
   node switch; expose the session creds for drops. Builds on the Step-1 cert layer
   already in `ChatStore` (`certSeedHex`, `ensureCert`, `certAuth`).
2. **Onion-send wiring** — *dev-buildable*. Make `chat_send_onion_2hop` (dotwave
   `rust_core/src/chat.rs`) sign the packet via `chat_session_sign_drop` and pass
   `session_cert_thumbprint_hex` + `session_sig_hex` to the node's `chat_send_onion`
   (the node params already exist). Falls back to cert-auth when no session.
3. **StrongBox HIP-gen step** — **needs the S20**. Feed `prepare`'s `nonce_hex` to the
   existing StrongBox ceremony (Kotlin `StrongBoxManager` / `ZkPkiCeremony`) as the
   attestation challenge, producing a SCALE `CanonicalHipProof::StrongBox`. That hex is
   the `hip_proof_hex` arg to `chat_session_authenticate`. Desktop TPM2.0 client = later gap.

---

## How to resume / test

**Build the node** (release; runtime is RISC-V):
```sh
cd ~/Rostro && SUBSTRATE_RUNTIME_TARGET=riscv cargo build --release -p gemini-node
```
(Run the node under `dangerouslyDisableSandbox` on this dev box — the RISC-V JIT
needs it; see lab notes.)

**Dev-box scope:** everything except a *real* HIP proof. `chat_session_prepare` and
`chat_session_sign_drop` are pure software and dev-testable; `chat_authenticate` plumbing
is dev-testable. The node's `do_authenticate` verifies the HIP and **cannot be satisfied
by a software mock** (a real `CanonicalHipProof` needs the secure element — its
chain/HMAC checks won't pass for a fake).

**Phone scope (S20):** the StrongBox HIP generation (step 4), the fingerprint gate, and
the **full end-to-end handshake** against a running node.

**Live end-to-end needs the full lab topology:**
- a **block-producing** chain (a single `--dev`/`--alice` node stalls at #0 — Sassafras
  needs a quorum / the star topology) — required because the cert mint + the anchor-block
  freshness check need real blocks;
- a **non-validator chat node** as the guard (validators don't host chat — see
  `scripts/run-chat-trio.sh`);
- the **S20** running dotwave, pointed at the guard's RPC, holding a real StrongBox cert.

**Dev-stub caveat:** a cert minted via the dev path (`chat_mint_test_cert` → `register_root`)
has **no `genesis_fingerprint`**, so the node falls back to `verify_hip_proof_internal`
(internal-consistency only, no drift detection, nonce NOT bound). Production certs
(mime-wrap StrongBox / TPM2 via `mint_cert`) carry the genesis fingerprint → full
`verify_hip_proof_against_genesis` drift detection.

---

## Locked decisions (do NOT re-litigate)

- **Scope:** mobile-app side of chat steps 1 (authenticate), 2 (drop onion), 6 (retrieve).
  The auth ceremony is the focus. **NOT group chat.** Onion (not direct `send_envelope`).
- **Session model:** one biometric+HIP handshake → node-local, **non-portable** session
  (guards don't vouch for each other; switch node → re-handshake). Drops ride a cheap
  software session key. **Per-drop hardware/biometric was explicitly rejected.**
- **W = 4 days**, node **monotonic** clock, **hard cap** (activity does NOT extend it;
  expiry → fresh HIP). Node owns W and returns the expiry to the client.
- **Block-anchored nonce**, derived (no nonce store), bound to block + cert + guard +
  session key. Freshness window 10 blocks.
- **Drift detection is the default** (mime-wrap/TPM2 cert is HIP-bearing).
- **Rejected:** OIDC / bearer tokens (weaker than per-use HW key) and on-chain session
  state (a public liveness beacon = metadata leak).

## Interop invariants (node & client MUST match byte-for-byte)

- `CHAT_SESSION_NONCE_DOMAIN = b"rostro/chat/session-nonce/v1"`
- `CHAT_SESSION_DROP_DOMAIN  = b"rostro/chat/session-drop/v1"`
- nonce = `blake2_256(NONCE_DOMAIN ‖ anchor_block_hash[32] ‖ cert_thumbprint[32] ‖ guard_node_id[32] ‖ session_pubkey[32])`
- drop sig = Ed25519 over `blake2_256(DROP_DOMAIN ‖ onion_packet_bytes)`
Defined in `gemini-node/src/chat_rpc.rs` (node) and `rust_core/src/chat_session.rs` (client).

## Known gaps / deferred

- TPM2.0 **desktop client** (Android/StrongBox first; chain side already handles `Tpm2`).
- `user_authentication_required` on-chain (Tier 5) — make biometric-gating chain-verifiable.
- The broader **F1 chat UI** (onboarding, name-addressed conversations, verified-sender
  thread, read step) is a *parallel* dotwave track — see [DOTWAVE-CHAT-FRONTEND-PLAN.md].
