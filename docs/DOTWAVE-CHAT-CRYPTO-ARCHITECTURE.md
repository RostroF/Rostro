# dotwave ⇄ Rostro chat — crypto architecture & gated plan (v1.0)

**Last touched:** 2026-06-11
**Status:** active. Supersedes the crypto-layering in
[DOTWAVE-CHAT-ROADMAP.md](DOTWAVE-CHAT-ROADMAP.md) (mission/threat-model section
there still holds). Captures the architecture settled in the 2026-06-11 design
thread + the phased plan with hard gates.
**Companions:** [[DOTWAVE-CHAT-ROADMAP]], [[DOTWAVE-BRIDGE-TESTNET]],
[[decentralized-chat-architecture]], the secret-squirrel dead-drop pallet
(`/home/coder/Polkadot/secure-messenger`).

---

## The layered crypto (v1.0)

Three independent layers, each with its **own key and its own job**. They do not
share keys — and on real silicon they *cannot* (TPM restricted AKs + StrongBox
fixed-usage keys forbid one key doing both sign and decrypt).

| Layer | Key | Where | Job | Processing |
|---|---|---|---|---|
| **Node admission** | mime-wrap HW-attested cert (signing) | secure silicon | auth to *drop* an envelope — anti-spam / personhood | automatic |
| **Outer** (sealed sender) | **Ed25519 → X25519** | **software, cross-platform** | encrypt + map sender↔recipient, hide sender | **background, no prompt** |
| **Inner** (content) | recipient's **silicon-native** key | secure silicon | content decrypt | **biometric-gated, encrypted-at-rest** |

### Send (Alice → Bob)
1. Alice authenticates to her node with her **mime-wrap HW-attested cert** (signs
   the drop; node `verify_chat_auth` admits). Auth only — the node never sees inside.
2. She builds the envelope: **inner** content sealed to **Bob's silicon content
   key** (software-ephemeral ECDH to Bob's published static key); **outer** =
   sealed-sender wrap via **Ed25519→X25519, unchanged**.
3. Encrypted envelope dropped → XOR-striped across relays.

### Receive (Bob)
1. Phone collects shares → XOR-reassembles → unwraps the **outer** layer
   (Ed25519/X25519, **software, background, no prompt**) — pure envelope handling
   (routing + sender/recipient mapping).
2. The **inner** blob remains **encrypted at rest** in app storage. The app can
   sync/collect in the background and *never* holds cleartext.
3. To read: **fingerprint → authorizes the silicon key → in-chip decrypt →**
   plaintext, transient only. Amnesiac app discards it after.

**Property:** reassembled messages are encrypted at rest; the keys to view them
**never leave the secure silicon**; viewing needs *the chip + the human*. A seized,
locked, or app-closed device yields encrypted blobs behind a chip-locked,
biometric-gated key.

## Silicon → curve mapping (the inner content key is platform-driven)

| Platform | Secure element | Admission cert (sign) | Inner content key (decrypt) |
|---|---|---|---|
| Mobile (Android) | **StrongBox** | P-256 | **P-256** (StrongBox's only EC curve; no P-384/521, no Curve25519) |
| Laptop/desktop (future) | **TPM 2.0** | NIST P-256/P-384 (restricted AK) | **P-384** (stronger, TPM-native) |

- StrongBox does **not** support P-521 or Curve25519 — corrected from an earlier
  assumption. The hardware-bound keys use **what the silicon natively offers**
  (NIST P-curves); the djb curves (Ed25519/X25519) stay in the **software outer
  layer**, identical on every platform.
- **Cross-platform messaging works by construction:** the *recipient's* silicon
  decides their content-key curve; the *sender* is always software on the inner
  seal (ephemeral on the recipient's curve). Alice-on-phone (P-256) → Bob-on-laptop
  (P-384): she resolves `bob.rst`, sees `{content-key: P-384}`, software-ECDHs to it;
  Bob's TPM decrypts in-chip. The **RNS record's scheme tag** advertises the curve.

## RNS record = the common thread (and the non-inhibition rule)

Both the basic chat **and** secret-squirrel dead-drop bootstrap from **a public key
published in an RNS record**. So the record is built **general**, not chat-specific:
- **Curve-agnostic + scheme-tagged** — holds Ed25519 (outer), P-256/P-384 (inner),
  secp521r1 (dead-drop), PQ (v1.1). The tag drives version negotiation.
- **Any name, including throwaways** — register is name-agnostic (proven).
- **Multi-identity per user** — the device manages a *set* of `(name, key)`
  identities; throwaways are minted per-correspondent.
- **The relay tag stays opaque** — so client-side derivation can be `H(pubkey)`
  (convenient) *or* `H(shared_secret ‖ counter)` (dead-drop). The transport already
  doesn't preclude either.

**Two products, one foundation.** Basic Rostro chat (named, convenient) and
secure-messenger (dead-drop, throwaway, deniable, on-chain self-destructing slots)
are **different products on the same RNS/relay foundation**. The rule: the basic
chat structure must **not inhibit** secure-messenger. "Known vs unknown" is an
app fiction — the chain has no social graph; a relationship *is* possession of a
shared secret, established out-of-band, fluid and local.

---

## Phased plan with hard gates

Each gate = exit criteria + go/no-go before the next phase begins.

### FOUNDATION — ✅ DONE & VERIFIED
Transport (sealed sender + XOR-stripe relay), dotwave `chat.rs` port, **R1** (RNS
genesis init — Official + base node), **R2** (mixed validator/relay topology),
`register` finalizes end-to-end.
- **Gate (passed):** local round-trip + register finalize on the mixed topology.
- **Gate (deferred):** phone-to-phone on lab hardware — opens when the lab powers up.

### PHASE 1 — Named identity  ◀ **logic COMPLETE; UI deferred**
**Built + verified (4 green tests on the live mixed topology):**
- Curve-agnostic, scheme-tagged chat-identity record in RNS `PUBKEY1` (zero chain
  change) — `chat_publish_identity` / `chat_resolve_identity`.
- **Item 1** — message *by name* (`name_addressed_message_lands`).
- **Item 2** — receive shows the *verified* sender name via **forward-resolve-and-
  verify** (claim in the signed inner; recipient resolves it + checks the published
  key == the signed sender pubkey; **impersonation-resistant**) (`sender_name_verified_on_receive`).
- **Item 3** — one-step onboarding `chat_setup_messaging` (register + publish)
  (`chat_setup_messaging_onboards`).
- Inner payload now `{sender_name, body}` (SCALE, signed); `chat_send` takes
  `sender_name`; `RecoveredMessage` exposes `claimed_sender_name`.

**DEFERRED — item 4, the UI** (skipped intentionally: don't lock a UX pattern before
Phases 2–3 + secure-messenger features exist, then jam them in). When we circle back:
re-run FRB codegen to expose the new fns; **fix `chat_store.dart` for the new
`chatSend(senderName)` signature** (currently stale); build the onboarding screen,
new-conversation-by-`.rst`-name, and the verified-sender-name thread.

- **GATE (logic, met):** name-addressed both directions, verified, no hex *in the
  path*; record holds Ed25519 now + room for the P-256/PQ inner key.
- **GATE (UX, deferred):** the same, surfaced in the app with zero hex on screen.

### PHASE 2 — Cert-gated send  ◀ **✅ DONE & GATE MET (2026-06-11)**
**Built:** mime-wrap cert enforced at admission (node `verify_chat_auth`
optional→**required**, flip landed as `4b7d840c29` / branch chat-cert-gate-v0;
dotwave signs each drop — software P-256 on the dev box, StrongBox/TPM on real
hardware, same digest + wire format).
- **GATE (met, proven on a fresh flipped R2 fabric):** unauthed drop rejected
  (-32602); cert-holder admitted + recovered cross-node; wrong-key sig under a
  real Active cert rejected (-32000); no unauthenticated path remains.
- **dotwave side (uncommitted in the dotwave repo):** `chat_send` takes
  `(auth_cert_thumbprint_hex, auth_cert_seed_hex)` and signs internally;
  `chat_mint_test_cert` (idempotent, one-extrinsic dev mint) +
  `dev_cert_seed_hex` (per-account derived seed — keeps the idempotent mint and
  the signing key in lockstep); tests: `tests/chat_auth.rs` (3 gate tests) + the
  4 legacy chat tests reworked to authed sends. `frb_generated.rs` chat_send arm
  HAND-PATCHED pending the deferred FRB codegen rerun.
- NOTE: the p256 `Signer`/`Verifier` traits SHA-256 the message internally, so
  the wire signature is ECDSA-P256 over SHA-256(blake2_256(domain‖env‖ts)) —
  symmetric on both sides by using the same standard traits; don't "optimize"
  either side to prehashed.

**Grounding (was: start coding from here — now landed; kept for reference):**
- **Cert mint = ONE extrinsic on the dev box.** `register_root(proxy, device_pubkey,
  attestation, ttl_blocks, capability_ekus)`. `TpmTestAttestationVerifier`
  (`zkpki-primitives/src/traits.rs:55`) **ignores `attestation` entirely**;
  gemini wires `NoopProxyValidator` (`runtime/gemini/src/lib.rs:777`) so the proxy
  check passes. `register_root` stores the passed `device_pubkey` AS the
  `cert_ec_pubkey` in `CertLookupCold` (`zkpki-pallet/src/lib.rs:~1131`) — which is
  exactly what the chat-auth verifies against.
- **Device key = P-256 ECDSA.** `DevicePublicKey { EcdsaP256, SEC1 bytes }`
  (`zkpki-primitives/src/crypto.rs:58`, `new_p256(...)`). On the dev box use a
  **software P-256 key** (no StrongBox). The node's `verify_p256(digest, sig)`
  accepts DER **or** raw (r‖s) ECDSA-P256.
- **What's signed:** `digest = blake2_256(CHAT_AUTH_DOMAIN ‖ envelope_bytes ‖
  ts.to_be_bytes())` (`chat_rpc.rs verify_chat_auth`, ~line 418). dotwave signs that
  digest with the `p256` crate.
- **Thumbprint:** read `Roots(account).cert_thumbprint` from storage (the mint event
  carries only `root`).
- **Node flip = one line:** `chat_rpc.rs` send-envelope `(None,None,None)` arm
  (~line 514) returns an error instead of `log::warn!`.

**Four components (3+2 are COUPLED — flip kills all chat until auth-signing lands):**
1. dotwave: mint a test cert — add `p256` dep; gen P-256 key; `register_root` w/
   `DevicePublicKey::new_p256` + dummy attestation; read thumbprint from `Roots`.
2. dotwave: fill the `auth_*` seam in `chat_send` — sign the digest, pass
   `(thumbprint, ts, sig)`. **Provable against the CURRENT node** (it runs
   `verify_chat_auth` when the params are present) — no node rebuild needed for 1+2.
3. node: flip the gate + `cargo build -p gemini-node` + restart the relays.
4. rework the 4 chat tests (`chat_roundtrip`, `name_addressed_message_lands`,
   `sender_name_verified_on_receive`, plus the relay sends) to mint a cert + send
   authed, else they fail under the flip.

**Resume the test bed:** re-run R2 (validator + 3 relays). Sandbox/launch notes are
in the vault's node-spinup doc; the dev-box quirks (one node per harness-tracked
background task, `dangerouslyDisableSandbox` for the RISC-V JIT) are session-local.

### PHASE 3 — Hardware-bound content  ◀ **v1.0 ships here. CRYPTO + PIPELINE ✅ (2026-06-11); silicon items await lab hardware**
**Built (dev-box, software content keys behind the silicon seam):**
- New crate `substrate/utils/rostro-chat-content-seal` (Apache, sister to
  sealed-sender): per-message ephemeral ECDH **on the recipient's curve**
  (P-256/P-384) + HKDF-SHA256 + ChaCha20-Poly1305; SCALE `ContentSealed` IS the
  `inner_ciphertext` (the layering the envelope crate always reserved). **The
  silicon seam = `ContentEcdh` trait**: decrypt needs exactly ONE private-key op
  (ECDH vs the ephemeral); StrongBox/TPM perform it in-chip later,
  `SoftwareContentKey` is the dev stand-in + reference implementation.
- RNS record: `inner_content_key` now REQUIRED at publish — hex of SCALE
  curve-tagged `ContentPublicKey`. The curve tag lives on the KEY (rotation
  without a record-scheme bump); `scheme` stays the record-layout version.
- dotwave: `chat_send` takes the recipient content key (record-resolved) and
  seals the payload — no plaintext-inner path; `chat_fetch` returns
  `AtRestMessage{sealed_content_hex}` (outer-unwrapped, sender-verified,
  content STILL sealed); `chat_read_content` is the explicit biometric/silicon
  read step. Sender-name verify moves to read time by construction.
- **Zero node/chain changes** — the node never looks inside.
- **GATE (dev-box items, met on the live fabric):** ✅ reassembled content
  encrypted at rest (fetch yields sealed blob only; no-leak asserted);
  ✅ cross-platform P-256 ↔ P-384 decrypts (live-fabric P-384 recipient +
  both-direction unit tests). 8 crate tests + full 8-test chat suite green.
- **GATE (silicon items, DEFERRED to lab hardware):** decrypt only via
  biometric→silicon; key proven non-extractable. The seam is built; the lab
  fills `ContentEcdh` with StrongBox/TPM and proves both. **v1.0 ships when
  these pass on the phones.**

*— Phases 1→3 are strictly sequential and land **v1.0** (named, cert-gated,
hardware-bound content). After P3 the tracks fork.*

### PHASE 4 — Metadata anonymity + device hardening  *(secure-messenger core)*
**Build:** sender anonymity to the entry relay (onion); traffic-analysis resistance
(cover traffic/padding); amnesiac app (consume-on-read), disappearing messages,
panic-wipe.
- **GATE:** entry relay can't identify sender; LAN observer can't link A↔B; seized
  device discloses nothing; residual traffic-analysis risk stated in-app.

### PHASE 5 — Forward secrecy (Double Ratchet)
**Build:** DR over the transport (reorder buffer + bounded skipped-keys for
TTL-gaps, X3DH bootstrap); DR session state encrypted-at-rest under the hardware key.
- **GATE:** 1:1 forward-secret + post-compromise-secure; survives out-of-order,
  TTL-gap, and app restart.

### PHASE 6 — Groups (MLS)
**Build:** persistent MLS storage (replace `MemoryStorage`); admin-committer
ordering; KeyPackage/Welcome over the relay; group UI.
- **GATE:** small admin group works E2E; removed member can't read post-removal (FS).

### PHASE 7 — secure-messenger enablement + productionization
**Build:** prove the foundation hosts dead-drop (shared-secret slot addressing +
throwaway multi-address) *without changing the basic chat*; per-SS58 rate-limit,
relay selection, DHT tuning, notifications, backup UX, public endpoints.
- **GATE:** secure-messenger builds/ships on the same foundation with no basic-chat
  edits; public-testnet deploy live.

### FUTURE — v1.1 PQ
**Build:** new Pixel ships PQ in silicon → publish a PQ inner content key; same
record + scheme-tag mechanism.
- **GATE:** PQ content key publishes + negotiates via the scheme tag; v1.0↔v1.1
  interop documented.

---

**Critical path:** 1→2→3 sequential → **v1.0**. Then 4 (anonymity/dead-drop, the
secure-messenger line) ∥ 5 (FS) ∥ 6 (groups). P7 + PQ are the tail.
