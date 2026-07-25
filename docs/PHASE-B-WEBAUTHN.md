# Phase B — WebAuthn variant 5 (the keystone)

Authoritative slice plan for Phase B of the seedless-onboarding vision. Product
context: `dotwave/docs/SEEDLESS-ONBOARDING.md` §7 (the keystone) and §8 (phased
plan). This doc is the implementation plan of record; scope changes edit this
file BEFORE code, and chat summaries defer to the status column here.

Repo split: **B1 is chain work (this Rostro worktree `webauthn-v0`)**. B2/B3 are
client work (dotwave). `/docs/` is gitignored here — commit this file with
`git add -f` (vault-doc precedent, cf. RAILS-V0-PLAN.md).

---

## 0. Where this sits

Phase A is complete + merged + on-device-proven (dotwave `origin/main` d6bdea4):
generic two-phase StrongBox signing over every `TxAction` (#1), on-chain key
revoke/lifecycle (#2), and the recovery-nudge banner (#3, shipped **dormant** —
it fires only for a seedless account with no recovery, which cannot exist until
this phase lands).

Phase B builds the one primitive that unlocks the rest: **WebAuthn variant 5**.

## 1. The keystone primitive

`RostroSignature::WebAuthnP256` — signature variant **index 5**, reserved and
unbuilt in `substrate/utils/rostro-multi-key/src/lib.rs` (the comment at the
`EcdsaP256` variant reserves "index 5 next to it").

**Load-bearing simplification (verified 2026-07-25):** the *signer* arm is
shared. `RostroSigner::EcdsaP256([u8;33])` already covers both P-256 signature
envelopes — "same curve, same device key, **same account**" (lib.rs:107-111).
The account is `blake2_256(compressed_pubkey)` via `ecdsa_p256_to_account`.

Therefore Phase B adds **no new address derivation** and **no new signer
variant** — a passkey account reuses the existing P-256 derivation. Only a new
*signature envelope* (variant 5) and its verify are needed. A passkey and a
StrongBox key that happen to share a pubkey would resolve to the same account;
in practice each ceremony mints its own P-256 key, hence its own account.

### What a WebAuthn assertion is

An `navigator.credentials.get()` / Credential Manager assertion yields:
- `authenticatorData` — `rpIdHash(32) ‖ flags(1) ‖ signCount(4) ‖ …`.
- `clientDataJSON` — UTF-8 JSON `{"type":"webauthn.get","challenge":"<b64url>","origin":"…",…}`.
- `signature` — ECDSA P-256 (DER) over `authenticatorData ‖ SHA256(clientDataJSON)`.

The signed message is **not** a raw prehash of our payload; the chain must
reconstruct the envelope and confirm the embedded `challenge` is our extrinsic
signer payload. That envelope reconstruction + challenge binding is the entire
new attack surface.

## 2. Slice split

| Slice | Where | Depends on | Gasless? | Delivers |
|-------|-------|-----------|----------|----------|
| **B1** WebAuthn verify | chain (this worktree) | — | n/a | the primitive |
| **B2** Passkey **recovery** | dotwave | B1 | **no** | "add recovery method" → completes #3; activates the dormant banner |
| **B3** Passkey **account** | dotwave | B1 + gasless | **yes** | seedless "Continue with Google" onboarding |
| Parallel | chain/infra | — | — | sponsorship model (faucet / meta-tx / PoP-gated) for B3 |

Sequence: **B1 → B2 → B3**. B2 is the self-contained early win (rides an already
funded account, no gasless); B3 waits on the sponsorship decision.

### 2a. Trust boundary — hostile parsing stays inside RVM

Two execution zones, and where code sits decides its blast radius:

- **The runtime** runs inside the **RVM sandbox** (RISC-V). A fault here is
  contained by the VM isolation. This is where signature verification runs
  (extrinsic `Checkable`/`verify`), so the untrusted WebAuthn envelope is
  SCALE-decoded (bounded) and scanned **inside** the sandbox.
- **The node/host** is the process that *runs* the runtime and terminates
  **libp2p + RPC** — the network-facing perimeter, holding real OS handles.
  Cannae sandboxes the host, but the host is still where hostile bytes arrive
  first. Code here is *on the perimeter*, not behind the RVM wall.

Consequences baked into this scope:

1. **No host-side surface for the signature types.** `serde`/`serde_json`
   `Serialize`/`Deserialize` on `RostroSignature`/`RostroSigner` is std-only =
   host-side. It has no consumer today, but a serde impl on a signature type is
   exactly what later gets wired into an RPC response or gossip decode — putting
   std deserialization of attacker-influenced bytes *on the perimeter, outside
   RVM*. So we **delete it** (B1.0). "Outside the walled garden" ≠ safe; it is
   the more exposed position.
2. **All WebAuthn envelope parsing lives in the runtime verify**, never
   host-side. The only consumers of these types are runtime-side (confirmed:
   gemini runtime, keyring pallet) — hostile bytes never reach a host parser.
3. **Minimal hand-rolled scanner, not `serde_json`, even inside RVM.** Note
   `serde_json` (no_std+alloc) is *already* a gemini-runtime dependency — so this
   is **not** a "avoid a new dep" call. It is a blast-radius call: the one path
   that willingly ingests hostile input gets the smallest possible parser, so a
   parser bug is as contained and auditable as we can make it, sandbox or not.

---

## 3. B1 deliverables (this slice)

| # | Deliverable | Acceptance | Status |
|---|-------------|-----------|--------|
| B1.0 | **Drop `serde` from `rostro-multi-key`** (perimeter-surface reduction, §2a) | optional `serde` dep + `derive(Serialize,Deserialize)` + `serde(with=…)` attrs + `serde_bytes_array` module removed; types are pure SCALE; runtime (RISC-V) + `gemini-node` (std) build green | ☐ |
| B1.1 | `RostroSignature::WebAuthnP256 { pubkey:[u8;33], authenticator_data: BoundedVec<u8,A>, client_data_json: BoundedVec<u8,C>, sig:[u8;64] }` appended at index 5, **serde-free** | Encode/Decode/TypeInfo/MaxEncodedLen derive; NO serde attrs; index 5 stable; existing variants byte-unchanged | ☐ |
| B1.2 | `Verify::verify` + `verify_against` arms | reconstruct `authData ‖ sha256(clientDataJSON)`, P-256 verify over its sha256, low-s enforced, pubkey→account match (verify) / enrolled-key match (verify_against) | ☐ |
| B1.3 | clientDataJSON challenge binding (D1) | reject if any `\`; `clientDataJSON` contains `"challenge":"<base64url(sha2_256(payload))>"` and `"type":"webauthn.get"`; else reject | ☐ |
| B1.4 | authenticatorData flag checks | UP (user-present) bit required; UV surfaced; rpId per D2; signCount ignored (nonce covers replay) | ☐ |
| B1.5 | Fixture test vectors | known `(pubkey, authData, clientDataJSON, sig, challenge)` → pass; tamper each field → fail; `(scheme,pubkey)→AccountId32` pinned (reuses P-256 vector) | ☐ |
| B1.6 | Runtime wiring | `KeyringSignature`/`Checkable` verify path admits variant 5; keyring `enroll_key` unchanged (signer already `EcdsaP256`); metadata regen; `cargo build --release -p gemini-node` (RISC-V) green | ☐ |
| B1.7 | Solo-node encoding/verify proof | a WebAuthn-signed extrinsic (software P-256 assertion fixture) accepted on the spec-bumped solo node | ☐ |

**Bounds (B1.1):** the WebAuthn envelope is larger than other variants
(authData ~37B, clientDataJSON ~120-250B). Use `BoundedVec` so `MaxEncodedLen`
stays finite and extrinsic size is capped. Proposed: `A = 256`, `C = 1024`
(revisit against real Android/iOS payloads).

## 4. The two hard design decisions

### D1 — on-chain clientDataJSON validation — RESOLVED
The runtime is `no_std`; full JSON parsing is unwanted weight + attack surface.
Prior art (see §8) converges on: don't parse — string-match. Resolution:

- **Challenge = `sha2_256(payload)`** (32 bytes). Aptos does exactly this (they
  hash the txn — with SHA3, which we drop — *specifically* to bound the challenge
  size inside clientDataJSON). Fixed 32-byte challenge ⇒ fixed 43-char base64url ⇒
  bounded field, fixed-size compare, no size worries. **No SHA3** — sha2 only
  (the WebAuthn envelope's inner `SHA256(clientDataJSON)` is sha2 by spec, so the
  path is all-sha2 end to end).
- **Encode-and-match, never decode (the webauthn-sol trick).** Build
  `needle = "\"challenge\":\"" ‖ base64url(sha2_256(payload)) ‖ "\""` and check
  `clientDataJSON` contains it. We only base64url-**encode** our own 32-byte hash;
  we never run a base64 *decoder* on attacker-controlled bytes. Also require the
  substring `"type":"webauthn.get"`.
- **Safety invariant: reject any `\` (backslash) in clientDataJSON.** Then every
  `"` is structural (no escaped quotes can exist), so no field value can embed a
  decoy `"challenge":"…"`, and the substring match is provably unambiguous. Legit
  clientDataJSON for our controlled ceremony is backslash-free (type is a literal,
  challenge is base64url, origin is an ASCII URL / `android:apk-key-hash:…`).
- Rejected: (b) canonical fixed-byte layout — platforms vary key order/whitespace;
  (c) caller-provided `challengeIndex`/`typeIndex` (webauthn-sol's EVM gas hack) —
  adds untrusted inputs to validate; the self-contained scan is cleaner off-EVM.

If a real platform ever emits a backslash in a field we don't touch, harden to an
escape-aware structural scan (still no JSON lib) — additive, not a wire change.

### D2 — rpId / relying-party binding
`authenticatorData[0..32] == SHA256(rpId)`. rpId is the passkey's RP domain.

- Account binding does **not** need rpId: the account is `hash(pubkey)`, so a
  foreign-RP passkey is simply a different account, not a forgery.
- rpId matters for the *product* (Google/Apple Password Manager sync is scoped to
  the RP; the Android app must be associated to the domain via assetlinks). Ties
  to the rails presentation-domain work.
- **(b) Do NOT enforce rpId on-chain in B1 (recommended).** Check the UP flag;
  record but don't constrain rpIdHash. Revisit enforcement when a canonical
  `rostro` rpId + assetlinks/well-known infra exists. Forward-commitment noted so
  a later enforce is an additive tightening, not a wire break.
- (a) Enforce `rpIdHash == SHA256(<canonical rostro rpId>)` — deferred; needs the
  domain decision first.

## 5. Scope fence — B1 OUT (forwarding addresses)

- Client passkey ceremony / Credential Manager → **B2/B3** (dotwave).
- "Add recovery method" UX + `setRecoveryConfigured()` wiring → **B2**.
- Seedless onboarding fork + passkey account creation → **B3**.
- Gasless/sponsored funding → **parallel track**.
- rpId on-chain enforcement → deferred (D2b), tracked as a forward commitment.
- iOS AuthenticationServices → later (B2/B3 land Android first).

## 6. Decision log

- 2026-07-25 — Shared `EcdsaP256` signer arm ⇒ no new address derivation; variant
  5 is signature-only, append-only at index 5.
- 2026-07-25 — **D1 RESOLVED:** challenge = `sha2_256(payload)` (bounded 32 B);
  encode-and-match (never decode); reject-on-backslash makes the substring match
  provably safe; require `"type":"webauthn.get"`. See §4 D1 + §8.
- 2026-07-25 — **No SHA3 / keccak** anywhere (user ruling): challenge hash is sha2,
  not SHA3 (Aptos uses SHA3 here — we deliberately diverge). Rostro goes sha2 → PQ;
  keccak only ever considered for transport, not this path. Path is all-sha2.
- 2026-07-25 — D2: rpId not enforced on-chain in B1; UP flag required; enforce
  deferred behind a rostro-domain/assetlinks decision. Matches Aptos treating
  origin as application-layer (their audit LOW-1).
- 2026-07-25 — Envelope fields `BoundedVec` (A=256, C=1024 provisional). Enforce
  the cap **at decode** (FRAME `MaxEncodedLen`/`Decode` gives this free) — Aptos's
  audit HIGH-1 was defining a 1024 cap and never enforcing it; we won't repeat it.
- 2026-07-25 — **Build our own no_std verify** (user ruling), not a vendored crate:
  reuse existing `verify_p256` + `sp_io` sha2; the only net-new code is a base64url
  encoder + the clientDataJSON field-check. Mirror Aptos's 8-step checklist (Apache-2.0)
  structurally; JSON parse swapped for webauthn-sol-style string match (MIT). No
  passkey_types, aptos_crypto, anyhow, or ring.
- 2026-07-25 — **Drop `serde` from `rostro-multi-key`** (B1.0) — perimeter-surface
  reduction, not just hygiene. serde on signature types is std/host-side, and the
  host is the network-facing perimeter *outside* RVM (see §2a). It has no consumer
  today; deleting it forecloses ever putting host-side std deserialization of
  hostile bytes on the perimeter. Variant 5 is serde-free.
- 2026-07-25 — Correction: the "minimal scanner not serde_json" call is about
  **blast radius, not dependencies** — `serde_json` (no_std+alloc) is *already* a
  gemini-runtime dep (`runtime/gemini/Cargo.toml`). The hostile-input verify path
  gets the smallest possible parser regardless.

## 7. Open questions

1. ~~Challenge = payload vs sha256(payload)~~ — **RESOLVED: `sha2_256(payload)`** (D1).
2. **rpId now or deferred?** Deferred (D2b) — lean confirmed; matches Aptos. Reopen
   only when the rostro-domain/assetlinks infra lands.
3. **Canonical rpId domain** (only if/when D2a): which domain does Rostro own for
   the passkey RP + Android assetlinks? Deferred with #2.

## 8. Prior art + no_std dependency map (2026-07-25 research)

We are not reinventing: Aptos ships our exact design (native on-chain WebAuthn
P-256 tx auth, Rust, **Apache-2.0**, audited). `rostro-multi-key` is Apache-2.0, so
referencing Aptos (Apache-2.0) and Base/Coinbase `webauthn-sol` (**MIT**) is
license-clean. Avoid `webauthn-rs` (MPL-2.0) and full `passkey-rs` (std, heavy).

| Project | License | Architecture | Use to us |
|---|---|---|---|
| Aptos `aptos-core` (AIP-61) | Apache-2.0 | native on-chain WebAuthn P-256, Rust | **design + 8-step verify checklist** (std parse, doesn't port) |
| `base/webauthn-sol` | MIT | on-chain, no JSON parse (index/encode-match) | **no_std-shaped parse pattern** |
| Frequency `passkey-wallet-generator` | Apache-2.0 | passkey *derives sr25519 client-side*, **no on-chain verify** | the road not taken (contradicts §4 "passkey IS the root") |
| `1Password/passkey-rs` | Apache-2.0/MIT | full authenticator framework, std | too heavy / client-side |
| `kanidm/webauthn-rs` | MPL-2.0 | server-side, std | **avoid (license + std)** |
| Daimo p256-verifier / RIP-7212 | permissive | P-256 ECDSA primitive | we already have (ecalli-112) |

**Aptos's `webauthn.rs` deps → our no_std substitute** (their file is *not*
no_std-clean, but almost none of it is new work for us):

| Aptos dependency | Purpose | Our substitute | New code? |
|---|---|---|---|
| `serde_json::from_slice` → `CollectedClientData` | parse clientDataJSON | hand-rolled field-check (ban-backslash + substring) | **~15 lines** |
| `passkey_types::Bytes` base64url **decode** | challenge b64url | base64url **encode** of our hash + string-match | **~20 lines** |
| `passkey_types::crypto::sha256` | `SHA256(clientDataJSON)` | `sp_io::hashing::sha2_256` | own it |
| `aptos_crypto::secp256r1_ecdsa` verify | P-256 ECDSA | existing `verify_p256` (powers variant 4) | own it |
| `HashValue::sha3_256_of` (challenge) | bound challenge | `sha2_256(payload)` (no SHA3) | own it |
| authenticatorData struct | flags/rpIdHash | byte-index: `len≥37`, `authData[32] & UP` | trivial |
| `anyhow`, `String`, `format!` | errors | `bool` (the `Verify` contract) | n/a |

Net-new code for B1: a base64url encoder (~20 lines) + the clientDataJSON
field-check (~15 lines) + authData byte-indexing. Everything cryptographic is
reuse. Verify reuse detail: `verify_p256(pubkey, sig, m, signer)` hashes `m` with
sha256 internally, so pass `m = authenticatorData ‖ sha2_256(clientDataJSON)` and
it computes `sha256(m)` = the exact WebAuthn digest — no change to the P-256 path.

Sources: aptos-foundation/AIPs aip-61 · aptos-labs/aptos-go-sdk SECURITY_AUDIT_REPORT.md ·
aptos-labs/aptos-core types/src/transaction/webauthn.rs · base/webauthn-sol ·
ProjectLibertyLabs/passkey-wallet-generator · 1Password/passkey-rs.
