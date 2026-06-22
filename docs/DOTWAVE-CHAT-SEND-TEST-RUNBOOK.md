# dotwave ⇄ Rostro chat — first message-send test runbook

**Created:** 2026-06-21
**Status:** app side built & APK green; awaiting the 4-node lab rig + S20s.
**Goal:** send a real message **from the dotwave app** end-to-end — Alice (phone)
→ 2-hop onion → guard → relay-2 → stripe → Bob (phone) reads it.
**Companions:** [DOTWAVE-CHAT-AUTH-CEREMONY.md](DOTWAVE-CHAT-AUTH-CEREMONY.md) (why
the drop is auth-gated), [DOTWAVE-CHAT-FRONTEND-PLAN.md](DOTWAVE-CHAT-FRONTEND-PLAN.md)
(the UI track this exercises), [DOTWAVE-CHAT-AUTH-HANDOFF.md](DOTWAVE-CHAT-AUTH-HANDOFF.md).

---

## What forced this shape (read before changing the plan)

The "obvious" path — `ChatStore.send()` → `chat_send` — is **always `Ratcheted`**
(Double Ratchet), so it's blocked on F2. The only **non-ratcheted** send the app
can do is the **onion** path. And the node's `chat_send_onion` handler imposes two
hard constraints (`gemini-node/src/chat_rpc.rs`):

1. **Auth is mandatory** — a drop with no session and no cert is rejected. There is
   **no auth-optional mode** on the onion path; the auth ceremony exists to gate it.
2. **≥2 hops mandatory** — `PeelMode::GuardEntry` rejects a 1-hop onion (the guard
   must never be the final hop and see sender+recipient together). Guard *forwards*
   to relay-2; relay-2 *delivers* + stripes.

Cert-auth reads the cert from chain state (`runtime_api().cert_authentication`), so
the cert must be **minted in a block** → the chain must **produce blocks**. And
`chat_admission.rs` **rejects chat traffic to any known validator**, so both the
guard and relay-2 must be **non-validators**.

Net: the first app send is **2-hop onion + cert-auth**, on a rig of **2 validators
(blocks) + 2 non-validator relays (guard + relay-2)**.

## App side — what's built (dotwave branch `chat-auth-client-v0`)

- `ChatStore.send()` → `chat_send_onion_2hop` with `Plain` content + cert-auth
  (`certAuth()` → thumbprint + cert seed; rust derives the `blake2_256(domain ‖
  packet ‖ ts)` ECDSA sig the node verifies). Clear errors if relay-2 or the cert
  is missing. The F2 upgrade swaps `Plain`→`Ratcheted` here; the onion + auth are
  unchanged.
- **Relay-2 RPC** setting + **Mint admission cert** action in Messages → node
  settings. The standalone mint is `register_root` only — **no RNS name required**,
  which is why a root account can send (see account roles below).
- **Content-key** field in "new conversation" + **copy-your-content-key** on the
  identity card — a no-RNS contact-bootstrap fallback. With RNS names published, use
  start-by-name instead (`resolveContactByName`).
- `librust_core.so` rebuilt for arm64 from HEAD; `flutter build apk --debug` green
  → `build/app/outputs/flutter-apk/app-debug.apk`.

## Account roles (load-bearing)

- **Bob (non-root) = named recipient.** Runs **set up messaging** (`setupMessaging`)
  → registers `bob.rst`, publishes **CHAT** (ed25519) + **MESSAGE** (content key)
  records. Receives only — no cert needed.
- **Alice (root) = sender.** Root **cannot create a canonical RNS name**, so Alice
  does *not* run setup-messaging. She uses the standalone **Mint admission cert**
  (no name) and sends to `bob.rst`. Her claimed sender-name is blank/unverified on
  Bob's side; the message still delivers (the read step leaves the name blank rather
  than dropping it).
- Direction is therefore **Alice → Bob**.

## ⚠️ The one gotcha that fails silently

The 2 relays must be on the **same chain as the 2 validators** — same `--chain`
spec, relays bootnoded into a validator. If the relays form their own island (the
default for `run-chat-trio`/`run-chat-lan`), Bob's name registration and Alice's
cert mint never reach a validator for inclusion, the guard's `best_hash` never shows
them, and every send is rejected with a cert-not-found / not-Active error.

## Runbook

Assume guard relay RPC `9954`, relay-2 RPC `9955`.

0. **Build node binaries** (once):
   ```sh
   cd ~/Rostro && SUBSTRATE_RUNTIME_TARGET=riscv \
     cargo build --release -p gemini-node -p rostro-supervisor
   ```
   Run the nodes under `dangerouslyDisableSandbox` on the dev box (RISC-V JIT).
1. **Rig:** 2 validators producing blocks + 2 non-validator relays (guard + relay-2),
   **all one network**. Confirm a validator is producing blocks and the relays are
   peered in.
2. **Install + USB plumbing** (S20 connected):
   ```sh
   adb install -r ~/Polkadot/dotwave/build/app/outputs/flutter-apk/app-debug.apk
   adb reverse tcp:9954 tcp:9954
   adb reverse tcp:9955 tcp:9955
   ```
3. **Bob's phone:** messaging → **set up messaging** as `bob` (registers `bob.rst`,
   publishes CHAT+MESSAGE). Set Bob's guard URL so he can fetch.
4. **Alice's phone (root):** node settings → Guard `ws://127.0.0.1:9954`, Relay-2
   `ws://127.0.0.1:9955` → Save → **Mint admission cert** (enter the account phrase;
   watch a validator include it).
5. **Alice:** new conversation → `bob` (resolves by name) → type → **send**.
6. **Confirm on the wire:** relay logs show guard peel→forward
   (`/rostro/chat-onion-forward/1`) and relay-2 deliver→stripe (`rostro-chat-rpc`,
   `rostro-chat-stripe` at debug).
7. **Bob:** refresh → sealed thread appears → the explicit read step decrypts.

## Read-back

`rostro-chat-cli` is **v0.1 plaintext-inner** and cannot decode the app's v1.0
content-sealed payload, so it can't act as Bob. Use the **second Samsung** running
the same APK as Bob. (A scriptable box-side Bob would need the CLI upgraded to v1.0
content-seal — a separate task.)

## Interop invariants exercised

- cert-auth digest: `blake2_256(b"rostro/chat/auth/v1" ‖ packet_bytes ‖ ts_be)`,
  P-256 ECDSA, must match `CHAT_AUTH_DOMAIN` in `chat_rpc.rs` and `chat.rs`.
- 2-hop peel modes: guard `GuardEntry`→Forward, relay-2 `FinalRelay`→Deliver.
- content sealing: `ContentPayload::Plain(InnerPayload{sender_name, body})` sealed to
  the recipient's MESSAGE content key; read via `chat_read_content`'s Plain branch.

## Next iterations (after first green send)

- **Session-key drop auth** (cheaper than cert-auth per drop): wire the dart session
  manager (auth-ceremony handoff #1) → handshake → 4-day session → session-key sig.
- **F2 forward secrecy:** swap `Plain`→`Ratcheted` in `send()`, thread + persist the
  DR session state.
