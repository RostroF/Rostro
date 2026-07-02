# Chat: portable session tickets (witnessed spend as admission ticket)

Branch `session-ticket-v0`, worktree `/home/coder/Rostro-session-ticket`
(dotwave side on a matching branch). Follows CHAT-SPEND-WITNESS.md and
DOTWAVE-MEMBERSHIP-AUTH-CLIENT-PLAN.md; written 2026-07-01 as the P0
spec for the phased build below.

## 1. Problem

The anonymous membership session is node-local: `chat_authenticateMembership`
records the `AcceptedSession` only in the RAM of the guard that verified the
handshake. What gossips (`SpendRecord`) proves only "this nullifier is spent
this epoch", so every other guard can refuse a second handshake but cannot
admit the session that spend paid for. Two user-visible consequences,
both confirmed on hardware during the membership-client E2E:

1. **Pinned entry guard.** For the rest of the 24h epoch, anonymous sends
   can only enter through the issuing guard. If it goes down, there is no
   anonymous entry until the epoch rolls (today the app falls back to the
   identified cert path, which is testnet scaffolding).
2. **App restart loses the session.** The session keypair dies with the
   process; a fresh handshake is rejected with -32003 (nullifier already
   spent), so a restarted app is stuck on cert fallback for the epoch.

The spend design already frames the co-signed record as "the session's
admission ticket" (spend.rs doc comment). The ticket is just missing one
field to be portable: the session public key.

## 2. Design

### 2.1 Bind the session key into the witnessed spend

`SpendRecord` gains `session_pubkey: Vec<u8>` (32-byte Ed25519). Both
signature payloads commit to it:

- `verifier_sig_payload(nullifier, epoch, membership_root, session_pubkey)`
- `recorder_sig_payload(nullifier, epoch, membership_root, verifier,
  session_pubkey)`

Domain tags bump `...-v1` to `...-v2` so a v1 signature can never validate
a v2 payload (and vice versa). The recorder ALREADY receives the session
key in `WitnessRequest` and re-verifies the Groth16 proof whose public
inputs include `session_commit(session_pubkey)`, so counter-signing it adds
no new trust: it closes the gap where a signature that doesn't commit to
the session key would let a malicious verifier graft its own key onto a
victim's witnessed nullifier.

A record with `t` valid recorder signatures is now a self-contained,
publicly verifiable statement: "the committee witnessed a valid membership
proof for nullifier N at epoch E under root R, authorizing session key S."
That statement IS the admission ticket.

### 2.2 Admission at any guard (two transports)

**Gossip path.** `SpendStore` gains a session-pubkey index. The send path's
membership branch (`verify_membership_session_drop`), on a session-store
miss, looks the key up in the spend store, validates via the existing
quarantine-aware `admits(record, t)` against the current guard set, and on
success caches an `AcceptedSession` (then verifies the drop signature as
usual). Subsequent drops hit the cheap cached path.

**Client-carried path.** `ChatMembershipAuthResult` gains the SCALE-encoded
co-signed record (`ticket_hex`). A new one-shot RPC
`chat_presentSessionTicket(ticket_hex)` lets a client install its session
at a guard that hasn't (yet) received the record by gossip: the guard runs
the same `admits(record, t)` validation, inserts into its spend store
(which also feeds gossip) and session cache. The per-drop RPC surface is
unchanged; presenting is one extra call when entering a new guard.

The ticket is public data (it gossips anyway); possession grants nothing
without the session PRIVATE key, since every drop still requires the
Ed25519 signature over `blake2_256(CHAT_SESSION_DROP_DOMAIN || packet)`.

### 2.3 What does not change

- The nullifier spend stays once per epoch per member; round-robin
  handshake rejection (-32003/-32004) is untouched.
- Epoch rollover stays a hard cutover (re-handshake next epoch).
- Equivocation detection and quarantine: `admits(record, t)` is the same
  gate everywhere; a quarantined verifier's tickets stay dead.
- The Groth16 circuit, enrollment, and witness paths are untouched.

## 3. Wire and compatibility

Adding a field to `SpendRecord` breaks SCALE decode of the sync protocol,
and the new signature payloads invalidate v1 signatures. Per the standing
hard-cutover rule (no grace windows):

- libp2p protocols bump: `/rostro/chat-spend/1` -> `/rostro/chat-spend/2`,
  `/rostro/chat-spend-witness/1` -> `/rostro/chat-spend-witness/2`.
- Signature domain tags bump to `-v2` (see 2.1).
- Old nodes and new nodes simply do not interoperate on the spend plane;
  the spend set is per-epoch RAM, so there is no stored state to migrate.
  On the lab rig all nodes restart together; on a live testnet the
  canonical-files rollout handles the binary cutover.

## 4. Privacy note (decided)

With portability, every guard that admits the session (or receives the
record) learns the nullifier-to-session-key link, not just the issuing
guard. Accepted: the nullifier already gossips network-wide, the session
key is already visible to every recorder on the committee, and a guard
still only correlates the drops that enter through it, which is exactly
what the issuing guard sees today. Cross-epoch unlinkability is untouched
(fresh nullifier and fresh session key each epoch).

## 5. Decisions of record (P0)

- D1 Transport: BOTH gossip-path and client-carried ticket. Gossip alone
  leaves a window where a drop beats anti-entropy to a guard; the
  client-carried ticket makes admission deterministic.
- D2 Presenting: a dedicated one-shot RPC (`chat_presentSessionTicket`),
  not a per-send parameter. Keeps the hot path unchanged and the ticket
  install idempotent.
- D3 Cutover: hard protocol + domain-tag bump (section 3). No dual-decode.
- D4 Privacy: accepted per section 4.
- D5 Client persistence: the dotwave session (seed + ticket + epoch) is
  persisted in secure storage per address; an app restart inside the epoch
  reuses the session instead of burning a doomed handshake. The
  "-32003 marks membership unavailable for the run" patch from the
  membership-client build is removed as obsolete.

## 6. Phases and gates

- **P0, this spec + worktree.** Gate: committed with decisions. DONE.
- **P1, crate: the record binds the session key.** `SpendRecord.session_pubkey`,
  v2 payloads/tags, `verify_record` checks, `SpendStore` session index.
  Gate: crate tests green, including: a record whose session key was
  swapped after signing fails `verify_record`; a v1-style signature fails
  under v2 tags.
- **P2, node: portable admission via gossip.** Send-path fallback to the
  spend store + session caching. Protocol renames land here.
  Gate (rig, labtool): handshake at guard A; after one anti-entropy round,
  a session-signed drop is admitted at guard B with no handshake at B.
- **P3, node + labtool: client-carried ticket.** Handshake returns the
  ticket; `chat_presentSessionTicket`; labtool `auth` prints the ticket and
  gains `present-ticket`. Gate (rig): handshake at A, present at B before
  gossip could deliver, drop admitted at B; epoch spend count is still 1;
  a tampered ticket is refused.
- **P4, dotwave client.** Persist session per address (secure storage);
  `ensureSession` prefers the persisted session, presents the ticket on a
  session-store miss error, drops the -32003 patch. Gate (hardware): app
  restart sends anonymously with zero biometrics; switching the pinned
  guard sends anonymously; no cert-auth lines in any guard log.
- **P5, hardware E2E + land.** Handshake at guard 1; kill guard 1; send via
  guard 2 (ticket); restart app mid-epoch and send again; round-robin
  re-handshake still rejected; tampered ticket refused; equivocation tests
  unaffected. Then one coherent commit per side and merge both mainlines.

## 7. Out of scope (tracked)

- Fallback policy once the dev-cert scaffolding is culled (this work makes
  "no fallback" survivable; decide then).
- Proactive re-handshake at epoch rollover.
- Freshness-lapse lifecycle (deferred since the membership-client plan).
