# PQ Signatures & the Account Keyring

**Status:** design note. Phase 2 of the PQ program (docs/PQ-TRANSPORT.md
is Phase 1). NO code yet — this promotes the founding design thread of
2026-07-03 into a proper spec so the signature work has a written
starting point.

**One-line thesis:** a Rostro account is a *persistent identity* with a
*mutable, revocable set of signing keys*. Your account outlives every
cipher it has ever used. This note says how.

## Why this is Phase 2, not Phase 1

Transport (Phase 1) went first because the harvest-now-decrypt-later
clock is already running: an adversary records encrypted traffic today
and decrypts it at Q-day, so every byte sent before the hybrid handshake
lands is burned. Signatures have no such clock — a signature only needs
to be unforgeable *at the moment of spend*. What signatures need instead
is that the **enrollment** of a PQ key happen while classical signatures
are still trustworthy (see "The enrollment invariant" below). So Phase 2
can land later, but the *commitment* to a revocable key set should be
public now (it's in docs/WHITEPAPER-REWRITE-NOTES.md).

## What ships today

`substrate/utils/rostro-multi-key/` (`RostroSigner` / `RostroSignature`)
is the multi-*scheme* layer: one key, pick your curve. Variant order
mirrors substrate's `MultiSigner`/`MultiSignature` so the wire format is
Polkadot-compatible.

- **Sr25519** — raw 32-byte pubkey is the `AccountId32`. Byte-for-byte
  Polkadot parity: a DOT holder's account *is* their Rostro account.
- **Ed25519** — raw pubkey; source-matches Solana/Aptos/Sui/Cosmos/Ledger.
- **Ecdsa** — Ethereum-style (`last20(keccak256(uncompressed pk))`,
  zero-padded); a MetaMask `0x…` is the tail of the AccountId32.
- Signature side adds `EcdsaEip191` for MetaMask `personal_sign`.

This is "bring your own wallet." It is stateless: **the account IS the
key** — verification never touches storage, the address is derived from
the pubkey. That statelessness is exactly what Phase 2 changes.

Note: this is multi-*scheme* (one key, choose curve), distinct from
m-of-n multisig (`pallet-multisig`). This whole doc is about the former.

## The keyring overlay

Today authority is *derived*: `AccountId32 = f(pubkey)`, and only the
key that hashes to the address can spend. Phase 2 adds an **on-chain
keyring**: a map `AccountId32 → { authorized (scheme, pubkey) }` that,
**once populated, overrides the derived-key default.**

Design rules:

1. **Overlay, not replacement.** The derived key remains the default
   authority for every account with no keyring entry — which is 99% of
   accounts, forever. Zero new state for them, BYO-wallet flow
   unchanged. A keyring entry is opt-in and, once created, is the
   authority.
2. **Revocability is the whole point.** `pallet-proxy`-style delegation
   is *not enough*: the original key stays a root authority forever, so
   at Q-day the attacker just uses the original classical key. The
   classical key must be *removable* — authority has to be able to move
   out of the address derivation and into state.
3. **Stateful verification.** The signature check moves into the
   runtime's `Checkable` impl for `UncheckedExtrinsic`, where state is
   available — one storage read during `validate_transaction`, same cost
   class as the nonce check beside it. Upstream substrate would never
   accept stateful signature verification; we own the stack, so we can.

**Why the stable `AccountId32` matters beyond convenience:** PoP binding,
zkpki certs, chat-tree membership, RNS names, and reputation are all
keyed by account. A stable account under a rotating key set means the
*person* persists while key material has a lifecycle. For a
sovereign-identity chain that is the whole point, not a nice-to-have.

## Per-account policy

A keyring entry carries a policy field, present from day one even if the
wallet first exposes only `Either`:

- **`Either`** — any enrolled key may sign. The low-friction migration
  ramp.
- **`Both`** — hybrid AND: a classical + PQ signature both required.
  Protects against a quantum break (PQ leg holds) *and* against a
  cryptanalytic break of the young lattice scheme itself (classical leg
  holds). The **recommended transition default** once a PQ key is
  enrolled — same djb-hedging posture as the transport hybrid and the
  reason TLS shipped X25519+ML-KEM glued rather than ML-KEM alone.
- **`PQOnly`** — post-retirement; classical keys refused.

## The enrollment invariant (the part most projects miss)

An account holding `{classical, PQ}` under `Either` is exactly as
quantum-vulnerable as before (attacker uses the classical path) and
marginally *more* theft-exposed (two keys, either compromise loses the
account). So why enroll early?

**Because the enrollment itself is the security-critical event.** The
binding "this PQ key belongs to this account" is authenticated by a
*classical* signature, and that binding is only trustworthy while
classical signatures are unforgeable. After Q-day, a quantum attacker
can enroll *their* PQ key onto *your* account. Enrolling before Q-day is
the entire game; the `Either` window is just the ramp. Protection
arrives at retirement, not at enrollment — but retirement is only *safe*
because enrollment happened in time.

## The retirement endgame (and an honest open problem)

Rostro's raw-pubkey-as-address means every sr25519/ed25519 account's
public key is exposed on-chain *from the moment it receives funds* —
there is no Bitcoin-style hash shield (pubkey hidden until first spend).
So at Q-day, **every account that never enrolled a PQ key is
CRQC-spendable.**

Chain-wide classical retirement is a hard `set_code` cutover that makes
the classical signature variants fail verification with a clear error
(no grace window — consistent with the project's boundary discipline).
That **freezes** dormant classical-only accounts. Frozen beats stolen.

**OPEN QUESTION — what unfreezes them?** Candidates: SRT-gated recovery,
a ZK proof of preimage/seed knowledge, or nothing (frozen is final).
This does not need answering to start Phase 2, but it must be answered
before retirement is scheduled. Recorded, not resolved.

Interaction to note: the eth-derived accounts are currently the *only*
class with a pubkey-hash shield (H160 = hash of pubkey), so they behave
differently at Q-day. Mildly relevant to any future anonymity-set story.

## The PQ variant itself

- **Scheme: ML-DSA (Dilithium).** NIST primary, pure-integer (no Falcon
  floating-point signing hazards), most-audited constant-time code, the
  scheme HSM/secure-element vendors are committing silicon to. Falcon
  rejected (djb margin skepticism + FP signing); SPHINCS+ out on size
  (~8KB/sig). Kyber/ML-KEM was never a candidate — it's a KEM, it can't
  sign (it's the transport primitive, Phase 1).
- **Parameter set: ML-DSA-65 (category 3), exactly one, no menu.** Buys
  a category against the "NIST overstates the margin" critique for ~5.3KB
  sig+pk per tx — noise on a chain already moving certs and Groth16
  proofs. One frozen variant honors the append-only-enum scar (the
  multikey untag that caused the one sanctioned chain reset).
- **Address = hash(pubkey), pubkey rides in the signature.** ML-DSA
  pubkeys are ~1.3KB, too big to be the address; hashing gets the PQ
  class a pubkey shield for free — a pleasing symmetry with the classical
  side's lack of one.
- **Append-only, order frozen forever.** Any change to `RostroSignature`
  is a wire break. Additions only; the variant order never changes.

## Passkeys / WebAuthn (why the keyring dissolves the objection)

Device-bound passkeys live in a secure element and are non-exportable:
lose the device, lose the key — the stated objection. Synced passkeys
avoid that but put Google/Apple in custody of the key, which is
disqualifying as a *sole* key on a sovereignty chain.

The keyring answers both: **no single key is load-bearing.** A passkey
is enrolled as a *convenience* signer beside something recoverable
(paper-backed ed25519, or the device's StrongBox key). Lose the laptop,
sign with another enrolled key, revoke the lost passkey. The
PQ-migration machinery and the lost-device-recovery machinery are the
same pallet — which is the sign the abstraction is right. (Rostro already
leans on device-bound secure-element keys for StrongBox content keys and
TPM PoP, so this problem exists in the stack today regardless of
passkeys; the keyring is the answer there too.)

A WebAuthn signature variant is a foreign-envelope verifier like
`EcdsaEip191`, just with more parsing (the signature covers
`authenticatorData ‖ sha256(clientDataJSON)` with the tx challenge buried
in the clientDataJSON). Known quantity; done on other chains.

## Implementation sequence (when Phase 2 starts)

1. **Vendor ML-DSA-65 + NIST KATs.** RustCrypto `ml-dsa` (pure Rust,
   shares the `module-lattice` foundation the vendored `ml-kem` already
   pulls in) or PQClean bindings. Vendored = ours to own
   ([[feedback_sovereign_chain_vendored_is_ours]]). KATs live beside it
   like the ml-kem KATs in rostro-hybrid-kex.
2. **Host function BEFORE runtime — the trap.** ML-DSA verify is an
   sp_io-style host function (lattice verify in-RVM would be painful),
   which is consensus surface: a canonical-files/versioning event. It
   must ship in the **binary at rollout N**, and the runtime may
   reference it **only at set_code N+1**. A runtime that calls a host
   function the fleet's binaries don't export fails at upgrade. Two
   forkless events, strictly ordered — exactly the two paths proven on
   the cluster 2026-07-02.
3. **Keyring pallet + custom `Checkable` + append-only `MlDsa65`
   variant + policy field**, one runtime upgrade.
4. **dotwave enrollment UX** + typed subxt regen.
5. **Retirement machinery: deferred indefinitely** (the unfreeze policy
   above stays open).

All of this is forkless-deliverable post-genesis; nothing here blocks
Camino. The overlay design keeps the derived key as the default, so
migrated accounts are strictly opt-in.

## Cross-references

- docs/PQ-TRANSPORT.md — Phase 1, the transport hybrid (shipped P0-P2).
- docs/WHITEPAPER-REWRITE-NOTES.md — the public framing of the
  persistent-identity / revocable-key-set invariant.
- `substrate/utils/rostro-multi-key/` — the multi-scheme layer this
  extends.
