# Account Keyring — revocable multi-key authority (spec 107)

**Status:** in build (worktree `/home/coder/Rostro-keyring/`, branch
`keyring-v0`). Implements the Stage B keyring overlay from
[PQ-SIGNATURES.md](PQ-SIGNATURES.md), classical-schemes-only: no ML-DSA,
no new host function, so the whole feature is **one pure `set_code`**
(spec 106 → 107). The `EcdsaP256` signature variant (fbb7f1456d) rides
the same upgrade.

## One-line thesis

An account is a persistent identity with a mutable, revocable set of
signing keys. The keyring is the on-chain map that makes the set real:
`AccountId32 → { authorized (scheme, pubkey) }`, consulted during
extrinsic signature verification.

## Semantics (locked 2026-07-12)

The founding use case: a user mints their account with a 25519 root key
(mnemonic today, Ledger later), then appends a P-256 device key
(StrongBox/TPM) as a **convenience signer**. Either key can be
rescinded; at least one authority must always remain.

- **No keyring entry (99% of accounts, forever):** verification is the
  stateless derived-key default, unchanged. Zero new state.
- **Entry exists:** a signature is valid if it verifies against the
  derived key (unless derived authority is rescinded) OR against any
  enrolled key. Scheme is taken from the signature variant; the enrolled
  key supplies the pubkey, replacing the address-derivation binding.
- **Derived authority is a flag, not a list entry.** The raw-pubkey
  namespace is shared between sr25519 and ed25519, so "the derived key"
  is not a single `(scheme, pubkey)` pair; rescinding it must kill both
  derived paths at once. Hence `derived_rescinded: bool` on the entry.
  This deliberately softens PQ-SIGNATURES.md's "once populated,
  overrides" rule: implicit derived authority survives population until
  *explicitly* rescinded. Rationale: the strict-override rule creates a
  brick window (first enroll of only a device key would instantly
  disinherit the root) and an auto-enroll of the root is impossible
  (scheme ambiguity above). Revocability — the Q-day requirement — is
  fully preserved: `rescind_derived` removes classical root authority.
- **At-least-one invariant:** `rescind_key` refuses to empty the key
  list while derived authority is rescinded; `rescind_derived` requires
  a non-empty key list. An entry whose key list empties while derived
  authority is active is deleted outright (account returns to the
  stateless default, state refunded).
- **Proof of possession at enroll:** the candidate key must sign
  `SCALE(("rostro:keyring:enroll:v1", genesis_hash, account))`. Blocks
  enrolling a key you don't hold (griefing + future rogue-key hazard for
  the `Both` policy). Replay is inert: cross-chain blocked by genesis
  hash, cross-account by the account, same-account re-submission still
  requires the account's own authority plus the tx nonce.
- **Policy field present from day one** (`Either` / `Both` / `PqOnly`,
  wire-frozen) but only `Either` is constructible: there is no
  `set_policy` call yet, and verification implements only `Either`.
  `Both` needs a dual-signature envelope that doesn't exist; `PqOnly`
  needs a PQ scheme. Both arrive with the ML-DSA phase.

## Components

1. **`rostro-multi-key`: `RostroSignature::verify_against(payload,
   &RostroSigner)`** — verify against an explicitly supplied key rather
   than the address. Scheme-matched pairs only; secp256k1 arms recover
   the compressed pubkey and compare; the P-256 arm requires carried
   pubkey == enrolled pubkey plus the same low-s discipline as the
   derived path.
2. **`pallet-rostro-keyring`** (`substrate/frame/rostro-keyring/`).
   Storage: `Keyring: AccountId32 → KeyringEntry { keys:
   BoundedVec<RostroSigner, MaxKeys=5>, policy, derived_rescinded }`.
   Calls: `enroll_key(key, pop)`, `rescind_key(key)`,
   `rescind_derived()`, `restore_derived()`. Config pins
   `AccountId = AccountId32` — the pallet's whole subject is AccountId32
   derivation semantics.
3. **Stateful verification glue** (`substrate/runtime/gemini/src/
   keyring_signature.rs`): newtype `KeyringSignature(RostroSignature)`,
   SCALE-transparent, whose `Verify` impl calls
   `Pallet::verify_extrinsic_signature`. Wired as the `Signature` type
   parameter of `UncheckedExtrinsic` only; the `Signature` alias used by
   pallet-level stateless verification (bilateral-receipt etc.) stays
   `RostroSignature`. One storage read per tx validation, same cost
   class as the nonce check. Upstream substrate would never take
   stateful signature verification; we own the stack.

## Wire + deployment notes

- `KeyringSignature` is a single-field newtype: SCALE encoding of signed
  extrinsics is **byte-identical** to today. Existing wallets/txs are
  untouched; dotwave regen picks up the new type name in metadata.
- Pallet appended at the END of `construct_runtime` (positional
  indices, live runtime). No transaction_version bump: append-only.
- spec_version 106 → 107. Note fbb7f1456d added the `EcdsaP256` variant
  without a bump; this upgrade carries it.
- Pool-time vs apply-time drift (key rescinded while a tx signed by it
  sits in the pool) resolves exactly like a nonce race: re-check at
  apply fails, tx dropped.

## Weights

Placeholder constant weights, matching the current codebase posture.
Per-scheme verify cost (the NPoS gas-battery input) differs by variant;
real benchmarks land with the fee workstream. Verification itself adds
one `Keyring` read per signed extrinsic.

## dotwave sequence (after chain side proves out)

Enrollment UX: root account runs the StrongBox PoP ceremony
(SHA256withECDSA over the enroll challenge — matches `verify_against`'s
sha256 prehash convention), submits `enroll_key`, then P-256 becomes the
default signer for everyday txs. DER→r‖s conversion + low-s
normalization in rust_core. Typed metadata regen against spec 107.

## Cross-references

- [PQ-SIGNATURES.md](PQ-SIGNATURES.md) — the design note this implements
  (Stage B); ML-DSA/policy endgame lives there.
- `substrate/utils/rostro-multi-key/` — scheme layer + both verify entry
  points.
- fbb7f1456d — `EcdsaP256` signature variant (same set_code).
