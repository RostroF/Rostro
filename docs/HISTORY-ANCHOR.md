# History Anchor — dual-hash sealing + head publication

Status: pallet + verifier + star proof landed (`a83485f391`, spec 104).
This document freezes the **publication payload format (v1)** and defines
the publication ritual and the century capsule. Publication cadence and
write-once channel selection are OPEN DECISIONS (marked below).

## 1. One-paragraph recap

`pallet-rostro-history-anchor` folds each session's final header into a
running Keccak-512 chain at the next session's first block, verified
in-runtime against `parent_hash` while BLAKE2-256 is sound ("bind while
fresh"). The fold is keyless and offline-recomputable from raw headers
(`rostro-history-anchor-verify`). Consequence: a future forger with a
structural BLAKE2 break can also recompute a valid-looking Keccak chain
over forged headers. What defeats him is **possession of authentic head
values recorded at the time**. The scheme is therefore complete only if
at least one authentic head survives outside the chain, somewhere he
cannot rewrite. That is what publication is for. Security composes as an
OR across channels: one surviving authentic copy, with checkable
provenance, defeats the forgery.

## 2. Publication payload — FORMAT v1 (FROZEN)

Plain UTF-8 text, LF line endings, exact field order, one trailing
newline. No JSON, no encoding cleverness: this must be trivially
readable, printable, and re-typeable in 2076.

```
ROSTRO HISTORY ANCHOR PUBLICATION v1
genesis: 0x<32-byte chain genesis hash, lowercase hex>
spec-name: <runtime spec name>
runtime-spec: <spec_version at verification time>
era: <era index of the tip anchor>
sealed-height: <block height of the tip anchor's sealed header>
head: 0x<64-byte anchor head, lowercase hex>
previous-publication: 0x<32-byte sha-256 of the previous payload> | none
```

- **publication-hash** = SHA-256 over the exact payload bytes. It is not
  part of the payload; it is what the *next* publication references.
  SHA-256 chosen for the chaining hash on universality grounds: it is
  the digest most likely to have a running implementation within reach
  of anyone, anywhere, decades out.
- `previous-publication` chains publications into their own
  tamper-evident sequence; a forged or missing intermediate is
  detectable from any later publication.
- The SRT threshold signature is computed over the exact payload bytes.
  Signature format rides the SRT's standing scheme and is carried
  alongside the payload, never inside it.

`rostro-history-anchor-verify publication [--prev 0x…]` emits this
payload **only after a full verification pass succeeds** (exit 1
otherwise), and prints the publication-hash to stderr.

## 3. The ritual

1. Run `rostro-history-anchor-verify --url <node>` against a node you
   operate. Require exit 0.
2. Run `… publication --prev <hash of last publication>` and capture the
   payload.
3. SRT threshold-signs the payload bytes.
4. Publish payload + signature to every standing channel (§4).
5. Record the publication-hash where the next ritual will find it.

Boring and deterministic is the point. A skipped or irregular ritual is
itself a signal.

## 4. Channels

Heterogeneous failure domains, cheapest first:

| channel | class | status |
|---|---|---|
| rostro.org page | continuous, revocable | standing (copy TBD, goes through the user) |
| signed git tag on the public repo | continuous, distributed | standing |
| Internet Archive snapshot of the site page | institutional | standing |
| newspaper of record (print notice) | **write-once** | OPEN DECISION |
| external chain anchor (e.g. OpenTimestamps → Bitcoin: third hash family SHA-256d + foreign proof-of-work) | **write-once** | OPEN DECISION (sovereignty judgment: writes Rostro's name in someone else's ledger) |
| dotwave herd witness (every wallet caches `Anchored` heads) | population-scale | P4 dotwave-side, pending |

Cadence: OPEN DECISION. Continuous channels can track every session;
the ritual channels want a fixed rhythm (monthly/quarterly). Even yearly
suffices; regularity matters more than frequency.

## 5. Century capsule

`rostro-history-anchor-verify capsule --out <dir> [--prev 0x…]` exports,
after a full verification pass:

- `README.md` — the fold, restated in prose + pseudocode simple enough
  to reimplement in ~50 lines of any future language, with verification
  instructions that assume no Rostro software exists.
- `headers.jsonl` — one line per sealed header: height + raw SCALE hex.
- `anchors.jsonl` — one line per anchor: era, sealed height, head.
- `publication.txt` — the v1 payload for the capsule tip.

`verify-capsule --dir <dir>` re-verifies a capsule fully offline (no
RPC, no node): recompute the fold from `headers.jsonl`, compare every
anchor, print the tip head. A capsule in a safe plus any one published
head is a complete, software-independent proof of history.

Offline scope, stated honestly: the capsule proves the sealed headers
chain correctly under Keccak-512 and match the anchors. Binding those
headers to *the* canonical chain is the published head's job (and, for
full-block context, any surviving archive's).

## 6. Remaining work — runbook

What exists: pallet + node wiring (spec 104), verifier with
`publication`/`capsule`/`verify-capsule`, star-proven E2E, this format
spec. What remains, in order:

1. **Three standing decisions** (blocking nothing until the first
   ritual, but decide before mainnet genesis):
   - Publication cadence (monthly/quarterly; regularity > frequency).
   - Print channel: yes/no, and which newspaper of record.
   - External-chain anchoring (OpenTimestamps → Bitcoin): pure
     cryptographic win (third hash family + foreign PoW), but writes
     Rostro's name in someone else's ledger. Sovereignty judgment.
2. **First publication bootstrap.** After the next fresh genesis
   carrying spec ≥104 (the PQ-finality reset genesis is the expected
   vehicle): run `rostro-history-anchor-verify` (exit 0 required), then
   `… publication` with NO `--prev` (the only publication ever allowed
   to omit it), sign, publish to the standing channels, and record the
   publication-hash where the next ritual will find it (suggested: a
   `HISTORY-ANCHOR-PUBLICATIONS.log` in the repo, one payload+hash per
   entry, appended by each ritual).
3. **Signed git tag convention.** `anchor-pub-<era>` on the repo,
   tagging the commit that appends to the publications log.
4. **rostro.org page.** Copy is drafted in conversation BEFORE touching
   `site/` (standing rule), then published + Internet Archive snapshot
   taken as part of each ritual.
5. **SRT threshold signing.** The payload is signed off-chain by the
   SRT's standing scheme once SRT tooling lands (on-chain origins are
   still EnsureRoot stubs; publication signing does not depend on
   them). Until then, publications ride maintainer signatures —
   explicitly interim, say so on the page.
6. **dotwave herd witness.** Wallet-side: record `Anchored` events
   (era, sealed height, head) into local storage; sparse historical
   retention (all heads is fine: 64 B + metadata per session). Read the
   dotwave memory notes before touching chain paths (typed subxt macro,
   not dynamic). Optional later: cross-check on wallet restore, a
   diagnostics screen.
7. **Capsule habit.** Export a century capsule at every ritual
   (`capsule --out … --prev …`), store offline alongside the
   publication record.
8. **Lab/testnet adoption.** Spec 104 rides the next lab-cluster
   genesis (PQ reset) or a `set_code`; the pallet self-activates
   mid-chain (seals immediately, `LastSealedEra = None` rule). Run the
   verifier against the cluster afterwards as the acceptance check.

## 7. Verifying from scratch in 2076

Given: a capsule (or raw headers from any archive) + one published head
with provenance (a print notice, an external-chain anchor, a signed tag).

1. `head₀ = keccak_512("rostro-history-anchor-v0")`
2. For each sealed header in era order: `headᵢ₊₁ = keccak_512(headᵢ ||
   raw_header_bytes)`
3. Some `headᵢ` must equal the published head, byte for byte.
4. Anything a header commits to (state roots above all) is then bound
   under two unrelated hash families as of the publication's date.

A forger must instead produce different bytes that thread the same
needle, which requires simultaneous structural breaks of BLAKE2-256 and
Keccak-512, *and* the suppression of every surviving authentic head.
