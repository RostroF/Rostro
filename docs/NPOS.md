# NPoS — pallet-staking wiring (spec 106)

Upstream-vanilla Nominated Proof-of-Stake on the gemini runtime. Before this,
the validator set was locked at genesis: whoever was in the genesis session
set stayed in the active set forever (KeyLineage re-fed a frozen roster).
Now pallet-staking's election produces the set each era, and block production
follows it.

## Shape

- **pallet-staking** (modern holds-based Config; `Currency = Balances` via
  `RuntimeHoldReason`) with the **on-chain sequential-phragmen** election
  provider (`frame_election_provider_support::onchain::OnChainExecution`),
  both per-era and at genesis. This fork culled
  `election-provider-multi-phase`; `election-provider-multi-block` remains
  in-tree as the scale-up path if on-chain solving ever outgrows the block
  budget.
- **Voter/target lists** are staking's own unsorted maps
  (`UseNominatorsAndValidatorsMap` / `UseValidatorsMap`) — no bags-list
  pallet at testnet scale.
- **Eras**: `SessionsPerEra = 6` sessions of one sassafras epoch each
  (~1h at 600 six-second slots) → ~6h eras. `BondingDuration = 28` eras
  (~7 days), `SlashDeferDuration = 27`.
- **Rewards**: standard inflation curve (2.5% floor, 10% at the 50% ideal
  staking rate) via `ConvertCurve`; the non-staker remainder **burns** (no
  treasury yet). Era reward points: 20/block to the author, credited to the
  real stash via `FindAccountFromAuthorIndex` (sassafras exposes the slot
  claim's `authority_idx`; session maps index → validator account). RNS'
  author fee share now lands on the same real account.
- **Slashing**: offences (GRANDPA equivocation, retired-key canary) fan out
  from pallet-offences to BOTH sinks — staking (slash by fraction, era
  accounting, in-session disabling via `SessionInterface` +
  `UpToLimitWithReEnablingDisablingStrategy`) and KeyLineage
  (disable-and-record, heal on fresh key). GRANDPA reports pass through
  `FilterHistoricalOffences` so pre-bonding-window reports are discarded
  politely. Slashed funds burn.

## Sassafras is session-driven now

Upstream never wrote pallet-sassafras's session integration; this fork adds
the BABE-patterned impls (`OneSessionHandler`, `ShouldEndSession`,
`EstimateNextSessionRotation`, `FindAuthor<u32>`) and flips the runtime to
`EpochChangeExternalTrigger`:

- **Sessions ARE sassafras epochs.** The epoch arithmetic is slot-based and
  fixed-length (exactly like BABE), so sassafras decides when sessions end;
  a block-counting `PeriodicSessions` would desync on missed slots.
- The bandersnatch key joined `SessionKeys` (`{ sassafras, grandpa }`), so
  `set_keys` takes a two-signature proof-of-possession tuple (field order).
  Elected validators' sassafras keys activate at the next epoch enactment;
  the ring verifier is rebuilt on authority change.
- Genesis authorities flow through session genesis for BOTH keys now
  (`sassafras.authorities` left empty in chain specs — the staking genesis
  election's order is canonical; `on_genesis_session` initializes the pallet
  and derives the ring verifier).
- Ordering invariants, encoded as comments in `construct_runtime!`:
  Sassafras before Session (slot freshness for `ShouldEndSession`), Balances
  before Staking (genesis bonding), Staking before Session (genesis election
  runs inside session's genesis build).

## The era-boundary ring-verifier rebuild (and why it runs in-VM)

Enacting a *changed* authority set rebuilds the sassafras ring-VRF verifier
key — BLS12-381 MSMs over the KZG URS plus piop bookkeeping. On the plain
RVM interpreter (hard-pinned by the Cannae threat model) that build measured
**~4.8s against a ~4s block-proposal deadline**: the first block after an
era election that changes the set could NEVER be sealed — every validator
builds it, blows the deadline, discards, and retries the same rotation next
slot. A permanent livelock, observed live TWICE on the join scenario (the
original run froze at the era-1 boundary for 24+ minutes; the ring-ab
control run reproduced it on the intrinsics-bearing VM with the hooks
bypassed). Rejected alternatives: ring-domain right-sizing (512 → 64 bought
only ~1.7x — cost is domain-overhead-dominated) and a scheme-shaped
`ring_ops` host function (shipped briefly on this branch, then removed —
it froze the whole bandersnatch ring-VRF construction into the node's host
ABI).

Fix: the build runs **in-VM on the hooked curve stack**. The pallet's
`update_ring_verifier` is upstream-shaped (`ring_ctx.verifier_key(&pks)`);
underneath, the vendored ark-vrf's curve configs route every heavy group op
(MSM via the Montgomery-limb intrinsics, Miller loop, final exponentiation)
through `RostroCurveHooks` to native intrinsics in the RVM. Live-proven on
this scenario: boundary blocks seal at full slot cadence (fixture-measured
build ~98ms, 2.8x native — the residual is non-MSM piop bookkeeping that
stays interpreted). Consequences:

- The node pins no VRF scheme: its native surface is curve primitives
  (reserved-index ecalli intrinsics), and rostro-executor registers the
  intrinsic import stubs on every instantiation path — including chain-spec
  genesis builds, where session genesis derives the ring verifier the same
  way. A runtime importing an intrinsic an old node lacks fails loudly at
  instantiation (node before runtime, never a silent fallback).
- Key count barely matters to the MSM cost, so this is already
  ≥700-validator-ready; the RING_SIZE=512 URS ceiling is the binding
  constraint, unchanged.
- The rebuild only fires when the elected set actually changes (mid-era
  sessions re-feed an identical set → `next_authorities == authorities` →
  no rebuild), so steady-state blocks are untouched.

## Roster delivery: KeyLineage stays in the loop

`SessionManager = NoteHistoricalRoot<Runtime, KeyLineage>` is unchanged.
KeyLineage's Config gained `ElectedSet = Staking`: staking elects, KeyLineage
filters (offence-disabled + rotation-deadline-missed excluded), lineage
records, historical notes the root. On `None` sessions (mid-era) KeyLineage
re-feeds its `PlannedSet` — the last election result — so enforcement runs
every session and healed validators re-enter mid-era. The frozen `Roster`
storage and root-only `force_roster` bootstrap are culled (the rotation-probe
subcommand went with them). See docs/CONSENSUS-KEY-LIFECYCLE.md §3.0.1.

## Genesis

`testnet_genesis` (dev/local/star specs): every authority is a self-bonded
validator — `stakers: [(stash, stash, 250_000 ROS, Validator)]`,
`validatorCount = authorities.len()`, `minimumValidatorCount = 1`, no
invulnerables (real slashing on the testbed; KeyLineage's liveness floor is
the empty-set backstop). Session keys carry both public keys per validator.

## Wire/genesis break

`SessionKeys` layout, the set_keys proof format, and the construct_runtime
order all changed: spec 106 lands via **chain reset** (rides the queued
testnet reset), not `set_code`. Lab-fast (`lab-fast-lifecycle`) compresses
the epoch length to 25 slots, so sessions AND eras (150 blocks) are
scenario-observable; the feature no longer patches a separate SessionPeriod.

## Deliberately not wired (yet)

nomination-pools, fast-unstake, bags-list, delegated-staking, im-online,
authority-discovery, staking runtime API, treasury (reward remainder +
slashes burn until one exists). Validator gating by PoP/hardware/track record
(the low-barrier north star) composes later — staking is the economic leg
only.
