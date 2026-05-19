# Rostro

**A sovereign blockchain where every actor is a verified human bound to
attested hardware. One certificate, one vote — anonymous by cryptography,
not by policy.**

*Rostro* means **face** in Spanish. The network sees the human face behind
every account without ever learning who you are.

---

*Draft v0.2 — May 2026. Authored as* prodigalwon *for the Rostro Foundation.
This document supersedes v0.1 (April 2026) and re-states the
network's vision and mission so future implementation work can be checked
against a stable north star.*

---

## I. Why this network exists

Public blockchains were supposed to give ordinary people sovereign tools —
money, identity, governance, communication — that no single party could
capture. By 2026, most of them have failed at that. The failure is not at
the cryptographic layer. The cryptography mostly works. The failure is in
the mechanism design layered above the cryptography, and in a quiet
willingness to ship governance and economic primitives that were never
honest about the threat model they would ultimately have to carry.

The failure mode is consistent across networks. A chain launches
permissionless, anchored to first principles. Stake or compute concentrates.
Token-weighted governance emerges. A small, persistent voting bloc — ten
people, fifty people, two hundred people — controls outcomes for a network
nominally serving hundreds of thousands of users. Treasury funds flow to
insiders. The proposals that would constrain the bloc quietly die.
Cryptographic exploits in production primitives — bridges, light-client
aggregation, on-chain verifiers — drain real money before the post-mortem
is even written. The retail user, who provided the liquidity that made
the network worth capturing in the first place, watches the value of
their position fall sixty, eighty, ninety percent and is told not to
worry, because a **real** product is just around the corner.

The new product is late. *Don't worry,* says the moderator, *it's coming
next month.* Six months go by. The dev team stops talking about it
because the news cycle now has a flashier, newer thing to ship. Meanwhile
the blocks are closing empty, and the only attractive ROI from the
outside is the staking-reward rate, propped up high against the rest of
the ecosystem. Meanwhile, barriers to entry for new developers are high
and mechanisms to deploy novel ideas are centralized. The entire economy
is extractive, and yet this experiment is built to block new investment
while diluting pre-existing assets to siphon off what is needed to pay
the bills and make payroll.

Meanwhile, the governance is captured. Acemoglu and Robinson, in *Why
Nations Fail*, observed that a captured governance system is very
difficult to un-capture once those who benefit from the capture already
control the mechanism. A fork going in a different direction becomes the
only constructive response.

A network reinventing itself as a solution to a problem nobody has is a
symptom of a failed experiment. A retirement of NPoS in favor of a mass
reduction in validators with zero sybil-resistance mechanism is a sign
of desperation. And a governance that announces a MITM purse for era
rewards as a feature — in its April 2026 runtime upgrade notes, framed
as preparation for JAM, with the private keys to that purse held by the
captured governance itself — is not hiding capture. It is normalizing
it, and counting on the base to applaud.

When critics asked in the forum *why did you skip testing this on
Kusama?* the response from accounts likely aligned with the captured 
governance was a procedural shrug: *you should've voted.* That is the 
answer of a bloc that already knows it can count to a majority. 
It is the closing line of a process that no longer functions as a process.

This network is captured. Its core developer already forked the code and
built a JAM that is faster than JAM could ever be. In fact it could run
JAM on top of it as an L1.

A few receipts, because vagueness is how this conversation usually dies:

- **ChaosDAO** controlled on the order of **14 million DOT** of voting
  power on Polkadot's OpenGov — concentrated, persistent, and structurally
  unaccountable to the broader holder base it was nominally representing.
  This is not an accusation of malice. It is a description of mechanism.
  One-token-one-vote at scale produces this. It will always produce this.
- The **BEEFY-on-Hyperbridge** light-client cross-chain construction
  permitted, in **April 2026**, the exfiltration of approximately
  **$237,000 USD** of user funds via a flaw in proof aggregation. The
  cryptography was sound on paper. The composition was not.
- **RFC-0162**, a Polkadot proposal that would have introduced concrete
  constraints on delegate concentration, sat unaddressed long enough that
  its continued non-addressment stopped reading as inaction and started
  reading as evidence — of who the existing mechanism actually serves.

A network whose governance can be captured by 14 million tokens is not a
public network. It is a private network that allows public deposits.

### A note from the author

I am not writing this as an external observer. I built real products on
Polkadot. I combined the inheritance from my late mother with my life
savings and staked them on the network. The collapse was not abstract;
it was the loss of money that took a decade of work and the death of a
parent to assemble. I submitted identity primitives — the ones now
implemented on this fork — to the Polkadot Technical Fellowship as a
way to put real transactions back on a ghost network. The reply was
silence. Not rejection. Silence. And silence is its own answer.

I had two options: get mad, throw a fit, and do nothing — or accept that
the primitives I had built solved real-world problems, and that the only
way forward was to fork the SDK the way Wei did.

Rostro is the constructive response that no longer requires anyone
else's permission to exist.

This is not a complaint document. The diagnosis is here because the design
choices in the rest of this whitepaper only make sense if you understand
what we are explicitly refusing to inherit. If you share my frustrations,
this is for you.

---

## II. Mission

**Rostro is the network where one human equals one vote — anonymously,
verifiably, and permanently.**

Three properties. Each non-negotiable. Each cryptographically enforced, not
politely requested.

### 1. One human, one vote

No actor appears on Rostro — voter, validator, governance candidate,
treasury beneficiary, operator, nominator, contract deployer — without
proving they are a unique human being bound to a single piece of attested
hardware. Personhood is a hardware-anchored proof rooted in a
machine-readable identity document and a continuously-attested secure
element. There is exactly one certificate per human. Re-mint requires
explicit discard of the prior cert; nobody can hold two at once.

Sybils cannot enter. Whales cannot multiply their voice. Captive delegates
cannot stack ballots.

### 2. Anonymous by cryptography, not by policy

The chain knows that you exist and is cryptographically certain that you
are a singular adult human resident of a particular country. It does not
know — and is structurally incapable of knowing — who you are, 
what your face looks like, when you registered, what eyeballs you have,
or what device you registered from. Your ballot on one referendum is not
linkable to your ballot on the next. Your participation in governance is
not linkable to your validator registration.

Privacy is a property of the proof system. It is not a promise on a
corporate website that survives only until subpoena.

### 3. Permanent

Mechanism choices that prevent capture in version 1 must continue to
prevent capture in version 100. Rostro reserves a category of constants —
hardware attestation requirement, one-cert-one-vote, anonymous-by-default
ballot proofs, no inflation-funded discretionary treasury, no
foundation-issued upfront grants — that the on-chain governance itself
cannot vote away. The history of governance is people voting away the
protections that brought them to power. We are not going to let that
happen here.

Everything else in this document is implementation in service of those
three.

---

## III. Vision

A working Rostro, five years in:

A retiree in Buenos Aires runs a Rostro node on a ~$1,200 commodity PC
under her desk. She earns the same per-validator reward as a data-center
operator running the same hardware spec. Same TPM 2.0 attestation
requirement. Same canonical binary. Same vote.

A teenager in Lagos votes on a constitutional amendment from a hardware-
attested mobile device. The chain has cryptographic certainty that her
ballot is one-of-one. It does not know her name. It does not know her age
beyond an adult-or-not bit. It cannot connect her vote on this referendum
to her vote on the last one.

A founder in Seoul launches a savings product as an operator-supplied
sandboxed shop inside the network. She does not bootstrap her own
consensus. She does not run her own validator set. She does not pay a
parachain auction. The shared infrastructure carries her — and her
customers' state is cryptographically isolated from every other shop,
every other operator, and the network itself. Plus, her customers can resolve
her via native web2 DNS.

A journalist in Istanbul sends an encrypted message to a colleague through
a chat fabric that lives inside the network's relay nodes. There is no
server. There is no log. There is no machine in the delivery path —
including the journalist's own gateway node — that can read the contents
or know who sent it. If a relay's binary is tampered with, that relay drops
out of the gossip mesh before it can carry a single byte.

A developer requests a grant for funding. "Give me money and I'll get Rostro's
logo on t-shirts!" he claims. Only the network explicitly prevents the oldest
contractor grift there is: no shipped code, no funding. If you ship code, and it doesn't
directly increase transactions on the network, don't expect to get a grant.
Grants are funded by shipped code that generates economic activity on the network.
While your idea might be great, if it doesn't generate activity, it's just a pipe dream.
Better luck on your next idea.

A ten-year-old runs an installer on a laptop and joins the network. The
binary refuses to be misconfigured. There is no manual to read first.

None of this requires asking permission. All of it is achievable. Most of
it is already in code.

---

## IV. What is already built

Rostro is not a thought experiment. As of May 2026, the network's
foundations are in implementation:

- **Hardware-anchored personhood.** The PoP pallet plus zero-knowledge
  circuits over Plonky3 — no trusted setup, post-quantum secure by
  construction. Cryptographically-authenticated proof of personhood
  without eyeball scans. Lose your phone, get a new cert. The chain
  learns *adult / not adult*. It learns nothing else.

- **Anonymous consensus.** Sassafras (Ring VRF) assigns block slots
  anonymously. No validator — not even the validator who holds the slot —
  knows in advance who will produce the next block. The deterministic-VRF
  collusion surface that exists on every BABE-class chain is closed by
  design. GRANDPA handles finality on top. Active-validator chatter is
  end-to-end encrypted and double-ratcheted, the same construction Signal
  uses. Validators see what they need to see for their session, and
  they're out.

- **Self-healing canonical binaries.** Every node runs a foundation-
  canonical binary enforced at boot via measured-boot hash check and at
  the network edge via peer-to-peer attestation. Drift triggers automatic
  heal: bytes-by-hash p2p fetch, atomic stage, exit-code swap-and-restart
  via a cross-platform supervisor. The Kusama-class *"validators forgot to
  upgrade"* failure mode is gone.

- **RostroVM.** The chain's runtime executor is RostroVM — Rostro's
  Apache-2.0 fork of PolkaVM, retargeted at RISC-V. No WebAssembly in
  the chain's trust boundary. The crypto and zero-knowledge
  verification workloads the chain actually runs — signature
  verification, hashing, STARK fold loops, post-quantum primitives —
  run **tens to hundreds of times faster** on RostroVM than on the
  WebAssembly or unmodified PolkaVM engines it replaces.

- **Strip-mall operator architecture.** Operators run the canonical
  Rostro binary (chain-side, RostroVM/RISC-V) alongside a separate
  sidecar process they own. The sidecar hosts the operator's shop —
  typically a WASM blob, but any sandbox the operator's runtime
  understands is fine — and submits transactions to the chain over IPC.
  Operator state is keyed by `(rns_name, operator_account_id)` so a
  lapsed name re-registration by someone else cannot grant access to
  the previous holder's state. The chain enforces the boundary; the
  operator owns the contents of the unit. Think of the network like a
  strip mall. The infrastructure is Rostro. The shop belongs to the
  node operator. No more Coretime, Relay Chain, Parachains.

- **Bicameral governance** *(designed; pallet not yet built)*. Upper
  house, Lower house. Both chambers must approve; either can block.
  Term limits. Staggered thirds. Money-out-of-politics enforced at the
  pallet level: transfers to and from candidate addresses are filtered
  during campaign windows, and the treasury is structurally forbidden
  from disbursing to candidates or sitting representatives. Bribing an
  official is encouraged. There is no way to determine how an official
  voted, so we encourage them to take your money and vote however they
  wanted to in private. We hope they laugh at you.

- **Milestone-first treasury.** No upfront grants. Ever. Working code,
  then payment. Funding decisions are ranked-choice and anonymous-by-
  construction, like every other governance act.

- **State rent and permissionless cleanup.** Every state-creating object
  carries a deposit and an expiration. Anyone can call the cleanup
  function on any expired object and collect the deposit residue. State
  growth is bounded by economic gravity rather than by privileged
  janitors.

- **Code-enforced operational invariants.** Rostro binaries refuse
  misconfiguration. A validator wired to expose unsafe RPC hard-rejects
  at boot. A non-validator whose key shows up in the active set crashes
  at the chain-state self-check before silent absence can harm finality.
  Polkadot prints warnings; Rostro refuses.

- **Subtract by default.** Rostro is a hard fork of the Polkadot SDK with
  the relay chain, parachain framework, bridges, and EVM-compatibility
  surfaces removed. What remains is the Substrate framework, FRAME, and
  the consensus and client primitives needed for a sovereign chain —
  nothing more. The architectural rationale for each cull lives in the
  project's commit history and is publicly auditable.

The technical detail for each of the above lives in the [README](../README.md)
and the per-pallet specifications. This document does not repeat them.
This document fixes *why* they exist.

---

## V. What we refuse to compromise

The following are constitutional, in the engineering sense: they sit at a
layer that on-chain governance cannot reach.

- **A hardware floor for every actor.** Voter, validator, nominator,
  candidate, operator, contract deployer. There is no second-class
  anonymous economic role. There is no "lite" certificate. The network
  is a network of verified humans end-to-end. The narrow argument that
  sybil-splitting does not change total bond is true but insufficient —
  legibility matters, and a network that cannot tell whether its N
  nominators are one person or N people is not the network we are
  building.

- **Stewards of the network.** Inspired by Simon Sinek. Governance
  members are stewards of the network. They understand that the network
  may not always be the flashiest or the most in demand. They are
  playing the infinite game — their goal is to steward the network, to
  protect it and keep it safe for the next generation. This is the core
  tenet of governance.

- **Security Response Team.** A group of highly skilled individuals
  responsible for patching the network and detecting CVEs. They operate
  publicly and answer to the people. Their own votes are handled by
  multisig. Their charter dictates that they are stewards of the
  network, entrusted to protect it from harm.

- **One cert, one vote.** Token weight is the disease. We are not
  treating the disease with a slightly milder strain of the disease. A
  whale who has bonded a million RST gets exactly one governance vote.
  Staking is economic; voting is by cert. These are separate axes. The
  Citizens-United critique applies to governance and is solved at the
  cert layer. No money in politics.

- **No inflation-funded discretionary treasury.** The treasury is funded
  by a percentage of transaction fees. Not by minting new RST on
  demand. The discipline this imposes is the point. If the network no 
  longer has a reason to exist, it dies. It does not exist to extract 
  from humans.

- **No foundation slush fund.** The Foundation holds approximately none 
of the operational decision-making. Treasury disbursement is governed by 
the bicameral chambers, not by a discretionary multisig.

- **A fee burn rate that is constitutionally non-zero.** Governance can
  raise it. It cannot set it to zero. The supply-side mechanism that
  protects token holders from unbounded inflation cannot be voted away
  by the people most positioned to benefit from voting it away.

- **No upgradeable hardware attestation requirement.** Future hardware
  vendors can be added to the whitelist by governance, with a delay
  window between vendor publication and chain acceptance. The
  *requirement itself* — that personhood is hardware-anchored — is not
  on the governance agenda.

- **Anonymity as a cryptographic property, not a policy.** Ballot
  privacy is a property of the proof system. Sender anonymity in the
  chat layer is a property of Sealed Sender plus the relay topology.
  Neither depends on operator goodwill or jurisdictional law.

- **A patent license that binds to the canonical chain, not to forks.**
  The patent covering the hardware-anchored personhood layer is
  personally held by the author and licensed to the
  Rostro Foundation's canonical chain. A captured hard fork does not
  inherit the license. This is a deliberate choice, not an oversight.

If a future governance vote attempts to compromise any of the above, the
chain refuses the call at the runtime layer. The constitution lives in
code.

---

## VI. What this is not

To save the reader time:

- **Not a token launch.** RST exists to pay for compute, secure
  consensus, and gate governance participation alongside the cert. We are
  not running a points program, a meme cycle, or a vibes-based pre-sale.
- **Not a privacy chain in the Zcash/Monero sense.** Account-level
  privacy is not the headline feature. Identity-level privacy is. You
  cannot pseudonymously run multiple accounts; you can pseudonymously
  *use* your single account.
- **Not a parachain framework.** Rostro is one sovereign chain. The
  strip-mall model gives operators application-layer sovereignty
  (sandboxed shops with isolated state) without giving them their own
  consensus, their own validator set, or their own auction queue.
- **Not Polkadot with better marketing.** Rostro forks the Polkadot SDK
  because the SDK is engineering work worth inheriting. The governance
  model, the relay/parachain split, the token-weighted voting, the
  upfront-grant treasury — all removed.
- **Not anti-Polkadot.** The diagnosis in Section I is specific because
  vagueness wastes time. Anyone working on similar problems in the
  Polkadot orbit is welcome to talk. The code is open. The disagreement
  is about mechanism.

---

## VII. Roadmap

**Camino testnet → Canaria canary → Rostro mainnet.**

Camino is the public testnet — value-free, fast iteration, breaking
changes expected. Canaria is the canary network — real RST, real
slashing, faster release cycle than mainnet, breaks first when something
is going to break. Rostro is the production mainnet.

Pre-launch items, in no order:

- **Security Response Team bootstrap.** Threshold-signing ceremony, named
  members, public charter. The SRT gates the on-chain reserved-name list,
  bug-bounty payouts, and emergency patches.
- **RNS seed-list ratification.** The initial reserved-name list (entity
  names, government bodies, well-known organizations) needs a public
  ratification mechanism before genesis so the network does not begin
  life with a foundation-controlled namespace.
- **Verifying-key trusted-setup ceremony for the personhood circuits.**
  Multi-party computation, public participation, transparent transcript.
  Plonky3 reduces but does not eliminate ceremony requirements at the
  pallet boundary.
- **Bicameral governance bootstrap.** The first upper house is sourced
  from the genesis passport bundle; the first lower house requires
  initial cert holders sufficient to seat it. The path from "five test
  nodes" to "first seated chamber" is a sequence of testnet phases.
- **Genesis account snapshot.** SS58 addresses that held DOT during
  defined snapshot windows will be accounted for at genesis. If you held
  DOT and watched it collapse, your address will be in the genesis
  state.

Active engineering phases as of May 2026: PoP zero-knowledge circuit
implementation (Plonky3 AIRs for the Curve25519 / Edwards25519 stack
landed and under audit), the WASM→RVM runtime executor swap
("Phase Star"), and the second-generation chat layer (MLS-based, end-to-
end demo achieved May 17, 2026).

---

## VIII. Closing

The reason this work continues is not the engineering. The engineering is
hard but tractable. The reason this work continues is that the alternative
— a generation of public networks captured by the people best positioned
to capture them, with the retail participants who funded that capture left
holding the loss — is not acceptable.

We do not need to ask anyone's permission to build a different network. We
are building it.

If you are an engineer who has shipped real cryptographic work, a
mechanism designer who has watched governance fail and wants to design
something better, a policy thinker who can read a threat model, or a
civic-technologist who is tired of watching the same failure modes recur
under new branding — there is work to do here.

If you are a holder who was burned by the last cycle of capture and you
want to see the next protocol built without those failure modes — your
address will be in our genesis state.

If you are looking for a place to deploy capital with the expectation of
extracting it from a captive user base — this is not the network.

The face behind every account is human. The chain knows that, and only
that. One certificate. One vote. Anonymous by cryptography. Permanent by
design.

This is the network we are building. We are not going to lose sight of
why.

---

*— prodigalwon*
*Rostro Foundation*
*May 2026*

---

## Pointers

- Code, license posture, and architectural detail: [README.md](../README.md)
- Attribution and patent notice: [NOTICE.md](../NOTICE.md)
- Security disclosure: [SECURITY.md](../SECURITY.md)
- Contribution flow: [CONTRIBUTING.md](../CONTRIBUTING.md)
- Project home: rostro.org
- Personal: substrate.icu
