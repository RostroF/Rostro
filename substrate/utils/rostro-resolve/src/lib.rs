//! rostro-resolve — the identity-rails resolution core.
//!
//! Deterministic answer to one question: *given a device public key
//! presented by some peer, is it a valid witnessed keypair, and at what
//! assurance tier?* Implements `docs/ZKPKI-RESOLUTION.md` §4–§7; if this
//! crate and that document disagree, one of them has a bug and the fix
//! says which.
//!
//! I/O-free by design: chain-view providers fetch facts, protocol
//! adapters (TLS callbacks, RADIUS modules, OIDC bridges) gather
//! possession/HIP evidence, and this crate only judges. That keeps the
//! judgment embeddable anywhere — server SDK today, WASM verifier or
//! proving circuit later — and keeps the trust ladder additive: a
//! stronger provider changes where facts come from, never what they mean.
//!
//! Key derivation lives in `zk-pki-primitives`
//! ([`DevicePublicKey::lookup_hash`]) — never hash as-presented key bytes.
//!
//! [`DevicePublicKey::lookup_hash`]: zk_pki_primitives::crypto::DevicePublicKey::lookup_hash

use zk_pki_primitives::eku::Eku;
use zk_pki_primitives::runtime_api::{
    CertState, CertStatusResponse, EntityState, OcspStatus,
};
use zk_pki_primitives::tpm::AttestationType;

// ──────────────────────────────────────────────────────────────────────
// Chain view — how facts arrive (trust ladder, §7)
// ──────────────────────────────────────────────────────────────────────

/// How much the chain-view provider verifies of what it is told.
/// Deployments state their posture explicitly; the SDK never silently
/// upgrades or downgrades it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustTier {
    /// RPC to a node the verifier operates. Full-node security over a
    /// socket — the v0 posture. There is deliberately no default
    /// endpoint anywhere in this crate family.
    OwnNode,
    /// RPC plus Merkle state proofs and client-side finality checks.
    VerifyingRpc,
    /// PQ-finality light client — the security floor.
    Light,
}

/// Where a set of facts came from. Carried from v0 so stronger
/// providers slot in without changing the core's contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    /// Finalized block hash the facts were read at.
    pub finalized_hash: [u8; 32],
    /// Block number of that finalized head.
    pub block_number: u64,
    /// State proof backing the facts, when the provider tier supplies
    /// one (`VerifyingRpc` / `Light`). `None` under `OwnNode`.
    pub state_proof: Option<Vec<u8>>,
}

/// Facts for one resolved key: the status response plus where it came
/// from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedFacts<AccountId> {
    pub status: CertStatusResponse<AccountId>,
    pub provenance: Provenance,
}

/// A source of chain facts (§4 steps 1–2). Implementations: the RPC
/// provider (own-node), later the verifying-RPC and light-client
/// providers. Implementations MUST read at a finalized block.
pub trait ChainView<AccountId> {
    type Error;

    /// Steps 1–2: `cert_by_device_key(key_hash)` then
    /// `cert_status(thumbprint)`. `Ok(None)` when the key has no index
    /// entry or the record vanished between the two reads.
    fn resolve_device_key(
        &self,
        key_hash: [u8; 32],
    ) -> Result<Option<ResolvedFacts<AccountId>>, Self::Error>;

    /// Current finalized head `(block_number, block_hash)` — the "now"
    /// used by the expiry and staleness gates.
    fn finalized_head(&self) -> Result<(u64, [u8; 32]), Self::Error>;
}

// ──────────────────────────────────────────────────────────────────────
// Policy — verifier-local judgment (§6)
// ──────────────────────────────────────────────────────────────────────

/// Verifier policy. Local, never on-chain: the protocol carries facts,
/// the verifier owns judgment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy<AccountId> {
    /// Roots this verifier accepts as trust anchors. **Ships empty** —
    /// configuring trust is an explicit operator act, never a default.
    pub accepted_roots: Vec<AccountId>,
    /// Maximum age, in blocks, of the facts' `this_update` relative to
    /// the finalized head. Bounds revocation latency: finality lag +
    /// this budget is the quotable number.
    pub max_staleness: u64,
    /// Attestation types acceptable to this verifier.
    pub accepted_attestation_types: Vec<AttestationType>,
    /// Require the mint-time manufacturer-chain check to have passed.
    pub require_manufacturer_verified: bool,
    /// EKUs the cert must carry (all of them).
    pub required_ekus: Vec<Eku>,
    /// Minimum assurance tier the adapter must have evidenced.
    pub min_tier: AssuranceTier,
}

impl<AccountId> Default for Policy<AccountId> {
    /// Fails closed: no accepted roots. Hardware-attestation posture
    /// (`Tpm` only), 64-block staleness budget, tier 0.
    fn default() -> Self {
        Self {
            accepted_roots: Vec::new(),
            max_staleness: 64,
            accepted_attestation_types: vec![AttestationType::Tpm],
            require_manufacturer_verified: false,
            required_ekus: Vec::new(),
            min_tier: AssuranceTier::Witnessed,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// Evidence + tiers (§5)
// ──────────────────────────────────────────────────────────────────────

/// What the protocol adapter actually observed. The core never infers
/// evidence; it only grades what the transport proved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TierEvidence {
    /// Live proof of possession: TLS 1.3 CertificateVerify over the
    /// session, or a valid domain-separated presentation token bound
    /// to this context (see `zk_pki_primitives::presentation`).
    pub possession_proven: bool,
    /// Fresh HIP verified against the cert's genesis fingerprint
    /// within `MaxProofAge`. Only meaningful on top of possession.
    pub hip_fresh: bool,
}

/// Assurance tiers (§5). Ordering is meaningful: higher = stronger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AssuranceTier {
    /// Facts alone: genuine secure element held the key at mint,
    /// issuer vouched. Does NOT prove the presenting peer holds it now.
    Witnessed = 0,
    /// Plus live proof of possession.
    Possession = 1,
    /// Plus fresh HIP: measured boot unchanged since mint.
    FreshDevice = 2,
}

impl TierEvidence {
    /// Tier actually achieved. HIP without possession does not
    /// upgrade — a freshness proof means nothing about who is at the
    /// other end of *this* session.
    pub fn achieved_tier(self) -> AssuranceTier {
        match (self.possession_proven, self.hip_fresh) {
            (true, true) => AssuranceTier::FreshDevice,
            (true, false) => AssuranceTier::Possession,
            (false, _) => AssuranceTier::Witnessed,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// Verdict (§4 output)
// ──────────────────────────────────────────────────────────────────────

/// Why resolution failed. One vocabulary shared by the core (§4 gates
/// 3–6) and the providers/adapters (gates 1–2), so every rail reports
/// failures identically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidReason {
    /// Step 1: no index entry for the lookup hash.
    UnknownKey,
    /// Step 2: index pointed at a record that no longer exists.
    NoRecord,
    /// Step 3: cert is not Active (carries the state so the verifier
    /// can report *why* — Suspended vs Expired vs Purged).
    CertInactive(CertState),
    /// Step 3: expiry_block has passed at the finalized head.
    Expired,
    /// Step 4: issuer under challenge or compromised.
    IssuerNotActive(EntityState),
    /// Step 4: root under challenge or compromised.
    RootNotActive(EntityState),
    /// Step 5: root not in the verifier's accepted set.
    RootNotAccepted,
    /// Step 5: attestation type outside the accepted set.
    AttestationTypeRejected(AttestationType),
    /// Step 5: policy requires the manufacturer-chain check.
    ManufacturerUnverified,
    /// Step 5: a required EKU is missing.
    MissingEku(Eku),
    /// Step 6: facts older than the staleness budget.
    StaleFacts { age: u64, max: u64 },
    /// Evidence didn't reach the policy's minimum tier.
    TierBelowPolicy {
        achieved: AssuranceTier,
        required: AssuranceTier,
    },
}

/// Resolution output. No partial trust: any gate failing yields
/// `Invalid` with the first failing reason, in §4 gate order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict<AccountId> {
    Valid {
        thumbprint: [u8; 32],
        issuer: AccountId,
        root: AccountId,
        /// Tier actually achieved (≥ policy minimum). Never silently
        /// upgraded.
        tier: AssuranceTier,
    },
    Invalid(InvalidReason),
}

// ──────────────────────────────────────────────────────────────────────
// Resolution (§4 gates 3–6)
// ──────────────────────────────────────────────────────────────────────

/// Evaluate facts against policy at a finalized head. Gates run in
/// document order and the first failure wins, so a given (facts,
/// policy, head, evidence) tuple always produces the same verdict —
/// byte-determinism is what makes the semantics portable into proofs
/// later.
pub fn resolve<AccountId: PartialEq + Clone>(
    facts: &CertStatusResponse<AccountId>,
    evidence: TierEvidence,
    policy: &Policy<AccountId>,
    finalized_head: u64,
) -> Verdict<AccountId> {
    // Gate 3 — cert.
    if facts.status != OcspStatus::Good || facts.cert_state != CertState::Active {
        return Verdict::Invalid(InvalidReason::CertInactive(facts.cert_state.clone()));
    }
    if facts.expiry_block <= finalized_head {
        return Verdict::Invalid(InvalidReason::Expired);
    }

    // Gate 4 — chain.
    if facts.issuer_status != EntityState::Active {
        return Verdict::Invalid(InvalidReason::IssuerNotActive(facts.issuer_status.clone()));
    }
    if facts.root_status != EntityState::Active {
        return Verdict::Invalid(InvalidReason::RootNotActive(facts.root_status.clone()));
    }

    // Gate 5 — policy.
    if !policy.accepted_roots.contains(&facts.root) {
        return Verdict::Invalid(InvalidReason::RootNotAccepted);
    }
    if !policy
        .accepted_attestation_types
        .contains(&facts.attestation_type)
    {
        return Verdict::Invalid(InvalidReason::AttestationTypeRejected(
            facts.attestation_type.clone(),
        ));
    }
    if policy.require_manufacturer_verified && !facts.manufacturer_verified {
        return Verdict::Invalid(InvalidReason::ManufacturerUnverified);
    }
    for eku in &policy.required_ekus {
        if !facts.ekus.contains(eku) {
            return Verdict::Invalid(InvalidReason::MissingEku(eku.clone()));
        }
    }

    // Gate 6 — freshness.
    let age = finalized_head.saturating_sub(facts.this_update);
    if age > policy.max_staleness {
        return Verdict::Invalid(InvalidReason::StaleFacts {
            age,
            max: policy.max_staleness,
        });
    }

    // Tier.
    let achieved = evidence.achieved_tier();
    if achieved < policy.min_tier {
        return Verdict::Invalid(InvalidReason::TierBelowPolicy {
            achieved,
            required: policy.min_tier,
        });
    }

    Verdict::Valid {
        thumbprint: facts.thumbprint,
        issuer: facts.issuer.clone(),
        root: facts.root.clone(),
        tier: achieved,
    }
}

/// Full §4 pipeline over a chain view: locate (gate 1), fetch status
/// (gate 2), then [`resolve`] (gates 3–6). The convenience entry point
/// adapters call.
pub fn resolve_key<AccountId, V>(
    view: &V,
    key_hash: [u8; 32],
    evidence: TierEvidence,
    policy: &Policy<AccountId>,
) -> Result<Verdict<AccountId>, V::Error>
where
    AccountId: PartialEq + Clone,
    V: ChainView<AccountId>,
{
    let (head, _hash) = view.finalized_head()?;
    match view.resolve_device_key(key_hash)? {
        None => Ok(Verdict::Invalid(InvalidReason::UnknownKey)),
        Some(facts) => Ok(resolve(&facts.status, evidence, policy, head)),
    }
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use frame_support::BoundedVec;
    use zk_pki_primitives::runtime_api::RevocationReason;

    type AccountId = u64;
    const ISSUER: AccountId = 10;
    const ROOT: AccountId = 20;
    const HEAD: u64 = 1_000;

    fn good_facts() -> CertStatusResponse<AccountId> {
        CertStatusResponse {
            status: OcspStatus::Good,
            this_update: HEAD,
            next_update: HEAD + 64,
            revocation_time: None,
            revocation_reason: None,
            thumbprint: [0xAB; 32],
            cert_state: CertState::Active,
            expiry_block: HEAD + 10_000,
            mint_block: 1,
            issuer: ISSUER,
            issuer_status: EntityState::Active,
            issuer_compromised_at_block: None,
            root: ROOT,
            root_status: EntityState::Active,
            root_compromised_at_block: None,
            attestation_type: AttestationType::Tpm,
            manufacturer_verified: true,
            ek_hash: Some([0x11; 32]),
            template_name: BoundedVec::default(),
            template_pop_requirement: None,
            ekus: BoundedVec::try_from(vec![Eku::ClientAuth]).unwrap(),
        }
    }

    fn accepting_policy() -> Policy<AccountId> {
        Policy {
            accepted_roots: vec![ROOT],
            ..Policy::default()
        }
    }

    fn possession() -> TierEvidence {
        TierEvidence {
            possession_proven: true,
            hip_fresh: false,
        }
    }

    #[test]
    fn good_facts_resolve_valid_at_achieved_tier() {
        let v = resolve(&good_facts(), possession(), &accepting_policy(), HEAD);
        assert_eq!(
            v,
            Verdict::Valid {
                thumbprint: [0xAB; 32],
                issuer: ISSUER,
                root: ROOT,
                tier: AssuranceTier::Possession,
            }
        );
    }

    #[test]
    fn default_policy_fails_closed_on_empty_root_set() {
        let v = resolve(&good_facts(), possession(), &Policy::default(), HEAD);
        assert_eq!(v, Verdict::Invalid(InvalidReason::RootNotAccepted));
    }

    #[test]
    fn revoked_cert_reports_state() {
        let mut f = good_facts();
        f.status = OcspStatus::Revoked;
        f.cert_state = CertState::Suspended;
        f.revocation_reason = Some(RevocationReason::Suspended);
        let v = resolve(&f, possession(), &accepting_policy(), HEAD);
        assert_eq!(
            v,
            Verdict::Invalid(InvalidReason::CertInactive(CertState::Suspended))
        );
    }

    #[test]
    fn expiry_is_checked_against_finalized_head() {
        let mut f = good_facts();
        f.expiry_block = HEAD; // expires exactly at head → not valid
        let v = resolve(&f, possession(), &accepting_policy(), HEAD);
        assert_eq!(v, Verdict::Invalid(InvalidReason::Expired));
    }

    #[test]
    fn compromised_parent_fails_closed() {
        let mut f = good_facts();
        f.issuer_status = EntityState::Compromised;
        f.issuer_compromised_at_block = Some(HEAD - 5);
        let v = resolve(&f, possession(), &accepting_policy(), HEAD);
        assert!(matches!(
            v,
            Verdict::Invalid(InvalidReason::IssuerNotActive(_))
        ));

        let mut f = good_facts();
        f.root_status = EntityState::Challenge;
        let v = resolve(&f, possession(), &accepting_policy(), HEAD);
        assert!(matches!(v, Verdict::Invalid(InvalidReason::RootNotActive(_))));
    }

    #[test]
    fn attestation_type_and_manufacturer_gates() {
        let mut f = good_facts();
        f.attestation_type = AttestationType::Packed;
        let v = resolve(&f, possession(), &accepting_policy(), HEAD);
        assert_eq!(
            v,
            Verdict::Invalid(InvalidReason::AttestationTypeRejected(
                AttestationType::Packed
            ))
        );

        let mut f = good_facts();
        f.manufacturer_verified = false;
        let mut p = accepting_policy();
        p.require_manufacturer_verified = true;
        let v = resolve(&f, possession(), &p, HEAD);
        assert_eq!(v, Verdict::Invalid(InvalidReason::ManufacturerUnverified));
    }

    #[test]
    fn required_eku_must_be_present() {
        let mut p = accepting_policy();
        p.required_ekus = vec![Eku::ProofOfPersonhood];
        let v = resolve(&good_facts(), possession(), &p, HEAD);
        assert_eq!(
            v,
            Verdict::Invalid(InvalidReason::MissingEku(Eku::ProofOfPersonhood))
        );
    }

    #[test]
    fn stale_facts_rejected_by_budget() {
        let p = accepting_policy();
        let head_far_ahead = HEAD + p.max_staleness + 1;
        let v = resolve(&good_facts(), possession(), &p, head_far_ahead);
        assert_eq!(
            v,
            Verdict::Invalid(InvalidReason::StaleFacts {
                age: p.max_staleness + 1,
                max: p.max_staleness,
            })
        );
    }

    #[test]
    fn tier_grading_never_silently_upgrades() {
        // HIP without possession is still tier 0.
        let e = TierEvidence {
            possession_proven: false,
            hip_fresh: true,
        };
        assert_eq!(e.achieved_tier(), AssuranceTier::Witnessed);

        let mut p = accepting_policy();
        p.min_tier = AssuranceTier::Possession;
        let v = resolve(&good_facts(), e, &p, HEAD);
        assert_eq!(
            v,
            Verdict::Invalid(InvalidReason::TierBelowPolicy {
                achieved: AssuranceTier::Witnessed,
                required: AssuranceTier::Possession,
            })
        );

        let both = TierEvidence {
            possession_proven: true,
            hip_fresh: true,
        };
        assert_eq!(both.achieved_tier(), AssuranceTier::FreshDevice);
    }

    // ── resolve_key over a mock chain view ─────────────────────────

    struct MockView {
        facts: Option<ResolvedFacts<AccountId>>,
        head: u64,
    }

    impl ChainView<AccountId> for MockView {
        type Error = ();

        fn resolve_device_key(
            &self,
            _key_hash: [u8; 32],
        ) -> Result<Option<ResolvedFacts<AccountId>>, ()> {
            Ok(self.facts.clone())
        }

        fn finalized_head(&self) -> Result<(u64, [u8; 32]), ()> {
            Ok((self.head, [0x77; 32]))
        }
    }

    #[test]
    fn resolve_key_unknown_key_and_full_pipeline() {
        let empty = MockView {
            facts: None,
            head: HEAD,
        };
        assert_eq!(
            resolve_key(&empty, [0u8; 32], possession(), &accepting_policy()),
            Ok(Verdict::Invalid(InvalidReason::UnknownKey)),
        );

        let populated = MockView {
            facts: Some(ResolvedFacts {
                status: good_facts(),
                provenance: Provenance {
                    finalized_hash: [0x77; 32],
                    block_number: HEAD,
                    state_proof: None,
                },
            }),
            head: HEAD,
        };
        assert!(matches!(
            resolve_key(&populated, [0u8; 32], possession(), &accepting_policy()),
            Ok(Verdict::Valid { .. }),
        ));
    }
}
