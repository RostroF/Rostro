#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;
pub mod mime_wrap;
pub mod weights;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

#[frame_support::pallet]
pub mod pallet {
    use frame_support::{
        pallet_prelude::*,
        traits::{
            fungible::{Inspect as FungibleInspect, MutateHold},
            tokens::{Fortitude, Precision, Restriction},
            Currency, ExistenceRequirement, FindAuthor, ReservableCurrency,
        },
        BoundedVec,
    };
    use frame_system::pallet_prelude::*;
    use sp_runtime::traits::{UniqueSaturatedFrom, UniqueSaturatedInto, Zero};
    use sp_runtime::Saturating;
    use zk_pki_primitives::{
        bounds::{
            ABSOLUTE_MAX_ISSUERS_PER_ROOT, MAX_ATTESTATION_LEN, MAX_METADATA_LEN,
            MAX_SUSPENSION_REASON_LEN,
        },
        cert::{CertCanonical, CertState, SchemaVersion, Thumbprint, CURRENT_SCHEMA_VERSION},
        contract::ContractOffer,
        crypto::DevicePublicKey,
        ek::EkHash,
        eku::Eku,
        hip::{
            CanonicalHipProof, GenesisHardwareFingerprint, HipPlatform,
            StrongBoxGenesisFingerprint, Tpm2GenesisFingerprint,
        },
        pop::{derive_pop_nonce, PopAssertion},
        proxy::ValidateProxy,
        issuer::{
            DeregistrationRecord, EntityState, IssuerRecord, RootRecord, MAX_CAPABILITY_EKUS,
        },
        keys::{IssuerUserKey, UserIssuerKey},
        template::{
            CertTemplate, PopMechanism, PopRequirement, MAX_TEMPLATE_EKUS,
            MAX_TEMPLATE_METADATA_SCHEMA_LEN, MAX_TEMPLATE_NAME_LEN,
        },
        tpm::AttestationType,
        traits::AttestationVerifier,
    };
    use zk_pki_tpm::{AttestationPayloadV3, BindingProofVerifier};
    use rostro_membership_tree::{
        empty_leaf, empty_root, empty_roots, update as smt_update, NodeStore,
        CAPACITY as MEMBERSHIP_CAPACITY,
    };
    use rostro_poseidon_bn254::{
        fr_from_canonical_bytes_le, fr_to_bytes_le, hash_leaf, params as poseidon_params,
        PoseidonField as MembershipFr,
    };
    // Bring the `WeightInfo` trait into scope so every extrinsic's
    // `#[pallet::weight(T::WeightInfo::foo())]` resolves.
    use crate::weights::WeightInfo as _;

    /// Balance type shorthand.
    pub type BalanceOf<T> =
        <<T as Config>::Currency as frame_support::traits::Currency<
            <T as frame_system::Config>::AccountId,
        >>::Balance;

    /// Maximum number of blocks the `push_to_*_index` helpers will
    /// look ahead when the intended slot's 256-entry `BoundedVec` is
    /// full. Distributes same-expiry-block pressure across up to
    /// `MAX_PURGE_LOOKAHEAD` blocks before giving up and skipping the
    /// schedule (in which case a `PurgeScheduleSkipped` event fires
    /// and the caller's extrinsic still succeeds — the cert is not
    /// lost, just not auto-purged).
    pub const MAX_PURGE_LOOKAHEAD: u32 = 10;

    // ---------------------------------------------------------------------------
    // Config
    // ---------------------------------------------------------------------------

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// Number of blocks equal to 30 days at this chain's block time.
        /// Post-expiry grace period during which the holder can
        /// self-discard and recover their deposit. After it elapses,
        /// the cert becomes reapable via `cleanup()` by anyone.
        #[pallet::constant]
        type InactivePurgePeriod: Get<BlockNumberFor<Self>>;

        /// Number of blocks a contract offer remains valid after creation.
        #[pallet::constant]
        type ContractOfferTtlBlocks: Get<BlockNumberFor<Self>>;

        /// Maximum number of blocks for a root cert TTL (5 years).
        #[pallet::constant]
        type MaxRootTtlBlocks: Get<BlockNumberFor<Self>>;

        /// Maximum issuers per root. Must not exceed `ABSOLUTE_MAX_ISSUERS_PER_ROOT` (100).
        #[pallet::constant]
        type MaxIssuersPerRoot: Get<u32>;

        /// Number of blocks for the challenge contest window (45 days).
        #[pallet::constant]
        type ChallengeWindowBlocks: Get<BlockNumberFor<Self>>;

        /// Storage deposit for a cert. Covers both the hot and cold
        /// record rows combined — the pallet reserves `CertDeposit`
        /// once per cert at mint and releases it once at purge.
        #[pallet::constant]
        type CertDeposit: Get<BalanceOf<Self>>;

        /// Storage deposit amount for a contract offer.
        #[pallet::constant]
        type OfferDeposit: Get<BalanceOf<Self>>;

        /// Minimum TTL for root certs at renewal (~90 days). Prevents rapid renewal storage bloat.
        #[pallet::constant]
        type MinRootTtlBlocks: Get<BlockNumberFor<Self>>;

        /// Minimum TTL for issuer certs at renewal (~30 days). Prevents rapid renewal storage bloat.
        #[pallet::constant]
        type MinIssuerTtlBlocks: Get<BlockNumberFor<Self>>;

        /// How often relying parties should re-query `cert_status`
        /// (surfaced as the `next_update - this_update` delta in
        /// every OCSP-style response). A reasonable default is ~1 day
        /// worth of blocks.
        #[pallet::constant]
        type TtlCheckInterval: Get<BlockNumberFor<Self>>;

        /// Runtime's aggregated hold-reason type. Auto-generated by
        /// `#[runtime::derive(RuntimeHoldReason)]` in the runtime's
        /// construct_runtime; `From<HoldReason>` lets this pallet
        /// push its own variant onto the combined type.
        type RuntimeHoldReason: From<HoldReason>;

        /// Currency for storage deposits AND fee distribution. Must
        /// implement both the legacy `Currency + ReservableCurrency`
        /// API (for free-balance reads, transfers, and any remaining
        /// unreserve paths) AND the fungible `MutateHold + Inspect`
        /// API (for the `CertDeposit` hold + fee distribution at
        /// mint_cert).
        type Currency: Currency<Self::AccountId>
            + ReservableCurrency<Self::AccountId>
            + FungibleInspect<Self::AccountId>
            + MutateHold<
                Self::AccountId,
                Reason = Self::RuntimeHoldReason,
                Balance = BalanceOf<Self>,
            >;

        /// Block author resolver — used at mint_cert to route the
        /// capped tip to the current block creator. Wire to
        /// `pallet_authorship::Pallet<Runtime>` in production; `()`
        /// works for test harnesses (returns None → no tip paid).
        type FindAuthor: FindAuthor<Self::AccountId>;

        /// SS58 of the protocol maintainer — receives the protocol
        /// fee cut (10% by default) and any remainder left after
        /// the block-author tip cap.
        #[pallet::constant]
        type ProtocolFeeRecipient: Get<Self::AccountId>;

        /// Protocol fee in basis points of the mint fee. Default
        /// `1_000` = 10%.
        #[pallet::constant]
        type ProtocolFeeBasisPoints: Get<u32>;

        /// Block creator tip cap in basis points. Default `4_000`
        /// = 40% of the mint fee.
        #[pallet::constant]
        type BlockCreatorCapBasisPoints: Get<u32>;

        /// Deposit in basis points of the mint fee. Default `500`
        /// = 5%. `max(deposit_pct, MinDeposit)` is the actual held
        /// amount.
        #[pallet::constant]
        type DepositBasisPoints: Get<u32>;

        /// Floor for the held cert deposit regardless of mint-fee
        /// percentage.
        #[pallet::constant]
        type MinDeposit: Get<BalanceOf<Self>>;

        /// Mint fee for Tpm certs carrying the `ProofOfPersonhood`
        /// EKU. Lowest tier — PoP certs are the flagship use case.
        #[pallet::constant]
        type MintFeePoP: Get<BalanceOf<Self>>;

        /// Mint fee for certs with Tpm attestation minus PoP EKU,
        /// and all Packed-attestation certs.
        #[pallet::constant]
        type MintFeePacked: Get<BalanceOf<Self>>;

        /// Mint fee for certs with no hardware attestation at all.
        /// Highest tier — reflects lowest trust.
        #[pallet::constant]
        type MintFeeNone: Get<BalanceOf<Self>>;

        /// TPM attestation verifier. Validates attestation blobs, extracts EK hashes.
        /// Use `NoopAttestationVerifier` for testnet, `TpmAttestationVerifier` for production.
        ///
        /// **Used by `register_root` and `issue_issuer_cert`** — the
        /// pre-TODO-3 single-chain attestation path. The end-user
        /// flow (`mint_cert`) uses the TODO-3 payload verifier
        /// configured below instead.
        type Attestation: zk_pki_primitives::traits::AttestationVerifier<Error = sp_runtime::DispatchError>;

        /// TODO-3 binding-proof verifier. Used by `mint_cert` to
        /// verify the two-chain attestation payload + HMAC binding +
        /// integrity attestation in one call.
        ///
        /// Production runtimes should wire
        /// `zk_pki_tpm::ProductionBindingProofVerifier`; test
        /// runtimes can wire a mock from
        /// `zk_pki_tpm::test_mock_verifier` (requires the
        /// `test-utils` feature on `zk-pki-tpm`) to bypass crypto
        /// checks and focus on exercising pallet storage logic.
        type BindingProofVerifier: zk_pki_tpm::BindingProofVerifier;

        /// Proxy-relationship validator. `register_root` and
        /// `issue_issuer_cert` reject if `has_proxy(who, proxy)`
        /// returns false. Production runtimes bind a
        /// `pallet_proxy`-reading impl (see
        /// `zk-pki-runtime/src/proxy_validator.rs`); the
        /// integration-test runtime binds
        /// [`zk_pki_primitives::proxy::NoopProxyValidator`] so the
        /// existing test corpus continues to pass without wiring
        /// real proxy records for every fixture.
        type ProxyValidator:
            zk_pki_primitives::proxy::ValidateProxy<Self::AccountId>;

        /// Weight cost table for pallet extrinsics. Production
        /// runtimes bind `crate::weights::SubstrateWeight<Runtime>`
        /// (placeholder values today; replace with benchmark-CLI
        /// output before Kusama). The integration-test runtime
        /// binds `crate::weights::UnitTestWeight` so weight changes
        /// don't perturb test outcomes.
        type WeightInfo: crate::weights::WeightInfo;

        /// Storage deposit reserved from an issuer when they create a
        /// cert template. Held until the template is discarded; then
        /// released back to the issuer.
        #[pallet::constant]
        type TemplateDeposit: Get<BalanceOf<Self>>;

        /// Upper bound on how many templates a single issuer may hold
        /// concurrently (active + deactivated, not yet discarded).
        /// The `IssuerTemplateNames` bounded vector width is fixed at
        /// 256 in storage; this constant can be set to any value ≤ 256.
        #[pallet::constant]
        type MaxTemplatesPerIssuer: Get<u32>;
    }

    // ---------------------------------------------------------------------------
    // Storage
    // ---------------------------------------------------------------------------

    /// Hot cert record lookup: Thumbprint → CertRecordHot.
    /// The small, always-read projection — state, chain addresses,
    /// expiry, attestation type, EK, template. Every validity check
    /// and common RPC response reads only this row.
    #[pallet::storage]
    #[pallet::getter(fn cert_hot_by_thumbprint)]
    pub type CertLookupHot<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        Thumbprint,
        CertRecordHot<T::AccountId, BlockNumberFor<T>>,
        OptionQuery,
    >;

    /// Cold cert record lookup: Thumbprint → CertRecordCold.
    /// Deep verification / audit fields — device pubkey, suspension
    /// metadata, attestation-captured OS state, immutable issuer
    /// metadata. Read only by successor signature verification,
    /// non-repudiation queries, or long-tail audit paths.
    #[pallet::storage]
    pub type CertLookupCold<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        Thumbprint,
        CertRecordCold<BlockNumberFor<T>, BalanceOf<T>>,
        OptionQuery,
    >;

    /// Expiry schedule: block_number → thumbprints that expire at that
    /// block. Written at mint; taken-and-processed by `on_initialize`
    /// in O(1) at each block.
    #[pallet::storage]
    pub type ExpiryIndex<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        BlockNumberFor<T>,
        BoundedVec<Thumbprint, ConstU32<256>>,
        ValueQuery,
    >;

    /// Secondary index: Issuer → Thumbprint. Used by `certs_by_issuer`
    /// runtime API; prefix iteration is naturally paginated by the
    /// storage trie.
    #[pallet::storage]
    pub type CertsByIssuer<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        Blake2_128Concat,
        Thumbprint,
        (),
        OptionQuery,
    >;

    /// Secondary index: User → Thumbprint.
    #[pallet::storage]
    pub type CertsByUser<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        Blake2_128Concat,
        Thumbprint,
        (),
        OptionQuery,
    >;

    /// Secondary index: Root → Thumbprint.
    #[pallet::storage]
    pub type CertsByRoot<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        Blake2_128Concat,
        Thumbprint,
        (),
        OptionQuery,
    >;

    /// EK registry — root-scoped dedup: `(root, ek_hash) → active
    /// Thumbprint`. EK deduplication is per root trust hierarchy;
    /// different roots are independent trust domains and may
    /// independently certify the same physical device. Within a
    /// single root's hierarchy, a device with an existing active
    /// PoP cert cannot mint a second PoP cert — reissuance is
    /// required. This preserves Sybil resistance within each
    /// domain while allowing real-world institutions to
    /// independently certify the same user on the same hardware.
    #[pallet::storage]
    pub type EkRegistry<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat, T::AccountId,
        Blake2_128Concat, EkHash,
        Thumbprint,
        OptionQuery,
    >;

    // -----------------------------------------------------------------------
    // Chat anonymous-membership tree (depth-32 sparse Poseidon SMT).
    // Storage adapter over `rostro-membership-tree`; the math lives there,
    // the persisted state lives here. Leaves are inserted at mint and cleared
    // on revoke/expiry (wired into the mint / remove paths in a later step).
    // See DOTWAVE-CHAT-ANON-MEMBERSHIP-AUTH-DECISIONS D5/D6.
    // -----------------------------------------------------------------------

    /// Domain `scope` committed into every membership leaf, defining the
    /// anonymity set. One broad scope gives the largest set / best privacy
    /// (decisions OQ4). A constant for now; promote to a Config item only if
    /// per-runtime scoping is ever needed.
    const MEMBERSHIP_SCOPE: u64 = 1;

    /// Recent-root ring depth: how many superseded roots stay acceptable so a
    /// proof built just before a root change still verifies.
    const MEMBERSHIP_ROOT_HISTORY: u32 = 128;

    /// Sparse occupied tree nodes: `(level, index)` → 32-byte field element.
    /// A missing entry is the empty-subtree root for that level.
    #[pallet::storage]
    pub type MembershipNodes<T: Config> =
        StorageMap<_, Blake2_128Concat, (u8, u64), [u8; 32], OptionQuery>;

    /// Current membership root (canonical 32-byte field element). `None`
    /// before the first leaf — readers fall back to the empty-tree root.
    #[pallet::storage]
    pub type MembershipRoot<T: Config> = StorageValue<_, [u8; 32], OptionQuery>;

    /// Next never-used leaf index (the high-water mark).
    #[pallet::storage]
    pub type MembershipNextIndex<T: Config> = StorageValue<_, u64, ValueQuery>;

    /// Free-list stack of reusable slots: stack position → leaf index.
    #[pallet::storage]
    pub type MembershipFreeSlots<T: Config> =
        StorageMap<_, Blake2_128Concat, u32, u64, OptionQuery>;

    /// Number of entries currently on the free-list stack.
    #[pallet::storage]
    pub type MembershipFreeCount<T: Config> = StorageValue<_, u32, ValueQuery>;

    /// Ring of recent roots (newest last), bounded at [`MEMBERSHIP_ROOT_HISTORY`].
    #[pallet::storage]
    pub type MembershipRootHistory<T: Config> =
        StorageValue<_, BoundedVec<[u8; 32], ConstU32<MEMBERSHIP_ROOT_HISTORY>>, ValueQuery>;

    /// Binds the membership tree's [`NodeStore`] to pallet storage. Stored
    /// nodes are always written canonically, so the read back never fails the
    /// canonical decode.
    pub struct MembershipNodeStore<T>(core::marker::PhantomData<T>);

    impl<T: Config> NodeStore for MembershipNodeStore<T> {
        fn get(&self, level: u8, index: u64) -> Option<MembershipFr> {
            MembershipNodes::<T>::get((level, index)).and_then(|b| fr_from_canonical_bytes_le(&b))
        }
        fn set(&mut self, level: u8, index: u64, value: MembershipFr) {
            MembershipNodes::<T>::insert((level, index), fr_to_bytes_le(&value));
        }
        fn clear(&mut self, level: u8, index: u64) {
            MembershipNodes::<T>::remove((level, index));
        }
    }

    impl<T: Config> Pallet<T> {
        /// The leaf value for a cert: `H(id_commitment, expiry_block, scope)`.
        /// `expiry_block` is the cert's TTL deadline; `scope` is the constant
        /// anonymity-set domain. Freshness is committed separately (D6).
        pub fn membership_leaf_value(
            id_commitment: MembershipFr,
            expiry_block: BlockNumberFor<T>,
        ) -> MembershipFr {
            let params = poseidon_params();
            let expiry: u64 = expiry_block.unique_saturated_into();
            hash_leaf(
                &params,
                id_commitment,
                MembershipFr::from(expiry),
                MembershipFr::from(MEMBERSHIP_SCOPE),
            )
        }

        /// Insert `leaf`, returning its index, or `None` if the tree is full.
        pub fn membership_insert(leaf: MembershipFr) -> Option<u64> {
            let params = poseidon_params();
            let empties = empty_roots(&params);
            let index = Self::membership_alloc_slot()?;
            let mut store = MembershipNodeStore::<T>(core::marker::PhantomData);
            let root = smt_update(&mut store, &params, &empties, index, leaf);
            Self::membership_commit_root(fr_to_bytes_le(&root));
            Some(index)
        }

        /// Clear the leaf at `index`, returning the slot to the free-list.
        pub fn membership_remove(index: u64) {
            let params = poseidon_params();
            let empties = empty_roots(&params);
            let mut store = MembershipNodeStore::<T>(core::marker::PhantomData);
            let root = smt_update(&mut store, &params, &empties, index, empty_leaf());
            Self::membership_free_slot(index);
            Self::membership_commit_root(fr_to_bytes_le(&root));
        }

        /// The current membership root, or the empty-tree root before any leaf.
        pub fn membership_root() -> [u8; 32] {
            MembershipRoot::<T>::get().unwrap_or_else(|| {
                let params = poseidon_params();
                fr_to_bytes_le(&empty_root(&params))
            })
        }

        /// Whether `root` is the current root or within the recent-root ring.
        pub fn membership_root_recent(root: &[u8; 32]) -> bool {
            if Self::membership_root() == *root {
                return true;
            }
            MembershipRootHistory::<T>::get().iter().any(|r| r == root)
        }

        /// Reserve a leaf index, reusing a freed slot before advancing the
        /// high-water mark.
        fn membership_alloc_slot() -> Option<u64> {
            let count = MembershipFreeCount::<T>::get();
            if count > 0 {
                let pos = count - 1;
                if let Some(slot) = MembershipFreeSlots::<T>::take(pos) {
                    MembershipFreeCount::<T>::put(pos);
                    return Some(slot);
                }
            }
            let next = MembershipNextIndex::<T>::get();
            if next >= MEMBERSHIP_CAPACITY {
                return None;
            }
            MembershipNextIndex::<T>::put(next + 1);
            Some(next)
        }

        /// Return a slot to the free-list stack.
        fn membership_free_slot(index: u64) {
            let count = MembershipFreeCount::<T>::get();
            MembershipFreeSlots::<T>::insert(count, index);
            MembershipFreeCount::<T>::put(count + 1);
        }

        /// Persist a new root and append it to the recent-root ring (evicting
        /// the oldest when full; a repeated root is not duplicated).
        fn membership_commit_root(root: [u8; 32]) {
            MembershipRoot::<T>::put(root);
            MembershipRootHistory::<T>::mutate(|h| {
                if h.last() == Some(&root) {
                    return;
                }
                if h.len() as u32 >= MEMBERSHIP_ROOT_HISTORY {
                    let _ = h.remove(0);
                }
                let _ = h.try_push(root);
            });
        }
    }

    /// Registered roots: AccountId → RootRecord.
    #[pallet::storage]
    #[pallet::getter(fn root_record)]
    pub type Roots<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        RootRecord<T::AccountId, BlockNumberFor<T>>,
        OptionQuery,
    >;

    /// Registered issuers: AccountId → IssuerRecord.
    #[pallet::storage]
    #[pallet::getter(fn issuer_record)]
    pub type Issuers<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        IssuerRecord<T::AccountId, BlockNumberFor<T>>,
        OptionQuery,
    >;

    /// Root → issuers secondary index. Maintained at issue_issuer_cert and
    /// invalidate_issuer/deregister_root. Replaces unbounded Issuers::iter() scan.
    #[pallet::storage]
    pub type RootIssuers<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        BoundedVec<T::AccountId, T::MaxIssuersPerRoot>,
        ValueQuery,
    >;

    /// Deregistered roots: AccountId → DeregistrationRecord.
    /// Append-only, never pruned. Tainted flag is write-once.
    #[pallet::storage]
    pub type DeregisteredRoots<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        DeregistrationRecord<BlockNumberFor<T>>,
        OptionQuery,
    >;

    /// Issuer count per root. Decremented on invalidation/deregistration.
    #[pallet::storage]
    pub type IssuerCountPerRoot<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, u32, ValueQuery>;

    /// Open contract offers: nonce → ContractOffer.
    #[pallet::storage]
    #[pallet::getter(fn contract_offer)]
    pub type ContractOffers<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        [u8; 32],
        ContractOffer<T::AccountId, BlockNumberFor<T>, BalanceOf<T>>,
        OptionQuery,
    >;

    /// Reverse index: (issuer, user) → nonce. One active offer per pair.
    #[pallet::storage]
    pub type OfferIndex<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        IssuerUserKey<T::AccountId>,
        [u8; 32],
        OptionQuery,
    >;

    /// One active cert per user address per issuer.
    #[pallet::storage]
    pub type UserIssuerIndex<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        UserIssuerKey<T::AccountId>,
        Thumbprint,
        OptionQuery,
    >;

    /// Purge schedule: block_number → thumbprints that become
    /// deposit-reapable at that block. Populated by `on_initialize`
    /// when a cert's expiry rolls over, and by `suspend_cert` when
    /// an issuer suspends. Taken-and-processed by `on_initialize`.
    ///
    /// # Overflow behavior — distributed scheduling
    ///
    /// Each per-block slot holds at most 256 entries. When
    /// `push_to_purge_index` or `push_to_expiry_index` finds the
    /// intended slot full, the entry is redirected to the next
    /// available block within a `MAX_PURGE_LOOKAHEAD`-block window
    /// (see the const at the top of this module). If every slot in
    /// the window is saturated — unlikely in practice but possible
    /// under a targeted griefing campaign — the entry is skipped, a
    /// `PurgeScheduleSkipped` event fires as an observability
    /// signal, and the caller's extrinsic still succeeds. The cert
    /// is recoverable via `self_discard_cert` (holder-initiated) or
    /// `cleanup()` (permissionless, once past the grace period).
    #[pallet::storage]
    pub type PurgeIndex<T: Config> = StorageMap<
        _,
        Twox64Concat,
        BlockNumberFor<T>,
        BoundedVec<Thumbprint, ConstU32<256>>,
        ValueQuery,
    >;

    /// Secondary offer expiry index: expiry_block → nonces.
    #[pallet::storage]
    pub type OfferExpiryIndex<T: Config> = StorageMap<
        _,
        Twox64Concat,
        BlockNumberFor<T>,
        BoundedVec<[u8; 32], ConstU32<256>>,
        ValueQuery,
    >;

    /// Primary template index: (issuer, name) → CertTemplate.
    /// Templates are scoped to the issuer's SS58 namespace — the
    /// same name from two different issuers is two different
    /// templates.
    #[pallet::storage]
    pub type CertTemplates<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        Blake2_128Concat,
        BoundedVec<u8, ConstU32<MAX_TEMPLATE_NAME_LEN>>,
        CertTemplate<T::AccountId, BlockNumberFor<T>, BalanceOf<T>>,
        OptionQuery,
    >;

    /// Secondary index: issuer → template names. Enforces the
    /// `MaxTemplatesPerIssuer` bound. The inner bounded vec is sized
    /// to the absolute ceiling (256); runtimes can set the Config
    /// constant lower.
    #[pallet::storage]
    pub type IssuerTemplateNames<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        BoundedVec<BoundedVec<u8, ConstU32<MAX_TEMPLATE_NAME_LEN>>, ConstU32<256>>,
        ValueQuery,
    >;

    /// Active-cert counter per template: (issuer, name) → count of
    /// certs currently in storage that were minted under this
    /// template. Incremented at `mint_cert`, decremented when a cert
    /// leaves storage (expiry+purge, invalidate, self-discard,
    /// cleanup, reissue-replace, deregister-cascade). Discard safety
    /// is `counter == 0`, O(1) — no `CertsByIssuer` scan.
    #[pallet::storage]
    pub type TemplateActiveCertCount<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        Blake2_128Concat,
        BoundedVec<u8, ConstU32<MAX_TEMPLATE_NAME_LEN>>,
        u32,
        ValueQuery,
    >;

    // ── Mime-wrap PoP storage (Android StrongBox tier, schema v3+) ──
    //
    // Three maps keep the mime-wrap surface isolated from the rest of
    // pki's storage. Cold-tier conceptually — touched only at sign
    // time. Standalone maps (rather than fields on `CertRecordCold`)
    // because the verifier needs only `commitment_c` (32 bytes) and
    // not the rest of the Cold record; loading the full Cold row on
    // every sign-time verify would be overhead for no benefit.

    /// Per-cert mime-wrap binding pair: `(commitment_c, ec_key_pub)`.
    /// Populated only at `mint_cert` time when the cert's template
    /// carries `pop_mechanism == Some(PopMechanism::MimeWrap)`.
    /// `None` for every other cert. Removed alongside the cert's
    /// other rows in `remove_cert_entry`.
    ///
    /// `ec_key_pub` is stored explicitly — not derived at sign time —
    /// because (a) deriving it at every verify would re-canonicalize
    /// the device pubkey on every PoP assertion (overhead), and
    /// (b) storing it makes the equality tripwire's result the
    /// authoritative bytes the verifier consumes. Paseo phase
    /// (option B) re-derives it at MINT time from
    /// `cert.cold.cert_ec_pubkey` and asserts equality with the
    /// caller-supplied value before storing; mainnet phase (option A)
    /// will derive only.
    #[pallet::storage]
    pub type MimeWrapCommitments<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        Thumbprint,
        ([u8; 32], [u8; 32]),
        OptionQuery,
    >;

    /// Replay registry for mime-wrap PoP. Keyed `(bucket, nonce)`.
    /// Inserted by `verify_pop_assertion` on the MimeWrap path; a
    /// repeat presentation of the same pair is rejected with
    /// `MimeWrapReplayRejected`. Pruning (`on_idle`) is a follow-up;
    /// for now the map grows monotonically.
    ///
    /// Per-cert keying was considered and rejected — 32-byte random
    /// nonces make cross-cert collision negligible (2^-256 in a
    /// single bucket), so widening the key to `(thumbprint, bucket,
    /// nonce)` would be storage cost without security gain.
    #[pallet::storage]
    pub type ConsumedMimeWrapNonces<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        (u64, [u8; 32]),
        (),
        OptionQuery,
    >;

    /// Mime-wrap circuit Verifying Key, installed via
    /// `set_mime_wrap_vk`. Singleton — every MimeWrap cert today
    /// uses the same circuit. Per-template VK is a future change if
    /// the circuit ever forks (`MimeWrapVks: (issuer, template_name)
    /// → VkBytes`); migration is straightforward at that point.
    ///
    /// Bound is slack relative to the observed ~19 KB compressed VK
    /// for the current circuit.
    #[pallet::storage]
    pub type MimeWrapVk<T: Config> = StorageValue<
        _,
        BoundedVec<u8, ConstU32<MAX_MIME_WRAP_VK_BYTES>>,
        OptionQuery,
    >;

    /// Hard cap on stored mime-wrap VK bytes. Enforced at
    /// `set_mime_wrap_vk` decode time.
    pub const MAX_MIME_WRAP_VK_BYTES: u32 = 32_768;

    // ---------------------------------------------------------------------------
    // Events
    // ---------------------------------------------------------------------------

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        RootRegistered { root: T::AccountId },
        RootDeregistered { root: T::AccountId },
        IssuerCertIssued { root: T::AccountId, issuer: T::AccountId, thumbprint: Thumbprint },
        ContractOffered { issuer: T::AccountId, user: T::AccountId, nonce: [u8; 32], expiry_block: BlockNumberFor<T> },
        ContractReplaced { issuer: T::AccountId, user: T::AccountId, old_nonce: [u8; 32], new_nonce: [u8; 32] },
        CertMinted { thumbprint: Thumbprint, user: T::AccountId, issuer: T::AccountId },
        CertSuspended { thumbprint: Thumbprint, issuer: T::AccountId },
        CertReactivated { thumbprint: Thumbprint, issuer: T::AccountId },
        CertInvalidated { thumbprint: Thumbprint },
        CertPurged { thumbprint: Thumbprint, deposit_claimed_by: T::AccountId },
        CertReissued { old_thumbprint: Thumbprint, new_thumbprint: Thumbprint, issuer: T::AccountId },
        CertSelfDiscarded { thumbprint: Thumbprint, holder: T::AccountId },
        /// Emitted when `self_discard_cert` is called without a
        /// `PopAssertion` — i.e. the recovery path. The caller
        /// proved SS58 ownership but not hardware control, so this
        /// event is visible signal for the reputation scoring
        /// off-chain worker. Losing a device is a normal life event
        /// and one recovery discard is not a negative signal on its
        /// own; three in a short window is. The `block` field is a
        /// timestamp for issuer audit during re-KYC.
        CertSelfDiscardedRecovery {
            thumbprint: Thumbprint,
            holder: T::AccountId,
            block: BlockNumberFor<T>,
        },
        IssuerInvalidated { issuer: T::AccountId, root: T::AccountId, at_block: BlockNumberFor<T> },
        RootFlaggedCompromised { root: T::AccountId, at_block: BlockNumberFor<T> },
        ChallengeInitiated { entity: T::AccountId, deadline: BlockNumberFor<T> },
        ChallengeResolved { entity: T::AccountId, restored: bool },
        /// Surfaces compromise context for relying parties.
        CompromisedEntityAction { entity: T::AccountId, action: ActionType },
        /// Root or issuer renewed their cert. Old cert → retired, new cert active.
        CertRenewed { entity: T::AccountId, old_thumbprint: Thumbprint, new_thumbprint: Thumbprint },
        /// Emitted when an expired offer is cleaned up.
        OfferPurged { nonce: [u8; 32], issuer: T::AccountId, user: T::AccountId, at_block: BlockNumberFor<T> },
        /// Emitted by `on_initialize` when a cert's expiry block
        /// rolls over — hot record flipped to Suspended, purge
        /// scheduled at `now + InactivePurgePeriod`.
        CertExpiredAndScheduled { thumbprint: Thumbprint, purge_block: BlockNumberFor<T> },
        /// Emitted when `cleanup` (permissionless) reaps a cert's
        /// storage deposit. `reaped_by` is the caller; `deposit_recipient`
        /// is where the deposit landed — defaults to the cert holder,
        /// redirects if the caller specified an alternate address.
        CertReaped {
            thumbprint: Thumbprint,
            reaped_by: T::AccountId,
            deposit_recipient: T::AccountId,
        },
        /// Issuer created a new cert template.
        TemplateCreated {
            issuer: T::AccountId,
            name: BoundedVec<u8, ConstU32<MAX_TEMPLATE_NAME_LEN>>,
        },
        /// Issuer deactivated a template — no new offers can reference
        /// it. Existing certs under the template remain valid.
        TemplateDeactivated {
            issuer: T::AccountId,
            name: BoundedVec<u8, ConstU32<MAX_TEMPLATE_NAME_LEN>>,
        },
        /// Issuer discarded a deactivated template with zero active
        /// certs. Deposit released.
        TemplateDiscarded {
            issuer: T::AccountId,
            name: BoundedVec<u8, ConstU32<MAX_TEMPLATE_NAME_LEN>>,
        },
        /// `push_to_expiry_index` / `push_to_purge_index` /
        /// `push_to_offer_expiry_index` found every slot in the
        /// lookahead window (`MAX_PURGE_LOOKAHEAD` blocks) full and
        /// could not schedule the entry. The extrinsic still
        /// succeeds; the cert/offer is not lost, just not
        /// auto-purged. Holder can `self_discard_cert` to recover
        /// their deposit; anyone can `cleanup()` once the cert is
        /// past its grace period. Intended as a rare-case
        /// observability signal — if this fires repeatedly on
        /// mainnet, it's a griefing campaign.
        PurgeScheduleSkipped {
            intended_block: BlockNumberFor<T>,
            kind: PurgeScheduleKind,
        },
        /// Mime-wrap verifying key installed (or rotated) in
        /// `MimeWrapVk` storage. PoC-mode entry point is
        /// `set_mime_wrap_vk`; production routes through governance
        /// origin.
        MimeWrapVkSet,
        /// Mime-wrap commitment recorded for a freshly-minted cert
        /// whose template selected `Some(PopMechanism::MimeWrap)`.
        /// The commitment lives in the separate
        /// `MimeWrapCommitments` map (Cold tier — accessed only at
        /// sign time, kept off the hot Cold-record load path).
        MimeWrapCommitmentRecorded {
            thumbprint: Thumbprint,
        },
        /// Mime-wrap PopAssertion verified successfully against a
        /// cert. Emitted from `verify_pop_assertion` after the
        /// pairing check passes and `(bucket, nonce)` is recorded
        /// as consumed. The bucket is surfaced so off-chain
        /// authorization layers can subscribe per cert per bucket.
        MimeWrapPopVerified {
            thumbprint: Thumbprint,
            bucket: u64,
        },
    }

    /// Which index a `PurgeScheduleSkipped` event was raised from.
    #[derive(
        Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, TypeInfo, MaxEncodedLen, Debug,
    )]
    pub enum PurgeScheduleKind {
        Expiry,
        Purge,
        OfferExpiry,
    }

    #[derive(Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, TypeInfo, MaxEncodedLen, Debug)]
    pub enum ActionType {
        IssuedCert,
        OfferedContract,
        InvalidatedIssuer,
    }

    // ---------------------------------------------------------------------------
    // Errors
    // ---------------------------------------------------------------------------

    #[pallet::error]
    pub enum Error<T> {
        OfferNotFound,
        ContractExpired,
        NotOfferRecipient,
        /// The `offer_created_at_block` the caller passed to
        /// `mint_cert` does not match `offer.created_at` in storage.
        /// A sanity check — the client has to have read the offer
        /// to know the exact block, so a mismatch means either a
        /// stale client or a spoofed argument.
        OfferCreatedAtMismatch,
        EkAlreadyRegistered,
        ThumbprintCollision,
        CertNotFound,
        NotCertIssuer,
        NotARoot,
        NotAnIssuer,
        IssuerAlreadyRegistered,
        RootAlreadyRegistered,
        RootAlreadyCompromised,
        IssuerAlreadyCompromised,
        AttestationInvalid,
        InvalidPublicKey,
        UserAlreadyHasCertFromIssuer,
        AlreadySuspended,
        AlreadyActive,
        TtlExceedsRootMax,
        ExpiryExceedsParent,
        CertExpired,
        MaxIssuersReached,
        AddressIsIssuer,
        AddressIsRoot,
        AddressTainted,
        IssuerCertCannotBeSuspended,
        IllegalStateTransition,
        InvalidEntityState,
        NoChallengeToResolve,
        InsufficientDeposit,
        ProxyNotFound,
        /// Cert exists but is not in a reapable state for `cleanup`.
        CertNotReapable,
        /// Compromised issuers are permanently disqualified from re-anchoring.
        IssuerPermanentlyCompromised,
        /// Reserved for catastrophic schedule saturation. After the
        /// distributed-scheduling change (see `push_to_*_index`
        /// helpers and the doc on `PurgeIndex`), the normal overflow
        /// path no longer surfaces this error — instead it
        /// distributes into a later block or emits
        /// `PurgeScheduleSkipped`. Kept as a safety-net variant in
        /// case a future code path needs a hard failure.
        PurgeIndexFull,
        /// TTL is below the minimum required for this cert type.
        TtlBelowMinimum,
        /// Entity must be in Compromised state to initiate a challenge.
        NotCompromised,
        /// Successor signature verification failed.
        SuccessorSignatureInvalid,
        /// Entity has active issuers that must be handled first.
        HasActiveIssuers,
        /// Root is permanently compromised — cannot renew.
        RootPermanentlyCompromised,
        /// Challenge already used — one shot only.
        ChallengeAlreadyUsed,
        /// Issuer already has a template with this name.
        TemplateNameTaken,
        /// `max_ttl_blocks` exceeds the issuer's own cert NotAfter
        /// window — a child's TTL can never outlive its parent.
        TemplateTtlExceedsIssuerCert,
        /// `min_ttl_blocks >= max_ttl_blocks` — range is empty or inverted.
        TemplateInvalidTtlRange,
        /// Issuer already holds `MaxTemplatesPerIssuer` templates.
        TooManyTemplates,
        /// Template referenced by `(issuer, name)` does not exist.
        TemplateNotFound,
        /// Template exists but `is_active == false` — no new offers.
        TemplateInactive,
        /// `deactivate_cert_template` on a template already inactive.
        TemplateAlreadyInactive,
        /// `discard_cert_template` called before the template was
        /// deactivated.
        TemplateStillActive,
        /// `discard_cert_template` blocked because at least one cert
        /// minted under this template is still in storage.
        TemplateHasActiveCerts,
        /// Offer `ttl_blocks` fell outside `[min_ttl_blocks, max_ttl_blocks]`.
        TemplateTtlOutOfRange,
        /// `template.issued_count` has reached `template.max_certs`.
        TemplateMaxCertsReached,
        /// Template declares `PopRequirement::Required` and the cert
        /// being minted is not `AttestationType::Tpm`.
        PopRequired,
        /// EKU is hierarchical and the issuer (or root when issuing
        /// issuer certs) does not carry it as a capability.
        EkuNotAuthorized,
        /// A template lists an EKU whose `implies_pop_required()` is
        /// true but the template's `pop_requirement` is `NotRequired`.
        PopRequiredForEku,
        /// EKU is not valid as a root capability (fails
        /// `Eku::valid_for_root()`).
        InvalidRootEku,
        /// EKU is not valid as an issuer capability (fails
        /// `Eku::valid_for_issuer()`).
        InvalidIssuerEku,
        /// PoP cert mint arrived without a `hip_proof_at_genesis`
        /// argument. PoP certs at schema v2+ must record a hardware
        /// integrity baseline at mint.
        HipProofRequired,
        /// HIP proof verification failed (signature, EK hash
        /// mismatch, etc.). See `zk_pki_hip::HipError` on the
        /// verifier side for the exact cause.
        HipProofInvalid,
        /// HIP proof arrived with a `HipPlatform` the pallet has no
        /// verifier for (Linux tpm2, StrongBox in the current pass).
        HipProofPlatformNotImplemented,
        /// Cold record absent for a cert whose Hot record was present
        /// — atomic-pair invariant violated. Should be unreachable
        /// if every mint/remove path goes through the canonical
        /// helpers, but the pallet surfaces it explicitly so bugs
        /// don't get masked as generic errors.
        CertColdRecordMissing,
        /// PopAssertion reached `verify_pop_assertion` with a cert
        /// that wasn't in `CertState::Active`. Expired or suspended
        /// certs can't assert identity.
        CertNotActive,
        /// PopAssertion targeted a cert that does not carry the
        /// `ProofOfPersonhood` EKU. Non-PoP certs use the recovery
        /// path (SS58 ownership only) instead.
        PopEkuRequired,
        /// `cert_ec_signature` on a PopAssertion failed verification
        /// against the cert's stored `cert_ec_pubkey`. Either the
        /// signature was tampered or the caller doesn't control the
        /// hardware-bound cert keypair.
        CertEcSignatureInvalid,
        /// Caller's Substrate AccountId does not match the cert's
        /// `user` field. Used by `self_discard_cert`'s recovery
        /// path, where SS58 ownership is the sole authorization.
        NotCertHolder,
        /// PopAssertion reached verification but the cert's Cold
        /// record has `genesis_fingerprint: None`. Should be
        /// unreachable — PoP certs always record a fingerprint at
        /// mint. Defensive.
        GenesisFingerprintMissing,

        // ── Mime-wrap PoP (Android StrongBox tier) ──
        /// `pop_mechanism` declared on the cert at mint does not
        /// match the variant carried on the submitted `PopAssertion`.
        /// E.g. cert has `Some(HipSigned)` but caller sent a
        /// `PopAssertion::MimeWrap`. Cross-tier bypass guard.
        PopMechanismMismatch,
        /// Template declares `Some(PopMechanism::HipSigned)` but the
        /// minting attestation chain is StrongBox. The StrongBox
        /// HMAC binding is the very weakness MimeWrap was designed
        /// to mask, so HipSigned on StrongBox is rejected at mint.
        HipSignedNotPermittedOnStrongBox,
        /// Template declares `Some(PopMechanism::MimeWrap)` but the
        /// minting attestation chain is TPM2. Category error —
        /// TPM2 already supports HipSigned natively, no benefit to
        /// the ZK detour.
        MimeWrapNotPermittedOnTpm2,
        /// `mint_cert` invoked with `commitment_c: Some(_)` for a
        /// template whose `pop_mechanism` is not `MimeWrap`. The
        /// commitment field is meaningless for HipSigned certs and
        /// would mislead off-chain verifiers if persisted.
        MimeWrapCommitmentNotApplicable,
        /// `mint_cert` invoked with `commitment_c: None` for a
        /// template whose `pop_mechanism == Some(MimeWrap)`. Mime-wrap
        /// proofs commit to this 32-byte value via the ZK
        /// public-input vector; without it stored on chain the
        /// verifier cannot reconstruct the inputs.
        MimeWrapCommitmentRequired,
        /// Mime-wrap PoP submitted but the chain has no VK installed
        /// in `MimeWrapVk` storage. Operator must run
        /// `set_mime_wrap_vk` (or wait for governance) before any
        /// MimeWrap cert can be used.
        MimeWrapVkNotSet,
        /// Stored VK bytes failed `VerifyingKey::deserialize_compressed`.
        /// Defensive — `set_mime_wrap_vk` validates length but not
        /// arkworks-deserializability before storing.
        MimeWrapVkMalformed,
        /// `proof` field on the assertion is the wrong size or
        /// otherwise fails `Proof::deserialize_compressed`.
        MimeWrapProofMalformed,
        /// Pairing check failed — proof either was not generated
        /// against the installed VK, was generated against different
        /// public inputs than the ones the pallet rebuilt, or is
        /// outright invalid.
        MimeWrapProofInvalid,
        /// `(bucket, nonce)` pair is already in `ConsumedMimeWrapNonces`.
        /// Verifier rejects without rerunning the pairing check.
        MimeWrapReplayRejected,
        /// `user_otp` exceeds 24 bits (top 8 bits of the u32 are
        /// non-zero). Caller bug — surface explicitly rather than
        /// silently truncating.
        MimeWrapOtpOutOfRange,
        /// `set_mime_wrap_vk` invoked with VK bytes longer than
        /// `MAX_MIME_WRAP_VK_BYTES`. Bound is slack relative to the
        /// observed mime-wrap VK size (~19 KB) for forward-compat
        /// with larger circuits, but a hard cap is still enforced.
        MimeWrapVkTooLong,
        /// Paseo-tier tripwire: client-supplied `ec_key_pub` on
        /// `mint_cert` does not match the chain's independent
        /// derivation from `cert.cold.cert_ec_pubkey`
        /// (canonicalize SEC1 → DER SPKI, then SHA256). Mismatch
        /// indicates the dotwave-side and pallet-side
        /// canonicalization specs have drifted, or that the caller
        /// is attempting to bind a fake `ec_key_pub` to a real cert
        /// to bypass the device-binding guarantee. The error fails
        /// the mint loudly rather than silently producing a cert
        /// whose proofs would later verify against bytes the device
        /// doesn't control. Pre-mainnet migration removes the
        /// client-supplied parameter and chain-derives only — see
        /// `ZK-PKI ec_key_pub Binding` memory.
        MimeWrapEcKeyPubMismatch,
    }

    // ---------------------------------------------------------------------------
    // Pallet struct & hooks
    // ---------------------------------------------------------------------------

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    /// Hold reasons for `fungible::MutateHold` calls out of this
    /// pallet. Aggregated into the runtime's `RuntimeHoldReason`
    /// via the `#[runtime::derive(RuntimeHoldReason)]` attribute
    /// on the runtime's `construct_runtime!`. Every cert-deposit
    /// hold (mint, register_root, issue_issuer_cert, reissue,
    /// renew) uses the single `CertDeposit` variant; deposit
    /// amount is stored per-cert on `CertRecordCold.deposit` so
    /// release paths know the exact amount to drain.
    #[pallet::composite_enum]
    pub enum HoldReason {
        /// Held at cert creation; released at self_discard /
        /// on_initialize purge / invalidate_cert / deregister_root
        /// cascade, or transferred on-hold to the caller by
        /// `cleanup`.
        CertDeposit,
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        /// Two-phase take-based scheduling. Both phases are O(1) when
        /// the slot is empty, which is the steady-state case.
        ///
        /// Phase 1 — expiry. Any cert whose `expiry_block == now`
        /// flips `state` to Suspended and gets scheduled for purge
        /// at `now + InactivePurgePeriod`. Suspension_block is set
        /// so `cleanup` / reactivation can locate the purge slot.
        ///
        /// Phase 2 — purge. Any thumbprint in `PurgeIndex[now]` that
        /// is still Suspended is reaped: hot + cold + secondary
        /// indexes + EK registry removed, deposit unreserved to the
        /// original holder. If the cert was reactivated between
        /// suspension and the scheduled block, the PurgeIndex entry
        /// was already removed by `reactivate_cert` and the take
        /// simply returns nothing for this thumbprint — no action.
        fn on_initialize(now: BlockNumberFor<T>) -> Weight {
            let expiring = ExpiryIndex::<T>::take(now);
            let mut expired_flipped = 0u64;
            for thumbprint in expiring.iter() {
                // Only flip active certs. A cert that was suspended
                // before expiry stays suspended and won't be
                // double-scheduled.
                CertLookupHot::<T>::mutate(thumbprint, |maybe| {
                    if let Some(c) = maybe {
                        if c.state.is_active() {
                            c.state = CertState::Suspended;
                        }
                    }
                });
                CertLookupCold::<T>::mutate(thumbprint, |maybe| {
                    if let Some(c) = maybe {
                        if c.suspension_block.is_none() {
                            c.suspension_block = Some(now);
                        }
                    }
                });
                let purge_block = now.saturating_add(T::InactivePurgePeriod::get());
                PurgeIndex::<T>::mutate(purge_block, |v| {
                    // Silent drop if slot is genuinely full — the
                    // `cleanup` extrinsic is the fallback. Deposit is
                    // still recoverable via `cleanup` condition 1.
                    let _ = v.try_push(*thumbprint);
                });
                Self::deposit_event(Event::CertExpiredAndScheduled {
                    thumbprint: *thumbprint,
                    purge_block,
                });
                expired_flipped = expired_flipped.saturating_add(1);
            }

            let purging = PurgeIndex::<T>::take(now);
            let mut purged = 0u64;
            for thumbprint in purging.iter() {
                if let Some(cert) = CertLookupHot::<T>::get(thumbprint) {
                    if !cert.is_active() {
                        let holder = cert.user.clone();
                        let deposit = CertLookupCold::<T>::get(thumbprint)
                            .map(|c| c.deposit)
                            .unwrap_or_else(|| T::CertDeposit::get());
                        Self::remove_cert_entry(*thumbprint, &cert);
                        // on_initialize can't return an error; if the
                        // release fails (shouldn't — we hold exactly
                        // `deposit` per cert), surface via an event
                        // would be ideal but the current Event type
                        // doesn't carry a variant for that. Silent
                        // best-effort is acceptable for the purge
                        // hook because the cert is already gone from
                        // storage; a stranded hold will be caught by
                        // cleanup's orphan path.
                        let _ = Self::release_cert_deposit(&holder, deposit);
                        Self::deposit_event(Event::CertPurged {
                            thumbprint: *thumbprint,
                            deposit_claimed_by: holder,
                        });
                        purged = purged.saturating_add(1);
                    }
                    // Cert was reactivated between suspension and now —
                    // shouldn't land here because reactivation removes
                    // from PurgeIndex, but tolerate gracefully.
                }
            }

            T::DbWeight::get().reads_writes(
                2u64.saturating_add(expired_flipped).saturating_add(purged),
                expired_flipped.saturating_mul(3).saturating_add(purged.saturating_mul(6)),
            )
        }
    }

    // ---------------------------------------------------------------------------
    // Extrinsics
    // ---------------------------------------------------------------------------

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Register caller as a root CA.
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::register_root())]
        pub fn register_root(
            origin: OriginFor<T>,
            proxy: T::AccountId,
            device_pubkey: DevicePublicKey,
            attestation: BoundedVec<u8, ConstU32<MAX_ATTESTATION_LEN>>,
            ttl_blocks: BlockNumberFor<T>,
            capability_ekus: BoundedVec<Eku, ConstU32<MAX_CAPABILITY_EKUS>>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(device_pubkey.is_valid(), Error::<T>::InvalidPublicKey);
            ensure!(!Roots::<T>::contains_key(&who), Error::<T>::RootAlreadyRegistered);
            ensure!(!Issuers::<T>::contains_key(&who), Error::<T>::AddressIsIssuer);
            if let Some(dereg) = DeregisteredRoots::<T>::get(&who) {
                ensure!(!dereg.tainted, Error::<T>::AddressTainted);
            }
            ensure!(ttl_blocks <= T::MaxRootTtlBlocks::get(), Error::<T>::TtlExceedsRootMax);
            let now = <frame_system::Pallet<T>>::block_number();
            // TPM attestation verification (validates pubkey is valid curve point)
            let challenge = sp_io::hashing::blake2_256(&(who.clone(), now).encode());
            let (ek_hash, att_type) = T::Attestation::verify(&attestation, &device_pubkey, &challenge)
                .map_err(|_| Error::<T>::AttestationInvalid)?;

            // EK deduplication (PoP only). Root-scoped: a root
            // self-registering is its own trust domain, so the
            // lookup key is `(who, ek_hash)`.
            if att_type.is_pop_eligible() {
                ensure!(
                    !EkRegistry::<T>::contains_key(&who, ek_hash),
                    Error::<T>::EkAlreadyRegistered,
                );
            }

            // Capability-EKU validation. Root-valid check is a pure
            // function of the EKU variant. The ProofOfPersonhood
            // capability additionally requires a Tpm attestation —
            // a root that cannot itself prove personhood must not
            // claim the authority to certify it.
            for eku in capability_ekus.iter() {
                ensure!(eku.valid_for_root(), Error::<T>::InvalidRootEku);
            }
            if capability_ekus.contains(&Eku::ProofOfPersonhood) {
                ensure!(att_type == AttestationType::Tpm, Error::<T>::PopRequired);
            }

            // Proxy relationship must already exist in
            // `pallet_proxy` before `register_root` is accepted —
            // invariant #12 in pki/CLAUDE.md. The check is abstracted
            // through `T::ProxyValidator` so the pallet doesn't need
            // a direct `pallet_proxy::Config` supertrait; production
            // runtimes wire a reader-impl, test runtimes wire a
            // no-op.
            ensure!(
                <T as Config>::ProxyValidator::has_proxy(&who, &proxy),
                Error::<T>::ProxyNotFound,
            );
            let expiry_block = now.saturating_add(ttl_blocks);
            let canonical = CertCanonical {
                schema_version: CURRENT_SCHEMA_VERSION,
                root: who.clone(), issuer: who.clone(), user: who.clone(),
                user_pubkey: device_pubkey.clone(), registration_block: now,
                expiry: expiry_block,
                metadata: BoundedVec::<u8, ConstU32<MAX_METADATA_LEN>>::default(),
            };
            let thumbprint = Self::compute_thumbprint(&canonical);
            ensure!(!CertLookupHot::<T>::contains_key(thumbprint), Error::<T>::ThumbprintCollision);
            let deposit = T::CertDeposit::get();
            Self::hold_cert_deposit(&who, deposit)?;
            let ek_opt = if att_type.is_pop_eligible() { Some(ek_hash) } else { None };
            CertLookupHot::<T>::insert(thumbprint, CertRecordHot {
                schema_version: CURRENT_SCHEMA_VERSION, thumbprint,
                root: who.clone(), issuer: who.clone(), user: who.clone(),
                mint_block: now, expiry_block, state: CertState::Active,
                ek_hash: ek_opt, attestation_type: att_type, manufacturer_verified: false,
                template_name: BoundedVec::default(),
                ekus: BoundedVec::default(),
                // Root certs are minted outside the templated cert
                // flow; no template, no PoP mechanism choice.
                pop_mechanism: None,
            });
            CertLookupCold::<T>::insert(thumbprint, CertRecordCold {
                thumbprint,
                cert_ec_pubkey: device_pubkey,
                deposit,
                genesis_os_version: None,
                genesis_os_patch_level: None,
                genesis_vendor_patch_level: None,
                genesis_boot_patch_level: None,
                suspension_reason: None,
                suspension_block: None,
                issuer_metadata: None,
                genesis_fingerprint: None,
            });
            if let Some(eh) = ek_opt {
                EkRegistry::<T>::insert(&who, eh, thumbprint);
            }
            CertsByIssuer::<T>::insert(&who, thumbprint, ());
            CertsByUser::<T>::insert(&who, thumbprint, ());
            CertsByRoot::<T>::insert(&who, thumbprint, ());
            Self::push_to_expiry_index(expiry_block, thumbprint)?;
            Roots::<T>::insert(&who, RootRecord {
                proxy, cert_thumbprint: thumbprint, registered_at: now, state: EntityState::Active, challenge_used: false,
                capability_ekus,
            });
            Self::deposit_event(Event::RootRegistered { root: who });
            Ok(())
        }

        /// Root issues an issuer cert.
        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::issue_issuer_cert())]
        pub fn issue_issuer_cert(
            origin: OriginFor<T>, issuer: T::AccountId, proxy: T::AccountId,
            device_pubkey: DevicePublicKey,
            attestation: BoundedVec<u8, ConstU32<MAX_ATTESTATION_LEN>>,
            ttl_blocks: BlockNumberFor<T>,
            capability_ekus: BoundedVec<Eku, ConstU32<MAX_CAPABILITY_EKUS>>,
        ) -> DispatchResult {
            let root_addr = ensure_signed(origin)?;
            ensure!(device_pubkey.is_valid(), Error::<T>::InvalidPublicKey);
            let now = <frame_system::Pallet<T>>::block_number();
            Self::enforce_challenge_deadline_root(&root_addr, now);
            let root_rec = Roots::<T>::get(&root_addr).ok_or(Error::<T>::NotARoot)?;
            ensure!(root_rec.can_issue() || root_rec.state.is_compromised(), Error::<T>::InvalidEntityState);
            ensure!(!Roots::<T>::contains_key(&issuer), Error::<T>::AddressIsRoot);
            ensure!(!Issuers::<T>::contains_key(&issuer), Error::<T>::IssuerAlreadyRegistered);
            let count = IssuerCountPerRoot::<T>::get(&root_addr);
            ensure!(count < T::MaxIssuersPerRoot::get(), Error::<T>::MaxIssuersReached);
            ensure!(T::MaxIssuersPerRoot::get() <= ABSOLUTE_MAX_ISSUERS_PER_ROOT, Error::<T>::MaxIssuersReached);
            // TPM attestation verification (validates pubkey is valid curve point)
            let challenge = sp_io::hashing::blake2_256(&(issuer.clone(), now).encode());
            let (ek_hash, att_type) = T::Attestation::verify(&attestation, &device_pubkey, &challenge)
                .map_err(|_| Error::<T>::AttestationInvalid)?;
            // EK dedup is root-scoped — the issuer cert is anchored
            // under `root_addr`, so that's the trust domain whose
            // registry we consult.
            if att_type.is_pop_eligible() {
                ensure!(
                    !EkRegistry::<T>::contains_key(&root_addr, ek_hash),
                    Error::<T>::EkAlreadyRegistered,
                );
            }

            // Capability-EKU validation. Every entry must be
            // issuer-valid by variant; hierarchical entries must also
            // appear in the root's own capability set (cannot grant
            // what you don't have). ProofOfPersonhood additionally
            // requires a Tpm attestation on the issuer's cert.
            for eku in capability_ekus.iter() {
                ensure!(eku.valid_for_issuer(), Error::<T>::InvalidIssuerEku);
                if eku.requires_issuer_capability() {
                    ensure!(
                        root_rec.capability_ekus.contains(eku),
                        Error::<T>::EkuNotAuthorized,
                    );
                }
            }
            if capability_ekus.contains(&Eku::ProofOfPersonhood) {
                ensure!(att_type == AttestationType::Tpm, Error::<T>::PopRequired);
            }

            let root_cert = CertLookupHot::<T>::get(root_rec.cert_thumbprint).ok_or(Error::<T>::CertNotFound)?;
            ensure!(now < root_cert.expiry_block, Error::<T>::CertExpired);
            let expiry_block = now.saturating_add(ttl_blocks);
            ensure!(expiry_block <= root_cert.expiry_block, Error::<T>::ExpiryExceedsParent);
            ensure!(ttl_blocks >= T::MinIssuerTtlBlocks::get(), Error::<T>::TtlBelowMinimum);
            if root_rec.state.is_compromised() {
                Self::deposit_event(Event::CompromisedEntityAction { entity: root_addr.clone(), action: ActionType::IssuedCert });
            }
            // Proxy-relationship check — same rationale as in
            // `register_root`. Here the delegator is the issuer
            // candidate (whose proxy the caller-root is naming on
            // their behalf), so `has_proxy(&issuer, &proxy)`.
            ensure!(
                <T as Config>::ProxyValidator::has_proxy(&issuer, &proxy),
                Error::<T>::ProxyNotFound,
            );
            let deposit = T::CertDeposit::get();
            // The issuer cert's storage deposit is paid by the ROOT
            // who signs `issue_issuer_cert`. The issuer hasn't
            // touched the chain yet at this point, so they can't be
            // the one paying. The matching release in
            // `deregister_root` targets the same root account — see
            // the comment next to the release there.
            Self::hold_cert_deposit(&root_addr, deposit)?;
            let canonical = CertCanonical {
                schema_version: CURRENT_SCHEMA_VERSION,
                root: root_addr.clone(), issuer: root_addr.clone(), user: issuer.clone(),
                user_pubkey: device_pubkey.clone(), registration_block: now, expiry: expiry_block,
                metadata: BoundedVec::<u8, ConstU32<MAX_METADATA_LEN>>::default(),
            };
            let thumbprint = Self::compute_thumbprint(&canonical);
            ensure!(!CertLookupHot::<T>::contains_key(thumbprint), Error::<T>::ThumbprintCollision);
            let ek_opt = if att_type.is_pop_eligible() { Some(ek_hash) } else { None };
            CertLookupHot::<T>::insert(thumbprint, CertRecordHot {
                schema_version: CURRENT_SCHEMA_VERSION, thumbprint,
                root: root_addr.clone(), issuer: root_addr.clone(), user: issuer.clone(),
                mint_block: now, expiry_block, state: CertState::Active,
                ek_hash: ek_opt, attestation_type: att_type, manufacturer_verified: false,
                template_name: BoundedVec::default(),
                ekus: BoundedVec::default(),
                // Issuer certs aren't templated; PoP mechanism
                // doesn't apply.
                pop_mechanism: None,
            });
            CertLookupCold::<T>::insert(thumbprint, CertRecordCold {
                thumbprint,
                cert_ec_pubkey: device_pubkey,
                deposit,
                genesis_os_version: None,
                genesis_os_patch_level: None,
                genesis_vendor_patch_level: None,
                genesis_boot_patch_level: None,
                suspension_reason: None,
                suspension_block: None,
                issuer_metadata: None,
                genesis_fingerprint: None,
            });
            if let Some(eh) = ek_opt {
                EkRegistry::<T>::insert(&root_addr, eh, thumbprint);
            }
            CertsByIssuer::<T>::insert(&root_addr, thumbprint, ());
            CertsByUser::<T>::insert(&issuer, thumbprint, ());
            CertsByRoot::<T>::insert(&root_addr, thumbprint, ());
            Self::push_to_expiry_index(expiry_block, thumbprint)?;
            Issuers::<T>::insert(&issuer, IssuerRecord {
                root: root_addr.clone(), proxy, cert_thumbprint: thumbprint,
                registered_at: now, state: EntityState::Active, challenge_used: false,
                capability_ekus,
            });
            IssuerCountPerRoot::<T>::mutate(&root_addr, |c| *c = c.saturating_add(1));
            RootIssuers::<T>::try_mutate(&root_addr, |issuers| -> DispatchResult {
                issuers.try_push(issuer.clone()).map_err(|_| Error::<T>::MaxIssuersReached)?;
                Ok(())
            })?;
            Self::deposit_event(Event::IssuerCertIssued { root: root_addr, issuer, thumbprint });
            Ok(())
        }

        /// Issuer creates a contract offer for a user under a specific
        /// cert template. The template gates PoP policy and TTL range;
        /// the offer stores its name so mint can enforce consistently.
        #[pallet::call_index(2)]
        #[pallet::weight(T::WeightInfo::offer_contract())]
        pub fn offer_contract(
            origin: OriginFor<T>, user: T::AccountId,
            ttl_blocks: BlockNumberFor<T>,
            template_name: BoundedVec<u8, ConstU32<MAX_TEMPLATE_NAME_LEN>>,
            metadata: BoundedVec<u8, ConstU32<MAX_METADATA_LEN>>,
        ) -> DispatchResult {
            let issuer_addr = ensure_signed(origin)?;
            let now = <frame_system::Pallet<T>>::block_number();
            Self::enforce_challenge_deadline_issuer(&issuer_addr, now);
            let issuer_rec = Issuers::<T>::get(&issuer_addr).ok_or(Error::<T>::NotAnIssuer)?;
            ensure!(issuer_rec.can_issue() || issuer_rec.state.is_compromised(), Error::<T>::InvalidEntityState);
            let ui_key = UserIssuerKey::new(user.clone(), issuer_addr.clone());
            ensure!(!UserIssuerIndex::<T>::contains_key(&ui_key), Error::<T>::UserAlreadyHasCertFromIssuer);
            let issuer_cert = CertLookupHot::<T>::get(issuer_rec.cert_thumbprint).ok_or(Error::<T>::CertNotFound)?;
            ensure!(now < issuer_cert.expiry_block, Error::<T>::CertExpired);
            Self::enforce_challenge_deadline_root(&issuer_rec.root, now);
            let root_rec = Roots::<T>::get(&issuer_rec.root).ok_or(Error::<T>::NotARoot)?;
            let root_cert = CertLookupHot::<T>::get(root_rec.cert_thumbprint).ok_or(Error::<T>::CertNotFound)?;
            ensure!(now < root_cert.expiry_block, Error::<T>::CertExpired);

            // Template gate. Lookup by (caller, name) is the issuer-ownership check —
            // only the template's issuer can use it, by construction.
            let template = CertTemplates::<T>::get(&issuer_addr, &template_name)
                .ok_or(Error::<T>::TemplateNotFound)?;
            ensure!(template.is_active, Error::<T>::TemplateInactive);
            let ttl_u64: u64 = ttl_blocks.unique_saturated_into();
            ensure!(
                ttl_u64 >= template.min_ttl_blocks && ttl_u64 <= template.max_ttl_blocks,
                Error::<T>::TemplateTtlOutOfRange,
            );
            ensure!(
                template.issued_count < template.max_certs.unwrap_or(u32::MAX),
                Error::<T>::TemplateMaxCertsReached,
            );

            let user_expiry = now.saturating_add(ttl_blocks);
            ensure!(user_expiry <= issuer_cert.expiry_block, Error::<T>::ExpiryExceedsParent);
            if issuer_rec.state.is_compromised() {
                Self::deposit_event(Event::CompromisedEntityAction { entity: issuer_addr.clone(), action: ActionType::OfferedContract });
            }
            let expiry_block = now.saturating_add(T::ContractOfferTtlBlocks::get());
            let parent_hash = <frame_system::Pallet<T>>::parent_hash();
            let nonce: [u8; 32] = sp_io::hashing::blake2_256(&(issuer_addr.clone(), user.clone(), now, parent_hash).encode());
            let offer_deposit = T::OfferDeposit::get();
            let offer_key = IssuerUserKey::new(issuer_addr.clone(), user.clone());
            if let Some(old_nonce) = OfferIndex::<T>::get(&offer_key) {
                if let Some(old_offer) = ContractOffers::<T>::take(old_nonce) {
                    T::Currency::unreserve(&issuer_addr, old_offer.deposit);
                    OfferExpiryIndex::<T>::mutate(old_offer.expiry_block, |n| n.retain(|x| x != &old_nonce));
                }
                Self::deposit_event(Event::ContractReplaced { issuer: issuer_addr.clone(), user: user.clone(), old_nonce, new_nonce: nonce });
            }
            T::Currency::reserve(&issuer_addr, offer_deposit)?;
            ContractOffers::<T>::insert(nonce, ContractOffer {
                issuer: issuer_addr.clone(), user: user.clone(), nonce, expiry_block,
                created_at: now, ttl_blocks, deposit: offer_deposit, metadata,
                template_name,
            });
            OfferIndex::<T>::insert(&offer_key, nonce);
            Self::push_to_offer_expiry_index(expiry_block, nonce)?;
            Self::deposit_event(Event::ContractOffered { issuer: issuer_addr, user, nonce, expiry_block });
            Ok(())
        }

        /// End-user responds to a contract offer to mint their cert NFT.
        ///
        /// Signature after TODO-4 wiring:
        ///
        /// - `contract_nonce` — the offer nonce the issuer generated at
        ///   `offer_contract` time. Used both as the `ContractOffers`
        ///   lookup key AND as the attestation challenge the Kotlin
        ///   ceremony baked into `setAttestationChallenge()` on both
        ///   EC keys. **The nonce IS the challenge** — the stub
        ///   `blake2_256((who, now))` derivation that lived here
        ///   before TODO-4 is gone.
        /// - `attestation_payload` — the TODO-3
        ///   [`AttestationPayloadV3`] (cert_ec chain + attest_ec chain
        ///   + HMAC binding + binding sig + integrity blob + integrity
        ///   sig). Replaces the pre-TODO-4 `device_pubkey +
        ///   attestation_bytes` pair; the verified
        ///   `cert_ec_pubkey` is extracted from the payload and
        ///   written into the cert record.
        /// - `offer_created_at_block` — the block at which the offer
        ///   was created. Passed from the client and sanity-checked
        ///   against `offer.created_at` in storage. Forwarded to
        ///   [`BindingProofVerifier::verify`] as the lower bound for
        ///   the integrity blob's `block_number` field.
        ///
        /// The proof-of-ceremony anchor is the `AttestationPayloadV3`
        /// (cert_ec chain + attest_ec chain + HMAC binding signature +
        /// integrity blob + integrity signature); a separate TOTP
        /// second-factor was part of an earlier design and is no
        /// longer carried as an extrinsic parameter.
        #[pallet::call_index(3)]
        #[pallet::weight(T::WeightInfo::mint_cert())]
        // mint_cert parameter notes:
        //   * `hip_proof_at_genesis` — required for PoP certs
        //     (template's `pop_requirement == Required`); `None` is
        //     accepted for non-PoP certs and ignored. The verifier
        //     runs internal consistency checks only — there's no
        //     prior fingerprint to compare against at genesis.
        //   * `commitment_c` — required exactly when the template's
        //     `pop_mechanism == Some(MimeWrap)`; rejected with
        //     `MimeWrapCommitmentNotApplicable` for any other case.
        //   * `ec_key_pub_claimed` — Paseo tripwire (option B): the
        //     chain re-derives the same value from
        //     `cert.cold.cert_ec_pubkey` (canonicalize SEC1 → DER
        //     SPKI, then SHA256) and asserts equality. Mainnet
        //     (option A) drops this parameter and chain-derives
        //     only. See `ZK-PKI ec_key_pub Binding` memory.
        pub fn mint_cert(
            origin: OriginFor<T>,
            contract_nonce: [u8; 32],
            attestation_payload: AttestationPayloadV3,
            offer_created_at_block: BlockNumberFor<T>,
            hip_proof_at_genesis: Option<CanonicalHipProof>,
            commitment_c: Option<[u8; 32]>,
            ec_key_pub_claimed: Option<[u8; 32]>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let offer = ContractOffers::<T>::get(contract_nonce)
                .ok_or(Error::<T>::OfferNotFound)?;
            ensure!(offer.user == who, Error::<T>::NotOfferRecipient);
            ensure!(
                offer_created_at_block == offer.created_at,
                Error::<T>::OfferCreatedAtMismatch,
            );
            let now = <frame_system::Pallet<T>>::block_number();
            ensure!(now < offer.expiry_block, Error::<T>::ContractExpired);
            let ui_key = UserIssuerKey::new(who.clone(), offer.issuer.clone());
            ensure!(!UserIssuerIndex::<T>::contains_key(&ui_key), Error::<T>::UserAlreadyHasCertFromIssuer);
            Self::enforce_challenge_deadline_issuer(&offer.issuer, now);
            let issuer_rec = Issuers::<T>::get(&offer.issuer).ok_or(Error::<T>::NotAnIssuer)?;
            let issuer_cert = CertLookupHot::<T>::get(issuer_rec.cert_thumbprint).ok_or(Error::<T>::CertNotFound)?;
            ensure!(now < issuer_cert.expiry_block, Error::<T>::CertExpired);
            Self::enforce_challenge_deadline_root(&issuer_rec.root, now);
            let root_rec = Roots::<T>::get(&issuer_rec.root).ok_or(Error::<T>::NotARoot)?;
            let root_cert = CertLookupHot::<T>::get(root_rec.cert_thumbprint).ok_or(Error::<T>::CertNotFound)?;
            ensure!(now < root_cert.expiry_block, Error::<T>::CertExpired);
            let expiry_block = now.saturating_add(offer.ttl_blocks);
            ensure!(expiry_block <= issuer_cert.expiry_block, Error::<T>::ExpiryExceedsParent);

            // Template re-check at mint. The issuer may have discarded
            // the referenced template between offer and mint; that
            // signals they no longer stand behind this class and the
            // mint must fail so the user doesn't end up with a cert
            // whose policy is already orphaned. We hold the template
            // record for PoP enforcement and the issued_count bump below.
            let template = CertTemplates::<T>::get(&offer.issuer, &offer.template_name)
                .ok_or(Error::<T>::TemplateNotFound)?;

            // TODO-3 binding-proof verification. The verified result
            // carries everything we need to write the cert record —
            // the cert_ec pubkey, the EK hash for dedup, the
            // attestation type, and the manufacturer-verified flag.
            // Offer-nonce-is-challenge: `contract_nonce` is passed
            // directly; no derivation.
            let verified = T::BindingProofVerifier::verify(
                &attestation_payload,
                &contract_nonce,
                offer.created_at.unique_saturated_into(),
                offer.expiry_block.unique_saturated_into(),
            )
            .map_err(|_| Error::<T>::AttestationInvalid)?;

            ensure!(verified.cert_ec_pubkey.is_valid(), Error::<T>::InvalidPublicKey);

            let att_type = verified.attestation_type.clone();
            let ek_hash = verified.ek_hash;
            let device_pubkey = verified.cert_ec_pubkey.clone();

            // PoP enforcement per the template's declared policy. A
            // template marked Required accepts only AttestationType::Tpm;
            // NotRequired waives the check entirely.
            if matches!(template.pop_requirement, PopRequirement::Required)
                && att_type != AttestationType::Tpm
            {
                return Err(Error::<T>::PopRequired.into());
            }

            // HIP genesis recording. For PoP templates we require a
            // `CanonicalHipProof` and verify it internally (no prior
            // fingerprint to compare against at genesis). The
            // returned fingerprint is pinned onto the Cold record so
            // future HIP-gated extrinsics have a baseline. Non-PoP
            // templates accept `None` and don't record anything.
            let genesis_fingerprint: Option<GenesisHardwareFingerprint> =
                if matches!(template.pop_requirement, PopRequirement::Required) {
                    let proof = hip_proof_at_genesis
                        .as_ref()
                        .ok_or(Error::<T>::HipProofRequired)?;
                    // Verify the proof's crypto before recording anything.
                    // Same call for both Tpm2 and StrongBox variants —
                    // dispatch lives inside the hip crate.
                    zk_pki_hip::verify_hip_proof_internal(proof)
                        .map_err(|_| Error::<T>::HipProofInvalid)?;
                    // Derive a matching genesis fingerprint variant.
                    // StrongBox's RootOfTrust / patch fields are `None`
                    // this pass — X.509 chain parsing is deferred to
                    // the seal-break taxonomy session, at which point
                    // the mint path will populate real values and the
                    // compare logic will begin enforcing them.
                    Some(match proof {
                        CanonicalHipProof::Tpm2(p) => {
                            GenesisHardwareFingerprint::Tpm2(Tpm2GenesisFingerprint {
                                flavor: p.flavor,
                                ek_hash: p.ek_hash,
                                aik_public_hash: sp_io::hashing::blake2_256(
                                    p.aik_public.as_slice(),
                                ),
                                pcr_values: p.pcr_values.clone(),
                                schema_version: CURRENT_SCHEMA_VERSION,
                            })
                        }
                        CanonicalHipProof::StrongBox(p) => {
                            let mut binding_input = [0u8; 64];
                            binding_input[..32].copy_from_slice(&p.hmac_binding_output);
                            binding_input[32..].copy_from_slice(&p.nonce);
                            GenesisHardwareFingerprint::StrongBox(
                                StrongBoxGenesisFingerprint {
                                    cert_ec_public_hash: sp_io::hashing::blake2_256(
                                        &p.cert_ec_public,
                                    ),
                                    attest_ec_public_hash: sp_io::hashing::blake2_256(
                                        &p.attest_ec_public,
                                    ),
                                    hmac_binding_commitment:
                                        sp_io::hashing::blake2_256(&binding_input),
                                    root_of_trust: None,
                                    os_patch_level: None,
                                    boot_patch_level: None,
                                    vendor_patch_level: None,
                                    schema_version: CURRENT_SCHEMA_VERSION,
                                },
                            )
                        }
                    })
                } else {
                    None
                };

            // ── Mime-wrap PoP path (Android StrongBox tier) ──
            //
            // Validate the `commitment_c` / `ec_key_pub_claimed`
            // arguments against the template's `pop_mechanism`,
            // platform-gate the mechanism against the attestation
            // chain, derive ec_key_pub from the verified cert pubkey,
            // and assert the equality tripwire (Paseo phase, option
            // B). On success, the pair is stored in
            // `MimeWrapCommitments` after the thumbprint is
            // computed below.
            //
            // The match below also rejects cross-tier requests:
            // a HipSigned template with a StrongBox proof, or a
            // MimeWrap template with a Tpm2 proof, fail before any
            // state changes.
            let mime_wrap_pair: Option<([u8; 32], [u8; 32])> =
                match template.pop_mechanism {
                    Some(PopMechanism::MimeWrap) => {
                        // Required: commitment_c and ec_key_pub_claimed.
                        let commitment = commitment_c
                            .ok_or(Error::<T>::MimeWrapCommitmentRequired)?;
                        let claimed = ec_key_pub_claimed
                            .ok_or(Error::<T>::MimeWrapCommitmentRequired)?;

                        // Platform gate. MimeWrap permitted only on
                        // StrongBox; Tpm2 is a category error.
                        let platform = hip_proof_at_genesis
                            .as_ref()
                            .map(HipPlatform::from_proof)
                            .ok_or(Error::<T>::HipProofRequired)?;
                        ensure!(
                            matches!(platform, HipPlatform::StrongBox),
                            Error::<T>::MimeWrapNotPermittedOnTpm2,
                        );

                        // Tripwire: re-derive ec_key_pub from the
                        // verified device pubkey and assert equality
                        // with the client-supplied value. Mismatch
                        // means dotwave/pallet canonicalization specs
                        // have drifted, or the caller is attempting
                        // to bind a fake ec_key_pub to a real cert.
                        let derived = crate::mime_wrap::derive_ec_key_pub_p256(
                            device_pubkey.key_bytes.as_slice(),
                        )
                        .ok_or(Error::<T>::MimeWrapEcKeyPubMismatch)?;
                        ensure!(
                            derived == claimed,
                            Error::<T>::MimeWrapEcKeyPubMismatch,
                        );

                        Some((commitment, derived))
                    }
                    Some(PopMechanism::HipSigned) => {
                        // HipSigned permitted only on Tpm2; StrongBox
                        // would re-introduce the HMAC-binding
                        // weakness MimeWrap was designed to mask.
                        let platform = hip_proof_at_genesis
                            .as_ref()
                            .map(HipPlatform::from_proof)
                            .ok_or(Error::<T>::HipProofRequired)?;
                        ensure!(
                            !matches!(platform, HipPlatform::StrongBox),
                            Error::<T>::HipSignedNotPermittedOnStrongBox,
                        );
                        // Mime-wrap fields not applicable on this
                        // path; surface explicitly rather than
                        // silently dropping them.
                        ensure!(
                            commitment_c.is_none() && ec_key_pub_claimed.is_none(),
                            Error::<T>::MimeWrapCommitmentNotApplicable,
                        );
                        None
                    }
                    None => {
                        // Non-PoP template: no mechanism, no mime-wrap
                        // fields permitted.
                        ensure!(
                            commitment_c.is_none() && ec_key_pub_claimed.is_none(),
                            Error::<T>::MimeWrapCommitmentNotApplicable,
                        );
                        None
                    }
                };

            // EK deduplication: only applies to PoP-eligible
            // (`AttestationType::Tpm`) certs. Packed or None verdicts
            // skip the registry entirely — they're explicitly not
            // hardware-bound identities, so minting a second Packed
            // cert with the same EK hash is not a duplication
            // violation.
            // Root-scoped lookup: the end-user cert is anchored
            // under `issuer_rec.root`, so that's the trust domain
            // whose EK registry we consult. Two different roots
            // certifying the same device is allowed by design.
            if att_type.is_pop_eligible() {
                ensure!(
                    !EkRegistry::<T>::contains_key(&issuer_rec.root, ek_hash),
                    Error::<T>::EkAlreadyRegistered,
                );
            }
            let ek_opt = if att_type.is_pop_eligible() { Some(ek_hash) } else { None };
            let canonical = CertCanonical {
                schema_version: CURRENT_SCHEMA_VERSION,
                root: issuer_rec.root.clone(), issuer: offer.issuer.clone(), user: who.clone(),
                user_pubkey: device_pubkey.clone(), registration_block: now, expiry: expiry_block,
                metadata: offer.metadata.clone(),
            };
            let thumbprint = Self::compute_thumbprint(&canonical);
            ensure!(!CertLookupHot::<T>::contains_key(thumbprint), Error::<T>::ThumbprintCollision);

            // ──────────── Fee system ────────────
            //
            // Full fee distribution for `mint_cert`. All other
            // cert-creation sites (register_root, issue_issuer_cert,
            // reissue, renew) take only `T::CertDeposit::get()`;
            // mint_cert is the only path that charges a tiered fee
            // AND derives the held deposit from it.
            //
            // Tier selection: PoP certs pay `MintFeePoP` (lowest —
            // the flagship use case); non-PoP Tpm and all Packed pay
            // `MintFeePacked`; no-attestation pays `MintFeeNone`
            // (highest — lowest trust).
            //
            // Distribution:
            //   protocol_fee    = mint_fee * ProtocolFeeBasisPoints
            //                     → transferred to ProtocolFeeRecipient
            //   deposit         = max(mint_fee * DepositBasisPoints,
            //                         MinDeposit)
            //                     → held under HoldReason::CertDeposit
            //                       on the minter's own account
            //   block_creator   = min(mint_fee - protocol_fee - deposit,
            //                         mint_fee * BlockCreatorCapBasisPoints)
            //                     → transferred to FindAuthor result
            //                       (skipped if no author or author=None)
            //   remainder       = mint_fee - protocol_fee - deposit
            //                     - block_creator_tip
            //                     → transferred to ProtocolFeeRecipient
            //
            // All four movements happen inside this atomic dispatch —
            // any `?` unwinds the whole mint.
            let mint_fee = Self::mint_fee_for(&att_type, &template.ekus);
            let protocol_fee = Self::bp_of(mint_fee, T::ProtocolFeeBasisPoints::get());
            let deposit_pct = Self::bp_of(mint_fee, T::DepositBasisPoints::get());
            let deposit = deposit_pct.max(T::MinDeposit::get());
            let creator_cap = Self::bp_of(mint_fee, T::BlockCreatorCapBasisPoints::get());
            let after_protocol_and_deposit = mint_fee
                .saturating_sub(protocol_fee)
                .saturating_sub(deposit);
            let block_creator_tip = after_protocol_and_deposit.min(creator_cap);
            let remainder = after_protocol_and_deposit.saturating_sub(block_creator_tip);

            let protocol_recipient = T::ProtocolFeeRecipient::get();

            // 1. Transfer the protocol-fee cut first. This also
            //    doubles as the up-front balance-sufficient check:
            //    if the user can't cover the protocol fee, the whole
            //    mint reverts before any storage is touched.
            if !protocol_fee.is_zero() {
                <T::Currency as Currency<T::AccountId>>::transfer(
                    &who,
                    &protocol_recipient,
                    protocol_fee,
                    ExistenceRequirement::KeepAlive,
                )?;
            }
            // 2. Place the hold.
            Self::hold_cert_deposit(&who, deposit)?;
            // 3. Tip the block author if FindAuthor returns one. `()`
            //    (the test wiring) returns None — mint still works,
            //    the tip just rolls into the remainder.
            let author_opt: Option<T::AccountId> =
                <T::FindAuthor as FindAuthor<T::AccountId>>::find_author(
                    core::iter::empty(),
                );
            let actual_block_tip = match (author_opt.as_ref(), block_creator_tip.is_zero()) {
                (Some(author), false) => {
                    <T::Currency as Currency<T::AccountId>>::transfer(
                        &who,
                        author,
                        block_creator_tip,
                        ExistenceRequirement::KeepAlive,
                    )?;
                    block_creator_tip
                }
                _ => BalanceOf::<T>::zero(),
            };
            // 4. Anything left (including the tip that wasn't paid
            //    because FindAuthor returned None) ships to the
            //    protocol recipient.
            let rollup_to_protocol = remainder.saturating_add(
                block_creator_tip.saturating_sub(actual_block_tip),
            );
            if !rollup_to_protocol.is_zero() {
                <T::Currency as Currency<T::AccountId>>::transfer(
                    &who,
                    &protocol_recipient,
                    rollup_to_protocol,
                    ExistenceRequirement::KeepAlive,
                )?;
            }

            CertLookupHot::<T>::insert(thumbprint, CertRecordHot {
                schema_version: CURRENT_SCHEMA_VERSION, thumbprint,
                root: issuer_rec.root.clone(), issuer: offer.issuer.clone(), user: who.clone(),
                mint_block: now, expiry_block, state: CertState::Active,
                ek_hash: ek_opt,
                attestation_type: att_type,
                manufacturer_verified: verified.manufacturer_verified,
                template_name: offer.template_name.clone(),
                ekus: template.ekus.clone(),
                // Inherit the template's PoP mechanism — pinned at
                // mint, never mutated. Drives `verify_pop_assertion`
                // dispatch later.
                pop_mechanism: template.pop_mechanism,
            });
            CertLookupCold::<T>::insert(thumbprint, CertRecordCold {
                thumbprint,
                cert_ec_pubkey: device_pubkey,
                deposit,
                genesis_os_version: None,
                genesis_os_patch_level: None,
                genesis_vendor_patch_level: None,
                genesis_boot_patch_level: None,
                suspension_reason: None,
                suspension_block: None,
                issuer_metadata: Some(offer.metadata.clone()),
                genesis_fingerprint,
            });
            if let Some(eh) = ek_opt {
                EkRegistry::<T>::insert(&issuer_rec.root, eh, thumbprint);
            }
            // Persist the mime-wrap binding pair if the template
            // selected MimeWrap. The pair was already validated
            // above (commitment_c provided, platform gate passed,
            // ec_key_pub tripwire matched), so this is a pure write.
            if let Some(pair) = mime_wrap_pair {
                MimeWrapCommitments::<T>::insert(thumbprint, pair);
                Self::deposit_event(Event::MimeWrapCommitmentRecorded { thumbprint });
            }
            UserIssuerIndex::<T>::insert(&ui_key, thumbprint);
            CertsByIssuer::<T>::insert(&offer.issuer, thumbprint, ());
            CertsByUser::<T>::insert(&who, thumbprint, ());
            CertsByRoot::<T>::insert(&issuer_rec.root, thumbprint, ());
            Self::push_to_expiry_index(expiry_block, thumbprint)?;
            ContractOffers::<T>::remove(contract_nonce);
            let offer_key = IssuerUserKey::new(offer.issuer.clone(), who.clone());
            OfferIndex::<T>::remove(&offer_key);
            T::Currency::unreserve(&offer.issuer, offer.deposit);
            OfferExpiryIndex::<T>::mutate(offer.expiry_block, |n| n.retain(|x| x != &contract_nonce));

            // Template accounting — lifetime counter (monotonic) and
            // the O(1) discard-safety counter. Both writes are in the
            // same execution as the cert insert above, so no partial
            // state is ever observable.
            CertTemplates::<T>::mutate(&offer.issuer, &offer.template_name, |maybe| {
                if let Some(tpl) = maybe.as_mut() {
                    tpl.issued_count = tpl.issued_count.saturating_add(1);
                }
            });
            TemplateActiveCertCount::<T>::mutate(&offer.issuer, &offer.template_name, |c| {
                *c = c.saturating_add(1);
            });

            Self::deposit_event(Event::CertMinted { thumbprint, user: who, issuer: offer.issuer });
            Ok(())
        }

        /// Issuer suspends an end-user cert.
        #[pallet::call_index(4)]
        #[pallet::weight(T::WeightInfo::suspend_cert())]
        pub fn suspend_cert(origin: OriginFor<T>, thumbprint: Thumbprint, reason: Option<BoundedVec<u8, ConstU32<MAX_SUSPENSION_REASON_LEN>>>) -> DispatchResult {
            let issuer = ensure_signed(origin)?;
            let now = <frame_system::Pallet<T>>::block_number();
            CertLookupHot::<T>::try_mutate(thumbprint, |maybe| -> DispatchResult {
                let rec = maybe.as_mut().ok_or(Error::<T>::CertNotFound)?;
                ensure!(rec.issuer == issuer, Error::<T>::NotCertIssuer);
                ensure!(!Issuers::<T>::contains_key(&rec.user), Error::<T>::IssuerCertCannotBeSuspended);
                ensure!(rec.state.is_active(), Error::<T>::AlreadySuspended);
                rec.state = CertState::Suspended;
                Ok(())
            })?;
            // Cold: record suspension reason + block so reactivation can
            // find the right PurgeIndex slot to unschedule from.
            CertLookupCold::<T>::try_mutate(thumbprint, |maybe| -> DispatchResult {
                let cold = maybe.as_mut().ok_or(Error::<T>::CertNotFound)?;
                cold.suspension_reason = reason;
                cold.suspension_block = Some(now);
                Ok(())
            })?;
            // Schedule purge. Under the new design, active certs are
            // NOT in the PurgeIndex; they're in the ExpiryIndex only.
            // We leave the ExpiryIndex entry alone — when the cert
            // hits expiry, on_initialize will skip flipping it since
            // it's already Suspended.
            let purge_block = now.saturating_add(T::InactivePurgePeriod::get());
            Self::push_to_purge_index(purge_block, thumbprint)?;
            Self::deposit_event(Event::CertSuspended { thumbprint, issuer });
            Ok(())
        }

        /// Issuer reactivates a suspended cert.
        #[pallet::call_index(5)]
        #[pallet::weight(T::WeightInfo::reactivate_cert())]
        pub fn reactivate_cert(origin: OriginFor<T>, thumbprint: Thumbprint) -> DispatchResult {
            let issuer = ensure_signed(origin)?;
            let now = <frame_system::Pallet<T>>::block_number();
            // Read Cold to recover the suspension block — needed to
            // locate the PurgeIndex slot scheduled by suspend_cert.
            let cold = CertLookupCold::<T>::get(thumbprint).ok_or(Error::<T>::CertNotFound)?;
            let suspension_block = cold.suspension_block.ok_or(Error::<T>::AlreadyActive)?;
            CertLookupHot::<T>::try_mutate(thumbprint, |maybe| -> DispatchResult {
                let rec = maybe.as_mut().ok_or(Error::<T>::CertNotFound)?;
                ensure!(rec.issuer == issuer, Error::<T>::NotCertIssuer);
                ensure!(rec.state.is_suspended(), Error::<T>::AlreadyActive);
                ensure!(now < rec.expiry_block, Error::<T>::CertExpired);
                rec.state = CertState::Active;
                Ok(())
            })?;
            CertLookupCold::<T>::mutate(thumbprint, |maybe| {
                if let Some(c) = maybe.as_mut() {
                    c.suspension_reason = None;
                    c.suspension_block = None;
                }
            });
            // Unschedule purge — compute the slot from suspension_block.
            let scheduled = suspension_block.saturating_add(T::InactivePurgePeriod::get());
            PurgeIndex::<T>::mutate(scheduled, |e| e.retain(|t| t != &thumbprint));
            Self::deposit_event(Event::CertReactivated { thumbprint, issuer });
            Ok(())
        }

        /// Issuer invalidates a cert.
        #[pallet::call_index(6)]
        #[pallet::weight(T::WeightInfo::invalidate_cert())]
        pub fn invalidate_cert(origin: OriginFor<T>, thumbprint: Thumbprint) -> DispatchResult {
            let issuer = ensure_signed(origin)?;
            let rec = CertLookupHot::<T>::get(thumbprint).ok_or(Error::<T>::CertNotFound)?;
            ensure!(rec.issuer == issuer, Error::<T>::NotCertIssuer);
            let cold = CertLookupCold::<T>::get(thumbprint)
                .ok_or(Error::<T>::CertColdRecordMissing)?;
            let user = rec.user.clone();
            let deposit = cold.deposit;
            Self::remove_cert_entry(thumbprint, &rec);
            Self::release_cert_deposit(&user, deposit)?;
            Self::deposit_event(Event::CertInvalidated { thumbprint });
            Ok(())
        }

        /// User self-discards their own cert. Two-tier model:
        ///
        /// - **Standard path** — caller passes a `PopAssertion`
        ///   proving control of the cert keypair + live hardware
        ///   integrity. Emits `CertSelfDiscarded`.
        /// - **Recovery path** — caller passes `None` for
        ///   `pop_assertion`. SS58 ownership is the sole
        ///   authorization (the Substrate keypair already signed
        ///   the tx; knowing the exact thumbprint is the soft
        ///   second factor). Emits `CertSelfDiscardedRecovery`
        ///   so reputation scoring and issuer-side re-KYC audit
        ///   can see the discard happened without hardware attest.
        ///
        /// Non-PoP certs (no `ProofOfPersonhood` EKU) always use
        /// the recovery path — the cert never had hardware-bound
        /// identity guarantees to assert.
        #[pallet::call_index(7)]
        #[pallet::weight(T::WeightInfo::self_discard_cert())]
        pub fn self_discard_cert(
            origin: OriginFor<T>,
            cert_thumbprint: Thumbprint,
            pop_assertion: Option<PopAssertion>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let hot = CertLookupHot::<T>::get(cert_thumbprint)
                .ok_or(Error::<T>::CertNotFound)?;
            // SS58 ownership check gates both paths.
            ensure!(hot.user == who, Error::<T>::NotCertHolder);
            let cold = CertLookupCold::<T>::get(cert_thumbprint)
                .ok_or(Error::<T>::CertColdRecordMissing)?;

            let recovery_discard = match pop_assertion {
                Some(assertion) => {
                    // Standard path — the call's canonical data is
                    // the SCALE-encoded thumbprint (the assertion's
                    // signature can't sign itself, so it's excluded
                    // from the call_data tuple).
                    let call_data = cert_thumbprint.encode();
                    Self::verify_pop_assertion(&assertion, &call_data)?;
                    false
                }
                None => true,
            };

            let deposit = cold.deposit;
            Self::remove_cert_entry(cert_thumbprint, &hot);
            Self::release_cert_deposit(&who, deposit)?;

            if recovery_discard {
                Self::deposit_event(Event::CertSelfDiscardedRecovery {
                    thumbprint: cert_thumbprint,
                    holder: who,
                    block: <frame_system::Pallet<T>>::block_number(),
                });
            } else {
                Self::deposit_event(Event::CertSelfDiscarded {
                    thumbprint: cert_thumbprint,
                    holder: who,
                });
            }
            Ok(())
        }

        /// Root invalidates an issuer. Administrative authority persists after cert expiry.
        #[pallet::call_index(8)]
        #[pallet::weight(T::WeightInfo::invalidate_issuer())]
        pub fn invalidate_issuer(origin: OriginFor<T>, issuer: T::AccountId) -> DispatchResult {
            let root_addr = ensure_signed(origin)?;
            let root_rec = Roots::<T>::get(&root_addr).ok_or(Error::<T>::NotARoot)?;
            if root_rec.state.is_compromised() {
                Self::deposit_event(Event::CompromisedEntityAction { entity: root_addr.clone(), action: ActionType::InvalidatedIssuer });
            }
            Issuers::<T>::try_mutate(&issuer, |maybe| -> DispatchResult {
                let rec = maybe.as_mut().ok_or(Error::<T>::NotAnIssuer)?;
                ensure!(rec.root == root_addr, Error::<T>::NotARoot);
                ensure!(!rec.state.is_compromised(), Error::<T>::IssuerAlreadyCompromised);
                let now = <frame_system::Pallet<T>>::block_number();
                rec.state.transition(EntityState::Compromised { at_block: now }).map_err(|_| Error::<T>::IllegalStateTransition)?;
                IssuerCountPerRoot::<T>::mutate(&root_addr, |c| *c = c.saturating_sub(1));
                RootIssuers::<T>::mutate(&root_addr, |issuers| {
                    issuers.retain(|a| a != &issuer);
                });
                Self::deposit_event(Event::IssuerInvalidated { issuer: issuer.clone(), root: root_addr.clone(), at_block: now });
                Ok(())
            })
        }

        /// Governance-only: flag a root as compromised.
        #[pallet::call_index(9)]
        #[pallet::weight(T::WeightInfo::flag_root_compromised())]
        pub fn flag_root_compromised(origin: OriginFor<T>, root: T::AccountId) -> DispatchResult {
            ensure_root(origin)?;
            Roots::<T>::try_mutate(&root, |maybe| -> DispatchResult {
                let rec = maybe.as_mut().ok_or(Error::<T>::NotARoot)?;
                ensure!(!rec.state.is_compromised(), Error::<T>::RootAlreadyCompromised);
                let now = <frame_system::Pallet<T>>::block_number();
                rec.state.transition(EntityState::Compromised { at_block: now }).map_err(|_| Error::<T>::IllegalStateTransition)?;
                Self::deposit_event(Event::RootFlaggedCompromised { root: root.clone(), at_block: now });
                Ok(())
            })
        }

        /// Issuer-initiated atomic reissuance. Reserve first, remove second (#2).
        #[pallet::call_index(10)]
        #[pallet::weight(T::WeightInfo::reissue_cert())]
        pub fn reissue_cert(
            origin: OriginFor<T>, old_thumbprint: Thumbprint, new_device_pubkey: DevicePublicKey,
            new_attestation: BoundedVec<u8, ConstU32<MAX_ATTESTATION_LEN>>,
            new_ttl_blocks: BlockNumberFor<T>, new_metadata: BoundedVec<u8, ConstU32<MAX_METADATA_LEN>>,
        ) -> DispatchResult {
            let issuer_addr = ensure_signed(origin)?;
            ensure!(new_device_pubkey.is_valid(), Error::<T>::InvalidPublicKey);
            let now = <frame_system::Pallet<T>>::block_number();
            Self::enforce_challenge_deadline_issuer(&issuer_addr, now);
            let issuer_rec = Issuers::<T>::get(&issuer_addr).ok_or(Error::<T>::NotAnIssuer)?;
            ensure!(!issuer_rec.state.is_compromised(), Error::<T>::IssuerPermanentlyCompromised);
            ensure!(
                issuer_rec.can_issue() || issuer_rec.state.is_compromised(),
                Error::<T>::InvalidEntityState
            );
            let issuer_cert = CertLookupHot::<T>::get(issuer_rec.cert_thumbprint).ok_or(Error::<T>::CertNotFound)?;
            ensure!(now < issuer_cert.expiry_block, Error::<T>::CertExpired);
            // Full root chain check (#5)
            Self::enforce_challenge_deadline_root(&issuer_rec.root, now);
            let root_rec = Roots::<T>::get(&issuer_rec.root).ok_or(Error::<T>::NotARoot)?;
            let root_cert = CertLookupHot::<T>::get(root_rec.cert_thumbprint).ok_or(Error::<T>::CertNotFound)?;
            ensure!(now < root_cert.expiry_block, Error::<T>::CertExpired);
            let old_rec = CertLookupHot::<T>::get(old_thumbprint).ok_or(Error::<T>::CertNotFound)?;
            ensure!(old_rec.issuer == issuer_addr, Error::<T>::NotCertIssuer);
            let new_expiry = now.saturating_add(new_ttl_blocks);
            ensure!(new_expiry <= issuer_cert.expiry_block, Error::<T>::ExpiryExceedsParent);
            // TPM attestation verification for new key (validates pubkey is valid curve point)
            let challenge = sp_io::hashing::blake2_256(&(old_rec.user.clone(), now).encode());
            let (new_ek_hash_raw, att_type) = T::Attestation::verify(&new_attestation, &new_device_pubkey, &challenge)
                .map_err(|_| Error::<T>::AttestationInvalid)?;
            // Root-scoped dedup under the cert's existing root.
            if att_type.is_pop_eligible() {
                ensure!(
                    !EkRegistry::<T>::contains_key(&old_rec.root, new_ek_hash_raw),
                    Error::<T>::EkAlreadyRegistered,
                );
            }
            let new_ek_hash: Option<EkHash> = if att_type.is_pop_eligible() { Some(new_ek_hash_raw) } else { None };
            let canonical = CertCanonical {
                schema_version: CURRENT_SCHEMA_VERSION,
                root: old_rec.root.clone(), issuer: issuer_addr.clone(), user: old_rec.user.clone(),
                user_pubkey: new_device_pubkey.clone(), registration_block: now, expiry: new_expiry,
                metadata: new_metadata.clone(),
            };
            let new_thumbprint = Self::compute_thumbprint(&canonical);
            ensure!(!CertLookupHot::<T>::contains_key(new_thumbprint), Error::<T>::ThumbprintCollision);
            let new_deposit = T::CertDeposit::get();
            // #2 — hold first. If fails, nothing touched.
            Self::hold_cert_deposit(&issuer_addr, new_deposit)?;
            let old_cold = CertLookupCold::<T>::get(old_thumbprint)
                .ok_or(Error::<T>::CertColdRecordMissing)?;
            Self::remove_cert_entry(old_thumbprint, &old_rec);
            Self::release_cert_deposit(&old_rec.user, old_cold.deposit)?;
            CertLookupHot::<T>::insert(new_thumbprint, CertRecordHot {
                schema_version: CURRENT_SCHEMA_VERSION, thumbprint: new_thumbprint,
                root: old_rec.root.clone(), issuer: issuer_addr.clone(), user: old_rec.user.clone(),
                mint_block: now, expiry_block: new_expiry, state: CertState::Active,
                ek_hash: new_ek_hash, attestation_type: att_type, manufacturer_verified: false,
                template_name: BoundedVec::default(),
                ekus: BoundedVec::default(),
                // Reissue path preserves the original cert's PoP
                // mechanism — replacing a cert under issuer
                // authority shouldn't silently change which
                // mechanism the holder must continue to satisfy.
                pop_mechanism: old_rec.pop_mechanism,
            });
            CertLookupCold::<T>::insert(new_thumbprint, CertRecordCold {
                thumbprint: new_thumbprint,
                cert_ec_pubkey: new_device_pubkey,
                deposit: new_deposit,
                genesis_os_version: None,
                genesis_os_patch_level: None,
                genesis_vendor_patch_level: None,
                genesis_boot_patch_level: None,
                suspension_reason: None,
                suspension_block: None,
                issuer_metadata: Some(new_metadata),
                genesis_fingerprint: None,
            });
            if let Some(eh) = new_ek_hash {
                EkRegistry::<T>::insert(&old_rec.root, eh, new_thumbprint);
            }
            UserIssuerIndex::<T>::insert(&UserIssuerKey::new(old_rec.user.clone(), issuer_addr.clone()), new_thumbprint);
            CertsByIssuer::<T>::insert(&issuer_addr, new_thumbprint, ());
            CertsByUser::<T>::insert(&old_rec.user, new_thumbprint, ());
            CertsByRoot::<T>::insert(&old_rec.root, new_thumbprint, ());
            Self::push_to_expiry_index(new_expiry, new_thumbprint)?;
            Self::deposit_event(Event::CertReissued { old_thumbprint, new_thumbprint, issuer: issuer_addr });
            Ok(())
        }

        /// Permissionless cleanup: anyone can reap a cert that is in a
        /// reapable state. The deposit is always released from the
        /// original cert holder's reserve; by default it goes back to
        /// the holder's free balance. The caller may redirect the
        /// deposit to any account by passing `deposit_recipient` —
        /// useful when Dotwave resolves an RNS name to an SS58 address
        /// client-side and passes that through.
        ///
        /// Reapable conditions (any of):
        /// 1. `!cert.is_active()` AND current block has passed the
        ///    grace period (`expiry_block + InactivePurgePeriod`).
        /// 2. Orphaned Cold record — Hot is gone but Cold still
        ///    lingers. Pure data-integrity fallback.
        ///
        /// Compromise status of the issuer or root is **not** a
        /// reapable trigger. Compromise is a reputation signal for
        /// relying parties, not a cert-lifecycle event; users retain
        /// the full grace window to self-discard and recover their
        /// deposit regardless of trust-chain state. Same flow for
        /// everyone.
        #[pallet::call_index(13)]
        #[pallet::weight(T::WeightInfo::cleanup())]
        pub fn cleanup(
            origin: OriginFor<T>,
            thumbprint: Thumbprint,
            deposit_recipient: Option<T::AccountId>,
        ) -> DispatchResult {
            let caller = ensure_signed(origin)?;
            let now = <frame_system::Pallet<T>>::block_number();

            let cert_hot_opt = CertLookupHot::<T>::get(thumbprint);
            let cert_cold_opt = CertLookupCold::<T>::get(thumbprint);

            let reapable = match (&cert_hot_opt, &cert_cold_opt) {
                // Condition 2 — Hot is gone but Cold wasn't cleaned up.
                (None, Some(_)) => true,
                (Some(cert), _) => {
                    // Condition 1 — inactive past grace period.
                    !cert.is_active()
                        && now >= cert.expiry_block.saturating_add(T::InactivePurgePeriod::get())
                }
                // Nothing to reap.
                (None, None) => false,
            };
            ensure!(reapable, Error::<T>::CertNotReapable);

            // Orphaned-cold path — no Hot, no deposit held, just wipe Cold.
            let Some(cert) = cert_hot_opt else {
                CertLookupCold::<T>::remove(thumbprint);
                Self::deposit_event(Event::CertReaped {
                    thumbprint,
                    reaped_by: caller.clone(),
                    deposit_recipient: caller,
                });
                return Ok(());
            };

            let holder = cert.user.clone();
            let recipient = deposit_recipient.unwrap_or_else(|| holder.clone());

            // Unschedule any PurgeIndex slot still pointing at this
            // thumbprint. Slot anchor is `suspension_block` when set
            // (suspended or expired-rolled-over), else falls back to
            // `expiry_block`. Mutating a non-existent slot is a no-op,
            // so this is safe for conditions 3/4 where no PurgeIndex
            // entry exists.
            let purge_slot_anchor = cert_cold_opt
                .as_ref()
                .and_then(|c| c.suspension_block)
                .unwrap_or(cert.expiry_block);
            let purge_slot = purge_slot_anchor.saturating_add(T::InactivePurgePeriod::get());
            PurgeIndex::<T>::mutate(purge_slot, |v| v.retain(|t| t != &thumbprint));

            let deposit = cert_cold_opt
                .as_ref()
                .map(|c| c.deposit)
                .unwrap_or_else(|| T::CertDeposit::get());

            Self::remove_cert_entry(thumbprint, &cert);

            // Deposit routing. Always release/transfer from the
            // original holder's hold slot. If recipient == holder,
            // release back to free balance; otherwise transfer the
            // held amount directly to the recipient's free balance.
            if recipient == holder {
                Self::release_cert_deposit(&holder, deposit)?;
            } else {
                Self::transfer_cert_deposit_on_hold(&holder, &recipient, deposit)?;
            }

            Self::deposit_event(Event::CertReaped {
                thumbprint,
                reaped_by: caller,
                deposit_recipient: recipient,
            });
            Ok(())
        }

        /// Root or issuer renews their cert. Old cert → retired state with successor binding.
        /// Same keypair, new cert, extended validity window.
        /// Old keypair signs the new cert's thumbprint; the binding is verified
        /// via `verify_successor_sig` on both the root-renewal and issuer-renewal paths.
        /// Issuer renewal before expiry re-anchors end users automatically.
        #[pallet::call_index(11)]
        #[pallet::weight(T::WeightInfo::renew_cert())]
        pub fn renew_cert(
            origin: OriginFor<T>,
            new_device_pubkey: DevicePublicKey,
            attestation: BoundedVec<u8, ConstU32<MAX_ATTESTATION_LEN>>,
            new_ttl_blocks: BlockNumberFor<T>,
            successor_signature: BoundedVec<u8, ConstU32<MAX_ATTESTATION_LEN>>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(new_device_pubkey.is_valid(), Error::<T>::InvalidPublicKey);
            let now = <frame_system::Pallet<T>>::block_number();

            // TPM attestation for new key
            let challenge = sp_io::hashing::blake2_256(&(who.clone(), now).encode());
            let (renewal_ek_hash, renewal_att_type) = T::Attestation::verify(&attestation, &new_device_pubkey, &challenge)
                .map_err(|_| Error::<T>::AttestationInvalid)?;
            let renewal_ek_opt = if renewal_att_type.is_pop_eligible() { Some(renewal_ek_hash) } else { None };

            // Determine if caller is a root or issuer
            let is_root = Roots::<T>::contains_key(&who);
            let is_issuer = Issuers::<T>::contains_key(&who);
            ensure!(is_root || is_issuer, Error::<T>::InvalidEntityState);

            if is_root {
                Self::enforce_challenge_deadline_root(&who, now);
                let root_rec = Roots::<T>::get(&who).ok_or(Error::<T>::NotARoot)?;
                ensure!(!root_rec.state.is_compromised(), Error::<T>::RootPermanentlyCompromised);
                ensure!(root_rec.can_issue(), Error::<T>::InvalidEntityState);

                // Root cert must not be expired yet (renewal before expiry)
                let old_cert = CertLookupHot::<T>::get(root_rec.cert_thumbprint)
                    .ok_or(Error::<T>::CertNotFound)?;
                ensure!(now < old_cert.expiry_block, Error::<T>::CertExpired);

                // TTL cap
                ensure!(new_ttl_blocks <= T::MaxRootTtlBlocks::get(), Error::<T>::TtlExceedsRootMax);
                ensure!(new_ttl_blocks >= T::MinRootTtlBlocks::get(), Error::<T>::TtlBelowMinimum);

                let expiry_block = now.saturating_add(new_ttl_blocks);
                let canonical = CertCanonical {
                    schema_version: CURRENT_SCHEMA_VERSION,
                    root: who.clone(), issuer: who.clone(), user: who.clone(),
                    user_pubkey: new_device_pubkey.clone(), registration_block: now,
                    expiry: expiry_block,
                    metadata: BoundedVec::<u8, ConstU32<MAX_METADATA_LEN>>::default(),
                };
                let new_thumbprint = Self::compute_thumbprint(&canonical);
                ensure!(!CertLookupHot::<T>::contains_key(new_thumbprint), Error::<T>::ThumbprintCollision);

                // Successor binding: old keypair signs the new thumbprint.
                // `verify_successor_sig` reads the Cold row for the pubkey.
                ensure!(
                    old_cert.ek_hash.is_none() || // NoopVerifier / non-PoP: skip sig check
                    Self::verify_successor_sig(&root_rec.cert_thumbprint, &new_thumbprint, &successor_signature),
                    Error::<T>::SuccessorSignatureInvalid
                );

                let deposit = T::CertDeposit::get();
                Self::hold_cert_deposit(&who, deposit)?;

                CertLookupHot::<T>::insert(new_thumbprint, CertRecordHot {
                    schema_version: CURRENT_SCHEMA_VERSION, thumbprint: new_thumbprint,
                    root: who.clone(), issuer: who.clone(), user: who.clone(),
                    mint_block: now, expiry_block, state: CertState::Active,
                    ek_hash: renewal_ek_opt, attestation_type: renewal_att_type.clone(), manufacturer_verified: false,
                    template_name: BoundedVec::default(),
                    ekus: BoundedVec::default(),
                    // Root renewal — root certs aren't templated.
                    pop_mechanism: None,
                });
                CertLookupCold::<T>::insert(new_thumbprint, CertRecordCold {
                    thumbprint: new_thumbprint,
                    cert_ec_pubkey: new_device_pubkey.clone(),
                    deposit,
                    genesis_os_version: None,
                    genesis_os_patch_level: None,
                    genesis_vendor_patch_level: None,
                    genesis_boot_patch_level: None,
                    suspension_reason: None,
                    suspension_block: None,
                    issuer_metadata: None,
                    genesis_fingerprint: None,
                });
                if let Some(eh) = renewal_ek_opt {
                    EkRegistry::<T>::insert(&who, eh, new_thumbprint);
                }
                CertsByIssuer::<T>::insert(&who, new_thumbprint, ());
                CertsByUser::<T>::insert(&who, new_thumbprint, ());
                CertsByRoot::<T>::insert(&who, new_thumbprint, ());
                Self::push_to_expiry_index(expiry_block, new_thumbprint)?;

                // Strict X.509: no retired records. Old cert stays in lookup table until purged.
                let old_thumbprint = root_rec.cert_thumbprint;

                // Update active root record
                Roots::<T>::insert(&who, RootRecord {
                    proxy: root_rec.proxy,
                    cert_thumbprint: new_thumbprint,
                    registered_at: now,
                    state: EntityState::Active,
                    challenge_used: root_rec.challenge_used,
                    capability_ekus: root_rec.capability_ekus,
                });

                Self::deposit_event(Event::CertRenewed {
                    entity: who, old_thumbprint, new_thumbprint,
                });
            } else {
                // Issuer renewal
                Self::enforce_challenge_deadline_issuer(&who, now);
                let issuer_rec = Issuers::<T>::get(&who).ok_or(Error::<T>::NotAnIssuer)?;
                ensure!(!issuer_rec.state.is_compromised(), Error::<T>::IssuerPermanentlyCompromised);
                ensure!(issuer_rec.can_issue(), Error::<T>::InvalidEntityState);

                let old_cert = CertLookupHot::<T>::get(issuer_rec.cert_thumbprint)
                    .ok_or(Error::<T>::CertNotFound)?;
                ensure!(now < old_cert.expiry_block, Error::<T>::CertExpired);

                // Root cert must still be valid
                Self::enforce_challenge_deadline_root(&issuer_rec.root, now);
                let root_rec = Roots::<T>::get(&issuer_rec.root).ok_or(Error::<T>::NotARoot)?;
                let root_cert = CertLookupHot::<T>::get(root_rec.cert_thumbprint)
                    .ok_or(Error::<T>::CertNotFound)?;
                ensure!(now < root_cert.expiry_block, Error::<T>::CertExpired);

                // Axis of evil: surface if root is compromised
                if root_rec.state.is_compromised() {
                    Self::deposit_event(Event::CompromisedEntityAction {
                        entity: issuer_rec.root.clone(),
                        action: ActionType::IssuedCert,
                    });
                }

                // Issuer TTL cannot exceed root's remaining validity
                let expiry_block = now.saturating_add(new_ttl_blocks);
                ensure!(expiry_block <= root_cert.expiry_block, Error::<T>::ExpiryExceedsParent);
                ensure!(new_ttl_blocks >= T::MinIssuerTtlBlocks::get(), Error::<T>::TtlBelowMinimum);

                let canonical = CertCanonical {
                    schema_version: CURRENT_SCHEMA_VERSION,
                    root: issuer_rec.root.clone(), issuer: issuer_rec.root.clone(), user: who.clone(),
                    user_pubkey: new_device_pubkey.clone(), registration_block: now,
                    expiry: expiry_block,
                    metadata: BoundedVec::<u8, ConstU32<MAX_METADATA_LEN>>::default(),
                };
                let new_thumbprint = Self::compute_thumbprint(&canonical);
                ensure!(!CertLookupHot::<T>::contains_key(new_thumbprint), Error::<T>::ThumbprintCollision);

                // Successor binding — pubkey sourced from Cold row.
                ensure!(
                    old_cert.ek_hash.is_none() ||
                    Self::verify_successor_sig(&issuer_rec.cert_thumbprint, &new_thumbprint, &successor_signature),
                    Error::<T>::SuccessorSignatureInvalid
                );

                let deposit = T::CertDeposit::get();
                Self::hold_cert_deposit(&who, deposit)?;

                CertLookupHot::<T>::insert(new_thumbprint, CertRecordHot {
                    schema_version: CURRENT_SCHEMA_VERSION, thumbprint: new_thumbprint,
                    root: issuer_rec.root.clone(), issuer: issuer_rec.root.clone(), user: who.clone(),
                    mint_block: now, expiry_block, state: CertState::Active,
                    ek_hash: renewal_ek_opt, attestation_type: renewal_att_type.clone(), manufacturer_verified: false,
                    template_name: BoundedVec::default(),
                    ekus: BoundedVec::default(),
                    // Issuer renewal — issuer certs aren't templated.
                    pop_mechanism: None,
                });
                CertLookupCold::<T>::insert(new_thumbprint, CertRecordCold {
                    thumbprint: new_thumbprint,
                    cert_ec_pubkey: new_device_pubkey.clone(),
                    deposit,
                    genesis_os_version: None,
                    genesis_os_patch_level: None,
                    genesis_vendor_patch_level: None,
                    genesis_boot_patch_level: None,
                    suspension_reason: None,
                    suspension_block: None,
                    issuer_metadata: None,
                    genesis_fingerprint: None,
                });
                if let Some(eh) = renewal_ek_opt {
                    EkRegistry::<T>::insert(&issuer_rec.root, eh, new_thumbprint);
                }
                CertsByIssuer::<T>::insert(&issuer_rec.root, new_thumbprint, ());
                CertsByUser::<T>::insert(&who, new_thumbprint, ());
                CertsByRoot::<T>::insert(&issuer_rec.root, new_thumbprint, ());
                Self::push_to_expiry_index(expiry_block, new_thumbprint)?;

                // Strict X.509: no retired records. Old cert stays in lookup until purged.
                let old_thumbprint = issuer_rec.cert_thumbprint;

                // Update active issuer record
                Issuers::<T>::insert(&who, IssuerRecord {
                    root: issuer_rec.root,
                    proxy: issuer_rec.proxy,
                    cert_thumbprint: new_thumbprint,
                    registered_at: now,
                    state: EntityState::Active,
                    challenge_used: issuer_rec.challenge_used,
                    capability_ekus: issuer_rec.capability_ekus,
                });

                Self::deposit_event(Event::CertRenewed {
                    entity: who, old_thumbprint, new_thumbprint,
                });
            }

            Ok(())
        }

        /// Root voluntarily deregisters. Cascades to issuers (invalidated, deposits returned).
        /// End-user certs untouched — users self-discard. Root deposit reclaimed.
        /// Clean exit: re-registration allowed. Tainted (compromised): permanently blocked.
        #[pallet::call_index(12)]
        #[pallet::weight(T::WeightInfo::deregister_root())]
        pub fn deregister_root(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let root_rec = Roots::<T>::get(&who).ok_or(Error::<T>::NotARoot)?;

            let tainted = root_rec.state.is_compromised()
                || root_rec.state.is_challenged()
                || root_rec.challenge_used;
            let now = <frame_system::Pallet<T>>::block_number();

            // Cascade to issuers via secondary index — bounded by MaxIssuersPerRoot
            let issuers_to_remove = RootIssuers::<T>::take(&who);

            for issuer_addr in issuers_to_remove.iter() {
                // Clean exit: remove issuer record entirely. Address is free to
                // re-register under a new root. Reputation tracks address lineage.
                if let Some(issuer_rec) = Issuers::<T>::take(issuer_addr) {
                    if let Some(cert) = CertLookupHot::<T>::get(issuer_rec.cert_thumbprint) {
                        let issuer_deposit = CertLookupCold::<T>::get(
                            issuer_rec.cert_thumbprint,
                        )
                        .map(|c| c.deposit)
                        .unwrap_or_else(|| T::CertDeposit::get());
                        Self::remove_cert_entry(issuer_rec.cert_thumbprint, &cert);
                        // The issuer cert's deposit was held on the
                        // root account at `issue_issuer_cert` time
                        // (the root is the signer — the issuer hasn't
                        // transacted yet at issuance). Release it
                        // back to the same root on clean exit.
                        Self::release_cert_deposit(&who, issuer_deposit)?;
                    }
                }
                Self::deposit_event(Event::IssuerInvalidated {
                    issuer: issuer_addr.clone(),
                    root: who.clone(),
                    at_block: now,
                });
            }

            // Remove root cert and return deposit
            if let Some(root_cert) = CertLookupHot::<T>::get(root_rec.cert_thumbprint) {
                let root_deposit = CertLookupCold::<T>::get(root_rec.cert_thumbprint)
                    .map(|c| c.deposit)
                    .unwrap_or_else(|| T::CertDeposit::get());
                Self::remove_cert_entry(root_rec.cert_thumbprint, &root_cert);
                Self::release_cert_deposit(&who, root_deposit)?;
            }

            Roots::<T>::remove(&who);
            // #10 — clean up IssuerCountPerRoot entirely
            IssuerCountPerRoot::<T>::remove(&who);

            DeregisteredRoots::<T>::insert(&who, DeregistrationRecord {
                at_block: now,
                tainted,
            });

            Self::deposit_event(Event::RootDeregistered { root: who });
            Ok(())
        }

        /// Flagged entity (root or issuer) contests a compromise flag. 45-day window.
        /// Only callable by the compromised entity itself.
        #[pallet::call_index(14)]
        #[pallet::weight(T::WeightInfo::challenge_compromise())]
        pub fn challenge_compromise(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let now = <frame_system::Pallet<T>>::block_number();
            let deadline = now.saturating_add(T::ChallengeWindowBlocks::get());

            let is_root = Roots::<T>::contains_key(&who);
            let is_issuer = Issuers::<T>::contains_key(&who);
            ensure!(is_root || is_issuer, Error::<T>::InvalidEntityState);

            if is_root {
                Roots::<T>::try_mutate(&who, |maybe| -> DispatchResult {
                    let rec = maybe.as_mut().ok_or(Error::<T>::NotARoot)?;
                    ensure!(rec.state.is_compromised(), Error::<T>::NotCompromised);
                    ensure!(!rec.challenge_used, Error::<T>::ChallengeAlreadyUsed);
                    rec.state.transition(EntityState::Challenge { challenged_at: now, deadline })
                        .map_err(|_| Error::<T>::IllegalStateTransition)?;
                    Ok(())
                })?;
            } else {
                Issuers::<T>::try_mutate(&who, |maybe| -> DispatchResult {
                    let rec = maybe.as_mut().ok_or(Error::<T>::NotAnIssuer)?;
                    ensure!(rec.state.is_compromised(), Error::<T>::NotCompromised);
                    ensure!(!rec.challenge_used, Error::<T>::ChallengeAlreadyUsed);
                    rec.state.transition(EntityState::Challenge { challenged_at: now, deadline })
                        .map_err(|_| Error::<T>::IllegalStateTransition)?;
                    Ok(())
                })?;
            }

            Self::deposit_event(Event::ChallengeInitiated { entity: who, deadline });
            Ok(())
        }

        /// Governance resolves a challenge. Restores to Active or confirms Compromised.
        #[pallet::call_index(15)]
        #[pallet::weight(T::WeightInfo::resolve_challenge())]
        pub fn resolve_challenge(
            origin: OriginFor<T>,
            entity: T::AccountId,
            restore: bool,
        ) -> DispatchResult {
            ensure_root(origin)?;
            let now = <frame_system::Pallet<T>>::block_number();

            let is_root = Roots::<T>::contains_key(&entity);
            let is_issuer = Issuers::<T>::contains_key(&entity);
            ensure!(is_root || is_issuer, Error::<T>::InvalidEntityState);

            if is_root {
                Roots::<T>::try_mutate(&entity, |maybe| -> DispatchResult {
                    let rec = maybe.as_mut().ok_or(Error::<T>::NotARoot)?;
                    ensure!(rec.state.is_challenged(), Error::<T>::NoChallengeToResolve);
                    if restore {
                        rec.state.transition(EntityState::Active)
                            .map_err(|_| Error::<T>::IllegalStateTransition)?;
                    } else {
                        rec.state.transition(EntityState::Compromised { at_block: now })
                            .map_err(|_| Error::<T>::IllegalStateTransition)?;
                        rec.challenge_used = true;
                    }
                    Ok(())
                })?;
            } else {
                Issuers::<T>::try_mutate(&entity, |maybe| -> DispatchResult {
                    let rec = maybe.as_mut().ok_or(Error::<T>::NotAnIssuer)?;
                    ensure!(rec.state.is_challenged(), Error::<T>::NoChallengeToResolve);
                    if restore {
                        rec.state.transition(EntityState::Active)
                            .map_err(|_| Error::<T>::IllegalStateTransition)?;
                    } else {
                        rec.state.transition(EntityState::Compromised { at_block: now })
                            .map_err(|_| Error::<T>::IllegalStateTransition)?;
                        rec.challenge_used = true;
                    }
                    Ok(())
                })?;
            }

            Self::deposit_event(Event::ChallengeResolved { entity, restored: restore });
            Ok(())
        }

        /// Issuer creates a new cert template. Immutable after creation
        /// except for `is_active` (deactivate) and `issued_count`
        /// (monotonic). Template names are unique within the caller's
        /// SS58 namespace; two different issuers may re-use the same
        /// name without collision.
        #[pallet::call_index(16)]
        #[pallet::weight(T::WeightInfo::create_cert_template())]
        // create_cert_template's `pop_mechanism` parameter MUST be
        // `Some(_)` exactly when `pop_requirement == Required`;
        // `None` otherwise. The pallet enforces this invariant in
        // the body, then enforces the platform gate (HipSigned ↔
        // Tpm2 / MimeWrap ↔ StrongBox) at every `mint_cert` against
        // the resulting template.
        pub fn create_cert_template(
            origin: OriginFor<T>,
            name: BoundedVec<u8, ConstU32<MAX_TEMPLATE_NAME_LEN>>,
            pop_requirement: PopRequirement,
            pop_mechanism: Option<PopMechanism>,
            max_ttl_blocks: u64,
            min_ttl_blocks: u64,
            max_certs: Option<u32>,
            metadata_schema:
                Option<BoundedVec<u8, ConstU32<MAX_TEMPLATE_METADATA_SCHEMA_LEN>>>,
            ekus: BoundedVec<Eku, ConstU32<MAX_TEMPLATE_EKUS>>,
        ) -> DispatchResult {
            let issuer_addr = ensure_signed(origin)?;
            let now = <frame_system::Pallet<T>>::block_number();

            Self::enforce_challenge_deadline_issuer(&issuer_addr, now);
            let issuer_rec = Issuers::<T>::get(&issuer_addr).ok_or(Error::<T>::NotAnIssuer)?;
            ensure!(issuer_rec.can_issue(), Error::<T>::InvalidEntityState);

            ensure!(
                !CertTemplates::<T>::contains_key(&issuer_addr, &name),
                Error::<T>::TemplateNameTaken,
            );
            ensure!(min_ttl_blocks < max_ttl_blocks, Error::<T>::TemplateInvalidTtlRange);

            // EKU validation. Hierarchical EKUs must appear in the
            // issuer's own capability set — issuers can only charter
            // templates for authorities they themselves hold. Standard
            // EKUs (ClientAuth, ServerAuth, etc.) fall through the
            // `requires_issuer_capability` gate since relying-party
            // trust for those is out of band.
            for eku in ekus.iter() {
                if eku.requires_issuer_capability() {
                    ensure!(
                        issuer_rec.capability_ekus.contains(eku),
                        Error::<T>::EkuNotAuthorized,
                    );
                }
            }
            // PoP-implying EKUs force the template's
            // `pop_requirement = Required`. Otherwise the template
            // would silently let non-Tpm certs carry a PoP EKU —
            // defeating the EKU's purpose.
            if ekus.iter().any(|e| e.implies_pop_required())
                && !matches!(pop_requirement, PopRequirement::Required)
            {
                return Err(Error::<T>::PopRequiredForEku.into());
            }

            // PoP requirement ↔ mechanism consistency.
            // `pop_mechanism` MUST be `Some(_)` exactly when
            // `pop_requirement == Required`; `None` exactly when
            // `NotRequired`. Mismatch is a template-config bug: a
            // Required template without a mechanism couldn't be
            // verified at sign time, and a NotRequired template
            // with a mechanism would carry a setting that's never
            // consulted.
            match (&pop_requirement, &pop_mechanism) {
                (PopRequirement::Required, Some(_)) => {}
                (PopRequirement::NotRequired, None) => {}
                _ => return Err(Error::<T>::PopMechanismMismatch.into()),
            }

            let issuer_cert = CertLookupHot::<T>::get(issuer_rec.cert_thumbprint)
                .ok_or(Error::<T>::CertNotFound)?;
            ensure!(now < issuer_cert.expiry_block, Error::<T>::CertExpired);
            let issuer_remaining_ttl: u64 = issuer_cert
                .expiry_block
                .saturating_sub(now)
                .unique_saturated_into();
            ensure!(
                max_ttl_blocks <= issuer_remaining_ttl,
                Error::<T>::TemplateTtlExceedsIssuerCert,
            );

            IssuerTemplateNames::<T>::try_mutate(&issuer_addr, |names| -> DispatchResult {
                ensure!(
                    (names.len() as u32) < T::MaxTemplatesPerIssuer::get(),
                    Error::<T>::TooManyTemplates,
                );
                names
                    .try_push(name.clone())
                    .map_err(|_| Error::<T>::TooManyTemplates)?;
                Ok(())
            })?;

            let deposit = T::TemplateDeposit::get();
            T::Currency::reserve(&issuer_addr, deposit)
                .map_err(|_| Error::<T>::InsufficientDeposit)?;

            CertTemplates::<T>::insert(
                &issuer_addr,
                &name,
                CertTemplate {
                    issuer: issuer_addr.clone(),
                    name: name.clone(),
                    created_at_block: now,
                    pop_requirement,
                    pop_mechanism,
                    max_ttl_blocks,
                    min_ttl_blocks,
                    max_certs,
                    issued_count: 0,
                    deposit,
                    metadata_schema,
                    is_active: true,
                    ekus,
                },
            );

            Self::deposit_event(Event::TemplateCreated { issuer: issuer_addr, name });
            Ok(())
        }

        /// Issuer deactivates a template. No new offers may reference
        /// it, but existing certs remain valid until their own
        /// expiry. Deposit is NOT released until `discard_cert_template`.
        #[pallet::call_index(17)]
        #[pallet::weight(T::WeightInfo::deactivate_cert_template())]
        pub fn deactivate_cert_template(
            origin: OriginFor<T>,
            name: BoundedVec<u8, ConstU32<MAX_TEMPLATE_NAME_LEN>>,
        ) -> DispatchResult {
            let issuer_addr = ensure_signed(origin)?;
            CertTemplates::<T>::try_mutate(
                &issuer_addr,
                &name,
                |maybe| -> DispatchResult {
                    let tpl = maybe.as_mut().ok_or(Error::<T>::TemplateNotFound)?;
                    ensure!(tpl.is_active, Error::<T>::TemplateAlreadyInactive);
                    tpl.is_active = false;
                    Ok(())
                },
            )?;
            Self::deposit_event(Event::TemplateDeactivated { issuer: issuer_addr, name });
            Ok(())
        }

        /// Issuer discards a deactivated template. Blocked while any
        /// active cert references it — the O(1) check reads
        /// `TemplateActiveCertCount` rather than scanning `CertsByIssuer`.
        /// Deposit released back to the issuer on success.
        #[pallet::call_index(18)]
        #[pallet::weight(T::WeightInfo::discard_cert_template())]
        pub fn discard_cert_template(
            origin: OriginFor<T>,
            name: BoundedVec<u8, ConstU32<MAX_TEMPLATE_NAME_LEN>>,
        ) -> DispatchResult {
            let issuer_addr = ensure_signed(origin)?;
            let tpl = CertTemplates::<T>::get(&issuer_addr, &name)
                .ok_or(Error::<T>::TemplateNotFound)?;
            ensure!(!tpl.is_active, Error::<T>::TemplateStillActive);
            ensure!(
                TemplateActiveCertCount::<T>::get(&issuer_addr, &name) == 0,
                Error::<T>::TemplateHasActiveCerts,
            );

            CertTemplates::<T>::remove(&issuer_addr, &name);
            TemplateActiveCertCount::<T>::remove(&issuer_addr, &name);
            IssuerTemplateNames::<T>::mutate(&issuer_addr, |names| {
                names.retain(|n| n != &name);
            });
            T::Currency::unreserve(&issuer_addr, tpl.deposit);

            Self::deposit_event(Event::TemplateDiscarded { issuer: issuer_addr, name });
            Ok(())
        }

        /// Install (or rotate) the mime-wrap circuit's verifying key.
        ///
        /// **PoC trust model:** any signed account may set the VK.
        /// This is acceptable on Paseo because the chain's state is
        /// disposable and the VK can be re-installed at any time;
        /// it is NOT acceptable on production. The mainnet wiring
        /// MUST route this through a governance origin (collective
        /// approval / referendum / sudo-equivalent) — express that
        /// via runtime config rather than hardcoding here, since the
        /// pallet shouldn't bake in a specific governance scheme.
        ///
        /// Idempotent: re-installing the same bytes is a no-op
        /// modulo a fresh `MimeWrapVkSet` event. Rotation invalidates
        /// every previously-issued mime-wrap proof for every
        /// MimeWrap cert on chain — proofs were generated against
        /// the old VK's circuit, which no longer matches.
        #[pallet::call_index(19)]
        #[pallet::weight(T::WeightInfo::set_mime_wrap_vk())]
        pub fn set_mime_wrap_vk(
            origin: OriginFor<T>,
            vk: sp_std::vec::Vec<u8>,
        ) -> DispatchResult {
            let _who = ensure_signed(origin)?;
            ensure!(
                vk.len() <= MAX_MIME_WRAP_VK_BYTES as usize,
                Error::<T>::MimeWrapVkTooLong,
            );
            let bounded: BoundedVec<u8, ConstU32<MAX_MIME_WRAP_VK_BYTES>> = vk
                .try_into()
                .map_err(|_| Error::<T>::MimeWrapVkTooLong)?;
            MimeWrapVk::<T>::put(bounded);
            Self::deposit_event(Event::MimeWrapVkSet);
            Ok(())
        }
    }

    // ---------------------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------------------

    impl<T: Config> Pallet<T> {
        pub fn compute_thumbprint(
            canonical: &CertCanonical<T::AccountId, BlockNumberFor<T>, BoundedVec<u8, ConstU32<MAX_METADATA_LEN>>>,
        ) -> Thumbprint {
            sp_io::hashing::blake2_256(&canonical.encode())
        }

        /// Place the `CertDeposit` hold on `who` for `amount`.
        /// `fungible::MutateHold::hold` returns an error if the free
        /// balance is insufficient — bubbles up as a dispatch error.
        pub(crate) fn hold_cert_deposit(
            who: &T::AccountId,
            amount: BalanceOf<T>,
        ) -> DispatchResult {
            <T::Currency as MutateHold<T::AccountId>>::hold(
                &HoldReason::CertDeposit.into(),
                who,
                amount,
            )
        }

        /// Release `amount` of the `CertDeposit` hold on `who` back
        /// to their free balance. `Precision::Exact` — the release
        /// must drain exactly `amount`; if less is on hold, the call
        /// errors. Callers pass the per-cert `deposit` field from
        /// `CertRecordCold` so the amounts always match.
        pub(crate) fn release_cert_deposit(
            who: &T::AccountId,
            amount: BalanceOf<T>,
        ) -> DispatchResult {
            <T::Currency as MutateHold<T::AccountId>>::release(
                &HoldReason::CertDeposit.into(),
                who,
                amount,
                Precision::Exact,
            )
            .map(|_| ())
        }

        /// Transfer `amount` of held cert-deposit from `from` to
        /// `to`, keeping it on hold on neither side — lands in
        /// `to`'s free balance. Used by `cleanup` to pay the
        /// permissionless caller who reaps an orphan cert.
        pub(crate) fn transfer_cert_deposit_on_hold(
            from: &T::AccountId,
            to: &T::AccountId,
            amount: BalanceOf<T>,
        ) -> DispatchResult {
            <T::Currency as MutateHold<T::AccountId>>::transfer_on_hold(
                &HoldReason::CertDeposit.into(),
                from,
                to,
                amount,
                Precision::Exact,
                Restriction::Free,
                Fortitude::Polite,
            )
            .map(|_| ())
        }

        /// Resolve the mint fee for a cert being created under a
        /// given attestation verdict and template. PoP-eligible
        /// (Tpm + ProofOfPersonhood EKU) is the lowest tier; Tpm
        /// without PoP or Packed is mid; None is top.
        pub(crate) fn mint_fee_for(
            att_type: &AttestationType,
            ekus: &BoundedVec<Eku, ConstU32<MAX_TEMPLATE_EKUS>>,
        ) -> BalanceOf<T> {
            match att_type {
                AttestationType::Tpm if ekus.contains(&Eku::ProofOfPersonhood) => {
                    T::MintFeePoP::get()
                }
                AttestationType::Tpm | AttestationType::Packed => T::MintFeePacked::get(),
                AttestationType::None => T::MintFeeNone::get(),
            }
        }

        /// Basis-point math: `amount * bp / 10_000`, saturating.
        /// Handled via `UniqueSaturatedInto<u128>` to avoid overflow
        /// at any realistic balance size. Returns zero if amount or
        /// bp is zero.
        pub(crate) fn bp_of(amount: BalanceOf<T>, bp: u32) -> BalanceOf<T> {
            let amount_u128: u128 = amount.unique_saturated_into();
            let scaled = amount_u128.saturating_mul(bp as u128) / 10_000u128;
            BalanceOf::<T>::unique_saturated_from(scaled)
        }

        /// Validate full trust chain and enforce challenge deadlines. Mutates state.
        /// Strict X.509 NotAfter — every link in the chain must be valid NOW.
        /// No retired cert walkback. If the issuer or root cert is expired, the chain is broken.
        /// Short-circuits for root self-signed certs.
        pub fn validate_and_enforce_chain(
            thumbprint: Thumbprint, now: BlockNumberFor<T>,
        ) -> Result<CertRecordHot<T::AccountId, BlockNumberFor<T>>, Error<T>> {
            let rec = CertLookupHot::<T>::get(thumbprint).ok_or(Error::<T>::CertNotFound)?;
            ensure!(rec.state.is_active(), Error::<T>::AlreadySuspended);
            ensure!(now < rec.expiry_block, Error::<T>::CertExpired);

            // Root self-signed cert: skip chain walk
            if rec.root == rec.issuer && rec.issuer == rec.user { return Ok(rec); }

            // Issuer chain
            Self::enforce_challenge_deadline_issuer(&rec.issuer, now);
            let issuer_rec = Issuers::<T>::get(&rec.issuer).ok_or(Error::<T>::NotAnIssuer)?;
            let issuer_cert = CertLookupHot::<T>::get(issuer_rec.cert_thumbprint)
                .ok_or(Error::<T>::CertNotFound)?;
            ensure!(now < issuer_cert.expiry_block, Error::<T>::CertExpired);

            // Root chain
            Self::enforce_challenge_deadline_root(&issuer_rec.root, now);
            let root_rec = Roots::<T>::get(&issuer_rec.root).ok_or(Error::<T>::NotARoot)?;
            let root_cert = CertLookupHot::<T>::get(root_rec.cert_thumbprint)
                .ok_or(Error::<T>::CertNotFound)?;
            ensure!(now < root_cert.expiry_block, Error::<T>::CertExpired);

            Ok(rec)
        }

        /// Verify a `PopAssertion` attached to an extrinsic.
        ///
        /// # CALLER-BINDING INVARIANT
        ///
        /// This function does **not** take `origin` and does not,
        /// on its own, bind the assertion to any specific caller.
        /// The `cert_ec_signature` covers
        /// `cert_thumbprint || parent_hash || call_data`, not the
        /// caller's `AccountId`. Caller binding is enforced **at
        /// the call site** via an explicit `hot.user == who` check
        /// (see `self_discard_cert` at the `NotCertHolder` ensure).
        ///
        /// Any future refactor that introduces third-party-initiated
        /// operations on PoP certs — delegated signing, relying-party
        /// dispatch, meta-transactions, a "discard on behalf of"
        /// flow — MUST either:
        ///   (a) pass `origin` through this function and verify
        ///       caller binding here, OR
        ///   (b) re-establish caller binding at the new call site
        ///       before invoking this function.
        ///
        /// Failing to maintain this invariant creates an instant
        /// cross-account discard primitive: an attacker who knows
        /// the thumbprint of any PoP cert could submit a crafted
        /// `PopAssertion` (via replayed or observed signatures) and
        /// discard a cert they do not own.
        ///
        /// Gates (all must pass):
        /// 1. Cert exists in `CertLookupHot` and is `Active`.
        /// 2. Cert carries the `ProofOfPersonhood` EKU (non-PoP
        ///    certs cannot assert identity).
        /// 3. `cert_ec_signature` verifies over
        ///    `blake2_256(call_data || nonce)` under the cert's
        ///    `cert_ec_pubkey` (stored on the Cold record).
        /// 4. Genesis fingerprint must be present on the Cold
        ///    record (PoP certs always have one; defensive check).
        /// 5. HIP proof verifies against the genesis fingerprint
        ///    AND binds to the caller-supplied nonce (closes
        ///    stale-proof replay).
        ///
        /// The `nonce` is derived from `parent_hash() ||
        /// cert_thumbprint || call_data` — client-computable
        /// before submission.
        fn verify_pop_assertion(
            assertion: &PopAssertion,
            call_data: &[u8],
        ) -> Result<(), Error<T>> {
            let cert_thumbprint = *assertion.cert_thumbprint();

            // 1 — Load Hot row, check active + PoP EKU.
            let hot = CertLookupHot::<T>::get(cert_thumbprint)
                .ok_or(Error::<T>::CertNotFound)?;
            ensure!(hot.state == CertState::Active, Error::<T>::CertNotActive);
            ensure!(
                hot.ekus.contains(&Eku::ProofOfPersonhood),
                Error::<T>::PopEkuRequired,
            );

            // 2 — Tier gate. The cert's pop_mechanism was pinned at
            //     mint based on the attestation chain platform. The
            //     submitted assertion variant MUST agree — cross-tier
            //     bypass guard, defense-in-depth on top of mint-time
            //     gating.
            match (hot.pop_mechanism, assertion) {
                (Some(PopMechanism::HipSigned), PopAssertion::HipSigned { .. }) => {}
                (Some(PopMechanism::MimeWrap), PopAssertion::MimeWrap { .. }) => {}
                _ => return Err(Error::<T>::PopMechanismMismatch),
            }

            // 3 — Cold row for genesis fingerprint (universal across
            //     both mechanisms). HipSigned also needs cert_ec_pubkey
            //     for the signature check.
            let cold = CertLookupCold::<T>::get(cert_thumbprint)
                .ok_or(Error::<T>::CertColdRecordMissing)?;

            match assertion {
                PopAssertion::HipSigned {
                    cert_thumbprint: _,
                    cert_ec_signature,
                    hip_proof,
                } => {
                    // 4 (HipSigned) — Derive nonce, verify ECDSA
                    //     signature, verify HIP against genesis.
                    let parent_hash = <frame_system::Pallet<T>>::parent_hash();
                    let parent_bytes: [u8; 32] = parent_hash
                        .as_ref()
                        .try_into()
                        .unwrap_or([0u8; 32]);
                    let nonce = derive_pop_nonce(
                        &parent_bytes,
                        &cert_thumbprint,
                        call_data,
                    );

                    let mut signed_input =
                        sp_std::vec::Vec::with_capacity(call_data.len() + 32);
                    signed_input.extend_from_slice(call_data);
                    signed_input.extend_from_slice(&nonce);
                    let signed_payload = sp_io::hashing::blake2_256(&signed_input);
                    if !cold.cert_ec_pubkey.verify_signature(
                        &signed_payload,
                        cert_ec_signature.as_slice(),
                    ) {
                        return Err(Error::<T>::CertEcSignatureInvalid);
                    }

                    let genesis = cold
                        .genesis_fingerprint
                        .ok_or(Error::<T>::GenesisFingerprintMissing)?;
                    zk_pki_hip::verify_hip_proof_against_genesis(
                        hip_proof,
                        &genesis,
                        &nonce,
                    )
                    .map_err(|_| Error::<T>::HipProofInvalid)?;
                }
                PopAssertion::MimeWrap {
                    cert_thumbprint: _,
                    bucket,
                    nonce: mw_nonce,
                    user_otp,
                    proof,
                    hip_proof,
                } => {
                    // 4 (MimeWrap) — Replay check first (cheap), then
                    //     load commitment + ec_key_pub + VK, run
                    //     Groth16 verify, then HIP against genesis.
                    //     Bucket-nonce key prevents the second
                    //     presentation of the same proof from passing
                    //     even if the pairing check still would.
                    ensure!(
                        !ConsumedMimeWrapNonces::<T>::contains_key((*bucket, *mw_nonce)),
                        Error::<T>::MimeWrapReplayRejected,
                    );

                    let (commitment_c, ec_key_pub) =
                        MimeWrapCommitments::<T>::get(cert_thumbprint)
                            .ok_or(Error::<T>::CertColdRecordMissing)?;
                    let vk_bounded = MimeWrapVk::<T>::get()
                        .ok_or(Error::<T>::MimeWrapVkNotSet)?;
                    let vk_bytes: &[u8] = vk_bounded.as_slice();

                    let ok = crate::mime_wrap::verify_mime_wrap(
                        proof.as_slice(),
                        vk_bytes,
                        &commitment_c,
                        &ec_key_pub,
                        *bucket,
                        *user_otp,
                    )
                    .map_err(|e| match e {
                        crate::mime_wrap::VerifyError::ProofMalformed =>
                            Error::<T>::MimeWrapProofMalformed,
                        crate::mime_wrap::VerifyError::VerifyingKeyMalformed =>
                            Error::<T>::MimeWrapVkMalformed,
                        crate::mime_wrap::VerifyError::PairingFailed =>
                            Error::<T>::MimeWrapProofInvalid,
                        crate::mime_wrap::VerifyError::OtpOutOfRange =>
                            Error::<T>::MimeWrapOtpOutOfRange,
                    })?;
                    ensure!(ok, Error::<T>::MimeWrapProofInvalid);

                    // Record the consumed (bucket, nonce) before
                    // moving to HIP verify so a HIP-failed retry
                    // still reuses the same nonce slot — the proof
                    // is single-use either way.
                    ConsumedMimeWrapNonces::<T>::insert((*bucket, *mw_nonce), ());

                    // HIP proof binds hardware-still-intact at
                    // sign time, derived from the StrongBox proof's
                    // own internal nonce (not the mime-wrap nonce —
                    // those are different freshness mechanisms).
                    let genesis = cold
                        .genesis_fingerprint
                        .ok_or(Error::<T>::GenesisFingerprintMissing)?;
                    let strongbox_nonce: [u8; 32] = match hip_proof {
                        CanonicalHipProof::StrongBox(p) => p.nonce,
                        // Mint-time platform gate prevents this — a
                        // MimeWrap cert can only have a StrongBox
                        // proof. Defensive surface as proof-invalid.
                        CanonicalHipProof::Tpm2(_) =>
                            return Err(Error::<T>::HipProofInvalid),
                    };
                    zk_pki_hip::verify_hip_proof_against_genesis(
                        hip_proof,
                        &genesis,
                        &strongbox_nonce,
                    )
                    .map_err(|_| Error::<T>::HipProofInvalid)?;

                    Self::deposit_event(Event::MimeWrapPopVerified {
                        thumbprint: cert_thumbprint,
                        bucket: *bucket,
                    });
                }
            }

            Ok(())
        }

        /// Verify successor binding: the old cert's stored public key
        /// must have signed the new thumbprint. The pubkey lives on
        /// the Cold record; pass in the old thumbprint and this
        /// helper reads the Cold row itself.
        fn verify_successor_sig(
            old_thumbprint: &Thumbprint,
            new_thumbprint: &Thumbprint,
            signature: &[u8],
        ) -> bool {
            match CertLookupCold::<T>::get(old_thumbprint) {
                Some(cold) => cold.cert_ec_pubkey.verify_signature(new_thumbprint, signature),
                None => false,
            }
        }

        fn enforce_challenge_deadline_issuer(issuer: &T::AccountId, now: BlockNumberFor<T>) {
            Issuers::<T>::mutate(issuer, |maybe| {
                if let Some(rec) = maybe.as_mut() {
                    if rec.state.is_deadline_passed(&now) {
                        let _ = rec.state.transition(EntityState::Compromised { at_block: now });
                    }
                }
            });
        }

        fn enforce_challenge_deadline_root(root: &T::AccountId, now: BlockNumberFor<T>) {
            Roots::<T>::mutate(root, |maybe| {
                if let Some(rec) = maybe.as_mut() {
                    if rec.state.is_deadline_passed(&now) {
                        let _ = rec.state.transition(EntityState::Compromised { at_block: now });
                    }
                }
            });
        }

        /// Full removal of a cert's storage footprint. Hot + Cold +
        /// secondary indexes + EK registry + UserIssuerIndex. Does
        /// NOT touch deposits — callers handle that separately since
        /// the destination depends on the path (cert holder on
        /// invalidate/self_discard/renewal; optional redirect on
        /// cleanup).
        ///
        /// Also decrements `TemplateActiveCertCount` when the cert
        /// was minted under a template (non-empty `template_name`).
        /// Root / issuer certs minted via `register_root` /
        /// `issue_issuer_cert` / `renew_cert` carry an empty
        /// `template_name` and skip this path — templates scope
        /// end-user mints only.
        fn remove_cert_entry(thumbprint: Thumbprint, rec: &CertRecordHot<T::AccountId, BlockNumberFor<T>>) {
            CertLookupHot::<T>::remove(thumbprint);
            CertLookupCold::<T>::remove(thumbprint);
            // Mime-wrap binding pair, if any. Stored only for
            // MimeWrap-mechanism certs at mint; safe `remove` for
            // others (no-op).
            MimeWrapCommitments::<T>::remove(thumbprint);
            if let Some(eh) = rec.ek_hash {
                EkRegistry::<T>::remove(&rec.root, eh);
            }
            UserIssuerIndex::<T>::remove(&UserIssuerKey::new(rec.user.clone(), rec.issuer.clone()));
            CertsByIssuer::<T>::remove(&rec.issuer, thumbprint);
            CertsByUser::<T>::remove(&rec.user, thumbprint);
            CertsByRoot::<T>::remove(&rec.root, thumbprint);
            // Expiry schedule — remove if still pending.
            ExpiryIndex::<T>::mutate(rec.expiry_block, |e| e.retain(|t| t != &thumbprint));
            if !rec.template_name.is_empty() {
                TemplateActiveCertCount::<T>::mutate(
                    &rec.issuer,
                    &rec.template_name,
                    |c| *c = c.saturating_sub(1),
                );
            }
        }

        /// Schedule a cert for expiry processing. Written at mint /
        /// reissue / renew. `on_initialize` consumes the slot when
        /// the block rolls over and flips state to Suspended.
        ///
        /// Each per-block `ExpiryIndex` slot holds at most 256
        /// entries. When the intended slot is full, this helper
        /// distributes the entry into the next available block
        /// within a `MAX_PURGE_LOOKAHEAD`-block window. If every
        /// slot in the window is full, the entry is NOT scheduled
        /// (a `PurgeScheduleSkipped` event fires as an
        /// observability signal) and the caller's extrinsic still
        /// succeeds — the cert is recoverable via `self_discard_cert`
        /// by the holder or `cleanup()` once past the grace period.
        /// Returning `DispatchResult` is preserved for backwards
        /// compatibility, but this function never returns `Err`.
        fn push_to_expiry_index(expiry_block: BlockNumberFor<T>, thumbprint: Thumbprint) -> DispatchResult {
            for k in 0..MAX_PURGE_LOOKAHEAD {
                let slot = expiry_block.saturating_add(
                    BlockNumberFor::<T>::unique_saturated_from(k),
                );
                let mut landed = false;
                ExpiryIndex::<T>::mutate(slot, |e| {
                    if e.try_push(thumbprint).is_ok() {
                        landed = true;
                    }
                });
                if landed {
                    return Ok(());
                }
            }
            Self::deposit_event(Event::PurgeScheduleSkipped {
                intended_block: expiry_block,
                kind: PurgeScheduleKind::Expiry,
            });
            Ok(())
        }

        /// Schedule a suspended cert for purge. Written by
        /// `suspend_cert` at `now + InactivePurgePeriod`. Unscheduled
        /// by `reactivate_cert`. Distribution semantics match
        /// `push_to_expiry_index` — see that helper for the
        /// overflow behavior.
        fn push_to_purge_index(purge_block: BlockNumberFor<T>, thumbprint: Thumbprint) -> DispatchResult {
            for k in 0..MAX_PURGE_LOOKAHEAD {
                let slot = purge_block.saturating_add(
                    BlockNumberFor::<T>::unique_saturated_from(k),
                );
                let mut landed = false;
                PurgeIndex::<T>::mutate(slot, |e| {
                    if e.try_push(thumbprint).is_ok() {
                        landed = true;
                    }
                });
                if landed {
                    return Ok(());
                }
            }
            Self::deposit_event(Event::PurgeScheduleSkipped {
                intended_block: purge_block,
                kind: PurgeScheduleKind::Purge,
            });
            Ok(())
        }

        /// Offer-expiry index scheduling — same semantics as the
        /// above, for expired contract offers. Distribution matches
        /// `push_to_expiry_index`.
        fn push_to_offer_expiry_index(expiry_block: BlockNumberFor<T>, nonce: [u8; 32]) -> DispatchResult {
            for k in 0..MAX_PURGE_LOOKAHEAD {
                let slot = expiry_block.saturating_add(
                    BlockNumberFor::<T>::unique_saturated_from(k),
                );
                let mut landed = false;
                OfferExpiryIndex::<T>::mutate(slot, |e| {
                    if e.try_push(nonce).is_ok() {
                        landed = true;
                    }
                });
                if landed {
                    return Ok(());
                }
            }
            Self::deposit_event(Event::PurgeScheduleSkipped {
                intended_block: expiry_block,
                kind: PurgeScheduleKind::OfferExpiry,
            });
            Ok(())
        }
    }

    // ---------------------------------------------------------------------------
    // Runtime API query implementations (TODO-5)
    //
    // Pure storage reads that back `zk_pki_primitives::runtime_api::ZkPkiApi`.
    // Each method is callable directly from tests inside test externalities
    // AND wrappable in `impl_runtime_apis!` when the workspace gets a full
    // node runtime. Keeping them on the pallet struct (not a free module)
    // lets them access all storage types without re-exports.
    //
    // Block numbers are surfaced as `u64` at the API boundary — the runtime
    // picks whatever BlockNumber type it likes internally; the RPC contract
    // stays stable.
    // ---------------------------------------------------------------------------

    impl<T: Config> Pallet<T> {
        /// Convert the on-chain `EntityState<BlockNumber>` (5 variants,
        /// generic) into the RPC projection (3 variants, non-generic).
        /// Retired / Deactivated collapse to Active because existing
        /// certs under those entities remain trust-valid — the
        /// distinction is internal renewal-bookkeeping only.
        fn entity_state_to_rpc(
            state: &EntityState<BlockNumberFor<T>>,
        ) -> (zk_pki_primitives::runtime_api::EntityState, Option<u64>)
        where
            BlockNumberFor<T>: UniqueSaturatedInto<u64>,
            BlockNumberFor<T>: Clone,
        {
            use zk_pki_primitives::runtime_api::EntityState as RpcEntity;
            match state {
                EntityState::Active
                | EntityState::Retired { .. }
                | EntityState::Deactivated { .. } => (RpcEntity::Active, None),
                EntityState::Challenge { .. } => (RpcEntity::Challenge, None),
                EntityState::Compromised { at_block } => (
                    RpcEntity::Compromised,
                    Some(at_block.clone().unique_saturated_into()),
                ),
            }
        }

        /// Shape a single cert record into a [`CertSummary`] for list
        /// endpoints. Derives `cert_state` from the on-chain state +
        /// expiry comparison. Reads Hot only.
        fn cert_summary(
            record: &CertRecordHot<T::AccountId, BlockNumberFor<T>>,
        ) -> zk_pki_primitives::runtime_api::CertSummary
        where
            BlockNumberFor<T>: UniqueSaturatedInto<u64>,
            BlockNumberFor<T>: Clone + PartialOrd,
        {
            use zk_pki_primitives::runtime_api::CertState as RpcCertState;
            let now = <frame_system::Pallet<T>>::block_number();
            let cert_state = match record.state {
                CertState::Active => {
                    if now > record.expiry_block {
                        RpcCertState::Expired
                    } else {
                        RpcCertState::Active
                    }
                }
                CertState::Suspended => RpcCertState::Suspended,
            };
            zk_pki_primitives::runtime_api::CertSummary {
                thumbprint: record.thumbprint,
                cert_state,
                expiry_block: record.expiry_block.clone().unique_saturated_into(),
                mint_block: record.mint_block.clone().unique_saturated_into(),
                attestation_type: record.attestation_type.clone(),
                manufacturer_verified: record.manufacturer_verified,
            }
        }

        /// Full `cert_status` query. Returns `None` if the thumbprint
        /// has no lookup entry (purged or never existed).
        pub fn query_cert_status(
            thumbprint: [u8; 32],
        ) -> Option<zk_pki_primitives::runtime_api::CertStatusResponse<T::AccountId>>
        where
            BlockNumberFor<T>: UniqueSaturatedInto<u64>,
            BlockNumberFor<T>: Clone + PartialOrd,
        {
            use zk_pki_primitives::runtime_api::{
                CertState as RpcCertState, CertStatusResponse, OcspStatus, RevocationReason,
            };
            let record = CertLookupHot::<T>::get(thumbprint)?;
            let now = <frame_system::Pallet<T>>::block_number();
            let now_u64: u64 = now.clone().unique_saturated_into();

            let cert_state = match record.state {
                CertState::Active => {
                    if now > record.expiry_block {
                        RpcCertState::Expired
                    } else {
                        RpcCertState::Active
                    }
                }
                CertState::Suspended => RpcCertState::Suspended,
            };
            let status = match cert_state {
                RpcCertState::Active => OcspStatus::Good,
                _ => OcspStatus::Revoked,
            };
            let (revocation_time, revocation_reason) = match cert_state {
                RpcCertState::Suspended => {
                    // Suspension block is now stored directly on the
                    // Cold record. Avoids the pre-split reconstruction
                    // trick of subtracting InactivePurgePeriod from
                    // purge_eligible_block.
                    let suspended_at = CertLookupCold::<T>::get(thumbprint)
                        .and_then(|c| c.suspension_block)
                        .map(|b| b.unique_saturated_into());
                    (suspended_at, Some(RevocationReason::Suspended))
                }
                RpcCertState::Expired => (
                    Some(record.expiry_block.clone().unique_saturated_into()),
                    Some(RevocationReason::Expired),
                ),
                _ => (None, None),
            };

            // Parent entity state — map on-chain → RPC projection.
            let (issuer_status, issuer_cab) = Issuers::<T>::get(&record.issuer)
                .map(|rec| Self::entity_state_to_rpc(&rec.state))
                .unwrap_or((
                    zk_pki_primitives::runtime_api::EntityState::Active,
                    None,
                ));
            let (root_status, root_cab) = Roots::<T>::get(&record.root)
                .map(|rec| Self::entity_state_to_rpc(&rec.state))
                .unwrap_or((
                    zk_pki_primitives::runtime_api::EntityState::Active,
                    None,
                ));

            let next_update =
                now.saturating_add(T::TtlCheckInterval::get()).unique_saturated_into();

            // Template projection — graceful when the issuer discarded
            // the template after the cert was minted. No panic, no
            // phantom default: `template_pop_requirement` goes to
            // `None` so relying parties can tell the difference and
            // fall back to `attestation_type == Tpm` if they need PoP
            // signal.
            let template_pop_requirement =
                if record.template_name.is_empty() {
                    None
                } else {
                    CertTemplates::<T>::get(&record.issuer, &record.template_name)
                        .map(|tpl| tpl.pop_requirement)
                };

            Some(CertStatusResponse {
                status,
                this_update: now_u64,
                next_update,
                revocation_time,
                revocation_reason,
                thumbprint,
                cert_state,
                expiry_block: record.expiry_block.clone().unique_saturated_into(),
                mint_block: record.mint_block.clone().unique_saturated_into(),
                issuer: record.issuer.clone(),
                issuer_status,
                issuer_compromised_at_block: issuer_cab,
                root: record.root.clone(),
                root_status,
                root_compromised_at_block: root_cab,
                attestation_type: record.attestation_type.clone(),
                manufacturer_verified: record.manufacturer_verified,
                ek_hash: record.ek_hash,
                template_name: record.template_name.clone(),
                template_pop_requirement,
                ekus: record.ekus.clone(),
            })
        }

        /// `cert_authentication` query. Returns the minimum info
        /// needed to authenticate an off-chain challenge-response
        /// signed by the cert's hardware-attested device key.
        ///
        /// Pulls `bound_account` + state from the hot record and
        /// `device_pubkey` from the cold record. Both records must
        /// exist; returns `None` if either is missing (purged /
        /// never existed).
        ///
        /// The `cert_state` projection mirrors the one in
        /// `query_cert_status`: an Active hot record past its
        /// expiry block reports as `Expired`, not `Active`.
        pub fn query_cert_authentication(
            thumbprint: [u8; 32],
        ) -> Option<zk_pki_primitives::runtime_api::CertAuthInfo<T::AccountId>>
        where
            BlockNumberFor<T>: UniqueSaturatedInto<u64>,
            BlockNumberFor<T>: Clone + PartialOrd,
        {
            use zk_pki_primitives::runtime_api::{CertAuthInfo, CertState as RpcCertState};
            let hot = CertLookupHot::<T>::get(thumbprint)?;
            let cold = CertLookupCold::<T>::get(thumbprint)?;
            let now = <frame_system::Pallet<T>>::block_number();
            let cert_state = match hot.state {
                CertState::Active => {
                    if now > hot.expiry_block {
                        RpcCertState::Expired
                    } else {
                        RpcCertState::Active
                    }
                }
                CertState::Suspended => RpcCertState::Suspended,
            };
            Some(CertAuthInfo {
                bound_account: hot.user.clone(),
                device_pubkey: cold.cert_ec_pubkey.clone(),
                cert_state,
                expiry_block: hot.expiry_block.clone().unique_saturated_into(),
            })
        }

        /// The cert's enrolled HIP genesis fingerprint, or `None` if the
        /// cert carries no HIP (non-PoP / dev-stub cert) or the thumbprint
        /// is unknown. Backing read for the `cert_hip_genesis` runtime API
        /// — the chat-auth session handshake verifies a fresh
        /// `CanonicalHipProof` against this baseline (device-state drift).
        pub fn query_cert_hip_genesis(
            thumbprint: [u8; 32],
        ) -> Option<zk_pki_primitives::hip::GenesisHardwareFingerprint> {
            CertLookupCold::<T>::get(thumbprint)?.genesis_fingerprint
        }

        /// Prefix-iterate the `CertsByIssuer` double map for this
        /// issuer. Trie prefix iteration scales with the number of
        /// matching entries, not the full cert table.
        pub fn query_certs_by_issuer(
            issuer: T::AccountId,
        ) -> sp_std::vec::Vec<zk_pki_primitives::runtime_api::CertSummary>
        where
            BlockNumberFor<T>: UniqueSaturatedInto<u64>,
            BlockNumberFor<T>: Clone + PartialOrd,
        {
            CertsByIssuer::<T>::iter_prefix(&issuer)
                .filter_map(|(thumbprint, ())| CertLookupHot::<T>::get(thumbprint))
                .map(|r| Self::cert_summary(&r))
                .collect()
        }

        pub fn query_certs_by_user(
            user: T::AccountId,
        ) -> sp_std::vec::Vec<zk_pki_primitives::runtime_api::CertSummary>
        where
            BlockNumberFor<T>: UniqueSaturatedInto<u64>,
            BlockNumberFor<T>: Clone + PartialOrd,
        {
            CertsByUser::<T>::iter_prefix(&user)
                .filter_map(|(thumbprint, ())| CertLookupHot::<T>::get(thumbprint))
                .map(|r| Self::cert_summary(&r))
                .collect()
        }

        pub fn query_certs_by_root(
            root: T::AccountId,
        ) -> sp_std::vec::Vec<zk_pki_primitives::runtime_api::CertSummary>
        where
            BlockNumberFor<T>: UniqueSaturatedInto<u64>,
            BlockNumberFor<T>: Clone + PartialOrd,
        {
            CertsByRoot::<T>::iter_prefix(&root)
                .filter_map(|(thumbprint, ())| CertLookupHot::<T>::get(thumbprint))
                .map(|r| Self::cert_summary(&r))
                .collect()
        }

        /// Entity status for a registered root or issuer.
        ///
        /// `cert_volume` and `invalidation_rate` are placeholders —
        /// neither count is currently maintained in pallet storage.
        /// Proper tracking requires dedicated counters on the root /
        /// issuer record; wiring them is out of TODO-5 scope.
        /// Returning 0 for both keeps the response schema stable for
        /// callers that just want the state + compromise-time
        /// signals, which ARE accurate.
        pub fn query_entity_status(
            address: T::AccountId,
        ) -> Option<zk_pki_primitives::runtime_api::EntityStatusResponse<T::AccountId>>
        where
            BlockNumberFor<T>: UniqueSaturatedInto<u64>,
            BlockNumberFor<T>: Clone,
        {
            use zk_pki_primitives::runtime_api::{EntityStatusResponse, EntityType};
            if let Some(rec) = Roots::<T>::get(&address) {
                let (state, cab) = Self::entity_state_to_rpc(&rec.state);
                return Some(EntityStatusResponse {
                    address,
                    entity_type: EntityType::Root,
                    state,
                    compromised_at_block: cab,
                    cert_volume: 0,
                    invalidation_rate: 0,
                });
            }
            if let Some(rec) = Issuers::<T>::get(&address) {
                let (state, cab) = Self::entity_state_to_rpc(&rec.state);
                return Some(EntityStatusResponse {
                    address,
                    entity_type: EntityType::Issuer,
                    state,
                    compromised_at_block: cab,
                    cert_volume: 0,
                    invalidation_rate: 0,
                });
            }
            None
        }

        /// EK registry lookup — root-scoped. Returns the active PoP
        /// thumbprint (if any) minted under `root`'s trust hierarchy
        /// for a device with EK hash `ek_hash`. Different roots are
        /// independent trust domains; the same device may hold active
        /// PoP certs under multiple roots concurrently, which is why
        /// this lookup requires both the trust domain and the device
        /// identifier.
        pub fn query_ek_lookup(
            root: T::AccountId,
            ek_hash: [u8; 32],
        ) -> Option<[u8; 32]> {
            EkRegistry::<T>::get(&root, ek_hash)
        }

        /// Was the cert valid at a specific historical block? True
        /// iff: record exists, minted by `block_number`, not yet
        /// expired at `block_number`, and no parent in the chain was
        /// compromised at or before `block_number`.
        pub fn query_chain_valid_at(thumbprint: [u8; 32], block_number: u64) -> bool
        where
            BlockNumberFor<T>: UniqueSaturatedInto<u64>,
            BlockNumberFor<T>: Clone + PartialOrd,
        {
            let Some(record) = CertLookupHot::<T>::get(thumbprint) else {
                return false;
            };
            let mint_u64: u64 = record.mint_block.clone().unique_saturated_into();
            let expiry_u64: u64 = record.expiry_block.clone().unique_saturated_into();
            if mint_u64 > block_number {
                return false;
            }
            if expiry_u64 < block_number {
                return false;
            }
            if let Some(iss) = Issuers::<T>::get(&record.issuer) {
                if let EntityState::Compromised { at_block } = iss.state {
                    let cab: u64 = at_block.unique_saturated_into();
                    if cab <= block_number {
                        return false;
                    }
                }
            }
            if let Some(rt) = Roots::<T>::get(&record.root) {
                if let EntityState::Compromised { at_block } = rt.state {
                    let cab: u64 = at_block.unique_saturated_into();
                    if cab <= block_number {
                        return false;
                    }
                }
            }
            true
        }

        /// Public-API gate used by sibling pallets that need to
        /// confirm the holder of a HW cert is still in good standing
        /// AND the device's current boot state still matches the
        /// genesis fingerprint recorded at cert mint. Closes the
        /// "device compromised between cert mint and the
        /// caller-extrinsic's submission" window — without this, the
        /// only thing the chain knows is "cert was minted on a
        /// genuine device some time ago," which is too weak for
        /// PoP-grade trust.
        ///
        /// Used by `pallet-rostro-personhood::mint_pop` to gate
        /// PoP-cert issuance on a fresh device-state attestation.
        /// May be useful to other future pallets that want the same
        /// "still-genuine-now" check (e.g., validator
        /// slash-on-rejoin).
        ///
        /// Errors map exactly the same as zkpki's own internal
        /// PopAssertion::HipSigned path, so callers translate them
        /// uniformly.
        pub fn verify_active_cert_and_hip(
            thumbprint: Thumbprint,
            expected_user: &T::AccountId,
            hip_proof: &CanonicalHipProof,
            challenge_nonce: &[u8; 32],
        ) -> Result<(), Error<T>> {
            let hot = CertLookupHot::<T>::get(thumbprint).ok_or(Error::<T>::CertNotFound)?;
            if &hot.user != expected_user {
                return Err(Error::<T>::NotCertHolder);
            }
            if !hot.is_active() {
                return Err(Error::<T>::CertNotActive);
            }
            let now = <frame_system::Pallet<T>>::block_number();
            if now > hot.expiry_block {
                return Err(Error::<T>::CertExpired);
            }
            let cold =
                CertLookupCold::<T>::get(thumbprint).ok_or(Error::<T>::CertColdRecordMissing)?;
            let genesis = cold
                .genesis_fingerprint
                .ok_or(Error::<T>::GenesisFingerprintMissing)?;
            zk_pki_hip::verify_hip_proof_against_genesis(hip_proof, &genesis, challenge_nonce)
                .map_err(|_| Error::<T>::HipProofInvalid)?;
            Ok(())
        }
    }

    // ---------------------------------------------------------------------------
    // Storage types
    // ---------------------------------------------------------------------------

    /// Hot record — small, always-read projection. Used by chain
    /// walks, validity checks, and common RPC responses. Does NOT
    /// carry the device pubkey, suspension metadata, or attestation
    /// OS-state fields — those live in `CertRecordCold`.
    #[derive(Encode, Decode, Clone, PartialEq, Eq, TypeInfo, MaxEncodedLen)]
    #[cfg_attr(feature = "std", derive(Debug))]
    #[scale_info(skip_type_params(AccountId, BlockNumber))]
    pub struct CertRecordHot<AccountId, BlockNumber> {
        pub schema_version: SchemaVersion,
        pub thumbprint: Thumbprint,
        pub root: AccountId,
        pub issuer: AccountId,
        pub user: AccountId,
        pub mint_block: BlockNumber,
        pub expiry_block: BlockNumber,
        pub state: CertState,
        pub ek_hash: Option<EkHash>,
        pub attestation_type: AttestationType,
        /// Set when the TODO-3 `verify_binding_proof` confirmed the
        /// cert_ec chain contained a manufacturer intermediate in the
        /// known-good list (Gate 1 — Samsung S3K250AF etc.). Relying
        /// parties use this as a reputation signal — a Packed or
        /// unknown-hardware cert has this false.
        pub manufacturer_verified: bool,
        /// Template identifier (future cert-template work). Empty
        /// vector until templates land; kept on Hot so the common
        /// query path can surface it without a Cold read.
        pub template_name: BoundedVec<u8, ConstU32<64>>,
        /// EKUs attached to this cert at mint. Copied from the
        /// referenced `CertTemplate.ekus` in a single execution with
        /// the rest of the mint writes. Empty for root / issuer
        /// certs — those carry capabilities on their entity record,
        /// not on the cert itself.
        pub ekus: BoundedVec<Eku, ConstU32<MAX_TEMPLATE_EKUS>>,
        /// PoP cryptographic mechanism the cert was minted under,
        /// copied verbatim from `CertTemplate.pop_mechanism` at
        /// `mint_cert`. `None` when the template's `pop_requirement`
        /// is `NotRequired` (no PoP cert), or for root/issuer certs
        /// minted outside the templated cert flow. Hot-tier because
        /// `verify_pop_assertion` dispatches on this on every
        /// PoP-gated extrinsic — touching Cold for it would defeat
        /// the hot/cold split's purpose.
        ///
        /// Pinned at mint; never mutated. The mint-time platform
        /// gate (StrongBox → MimeWrap, Tpm2 → HipSigned) ensures
        /// this can only ever match one variant of `PopAssertion`,
        /// so cross-tier bypass at sign time is structurally
        /// impossible.
        pub pop_mechanism: Option<PopMechanism>,
    }

    impl<AccountId, BlockNumber> CertRecordHot<AccountId, BlockNumber> {
        /// Derives active state from the CertState enum rather than a
        /// raw bool — cert.is_active() is the single source of truth.
        pub fn is_active(&self) -> bool {
            self.state.is_active()
        }
    }

    /// Cold record — deep verification / audit fields. Read by
    /// successor signature verification during renewal, by cleanup
    /// for the orphan-detection path, and by long-tail
    /// non-repudiation queries.
    #[derive(Encode, Decode, Clone, PartialEq, Eq, TypeInfo, MaxEncodedLen)]
    #[cfg_attr(feature = "std", derive(Debug))]
    #[scale_info(skip_type_params(BlockNumber, Balance))]
    pub struct CertRecordCold<BlockNumber, Balance> {
        pub thumbprint: Thumbprint,
        /// Device public key (P-256, P-521, or ML-DSA depending on
        /// hardware). Used for successor signature verification
        /// during renewal.
        pub cert_ec_pubkey: DevicePublicKey,
        /// Amount held under `HoldReason::CertDeposit` when this cert
        /// was created. All release paths (self_discard, on_initialize
        /// purge, invalidate_cert, deregister_root, cleanup) drain
        /// exactly this much — the per-cert record is load-bearing
        /// because the mint-fee-derived deposit varies per cert.
        pub deposit: Balance,
        /// Android Keystore `osVersion` captured at genesis. `None`
        /// until the tpm crate's parser is extended to surface it —
        /// stub field for a separate TODO.
        pub genesis_os_version: Option<u32>,
        pub genesis_os_patch_level: Option<u32>,
        pub genesis_vendor_patch_level: Option<u32>,
        pub genesis_boot_patch_level: Option<u32>,
        pub suspension_reason: Option<BoundedVec<u8, ConstU32<MAX_SUSPENSION_REASON_LEN>>>,
        /// Block at which the cert was most recently suspended.
        /// Cleared on reactivation. Used by cleanup to compute the
        /// purge window without storing `purge_eligible_block`.
        pub suspension_block: Option<BlockNumber>,
        /// Immutable issuer-defined metadata from the contract offer.
        /// Populated at mint_cert; `None` for root/issuer/renewal
        /// paths where no offer exists.
        pub issuer_metadata: Option<BoundedVec<u8, ConstU32<MAX_METADATA_LEN>>>,
        /// Genesis hardware fingerprint for PoP certs. Recorded at
        /// `mint_cert` when the user's template carries the
        /// `ProofOfPersonhood` EKU; `None` for non-PoP certs and for
        /// root/issuer/renewal paths. Future HIP-gated extrinsics
        /// compare fresh proofs against this ground truth.
        pub genesis_fingerprint: Option<zk_pki_primitives::hip::GenesisHardwareFingerprint>,
    }
}
