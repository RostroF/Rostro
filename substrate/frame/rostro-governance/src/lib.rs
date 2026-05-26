// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # Rostro bicameral governance v1
//!
//! One cert = one vote. Upper house seated by country (ICAO doc
//! nationality), lower house round-robin assigned at registration.
//! Ranked-choice instant-runoff tallies independently per chamber;
//! concurrent assent — both chambers must elect the same winner for
//! a proposal to pass; either chamber producing no winner (or a
//! different winner) blocks. Voting extrinsics ship with
//! `Pays::No` so casting a vote costs no transaction fee.
//!
//! ## What's stubbed in v1
//!
//! - **Cert gating**: any signed origin can register as a voter.
//!   Real PoP-cert verification replaces this when the personhood
//!   pallet lands. Until then, registration takes a country code
//!   directly instead of deriving it from an ICAO doc.
//! - **Round-robin lower-house distribution**: sequential
//!   assignment (district 0, 1, 2, …, wraps). The non-repeating
//!   round-robin from the bicameral memo lands when randomness is
//!   sourced from Sassafras's ring-VRF block randomness.
//! - **Pruning of non-voters at addition pace**: not implemented
//!   in v1. Lower-district rosters grow monotonically. Pruning
//!   lands in 8b alongside the strike system.
//! - **Term limits**: tracked (`consecutive_terms_*`) but not
//!   enforced. The 3-consecutive-term cap lands when terms
//!   actually rotate (term-rotation logic = 8b).
//! - **Anonymous voting**: ballots are AccountId-bound. ZK-attested
//!   nullifier-based voting is 8d — same pallet, same proposal
//!   shape, swap the ballot-binding mechanism.
//!
//! ## Inter-chamber resolution
//!
//! Concurrent assent (per the whitepaper). A proposal passes iff:
//! 1. Upper chamber's IRV produces a winner with quorum.
//! 2. Lower chamber's IRV produces a winner with quorum.
//! 3. Both winners are the same `CandidateId`.
//!
//! Any failure in 1, 2, or 3 marks the proposal blocked. Which
//! chamber blocked it is recorded for off-chain auditing and for
//! the future strike system.
//!
//! ## Phase 8b (this revision)
//!
//! Adds the voter-level mechanics from the bicameral memo and the
//! whitepaper round-escalation rule that don't require a
//! representative layer:
//!
//! - **Addition-paced pruning**: voters who miss enough tallied
//!   proposals are eligible-to-be-removed; removal only happens as
//!   the swap-out leg of a new registration into their lower-house
//!   district. Districts never shrink in spikes.
//! - **Missed-vote counter** (`VoterRecord::missed_votes`): bumped
//!   on tally for voters who didn't cast, reset on `cast_vote`. The
//!   bicameral memo's strike marker — distinct from the
//!   whitepaper's rep-level strike system (deferred).
//! - **Eligibility tracking** (`VoterRecord::eligible_from_proposal_id`):
//!   prevents new voters from being struck for proposals that
//!   opened before they registered.
//! - **Round-1 → Round-2 quorum-failure escalation**: when a
//!   proposal's tally produces a `QuorumFailed` outcome, anyone can
//!   call `escalate_to_round_2` to spawn a re-poll with a
//!   72h-equivalent (43,200-block) window. Round-3 escalation to
//!   constituents requires reps and is deferred.
//!
//! ## What's NOT in this pallet (still deferred)
//!
//! - Representative election (seats as holdable things, terms,
//!   3-consecutive-term cap, staggered thirds) — required before
//!   recall and round-3 escalation can land
//! - Recall (60% of original electing voters → special election) —
//!   needs reps
//! - Whitepaper rep-strike system (3 strikes / 30 days rolling →
//!   automatic removal + special election) — needs reps
//! - Money-out-of-politics tx filter (8c)
//! - ZK-anonymous voting / dual-nullifier (8d)
//! - PoP-cert integration (8e)
//! - Non-repeating round-robin distribution (sourced from
//!   Sassafras ring-VRF)

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

extern crate alloc;

use alloc::vec::Vec;
use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use frame_support::pallet_prelude::*;
use frame_system::pallet_prelude::BlockNumberFor;
use scale_info::TypeInfo;
use sp_runtime::traits::Saturating;

/// Two-byte ISO 3166-1 alpha-2 country code (e.g. `[b'U', b'S']`).
/// In v1 the registration extrinsic takes this directly; when PoP
/// integrates (8e) the chain derives it from the ICAO doc bundle.
pub type CountryCode = [u8; 2];

/// Lower-house district identifier. Round-robin assignment in v1
/// just increments a counter and wraps modulo `T::TotalDistricts`.
pub type DistrictId = u32;

/// Sequential proposal identifier.
pub type ProposalId = u32;

/// Candidate identifier within a single proposal. Operators
/// (proposers) pick these freely — no global candidate registry.
pub type CandidateId = u8;

/// Maximum candidates per proposal. 32 is generous for any
/// realistic referendum + ranked-choice election shape.
pub const MAX_CANDIDATES: u32 = 32;

/// Maximum bytes in a proposal title.
pub const MAX_PROPOSAL_TITLE_LEN: u32 = 256;

/// Maximum bytes in a candidate label.
pub const MAX_CANDIDATE_LABEL_LEN: u32 = 128;

/// Where a voter sits in the bicameral structure. Every registered
/// voter has *both* an upper and lower seat — voting in upper-
/// chamber tallies uses the upper seat, voting in lower-chamber
/// tallies uses the lower seat. The same ballot counts in both.
#[derive(
	Debug, Clone, PartialEq, Eq,
	Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
)]
pub struct ChamberSeats {
	/// Upper-house seat: country-fixed.
	pub upper_country: CountryCode,
	/// Lower-house district: round-robin assigned.
	pub lower_district: DistrictId,
}

/// Per-voter governance record.
#[derive(
	Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
	frame_support::CloneNoBound, frame_support::PartialEqNoBound,
	frame_support::EqNoBound, frame_support::DebugNoBound,
)]
#[scale_info(skip_type_params(T))]
pub struct VoterRecord<T: Config> {
	pub seats: ChamberSeats,
	pub registered_at: BlockNumberFor<T>,
	/// First proposal id this voter is expected to participate in.
	/// Set at registration to the value of `NextProposalId` so that
	/// proposals opened before the voter registered don't count
	/// against them at strike-sweep time.
	pub eligible_from_proposal_id: ProposalId,
	/// Running count of consecutive eligible proposals this voter
	/// failed to cast on. Bumped on `tally`, reset on `cast_vote`.
	/// At `>= T::StrikesBeforePruning` the voter is
	/// eligible-to-be-removed at the next registration into their
	/// lower-house district (per the bicameral memo's
	/// addition-paced pruning rule). This is distinct from the
	/// whitepaper's rep-level strike system, which lands with the
	/// representative layer.
	pub missed_votes: u32,
	/// Number of consecutive terms in the upper chamber. Tracked
	/// for the future 3-consecutive-term limit; not enforced in
	/// v1.
	pub consecutive_terms_upper: u8,
	pub consecutive_terms_lower: u8,
}

/// A proposal under deliberation.
#[derive(
	Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
	frame_support::CloneNoBound, frame_support::PartialEqNoBound,
	frame_support::EqNoBound, frame_support::DebugNoBound,
)]
#[scale_info(skip_type_params(T))]
pub struct Proposal<T: Config> {
	pub title: BoundedVec<u8, ConstU32<MAX_PROPOSAL_TITLE_LEN>>,
	pub candidates: BoundedVec<Candidate, ConstU32<MAX_CANDIDATES>>,
	pub voting_period_end: BlockNumberFor<T>,
	/// Minimum number of upper-chamber ballots required to consider
	/// the upper-chamber tally valid. If fewer voters cast ballots
	/// the upper chamber is treated as "no quorum."
	pub upper_quorum: u32,
	pub lower_quorum: u32,
	pub state: ProposalState,
	/// `1` for the initial vote, `2` for a re-poll spawned by
	/// `escalate_to_round_2`. Round 3 (escalation to constituents)
	/// requires the representative layer and is not implemented.
	pub round: u8,
	/// The round-1 proposal id this round-2 proposal re-polls.
	/// `None` for round-1 proposals.
	pub parent_proposal: Option<ProposalId>,
}

/// One candidate within a proposal. Candidates carry a numeric id
/// (used in ballots) and a human-readable label (used by clients
/// for display).
#[derive(
	Debug, Clone, PartialEq, Eq,
	Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
)]
pub struct Candidate {
	pub id: CandidateId,
	pub label: BoundedVec<u8, ConstU32<MAX_CANDIDATE_LABEL_LEN>>,
}

/// Where a proposal is in its lifecycle.
#[derive(
	Debug, Clone, PartialEq, Eq,
	Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
)]
pub enum ProposalState {
	/// Voting window is open.
	Active,
	/// Tally complete. The outcome carries the concrete reason —
	/// passed, disagreement (both chambers met quorum but elected
	/// different winners), or quorum failure (one or both chambers
	/// didn't reach quorum). Only `QuorumFailed` is eligible for
	/// round-2 escalation.
	Tallied(TallyOutcome),
}

/// Outcome of a concurrent-assent tally.
#[derive(
	Debug, Clone, PartialEq, Eq,
	Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
)]
pub enum TallyOutcome {
	/// Both chambers met quorum and elected the same candidate.
	Passed { winner: CandidateId },
	/// Both chambers met quorum but produced different IRV
	/// winners. Terminal in v1 — there is no representative layer
	/// to mediate the disagreement, and round-2 escalation only
	/// applies to quorum failure (the failure mode the whitepaper
	/// names "with strikes").
	Disagreement,
	/// At least one chamber missed quorum. Eligible for round-2
	/// re-poll via `escalate_to_round_2`; the new proposal id
	/// (when escalated) is recorded in `escalated_to`.
	QuorumFailed {
		upper_failed: bool,
		lower_failed: bool,
		escalated_to: Option<ProposalId>,
	},
}

/// Which chamber a tally event refers to. Retained as a public
/// type for downstream consumers (events, off-chain indexers).
#[derive(
	Debug, Clone, Copy, PartialEq, Eq,
	Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
)]
pub enum Chamber {
	Upper,
	Lower,
}

/// One voter's ballot on one proposal. Ranking is ordered:
/// `ranking[0]` is the voter's first preference, `ranking[1]` their
/// second, etc. Duplicate or unknown candidate ids in the ranking
/// are rejected at cast time.
#[derive(
	Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
	frame_support::CloneNoBound, frame_support::PartialEqNoBound,
	frame_support::EqNoBound, frame_support::DebugNoBound,
)]
#[scale_info(skip_type_params(T))]
pub struct Ballot<T: Config> {
	pub ranking: BoundedVec<CandidateId, ConstU32<MAX_CANDIDATES>>,
	pub cast_at: BlockNumberFor<T>,
}

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
		/// Number of lower-house districts. Round-robin assignment
		/// wraps modulo this value. Tunable by governance once the
		/// chain is live (parameter change). Pre-launch: size
		/// against expected certified population.
		#[pallet::constant]
		type TotalDistricts: Get<u32>;

		/// Maximum members in any single lower-house district
		/// roster. Bounds the storage cost of district metadata.
		#[pallet::constant]
		type MaxDistrictSize: Get<u32>;

		/// Maximum members in any single upper-house country
		/// delegation. Larger countries have more voters per
		/// seat — this caps the per-country storage but doesn't
		/// affect their voting power (each member gets one vote
		/// in the country's tally).
		#[pallet::constant]
		type MaxCountryDelegation: Get<u32>;

		/// Threshold at which a voter's `missed_votes` counter
		/// makes them eligible for addition-paced pruning from
		/// their lower-house district roster. The bicameral memo
		/// doesn't pin a specific value; the whitepaper's "3
		/// strikes" rule is rep-level (separate system) but
		/// suggests the same magnitude here.
		#[pallet::constant]
		type StrikesBeforePruning: Get<u32>;

		/// Voting-period length for a round-2 re-poll spawned by
		/// `escalate_to_round_2`. The whitepaper specifies "72h"
		/// which is 43,200 blocks at 6s block time.
		#[pallet::constant]
		type Round2WindowBlocks: Get<BlockNumberFor<Self>>;
	}

	/// Per-voter governance record. AccountId → seats + term
	/// counts.
	#[pallet::storage]
	pub type Voters<T: Config> =
		StorageMap<_, Blake2_128Concat, T::AccountId, VoterRecord<T>, OptionQuery>;

	/// Lower-house district roster. Each district maps to its
	/// member list.
	#[pallet::storage]
	pub type LowerDistrictRoster<T: Config> = StorageMap<
		_,
		Twox64Concat,
		DistrictId,
		BoundedVec<T::AccountId, T::MaxDistrictSize>,
		ValueQuery,
	>;

	/// Upper-house country roster. Each country maps to its
	/// member list. Bundling for small countries (per the
	/// bicameral memo) is implemented at the registration level
	/// — the same `country_code` can be assigned to multiple
	/// real countries to bundle them; that's a v1 implementation
	/// detail handled outside this pallet.
	#[pallet::storage]
	pub type UpperCountryRoster<T: Config> = StorageMap<
		_,
		Twox64Concat,
		CountryCode,
		BoundedVec<T::AccountId, T::MaxCountryDelegation>,
		ValueQuery,
	>;

	/// Round-robin counter for lower-house district assignment.
	/// Increments on every successful registration; the assigned
	/// district is `next_district % TotalDistricts`.
	#[pallet::storage]
	pub type NextDistrictAssignment<T: Config> = StorageValue<_, u32, ValueQuery>;

	/// Sequential proposal-id counter.
	#[pallet::storage]
	pub type NextProposalId<T: Config> = StorageValue<_, ProposalId, ValueQuery>;

	/// Active and historical proposals.
	#[pallet::storage]
	pub type Proposals<T: Config> =
		StorageMap<_, Twox64Concat, ProposalId, Proposal<T>, OptionQuery>;

	/// Per-proposal, per-voter ballots. Double-map keyed by
	/// `(proposal_id, account)`.
	#[pallet::storage]
	pub type Votes<T: Config> = StorageDoubleMap<
		_,
		Twox64Concat,
		ProposalId,
		Blake2_128Concat,
		T::AccountId,
		Ballot<T>,
		OptionQuery,
	>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		VoterRegistered {
			account: T::AccountId,
			seats: ChamberSeats,
		},
		/// A voter was swapped out during a `register_voter` call
		/// as the addition-paced pruning leg.
		VoterPruned {
			account: T::AccountId,
			district: DistrictId,
		},
		ProposalCreated {
			proposal_id: ProposalId,
			voting_period_end: BlockNumberFor<T>,
		},
		VoteCast {
			proposal_id: ProposalId,
			voter: T::AccountId,
		},
		ProposalTallied {
			proposal_id: ProposalId,
			outcome: TallyOutcome,
		},
		/// A quorum-failed proposal was re-polled as round 2.
		ProposalEscalatedToRound2 {
			parent_proposal_id: ProposalId,
			new_proposal_id: ProposalId,
			upper_failed: bool,
			lower_failed: bool,
		},
	}

	#[pallet::error]
	pub enum Error<T> {
		AlreadyRegistered,
		DistrictRosterFull,
		CountryDelegationFull,
		EmptyTitle,
		TitleTooLong,
		EmptyCandidateList,
		TooManyCandidates,
		DuplicateCandidateId,
		EmptyCandidateLabel,
		CandidateLabelTooLong,
		ZeroVotingPeriod,
		ProposalNotFound,
		ProposalNotActive,
		VotingPeriodEnded,
		VotingPeriodStillOpen,
		NotRegisteredVoter,
		AlreadyVoted,
		EmptyRanking,
		DuplicateRankingId,
		UnknownCandidateInRanking,
		ProposalAlreadyTallied,
		/// `escalate_to_round_2` called on a proposal that didn't
		/// produce a `QuorumFailed` outcome (passed, disagreement,
		/// or still active).
		NotQuorumFailed,
		/// `escalate_to_round_2` called on a proposal that has
		/// already been escalated.
		AlreadyEscalated,
		/// `escalate_to_round_2` called on a round-2 proposal.
		/// Round-3 escalation requires the representative layer
		/// and is not implemented.
		NotRound1,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Register the caller as a voter under the given country
		/// code. v1 stub: any signed origin can register, no PoP
		/// check, country code is supplied by the caller. When PoP
		/// lands (8e), this extrinsic becomes a no-op for end users
		/// — registration is automatic on cert activation, with
		/// the country code derived from the ICAO doc.
		///
		/// Applies **addition-paced pruning** per the bicameral
		/// memo: if the round-robin-assigned lower-house district
		/// already contains a voter whose `missed_votes` exceeds
		/// the strike threshold, that voter is atomically removed
		/// (from `Voters`, lower-district roster, and upper-country
		/// roster) and the new voter takes their slot — net
		/// district size unchanged. If no eligible-to-prune voter
		/// exists in that district, the new voter simply grows it.
		#[pallet::call_index(0)]
		#[pallet::weight(Weight::from_parts(20_000, 0))]
		pub fn register_voter(
			origin: OriginFor<T>,
			country: CountryCode,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			ensure!(!Voters::<T>::contains_key(&who), Error::<T>::AlreadyRegistered);

			let total_districts = T::TotalDistricts::get();
			let next = NextDistrictAssignment::<T>::get();
			let district = if total_districts == 0 { 0 } else { next % total_districts };
			NextDistrictAssignment::<T>::put(next.saturating_add(1));

			// Look for a swap-out candidate in the target district
			// — a voter with missed_votes >= threshold. First match
			// wins (deterministic by iteration order = roster
			// insertion order).
			let prune_threshold = T::StrikesBeforePruning::get();
			let pruned: Option<T::AccountId> =
				LowerDistrictRoster::<T>::get(district).iter().find_map(|account| {
					Voters::<T>::get(account)
						.filter(|r| r.missed_votes >= prune_threshold)
						.map(|_| account.clone())
				});

			if let Some(prune_target) = pruned.as_ref() {
				// Remove from lower-district roster (swap-out).
				LowerDistrictRoster::<T>::mutate(district, |roster| {
					roster.retain(|a| a != prune_target);
				});
				// Remove from upper-country roster.
				if let Some(prune_record) = Voters::<T>::get(prune_target) {
					let prune_country = prune_record.seats.upper_country;
					UpperCountryRoster::<T>::mutate(prune_country, |roster| {
						roster.retain(|a| a != prune_target);
					});
				}
				// Remove the voter record itself.
				Voters::<T>::remove(prune_target);
				Self::deposit_event(Event::VoterPruned {
					account: prune_target.clone(),
					district,
				});
			}

			LowerDistrictRoster::<T>::try_mutate(district, |roster| -> DispatchResult {
				roster.try_push(who.clone()).map_err(|_| Error::<T>::DistrictRosterFull)?;
				Ok(())
			})?;

			UpperCountryRoster::<T>::try_mutate(country, |roster| -> DispatchResult {
				roster.try_push(who.clone()).map_err(|_| Error::<T>::CountryDelegationFull)?;
				Ok(())
			})?;

			let seats = ChamberSeats { upper_country: country, lower_district: district };
			let record = VoterRecord::<T> {
				seats: seats.clone(),
				registered_at: <frame_system::Pallet<T>>::block_number(),
				eligible_from_proposal_id: NextProposalId::<T>::get(),
				missed_votes: 0,
				consecutive_terms_upper: 0,
				consecutive_terms_lower: 0,
			};
			Voters::<T>::insert(&who, record);

			Self::deposit_event(Event::VoterRegistered { account: who, seats });
			Ok(())
		}

		/// Create a new ranked-choice proposal. Anyone can propose
		/// in v1; future revisions can gate by deposit, by a
		/// proposing-tier of registered voters, or by SRT.
		#[pallet::call_index(1)]
		#[pallet::weight(Weight::from_parts(30_000, 0))]
		pub fn propose(
			origin: OriginFor<T>,
			title: Vec<u8>,
			candidates: Vec<Candidate>,
			voting_period_blocks: BlockNumberFor<T>,
			upper_quorum: u32,
			lower_quorum: u32,
		) -> DispatchResult {
			let _proposer = ensure_signed(origin)?;
			ensure!(!title.is_empty(), Error::<T>::EmptyTitle);
			ensure!(!candidates.is_empty(), Error::<T>::EmptyCandidateList);
			ensure!(
				voting_period_blocks > BlockNumberFor::<T>::from(0u32),
				Error::<T>::ZeroVotingPeriod,
			);

			Self::validate_candidates(&candidates)?;

			let title_bv: BoundedVec<u8, ConstU32<MAX_PROPOSAL_TITLE_LEN>> =
				BoundedVec::try_from(title).map_err(|_| Error::<T>::TitleTooLong)?;
			let candidates_bv: BoundedVec<Candidate, ConstU32<MAX_CANDIDATES>> =
				BoundedVec::try_from(candidates).map_err(|_| Error::<T>::TooManyCandidates)?;

			let id = NextProposalId::<T>::get();
			NextProposalId::<T>::put(id.saturating_add(1));

			let now = <frame_system::Pallet<T>>::block_number();
			let voting_period_end = now.saturating_add(voting_period_blocks);
			let proposal = Proposal::<T> {
				title: title_bv,
				candidates: candidates_bv,
				voting_period_end,
				upper_quorum,
				lower_quorum,
				state: ProposalState::Active,
				round: 1,
				parent_proposal: None,
			};
			Proposals::<T>::insert(id, proposal);

			Self::deposit_event(Event::ProposalCreated { proposal_id: id, voting_period_end });
			Ok(())
		}

		/// Cast a ranked-choice ballot. **Pays::No** — voting is
		/// free.
		///
		/// Caller must be a registered voter. Ranking entries must
		/// be unique and reference candidates that exist on the
		/// proposal. Voters can only cast once per proposal.
		#[pallet::call_index(2)]
		#[pallet::weight(
			(Weight::from_parts(15_000, 0), DispatchClass::Normal, Pays::No)
		)]
		pub fn cast_vote(
			origin: OriginFor<T>,
			proposal_id: ProposalId,
			ranking: Vec<CandidateId>,
		) -> DispatchResultWithPostInfo {
			let who = ensure_signed(origin)?;
			ensure!(Voters::<T>::contains_key(&who), Error::<T>::NotRegisteredVoter);

			let proposal = Proposals::<T>::get(proposal_id).ok_or(Error::<T>::ProposalNotFound)?;
			ensure!(matches!(proposal.state, ProposalState::Active), Error::<T>::ProposalNotActive);
			let now = <frame_system::Pallet<T>>::block_number();
			ensure!(now < proposal.voting_period_end, Error::<T>::VotingPeriodEnded);

			ensure!(!Votes::<T>::contains_key(proposal_id, &who), Error::<T>::AlreadyVoted);

			ensure!(!ranking.is_empty(), Error::<T>::EmptyRanking);
			Self::validate_ranking(&ranking, &proposal.candidates)?;

			let ranking_bv: BoundedVec<CandidateId, ConstU32<MAX_CANDIDATES>> =
				BoundedVec::try_from(ranking).map_err(|_| Error::<T>::TooManyCandidates)?;
			let ballot = Ballot::<T> { ranking: ranking_bv, cast_at: now };
			Votes::<T>::insert(proposal_id, &who, ballot);

			// Casting on any proposal resets the missed-vote
			// streak. Pruning eligibility tracks *consecutive*
			// misses; one participation breaks the streak.
			Voters::<T>::mutate(&who, |maybe| {
				if let Some(record) = maybe.as_mut() {
					record.missed_votes = 0;
				}
			});

			Self::deposit_event(Event::VoteCast { proposal_id, voter: who });
			Ok(Pays::No.into())
		}

		/// Tally a proposal whose voting period has ended. Anyone
		/// can call. Computes IRV separately for upper-chamber and
		/// lower-chamber ballots, then applies concurrent assent:
		/// proposal passes only if both chambers' IRV winners agree
		/// AND both chambers met their respective quorum.
		///
		/// Also runs the **strike sweep**: every registered voter
		/// who was eligible at this proposal's creation either has
		/// their `missed_votes` reset to 0 (if they cast) or
		/// incremented by 1 (if they didn't). This is O(V) in the
		/// total voter count — a v1 limitation; v2 will move to
		/// lazy accumulation.
		#[pallet::call_index(3)]
		#[pallet::weight(Weight::from_parts(50_000, 0))]
		pub fn tally(origin: OriginFor<T>, proposal_id: ProposalId) -> DispatchResult {
			let _ = ensure_signed(origin)?;

			let mut proposal =
				Proposals::<T>::get(proposal_id).ok_or(Error::<T>::ProposalNotFound)?;
			ensure!(matches!(proposal.state, ProposalState::Active), Error::<T>::ProposalAlreadyTallied);
			let now = <frame_system::Pallet<T>>::block_number();
			ensure!(now >= proposal.voting_period_end, Error::<T>::VotingPeriodStillOpen);

			let mut upper_ballots: Vec<Vec<CandidateId>> = Vec::new();
			let mut lower_ballots: Vec<Vec<CandidateId>> = Vec::new();
			for (account, ballot) in Votes::<T>::iter_prefix(proposal_id) {
				if Voters::<T>::contains_key(&account) {
					let ranking = ballot.ranking.into_inner();
					// In v1 every voter has both an upper and a
					// lower seat, so the same ballot counts in
					// both tallies. ZK voting (8d) doesn't change
					// this — same nullifier appears in both
					// chamber-level tally inputs.
					upper_ballots.push(ranking.clone());
					lower_ballots.push(ranking);
				}
			}

			let candidate_ids: Vec<CandidateId> =
				proposal.candidates.iter().map(|c| c.id).collect();

			let upper_met_quorum = (upper_ballots.len() as u32) >= proposal.upper_quorum;
			let lower_met_quorum = (lower_ballots.len() as u32) >= proposal.lower_quorum;

			let upper_winner = if upper_met_quorum {
				irv_winner(&upper_ballots, &candidate_ids)
			} else {
				None
			};
			let lower_winner = if lower_met_quorum {
				irv_winner(&lower_ballots, &candidate_ids)
			} else {
				None
			};

			let outcome = if !upper_met_quorum || !lower_met_quorum {
				TallyOutcome::QuorumFailed {
					upper_failed: !upper_met_quorum,
					lower_failed: !lower_met_quorum,
					escalated_to: None,
				}
			} else {
				// Both chambers met quorum. `irv_winner` can still
				// return `None` on a perfect tie; treat that as
				// disagreement (terminal, not escalation-eligible
				// — escalation is for the "with strikes" failure
				// mode the whitepaper names, i.e. people didn't
				// show up).
				match (upper_winner, lower_winner) {
					(Some(u), Some(l)) if u == l => TallyOutcome::Passed { winner: u },
					_ => TallyOutcome::Disagreement,
				}
			};

			// Strike sweep. Visit every voter; reset for casters,
			// increment for eligible non-casters. Voters whose
			// `eligible_from_proposal_id` is past this proposal
			// (i.e. registered after it was created) are skipped.
			Voters::<T>::translate(
				|account, mut record: VoterRecord<T>| -> Option<VoterRecord<T>> {
					if record.eligible_from_proposal_id > proposal_id {
						return Some(record);
					}
					if Votes::<T>::contains_key(proposal_id, &account) {
						record.missed_votes = 0;
					} else {
						record.missed_votes = record.missed_votes.saturating_add(1);
					}
					Some(record)
				},
			);

			proposal.state = ProposalState::Tallied(outcome.clone());
			Proposals::<T>::insert(proposal_id, proposal);

			Self::deposit_event(Event::ProposalTallied { proposal_id, outcome });
			Ok(())
		}

		/// Escalate a quorum-failed round-1 proposal to round 2,
		/// re-polling within the configured `Round2WindowBlocks`
		/// window. Anyone can call; gas is the only rate limit.
		///
		/// The new proposal inherits the parent's candidates and
		/// quorum thresholds; its title is the parent's title
		/// prefixed with `"[r2] "` to distinguish in client UIs.
		/// (If prefixing would exceed `MAX_PROPOSAL_TITLE_LEN`,
		/// the parent's title is truncated from the end.)
		///
		/// Round 3 — escalation to "constituents who elected
		/// absent reps" — requires the representative layer and
		/// is not implemented in v1; round-2 proposals are
		/// terminal regardless of their outcome.
		#[pallet::call_index(4)]
		#[pallet::weight(Weight::from_parts(40_000, 0))]
		pub fn escalate_to_round_2(
			origin: OriginFor<T>,
			proposal_id: ProposalId,
		) -> DispatchResult {
			let _ = ensure_signed(origin)?;

			let mut parent =
				Proposals::<T>::get(proposal_id).ok_or(Error::<T>::ProposalNotFound)?;
			ensure!(parent.round == 1, Error::<T>::NotRound1);

			let (upper_failed, lower_failed) = match &parent.state {
				ProposalState::Tallied(TallyOutcome::QuorumFailed {
					upper_failed,
					lower_failed,
					escalated_to,
				}) => {
					ensure!(escalated_to.is_none(), Error::<T>::AlreadyEscalated);
					(*upper_failed, *lower_failed)
				},
				_ => return Err(Error::<T>::NotQuorumFailed.into()),
			};

			let new_id = NextProposalId::<T>::get();
			NextProposalId::<T>::put(new_id.saturating_add(1));

			let now = <frame_system::Pallet<T>>::block_number();
			let voting_period_end = now.saturating_add(T::Round2WindowBlocks::get());

			// Build the round-2 title: "[r2] " + parent.title,
			// truncating the parent's bytes if needed to fit.
			let prefix: &[u8] = b"[r2] ";
			let max_len = MAX_PROPOSAL_TITLE_LEN as usize;
			let mut new_title_bytes: Vec<u8> = Vec::with_capacity(max_len);
			new_title_bytes.extend_from_slice(prefix);
			let parent_title = parent.title.as_slice();
			let room = max_len.saturating_sub(prefix.len());
			let take = parent_title.len().min(room);
			new_title_bytes.extend_from_slice(&parent_title[..take]);
			let new_title: BoundedVec<u8, ConstU32<MAX_PROPOSAL_TITLE_LEN>> =
				BoundedVec::try_from(new_title_bytes)
					.expect("title bounded by max_len construction; qed");

			let new_proposal = Proposal::<T> {
				title: new_title,
				candidates: parent.candidates.clone(),
				voting_period_end,
				upper_quorum: parent.upper_quorum,
				lower_quorum: parent.lower_quorum,
				state: ProposalState::Active,
				round: 2,
				parent_proposal: Some(proposal_id),
			};
			Proposals::<T>::insert(new_id, new_proposal);

			// Link the parent's escalation pointer in place.
			parent.state = ProposalState::Tallied(TallyOutcome::QuorumFailed {
				upper_failed,
				lower_failed,
				escalated_to: Some(new_id),
			});
			Proposals::<T>::insert(proposal_id, parent);

			Self::deposit_event(Event::ProposalEscalatedToRound2 {
				parent_proposal_id: proposal_id,
				new_proposal_id: new_id,
				upper_failed,
				lower_failed,
			});
			Self::deposit_event(Event::ProposalCreated {
				proposal_id: new_id,
				voting_period_end,
			});
			Ok(())
		}
	}

	impl<T: Config> Pallet<T> {
		fn validate_candidates(candidates: &[Candidate]) -> DispatchResult {
			for c in candidates {
				ensure!(!c.label.is_empty(), Error::<T>::EmptyCandidateLabel);
			}
			let mut ids: Vec<CandidateId> = candidates.iter().map(|c| c.id).collect();
			ids.sort();
			for win in ids.windows(2) {
				if win[0] == win[1] {
					return Err(Error::<T>::DuplicateCandidateId.into());
				}
			}
			Ok(())
		}

		fn validate_ranking(
			ranking: &[CandidateId],
			candidates: &[Candidate],
		) -> DispatchResult {
			let known: alloc::collections::BTreeSet<CandidateId> =
				candidates.iter().map(|c| c.id).collect();
			let mut seen: alloc::collections::BTreeSet<CandidateId> = Default::default();
			for &id in ranking {
				ensure!(known.contains(&id), Error::<T>::UnknownCandidateInRanking);
				ensure!(seen.insert(id), Error::<T>::DuplicateRankingId);
			}
			Ok(())
		}

		/// Read accessors used by tests and downstream pallets.
		pub fn voter_of(account: &T::AccountId) -> Option<VoterRecord<T>> {
			Voters::<T>::get(account)
		}
		pub fn proposal_of(id: ProposalId) -> Option<Proposal<T>> {
			Proposals::<T>::get(id)
		}
	}
}

/// Compute the IRV (instant-runoff) winner over a slice of
/// rankings. Returns `None` if the input is empty or no candidate
/// achieves a majority through successive elimination (which only
/// happens on perfect ties — rare in practice).
///
/// Each ballot's preference list is consulted in order; if its
/// current first-preference candidate has been eliminated, the
/// next preference takes over, and so on. Eliminations remove
/// the candidate with the fewest current first-preferences each
/// round; ties on elimination break by lowest candidate id (a
/// deterministic rule, not a fairness claim).
pub fn irv_winner(ballots: &[Vec<CandidateId>], candidates: &[CandidateId]) -> Option<CandidateId> {
	if ballots.is_empty() || candidates.is_empty() {
		return None;
	}
	let mut active: alloc::collections::BTreeSet<CandidateId> =
		candidates.iter().copied().collect();

	loop {
		if active.len() == 1 {
			return active.into_iter().next();
		}
		let mut tally: alloc::collections::BTreeMap<CandidateId, u32> = Default::default();
		for &c in &active {
			tally.insert(c, 0);
		}
		let mut total: u32 = 0;
		for ballot in ballots {
			if let Some(&first_active) = ballot.iter().find(|c| active.contains(c)) {
				*tally.entry(first_active).or_insert(0) += 1;
				total += 1;
			}
		}
		if total == 0 {
			return None;
		}
		// Majority check.
		for (&c, &count) in &tally {
			if count * 2 > total {
				return Some(c);
			}
		}
		// Eliminate the candidate with the fewest votes (ties broken
		// by lowest id).
		let (&loser, _) = tally
			.iter()
			.min_by(|a, b| a.1.cmp(b.1).then_with(|| a.0.cmp(b.0)))?;
		active.remove(&loser);
	}
}

#[cfg(test)]
mod tests;
