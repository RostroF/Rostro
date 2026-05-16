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
//! ## What's NOT in this pallet
//!
//! - Strikes / quorum-failure escalation (8b)
//! - Recall (8b)
//! - Money-out-of-politics tx filter (8c)
//! - ZK-anonymous voting / dual-nullifier (8d)
//! - PoP-cert integration (8e)
//! - Election of representatives (this scaffold handles
//!   *referenda* — winner-takes-all on a proposal. Electing reps
//!   to seats is a different shape that lands when chamber seats
//!   are real things, not just registration buckets.)

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
	/// Tally complete. `winner` is `Some` only if both chambers
	/// reached quorum AND elected the same candidate (concurrent
	/// assent passed). `blocking_chamber` records which chamber
	/// (or `None` if both reached quorum but disagreed) caused a
	/// block, useful for off-chain auditing + the future strike
	/// pipeline.
	Tallied {
		winner: Option<CandidateId>,
		blocking_chamber: Option<Chamber>,
	},
}

/// Which chamber a tally event refers to.
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
			winner: Option<CandidateId>,
			blocking_chamber: Option<Chamber>,
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
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Register the caller as a voter under the given country
		/// code. v1 stub: any signed origin can register, no PoP
		/// check, country code is supplied by the caller. When PoP
		/// lands (8e), this extrinsic becomes a no-op for end users
		/// — registration is automatic on cert activation, with
		/// the country code derived from the ICAO doc.
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

			Self::deposit_event(Event::VoteCast { proposal_id, voter: who });
			Ok(Pays::No.into())
		}

		/// Tally a proposal whose voting period has ended. Anyone
		/// can call. Computes IRV separately for upper-chamber and
		/// lower-chamber ballots, then applies concurrent assent:
		/// proposal passes only if both chambers' IRV winners agree
		/// AND both chambers met their respective quorum.
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
				if let Some(record) = Voters::<T>::get(&account) {
					let ranking = ballot.ranking.into_inner();
					// In v1 every voter has both an upper and a
					// lower seat, so the same ballot counts in
					// both tallies. ZK voting (8d) doesn't change
					// this — same nullifier appears in both
					// chamber-level tally inputs.
					let _ = &record.seats;
					upper_ballots.push(ranking.clone());
					lower_ballots.push(ranking);
				}
			}

			let candidate_ids: Vec<CandidateId> =
				proposal.candidates.iter().map(|c| c.id).collect();

			let upper_winner = if (upper_ballots.len() as u32) >= proposal.upper_quorum {
				irv_winner(&upper_ballots, &candidate_ids)
			} else {
				None
			};
			let lower_winner = if (lower_ballots.len() as u32) >= proposal.lower_quorum {
				irv_winner(&lower_ballots, &candidate_ids)
			} else {
				None
			};

			let (winner, blocking_chamber) = match (upper_winner, lower_winner) {
				(Some(u), Some(l)) if u == l => (Some(u), None),
				(Some(_), Some(_)) => (None, None), // both quorum, disagreed — neither chamber alone "blocks"
				(None, Some(_)) => (None, Some(Chamber::Upper)),
				(Some(_), None) => (None, Some(Chamber::Lower)),
				(None, None) => (None, Some(Chamber::Upper)), // arbitrary — both blocked
			};

			proposal.state = ProposalState::Tallied { winner, blocking_chamber };
			Proposals::<T>::insert(proposal_id, proposal);

			Self::deposit_event(Event::ProposalTallied {
				proposal_id,
				winner,
				blocking_chamber,
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
