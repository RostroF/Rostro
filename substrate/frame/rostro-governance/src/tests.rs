// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Tests for `pallet-rostro-governance`. Mock runtime + scenarios
//! covering registration, proposal lifecycle, vote casting,
//! ranked-choice tally, and concurrent-assent inter-chamber
//! resolution.

use crate as pallet_rostro_governance;
use crate::*;

use frame_support::{assert_noop, assert_ok, derive_impl, traits::ConstU32};
use sp_core::H256;
use sp_runtime::{
	traits::{BlakeTwo256, IdentityLookup},
	BuildStorage,
};

type Block = frame_system::mocking::MockBlock<Test>;
type AccountId = u64;

frame_support::construct_runtime!(
	pub enum Test {
		System: frame_system,
		Governance: pallet_rostro_governance,
	}
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
	type Block = Block;
	type AccountId = AccountId;
	type Lookup = IdentityLookup<AccountId>;
	type Hash = H256;
	type Hashing = BlakeTwo256;
	type AccountData = ();
}

impl pallet_rostro_governance::Config for Test {
	type TotalDistricts = ConstU32<3>;
	type MaxDistrictSize = ConstU32<32>;
	type MaxCountryDelegation = ConstU32<32>;
}

const US: CountryCode = *b"US";
const UK: CountryCode = *b"UK";
const FR: CountryCode = *b"FR";

const ALICE: AccountId = 1;
const BOB: AccountId = 2;
const CHARLIE: AccountId = 3;
const DAVE: AccountId = 4;
const EVE: AccountId = 5;
const FRANK: AccountId = 6;
const GRACE: AccountId = 7;

fn ext() -> sp_io::TestExternalities {
	let t = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();
	let mut e = sp_io::TestExternalities::new(t);
	e.execute_with(|| System::set_block_number(1));
	e
}

fn cand(id: CandidateId, label: &[u8]) -> Candidate {
	Candidate {
		id,
		label: BoundedVec::try_from(label.to_vec()).unwrap(),
	}
}

// ─── registration ──────────────────────────────────────────────────────

#[test]
fn register_voter_assigns_seats_and_records() {
	ext().execute_with(|| {
		assert_ok!(Governance::register_voter(RuntimeOrigin::signed(ALICE), US));
		let v = Governance::voter_of(&ALICE).unwrap();
		assert_eq!(v.seats.upper_country, US);
		assert_eq!(v.seats.lower_district, 0);
		assert_eq!(LowerDistrictRoster::<Test>::get(0).into_inner(), alloc::vec![ALICE]);
		assert_eq!(UpperCountryRoster::<Test>::get(US).into_inner(), alloc::vec![ALICE]);
	});
}

#[test]
fn register_voter_round_robin_distributes_across_districts() {
	ext().execute_with(|| {
		assert_ok!(Governance::register_voter(RuntimeOrigin::signed(ALICE), US));
		assert_ok!(Governance::register_voter(RuntimeOrigin::signed(BOB), UK));
		assert_ok!(Governance::register_voter(RuntimeOrigin::signed(CHARLIE), FR));
		assert_ok!(Governance::register_voter(RuntimeOrigin::signed(DAVE), US));
		assert_eq!(Governance::voter_of(&ALICE).unwrap().seats.lower_district, 0);
		assert_eq!(Governance::voter_of(&BOB).unwrap().seats.lower_district, 1);
		assert_eq!(Governance::voter_of(&CHARLIE).unwrap().seats.lower_district, 2);
		// Wraps back to district 0
		assert_eq!(Governance::voter_of(&DAVE).unwrap().seats.lower_district, 0);
	});
}

#[test]
fn register_voter_rejects_double_registration() {
	ext().execute_with(|| {
		assert_ok!(Governance::register_voter(RuntimeOrigin::signed(ALICE), US));
		assert_noop!(
			Governance::register_voter(RuntimeOrigin::signed(ALICE), UK),
			Error::<Test>::AlreadyRegistered,
		);
	});
}

// ─── proposal ──────────────────────────────────────────────────────────

#[test]
fn propose_creates_proposal_with_voting_window() {
	ext().execute_with(|| {
		assert_ok!(Governance::propose(
			RuntimeOrigin::signed(ALICE),
			b"Approve foundation grant?".to_vec(),
			alloc::vec![cand(1, b"Yes"), cand(2, b"No")],
			100,
			1,
			1,
		));
		let p = Governance::proposal_of(0).unwrap();
		assert_eq!(p.title.into_inner(), b"Approve foundation grant?".to_vec());
		assert_eq!(p.candidates.len(), 2);
		assert!(matches!(p.state, ProposalState::Active));
		assert_eq!(p.voting_period_end, 101); // current=1 + period=100
	});
}

#[test]
fn propose_rejects_empty_title() {
	ext().execute_with(|| {
		assert_noop!(
			Governance::propose(
				RuntimeOrigin::signed(ALICE),
				alloc::vec![],
				alloc::vec![cand(1, b"Yes")],
				100,
				1,
				1,
			),
			Error::<Test>::EmptyTitle,
		);
	});
}

#[test]
fn propose_rejects_empty_candidate_list() {
	ext().execute_with(|| {
		assert_noop!(
			Governance::propose(
				RuntimeOrigin::signed(ALICE),
				b"x".to_vec(),
				alloc::vec![],
				100,
				1,
				1,
			),
			Error::<Test>::EmptyCandidateList,
		);
	});
}

#[test]
fn propose_rejects_duplicate_candidate_ids() {
	ext().execute_with(|| {
		assert_noop!(
			Governance::propose(
				RuntimeOrigin::signed(ALICE),
				b"x".to_vec(),
				alloc::vec![cand(1, b"A"), cand(1, b"B")],
				100,
				1,
				1,
			),
			Error::<Test>::DuplicateCandidateId,
		);
	});
}

#[test]
fn propose_rejects_zero_voting_period() {
	ext().execute_with(|| {
		assert_noop!(
			Governance::propose(
				RuntimeOrigin::signed(ALICE),
				b"x".to_vec(),
				alloc::vec![cand(1, b"A")],
				0,
				1,
				1,
			),
			Error::<Test>::ZeroVotingPeriod,
		);
	});
}

// ─── cast_vote ─────────────────────────────────────────────────────────

fn setup_proposal_with_two_voters() -> ProposalId {
	assert_ok!(Governance::register_voter(RuntimeOrigin::signed(ALICE), US));
	assert_ok!(Governance::register_voter(RuntimeOrigin::signed(BOB), UK));
	assert_ok!(Governance::propose(
		RuntimeOrigin::signed(ALICE),
		b"x".to_vec(),
		alloc::vec![cand(1, b"Yes"), cand(2, b"No")],
		100,
		1,
		1,
	));
	0
}

#[test]
fn cast_vote_records_ballot() {
	ext().execute_with(|| {
		let pid = setup_proposal_with_two_voters();
		assert_ok!(Governance::cast_vote(
			RuntimeOrigin::signed(ALICE),
			pid,
			alloc::vec![1, 2],
		));
		let ballot = Votes::<Test>::get(pid, ALICE).unwrap();
		assert_eq!(ballot.ranking.into_inner(), alloc::vec![1, 2]);
	});
}

#[test]
fn cast_vote_rejects_unregistered_voter() {
	ext().execute_with(|| {
		let pid = setup_proposal_with_two_voters();
		assert_noop!(
			Governance::cast_vote(
				RuntimeOrigin::signed(CHARLIE),
				pid,
				alloc::vec![1, 2],
			),
			Error::<Test>::NotRegisteredVoter,
		);
	});
}

#[test]
fn cast_vote_rejects_duplicate_vote() {
	ext().execute_with(|| {
		let pid = setup_proposal_with_two_voters();
		assert_ok!(Governance::cast_vote(RuntimeOrigin::signed(ALICE), pid, alloc::vec![1]));
		assert_noop!(
			Governance::cast_vote(RuntimeOrigin::signed(ALICE), pid, alloc::vec![2]),
			Error::<Test>::AlreadyVoted,
		);
	});
}

#[test]
fn cast_vote_rejects_unknown_candidate_id_in_ranking() {
	ext().execute_with(|| {
		let pid = setup_proposal_with_two_voters();
		assert_noop!(
			Governance::cast_vote(
				RuntimeOrigin::signed(ALICE),
				pid,
				alloc::vec![1, 99],
			),
			Error::<Test>::UnknownCandidateInRanking,
		);
	});
}

#[test]
fn cast_vote_rejects_duplicate_in_ranking() {
	ext().execute_with(|| {
		let pid = setup_proposal_with_two_voters();
		assert_noop!(
			Governance::cast_vote(
				RuntimeOrigin::signed(ALICE),
				pid,
				alloc::vec![1, 1],
			),
			Error::<Test>::DuplicateRankingId,
		);
	});
}

#[test]
fn cast_vote_rejects_after_voting_period_ends() {
	ext().execute_with(|| {
		let pid = setup_proposal_with_two_voters();
		System::set_block_number(200);
		assert_noop!(
			Governance::cast_vote(RuntimeOrigin::signed(ALICE), pid, alloc::vec![1]),
			Error::<Test>::VotingPeriodEnded,
		);
	});
}

// ─── tally ─────────────────────────────────────────────────────────────

fn populate_voters_and_propose(quorum_each: u32) -> ProposalId {
	for (acct, country) in [
		(ALICE, US),
		(BOB, US),
		(CHARLIE, UK),
		(DAVE, UK),
		(EVE, FR),
		(FRANK, FR),
		(GRACE, US),
	] {
		assert_ok!(Governance::register_voter(RuntimeOrigin::signed(acct), country));
	}
	assert_ok!(Governance::propose(
		RuntimeOrigin::signed(ALICE),
		b"Trade deal?".to_vec(),
		alloc::vec![cand(1, b"Yes"), cand(2, b"No"), cand(3, b"Defer")],
		10,
		quorum_each,
		quorum_each,
	));
	0
}

#[test]
fn tally_rejects_before_voting_period_ends() {
	ext().execute_with(|| {
		let pid = populate_voters_and_propose(1);
		assert_noop!(
			Governance::tally(RuntimeOrigin::signed(ALICE), pid),
			Error::<Test>::VotingPeriodStillOpen,
		);
	});
}

#[test]
fn tally_concurrent_assent_passes_when_both_chambers_agree() {
	ext().execute_with(|| {
		let pid = populate_voters_and_propose(3);
		// Everyone votes 1 first
		for acct in [ALICE, BOB, CHARLIE, DAVE, EVE, FRANK, GRACE] {
			assert_ok!(Governance::cast_vote(
				RuntimeOrigin::signed(acct),
				pid,
				alloc::vec![1, 2, 3],
			));
		}
		System::set_block_number(20);
		assert_ok!(Governance::tally(RuntimeOrigin::signed(ALICE), pid));
		let p = Governance::proposal_of(pid).unwrap();
		match p.state {
			ProposalState::Tallied { winner, blocking_chamber } => {
				assert_eq!(winner, Some(1));
				assert_eq!(blocking_chamber, None);
			},
			_ => panic!("expected Tallied"),
		}
	});
}

#[test]
fn tally_blocks_when_upper_chamber_quorum_unmet() {
	ext().execute_with(|| {
		// quorum=10 means upper chamber (7 voters total in v1
		// since the same ballots count both ways) won't reach
		// quorum.
		let pid = populate_voters_and_propose(10);
		for acct in [ALICE, BOB, CHARLIE, DAVE, EVE, FRANK, GRACE] {
			assert_ok!(Governance::cast_vote(
				RuntimeOrigin::signed(acct),
				pid,
				alloc::vec![1],
			));
		}
		System::set_block_number(20);
		assert_ok!(Governance::tally(RuntimeOrigin::signed(ALICE), pid));
		let p = Governance::proposal_of(pid).unwrap();
		match p.state {
			ProposalState::Tallied { winner, blocking_chamber: _ } => {
				assert_eq!(winner, None);
			},
			_ => panic!("expected Tallied"),
		}
	});
}

#[test]
fn tally_rejects_double_tally() {
	ext().execute_with(|| {
		let pid = populate_voters_and_propose(1);
		System::set_block_number(20);
		assert_ok!(Governance::tally(RuntimeOrigin::signed(ALICE), pid));
		assert_noop!(
			Governance::tally(RuntimeOrigin::signed(ALICE), pid),
			Error::<Test>::ProposalAlreadyTallied,
		);
	});
}

// ─── IRV correctness ───────────────────────────────────────────────────

#[test]
fn irv_winner_returns_majority_first_choice() {
	let ballots: Vec<Vec<CandidateId>> = alloc::vec![
		alloc::vec![1, 2, 3],
		alloc::vec![1, 3, 2],
		alloc::vec![1, 2, 3],
		alloc::vec![2, 1, 3],
	];
	assert_eq!(crate::irv_winner(&ballots, &alloc::vec![1, 2, 3]), Some(1));
}

#[test]
fn irv_winner_eliminates_low_then_runs_off() {
	// 3 voters: 2 want A first, 1 wants B first; B is also
	// least-popular and gets eliminated; B's voter flows to C.
	// Wait, that doesn't match — let me redo.
	// Ballots:
	//   A B C
	//   A C B
	//   B A C
	//   C B A
	//   C A B
	// First-prefs: A=2, B=1, C=2 → no majority (5 ballots, need 3).
	// Eliminate B (lowest, tied with itself). B-voter's next is A.
	// Round 2: A=3, C=2 → A wins.
	let ballots: Vec<Vec<CandidateId>> = alloc::vec![
		alloc::vec![1, 2, 3],
		alloc::vec![1, 3, 2],
		alloc::vec![2, 1, 3],
		alloc::vec![3, 2, 1],
		alloc::vec![3, 1, 2],
	];
	assert_eq!(crate::irv_winner(&ballots, &alloc::vec![1, 2, 3]), Some(1));
}

#[test]
fn irv_winner_handles_partial_rankings() {
	// Voter only ranks first preference; their ballot is exhausted
	// after that candidate is eliminated.
	let ballots: Vec<Vec<CandidateId>> = alloc::vec![
		alloc::vec![1],
		alloc::vec![2, 1, 3],
		alloc::vec![3, 1, 2],
	];
	// Round 1: 1=1, 2=1, 3=1 → no majority. Eliminate lowest id
	// (tie-break = lowest id) = 1. Ballot 1 exhausts. Round 2:
	// 2=1, 3=1 → still tie. Eliminate 2 (lowest). Round 3: 3=1
	// (from ballot 3 directly; ballot 2 had 2 eliminated, falls to
	// 1, but 1 is also gone, falls to 3) — total 3=2 winners.
	assert_eq!(crate::irv_winner(&ballots, &alloc::vec![1, 2, 3]), Some(3));
}

#[test]
fn irv_winner_returns_none_for_empty_input() {
	let ballots: Vec<Vec<CandidateId>> = alloc::vec![];
	assert_eq!(crate::irv_winner(&ballots, &alloc::vec![1, 2, 3]), None);
}
