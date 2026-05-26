// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Tests for `pallet-rostro-governance`. Mock runtime + scenarios
//! covering registration, proposal lifecycle, vote casting,
//! ranked-choice tally, and concurrent-assent inter-chamber
//! resolution.

use crate as pallet_rostro_governance;
use crate::*;

use frame_support::{assert_noop, assert_ok, derive_impl, traits::{ConstU32, ConstU64}};
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
	type StrikesBeforePruning = ConstU32<3>;
	// 200 blocks is a comfortable round-2 window for the test
	// scenarios (parent voting_period_blocks of 10–100 leaves
	// plenty of timing headroom). Production target: 43,200
	// (72h at 6s blocks).
	type Round2WindowBlocks = ConstU64<200>;
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
			ProposalState::Tallied(TallyOutcome::Passed { winner }) => {
				assert_eq!(winner, 1);
			},
			_ => panic!("expected Tallied(Passed)"),
		}
	});
}

#[test]
fn tally_blocks_when_both_chambers_miss_quorum() {
	ext().execute_with(|| {
		// quorum=10 means both chambers (7 voters total in v1
		// since the same ballots count both ways) miss quorum.
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
			ProposalState::Tallied(TallyOutcome::QuorumFailed {
				upper_failed,
				lower_failed,
				escalated_to,
			}) => {
				assert!(upper_failed);
				assert!(lower_failed);
				assert_eq!(escalated_to, None);
			},
			_ => panic!("expected Tallied(QuorumFailed)"),
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

// ─── 8b: strike accounting ─────────────────────────────────────────────

/// Helper: drive a proposal end-to-end, optionally with a subset
/// of voters casting. Returns the proposal id. Resets nothing —
/// caller controls scenario setup.
fn run_proposal_with_voters_casting(
	non_casters_skipped: &[AccountId],
) -> ProposalId {
	let pid = NextProposalId::<Test>::get();
	let start = System::block_number();
	assert_ok!(Governance::propose(
		RuntimeOrigin::signed(ALICE),
		b"x".to_vec(),
		alloc::vec![cand(1, b"Y"), cand(2, b"N")],
		10,
		1,
		1,
	));
	for acct in [ALICE, BOB, CHARLIE, DAVE, EVE, FRANK, GRACE] {
		if !Voters::<Test>::contains_key(&acct) || non_casters_skipped.contains(&acct) {
			continue;
		}
		assert_ok!(Governance::cast_vote(
			RuntimeOrigin::signed(acct),
			pid,
			alloc::vec![1, 2],
		));
	}
	System::set_block_number(start + 11);
	assert_ok!(Governance::tally(RuntimeOrigin::signed(ALICE), pid));
	pid
}

#[test]
fn tally_increments_missed_votes_for_eligible_non_casters() {
	ext().execute_with(|| {
		// All seven register before the proposal exists.
		for (acct, country) in [
			(ALICE, US), (BOB, US), (CHARLIE, UK), (DAVE, UK),
			(EVE, FR), (FRANK, FR), (GRACE, US),
		] {
			assert_ok!(Governance::register_voter(RuntimeOrigin::signed(acct), country));
		}
		// BOB skips voting.
		run_proposal_with_voters_casting(&[BOB]);
		assert_eq!(Governance::voter_of(&BOB).unwrap().missed_votes, 1);
		assert_eq!(Governance::voter_of(&ALICE).unwrap().missed_votes, 0);
	});
}

#[test]
fn tally_resets_missed_votes_for_casters() {
	ext().execute_with(|| {
		for (acct, country) in [(ALICE, US), (BOB, US)] {
			assert_ok!(Governance::register_voter(RuntimeOrigin::signed(acct), country));
		}
		// Two proposals where BOB doesn't vote → strikes climb.
		run_proposal_with_voters_casting(&[BOB]);
		run_proposal_with_voters_casting(&[BOB]);
		assert_eq!(Governance::voter_of(&BOB).unwrap().missed_votes, 2);
		// Now BOB casts → strikes reset.
		run_proposal_with_voters_casting(&[]);
		assert_eq!(Governance::voter_of(&BOB).unwrap().missed_votes, 0);
	});
}

#[test]
fn tally_skips_voters_registered_after_proposal_creation() {
	ext().execute_with(|| {
		assert_ok!(Governance::register_voter(RuntimeOrigin::signed(ALICE), US));
		let pid = NextProposalId::<Test>::get();
		assert_ok!(Governance::propose(
			RuntimeOrigin::signed(ALICE),
			b"x".to_vec(),
			alloc::vec![cand(1, b"Y"), cand(2, b"N")],
			10,
			1,
			1,
		));
		// BOB registers AFTER the proposal was created. He's not
		// expected to vote on it.
		assert_ok!(Governance::register_voter(RuntimeOrigin::signed(BOB), UK));
		assert_ok!(Governance::cast_vote(
			RuntimeOrigin::signed(ALICE),
			pid,
			alloc::vec![1, 2],
		));
		System::set_block_number(20);
		assert_ok!(Governance::tally(RuntimeOrigin::signed(ALICE), pid));
		// BOB should NOT be struck for skipping pid.
		assert_eq!(Governance::voter_of(&BOB).unwrap().missed_votes, 0);
	});
}

// ─── 8b: addition-paced pruning ────────────────────────────────────────

/// Drive enough proposals to push a target voter's missed_votes
/// above the threshold (3). Only the target abstains; everyone
/// else casts.
fn accumulate_strikes(target: AccountId, count: u32) {
	for _ in 0..count {
		run_proposal_with_voters_casting(&[target]);
	}
}

#[test]
fn register_voter_swaps_out_eligible_non_voter_in_target_district() {
	ext().execute_with(|| {
		// TotalDistricts=3 → ALICE,BOB,CHARLIE go to districts 0,1,2.
		// DAVE then targets district 0 (round-robin wraps).
		assert_ok!(Governance::register_voter(RuntimeOrigin::signed(ALICE), US));
		assert_ok!(Governance::register_voter(RuntimeOrigin::signed(BOB), UK));
		assert_ok!(Governance::register_voter(RuntimeOrigin::signed(CHARLIE), FR));
		// Drive ALICE's strikes above threshold (3).
		accumulate_strikes(ALICE, 3);
		assert!(Governance::voter_of(&ALICE).unwrap().missed_votes >= 3);

		// DAVE's registration should target district 0 and prune
		// ALICE atomically.
		assert_ok!(Governance::register_voter(RuntimeOrigin::signed(DAVE), US));
		assert!(Governance::voter_of(&ALICE).is_none(), "ALICE should be pruned");
		// Roster size unchanged: ALICE replaced by DAVE.
		assert_eq!(LowerDistrictRoster::<Test>::get(0).into_inner(), alloc::vec![DAVE]);
		// ALICE also removed from her upper-country roster.
		assert!(!UpperCountryRoster::<Test>::get(US).contains(&ALICE));
	});
}

#[test]
fn register_voter_no_swap_when_no_eligible_non_voter() {
	ext().execute_with(|| {
		assert_ok!(Governance::register_voter(RuntimeOrigin::signed(ALICE), US));
		assert_ok!(Governance::register_voter(RuntimeOrigin::signed(BOB), UK));
		assert_ok!(Governance::register_voter(RuntimeOrigin::signed(CHARLIE), FR));
		// No strikes. DAVE registers into district 0 → ALICE
		// stays, DAVE just grows the district.
		assert_ok!(Governance::register_voter(RuntimeOrigin::signed(DAVE), US));
		assert!(Governance::voter_of(&ALICE).is_some());
		assert_eq!(LowerDistrictRoster::<Test>::get(0).into_inner(), alloc::vec![ALICE, DAVE]);
	});
}

#[test]
fn register_voter_does_not_prune_voter_below_threshold() {
	ext().execute_with(|| {
		assert_ok!(Governance::register_voter(RuntimeOrigin::signed(ALICE), US));
		assert_ok!(Governance::register_voter(RuntimeOrigin::signed(BOB), UK));
		assert_ok!(Governance::register_voter(RuntimeOrigin::signed(CHARLIE), FR));
		// Two strikes, threshold is 3 → not eligible.
		accumulate_strikes(ALICE, 2);
		assert_eq!(Governance::voter_of(&ALICE).unwrap().missed_votes, 2);
		assert_ok!(Governance::register_voter(RuntimeOrigin::signed(DAVE), US));
		assert!(Governance::voter_of(&ALICE).is_some());
		assert_eq!(LowerDistrictRoster::<Test>::get(0).into_inner(), alloc::vec![ALICE, DAVE]);
	});
}

#[test]
fn register_voter_only_prunes_target_district() {
	ext().execute_with(|| {
		assert_ok!(Governance::register_voter(RuntimeOrigin::signed(ALICE), US));
		assert_ok!(Governance::register_voter(RuntimeOrigin::signed(BOB), UK));
		assert_ok!(Governance::register_voter(RuntimeOrigin::signed(CHARLIE), FR));
		// ALICE accumulates strikes — she's in district 0.
		accumulate_strikes(ALICE, 3);
		// Force the next registration to target district 1 (BOB's
		// district), not district 0 (ALICE's). The round-robin
		// counter wraps mod TotalDistricts=3, so value 4 ≡ 1.
		NextDistrictAssignment::<Test>::put(4);
		assert_ok!(Governance::register_voter(RuntimeOrigin::signed(DAVE), UK));
		// District 1's non-voters are not ALICE → no prune in
		// district 0. BOB has no strikes → no prune in district 1.
		assert!(
			Governance::voter_of(&ALICE).is_some(),
			"ALICE in district 0 should not be pruned by registration into district 1",
		);
		assert!(Governance::voter_of(&BOB).is_some());
		assert_eq!(Governance::voter_of(&DAVE).unwrap().seats.lower_district, 1);
	});
}

// ─── 8b: round-2 escalation ────────────────────────────────────────────

#[test]
fn escalate_to_round_2_creates_followup_with_inherited_shape() {
	ext().execute_with(|| {
		// Single registered voter + quorum=5 forces quorum failure.
		assert_ok!(Governance::register_voter(RuntimeOrigin::signed(ALICE), US));
		let parent_id = NextProposalId::<Test>::get();
		assert_ok!(Governance::propose(
			RuntimeOrigin::signed(ALICE),
			b"Big question".to_vec(),
			alloc::vec![cand(1, b"A"), cand(2, b"B"), cand(3, b"C")],
			10,
			5,
			5,
		));
		assert_ok!(Governance::cast_vote(
			RuntimeOrigin::signed(ALICE),
			parent_id,
			alloc::vec![1],
		));
		System::set_block_number(20);
		assert_ok!(Governance::tally(RuntimeOrigin::signed(ALICE), parent_id));

		// Now escalate.
		assert_ok!(Governance::escalate_to_round_2(RuntimeOrigin::signed(ALICE), parent_id));
		let parent = Governance::proposal_of(parent_id).unwrap();
		let new_id = match parent.state {
			ProposalState::Tallied(TallyOutcome::QuorumFailed { escalated_to, .. }) => {
				escalated_to.expect("parent should now point at round 2")
			},
			_ => panic!("expected QuorumFailed with escalation pointer"),
		};
		let r2 = Governance::proposal_of(new_id).unwrap();
		assert_eq!(r2.round, 2);
		assert_eq!(r2.parent_proposal, Some(parent_id));
		assert_eq!(r2.upper_quorum, parent.upper_quorum);
		assert_eq!(r2.lower_quorum, parent.lower_quorum);
		assert_eq!(r2.candidates.len(), parent.candidates.len());
		assert!(matches!(r2.state, ProposalState::Active));
		// Title carries the "[r2] " prefix.
		assert!(r2.title.starts_with(b"[r2] "));
	});
}

#[test]
fn escalate_to_round_2_rejects_when_parent_passed() {
	ext().execute_with(|| {
		assert_ok!(Governance::register_voter(RuntimeOrigin::signed(ALICE), US));
		let pid = NextProposalId::<Test>::get();
		assert_ok!(Governance::propose(
			RuntimeOrigin::signed(ALICE),
			b"x".to_vec(),
			alloc::vec![cand(1, b"Y"), cand(2, b"N")],
			10,
			1,
			1,
		));
		assert_ok!(Governance::cast_vote(
			RuntimeOrigin::signed(ALICE),
			pid,
			alloc::vec![1],
		));
		System::set_block_number(20);
		assert_ok!(Governance::tally(RuntimeOrigin::signed(ALICE), pid));
		assert_noop!(
			Governance::escalate_to_round_2(RuntimeOrigin::signed(ALICE), pid),
			Error::<Test>::NotQuorumFailed,
		);
	});
}

#[test]
fn escalate_to_round_2_rejects_double_escalation() {
	ext().execute_with(|| {
		assert_ok!(Governance::register_voter(RuntimeOrigin::signed(ALICE), US));
		let pid = NextProposalId::<Test>::get();
		assert_ok!(Governance::propose(
			RuntimeOrigin::signed(ALICE),
			b"x".to_vec(),
			alloc::vec![cand(1, b"Y"), cand(2, b"N")],
			10,
			5,
			5,
		));
		assert_ok!(Governance::cast_vote(
			RuntimeOrigin::signed(ALICE),
			pid,
			alloc::vec![1],
		));
		System::set_block_number(20);
		assert_ok!(Governance::tally(RuntimeOrigin::signed(ALICE), pid));
		assert_ok!(Governance::escalate_to_round_2(RuntimeOrigin::signed(ALICE), pid));
		assert_noop!(
			Governance::escalate_to_round_2(RuntimeOrigin::signed(ALICE), pid),
			Error::<Test>::AlreadyEscalated,
		);
	});
}

#[test]
fn escalate_to_round_2_rejects_round_2_proposal() {
	ext().execute_with(|| {
		assert_ok!(Governance::register_voter(RuntimeOrigin::signed(ALICE), US));
		let r1 = NextProposalId::<Test>::get();
		assert_ok!(Governance::propose(
			RuntimeOrigin::signed(ALICE),
			b"x".to_vec(),
			alloc::vec![cand(1, b"Y"), cand(2, b"N")],
			10,
			5,
			5,
		));
		assert_ok!(Governance::cast_vote(
			RuntimeOrigin::signed(ALICE),
			r1,
			alloc::vec![1],
		));
		System::set_block_number(20);
		assert_ok!(Governance::tally(RuntimeOrigin::signed(ALICE), r1));
		assert_ok!(Governance::escalate_to_round_2(RuntimeOrigin::signed(ALICE), r1));
		// The new proposal is round 2. Even if it ALSO quorum-
		// fails, it can't be escalated to round 3.
		let r2 = NextProposalId::<Test>::get() - 1;
		assert_ok!(Governance::cast_vote(
			RuntimeOrigin::signed(ALICE),
			r2,
			alloc::vec![1],
		));
		System::set_block_number(System::block_number() + 250);
		assert_ok!(Governance::tally(RuntimeOrigin::signed(ALICE), r2));
		assert_noop!(
			Governance::escalate_to_round_2(RuntimeOrigin::signed(ALICE), r2),
			Error::<Test>::NotRound1,
		);
	});
}

#[test]
fn escalate_to_round_2_rejects_active_proposal() {
	ext().execute_with(|| {
		assert_ok!(Governance::register_voter(RuntimeOrigin::signed(ALICE), US));
		let pid = NextProposalId::<Test>::get();
		assert_ok!(Governance::propose(
			RuntimeOrigin::signed(ALICE),
			b"x".to_vec(),
			alloc::vec![cand(1, b"Y"), cand(2, b"N")],
			10,
			1,
			1,
		));
		assert_noop!(
			Governance::escalate_to_round_2(RuntimeOrigin::signed(ALICE), pid),
			Error::<Test>::NotQuorumFailed,
		);
	});
}
