// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

#![cfg(test)]

use crate::{
	mock::*, ActiveKey, DisableReason, Disabled, Error, Event, Keys as LineageKeys, Roster,
};
use frame_support::{assert_noop, assert_ok};

type Session = pallet_session::Pallet<Test>;

fn set_keys(who: AccountId, seed: u8) -> frame_support::dispatch::DispatchResult {
	Session::set_keys(RuntimeOrigin::signed(who), keys_for(seed), pop_proof(seed, who))
}

fn lineage_events() -> Vec<Event<Test>> {
	System::events()
		.into_iter()
		.filter_map(|r| match r.event {
			RuntimeEvent::KeyLineage(e) => Some(e),
			_ => None,
		})
		.collect()
}

#[test]
fn genesis_keys_captured_at_first_rotation() {
	new_test_ext().execute_with(|| {
		// Nothing recorded before the first rotation.
		assert!(ActiveKey::<Test>::iter().next().is_none());

		advance_session();

		// Roster captured, all four genesis validators active with their
		// genesis keys, each key permanently recorded.
		assert_eq!(Roster::<Test>::get().into_inner(), vec![1, 2, 3, 4]);
		for v in 1..=4u64 {
			let key = gran_key(v as u8).1;
			assert_eq!(active_grandpa_key(v), Some(key.clone()));
			let record = LineageKeys::<Test>::get(&key).unwrap();
			assert_eq!(record.owner, v);
			assert!(record.activated.is_some());
			assert!(record.retired.is_none());
		}
		assert_eq!(Session::validators(), vec![1, 2, 3, 4]);
	});
}

#[test]
fn fresh_key_rotates_and_old_key_retires_with_set_ids() {
	new_test_ext().execute_with(|| {
		run_to_block(3);
		let old_key = gran_key(1).1;
		assert_eq!(active_grandpa_key(1), Some(old_key.clone()));

		assert_ok!(set_keys(1, 11));
		let new_key = gran_key(11).1;

		// Registered immediately, activates two rotations later (queued at
		// the next rotation, active at the one after).
		let record = LineageKeys::<Test>::get(&new_key).unwrap();
		assert_eq!(record.owner, 1);
		assert!(record.activated.is_none());

		advance_session(); // new key gets queued
		assert_eq!(active_grandpa_key(1), Some(old_key.clone()));
		advance_session(); // new key becomes active

		assert_eq!(active_grandpa_key(1), Some(new_key.clone()));
		let old = LineageKeys::<Test>::get(&old_key).unwrap();
		let new = LineageKeys::<Test>::get(&new_key).unwrap();
		let retired = old.retired.expect("old key must be retired");
		let activated = new.activated.expect("new key must be activated");
		// The new key's first set is the one right after the old key's last.
		assert_eq!(activated.set_id, retired.set_id + 1);
		// The activation set is the one the swap rotation itself introduced,
		// i.e. the current set after the rotation's set-id bump.
		assert_eq!(activated.set_id, current_mock_set_id());
	});
}

#[test]
fn seen_key_is_rejected_forever() {
	new_test_ext().execute_with(|| {
		advance_session(); // capture genesis keys into lineage

		// Re-registering one's own live key: rejected.
		assert_noop!(set_keys(1, 1), Error::<Test>::GrandpaKeyAlreadySeen);
		// Another validator claiming a seen key: rejected.
		assert_noop!(set_keys(2, 1), Error::<Test>::GrandpaKeyAlreadySeen);

		// Fresh key accepted, then instantly burned for everyone, forever —
		// including its own registrant, even before it activates.
		assert_ok!(set_keys(1, 42));
		assert_noop!(set_keys(1, 42), Error::<Test>::GrandpaKeyAlreadySeen);
		assert_noop!(set_keys(3, 42), Error::<Test>::GrandpaKeyAlreadySeen);

		// A retired key stays burned.
		run_to_block(System::block_number() + 2);
		assert!(LineageKeys::<Test>::get(&gran_key(1).1).unwrap().retired.is_some());
		assert_noop!(set_keys(1, 1), Error::<Test>::GrandpaKeyAlreadySeen);
	});
}

#[test]
fn deadline_miss_disables_from_next_set_and_fresh_key_heals() {
	new_test_ext().execute_with(|| {
		advance_session(); // era 0: lineage capture, age clocks start

		// Era 7: age 7 == K, still compliant (strictly-older cutover).
		set_era(7);
		advance_session();
		assert_eq!(Session::validators(), vec![1, 2, 3, 4]);
		assert!(Disabled::<Test>::iter().next().is_none());

		// Era 8: age 8 > K. Validators 1-3 rotate in time; 4 does not.
		set_era(8);
		assert_ok!(set_keys(1, 21));
		assert_ok!(set_keys(2, 22));
		assert_ok!(set_keys(3, 23));
		advance_session(); // planning excludes 4, queues the compliant set
		let d = Disabled::<Test>::get(4).expect("4 must be disabled");
		assert_eq!(d.reason, DisableReason::DeadlineMissed);
		advance_session(); // exclusion takes effect in the active set
		assert_eq!(Session::validators(), vec![1, 2, 3]);

		// 4's genesis key retired when it dropped out.
		assert!(LineageKeys::<Test>::get(&gran_key(4).1).unwrap().retired.is_some());

		// Healing: 4 registers a fresh key; back in from the next planning.
		assert_ok!(set_keys(4, 24));
		assert!(Disabled::<Test>::get(4).is_none());
		assert!(lineage_events().contains(&Event::ValidatorHealed { validator: 4 }));
		advance_session();
		advance_session();
		assert_eq!(Session::validators(), vec![1, 2, 3, 4]);
		assert_eq!(active_grandpa_key(4), Some(gran_key(24).1));
	});
}

#[test]
fn liveness_floor_keeps_previous_set_when_everyone_misses() {
	new_test_ext().execute_with(|| {
		advance_session();
		set_era(20); // everyone's key is now hopelessly stale

		advance_session();
		// All four excluded → floor: previous set kept, alarm emitted.
		assert!(lineage_events().contains(&Event::EnforcementFloorHit));
		advance_session();
		assert_eq!(Session::validators(), vec![1, 2, 3, 4]);

		// All four carry a DeadlineMissed record: the floor does not pardon.
		for v in 1..=4u64 {
			assert_eq!(
				Disabled::<Test>::get(v).unwrap().reason,
				DisableReason::DeadlineMissed
			);
		}

		// One validator healing is enough for enforcement to resume — the
		// set collapses to the compliant one.
		assert_ok!(set_keys(2, 33));
		advance_session();
		advance_session();
		assert_eq!(Session::validators(), vec![2]);
	});
}

#[test]
fn purged_keys_drop_validator_and_retire_key() {
	new_test_ext().execute_with(|| {
		advance_session();
		assert_ok!(Session::purge_keys(RuntimeOrigin::signed(4)));
		advance_session(); // planning: no keys to load for 4
		advance_session();
		assert_eq!(Session::validators(), vec![1, 2, 3]);
		assert!(LineageKeys::<Test>::get(&gran_key(4).1).unwrap().retired.is_some());
		assert_eq!(active_grandpa_key(4), None);

		// purge did NOT free the key for re-registration.
		assert_noop!(set_keys(4, 4), Error::<Test>::GrandpaKeyAlreadySeen);
		// A fresh key brings the validator back.
		assert_ok!(set_keys(4, 44));
		advance_session();
		advance_session();
		assert_eq!(Session::validators(), vec![1, 2, 3, 4]);
	});
}

#[test]
fn offence_disable_excludes_until_fresh_key() {
	new_test_ext().execute_with(|| {
		advance_session();

		crate::Pallet::<Test>::disable_for_offence(&3);
		assert_eq!(Disabled::<Test>::get(3).unwrap().reason, DisableReason::Offence);

		advance_session();
		advance_session();
		assert_eq!(Session::validators(), vec![1, 2, 4]);

		// Rotating one's own key via the account origin is the healing path.
		assert_ok!(set_keys(3, 55));
		advance_session();
		advance_session();
		assert_eq!(Session::validators(), vec![1, 2, 3, 4]);
	});
}

#[test]
fn set_keys_proof_still_enforced() {
	new_test_ext().execute_with(|| {
		advance_session();
		// A valid PoP for the wrong owner must not pass: proves the
		// provenance hook composes with (not replaces) the possession check.
		let bad = Session::set_keys(
			RuntimeOrigin::signed(1),
			keys_for(60),
			pop_proof(60, 2), // signed for owner 2, submitted by 1
		);
		assert!(bad.is_err());
		// And the failed dispatch must not have burned the key.
		assert_ok!(set_keys(1, 60));
	});
}
