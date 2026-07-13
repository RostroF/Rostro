// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # Rostro key-lineage pallet
//!
//! Permanent lineage for the GRANDPA juror credential
//! (docs/CONSENSUS-KEY-LIFECYCLE.md, workstream 1 P1). Three jobs:
//!
//! 1. **Fresh-key primitive.** Every `pallet_session::set_keys` registration
//!    flows through [`pallet_session::KeyProvenance`], which this pallet
//!    implements: a GRANDPA key is accepted exactly once in chain history.
//!    `pallet_session` itself only prevents two validators holding the same
//!    key *concurrently* (it clears ownership on replacement); lineage makes
//!    the ban permanent, which is what turns a retired key into something
//!    that can never legitimately sign again.
//! 2. **Permanent key records.** For every key: owner, registration era, and
//!    activation/retirement points carrying the GRANDPA `set_id`. Retirement
//!    records the *last authority set the key served*, so any signature over
//!    a GRANDPA-domain preimage scoped to a later set is definitionally
//!    evidence of key compromise (the retired-key canary offence, P2).
//! 3. **Forced-rotation deadline.** As session manager, the pallet plans each
//!    session from the elected set produced by [`Config::ElectedSet`] (NPoS
//!    staking in the runtime; sessions where staking plans no new era re-feed
//!    the live set) minus validators whose *next* key is older than
//!    [`Config::MaxKeyAgeEras`] eras and minus validators disabled by an
//!    offence. Hard cutover, no grace window; re-entry is automatic on
//!    registering a fresh key, which is also the post-compromise healing
//!    path (the account key, not the session key, authorizes `set_keys`).
//!
//! An **era** here is the 24h membership epoch ([`Config::CurrentEra`] binds
//! to the same clock as the zkpki `membership_epoch`) — NOT pallet-staking's
//! election era, which is a shorter multiple of the session length.
//!
//! ## Liveness floor
//!
//! If enforcement would produce an *empty* validator set, the pallet returns
//! `None` (keep the previous set) and emits [`Event::EnforcementFloorHit`].
//! An empty GRANDPA authority set is unrecoverable chain death, not a hard
//! cutover; the floor converts "everyone missed the deadline" into a loudly
//! visible stall of enforcement rather than a bricked chain.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{vec, vec::Vec};
use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use frame_support::{
	dispatch::DispatchResult, ensure, traits::Get, weights::Weight, BoundedVec,
};
use pallet_session::SessionManager;
use scale_info::TypeInfo;
use sp_consensus_grandpa::{AuthorityId, AuthoritySignature};
use sp_runtime::{
	traits::{Convert, OpaqueKeys},
	Perbill, RuntimeAppPublic,
};
use sp_staking::{
	offence::{Kind, Offence, OffenceDetails, OffenceError, OnOffenceHandler, ReportOffence},
	SessionIndex,
};

/// The offender type reported to the offence sink: the historical
/// identification tuple, same shape GRANDPA equivocations use.
pub type IdentificationTuple<T> = pallet_session::historical::IdentificationTuple<T>;

pub use pallet::*;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

const LOG_TARGET: &str = "runtime::key-lineage";

/// Era index: the 24h membership epoch.
pub type EraIndex = u32;

/// A point in the key lifecycle, recorded when the pallet observes a
/// transition at a session rotation.
#[derive(Clone, Eq, PartialEq, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo, Debug)]
pub struct LifecyclePoint {
	/// Era at which the transition was observed.
	pub era: EraIndex,
	/// Session index at which the transition was observed.
	pub session: SessionIndex,
	/// For retirement: the last GRANDPA set id the key served — a signature
	/// scoped to any strictly greater set id is canary evidence. For
	/// activation: the first set id the key serves.
	pub set_id: u64,
}

/// Permanent record of one GRANDPA key. Never removed.
#[derive(Clone, Eq, PartialEq, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo, Debug)]
pub struct KeyRecord<ValidatorId> {
	/// The validator that registered the key. A key belongs to exactly one
	/// validator, forever.
	pub owner: ValidatorId,
	/// Era in which `set_keys` accepted the key (or, for keys that predate
	/// this pallet, the era in which the pallet first observed it live).
	pub registered_era: EraIndex,
	/// Set when the key first enters the authority set.
	pub activated: Option<LifecyclePoint>,
	/// Set when the key leaves the authority set. `set_id` is the last set
	/// it served.
	pub retired: Option<LifecyclePoint>,
}

/// Why a validator is currently excluded from new authority sets.
#[derive(Clone, Copy, Eq, PartialEq, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo, Debug)]
pub enum DisableReason {
	/// The validator's next-session key exceeded [`Config::MaxKeyAgeEras`].
	DeadlineMissed,
	/// An offence was reported against the validator (equivocation or
	/// retired-key canary; details live in `pallet_offences::Reports`).
	Offence,
}

/// The retired-key canary offence: a signature by a lineage-retired GRANDPA
/// key over a GRANDPA-domain preimage scoped to a set id *after* the key's
/// retirement. No honest process can produce one — the chain's own lineage
/// proves the key should never sign in that scope again — so the signature
/// itself is the complete evidence, submittable by anyone. Testnet
/// consequence is disable + permanent record; `slash_fraction` is the seam
/// where staking economics plug in later.
#[derive(Clone, PartialEq, Eq, Encode, Decode, TypeInfo, Debug)]
pub struct RetiredKeyOffence<Offender> {
	/// Session at which the evidence was accepted (the offence is timeless;
	/// this anchors the report for the offence store).
	pub session_index: SessionIndex,
	/// Validator-set size at acceptance, for slash-fraction arithmetic.
	pub validator_set_count: u32,
	/// The owner of the retired key.
	pub offender: Offender,
	/// The GRANDPA set id the forged preimage was scoped to.
	pub set_id: u64,
	/// The GRANDPA round the forged preimage was scoped to.
	pub round: u64,
}

impl<Offender: Clone> Offence<Offender> for RetiredKeyOffence<Offender> {
	const ID: Kind = *b"key-lineage:cnry";
	type TimeSlot = (u64, u64);

	fn offenders(&self) -> Vec<Offender> {
		vec![self.offender.clone()]
	}
	fn session_index(&self) -> SessionIndex {
		self.session_index
	}
	fn validator_set_count(&self) -> u32 {
		self.validator_set_count
	}
	fn time_slot(&self) -> Self::TimeSlot {
		(self.set_id, self.round)
	}
	fn slash_fraction(&self, _offenders_count: u32) -> Perbill {
		// Testnet: no staking, no economics — the consequence is
		// disable-and-record via the offence handler. When NPoS lands this
		// becomes a real fraction (a leaked juror credential is severe).
		Perbill::zero()
	}
}

/// Exclusion record. Removed (with the permanent history kept in events,
/// key records and offence reports) when the validator heals by registering
/// a fresh key.
#[derive(Clone, Copy, Eq, PartialEq, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo, Debug)]
pub struct DisableRecord {
	pub reason: DisableReason,
	pub era: EraIndex,
	pub session: SessionIndex,
}

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: pallet_session::historical::Config + frame_system::Config {
		/// The overarching event type.
		#[allow(deprecated)]
		type RuntimeEvent: From<Event<Self>>
			+ IsType<<Self as frame_system::Config>::RuntimeEvent>;

		/// The current era. Must be the 24h membership epoch: bind to the
		/// same arithmetic as the zkpki pallet's `current_epoch()` so "era"
		/// means one thing chain-wide.
		type CurrentEra: Get<EraIndex>;

		/// The current GRANDPA authority-set id, read live from
		/// `pallet_grandpa`. Consulted only at session rotation, *before*
		/// GRANDPA's session handler bumps it for the incoming session.
		type CurrentSetId: Get<u64>;

		/// Forced-rotation deadline K: a next-session key strictly older
		/// than this many eras excludes its validator from the next set.
		#[pallet::constant]
		type MaxKeyAgeEras: Get<u32>;

		/// Roster capacity; matches the GRANDPA `MaxAuthorities` bound.
		#[pallet::constant]
		type MaxValidators: Get<u32>;

		/// Where accepted retired-key canary evidence is reported
		/// (`pallet_offences` in the runtime; its handler routes back into
		/// this pallet's `OnOffenceHandler` for disable-and-record).
		type ReportCanary: ReportOffence<
			Self::AccountId,
			IdentificationTuple<Self>,
			RetiredKeyOffence<IdentificationTuple<Self>>,
		>;

		/// The producer of each session's intended validator set, filtered by
		/// this pallet's enforcement before it reaches `pallet_session`
		/// (pallet-staking's NPoS election in the runtime). `None` from the
		/// producer means "no new set planned this session"; this pallet then
		/// re-feeds [`PlannedSet`] — NOT the live session set, so a healed
		/// validator re-enters at the next session instead of waiting out the
		/// era — and every session stays `changed` (historical trie-root
		/// regeneration + GRANDPA set-id advance).
		type ElectedSet: pallet_session::SessionManager<Self::ValidatorId>;
	}

	/// The intended validator set: the most recent election result from
	/// [`Config::ElectedSet`]. On chains where no election has run yet it is
	/// captured lazily from the live session set at the first rotation.
	/// Enforcement filters this set each session; it is the stable base that
	/// lets an excluded validator re-enter on healing mid-era.
	#[pallet::storage]
	pub type PlannedSet<T: Config> =
		StorageValue<_, BoundedVec<T::ValidatorId, T::MaxValidators>, ValueQuery>;

	/// Permanent lineage, keyed by GRANDPA key. Entries are never removed.
	#[pallet::storage]
	pub type Keys<T: Config> =
		StorageMap<_, Blake2_128Concat, AuthorityId, KeyRecord<T::ValidatorId>, OptionQuery>;

	/// The key currently serving (or queued to serve) for each validator,
	/// maintained at session rotations.
	#[pallet::storage]
	pub type ActiveKey<T: Config> =
		StorageMap<_, Blake2_128Concat, T::ValidatorId, AuthorityId, OptionQuery>;

	/// Validators currently excluded from new authority sets. Cleared by a
	/// fresh `set_keys` registration (healing).
	#[pallet::storage]
	pub type Disabled<T: Config> =
		StorageMap<_, Blake2_128Concat, T::ValidatorId, DisableRecord, OptionQuery>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A fresh GRANDPA key was accepted for `validator` via `set_keys`.
		KeyRegistered { validator: T::ValidatorId, key: AuthorityId, era: EraIndex },
		/// A key entered the authority set (first set id it serves).
		KeyActivated { validator: T::ValidatorId, key: AuthorityId, set_id: u64 },
		/// A key left the authority set (`set_id` = last set it served).
		KeyRetired { validator: T::ValidatorId, key: AuthorityId, set_id: u64 },
		/// A validator was excluded from the next authority set.
		ValidatorDisabled { validator: T::ValidatorId, reason: DisableReason },
		/// A previously excluded validator healed by registering a fresh key.
		ValidatorHealed { validator: T::ValidatorId },
		/// Enforcement would have emptied the validator set; the previous
		/// set was kept instead. This is an operator-visible alarm, not a
		/// pardon: exclusion resumes as soon as at least one validator is
		/// compliant.
		EnforcementFloorHit,
		/// Valid retired-key canary evidence was accepted: `key` (owned by
		/// `validator`, retired as of `retired_set_id`) signed a
		/// GRANDPA-domain preimage scoped to the later `set_id`. The key is
		/// compromised.
		RetiredKeyEvidenceAccepted {
			validator: T::ValidatorId,
			key: AuthorityId,
			retired_set_id: u64,
			set_id: u64,
			round: u64,
		},
	}

	#[pallet::error]
	pub enum Error<T> {
		/// The submitted session keys contain no decodable GRANDPA key.
		MissingGrandpaKey,
		/// The GRANDPA key has already been seen on this chain. Keys are
		/// accepted exactly once in chain history; generate a fresh one.
		GrandpaKeyAlreadySeen,
		/// No lineage record for this key.
		UnknownKey,
		/// The key is not retired; a signature from a live key is not canary
		/// evidence (equivocation reporting covers live-key misbehaviour).
		KeyNotRetired,
		/// The preimage's set id does not postdate the key's retirement, so
		/// the signature could be a legitimately signed historical vote.
		ScopeNotAfterRetirement,
		/// Empty preimage.
		EmptyPreimage,
		/// The signature does not verify for this key over the GRANDPA
		/// signing domain `preimage ++ round ++ set_id`.
		BadSignature,
		/// This (key, set_id, round) evidence was already reported.
		DuplicateEvidence,
		/// The offence sink rejected the report.
		ReportRejected,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Report a signature made by a lineage-retired GRANDPA key over a
		/// GRANDPA-domain preimage scoped after the key's retirement.
		/// Submittable by anyone; the signature is the entire proof. The
		/// signed payload is checked against GRANDPA's signing domain:
		/// `message ++ round.encode() ++ set_id.encode()` (the
		/// `localized_payload` format), with `message` supplied raw so any
		/// GRANDPA-domain artifact qualifies, not only well-formed votes.
		///
		/// Fees are refunded when the evidence newly disables the offender,
		/// so watchers need no balance beyond the existential deposit; the
		/// refund is not repeatable for an already-disabled offender, which
		/// caps free-execution spam from a single stolen key.
		#[pallet::call_index(0)]
		#[pallet::weight(
			Weight::from_parts(150_000_000, 0)
				.saturating_add(T::DbWeight::get().reads_writes(4, 2))
		)]
		pub fn report_retired_key_signature(
			origin: OriginFor<T>,
			key: AuthorityId,
			round: u64,
			set_id: u64,
			message: BoundedVec<u8, ConstU32<4096>>,
			signature: AuthoritySignature,
		) -> DispatchResultWithPostInfo {
			let reporter = ensure_signed(origin)?;

			ensure!(!message.is_empty(), Error::<T>::EmptyPreimage);
			let record = Keys::<T>::get(&key).ok_or(Error::<T>::UnknownKey)?;
			let retired = record.retired.clone().ok_or(Error::<T>::KeyNotRetired)?;
			ensure!(set_id > retired.set_id, Error::<T>::ScopeNotAfterRetirement);

			// GRANDPA signing domain (sp_consensus_grandpa::localized_payload).
			let mut payload = message.into_inner();
			round.using_encoded(|b| payload.extend_from_slice(b));
			set_id.using_encoded(|b| payload.extend_from_slice(b));
			ensure!(key.verify(&payload, &signature), Error::<T>::BadSignature);

			let full = T::FullIdentificationOf::convert(record.owner.clone())
				// Cannot fail with unit identification; validate the handoff
				// anyway rather than assume.
				.ok_or(Error::<T>::ReportRejected)?;
			let newly_disabling = !Disabled::<T>::contains_key(&record.owner);

			let offence = RetiredKeyOffence {
				session_index: pallet_session::Pallet::<T>::current_index(),
				validator_set_count: pallet_session::Pallet::<T>::validators().len() as u32,
				offender: (record.owner.clone(), full),
				set_id,
				round,
			};
			T::ReportCanary::report_offence(vec![reporter], offence).map_err(|e| match e {
				OffenceError::DuplicateReport => Error::<T>::DuplicateEvidence,
				OffenceError::Other(_) => Error::<T>::ReportRejected,
			})?;

			Self::deposit_event(Event::RetiredKeyEvidenceAccepted {
				validator: record.owner,
				key,
				retired_set_id: retired.set_id,
				set_id,
				round,
			});

			Ok(if newly_disabling { Pays::No.into() } else { Pays::Yes.into() })
		}
	}
}

impl<T: Config> Pallet<T> {
	/// Extract the GRANDPA key from a session-keys bundle.
	fn grandpa_key(keys: &T::Keys) -> Option<AuthorityId> {
		keys.get::<AuthorityId>(sp_consensus_grandpa::KEY_TYPE)
	}

	/// Record an election result as [`PlannedSet`]. Truncates defensively at
	/// `MaxValidators`; the runtime aligns staking's `MaxValidatorSet` with
	/// it, so truncation firing means a misconfigured runtime.
	fn note_planned_set(
		elected: Vec<T::ValidatorId>,
	) -> BoundedVec<T::ValidatorId, T::MaxValidators> {
		if elected.len() > T::MaxValidators::get() as usize {
			log::warn!(
				target: LOG_TARGET,
				"elected set ({}) exceeds MaxValidators ({}); truncating",
				elected.len(),
				T::MaxValidators::get(),
			);
		}
		let bounded = BoundedVec::truncate_from(elected);
		PlannedSet::<T>::put(&bounded);
		bounded
	}

	/// Mark `key` retired as of the rotation being processed. `set_id` must
	/// be the id of the authority set that is ending, i.e. the last set the
	/// key served.
	fn retire_key(key: &AuthorityId, era: EraIndex, session: SessionIndex, set_id: u64) {
		Keys::<T>::mutate(key, |rec| {
			if let Some(rec) = rec {
				if rec.retired.is_none() {
					rec.retired = Some(LifecyclePoint { era, session, set_id });
					Self::deposit_event(Event::KeyRetired {
						validator: rec.owner.clone(),
						key: key.clone(),
						set_id,
					});
				}
			} else {
				log::warn!(
					target: LOG_TARGET,
					"retiring key with no lineage record; lineage started mid-life?"
				);
			}
		});
	}

	/// Session-rotation accounting: reconcile [`ActiveKey`] against the keys
	/// that become active at this rotation, recording activations and
	/// retirements with their GRANDPA set ids.
	///
	/// Called from `new_session`, which `pallet_session::rotate_session`
	/// invokes *before* GRANDPA's session handler runs: `CurrentSetId` still
	/// names the set that is ending, and the incoming keys will serve
	/// `CurrentSetId + 1`.
	fn account_rotation() {
		let era = T::CurrentEra::get();
		let session = pallet_session::Pallet::<T>::current_index();
		let ending_set_id = T::CurrentSetId::get();

		// Keys becoming active at this rotation. `QueuedKeys` is not
		// overwritten with the *next* session's keys until after
		// `new_session` returns.
		let incoming = pallet_session::Pallet::<T>::queued_keys();

		for (validator, keys) in &incoming {
			let Some(key) = Self::grandpa_key(keys) else {
				log::warn!(
					target: LOG_TARGET,
					"validator in incoming set without a GRANDPA key; skipping accounting"
				);
				continue;
			};
			let previous = ActiveKey::<T>::get(validator);
			if previous.as_ref() == Some(&key) {
				continue;
			}
			if let Some(old) = previous {
				Self::retire_key(&old, era, session, ending_set_id);
			}
			Keys::<T>::mutate(&key, |rec| match rec {
				Some(rec) => {
					rec.activated =
						Some(LifecyclePoint { era, session, set_id: ending_set_id + 1 });
				},
				// Keys that predate the pallet (genesis keys, or the live
				// set at the set_code upgrade that introduced it) are
				// captured here: registered now, owned by the validator
				// serving with them.
				None => {
					*rec = Some(KeyRecord {
						owner: validator.clone(),
						registered_era: era,
						activated: Some(LifecyclePoint {
							era,
							session,
							set_id: ending_set_id + 1,
						}),
						retired: None,
					});
				},
			});
			ActiveKey::<T>::insert(validator, &key);
			Self::deposit_event(Event::KeyActivated {
				validator: validator.clone(),
				key,
				set_id: ending_set_id + 1,
			});
		}

		// Validators that dropped out of the set entirely (excluded, or
		// purged keys): their last key retires with the ending set.
		let dropped: Vec<(T::ValidatorId, AuthorityId)> = ActiveKey::<T>::iter()
			.filter(|(v, _)| !incoming.iter().any(|(iv, _)| iv == v))
			.collect();
		for (validator, key) in dropped {
			Self::retire_key(&key, era, session, ending_set_id);
			ActiveKey::<T>::remove(&validator);
		}
	}

	/// Plan the next session's validator set: the elected set from
	/// [`Config::ElectedSet`] minus deadline-missed and offence-disabled
	/// validators. Sessions where the producer plans no new set (`None` —
	/// mid-era sessions under staking) re-feed [`PlannedSet`], so enforcement
	/// runs every session and healed validators re-enter without waiting for
	/// the next election. Returns `None` (keep the previous set) if
	/// enforcement would empty the set.
	fn plan_next_set(new_index: SessionIndex) -> Option<Vec<T::ValidatorId>> {
		let roster = match T::ElectedSet::new_session(new_index) {
			Some(elected) => Self::note_planned_set(elected),
			None => {
				let mut planned = PlannedSet::<T>::get();
				if planned.is_empty() {
					// No election has ever run: capture the live set once so
					// enforcement and healing have a stable base.
					let current = pallet_session::Pallet::<T>::validators();
					if current.is_empty() {
						return None;
					}
					planned = BoundedVec::truncate_from(current);
					PlannedSet::<T>::put(&planned);
				}
				planned
			},
		};

		let era = T::CurrentEra::get();
		let session = pallet_session::Pallet::<T>::current_index();
		let max_age = T::MaxKeyAgeEras::get();

		let mut included = Vec::with_capacity(roster.len());
		for validator in roster.iter() {
			if Disabled::<T>::contains_key(validator) {
				continue;
			}
			let Some(keys) = pallet_session::Pallet::<T>::load_keys(validator) else {
				// No registered keys (purged, never set): nothing to serve
				// with. Not a `Disabled` entry — registering keys is already
				// the way back in.
				log::warn!(
					target: LOG_TARGET,
					"roster validator has no session keys; excluded from next set"
				);
				continue;
			};
			let Some(key) = Self::grandpa_key(&keys) else {
				log::warn!(
					target: LOG_TARGET,
					"roster validator's session keys lack a GRANDPA key; excluded"
				);
				continue;
			};
			let record = match Keys::<T>::get(&key) {
				Some(record) => record,
				// A key observed in planning before any rotation accounted
				// it (first session the pallet manages): capture it now so
				// its age clock starts.
				None => {
					let record = KeyRecord {
						owner: validator.clone(),
						registered_era: era,
						activated: None,
						retired: None,
					};
					Keys::<T>::insert(&key, &record);
					record
				},
			};
			if record.owner != *validator {
				// Cannot happen while set_keys is vetted (a key belongs to
				// one validator forever), but this is a data handoff from
				// session storage: validate, don't assume.
				log::error!(
					target: LOG_TARGET,
					"next-session key owned by a different validator; excluded"
				);
				continue;
			}
			let age = era.saturating_sub(record.registered_era);
			if age > max_age {
				Disabled::<T>::insert(
					validator,
					DisableRecord { reason: DisableReason::DeadlineMissed, era, session },
				);
				Self::deposit_event(Event::ValidatorDisabled {
					validator: validator.clone(),
					reason: DisableReason::DeadlineMissed,
				});
				continue;
			}
			included.push(validator.clone());
		}

		if included.is_empty() {
			log::error!(
				target: LOG_TARGET,
				"rotation enforcement would empty the validator set; keeping previous set"
			);
			Self::deposit_event(Event::EnforcementFloorHit);
			return None;
		}

		// Signal a session change to `pallet_session` ONLY when the enforced
		// set actually differs from the currently active one. `pallet_session`
		// treats ANY `Some(_)` as `changed = true` (it cannot see that the
		// membership is identical), and `pallet_grandpa` bumps `set_id` on
		// every `changed` session. Because this pallet plans EVERY session
		// (to run enforcement + healing continuously), returning `Some` on
		// no-op sessions rotated the GRANDPA authority set every session even
		// on a stable validator set — a per-session stream of
		// finality-sensitive set changes that turns any finality lag into a
		// change backlog and, at worst, an unrecoverable voter wedge
		// (observed on the VM farm 2026-07-12). Returning `None` when nothing
		// changed keeps enforcement running (we still computed `included` and
		// re-fed `PlannedSet` above) while collapsing `set_id` churn from
		// per-session to per-actual-change. Order-sensitive: session compares
		// the exact Vec, so an ordering-only delta is still a real change.
		if included == pallet_session::Pallet::<T>::validators() {
			return None;
		}
		Some(included)
	}

	/// Disable a validator because of a reported offence. Permanent record
	/// stays in `pallet_offences::Reports` and this pallet's events; the
	/// exclusion itself heals on a fresh `set_keys`.
	/// Chain-authoritative retirement check. True iff `key` has a
	/// permanent retirement record. Queued-but-not-yet-active and
	/// currently-active keys return false — the node-side reaper must
	/// NEVER destroy those.
	pub fn is_retired(key: &AuthorityId) -> bool {
		Keys::<T>::get(key).map(|r| r.retired.is_some()).unwrap_or(false)
	}

	pub fn disable_for_offence(validator: &T::ValidatorId) {
		let era = T::CurrentEra::get();
		let session = pallet_session::Pallet::<T>::current_index();
		Disabled::<T>::insert(
			validator,
			DisableRecord { reason: DisableReason::Offence, era, session },
		);
		Self::deposit_event(Event::ValidatorDisabled {
			validator: validator.clone(),
			reason: DisableReason::Offence,
		});
	}
}

/// The fresh-key primitive: every `set_keys` runs through here.
impl<T: Config> pallet_session::KeyProvenance<T::ValidatorId, T::Keys> for Pallet<T> {
	fn note_set_keys(who: &T::ValidatorId, keys: &T::Keys) -> DispatchResult {
		let key = Self::grandpa_key(keys).ok_or(Error::<T>::MissingGrandpaKey)?;
		ensure!(!Keys::<T>::contains_key(&key), Error::<T>::GrandpaKeyAlreadySeen);

		let era = T::CurrentEra::get();
		Keys::<T>::insert(
			&key,
			KeyRecord::<T::ValidatorId> {
				owner: who.clone(),
				registered_era: era,
				activated: None,
				retired: None,
			},
		);
		Self::deposit_event(Event::KeyRegistered { validator: who.clone(), key, era });

		// A fresh key is the healing path: the account key (which authorizes
		// set_keys) evicting whatever held the old one.
		if Disabled::<T>::take(who).is_some() {
			Self::deposit_event(Event::ValidatorHealed { validator: who.clone() });
		}
		Ok(())
	}
}

impl<T: Config> pallet_session::SessionManager<T::ValidatorId> for Pallet<T> {
	fn new_session(new_index: SessionIndex) -> Option<Vec<T::ValidatorId>> {
		Self::account_rotation();
		Self::plan_next_set(new_index)
	}
	fn new_session_genesis(new_index: SessionIndex) -> Option<Vec<T::ValidatorId>> {
		// The elected-set producer plans the genesis set (staking runs its
		// genesis election over the genesis stakers; `None` falls back to
		// the genesis session keys). No enforcement at genesis — there is
		// no lineage yet; capture happens lazily at the first rotation.
		T::ElectedSet::new_session_genesis(new_index)
			.map(|elected| Self::note_planned_set(elected).into_inner())
	}
	// Era lifecycle: the producer (staking) tracks session starts/ends to
	// activate and close eras.
	fn start_session(start_index: SessionIndex) {
		T::ElectedSet::start_session(start_index)
	}
	fn end_session(end_index: SessionIndex) {
		T::ElectedSet::end_session(end_index)
	}
}

/// The offence sink's consequence: disable-and-record, for every offence
/// kind routed here (GRANDPA equivocation and the retired-key canary alike).
/// The permanent record lives in `pallet_offences::Reports` plus this
/// pallet's events and key records; the exclusion itself heals on a fresh
/// `set_keys`. Slash fractions are accepted but unused until NPoS staking
/// supplies economics.
impl<T: Config>
	OnOffenceHandler<T::AccountId, IdentificationTuple<T>, Weight> for Pallet<T>
{
	fn on_offence(
		offenders: &[OffenceDetails<T::AccountId, IdentificationTuple<T>>],
		_slash_fraction: &[Perbill],
		_session: SessionIndex,
	) -> Weight {
		for details in offenders {
			let (validator, _full) = &details.offender;
			Self::disable_for_offence(validator);
		}
		T::DbWeight::get().reads_writes(1, 2).saturating_mul(offenders.len() as u64)
	}
}

impl<T: Config>
	pallet_session::historical::SessionManager<T::ValidatorId, T::FullIdentification>
	for Pallet<T>
{
	fn new_session(
		new_index: SessionIndex,
	) -> Option<Vec<(T::ValidatorId, T::FullIdentification)>> {
		<Self as pallet_session::SessionManager<T::ValidatorId>>::new_session(new_index).map(
			|validators| {
				validators
					.into_iter()
					.filter_map(|v| {
						T::FullIdentificationOf::convert(v.clone()).map(|full| (v, full))
					})
					.collect()
			},
		)
	}
	fn new_session_genesis(
		new_index: SessionIndex,
	) -> Option<Vec<(T::ValidatorId, T::FullIdentification)>> {
		<Self as pallet_session::SessionManager<T::ValidatorId>>::new_session_genesis(new_index)
			.map(|validators| {
				validators
					.into_iter()
					.filter_map(|v| {
						T::FullIdentificationOf::convert(v.clone()).map(|full| (v, full))
					})
					.collect()
			})
	}
	fn start_session(start_index: SessionIndex) {
		<Self as pallet_session::SessionManager<T::ValidatorId>>::start_session(start_index)
	}
	fn end_session(end_index: SessionIndex) {
		<Self as pallet_session::SessionManager<T::ValidatorId>>::end_session(end_index)
	}
}

sp_api::decl_runtime_apis! {
	/// Key-lifecycle queries for node-side consumers. Consumer #1 is the
	/// retired-key reaper (docs/PQ-FINALITY.md P3): the fast chain's
	/// destruction discipline needs a chain-authoritative "this key is
	/// permanently retired" signal, because a live authority-set poll
	/// cannot distinguish a queued-not-yet-active key from a retired one
	/// (and destroying a queued key would be catastrophic).
	pub trait KeyLineageApi {
		/// True iff this GRANDPA key has a permanent retirement record.
		fn is_retired_grandpa_key(key: sp_consensus_grandpa::AuthorityId) -> bool;
	}
}
