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
//! 3. **Forced-rotation deadline.** As session manager, the pallet re-feeds
//!    the fixed validator roster each session (NPoS staking replaces this
//!    later) minus validators whose *next* key is older than
//!    [`Config::MaxKeyAgeEras`] eras and minus validators disabled by an
//!    offence. Hard cutover, no grace window; re-entry is automatic on
//!    registering a fresh key, which is also the post-compromise healing
//!    path (the account key, not the session key, authorizes `set_keys`).
//!
//! An **era** here is the 24h membership epoch ([`Config::CurrentEra`] binds
//! to the same clock as the zkpki `membership_epoch`); with 4h sessions a key
//! serves at most 6 sessions per era.
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
	}

	/// Permanent lineage, keyed by GRANDPA key. Entries are never removed.
	#[pallet::storage]
	pub type Keys<T: Config> =
		StorageMap<_, Blake2_128Concat, AuthorityId, KeyRecord<T::ValidatorId>, OptionQuery>;

	/// The key currently serving (or queued to serve) for each validator,
	/// maintained at session rotations.
	#[pallet::storage]
	pub type ActiveKey<T: Config> =
		StorageMap<_, Blake2_128Concat, T::ValidatorId, AuthorityId, OptionQuery>;

	/// The intended validator set, captured from `pallet_session` at the
	/// first rotation this pallet manages. Enforcement filters this roster;
	/// it never shrinks it. NPoS staking replaces this wholesale.
	#[pallet::storage]
	pub type Roster<T: Config> =
		StorageValue<_, BoundedVec<T::ValidatorId, T::MaxValidators>, ValueQuery>;

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
		/// The fixed roster was captured from the live session validator set.
		RosterCaptured { count: u32 },
		/// The roster was set by root (live-chain bootstrap; see
		/// [`Pallet::force_roster`]).
		RosterForced { count: u32 },
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
		/// `force_roster` with an empty list; an empty roster would plan an
		/// empty authority set.
		EmptyRoster,
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

		/// Root-only roster bootstrap for a live chain whose genesis predates
		/// session-owned validators (pre-spec-103 chains seeded GRANDPA
		/// authorities directly, leaving `pallet_session` empty — on such a
		/// chain the lazy roster capture has nothing to capture and rotation
		/// is inert). Ops order matters: every listed validator must have
		/// registered session keys via `set_keys` BEFORE this call takes
		/// effect at the next rotation — roster members without registered
		/// keys are excluded from planning, so forcing a roster ahead of the
		/// registrations would shrink the authority set to whoever has keys.
		#[pallet::call_index(1)]
		#[pallet::weight(T::DbWeight::get().reads_writes(0, 1))]
		pub fn force_roster(
			origin: OriginFor<T>,
			validators: BoundedVec<T::ValidatorId, T::MaxValidators>,
		) -> DispatchResult {
			ensure_root(origin)?;
			ensure!(!validators.is_empty(), Error::<T>::EmptyRoster);
			Roster::<T>::put(&validators);
			Self::deposit_event(Event::RosterForced { count: validators.len() as u32 });
			Ok(())
		}
	}
}

impl<T: Config> Pallet<T> {
	/// Extract the GRANDPA key from a session-keys bundle.
	fn grandpa_key(keys: &T::Keys) -> Option<AuthorityId> {
		keys.get::<AuthorityId>(sp_consensus_grandpa::KEY_TYPE)
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

	/// Plan the next session's validator set: the fixed roster minus
	/// deadline-missed and offence-disabled validators. Returns `None` (keep
	/// the previous set) if enforcement would empty the set.
	fn plan_next_set() -> Option<Vec<T::ValidatorId>> {
		let mut roster = Roster::<T>::get();
		if roster.is_empty() {
			let current = pallet_session::Pallet::<T>::validators();
			if current.is_empty() {
				return None;
			}
			roster = BoundedVec::truncate_from(current);
			Roster::<T>::put(&roster);
			Self::deposit_event(Event::RosterCaptured { count: roster.len() as u32 });
		}

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
		Some(included)
	}

	/// Disable a validator because of a reported offence. Permanent record
	/// stays in `pallet_offences::Reports` and this pallet's events; the
	/// exclusion itself heals on a fresh `set_keys`.
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
	fn new_session(_new_index: SessionIndex) -> Option<Vec<T::ValidatorId>> {
		Self::account_rotation();
		Self::plan_next_set()
	}
	fn new_session_genesis(_new_index: SessionIndex) -> Option<Vec<T::ValidatorId>> {
		// Fall back to the genesis session keys; `Validators` storage is not
		// populated while genesis is being built. Lineage capture happens
		// lazily at the first rotation.
		None
	}
	fn start_session(_start_index: SessionIndex) {}
	fn end_session(_end_index: SessionIndex) {}
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
		_new_index: SessionIndex,
	) -> Option<Vec<(T::ValidatorId, T::FullIdentification)>> {
		None
	}
	fn start_session(_start_index: SessionIndex) {}
	fn end_session(_end_index: SessionIndex) {}
}
