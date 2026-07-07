// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! # Rostro History Anchor
//!
//! Seals chain history under a second, design-independent hash family.
//! Block hashes and state roots are permanent commitments linked by
//! BLAKE2-256; if that function ever suffers a structural break, forged
//! alternate history could be presented against archives and light clients.
//! This pallet folds era-boundary headers into a running Keccak-512 chain,
//! so forging anchored history requires simultaneous structural breaks of
//! two unrelated constructions (BLAKE2's ChaCha-derived core, Keccak's
//! sponge) at 512-bit width.
//!
//! ## Bind while fresh
//!
//! The security argument is temporal. At inclusion time, consensus enforces
//! that the sealed bytes are the real parent header: the inherent's payload
//! must hash (under the chain's primary hasher) to this block's
//! `parent_hash`, and the primary hasher is sound *today*. The Keccak-512
//! chain then carries that binding forward permanently. A future adversary
//! who breaks BLAKE2-256 cannot rewrite what was dual-committed while
//! BLAKE2-256 was unbroken.
//!
//! ## Seal schedule: once per era, by the incoming active set
//!
//! A seal is required in the first block authored after `EraProvider`
//! advances past the last sealed era (and unconditionally in the first
//! block after activation, which on a fresh chain is block 1 sealing the
//! genesis header). The sealed header is that block's parent: the final
//! block of the previous era.
//!
//! To be precise about what the sealer asserts: the seal is a hash
//! transcription, not an endorsement. Its validity condition is byte
//! identity (`Hashing::hash(bytes) == parent_hash`), which any proposer
//! can verify locally regardless of how it synced; it attests nothing
//! about the conduct of prior validators. The parent header is sealed
//! because a block cannot seal its own header (the state root does not
//! exist until execution completes), the era-final state root is the most
//! valuable checkpoint to dual-seal ("state as of the close of era N"),
//! and the parent is the one header every proposer verifiably possesses.
//!
//! Stated honestly: only era-boundary headers (and the state roots inside
//! them) carry the dual seal. Intra-era headers rest on BLAKE2-256 alone,
//! so long-horizon historical proofs must anchor to era boundaries.
//!
//! ## Offline recomputability
//!
//! The chain is a pure fold over raw header bytes:
//!
//! `head_0 = keccak_512(DOMAIN_TAG)`, `head_{i+1} = keccak_512(head_i ||
//! header_bytes_i)`
//!
//! Anyone holding the raw headers can recompute every anchor without this
//! pallet, the runtime, or the trie. Durability therefore rests on
//! published 64-byte heads (events, explorers, SRT publications, archives),
//! not on this pallet's own storage surviving under the BLAKE2-rooted trie.
//!
//! ## Mirrors `pallet-rostro-proof-anchor`'s wiring
//!
//! Same inherent shape: the pallet exports the identifier and payload type;
//! the node-side `InherentDataProvider` lives in the node binary (it
//! fetches the parent header from its backend, which it always has). The
//! runtime re-verifies the binding, so a buggy provider cannot corrupt the
//! anchor chain, only fail to author a valid block.

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

extern crate alloc;

use alloc::vec::Vec;
use codec::{Decode, Encode};
use sp_core::H512;
use sp_inherents::{InherentIdentifier, IsFatalError};
use sp_runtime::traits::{Hash as HashT, One, Saturating, Zero};

/// Inherent identifier for the history-anchor seal.
pub const HISTORY_ANCHOR_INHERENT_ID: InherentIdentifier = *b"rstranch";

/// The inherent payload: SCALE-encoded bytes of the parent block's header,
/// exactly the preimage of this block's `parent_hash` under the chain's
/// primary hasher.
pub type InherentType = Vec<u8>;

/// Domain-separation tag; the initial anchor head is `keccak_512(DOMAIN_TAG)`.
pub const DOMAIN_TAG: &[u8] = b"rostro-history-anchor-v0";

/// Errors surfaced by the seal inherent. All fatal: a scheduled block
/// without a valid seal is an invalid block.
#[derive(Encode, Decode, core::fmt::Debug)]
pub enum InherentError {
	/// The seal schedule requires this block to carry a seal inherent and
	/// none was included.
	MissingSeal,
}

impl IsFatalError for InherentError {
	fn is_fatal_error(&self) -> bool {
		true
	}
}

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config {
		/// Current era index, wired to `pallet_staking::CurrentEra` in the
		/// real runtime. A seal is scheduled whenever this advances past
		/// the last sealed era. Runtimes without eras may return `None`
		/// permanently: such a chain gets exactly one seal (its genesis
		/// header) and nothing further.
		type EraProvider: Get<Option<u32>>;

		/// Upper bound on accepted header byte length. A weight guard, not
		/// a semantic bound: deliberately generous (real headers are a few
		/// hundred bytes) because a legitimate header failing this check
		/// would make the scheduled block unbuildable.
		#[pallet::constant]
		type MaxHeaderBytes: Get<u32>;
	}

	/// Initial anchor head: `keccak_512(DOMAIN_TAG)`.
	#[pallet::type_value]
	pub fn InitialAnchorHead() -> H512 {
		H512(sp_io::hashing::keccak_512(DOMAIN_TAG))
	}

	/// Running Keccak-512 fold over all sealed header bytes.
	#[pallet::storage]
	pub type AnchorHead<T: Config> = StorageValue<_, H512, ValueQuery, InitialAnchorHead>;

	/// Era index recorded at the most recent seal. `None` = never sealed
	/// (schedules a seal in the next authored block).
	#[pallet::storage]
	pub type LastSealedEra<T: Config> = StorageValue<_, u32, OptionQuery>;

	/// Height of the most recently sealed header.
	#[pallet::storage]
	pub type LastSealedHeight<T: Config> = StorageValue<_, BlockNumberFor<T>, OptionQuery>;

	/// Total headers folded so far (offline-verifier cross-check).
	#[pallet::storage]
	pub type SealedCount<T: Config> = StorageValue<_, u64, ValueQuery>;

	/// Anchor snapshots: era at seal time -> (sealed header height, head
	/// after folding it). 64 bytes plus key per era, kept forever by
	/// design; at daily eras that is under 3 MB per century.
	#[pallet::storage]
	pub type Anchors<T: Config> =
		StorageMap<_, Twox64Concat, u32, (BlockNumberFor<T>, H512), OptionQuery>;

	/// Whether the schedule requires a seal in the current block, latched in
	/// `on_initialize`. The latch exists because `seal` itself advances
	/// `LastSealedEra`, so the live schedule flips mid-block; every
	/// intra-block consumer (the call, the inherent hooks, the `on_finalize`
	/// check) must see the decision as of block start.
	#[pallet::storage]
	pub type SealDue<T: Config> = StorageValue<_, bool, ValueQuery>;

	/// Whether the seal inherent already ran in the current block. Checked
	/// and cleared in `on_finalize` (mirrors `pallet-timestamp::DidUpdate`).
	#[pallet::storage]
	pub type DidSeal<T: Config> = StorageValue<_, bool, ValueQuery>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A header was folded into the anchor chain. `head` is the new
		/// 64-byte anchor head; publishing it anywhere durable is what
		/// makes the seal irreversible.
		Anchored { era: u32, sealed_height: BlockNumberFor<T>, head: H512 },
	}

	#[pallet::error]
	pub enum Error<T> {
		/// A seal inherent was already included in this block.
		AlreadySealed,
		/// The seal schedule does not call for a seal in this block.
		SealNotExpected,
		/// Provided header bytes exceed `MaxHeaderBytes`.
		HeaderTooLarge,
		/// The provided bytes do not hash to this block's parent hash:
		/// they are not the parent header.
		BadParentHeader,
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn on_initialize(now: BlockNumberFor<T>) -> Weight {
			SealDue::<T>::put(Self::seal_required_at(now));
			// Includes the reservation for `on_finalize`.
			T::DbWeight::get().reads_writes(2, 2)
		}

		fn on_finalize(_now: BlockNumberFor<T>) {
			let due = SealDue::<T>::take();
			let sealed = DidSeal::<T>::take();
			if due {
				assert!(sealed, "history anchor seal inherent must be included in this block");
			} else {
				// `seal` enforces the same latch, so this can only fire if
				// the two disagree.
				debug_assert!(!sealed);
			}
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Seal the parent block's header into the anchor chain.
		///
		/// Mandatory inherent on scheduled blocks; unsigned, not
		/// user-callable.
		#[pallet::call_index(0)]
		#[pallet::weight((
			T::DbWeight::get().reads_writes(6, 6)
				.saturating_add(Weight::from_parts(5_000_000, 0)),
			DispatchClass::Mandatory
		))]
		pub fn seal(origin: OriginFor<T>, header_bytes: Vec<u8>) -> DispatchResult {
			ensure_none(origin)?;
			ensure!(!DidSeal::<T>::get(), Error::<T>::AlreadySealed);
			ensure!(SealDue::<T>::get(), Error::<T>::SealNotExpected);

			let now = frame_system::Pallet::<T>::block_number();
			ensure!(
				header_bytes.len() <= T::MaxHeaderBytes::get() as usize,
				Error::<T>::HeaderTooLarge
			);

			// Bind while fresh: consensus enforces, at inclusion time,
			// that these bytes are the real parent header under the
			// primary hash.
			ensure!(
				T::Hashing::hash(&header_bytes) == frame_system::Pallet::<T>::parent_hash(),
				Error::<T>::BadParentHeader
			);

			let mut buf = Vec::with_capacity(64 + header_bytes.len());
			buf.extend_from_slice(AnchorHead::<T>::get().as_bytes());
			buf.extend_from_slice(&header_bytes);
			let head = H512(sp_io::hashing::keccak_512(&buf));

			let era = T::EraProvider::get().unwrap_or(0);
			let sealed_height = now.saturating_sub(One::one());

			AnchorHead::<T>::put(head);
			LastSealedEra::<T>::put(era);
			LastSealedHeight::<T>::put(sealed_height);
			SealedCount::<T>::mutate(|c| *c = c.saturating_add(1));
			Anchors::<T>::insert(era, (sealed_height, head));
			DidSeal::<T>::put(true);

			Self::deposit_event(Event::Anchored { era, sealed_height, head });
			Ok(())
		}
	}

	#[pallet::inherent]
	impl<T: Config> ProvideInherent for Pallet<T> {
		type Call = Call<T>;
		type Error = InherentError;
		const INHERENT_IDENTIFIER: InherentIdentifier = HISTORY_ANCHOR_INHERENT_ID;

		fn create_inherent(data: &InherentData) -> Option<Self::Call> {
			// Runs after `on_initialize`: the latch is set.
			if !SealDue::<T>::get() {
				return None;
			}
			let header_bytes = data
				.get_data::<InherentType>(&HISTORY_ANCHOR_INHERENT_ID)
				.expect("history anchor inherent data not correctly encoded")
				.expect("history anchor inherent data must be provided on scheduled blocks");
			Some(Call::seal { header_bytes })
		}

		fn is_inherent_required(_: &InherentData) -> Result<Option<Self::Error>, Self::Error> {
			Ok(SealDue::<T>::get().then_some(InherentError::MissingSeal))
		}

		fn is_inherent(call: &Self::Call) -> bool {
			matches!(call, Call::seal { .. })
		}
	}

	impl<T: Config> Pallet<T> {
		/// Whether the block at `now` must carry a seal of its parent
		/// header. Deterministic in state: never-sealed schedules
		/// immediately (block 1 on a fresh chain, sealing genesis);
		/// afterwards a seal is due exactly when the era advances.
		pub fn seal_required_at(now: BlockNumberFor<T>) -> bool {
			if now.is_zero() {
				return false;
			}
			match LastSealedEra::<T>::get() {
				None => true,
				Some(last) => T::EraProvider::get().unwrap_or(0) > last,
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate as pallet_rostro_history_anchor;
	use frame_support::{
		assert_noop, assert_ok, derive_impl,
		inherent::ProvideInherent,
		parameter_types,
		traits::{ConstU32, Hooks},
	};
	use frame_system::pallet_prelude::HeaderFor;
	use sp_core::H256;
	use sp_inherents::InherentData;
	use sp_runtime::{
		traits::{BlakeTwo256, Header as HeaderT, IdentityLookup},
		BuildStorage,
	};

	type Block = frame_system::mocking::MockBlock<Test>;

	frame_support::construct_runtime!(
		pub enum Test {
			System: frame_system,
			HistoryAnchor: pallet_rostro_history_anchor,
		}
	);

	#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
	impl frame_system::Config for Test {
		type Block = Block;
		type AccountId = u64;
		type Lookup = IdentityLookup<Self::AccountId>;
		type Hash = H256;
		type Hashing = BlakeTwo256;
		type AccountData = ();
	}

	parameter_types! {
		pub static CurrentMockEra: Option<u32> = None;
	}

	impl pallet_rostro_history_anchor::Config for Test {
		type EraProvider = CurrentMockEra;
		type MaxHeaderBytes = ConstU32<65536>;
	}

	fn new_test_ext() -> sp_io::TestExternalities {
		let t = frame_system::GenesisConfig::<Test>::default()
			.build_storage()
			.unwrap();
		sp_io::TestExternalities::new(t)
	}

	fn mk_header(n: u64, parent_hash: H256) -> HeaderFor<Test> {
		HeaderFor::<Test>::new(
			n,
			H256::repeat_byte(0xE1), // extrinsics root: arbitrary
			H256::repeat_byte(0x51), // state root: arbitrary
			parent_hash,
			Default::default(),
		)
	}

	fn genesis_header() -> HeaderFor<Test> {
		mk_header(0, H256::zero())
	}

	/// Run the block after `parent`, including the seal inherent when the
	/// schedule requires it. Returns the new block's header for chaining.
	fn run_block(parent: &HeaderFor<Test>) -> HeaderFor<Test> {
		let n = *parent.number() + 1;
		let parent_hash = parent.hash();
		System::initialize(&n, &parent_hash, &Default::default());
		HistoryAnchor::on_initialize(n);
		if SealDue::<Test>::get() {
			assert_ok!(HistoryAnchor::seal(RuntimeOrigin::none(), parent.encode()));
		}
		HistoryAnchor::on_finalize(n);
		mk_header(n, parent_hash)
	}

	/// Independent reference fold.
	fn fold(head: [u8; 64], bytes: &[u8]) -> [u8; 64] {
		let mut buf = Vec::new();
		buf.extend_from_slice(&head);
		buf.extend_from_slice(bytes);
		sp_io::hashing::keccak_512(&buf)
	}

	#[test]
	fn genesis_sealed_at_block_one_then_quiet() {
		new_test_ext().execute_with(|| {
			CurrentMockEra::set(Some(0));
			let mut h = genesis_header();
			let genesis_bytes = h.encode();
			for _ in 0..5 {
				h = run_block(&h);
			}
			assert_eq!(SealedCount::<Test>::get(), 1);
			assert_eq!(LastSealedEra::<Test>::get(), Some(0));
			assert_eq!(LastSealedHeight::<Test>::get(), Some(0));
			let expected = fold(sp_io::hashing::keccak_512(DOMAIN_TAG), &genesis_bytes);
			assert_eq!(AnchorHead::<Test>::get(), H512(expected));
			assert_eq!(Anchors::<Test>::get(0), Some((0, H512(expected))));
		});
	}

	#[test]
	fn era_bump_seals_previous_eras_final_header() {
		new_test_ext().execute_with(|| {
			CurrentMockEra::set(Some(0));
			let mut h = genesis_header();
			for _ in 0..5 {
				h = run_block(&h); // blocks 1..=5; genesis sealed at 1
			}
			// h is now header 5, the final block of era 0.
			let era0_final_bytes = h.encode();
			let head_before = AnchorHead::<Test>::get();

			CurrentMockEra::set(Some(1));
			h = run_block(&h); // block 6: first block of era 1, seals header 5
			assert_eq!(SealedCount::<Test>::get(), 2);
			assert_eq!(LastSealedEra::<Test>::get(), Some(1));
			assert_eq!(LastSealedHeight::<Test>::get(), Some(5));
			let expected = fold(head_before.0, &era0_final_bytes);
			assert_eq!(Anchors::<Test>::get(1), Some((5, H512(expected))));

			// Event carries the publishable head.
			assert!(System::events().iter().any(|r| matches!(
				r.event,
				RuntimeEvent::HistoryAnchor(Event::Anchored { era: 1, sealed_height: 5, .. })
			)));

			// Quiet again within era 1.
			h = run_block(&h);
			run_block(&h);
			assert_eq!(SealedCount::<Test>::get(), 2);
		});
	}

	#[test]
	fn fold_matches_independent_recompute_across_eras() {
		new_test_ext().execute_with(|| {
			CurrentMockEra::set(Some(0));
			let mut headers = vec![genesis_header()];
			// Era bumps before blocks 4 and 8: era-0 final header is 3,
			// era-1 final header is 7.
			for n in 1u64..=10 {
				if n == 4 {
					CurrentMockEra::set(Some(1));
				}
				if n == 8 {
					CurrentMockEra::set(Some(2));
				}
				let next = run_block(headers.last().unwrap());
				headers.push(next);
			}
			let mut head = sp_io::hashing::keccak_512(DOMAIN_TAG);
			for sealed in [0usize, 3, 7] {
				head = fold(head, &headers[sealed].encode());
			}
			assert_eq!(AnchorHead::<Test>::get(), H512(head));
			assert_eq!(SealedCount::<Test>::get(), 3);
		});
	}

	#[test]
	fn wrong_bytes_rejected() {
		new_test_ext().execute_with(|| {
			let g = genesis_header();
			System::initialize(&1, &g.hash(), &Default::default());
			HistoryAnchor::on_initialize(1);
			let mut bytes = g.encode();
			bytes[0] ^= 1;
			assert_noop!(
				HistoryAnchor::seal(RuntimeOrigin::none(), bytes),
				Error::<Test>::BadParentHeader
			);
		});
	}

	#[test]
	fn seal_when_not_scheduled_rejected() {
		new_test_ext().execute_with(|| {
			CurrentMockEra::set(Some(0));
			let g = genesis_header();
			let h1 = run_block(&g); // seals genesis
			let h1_bytes = h1.encode();
			System::initialize(&2, &h1.hash(), &Default::default());
			assert_noop!(
				HistoryAnchor::seal(RuntimeOrigin::none(), h1_bytes),
				Error::<Test>::SealNotExpected
			);
		});
	}

	#[test]
	fn double_seal_rejected() {
		new_test_ext().execute_with(|| {
			let g = genesis_header();
			System::initialize(&1, &g.hash(), &Default::default());
			HistoryAnchor::on_initialize(1);
			assert_ok!(HistoryAnchor::seal(RuntimeOrigin::none(), g.encode()));
			assert_noop!(
				HistoryAnchor::seal(RuntimeOrigin::none(), g.encode()),
				Error::<Test>::AlreadySealed
			);
		});
	}

	#[test]
	fn oversize_rejected() {
		new_test_ext().execute_with(|| {
			let g = genesis_header();
			System::initialize(&1, &g.hash(), &Default::default());
			HistoryAnchor::on_initialize(1);
			assert_noop!(
				HistoryAnchor::seal(RuntimeOrigin::none(), vec![0u8; 70_000]),
				Error::<Test>::HeaderTooLarge
			);
		});
	}

	#[test]
	#[should_panic(expected = "history anchor seal inherent must be included")]
	fn missing_seal_panics_on_finalize() {
		new_test_ext().execute_with(|| {
			let g = genesis_header();
			System::initialize(&1, &g.hash(), &Default::default());
			HistoryAnchor::on_initialize(1);
			HistoryAnchor::on_finalize(1);
		});
	}

	#[test]
	fn provide_inherent_respects_schedule() {
		new_test_ext().execute_with(|| {
			CurrentMockEra::set(Some(0));
			let g = genesis_header();
			let mut data = InherentData::new();
			data.put_data(HISTORY_ANCHOR_INHERENT_ID, &g.encode()).unwrap();

			// Block 1: never sealed, so required.
			System::initialize(&1, &g.hash(), &Default::default());
			HistoryAnchor::on_initialize(1);
			assert!(matches!(
				HistoryAnchor::create_inherent(&data),
				Some(Call::seal { .. })
			));
			assert!(HistoryAnchor::is_inherent_required(&data).unwrap().is_some());
			assert_ok!(HistoryAnchor::seal(RuntimeOrigin::none(), g.encode()));
			HistoryAnchor::on_finalize(1);

			// Block 2, era unchanged: not required.
			let h1 = mk_header(1, g.hash());
			System::initialize(&2, &h1.hash(), &Default::default());
			HistoryAnchor::on_initialize(2);
			assert!(HistoryAnchor::create_inherent(&data).is_none());
			assert!(HistoryAnchor::is_inherent_required(&data).unwrap().is_none());
		});
	}

	#[test]
	fn post_activation_mid_chain_seals_immediately() {
		new_test_ext().execute_with(|| {
			// Pallet activated via set_code on a chain already at era 7,
			// block 100: LastSealedEra is None, so the very next block
			// seals its parent, mid-era.
			CurrentMockEra::set(Some(7));
			let h99 = mk_header(99, H256::repeat_byte(0x99));
			System::set_block_number(99);
			System::initialize(&100, &h99.hash(), &Default::default());
			HistoryAnchor::on_initialize(100);
			assert!(HistoryAnchor::seal_required_at(100));
			assert_ok!(HistoryAnchor::seal(RuntimeOrigin::none(), h99.encode()));
			HistoryAnchor::on_finalize(100);
			assert_eq!(LastSealedEra::<Test>::get(), Some(7));
			assert_eq!(Anchors::<Test>::get(7).map(|(h, _)| h), Some(99));
		});
	}
}
