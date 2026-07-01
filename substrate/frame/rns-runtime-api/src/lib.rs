#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::unnecessary_mut_passed)]

use rns_types::{
    ddns::codec_type::RecordType, AccountDashboard, DomainHash, ListingInfo, NameRecord,
};
use sp_runtime::traits::MaybeSerialize;
use codec::{Decode, Encode};

sp_api::decl_runtime_apis! {
    pub trait PnsStorageApi<Duration, Balance, AccountId>
    where
        Duration: Decode + Encode + MaybeSerialize,
        Balance: Decode + Encode + MaybeSerialize,
        AccountId: Decode + Encode + MaybeSerialize,
    {
        fn get_info(id: DomainHash) -> Option<NameRecord<AccountId, Duration, Balance>>;
        fn lookup(id: DomainHash, record_types: sp_std::vec::Vec<RecordType>) -> sp_std::vec::Vec<(RecordType, sp_std::vec::Vec<u8>)>;
        /// Resolve a plain label (e.g. b"alice") to the full name record including owner.
        /// Computes the namehash internally against the native base node.
        fn resolve_name(name: sp_std::vec::Vec<u8>) -> Option<NameRecord<AccountId, Duration, Balance>>;
        /// Return the active marketplace listing for a plain label (e.g. b"alice"), or `None` if not listed.
        fn get_listing(name: sp_std::vec::Vec<u8>) -> Option<ListingInfo<AccountId, Balance, Duration>>;
        /// Return all DNS records for a plain label or dotted name (e.g. b"alice" or b"sub.alice").
        /// Equivalent to calling name_to_hash then `lookup`, but in a single round-trip.
        fn lookup_by_name(name: sp_std::vec::Vec<u8>, record_types: sp_std::vec::Vec<RecordType>) -> sp_std::vec::Vec<(RecordType, sp_std::vec::Vec<u8>)>;
        /// Aggregate name-related state for an account: primary name, active subnames,
        /// pending subname offers, pending name-gift offers. Single round-trip
        /// for an inbox/dashboard view that would otherwise require N storage walks.
        fn account_dashboard(owner: AccountId) -> AccountDashboard;
        /// Every enrolled guard node identity: the 32-byte libp2p ed25519 keys
        /// published under names' `NODE` records. The consensus-agreed, enumerable
        /// guard set the witnessed-spend committee is selected over; read at a
        /// fixed block to get the per-epoch snapshot.
        fn guard_set() -> sp_std::vec::Vec<[u8; 32]>;
    }
}