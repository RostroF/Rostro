use codec::{Encode, FullCodec};
use core::fmt::Debug;
use frame_support::traits::Currency;
use sp_std::vec::Vec;
use rns_types::DomainHash;

pub trait BlockAuthor {
    type AccountId;
    fn author() -> Option<Self::AccountId>;
}

use sp_io::hashing::keccak_256;
use sp_runtime::{
    traits::{AtLeast32BitUnsigned, MaybeSerializeDeserialize},
    DispatchError, DispatchResult,
};


pub trait Registrar {
    type Balance;
    type AccountId;
    type Moment;
    fn check_expires_registrable(node: DomainHash) -> DispatchResult;
    fn check_expires_renewable(node: DomainHash) -> DispatchResult;
    fn check_expires_useable(node: DomainHash) -> DispatchResult;
    fn clear_registrar_info(node: DomainHash, owner: &Self::AccountId) -> DispatchResult;
    fn basenode() -> DomainHash;
    /// Returns `true` if `account` currently holds a valid (non-expired, within grace period)
    /// canonical name. Used by the registry to guard subdomain acceptance.
    fn has_valid_canonical_name(account: &Self::AccountId) -> bool;
}

pub trait Registry: NFT<Self::AccountId> {
    type AccountId;

    fn mint_subname(
        node_owner: &Self::AccountId,
        node: DomainHash,
        label_node: DomainHash,
        to: Self::AccountId,
        capacity: u32,
        do_payments: impl FnOnce(Option<&Self::AccountId>) -> DispatchResult,
    ) -> DispatchResult;
    fn available(caller: &Self::AccountId, node: DomainHash) -> DispatchResult;
    fn owner_of(node: DomainHash) -> Option<Self::AccountId>;
    fn transfer(from: &Self::AccountId, to: &Self::AccountId, node: DomainHash) -> DispatchResult;
    fn burn(caller: Self::AccountId, node: DomainHash) -> DispatchResult;

    /// Delete a name record and all its subnames from storage without
    /// ownership checks. No funds are burned — this only removes chain
    /// state. Used by cleanup() on expired registrations.
    fn force_delete(node: DomainHash) -> DispatchResult;

    /// Returns `true` if `account` currently holds at least one active subdomain.
    /// Used by the registrar to block canonical name registration/transfer to accounts
    /// that already hold a subdomain.
    fn has_active_subname(account: &Self::AccountId) -> bool;

    /// Create an offer for a subdomain under `parent`.
    /// Performs depth check, duplicate check, and capacity increment.
    /// `capacity` is the parent's subdomain capacity from RegistrarInfo.
    fn offer_subname(
        parent: DomainHash,
        label_node: DomainHash,
        label_bytes: frame_support::BoundedVec<u8, sp_core::ConstU32<63>>,
        to: Self::AccountId,
        capacity: u32,
    ) -> DispatchResult;

    /// Accept a pending offer. Changes state to Active, updates AccountToSubnames.
    /// Returns the parent DomainHash on success.
    fn accept_subname_offer(
        label_node: rns_types::DomainHash,
        acceptor: &Self::AccountId,
    ) -> Result<rns_types::DomainHash, sp_runtime::DispatchError>;

    /// Reject a pending offer. Changes state from Offered to Rejected.
    /// Removes from OfferedToAccount so it no longer appears as pending.
    fn reject_subname_offer(
        label_node: rns_types::DomainHash,
        caller: &Self::AccountId,
    ) -> DispatchResult;

    /// Revoke a subdomain (offered, rejected, or active) by the parent domain owner.
    /// Deletes the record and decrements the parent's children counter.
    fn revoke_subname(
        parent: DomainHash,
        label_node: DomainHash,
    ) -> DispatchResult;

    /// Release an active subdomain voluntarily by the holder.
    /// Deletes the record and decrements the parent's children counter.
    /// Returns parent DomainHash on success.
    fn release_subname(
        label_node: DomainHash,
        by: &Self::AccountId,
    ) -> Result<rns_types::DomainHash, sp_runtime::DispatchError>;

    /// Fully delete a pending subdomain offer where `target` is the intended recipient.
    ///
    /// Unlike `reject_subname_offer` (which changes state to Rejected), this removes
    /// the record entirely — used by the `register` extrinsic's `reject_offer` path so
    /// the recipient can free the slot in a single transaction.
    fn revoke_pending_offer_for_target(
        label_node: DomainHash,
        target: &Self::AccountId,
    ) -> DispatchResult;
}

/// Interface for the marketplace pallet to interact with name ownership.
pub trait NameRegistry {
    type AccountId;
    /// Returns the canonical name hash registered to `account`, if any.
    fn canonical_name(account: &Self::AccountId) -> Option<DomainHash>;
    /// Returns the current NFT owner of `node`, if any.
    fn owner_of(node: DomainHash) -> Option<Self::AccountId>;
    /// Transfers `node` from `from` to `to`, clearing the seller's canonical name entry.
    fn transfer_name(from: &Self::AccountId, to: &Self::AccountId, node: DomainHash) -> DispatchResult;
    /// Purchase a name as a gift for `recipient`.
    ///
    /// Transfers the NFT from `seller` to `recipient` and records the pending offer so
    /// that DNS lookups return null until the recipient calls `accept_offered_name`.
    /// `buyer` is the account that funded the purchase (recorded for audit purposes).
    fn offer_bought_name(
        seller: &Self::AccountId,
        buyer: &Self::AccountId,
        recipient: &Self::AccountId,
        node: DomainHash,
    ) -> DispatchResult;
    /// Returns true if the name is currently valid (not expired, not in grace).
    fn is_name_useable(node: DomainHash) -> bool;
    /// Charge the registration fee for a marketplace sale. The buyer pays
    /// the same fee as a fresh registration (based on label length): 5% held
    /// on buyer as cleanup deposit, 40% to block author, 55% to PnsCustodian.
    /// Releases the seller's old cleanup deposit back to them.
    fn charge_sale_fee(
        buyer: &Self::AccountId,
        node: DomainHash,
    ) -> DispatchResult;
}

pub trait Customer<AccountId> {
    type Currency: Currency<AccountId>;
}

pub trait PriceOracle {
    type Moment;
    type Balance;
    /// Returns the price to register or renew a name.
    /// * `name`: The name being registered or renewed.
    /// * `expires`: When the name presently expires (0 if this is a new registration).
    /// * `duration`: How long the name is being registered or extended for, in seconds.
    /// return The price of this renewal or registration, in wei.
    fn renew_fee(name_len: usize, duration: Self::Moment) -> Option<Self::Balance>;
    fn register_fee(name_len: usize, duration: Self::Moment) -> Option<Self::Balance>;
    fn registration_fee(name_len: usize) -> Option<Self::Balance>;
}

/// Abstraction over a non-fungible token system.
#[allow(clippy::upper_case_acronyms)]
pub trait NFT<AccountId> {
    /// The NFT class identifier.
    type ClassId: Default + Copy;

    /// The NFT token identifier.
    type TokenId: Default + Copy;

    /// The balance of account.
    type Balance: AtLeast32BitUnsigned
        + FullCodec
        + Copy
        + MaybeSerializeDeserialize
        + Debug
        + Default;

    /// The number of NFTs assigned to `who`.
    fn balance(who: &AccountId) -> Self::Balance;

    /// The owner of the given token ID. Returns `None` if the token does not
    /// exist.
    fn owner(token: (Self::ClassId, Self::TokenId)) -> Option<AccountId>;

    /// Transfer the given token ID from one account to another.
    fn transfer(
        from: &AccountId,
        to: &AccountId,
        token: (Self::ClassId, Self::TokenId),
    ) -> DispatchResult;
}

pub struct Label {
    pub node: DomainHash,
}
pub const LABEL_MAX_LEN: usize = 63;
pub const LABEL_MIN_LEN: usize = 1;
pub const MIN_REGISTRABLE_LEN: usize = 1;

impl Label {
    pub fn new(data: &[u8]) -> Option<Self> {
        check_label(data)?;

        let normalized = core::str::from_utf8(data).ok()?.to_ascii_lowercase();
        let node = DomainHash::from(keccak_256(normalized.as_bytes()));
        Some(Self { node })
    }
    pub fn new_basenode(data: &[u8]) -> Option<Self> {
        check_label(data)?;

        let normalized = core::str::from_utf8(data).ok()?.to_ascii_lowercase();
        let node = DomainHash::from(keccak_256(normalized.as_bytes()));

        let encoded = &(DomainHash::default(), node).encode();
        let hash_encoded = keccak_256(encoded);

        Some(Self {
            node: DomainHash::from(hash_encoded),
        })
    }

    pub fn encode_with_name(&self, data: &[u8]) -> Option<Self> {
        let node = Self::new(data)?;
        Some(Label {
            node: self.encode_with_node(&node.node),
        })
    }

    pub fn encode_with_basename(&self, data: &[u8]) -> Option<Self> {
        let node = Self::new(data)?;
        Some(Label {
            node: self.encode_with_baselabel(&node.node),
        })
    }
    pub fn new_with_len(data: &[u8]) -> Option<(Self, usize)> {
        check_label(data)?;

        let normalized = core::str::from_utf8(data).ok()?.to_ascii_lowercase();
        let node = DomainHash::from(keccak_256(normalized.as_bytes()));
        Some((Self { node }, normalized.len()))
    }

    pub fn encode_with_baselabel(&self, baselabel: &DomainHash) -> DomainHash {
        let basenode = Self::basenode(baselabel);
        let encoded_again = &(basenode, &self.node).encode();

        DomainHash::from(keccak_256(encoded_again))
    }

    pub fn basenode(baselabel: &DomainHash) -> DomainHash {
        let encoded = &(DomainHash::default(), baselabel).encode();
        let hash_encoded = keccak_256(encoded);
        DomainHash::from(hash_encoded)
    }

    pub fn to_basenode(&self) -> DomainHash {
        Self::basenode(&self.node)
    }

    pub fn encode_with_node(&self, node: &DomainHash) -> DomainHash {
        let encoded = &(node, &self.node).encode();

        DomainHash::from(keccak_256(encoded))
    }
}
// Chinese domain names: deferred to mainnet.
// Labels are case-insensitive, ASCII alphanumeric only (a-z, 0-9), 1-63 bytes.
pub fn check_label(label: &[u8]) -> Option<()> {
    let label = core::str::from_utf8(label)
        .map(|label| label.to_ascii_lowercase())
        .ok()?;

    if !(LABEL_MIN_LEN..=LABEL_MAX_LEN).contains(&label.len()) {
        return None;
    }

    if !label.chars().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }

    Some(())
}
pub trait Available {
    fn is_registrable(&self) -> bool;
}

impl Available for usize {
    fn is_registrable(&self) -> bool {
        *self >= MIN_REGISTRABLE_LEN
    }
}

/// Writes the SS58 (owner account) record for a domain node.
///
/// Implemented in the runtime using `pallet_rns_resolvers::resolvers::Pallet`.
/// Called by registrar (on register), registry (on transfer), and marketplace (on buy).
pub trait Ss58Updater {
    type AccountId;
    fn update_ss58(node: DomainHash, owner: &Self::AccountId) -> DispatchResult;
}

/// Writes the ORIGIN record (block hash of registration block) for a domain node.
///
/// Implemented in the runtime using `pallet_rns_resolvers::resolvers::Pallet`.
/// Called only by the registrar on initial registration — never on renew/transfer.
pub trait OriginRecorder {
    fn record_origin(node: DomainHash, block_hash: [u8; 32]) -> DispatchResult;
}

/// Clears all DNS records for a domain node except the SS58 record.
///
/// Called on ownership transfers (registry transfer, marketplace buy) to prevent
/// a new owner from inheriting the previous owner's DNS records.
pub trait RecordCleaner {
    fn clear_records_except_ss58(node: DomainHash);
    /// Clears ALL DNS records for a domain node (Records, Accounts, Texts).
    ///
    /// Called when a domain is completely removed (e.g. a subname that is
    /// auto-cleared when its parent is transferred, released, or sold).
    fn clear_all_records(node: DomainHash);
}

pub trait ExchangeRate {
    type Balance;
    /// 1 USD to balance
    fn get_exchange_rate() -> Self::Balance;
}

pub trait Official {
    type AccountId;

    fn get_official_account() -> Result<Self::AccountId, DispatchError>;
}

pub trait IsRegistrarOpen {
    fn is_open() -> bool;
}
