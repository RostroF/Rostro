#![cfg_attr(not(feature = "std"), no_std)]

pub mod ddns;

use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};

use scale_info::TypeInfo;
use rp_core::{self, ConstU32};

use serde::{Deserialize, Serialize};

/// Maximum byte length of a public key stored in a PUBKEY1/PUBKEY2/PUBKEY3 record.
/// Sized to accommodate post-quantum keys including CRYSTALS-Kyber-1024
/// (1568-byte public key) with headroom for future schemes.
pub type MaxPubKeySize = ConstU32<2048>;

/// Full resolution record returned by `pns_resolveName` / `pns_getInfo`.
/// Extends [`RegistrarInfo`] with the current NFT owner so callers
/// do not need a second query to discover who registered the name.
#[derive(Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Clone, TypeInfo, MaxEncodedLen)]
pub struct NameRecord<AccountId, Moment, Balance> {
    /// SS58 / raw account that currently owns this name.
    pub owner: AccountId,
    /// Expiration timestamp.
    pub expire: Moment,
    /// Maximum number of subdomains this name may create.
    pub capacity: u32,
    /// Fee paid at registration time (burned).
    pub register_fee: Balance,
    /// Whether the owner has listed this name for sale.
    pub for_sale: bool,
    /// Block number at which the name was last registered or renewed.
    pub last_block: u32,
    /// Block number at which this record was read from chain state.
    pub read_block_number: u32,
    /// Hash of the block at which this record was read.
    pub read_block_hash: DomainHash,
}

/// Active marketplace listing returned by `pns_getListing`.
#[derive(Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Clone, TypeInfo, MaxEncodedLen)]
pub struct ListingInfo<AccountId, Balance, Moment> {
    /// Account that created the listing and will receive the proceeds.
    pub seller: AccountId,
    /// Asking price in the native currency.
    pub price: Balance,
    /// Millisecond timestamp after which this listing is no longer valid.
    pub expires_at: Moment,
    /// Block number at which this listing was read from chain state.
    pub read_block_number: u32,
    /// Hash of the block at which this listing was read.
    pub read_block_hash: DomainHash,
}

#[derive(Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Clone, TypeInfo, MaxEncodedLen)]
pub struct RegistrarInfo<Moment, Balance> {
    /// Expiration time
    pub expire: Moment,
    /// Capacity for creating subdomains
    pub capacity: u32,
    /// Registration fee (burned at registration time)
    pub register_fee: Balance,
    /// Length of the label in bytes (used for pricing renewals)
    pub label_len: u32,
    /// Block number at which the last registration or renewal occurred
    pub last_block: u32,
}

#[derive(Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Clone, TypeInfo, MaxEncodedLen)]
pub enum DomainTracing {
    RuntimeOrigin(DomainHash),
    Root,
}

/// NFT token data attached to each registered name.
/// Tracks the number of active subdomains. Public key slots have moved to
/// `Records` storage in pns-resolvers as `PUBKEY1`/`PUBKEY2`/`PUBKEY3` record types.
#[derive(Serialize, Deserialize, Encode, Decode, DecodeWithMemTracking, PartialEq, Eq, Clone, Default, TypeInfo, Debug)]
pub struct Record {
    pub children: u32,
}

#[derive(Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Clone, TypeInfo, MaxEncodedLen, Debug)]
pub enum SubnameState {
    /// The parent domain owner has offered this subdomain; not yet accepted.
    Offered,
    /// The target accepted the offer. The subdomain is live.
    Active,
    /// The target explicitly rejected the offer. Visible to the offerer; cleared by revoke.
    Rejected,
}

/// On-chain record for a subdomain delegation.
/// Expiry is inherited from the parent; there is no independent expiry field.
#[derive(Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Clone, TypeInfo, MaxEncodedLen, Debug)]
pub struct SubnameRecord<AccountId> {
    /// Namehash of the parent canonical name.
    pub parent: DomainHash,
    /// ASCII label bytes of this subdomain (e.g. b"sally"), max 63 bytes.
    pub label: frame_support::BoundedVec<u8, ConstU32<63>>,
    /// The account this subdomain is offered to or held by.
    pub target: AccountId,
    /// Current state of the delegation.
    pub state: SubnameState,
}

/// A top-level name purchased via the marketplace as a gift for a recipient.
///
/// The name is in a "pending" state while this record exists: DNS lookups return
/// `null` for the name until the recipient calls `accept_offered_name`.
/// If the recipient calls `register` with `reject_offer` pointing to this name,
/// the NFT is burned and the registration slot is freed.
#[derive(Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Clone, TypeInfo, MaxEncodedLen, Debug)]
pub struct OfferedNameRecord<AccountId, Moment> {
    /// The account that purchased the name and funded the transaction.
    pub buyer: AccountId,
    /// The intended recipient who must accept or reject the name.
    pub recipient: AccountId,
    /// Timestamp when the offer was created. The recipient has `OfferWindow` (90 days)
    /// from this point to accept. After expiry the name becomes re-registrable.
    pub offered_at: Moment,
}

/// Account-level summary returned by `pns_accountDashboard`.
pub type DomainHash = rp_core::H256;

/// Namehash of "dot" — the Polkadot TLD base node.
pub const DOT_BASENODE: DomainHash = rp_core::H256([
    63, 206, 125, 19, 100, 168, 147, 226, 19, 188, 66, 18, 121, 43, 81, 127, 252, 136, 245, 177,
    59, 134, 200, 239, 156, 141, 57, 12, 58, 19, 112, 206,
]);

// TODO(rostro-basenode): replace DOT_BASENODE above with per-network constants
// (keccak256("rst") for mainnet, keccak256("canaria") for canary, keccak256("camino")
// for testnet). Each runtime selects its own via a `BaseNode: Get<DomainHash>` config
// type. Tracked in the Polkadot-isms-strip follow-up.
pub const NATIVE_BASENODE: DomainHash = DOT_BASENODE;

/// Parse a human-readable PNS name into a [`DomainHash`].
///
/// Rules:
/// - `"sub.domain"` (contains exactly one dot) → namehash of subdomain `sub`
///   under `domain.<base_tld>`.
/// - `"domain"` (no dot) → namehash of the top-level domain `domain.<base_tld>`.
///
/// Returns `None` if any label fails validation (illegal characters, wrong
/// length, etc.).  The caller is responsible for mapping `None` to the
/// appropriate [`DispatchError`].
pub fn parse_name_to_node(name: &[u8], base_node: &DomainHash) -> Option<DomainHash> {
    use rp_io::hashing::keccak_256;

    /// Validate and hash a single DNS label.
    fn hash_label(label: &[u8]) -> Option<DomainHash> {
        validate_label(label)?;
        let normalized = core::str::from_utf8(label).ok()?.to_ascii_lowercase();
        Some(DomainHash::from(keccak_256(normalized.as_bytes())))
    }

    /// Combine a parent node hash and a label hash into a child namehash.
    /// Mirrors `Label::encode_with_node` in pns-registrar.
    fn encode_with_node(parent: &DomainHash, label_hash: DomainHash) -> DomainHash {
        let encoded = (parent, label_hash).encode();
        DomainHash::from(keccak_256(&encoded))
    }

    if let Some(dot) = name.iter().position(|&b| b == b'.') {
        // "sub.domain" → hash of sub under domain.<base>
        let sub_label = &name[..dot];
        let domain_label = &name[dot + 1..];
        let domain_hash = encode_with_node(base_node, hash_label(domain_label)?);
        Some(encode_with_node(&domain_hash, hash_label(sub_label)?))
    } else {
        // "domain" → hash of top-level domain.<base>
        Some(encode_with_node(base_node, hash_label(name)?))
    }
}

/// Validate a single DNS label component (the part between dots).
///
/// Rules:
/// - Valid UTF-8, 1–63 characters after lowercasing.
/// - Every character must be ASCII alphanumeric (`a–z`, `A–Z`, `0–9`).
/// - No hyphens or other punctuation are permitted.
pub fn validate_label(label: &[u8]) -> Option<()> {
    let label = core::str::from_utf8(label)
        .map(|s| s.to_ascii_lowercase())
        .ok()?;

    const LABEL_MIN_LEN: usize = 1;
    const LABEL_MAX_LEN: usize = 63;

    if !(LABEL_MIN_LEN..=LABEL_MAX_LEN).contains(&label.len()) {
        return None;
    }

    if !label.chars().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }

    Some(())
}
