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

/// Full resolution record returned by `rns_resolveName` / `rns_getInfo`.
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

/// Active marketplace listing returned by `rns_getListing`.
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
/// `Records` storage in pallet-rns-resolvers as `PUBKEY1`/`PUBKEY2`/`PUBKEY3` record types.
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

pub type DomainHash = rp_core::H256;

// Per-network basenode constants. Each Rostro runtime selects one via its
// `BaseNode: Get<DomainHash>` config type — there is no implicit default,
// because the choice is network-defining and should be explicit at runtime
// wiring time. Values are `keccak_256(label)` precomputed at build time.

/// Namehash of "rst" — basenode for **Rostro mainnet**.
pub const RST_BASENODE: DomainHash = rp_core::H256([
    161, 35, 83, 185, 48, 192, 248, 170, 91, 171, 154, 39, 99, 61, 120, 167, 226, 225, 102, 211,
    121, 182, 144, 34, 106, 234, 186, 142, 117, 132, 223, 126,
]);

/// Namehash of "canaria" — basenode for **Canaria** (the canary network).
pub const CANARIA_BASENODE: DomainHash = rp_core::H256([
    252, 36, 102, 254, 93, 83, 25, 35, 152, 34, 171, 202, 98, 175, 139, 142, 124, 212, 211, 158,
    196, 113, 245, 241, 83, 138, 71, 42, 65, 49, 7, 170,
]);

/// Namehash of "camino" — basenode for **Camino** (the public testnet).
pub const CAMINO_BASENODE: DomainHash = rp_core::H256([
    219, 28, 127, 166, 210, 130, 98, 51, 53, 15, 21, 190, 190, 54, 187, 114, 16, 187, 79, 12, 73,
    84, 64, 156, 4, 173, 35, 143, 148, 45, 217, 93,
]);

/// Parse a human-readable RNS name into a [`DomainHash`].
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
    /// Mirrors `Label::encode_with_node` in pallet-rns-registrar.
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
