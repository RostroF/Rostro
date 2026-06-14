use codec::{Decode, DecodeWithMemTracking, Encode};

#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

pub mod codec_type {
    use codec::MaxEncodedLen;
    use scale_info::TypeInfo;

    use super::*;

    /// On-chain encoding of a smart contract address.
    ///
    /// Stored as the SCALE-encoded content of a `CONTRACT` DNS record so that
    /// clients can unambiguously identify both the address bytes and the VM target
    /// without relying on context.
    #[cfg_attr(feature = "std", derive(Deserialize, Serialize))]
    #[derive(Debug, PartialEq, Eq, Clone, Encode, Decode, TypeInfo, MaxEncodedLen, DecodeWithMemTracking)]
    pub enum ContractAddress {
        /// ink! / Wasm contract — 32-byte AccountId (same encoding as SS58)
        Wasm([u8; 32]),
        /// EVM contract (Frontier / Moonbeam) — 20-byte Ethereum address
        Evm([u8; 20]),
    }

    #[cfg_attr(feature = "std", derive(Deserialize, Serialize))]
    #[derive(Debug, PartialEq, Eq, Hash, Copy, Clone, Encode, Decode, TypeInfo, MaxEncodedLen, DecodeWithMemTracking)]
    #[allow(dead_code)]
    #[non_exhaustive]
    pub enum RecordType {
        /// Native SS58 address record (IANA private use 65280)
        SS58,
        /// JSON-RPC / WebSocket endpoint record (IANA private use 65281)
        RPC,
        /// Validator stash address record (IANA private use 65282)
        VALIDATOR,
        // Codes 65283 and 65284 intentionally unallocated (formerly PARA / PROXY,
        // retired pre-genesis as Polkadot-specific). On-the-wire decoders must
        // treat unallocated codes as `Unknown(u16)`.
        /// Public key slot 1 for encrypted messaging (IANA private use 65285)
        PUBKEY1,
        /// IPFS hash for avatar/profile image (IANA private use 65286)
        AVATAR,
        /// Smart contract address — ink!/Wasm or EVM (IANA private use 65287).
        /// Content is a SCALE-encoded [`ContractAddress`].
        CONTRACT,
        /// Public key slot 2 for encrypted messaging (IANA private use 65288)
        PUBKEY2,
        /// Public key slot 3 for encrypted messaging (IANA private use 65289)
        PUBKEY3,
        /// Block hash of the block containing the original name registration,
        /// stored as 32 raw bytes. Serves as on-chain proof of purchase validity
        /// (IANA private use 65290).
        ORIGIN,
        /// IPFS CID pointing to a directory of files (IANA private use 65291).
        /// Store the raw CID string.
        IPFS,
        /// IPFS CID pointing to a website or dapp hosted on IPFS (IANA private use 65292).
        /// Store the raw CID string. Distinct from AVATAR (65286) which is scoped to profile images.
        CONTENT,
        /// [RFC 1035](https://tools.ietf.org/html/rfc1035) IPv4 Address record
        A,
        /// [RFC 3596](https://tools.ietf.org/html/rfc3596) IPv6 address record
        AAAA,
        /// [RFC 1035](https://tools.ietf.org/html/rfc1035) Canonical name record
        CNAME,
        /// [RFC 1035](https://tools.ietf.org/html/rfc1035) Text record
        TXT,
        /// Chat mail address — the published Ed25519 *software* key a sender
        /// seals the outer (sealed-sender) layer to, and the chain resolves to
        /// reach a user, including for **system messages**. 32 raw bytes.
        /// Required to be chat-reachable. The Ed25519 is published explicitly
        /// (not derived from the SS58) because an SS58/AccountId is
        /// scheme-agnostic and may not be an Ed25519 — and only Ed25519 converts
        /// (XEdDSA → X25519) into a sealed-sender target. "Where to reach you."
        /// (IANA private use 65293.)
        CHAT,
        /// Message content key — the recipient's hardware (StrongBox P-256 /
        /// TPM P-384) decryption key a sender seals the INNER content layer to.
        /// SCALE-encoded curve-tagged `ContentPublicKey`; the curve tag is
        /// self-describing (P-256 = StrongBox, P-384 = TPM). On by default in
        /// identity setup; absent = dead-drop (content key exchanged
        /// out-of-band). **NOT a stored message** — the chain never holds
        /// message content; this is the key you encrypt content *to*.
        /// (IANA private use 65294.)
        MESSAGE,
        /// Unknown Record type, or unsupported
        Unknown(u16),
    }

    impl RecordType {
        pub fn all() -> [Self; 17] {
            [
                RecordType::A,
                RecordType::AAAA,
                RecordType::CNAME,
                RecordType::TXT,
                RecordType::SS58,
                RecordType::RPC,
                RecordType::VALIDATOR,
                RecordType::PUBKEY1,
                RecordType::AVATAR,
                RecordType::CONTRACT,
                RecordType::PUBKEY2,
                RecordType::PUBKEY3,
                RecordType::ORIGIN,
                RecordType::IPFS,
                RecordType::CONTENT,
                RecordType::CHAT,
                RecordType::MESSAGE,
            ]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::codec_type::RecordType;
    use codec::Encode;

    #[test]
    fn chat_and_message_are_index_safe() {
        // The SCALE variant index IS the storage key. CHAT/MESSAGE were inserted
        // BEFORE `Unknown` (which is never stored — not user-settable, never a
        // chain-managed record), so every existing record type keeps its index.
        assert_eq!(RecordType::SS58.encode(), vec![0]);
        assert_eq!(RecordType::CONTENT.encode(), vec![10]);
        assert_eq!(RecordType::TXT.encode(), vec![14]);
        // New, appended:
        assert_eq!(RecordType::CHAT.encode(), vec![15]);
        assert_eq!(RecordType::MESSAGE.encode(), vec![16]);
        // Unknown moved 15 -> 17; safe because nothing is ever stored under it.
        let mut expected = vec![17u8];
        expected.extend_from_slice(&65_293u16.encode());
        assert_eq!(RecordType::Unknown(65_293).encode(), expected);
    }

    #[test]
    fn all_includes_chat_and_message() {
        let all = RecordType::all();
        assert_eq!(all.len(), 17);
        assert!(all.contains(&RecordType::CHAT));
        assert!(all.contains(&RecordType::MESSAGE));
    }
}
