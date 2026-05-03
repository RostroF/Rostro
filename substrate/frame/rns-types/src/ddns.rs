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
        /// Polkadot SS58 address record (IANA private use 65280)
        SS58,
        /// Polkadot RPC/WebSocket endpoint record (IANA private use 65281)
        RPC,
        /// Polkadot validator stash address record (IANA private use 65282)
        VALIDATOR,
        /// Polkadot parachain ID record (IANA private use 65283)
        PARA,
        /// PNS name pointer, CNAME equivalent for SS58 namespace (IANA private use 65284)
        PROXY,
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
        /// Public key of a TLS certificate for this domain (IANA private use 65291).
        /// Allows clients to verify TLS without a traditional CA chain.
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
                // Polkadot-specific
                RecordType::SS58,
                RecordType::RPC,
                RecordType::VALIDATOR,
                RecordType::PARA,
                RecordType::PROXY,
                RecordType::PUBKEY1,
                RecordType::AVATAR,
                RecordType::CONTRACT,
                RecordType::PUBKEY2,
                RecordType::PUBKEY3,
                RecordType::ORIGIN,
                RecordType::IPFS,
                RecordType::CONTENT,
            ]
        }
    }
}
