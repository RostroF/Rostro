use codec::{Decode, Encode};

use rns_types::ddns::codec_type::RecordType;

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum RData {
    A([u8; 4]),
    Aaaa([u8; 16]),
    Cname(Vec<u8>),
    Txt(Vec<u8>),

    Ss58(Vec<u8>),
    Rpc(Vec<u8>),
    Validator(Vec<u8>),
    Pubkey1(Vec<u8>),
    Pubkey2(Vec<u8>),
    Pubkey3(Vec<u8>),
    Avatar(Vec<u8>),
    Contract(Vec<u8>),
    Origin([u8; 32]),
    Ipfs(Vec<u8>),
    Content(Vec<u8>),

    Unknown(u16, Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct DnsRecord {
    pub record_type: RecordType,
    pub rdata: RData,
    pub ttl: u32,
}

impl DnsRecord {
    pub fn a(addr: [u8; 4], ttl: u32) -> Self {
        Self { record_type: RecordType::A, rdata: RData::A(addr), ttl }
    }

    pub fn aaaa(addr: [u8; 16], ttl: u32) -> Self {
        Self { record_type: RecordType::AAAA, rdata: RData::Aaaa(addr), ttl }
    }

    pub fn cname(target: Vec<u8>, ttl: u32) -> Self {
        Self { record_type: RecordType::CNAME, rdata: RData::Cname(target), ttl }
    }

    pub fn txt(content: Vec<u8>, ttl: u32) -> Self {
        Self { record_type: RecordType::TXT, rdata: RData::Txt(content), ttl }
    }

    pub fn ss58(addr: Vec<u8>, ttl: u32) -> Self {
        Self { record_type: RecordType::SS58, rdata: RData::Ss58(addr), ttl }
    }

    pub fn rpc(endpoint: Vec<u8>, ttl: u32) -> Self {
        Self { record_type: RecordType::RPC, rdata: RData::Rpc(endpoint), ttl }
    }

    pub fn validator(stash: Vec<u8>, ttl: u32) -> Self {
        Self { record_type: RecordType::VALIDATOR, rdata: RData::Validator(stash), ttl }
    }

    pub fn pubkey1(key: Vec<u8>, ttl: u32) -> Self {
        Self { record_type: RecordType::PUBKEY1, rdata: RData::Pubkey1(key), ttl }
    }

    pub fn pubkey2(key: Vec<u8>, ttl: u32) -> Self {
        Self { record_type: RecordType::PUBKEY2, rdata: RData::Pubkey2(key), ttl }
    }

    pub fn pubkey3(key: Vec<u8>, ttl: u32) -> Self {
        Self { record_type: RecordType::PUBKEY3, rdata: RData::Pubkey3(key), ttl }
    }

    pub fn avatar(hash: Vec<u8>, ttl: u32) -> Self {
        Self { record_type: RecordType::AVATAR, rdata: RData::Avatar(hash), ttl }
    }

    pub fn contract(addr: Vec<u8>, ttl: u32) -> Self {
        Self { record_type: RecordType::CONTRACT, rdata: RData::Contract(addr), ttl }
    }

    pub fn origin(block_hash: [u8; 32], ttl: u32) -> Self {
        Self { record_type: RecordType::ORIGIN, rdata: RData::Origin(block_hash), ttl }
    }

    pub fn ipfs(key: Vec<u8>, ttl: u32) -> Self {
        Self { record_type: RecordType::IPFS, rdata: RData::Ipfs(key), ttl }
    }

    pub fn content(cid: Vec<u8>, ttl: u32) -> Self {
        Self { record_type: RecordType::CONTENT, rdata: RData::Content(cid), ttl }
    }

    pub fn from_raw(record_type: RecordType, data: Vec<u8>, ttl: u32) -> Self {
        let rdata = match record_type {
            RecordType::A => {
                let mut addr = [0u8; 4];
                if data.len() == 4 { addr.copy_from_slice(&data); }
                RData::A(addr)
            }
            RecordType::AAAA => {
                let mut addr = [0u8; 16];
                if data.len() == 16 { addr.copy_from_slice(&data); }
                RData::Aaaa(addr)
            }
            RecordType::CNAME => RData::Cname(data),
            RecordType::TXT => RData::Txt(data),
            RecordType::SS58 => RData::Ss58(data),
            RecordType::RPC => RData::Rpc(data),
            RecordType::VALIDATOR => RData::Validator(data),
            RecordType::PUBKEY1 => RData::Pubkey1(data),
            RecordType::PUBKEY2 => RData::Pubkey2(data),
            RecordType::PUBKEY3 => RData::Pubkey3(data),
            RecordType::AVATAR => RData::Avatar(data),
            RecordType::CONTRACT => RData::Contract(data),
            RecordType::ORIGIN => {
                let mut hash = [0u8; 32];
                if data.len() == 32 { hash.copy_from_slice(&data); }
                RData::Origin(hash)
            }
            RecordType::IPFS => RData::Ipfs(data),
            RecordType::CONTENT => RData::Content(data),
            RecordType::Unknown(code) => RData::Unknown(code, data),
            _ => RData::Unknown(0, data),
        };
        Self { record_type, rdata, ttl }
    }
}
