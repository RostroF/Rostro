//! Multi-curve device public key types for hardware-bound cert keypairs.
//!
//! Supported algorithms:
//! - P-256 (secp256r1) — Android StrongBox, Apple Secure Enclave
//! - P-521 (secp521r1) — Discrete TPM 2.0
//! - ML-DSA-65 / ML-DSA-87 — TPM 2.0 v1.85+ (post-quantum, stub until crate ships)
//!
//! Keys live inside StrongBox / Secure Enclave / discrete TPM — the private key
//! never leaves the secure hardware boundary. TEE (TrustZone) is NOT acceptable.
//!
//! **Audit caveat**: the underlying EC arithmetic in `p256` and `p521` crates has
//! never been independently audited and constant-time behavior is unverified.
//! Acceptable for Paseo testnet. Independent audit required before mainnet.

extern crate alloc;

use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use frame_support::BoundedVec;
use frame_support::traits::ConstU32;
use scale_info::TypeInfo;

use crate::bounds::MAX_DEVICE_PUBKEY_LEN;

/// Cryptographic algorithm identifier for device-bound keys.
/// The client picks the strongest algorithm its hardware supports.
/// The pallet validates signatures by dispatching on this discriminant.
#[derive(Encode, Decode, DecodeWithMemTracking, Clone, Copy, PartialEq, Eq, TypeInfo, MaxEncodedLen, Debug)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub enum KeyAlgorithm {
    /// ECDSA with NIST P-256 (secp256r1).
    /// Android StrongBox, Apple Secure Enclave. 128-bit classical security.
    EcdsaP256,
    /// ECDSA with NIST P-521 (secp521r1).
    /// Discrete TPM 2.0. 260-bit classical security.
    EcdsaP521,
    /// ML-DSA-65 (FIPS 204). Post-quantum lattice signatures.
    /// TPM 2.0 v1.85+. NIST security level 3.
    /// Stub — verification returns false until ml-dsa crate ships in no_std.
    MlDsa65,
    /// ML-DSA-87 (FIPS 204). Post-quantum lattice signatures.
    /// TPM 2.0 v1.85+. NIST security level 5 (highest).
    /// Stub — verification returns false until ml-dsa crate ships in no_std.
    MlDsa87,
}

/// A device public key with its algorithm identifier.
///
/// The key bytes are the raw public key in the format appropriate for the algorithm:
/// - P-256: SEC1 uncompressed point (65 bytes) or compressed (33 bytes)
/// - P-521: SEC1 uncompressed point (133 bytes) or compressed (67 bytes)
/// - ML-DSA-65: raw public key (~1,952 bytes)
/// - ML-DSA-87: raw public key (~2,592 bytes)
///
/// SCALE encoding includes the algorithm discriminant, so thumbprints are
/// naturally unique across key types even with identical raw bytes.
#[derive(Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, TypeInfo, MaxEncodedLen)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct DevicePublicKey {
    pub algorithm: KeyAlgorithm,
    pub key_bytes: BoundedVec<u8, ConstU32<MAX_DEVICE_PUBKEY_LEN>>,
}

#[cfg(feature = "std")]
impl core::fmt::Debug for DevicePublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let preview: &[u8] = if self.key_bytes.len() >= 4 {
            &self.key_bytes[..4]
        } else {
            &self.key_bytes
        };
        write!(f, "DevicePublicKey({:?}, 0x{}..  {} bytes)",
            self.algorithm,
            preview.iter().fold(alloc::string::String::new(), |acc, b| alloc::format!("{acc}{b:02x}")),
            self.key_bytes.len(),
        )
    }
}

#[cfg(not(feature = "std"))]
impl core::fmt::Debug for DevicePublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "DevicePublicKey({:?}, {} bytes)", self.algorithm, self.key_bytes.len())
    }
}

impl DevicePublicKey {
    /// Construct a P-256 device public key from raw SEC1 bytes.
    pub fn new_p256(key_bytes: &[u8]) -> Result<Self, ()> {
        Ok(Self {
            algorithm: KeyAlgorithm::EcdsaP256,
            key_bytes: BoundedVec::try_from(key_bytes.to_vec()).map_err(|_| ())?,
        })
    }

    /// Construct a P-521 device public key from raw SEC1 bytes.
    pub fn new_p521(key_bytes: &[u8]) -> Result<Self, ()> {
        Ok(Self {
            algorithm: KeyAlgorithm::EcdsaP521,
            key_bytes: BoundedVec::try_from(key_bytes.to_vec()).map_err(|_| ())?,
        })
    }

    /// Validate that the key bytes are a valid curve point for the declared algorithm.
    /// Returns false if the bytes cannot be parsed as a valid public key.
    /// The pallet MUST call this at the extrinsic boundary before writing to storage.
    pub fn is_valid(&self) -> bool {
        match self.algorithm {
            KeyAlgorithm::EcdsaP256 => {
                p256::ecdsa::VerifyingKey::from_sec1_bytes(&self.key_bytes).is_ok()
            }
            KeyAlgorithm::EcdsaP521 => {
                p521::ecdsa::VerifyingKey::from_sec1_bytes(&self.key_bytes).is_ok()
            }
            // PQC key validation stubbed until crate available
            KeyAlgorithm::MlDsa65 | KeyAlgorithm::MlDsa87 => false,
        }
    }

    /// Verify a signature over a message using this public key.
    /// Dispatches to the correct curve's verification logic.
    /// Accepts both DER-encoded and raw (r||s) signature formats for ECDSA.
    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> bool {
        match self.algorithm {
            KeyAlgorithm::EcdsaP256 => self.verify_p256(message, signature),
            KeyAlgorithm::EcdsaP521 => self.verify_p521(message, signature),
            // PQC verification stubbed — reject until ml-dsa crate ships in no_std
            KeyAlgorithm::MlDsa65 | KeyAlgorithm::MlDsa87 => false,
        }
    }

    fn verify_p256(&self, message: &[u8], signature: &[u8]) -> bool {
        use p256::ecdsa::signature::Verifier;

        let vk = match p256::ecdsa::VerifyingKey::from_sec1_bytes(&self.key_bytes) {
            Ok(k) => k,
            Err(_) => return false,
        };

        // Try DER first
        if let Ok(sig) = p256::ecdsa::Signature::from_der(signature) {
            if vk.verify(message, &sig).is_ok() {
                return true;
            }
        }

        // Fall back to raw (r || s)
        if let Ok(sig) = p256::ecdsa::Signature::from_slice(signature) {
            if vk.verify(message, &sig).is_ok() {
                return true;
            }
        }

        false
    }

    fn verify_p521(&self, message: &[u8], signature: &[u8]) -> bool {
        use p521::ecdsa::signature::Verifier;

        let vk = match p521::ecdsa::VerifyingKey::from_sec1_bytes(&self.key_bytes) {
            Ok(k) => k,
            Err(_) => return false,
        };

        // Try DER first
        if let Ok(sig) = p521::ecdsa::Signature::from_der(signature) {
            if vk.verify(message, &sig).is_ok() {
                return true;
            }
        }

        // Fall back to raw (r || s)
        if let Ok(sig) = p521::ecdsa::Signature::from_slice(signature) {
            if vk.verify(message, &sig).is_ok() {
                return true;
            }
        }

        false
    }
}

// ═══════════════════════════════════════════════════════════════
// Legacy type alias — existing code that references P521PublicKey
// continues to compile. Gradually migrate to DevicePublicKey.
// ═══════════════════════════════════════════════════════════════

/// SEC1 uncompressed point length for P-521: 1 (tag) + 66 + 66 = 133 bytes.
pub const P521_PUBKEY_LEN: usize = 133;

/// Legacy P-521 public key type. Kept for backward compatibility with code
/// that constructs P521PublicKey directly. New code should use DevicePublicKey.
#[derive(Clone, PartialEq, Eq)]
pub struct P521PublicKey(pub [u8; P521_PUBKEY_LEN]);

impl P521PublicKey {
    /// Convert to the new DevicePublicKey type.
    pub fn to_device_key(&self) -> DevicePublicKey {
        DevicePublicKey {
            algorithm: KeyAlgorithm::EcdsaP521,
            key_bytes: BoundedVec::try_from(self.0.to_vec())
                .expect("P521 key fits in MAX_DEVICE_PUBKEY_LEN"),
        }
    }
}

// SCALE Encode
impl Encode for P521PublicKey {
    fn encode_to<T: codec::Output + ?Sized>(&self, dest: &mut T) {
        self.0.encode_to(dest);
    }
    fn size_hint(&self) -> usize {
        P521_PUBKEY_LEN
    }
}

// SCALE Decode
impl Decode for P521PublicKey {
    fn decode<I: codec::Input>(input: &mut I) -> Result<Self, codec::Error> {
        let bytes = <[u8; P521_PUBKEY_LEN]>::decode(input)?;
        Ok(P521PublicKey(bytes))
    }
}

impl DecodeWithMemTracking for P521PublicKey {}

impl MaxEncodedLen for P521PublicKey {
    fn max_encoded_len() -> usize {
        P521_PUBKEY_LEN
    }
}

impl TypeInfo for P521PublicKey {
    type Identity = Self;
    fn type_info() -> scale_info::Type {
        scale_info::Type::builder()
            .path(scale_info::Path::new("P521PublicKey", module_path!()))
            .composite(
                scale_info::build::Fields::unnamed()
                    .field(|f| f.ty::<[u8; P521_PUBKEY_LEN]>()),
            )
    }
}

#[cfg(feature = "std")]
impl serde::Serialize for P521PublicKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let hex_str: alloc::string::String = self.0.iter().fold("0x".to_string(), |acc, b| alloc::format!("{acc}{b:02x}"));
        serializer.serialize_str(&hex_str)
    }
}

#[cfg(feature = "std")]
impl<'de> serde::Deserialize<'de> for P521PublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let hex_str = alloc::string::String::deserialize(deserializer)?;
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(&hex_str);
        let bytes: alloc::vec::Vec<u8> = (0..hex_str.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16))
            .collect::<Result<_, _>>()
            .map_err(serde::de::Error::custom)?;
        if bytes.len() != P521_PUBKEY_LEN {
            return Err(serde::de::Error::custom("invalid P521 pubkey length"));
        }
        let mut raw = [0u8; P521_PUBKEY_LEN];
        raw.copy_from_slice(&bytes);
        Ok(P521PublicKey(raw))
    }
}

#[cfg(feature = "std")]
impl core::fmt::Debug for P521PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "P521PublicKey(0x{:02x}{:02x}{:02x}{:02x}..)", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

#[cfg(not(feature = "std"))]
impl core::fmt::Debug for P521PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "P521PublicKey([{}, {}, ...])", self.0[0], self.0[1])
    }
}

impl P521PublicKey {
    pub fn to_verifying_key(&self) -> Option<p521::ecdsa::VerifyingKey> {
        p521::ecdsa::VerifyingKey::from_sec1_bytes(&self.0).ok()
    }

    pub fn from_verifying_key(key: &p521::ecdsa::VerifyingKey) -> Result<Self, ()> {
        let point = p521::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(
            key.as_affine(),
            false,
        );
        let bytes = point.as_bytes();
        if bytes.len() != P521_PUBKEY_LEN {
            return Err(());
        }
        let mut raw = [0u8; P521_PUBKEY_LEN];
        raw.copy_from_slice(bytes);
        Ok(P521PublicKey(raw))
    }

    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> bool {
        self.to_device_key().verify_signature(message, signature)
    }
}
