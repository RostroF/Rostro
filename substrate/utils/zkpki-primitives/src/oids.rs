//! OID constants for ZK-PKI certificate extensions and EKUs.
//!
//! Standard X.509 OIDs are final.
//! Custom ZK-PKI OIDs are pending IANA PEN assignment.
//!
//! IANA PEN request: PHH7-C3F-3EC (filed 2026-04-18)
//! Expected: within 7 days
//! Once assigned replace YOUR_PEN throughout this file.
//!
//! OID arc structure:
//!   1.3.6.1.4.1.YOUR_PEN.1      ZK-PKI
//!   1.3.6.1.4.1.YOUR_PEN.1.1   Extended Key Usages
//!   1.3.6.1.4.1.YOUR_PEN.1.2   Certificate Extensions
//!   1.3.6.1.4.1.YOUR_PEN.1.3   Certificate Policies
//!   1.3.6.1.4.1.YOUR_PEN.2      PNS (reserved)

// Standard X.509 EKUs — final
pub const OID_EKU_SERVER_AUTH: &str      = "1.3.6.1.5.5.7.3.1";
pub const OID_EKU_CLIENT_AUTH: &str      = "1.3.6.1.5.5.7.3.2";
pub const OID_EKU_CODE_SIGNING: &str     = "1.3.6.1.5.5.7.3.3";
pub const OID_EKU_EMAIL_PROTECTION: &str = "1.3.6.1.5.5.7.3.4";

// ZK-PKI EKUs — TODO: replace YOUR_PEN with assigned PEN
pub const OID_EKU_PROOF_OF_PERSONHOOD: &str   = "1.3.6.1.4.1.YOUR_PEN.1.1.1";
pub const OID_EKU_BLOCKCHAIN_SIGNING: &str    = "1.3.6.1.4.1.YOUR_PEN.1.1.2";
pub const OID_EKU_IDENTITY_ASSERTION: &str    = "1.3.6.1.4.1.YOUR_PEN.1.1.3";
pub const OID_EKU_ISSUER_CERT: &str           = "1.3.6.1.4.1.YOUR_PEN.1.1.4";
pub const OID_EKU_ROOT_CERT: &str             = "1.3.6.1.4.1.YOUR_PEN.1.1.5";
pub const OID_EKU_SMART_CONTRACT_ISSUER: &str = "1.3.6.1.4.1.YOUR_PEN.1.1.6";

// ZK-PKI Certificate Extensions — TODO: replace YOUR_PEN
pub const OID_EXT_THUMBPRINT: &str            = "1.3.6.1.4.1.YOUR_PEN.1.2.1";
pub const OID_EXT_EK_HASH: &str               = "1.3.6.1.4.1.YOUR_PEN.1.2.2";
pub const OID_EXT_ATTESTATION_TYPE: &str      = "1.3.6.1.4.1.YOUR_PEN.1.2.3";
pub const OID_EXT_MANUFACTURER_VERIFIED: &str = "1.3.6.1.4.1.YOUR_PEN.1.2.4";
pub const OID_EXT_MINT_BLOCK: &str            = "1.3.6.1.4.1.YOUR_PEN.1.2.5";
pub const OID_EXT_EXPIRY_BLOCK: &str          = "1.3.6.1.4.1.YOUR_PEN.1.2.6";
pub const OID_EXT_ISSUER_ADDRESS: &str        = "1.3.6.1.4.1.YOUR_PEN.1.2.7";
pub const OID_EXT_ROOT_ADDRESS: &str          = "1.3.6.1.4.1.YOUR_PEN.1.2.8";
pub const OID_EXT_TEMPLATE_NAME: &str         = "1.3.6.1.4.1.YOUR_PEN.1.2.9";
pub const OID_EXT_POP_REQUIRED: &str          = "1.3.6.1.4.1.YOUR_PEN.1.2.10";
pub const OID_EXT_NETWORK_ID: &str            = "1.3.6.1.4.1.YOUR_PEN.1.2.11";
pub const OID_EXT_PNS_NAME: &str              = "1.3.6.1.4.1.YOUR_PEN.1.2.12";
pub const OID_EXT_HIP_PROOF: &str             = "1.3.6.1.4.1.YOUR_PEN.1.2.13";
pub const OID_EXT_SCHEMA_VERSION: &str        = "1.3.6.1.4.1.YOUR_PEN.1.2.14";

// ZK-PKI Certificate Policies — TODO: replace YOUR_PEN
pub const OID_POLICY_POP_REQUIRED: &str          = "1.3.6.1.4.1.YOUR_PEN.1.3.1";
pub const OID_POLICY_POP_NOT_REQUIRED: &str      = "1.3.6.1.4.1.YOUR_PEN.1.3.2";
pub const OID_POLICY_HARDWARE_ATTESTED: &str     = "1.3.6.1.4.1.YOUR_PEN.1.3.3";
pub const OID_POLICY_SMART_CONTRACT_ISSUED: &str = "1.3.6.1.4.1.YOUR_PEN.1.3.4";
pub const OID_POLICY_HUMAN_REVIEWED: &str        = "1.3.6.1.4.1.YOUR_PEN.1.3.5";

// PNS reserved arc — TODO: replace YOUR_PEN
pub const OID_PNS_ARC: &str = "1.3.6.1.4.1.YOUR_PEN.2";
