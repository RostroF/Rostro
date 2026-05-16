//! Android Keystore attestation parsing.
//!
//! The attestation field delivered via `mint_cert` is a SCALE-encoded
//! `Vec<Vec<u8>>` where each inner vector is a DER-encoded X.509 certificate.
//! Order: leaf cert first (the one bound to the attested device key), then
//! intermediates, with Google's Hardware Attestation Root CA last.
//!
//! The leaf certificate carries the Android Keystore KeyDescription extension
//! (OID 1.3.6.1.4.1.11129.2.1.17). That extension is an OCTET STRING wrapping
//! a SEQUENCE whose fields include the attestation challenge we passed at key
//! generation time, the security levels the key lives under, and a
//! hardwareEnforced AuthorizationList that contains the RootOfTrust structure.
//! We extract the fields the pallet needs for a proof-of-personhood decision:
//!
//! - Attested pubkey and attestation challenge (freshness + binding).
//! - Both security levels (must be StrongBox — not TEE, not Software).
//! - RootOfTrust: `deviceLocked` and `verifiedBootState`.
//!
//! **Why the RootOfTrust check is load-bearing for PoP**: a rooted device
//! with an unlocked bootloader can automate the entire ceremony — produce
//! real StrongBox keys, valid attestation chains, and a valid binding proof
//! — without any human ever touching an authenticator app. EK deduplication
//! doesn't block the attack because a factory reset on the same hardware is
//! sufficient to re-enroll, and a farm of 1000 rooted devices is worse. The
//! cryptographic binding proof doesn't close it either because a rooted
//! device automates past the human-gate assumption.
//!
//! RootOfTrust is the anchor that closes the farm attack. Its fields are in
//! the **hardwareEnforced** AuthorizationList — collected by secure hardware,
//! not by userspace, and sealed into the attestation at ceremony time. A
//! rooted phone cannot fake `deviceLocked = true` or
//! `verifiedBootState = Verified` because those bits come from the same
//! secure element that's signing the attestation. Factory reset doesn't
//! help — bootloader unlock state is persisted at the hardware level.
//!
//! # Dotwave ceremony keys — key-purpose notes
//!
//! The ceremony produces three StrongBox-backed keys; two of them have
//! purpose choices the parser needs to understand so that a future reader
//! doesn't mistake a platform-forced deviation for a bug.
//!
//! - `zkpki_cert_ec` — `PURPOSE_SIGN | PURPOSE_VERIFY`. The user's
//!   on-chain cert signing key.
//!
//! - `zkpki_attest_ec` — `PURPOSE_SIGN | PURPOSE_VERIFY`, **not**
//!   `PURPOSE_ATTEST_KEY`. The ZK-PKI architecture originally called for
//!   an attest-key-purpose key whose only role was to sign another key's
//!   attestation certificate via Android's `setAttestKeyAlias`. Two
//!   platform constraints on Samsung Android 13 ruled that out:
//!
//!     1. Samsung KeyMint silently ignores `setAttestKeyAlias` on
//!        symmetric keys. The canonical chain-binding path for the HMAC
//!        key is unavailable — it returns a null chain with no error.
//!     2. A `PURPOSE_ATTEST_KEY`-only key cannot be used with
//!        `Signature.initSign()` — KeyMint rejects it as
//!        INCOMPATIBLE_PURPOSE. There's no way to sign arbitrary bytes
//!        (i.e. the binding proof commitment) with such a key.
//!
//!   So `zkpki_attest_ec` is configured as a regular signing key. Its
//!   role is still architecturally narrow — it exists to sign the
//!   binding proof commitment at ceremony time and nothing else. That
//!   discipline is enforced by convention (code comments in the Kotlin
//!   ceremony) rather than by the keystore's purpose restriction. The
//!   spec was adjusted to match what Android KeyMint actually
//!   implements on this hardware class; the operational binding proof
//!   replaces the AttestKey binding.
//!
//! - `zkpki_totp_hmac` — HMAC-SHA256, no attestation chain (Samsung
//!   KeyMint doesn't produce one). StrongBox-backed per
//!   `KeyInfo.securityLevel` checked during the ceremony. Its presence
//!   inside the same StrongBox as `zkpki_attest_ec` is proven by the
//!   binding-proof signature, not by a cert chain.
//!
//! Ground truth for development: `tests/fixtures/sm_g986u_attestation.rs`
//! contains a real cert chain captured from a Samsung Galaxy S20+ 5G
//! (locked bootloader, verified boot) running dotwave's ceremony on
//! 2026-04-16. That fixture's RootOfTrust has `deviceLocked = true` and
//! `verifiedBootState = Verified`.

extern crate alloc;

use alloc::vec::Vec;
use codec::Decode as ScaleDecode;
use const_oid::ObjectIdentifier;
use der::{Decode as DerDecode, Encode as DerEncode, Reader, SliceReader, Tag};
use x509_cert::Certificate;
use zk_pki_primitives::crypto::DevicePublicKey;

/// Android Keystore KeyDescription extension OID: 1.3.6.1.4.1.11129.2.1.17.
const KEY_DESCRIPTION_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.1.17");

/// Context-specific tag number for the `rootOfTrust` field inside the
/// hardwareEnforced AuthorizationList. Defined in the Android KeyMint
/// attestation schema.
const ROOT_OF_TRUST_TAG: u32 = 704;

/// Context-specific tag number for the `attestationApplicationId` field
/// inside the hardwareEnforced AuthorizationList. Matches AOSP
/// `KM_TAG_ATTESTATION_APPLICATION_ID = 709` (BYTES type).
///
/// # Wire format
///
/// The field is encoded as `[709] EXPLICIT OCTET STRING`, where the
/// OCTET STRING content is a DER-encoded SEQUENCE:
///
/// ```asn1
/// AttestationApplicationId ::= SEQUENCE {
///     package_infos      SET OF AttestationPackageInfo,
///     signature_digests  SET OF OCTET_STRING,
/// }
///
/// AttestationPackageInfo ::= SEQUENCE {
///     package_name  OCTET_STRING,
///     version       INTEGER,
/// }
/// ```
///
/// The Android Keystore daemon writes this at key-generation time, not
/// the app — so matching the chain's AAID against the integrity blob
/// proves the ceremony ran inside the genuine app and not a rogue
/// process with the right attestation keys.
const ATTESTATION_APPLICATION_ID_TAG: u32 = 709;

/// Android Keystore security level (from the `SecurityLevel` ENUMERATED
/// in the KeyDescription extension).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    Software = 0,
    TrustedEnvironment = 1,
    StrongBox = 2,
}

impl SecurityLevel {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Software),
            1 => Some(Self::TrustedEnvironment),
            2 => Some(Self::StrongBox),
            _ => None,
        }
    }
}

/// Android Keystore verified boot state (from the `VerifiedBootState`
/// ENUMERATED inside RootOfTrust).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifiedBootState {
    /// Fully verified boot chain with factory-trusted keys. Required for PoP.
    Verified = 0,
    /// Boot verified with user-supplied keys (e.g., custom ROM signed by user).
    /// Not PoP-eligible.
    SelfSigned = 1,
    /// Bootloader unlocked. Not PoP-eligible.
    Unverified = 2,
    /// Verified boot failed. Not PoP-eligible.
    Failed = 3,
}

impl VerifiedBootState {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Verified),
            1 => Some(Self::SelfSigned),
            2 => Some(Self::Unverified),
            3 => Some(Self::Failed),
            _ => None,
        }
    }
}

/// Parsed Android Keystore attestation — the subset of fields the pallet
/// needs to make a mint decision.
pub struct ParsedAttestation {
    /// Attested device public key extracted from the leaf cert's SPKI.
    pub pubkey: DevicePublicKey,
    /// Attestation challenge from the KeyDescription extension. Must match
    /// the offer nonce supplied to `mint_cert`.
    pub attestation_challenge: Vec<u8>,
    /// Top-level attestation security level from the KeyDescription.
    pub attestation_security_level: SecurityLevel,
    /// KeyMint security level — where the attested key actually lives.
    pub keymint_security_level: SecurityLevel,
    /// RootOfTrust: whether the device's bootloader is locked. A rooted
    /// device (unlocked bootloader) reports `false`.
    pub device_locked: bool,
    /// RootOfTrust: verified boot state. Only `Verified` (0) corresponds to
    /// a factory-signed, PoP-eligible boot chain.
    pub verified_boot_state: VerifiedBootState,
    /// DER bytes of the root (last) cert in the chain. Retained for
    /// fixture diagnostics; **not** the EK identity value.
    pub root_cert_der: Vec<u8>,
    /// DER bytes of the leaf certificate's `SubjectPublicKeyInfo`
    /// (AlgorithmIdentifier + subjectPublicKey). Device-unique: every
    /// StrongBox-backed keypair gets a fresh SPKI at generation time,
    /// so hashing this gives an EK identity that distinguishes devices
    /// sharing the same manufacturer attestation root.
    pub leaf_spki_der: Vec<u8>,
    /// True when both security-level fields are StrongBox.
    pub is_hardware: bool,
    /// True when the device is PoP-eligible: StrongBox on both levels AND
    /// bootloader locked AND verified boot state = Verified. A rooted phone
    /// farm fails this check. Factory reset doesn't bypass it.
    pub is_pop_eligible: bool,
    /// `attestationApplicationId`'s first `package_name` if present. The
    /// Android Keystore daemon writes this at key generation time — the
    /// app cannot forge it — so this is the load-bearing value for
    /// cross-checking against the integrity blob's declared
    /// `package_name`. `None` if the chain's KeyDescription does not
    /// carry tag [709] (older firmware or non-standard chains).
    pub package_name: Option<Vec<u8>>,
    /// `attestationApplicationId`'s first `signature_digest` if present.
    /// SHA-256 of the APK signing certificate, written by the Keystore
    /// daemon. Cross-checked against the integrity blob's
    /// `signing_cert_hash`. `None` if absent from the chain.
    pub signing_cert_hash: Option<[u8; 32]>,
}

/// Parse a SCALE-encoded cert chain (`Vec<Vec<u8>>`) and extract the
/// attestation fields. Returns `None` on any structural error.
pub fn parse_attestation(attestation: &[u8]) -> Option<ParsedAttestation> {
    let chain: Vec<Vec<u8>> = ScaleDecode::decode(&mut &attestation[..]).ok()?;

    // Chain signature verification and root pinning happen before we trust
    // any field in the KeyDescription extension. An attacker who provides
    // arbitrary certs with a forged KeyDescription would be rejected here.
    crate::chain::verify_chain(&chain).ok()?;

    parse_chain_without_verify(&chain)
}

/// Extract attestation fields from an already-parsed-and-verified cert
/// chain. Assumes `verify_chain` (or equivalent) has already run — the
/// caller is responsible for chain validity. Exists as a separate entry
/// point so the TODO-3 payload verifier in `verify::verify_binding_proof`
/// can validate two chains once and extract their leaf fields without
/// re-running chain verification on each pass.
pub fn parse_chain_without_verify(chain: &[Vec<u8>]) -> Option<ParsedAttestation> {
    if chain.is_empty() || chain.len() > 10 {
        return None;
    }

    let leaf = Certificate::from_der(&chain[0]).ok()?;

    // Extract the attested public key from the leaf's SPKI.
    // raw_bytes() returns the bytes as encoded in the BitString — for EC
    // SEC1 uncompressed points there are no unused bits so this is the
    // public key we want.
    let pubkey_bytes = leaf
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    let pubkey = DevicePublicKey::new_p256(pubkey_bytes).ok()?;

    // Find the KeyDescription extension on the leaf cert.
    let extensions = leaf.tbs_certificate.extensions.as_ref()?;
    let ext = extensions
        .iter()
        .find(|e| e.extn_id == KEY_DESCRIPTION_OID)?;

    let key_desc = parse_key_description(ext.extn_value.as_bytes())?;

    let is_hardware = key_desc.attestation_security_level == SecurityLevel::StrongBox
        && key_desc.keymint_security_level == SecurityLevel::StrongBox;

    let is_pop_eligible = is_hardware
        && key_desc.device_locked
        && key_desc.verified_boot_state == VerifiedBootState::Verified;

    // Root is the last cert in the chain. Retained for fixture
    // diagnostics only — the EK identity value is derived from the
    // leaf SPKI below, not from this field.
    let root_cert_der = chain.last()?.clone();

    // Leaf SPKI (AlgorithmIdentifier + subjectPublicKey) re-encoded
    // as DER. This is the EK identity basis: it's device-unique
    // (every StrongBox key generation produces a fresh SPKI) and it
    // lives inside the signed TBS so a chain that verifies cannot
    // have a mutated SPKI. Caller hashes with blake2-256.
    let leaf_spki_der = leaf.tbs_certificate.subject_public_key_info.to_der().ok()?;

    Some(ParsedAttestation {
        pubkey,
        attestation_challenge: key_desc.attestation_challenge,
        attestation_security_level: key_desc.attestation_security_level,
        keymint_security_level: key_desc.keymint_security_level,
        device_locked: key_desc.device_locked,
        verified_boot_state: key_desc.verified_boot_state,
        root_cert_der,
        leaf_spki_der,
        is_hardware,
        is_pop_eligible,
        package_name: key_desc.package_name,
        signing_cert_hash: key_desc.signing_cert_hash,
    })
}

/// Fields decoded from the KeyDescription ASN.1 SEQUENCE.
struct KeyDescription {
    attestation_security_level: SecurityLevel,
    keymint_security_level: SecurityLevel,
    attestation_challenge: Vec<u8>,
    device_locked: bool,
    verified_boot_state: VerifiedBootState,
    /// First `package_name` from `attestationApplicationId`'s package
    /// info set, or `None` if tag [709] is absent.
    package_name: Option<Vec<u8>>,
    /// First SHA-256 from `attestationApplicationId`'s signature digest
    /// set, or `None` if the digest set is missing / a different hash
    /// length is observed.
    signing_cert_hash: Option<[u8; 32]>,
}

/// Walk the KeyDescription SEQUENCE by position. ASN.1 layout:
///
/// ```asn1
/// KeyDescription ::= SEQUENCE {
///     attestationVersion         INTEGER,
///     attestationSecurityLevel   ENUMERATED,
///     keyMintVersion             INTEGER,
///     keyMintSecurityLevel       ENUMERATED,
///     attestationChallenge       OCTET_STRING,
///     uniqueId                   OCTET_STRING,
///     softwareEnforced           AuthorizationList,     -- skipped
///     hardwareEnforced           AuthorizationList,     -- walked for [704] RootOfTrust
/// }
/// ```
fn parse_key_description(extn_value: &[u8]) -> Option<KeyDescription> {
    let mut outer = SliceReader::new(extn_value).ok()?;

    let header = der::Header::decode(&mut outer).ok()?;
    if header.tag != Tag::Sequence {
        return None;
    }
    let body = outer.read_slice(header.length).ok()?;
    let mut r = SliceReader::new(body).ok()?;

    // attestationVersion INTEGER — skip.
    skip_tlv(&mut r)?;

    // attestationSecurityLevel ENUMERATED.
    let attestation_security_level = read_enumerated_u8(&mut r)?;

    // keyMintVersion INTEGER — skip.
    skip_tlv(&mut r)?;

    // keyMintSecurityLevel ENUMERATED.
    let keymint_security_level = read_enumerated_u8(&mut r)?;

    // attestationChallenge OCTET_STRING.
    let attestation_challenge = read_octet_string(&mut r)?;

    // uniqueId OCTET_STRING — skip.
    skip_tlv(&mut r)?;

    // softwareEnforced AuthorizationList (SEQUENCE).  Contains
    // [709] attestationApplicationId — written by the keystore2
    // userspace daemon at key generation time (not by the TEE, which
    // cannot verify package identity).  RootOfTrust lives in the next
    // list (hardwareEnforced) because those fields come from secure
    // hardware.
    let sw_header = der::Header::decode(&mut r).ok()?;
    if sw_header.tag != Tag::Sequence {
        return None;
    }
    let sw_body = r.read_slice(sw_header.length).ok()?;
    let (package_name, signing_cert_hash) =
        find_context_tag_body(sw_body, ATTESTATION_APPLICATION_ID_TAG)
            .and_then(parse_attestation_application_id)
            .unwrap_or((None, None));

    // hardwareEnforced AuthorizationList (SEQUENCE).  Contains
    // [704] rootOfTrust — the load-bearing PoP fields (deviceLocked +
    // verifiedBootState).  We read the SEQUENCE header and walk the
    // body manually because der 0.7 can't represent the high-numbered
    // context-specific tags that appear here.
    let hw_header = der::Header::decode(&mut r).ok()?;
    if hw_header.tag != Tag::Sequence {
        return None;
    }
    let hw_body = r.read_slice(hw_header.length).ok()?;
    let rot_body = find_context_tag_body(hw_body, ROOT_OF_TRUST_TAG)?;
    let (device_locked, verified_boot_state) = parse_root_of_trust(rot_body)?;

    Some(KeyDescription {
        attestation_security_level: SecurityLevel::from_u8(attestation_security_level)?,
        keymint_security_level: SecurityLevel::from_u8(keymint_security_level)?,
        attestation_challenge,
        device_locked,
        verified_boot_state,
        package_name,
        signing_cert_hash,
    })
}

/// Walk an AuthorizationList body (raw DER bytes, sans the outer
/// SEQUENCE header) looking for a single context-specific tag.  Returns
/// the element's value bytes (i.e. the content of the `[N] EXPLICIT …`
/// wrapper) if present, or `None` if absent or malformed.
///
/// AuthorizationList fields appear in increasing tag order, so once we
/// see a context-specific tag greater than the target we can stop
/// early.  Tags from other classes (shouldn't appear in
/// AuthorizationList at all, but if they do) are skipped without
/// disrupting the walk.
///
/// # Why this walker exists instead of using der::Header::decode
///
/// RustCrypto's `der` crate (as of version 0.7) cannot represent Android
/// KeyDescription's high-number tags at all. Its `TagNumber` type is
/// `pub struct TagNumber(u8)` — bounded to 255 — and its long-form
/// context-specific tag decoder (`0xBF` prefix path) additionally rejects
/// any byte above 0x7F (127) before even trying to construct a
/// multi-byte tag number. Anything like `[704]` produces a decode error,
/// not a decoded tag we could match on.
///
/// Android KeyDescription's hardwareEnforced AuthorizationList is full of
/// such high tags:
///
///   [303] rollbackResistance         [400] noAuthRequired
///   [503] creationDateTime           [504] origin
///   [701] creationPatchLevel         [702] osVersion
///   [703] osPatchLevel           ->  [704] rootOfTrust            <--
///   [709] attestationApplicationId   [710] attestationIdBrand
///   [713] attestationIdSerial        [714] attestationIdImei
///
/// Even if we only care about [704], we must walk past earlier high-tag
/// fields to reach it, and `der::Header::decode` will bail on the first
/// one it hits. Swapping to a newer `der` version doesn't necessarily
/// help — the crate has made little movement on multi-byte tag numbers
/// across releases, and even when it lands, it usually surfaces only as
/// a new `Tag::ContextSpecific` variant that callers have to adapt to.
///
/// So: this walker parses DER by hand at the class/tag-number/length
/// level just for the AuthorizationList body. Every other DER surface in
/// this crate (certificate parsing, outer KeyDescription SEQUENCE,
/// RootOfTrust inner SEQUENCE) still goes through the `der` crate,
/// because those only use low tag numbers that der handles correctly.
///
/// If you're reading this after bumping the `der` / `x509-cert`
/// dependency: re-check whether long-form context-specific tag numbers
/// above 127 are now first-class. If they are, this walker can be
/// replaced with `der::Header::decode` + pattern match on
/// `Tag::ContextSpecific { number, .. }`.
fn find_context_tag_body(body: &[u8], target_tag: u32) -> Option<&[u8]> {
    let mut rest = body;
    while !rest.is_empty() {
        let (tag_class, _constructed, tag_number, elem_body, remaining) =
            read_tlv(rest)?;
        if tag_class == TAG_CLASS_CONTEXT_SPECIFIC {
            if tag_number == target_tag {
                return Some(elem_body);
            }
            if tag_number > target_tag {
                // AuthorizationList is ordered; we've passed the target.
                return None;
            }
        }
        rest = remaining;
    }
    None
}

const TAG_CLASS_CONTEXT_SPECIFIC: u8 = 0b10;

/// Parse one DER TLV from `data`. Returns (tag class, constructed flag,
/// tag number, value bytes, remaining bytes).
///
/// Handles short-form and long-form tag encoding. Long-form tag numbers
/// use base-128 encoding where each byte's high bit signals continuation.
fn read_tlv(data: &[u8]) -> Option<(u8, bool, u32, &[u8], &[u8])> {
    if data.is_empty() {
        return None;
    }

    let first = data[0];
    let class = (first >> 6) & 0b11;
    let constructed = (first & 0b0010_0000) != 0;
    let low_tag = first & 0b0001_1111;

    let (tag_number, header_end): (u32, usize) = if low_tag != 0x1F {
        // Short form: tag number is 0..=30, fits in the low 5 bits.
        (low_tag as u32, 1)
    } else {
        // Long form: tag number follows as base-128 bytes. High bit set
        // means "more bytes follow"; cleared bit is the last byte.
        let mut number: u32 = 0;
        let mut i = 1usize;
        loop {
            if i >= data.len() {
                return None;
            }
            let b = data[i];
            // Guard against overflow — we only support tag numbers up to
            // ~2^24, well beyond anything in AuthorizationList.
            number = number.checked_shl(7)?;
            number |= (b & 0x7F) as u32;
            i += 1;
            if b & 0x80 == 0 {
                break;
            }
        }
        (number, i)
    };

    let (len_bytes, length) = parse_der_length(&data[header_end..])?;
    let body_start = header_end + len_bytes;
    let body_end = body_start.checked_add(length)?;
    if body_end > data.len() {
        return None;
    }

    Some((
        class,
        constructed,
        tag_number,
        &data[body_start..body_end],
        &data[body_end..],
    ))
}

/// Decode a DER length. Returns (bytes consumed, length value).
fn parse_der_length(bytes: &[u8]) -> Option<(usize, usize)> {
    if bytes.is_empty() {
        return None;
    }
    let first = bytes[0];
    if first & 0x80 == 0 {
        return Some((1, first as usize));
    }
    let n = (first & 0x7F) as usize;
    if n == 0 || n > 4 || bytes.len() < 1 + n {
        return None;
    }
    let mut len: usize = 0;
    for i in 0..n {
        len = (len << 8) | (bytes[1 + i] as usize);
    }
    Some((1 + n, len))
}

/// Parse a RootOfTrust SEQUENCE body (the EXPLICIT-tag content of [704]).
///
/// ```asn1
/// RootOfTrust ::= SEQUENCE {
///     verifiedBootKey       OCTET_STRING,
///     deviceLocked          BOOLEAN,
///     verifiedBootState     VerifiedBootState,
///     verifiedBootHash      OCTET_STRING,           -- not needed
/// }
/// ```
fn parse_root_of_trust(explicit_body: &[u8]) -> Option<(bool, VerifiedBootState)> {
    let mut wrapper = SliceReader::new(explicit_body).ok()?;

    let seq_header = der::Header::decode(&mut wrapper).ok()?;
    if seq_header.tag != Tag::Sequence {
        return None;
    }
    let seq_body = wrapper.read_slice(seq_header.length).ok()?;
    let mut r = SliceReader::new(seq_body).ok()?;

    // verifiedBootKey OCTET_STRING — skip.
    skip_tlv(&mut r)?;

    // deviceLocked BOOLEAN.
    let device_locked = read_boolean(&mut r)?;

    // verifiedBootState ENUMERATED.
    let vbs_byte = read_enumerated_u8(&mut r)?;
    let verified_boot_state = VerifiedBootState::from_u8(vbs_byte)?;

    Some((device_locked, verified_boot_state))
}

/// Parse the body of an `[709] EXPLICIT AttestationApplicationId`
/// element. Layout:
///
/// ```asn1
/// [709] EXPLICIT OCTET_STRING {
///     SEQUENCE {
///         SET OF AttestationPackageInfo { package_name OCTET_STRING,
///                                         version INTEGER },
///         SET OF OCTET_STRING  -- signature_digests
///     }
/// }
/// ```
///
/// Returns `(package_name, signing_cert_hash)` — either or both may be
/// `None` if the chain's AAID omits that sub-element or the encoded
/// forms are unexpected (wrong-sized digest, etc.). The caller decides
/// how to handle missing fields; this parser is best-effort so an
/// anomaly on one sub-element doesn't kill the other.
fn parse_attestation_application_id(
    explicit_body: &[u8],
) -> Option<(Option<Vec<u8>>, Option<[u8; 32]>)> {
    // [709] EXPLICIT wraps an OCTET STRING (the AAID field was added
    // late to the KeyMint schema, so it uses an encoded-bytes container
    // rather than appearing directly as a typed SEQUENCE).
    let mut wrapper = SliceReader::new(explicit_body).ok()?;
    let octet_header = der::Header::decode(&mut wrapper).ok()?;
    if octet_header.tag != Tag::OctetString {
        return None;
    }
    let octet_bytes = wrapper.read_slice(octet_header.length).ok()?;

    // The OCTET STRING's content is a DER-encoded SEQUENCE.
    let mut octet_reader = SliceReader::new(octet_bytes).ok()?;
    let seq_header = der::Header::decode(&mut octet_reader).ok()?;
    if seq_header.tag != Tag::Sequence {
        return None;
    }
    let seq_body = octet_reader.read_slice(seq_header.length).ok()?;

    let mut seq_reader = SliceReader::new(seq_body).ok()?;

    // First: SET OF AttestationPackageInfo.
    let pkg_set_header = der::Header::decode(&mut seq_reader).ok()?;
    if pkg_set_header.tag != Tag::Set {
        return None;
    }
    let pkg_set_body = seq_reader.read_slice(pkg_set_header.length).ok()?;
    let package_name = parse_first_package_info_name(pkg_set_body);

    // Second: SET OF OCTET STRING (signature_digests). Optional — some
    // AAID encodings in the wild omit this set entirely.
    let signing_cert_hash = match der::Header::decode(&mut seq_reader) {
        Ok(digest_set_header) if digest_set_header.tag == Tag::Set => {
            seq_reader
                .read_slice(digest_set_header.length)
                .ok()
                .and_then(parse_first_signature_digest_sha256)
        }
        _ => None,
    };

    Some((package_name, signing_cert_hash))
}

/// Extract the `package_name` from the first AttestationPackageInfo in
/// a SET OF. Returns `None` if the set is empty or the first element's
/// `package_name` field is missing or malformed.
fn parse_first_package_info_name(set_body: &[u8]) -> Option<Vec<u8>> {
    let mut reader = SliceReader::new(set_body).ok()?;
    let seq_header = der::Header::decode(&mut reader).ok()?;
    if seq_header.tag != Tag::Sequence {
        return None;
    }
    let seq_body = reader.read_slice(seq_header.length).ok()?;

    let mut seq_reader = SliceReader::new(seq_body).ok()?;
    let name_header = der::Header::decode(&mut seq_reader).ok()?;
    if name_header.tag != Tag::OctetString {
        return None;
    }
    let name_bytes = seq_reader.read_slice(name_header.length).ok()?;
    Some(name_bytes.to_vec())
}

/// Extract the first SHA-256 (32-byte OCTET STRING) from a SET OF. Any
/// non-32-byte digest or missing element returns `None` — the pallet
/// cross-check compares byte-for-byte against the integrity blob's
/// fixed-size `[u8; 32]`, so a different length cannot satisfy the
/// check anyway.
fn parse_first_signature_digest_sha256(set_body: &[u8]) -> Option<[u8; 32]> {
    let mut reader = SliceReader::new(set_body).ok()?;
    let octet_header = der::Header::decode(&mut reader).ok()?;
    if octet_header.tag != Tag::OctetString {
        return None;
    }
    let octet_bytes = reader.read_slice(octet_header.length).ok()?;
    if octet_bytes.len() != 32 {
        return None;
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(octet_bytes);
    Some(hash)
}

/// Read a DER BOOLEAN. DER encoding: 0xFF = true, 0x00 = false (strict).
/// BER is permissive; we follow DER here because attestation is DER-encoded.
fn read_boolean(r: &mut SliceReader<'_>) -> Option<bool> {
    let header = der::Header::decode(r).ok()?;
    if header.tag != Tag::Boolean {
        return None;
    }
    let bytes = r.read_slice(header.length).ok()?;
    if bytes.len() != 1 {
        return None;
    }
    match bytes[0] {
        0x00 => Some(false),
        0xFF => Some(true),
        _ => None,
    }
}

/// Read a single ENUMERATED value encoded as one byte and return it.
fn read_enumerated_u8(r: &mut SliceReader<'_>) -> Option<u8> {
    let header = der::Header::decode(r).ok()?;
    if header.tag != Tag::Enumerated {
        return None;
    }
    let bytes = r.read_slice(header.length).ok()?;
    if bytes.len() != 1 {
        return None;
    }
    Some(bytes[0])
}

/// Read an OCTET STRING and return its bytes as an owned Vec.
fn read_octet_string(r: &mut SliceReader<'_>) -> Option<Vec<u8>> {
    let header = der::Header::decode(r).ok()?;
    if header.tag != Tag::OctetString {
        return None;
    }
    let bytes = r.read_slice(header.length).ok()?;
    Some(bytes.to_vec())
}

/// Skip over a single TLV element (tag, length, value) without inspecting
/// the value.
fn skip_tlv(r: &mut SliceReader<'_>) -> Option<()> {
    let header = der::Header::decode(r).ok()?;
    r.read_slice(header.length).ok()?;
    Some(())
}
