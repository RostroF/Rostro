//! Hand-rolled TPM2 wire-format construction + TBS transport.
//!
//! Kept deliberately minimal — just enough to send the four commands
//! the HIP ceremony needs (`CreatePrimary`, `Certify`, `PCR_Read`,
//! `Quote`) and parse their responses into the fields the canonical
//! proof needs.
//!
//! Reference: TCG Trusted Platform Module Library — Part 2 (Structures)
//! and Part 3 (Commands), TPM 2.0 rev 1.59 or later.

#![cfg(target_os = "windows")]

use std::ffi::c_void;
use windows::Win32::System::TpmBaseServices::{
    Tbsi_Context_Create, Tbsi_GetDeviceInfo, Tbsip_Context_Close, Tbsip_Submit_Command,
    TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL, TBS_CONTEXT_PARAMS,
    TBS_CONTEXT_PARAMS2, TBS_CONTEXT_PARAMS2_0, TPM_DEVICE_INFO,
};

// ──────────────────────────────────────────────────────────────────────
// Constants from TCG Part 2 / Part 3
// ──────────────────────────────────────────────────────────────────────

pub const TPM_ST_NO_SESSIONS: u16 = 0x8001;
pub const TPM_ST_SESSIONS: u16 = 0x8002;

pub const TPM_RS_PW: u32 = 0x4000_0009;
pub const TPM_RH_ENDORSEMENT: u32 = 0x4000_000B;

pub const TPM_CC_CREATE_PRIMARY: u32 = 0x0000_0131;
pub const TPM_CC_CERTIFY: u32 = 0x0000_0148;
pub const TPM_CC_QUOTE: u32 = 0x0000_0158;
pub const TPM_CC_PCR_READ: u32 = 0x0000_017E;
pub const TPM_CC_FLUSH_CONTEXT: u32 = 0x0000_0165;

// Algorithm identifiers
pub const TPM_ALG_RSA: u16 = 0x0001;
pub const TPM_ALG_SHA256: u16 = 0x000B;
pub const TPM_ALG_NULL: u16 = 0x0010;
pub const TPM_ALG_ECDSA: u16 = 0x0018;
pub const TPM_ALG_ECC: u16 = 0x0023;

// ECC curve IDs
pub const TPM_ECC_NIST_P256: u16 = 0x0003;

// TPMA_OBJECT attribute bits
pub const TPMA_FIXED_TPM: u32 = 1 << 1;
pub const TPMA_FIXED_PARENT: u32 = 1 << 4;
pub const TPMA_SENSITIVE_DATA_ORIGIN: u32 = 1 << 5;
pub const TPMA_USER_WITH_AUTH: u32 = 1 << 6;
pub const TPMA_RESTRICTED: u32 = 1 << 16;
pub const TPMA_SIGN: u32 = 1 << 18;

// ──────────────────────────────────────────────────────────────────────
// TBS transport
// ──────────────────────────────────────────────────────────────────────

/// Wrapper around the raw TBS context handle. windows-rs doesn't
/// export a dedicated `TBS_HCONTEXT` type — the native header
/// `typedef HANDLE TBS_HCONTEXT` surfaces as `*mut c_void` on both
/// sides of the FFI. We keep ours as the pointer directly.
pub struct TbsContext(*mut c_void);

impl TbsContext {
    pub fn open() -> Result<Self, String> {
        // TBS_CONTEXT_PARAMS2 — version=2 plus the includeTpm20 bit
        // (bit 2 of the bitfield union). Construction of a union is
        // safe in Rust; only reading fields is unsafe.
        let params = TBS_CONTEXT_PARAMS2 {
            version: 2,
            Anonymous: TBS_CONTEXT_PARAMS2_0 { asUINT32: 1 << 2 },
        };
        let mut handle: *mut c_void = std::ptr::null_mut();
        // SAFETY: FFI to a Windows system DLL. `params` is valid for
        // the duration of the call; `handle` gets initialised only
        // if the call returns 0 (TBS_SUCCESS). The cast from a
        // `TBS_CONTEXT_PARAMS2` pointer to `*const TBS_CONTEXT_PARAMS`
        // (v1) is how `tbs.h` intends this — v2 is a layout-compatible
        // superset and the DLL reads `version` first to dispatch.
        let rc = unsafe {
            Tbsi_Context_Create(
                &params as *const TBS_CONTEXT_PARAMS2 as *const TBS_CONTEXT_PARAMS,
                &mut handle as *mut *mut c_void,
            )
        };
        if rc != 0 {
            return Err(format!("Tbsi_Context_Create failed: 0x{:08X}", rc));
        }
        Ok(Self(handle))
    }

    /// Sanity check — confirms we're talking to a TPM 2.0 device.
    /// Returns Err if the local TPM is 1.2 or absent entirely.
    pub fn require_tpm20(&self) -> Result<(), String> {
        let mut info = TPM_DEVICE_INFO {
            structVersion: 0,
            tpmVersion: 0,
            tpmInterfaceType: 0,
            tpmImpRevision: 0,
        };
        let rc = unsafe {
            Tbsi_GetDeviceInfo(
                std::mem::size_of::<TPM_DEVICE_INFO>() as u32,
                &mut info as *mut _ as *mut c_void,
            )
        };
        if rc != 0 {
            return Err(format!("Tbsi_GetDeviceInfo failed: 0x{:08X}", rc));
        }
        if info.tpmVersion != 2 {
            return Err(format!("TPM version is {} — need 2", info.tpmVersion));
        }
        Ok(())
    }

    pub fn submit(&self, cmd: &[u8]) -> Result<Vec<u8>, String> {
        let mut out = vec![0u8; 4096];
        let mut out_len: u32 = out.len() as u32;
        // SAFETY: FFI to a Windows system DLL. `cmd` is a live slice
        // for the duration of the call; `out` and `out_len` are
        // written only on rc == 0. Handle `self.0` is non-null
        // because `Self` can only be constructed via `open()` which
        // gates on a successful `Tbsi_Context_Create`.
        let rc = unsafe {
            Tbsip_Submit_Command(
                self.0,
                TBS_COMMAND_LOCALITY_ZERO,
                TBS_COMMAND_PRIORITY_NORMAL,
                cmd,
                out.as_mut_ptr(),
                &mut out_len as *mut u32,
            )
        };
        if rc != 0 {
            return Err(format!("Tbsip_Submit_Command failed: 0x{:08X}", rc));
        }
        out.truncate(out_len as usize);
        Ok(out)
    }
}

impl Drop for TbsContext {
    fn drop(&mut self) {
        // SAFETY: handle owned by this `TbsContext` and not closed
        // elsewhere; the call is idempotent on a valid handle.
        unsafe {
            let _ = Tbsip_Context_Close(self.0);
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// Little helpers for big-endian wire serialisation
// ──────────────────────────────────────────────────────────────────────

pub fn push_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_be_bytes());
}
pub fn push_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}
pub fn push_bytes(buf: &mut Vec<u8>, b: &[u8]) {
    buf.extend_from_slice(b);
}
pub fn push_sized_u16(buf: &mut Vec<u8>, inner: &[u8]) {
    push_u16(buf, inner.len() as u16);
    push_bytes(buf, inner);
}

// ──────────────────────────────────────────────────────────────────────
// Wire construction — commands
// ──────────────────────────────────────────────────────────────────────

/// Build a complete TPM2 command buffer: wrap tag + size + code +
/// body. `body` already contains handles, auth area, and parameters
/// in wire order; this function prepends the 10-byte header.
pub fn wrap(tag: u16, command_code: u32, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(10 + body.len());
    push_u16(&mut out, tag);
    push_u32(&mut out, (10 + body.len()) as u32);
    push_u32(&mut out, command_code);
    push_bytes(&mut out, body);
    out
}

/// Build a single password-session auth area with an empty password.
/// Returns the wire bytes for the TPMS_AUTH_COMMAND (including the
/// leading authorizationSize u32 for the whole auth area).
pub fn auth_empty_password() -> Vec<u8> {
    // One auth entry: handle (4) + nonceSize (2) + attrs (1) + hmacSize (2) = 9 bytes.
    let mut entry = Vec::with_capacity(9);
    push_u32(&mut entry, TPM_RS_PW);
    push_u16(&mut entry, 0); // nonce size
    entry.push(1); // attributes: continueSession
    push_u16(&mut entry, 0); // hmac size
    let mut out = Vec::with_capacity(4 + entry.len());
    push_u32(&mut out, entry.len() as u32);
    push_bytes(&mut out, &entry);
    out
}

/// ECC P-256 *signing* primary template. Fixed-TPM + fixed-parent so
/// it chains to the hierarchy seed (deterministically regenerable).
/// Attrs: restricted | sign | sensitiveDataOrigin | userWithAuth |
/// fixedTPM | fixedParent.
///
/// The `auth_policy` is empty (no policy), matching Windows's default
/// endorsement hierarchy posture. If the local TPM's endorsement
/// auth policy is set (rare on consumer Windows), this template
/// would need a TPM2_PolicySecret session — out of scope here.
pub fn ecc_p256_signing_template() -> Vec<u8> {
    let mut tpl = Vec::new();
    push_u16(&mut tpl, TPM_ALG_ECC); // type
    push_u16(&mut tpl, TPM_ALG_SHA256); // nameAlg
    let attrs = TPMA_FIXED_TPM
        | TPMA_FIXED_PARENT
        | TPMA_SENSITIVE_DATA_ORIGIN
        | TPMA_USER_WITH_AUTH
        | TPMA_RESTRICTED
        | TPMA_SIGN;
    push_u32(&mut tpl, attrs);
    push_u16(&mut tpl, 0); // authPolicy (empty)

    // TPMS_ECC_PARMS:
    //   symmetric: TPMT_SYM_DEF_OBJECT — NULL (no symmetric)
    //   scheme:    TPMT_ECC_SCHEME — ECDSA(SHA-256)
    //   curveID:   TPM_ECC_NIST_P256
    //   kdf:       TPMT_KDF_SCHEME — NULL
    push_u16(&mut tpl, TPM_ALG_NULL); // symmetric.algorithm
    push_u16(&mut tpl, TPM_ALG_ECDSA); // scheme.scheme
    push_u16(&mut tpl, TPM_ALG_SHA256); // scheme.details.hashAlg
    push_u16(&mut tpl, TPM_ECC_NIST_P256); // curveID
    push_u16(&mut tpl, TPM_ALG_NULL); // kdf.scheme

    // unique: TPMS_ECC_POINT — empty (TPM fills in during CreatePrimary)
    push_u16(&mut tpl, 0); // x size
    push_u16(&mut tpl, 0); // y size

    // Wrap in TPM2B_PUBLIC (size-prefixed).
    let mut out = Vec::with_capacity(tpl.len() + 2);
    push_sized_u16(&mut out, &tpl);
    out
}

/// Build a CreatePrimary command body for the given hierarchy and
/// public template. `sensitive_user_auth` is the userAuth for the
/// new object — pass empty bytes for "no password".
pub fn cmd_create_primary_body(
    hierarchy: u32,
    inner_public: &[u8], // already TPM2B_PUBLIC-wrapped
) -> Vec<u8> {
    let mut body = Vec::new();
    push_u32(&mut body, hierarchy); // authHandle
    body.extend_from_slice(&auth_empty_password()); // auth area

    // inSensitive: TPM2B_SENSITIVE_CREATE — empty userAuth + empty data
    let mut sensitive = Vec::new();
    push_u16(&mut sensitive, 0); // userAuth size
    push_u16(&mut sensitive, 0); // data size
    push_sized_u16(&mut body, &sensitive);

    // inPublic — already TPM2B_PUBLIC
    push_bytes(&mut body, inner_public);

    // outsideInfo: empty TPM2B_DATA
    push_u16(&mut body, 0);

    // creationPCR: empty TPML_PCR_SELECTION
    push_u32(&mut body, 0);

    body
}

/// PCR_Read command body — selects SHA-256 bank with the supplied
/// PCR indices. `indices` must all be < 24.
pub fn cmd_pcr_read_body(indices: &[u8]) -> Vec<u8> {
    let mut bitmap = [0u8; 3];
    for i in indices {
        assert!(*i < 24, "PCR index must be <24");
        bitmap[(*i / 8) as usize] |= 1 << (*i % 8);
    }
    let mut body = Vec::new();
    push_u32(&mut body, 1); // count: one selection
    push_u16(&mut body, TPM_ALG_SHA256);
    body.push(3); // sizeofSelect
    body.extend_from_slice(&bitmap);
    body
}

/// Certify command body. `object_handle` is the key being certified
/// (AIK). `sign_handle` is the key that signs (EK-equivalent signing
/// key). Uses ECDSA-SHA256 scheme.
pub fn cmd_certify_body(
    object_handle: u32,
    sign_handle: u32,
    qualifying_data: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    push_u32(&mut body, object_handle);
    push_u32(&mut body, sign_handle);

    // Two auth sessions, one per handle. Each empty-password PW
    // session. Concatenate entries; authorizationSize wraps the lot.
    let mut auth = Vec::new();
    // Entry 1
    push_u32(&mut auth, TPM_RS_PW);
    push_u16(&mut auth, 0);
    auth.push(1);
    push_u16(&mut auth, 0);
    // Entry 2
    push_u32(&mut auth, TPM_RS_PW);
    push_u16(&mut auth, 0);
    auth.push(1);
    push_u16(&mut auth, 0);
    push_u32(&mut body, auth.len() as u32);
    body.extend_from_slice(&auth);

    // qualifyingData: TPM2B_DATA
    push_sized_u16(&mut body, qualifying_data);

    // inScheme: TPMT_SIG_SCHEME — ECDSA(SHA-256)
    push_u16(&mut body, TPM_ALG_ECDSA);
    push_u16(&mut body, TPM_ALG_SHA256);

    body
}

/// Quote command body — signs the quote with `sign_handle` (the AIK).
pub fn cmd_quote_body(sign_handle: u32, qualifying_data: &[u8], pcr_indices: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    push_u32(&mut body, sign_handle);
    body.extend_from_slice(&auth_empty_password());

    push_sized_u16(&mut body, qualifying_data);

    // inScheme: ECDSA(SHA-256)
    push_u16(&mut body, TPM_ALG_ECDSA);
    push_u16(&mut body, TPM_ALG_SHA256);

    // PCRselect: TPML_PCR_SELECTION (same shape as PCR_Read)
    let mut bitmap = [0u8; 3];
    for i in pcr_indices {
        bitmap[(*i / 8) as usize] |= 1 << (*i % 8);
    }
    push_u32(&mut body, 1);
    push_u16(&mut body, TPM_ALG_SHA256);
    body.push(3);
    body.extend_from_slice(&bitmap);

    body
}

/// FlushContext — drop a transient handle from the TPM so we don't
/// leak across invocations.
pub fn cmd_flush_context(handle: u32) -> Vec<u8> {
    let mut body = Vec::new();
    push_u32(&mut body, handle);
    wrap(TPM_ST_NO_SESSIONS, TPM_CC_FLUSH_CONTEXT, &body)
}

// ──────────────────────────────────────────────────────────────────────
// Response parsing
// ──────────────────────────────────────────────────────────────────────

pub struct TpmResponse<'a> {
    pub rc: u32,
    pub body: &'a [u8],
}

impl<'a> TpmResponse<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, String> {
        if bytes.len() < 10 {
            return Err(format!("response too short: {} bytes", bytes.len()));
        }
        let rc = u32::from_be_bytes(bytes[6..10].try_into().unwrap());
        Ok(Self { rc, body: &bytes[10..] })
    }
    pub fn expect_ok(&self) -> Result<&[u8], String> {
        if self.rc != 0 {
            return Err(format!("TPM returned rc=0x{:08X}", self.rc));
        }
        Ok(self.body)
    }
}

/// Read a big-endian u16 at `pos`, advancing it. Returns the value.
pub fn read_u16(bytes: &[u8], pos: &mut usize) -> Result<u16, String> {
    if bytes.len() < *pos + 2 {
        return Err("buffer underrun reading u16".into());
    }
    let v = u16::from_be_bytes(bytes[*pos..*pos + 2].try_into().unwrap());
    *pos += 2;
    Ok(v)
}

pub fn read_u32(bytes: &[u8], pos: &mut usize) -> Result<u32, String> {
    if bytes.len() < *pos + 4 {
        return Err("buffer underrun reading u32".into());
    }
    let v = u32::from_be_bytes(bytes[*pos..*pos + 4].try_into().unwrap());
    *pos += 4;
    Ok(v)
}

pub fn read_sized_u16<'a>(bytes: &'a [u8], pos: &mut usize) -> Result<&'a [u8], String> {
    let size = read_u16(bytes, pos)? as usize;
    if bytes.len() < *pos + size {
        return Err("buffer underrun reading sized field".into());
    }
    let slice = &bytes[*pos..*pos + size];
    *pos += size;
    Ok(slice)
}

/// Parse a TPM2B_PUBLIC response blob into (name, ecc_x, ecc_y).
/// The response format from CreatePrimary has an outer TPM2B_PUBLIC
/// wrapping a TPMT_PUBLIC.
pub fn extract_ecc_pubkey_sec1(tpm2b_public: &[u8]) -> Result<Vec<u8>, String> {
    let mut p = 0usize;
    // outer TPM2B_PUBLIC size
    let inner = read_sized_u16(tpm2b_public, &mut p)?;
    // Inside TPMT_PUBLIC:
    //   type (u16), nameAlg (u16), objectAttributes (u32),
    //   authPolicy (TPM2B), parameters (TPMS_ECC_PARMS: 10 bytes
    //   for sym/scheme/curve/kdf), unique (TPMS_ECC_POINT: TPM2B x,
    //   TPM2B y).
    let mut q = 0usize;
    let ty = read_u16(inner, &mut q)?;
    if ty != TPM_ALG_ECC {
        return Err(format!("expected ECC public key, got type 0x{:04X}", ty));
    }
    let _name_alg = read_u16(inner, &mut q)?;
    let _attrs = read_u32(inner, &mut q)?;
    let _auth_policy = read_sized_u16(inner, &mut q)?;
    // parameters — sym_alg u16 + scheme u16 + scheme.hash u16 + curveID u16 + kdf u16 = 10
    q += 10;
    let x = read_sized_u16(inner, &mut q)?.to_vec();
    let y = read_sized_u16(inner, &mut q)?.to_vec();

    // SEC1 uncompressed: 0x04 || X || Y, padded to 32 each.
    let mut out = Vec::with_capacity(1 + 64);
    out.push(0x04);
    pad_big_endian(&mut out, &x, 32);
    pad_big_endian(&mut out, &y, 32);
    Ok(out)
}

fn pad_big_endian(out: &mut Vec<u8>, v: &[u8], len: usize) {
    if v.len() < len {
        out.extend(std::iter::repeat(0u8).take(len - v.len()));
    }
    // If longer than `len`, trim leading zeros (TPM may emit one
    // leading zero to avoid a high-bit negative interpretation in
    // some encodings — not standard for raw ECC points, but guard
    // anyway).
    let trimmed = if v.len() > len { &v[v.len() - len..] } else { v };
    out.extend_from_slice(trimmed);
}

/// Parse a CreatePrimary response. Layout:
///   objectHandle (u32)
///   parameterSize (u32)  ← only present if command used sessions
///   outPublic (TPM2B_PUBLIC)
///   creationData (TPM2B_CREATION_DATA)
///   creationHash (TPM2B_DIGEST)
///   creationTicket (TPMT_TK_CREATION)
///   name (TPM2B_NAME)
///   auth area
pub fn parse_create_primary_response(body: &[u8]) -> Result<(u32, Vec<u8>), String> {
    let mut p = 0usize;
    let handle = read_u32(body, &mut p)?;
    // Session-based responses prefix the params with a parameterSize u32.
    let _param_size = read_u32(body, &mut p)?;
    // Capture TPM2B_PUBLIC start so we can hand the full wrapped blob
    // to `extract_ecc_pubkey_sec1` (which expects outer TPM2B wrapper).
    let pub_start = p;
    let size = read_u16(body, &mut p)? as usize;
    p += size;
    let pub_blob = body[pub_start..p].to_vec();
    Ok((handle, pub_blob))
}

/// Parse a Certify / Quote response (same shape):
///   parameterSize (u32)
///   certifyInfo / attest (TPM2B_ATTEST)
///   signature (TPMT_SIGNATURE)
pub fn parse_attest_and_signature(body: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
    let mut p = 0usize;
    let _param_size = read_u32(body, &mut p)?;
    let attest = read_sized_u16(body, &mut p)?.to_vec();

    // TPMT_SIGNATURE: sigAlg (u16) then TPMS_SIGNATURE_ECC
    // (TPMS_SIGNATURE_ECC = hash (u16), signatureR (TPM2B_ECC_PARAMETER),
    //  signatureS (TPM2B_ECC_PARAMETER))
    let sig_alg = read_u16(body, &mut p)?;
    if sig_alg != TPM_ALG_ECDSA {
        return Err(format!("expected ECDSA sig, got 0x{:04X}", sig_alg));
    }
    let _hash_alg = read_u16(body, &mut p)?;
    let r = read_sized_u16(body, &mut p)?.to_vec();
    let s = read_sized_u16(body, &mut p)?.to_vec();

    let der = der_encode_ecdsa(&r, &s);
    Ok((attest, der.clone(), der))
}

/// DER-encode (r, s) as an ECDSA Signature ASN.1 SEQUENCE.
pub fn der_encode_ecdsa(r: &[u8], s: &[u8]) -> Vec<u8> {
    fn der_int(v: &[u8]) -> Vec<u8> {
        let mut trimmed = v;
        while trimmed.len() > 1 && trimmed[0] == 0 {
            trimmed = &trimmed[1..];
        }
        let mut body = Vec::with_capacity(trimmed.len() + 1);
        if !trimmed.is_empty() && trimmed[0] & 0x80 != 0 {
            body.push(0x00);
        }
        body.extend_from_slice(trimmed);
        let mut out = Vec::with_capacity(body.len() + 2);
        out.push(0x02);
        out.push(body.len() as u8);
        out.extend_from_slice(&body);
        out
    }
    let r_der = der_int(r);
    let s_der = der_int(s);
    let mut inner = Vec::with_capacity(r_der.len() + s_der.len());
    inner.extend_from_slice(&r_der);
    inner.extend_from_slice(&s_der);
    let mut out = Vec::with_capacity(inner.len() + 2);
    out.push(0x30);
    out.push(inner.len() as u8);
    out.extend_from_slice(&inner);
    out
}

/// Parse a PCR_Read response. Layout:
///   pcrUpdateCounter (u32)
///   pcrSelectionOut (TPML_PCR_SELECTION)
///   pcrValues (TPML_DIGEST: count u32, then count × TPM2B_DIGEST)
pub fn parse_pcr_read_response(body: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let mut p = 0usize;
    let _update_counter = read_u32(body, &mut p)?;
    // Skip pcrSelectionOut — same layout as input, count=1, one
    // selection of 3 bytes bitmap + 2-byte alg + 1-byte size = 1 u32 + 6 bytes.
    let sel_count = read_u32(body, &mut p)?;
    for _ in 0..sel_count {
        let _alg = read_u16(body, &mut p)?;
        if body.len() < p + 1 {
            return Err("bad selection size".into());
        }
        let sel_size = body[p] as usize;
        p += 1 + sel_size;
    }
    let digest_count = read_u32(body, &mut p)? as usize;
    let mut out = Vec::with_capacity(digest_count);
    for _ in 0..digest_count {
        let d = read_sized_u16(body, &mut p)?.to_vec();
        out.push(d);
    }
    Ok(out)
}

/// Extract the PCR digest from the TPMS_QUOTE_INFO embedded in a
/// TPMS_ATTEST's attested union. TPMS_ATTEST layout:
///   magic (u32)
///   type (u16)  ← should be TPM_ST_ATTEST_QUOTE 0x8018
///   qualifiedSigner (TPM2B_NAME)
///   extraData (TPM2B_DATA)
///   clockInfo (TPMS_CLOCK_INFO = 17 bytes)
///   firmwareVersion (u64)
///   attested (TPMU_ATTEST — for quote: TPMS_QUOTE_INFO)
///     TPMS_QUOTE_INFO:
///       pcrSelect (TPML_PCR_SELECTION)
///       pcrDigest (TPM2B_DIGEST)
pub fn extract_quote_pcr_digest(attest: &[u8]) -> Result<[u8; 32], String> {
    let mut p = 0usize;
    let _magic = read_u32(attest, &mut p)?;
    let _type = read_u16(attest, &mut p)?;
    let _qualified_signer = read_sized_u16(attest, &mut p)?;
    let _extra_data = read_sized_u16(attest, &mut p)?;
    // clockInfo 17 bytes + firmwareVersion 8 bytes = 25 bytes
    if attest.len() < p + 25 {
        return Err("attest truncated before clockInfo/firmwareVersion".into());
    }
    p += 25;
    // pcrSelect
    let sel_count = read_u32(attest, &mut p)?;
    for _ in 0..sel_count {
        let _alg = read_u16(attest, &mut p)?;
        let sel_size = *attest.get(p).ok_or("bad sel")? as usize;
        p += 1 + sel_size;
    }
    // pcrDigest
    let digest = read_sized_u16(attest, &mut p)?;
    if digest.len() != 32 {
        return Err(format!("pcr digest size {} != 32", digest.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(digest);
    Ok(out)
}
