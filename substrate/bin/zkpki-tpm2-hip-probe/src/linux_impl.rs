//! Linux TPM 2.0 HIP proof probe — kernel resource manager path.
//!
//! Linux exposes the TPM as a character device. `/dev/tpmrm0` is the
//! kernel's in-band resource manager (always TPM 2.0; 1.2 devices do
//! not expose it). Sending a command is a single `write()`; the
//! response comes back on the next `read()`. No external C library
//! needed — the ceremony uses the same wire-format helpers as the
//! Windows TBS path.
//!
//! Emits `CanonicalHipProof` with `platform: HipPlatform::Tpm2Linux`.
//!
//! # Device access
//!
//! The user running this probe must be able to read/write
//! `/dev/tpmrm0`. On Ubuntu the device is owned by `root:tss` with
//! `660` permissions; the install guide adds the invoking user to the
//! `tss` group so `sudo` is not required.
//!
//! # Scope caveats
//!
//! - Resource manager only (`/dev/tpmrm0`). We do NOT fall back to
//!   `/dev/tpm0` (the raw device) because the raw device requires
//!   the caller to do its own session/object lifecycle — the
//!   resource manager handles transient handle eviction for us.
//! - No 1.2 fallback (`/dev/tpmrm0` doesn't exist on 1.2-only
//!   hardware; open() will fail clearly).

#![cfg(target_os = "linux")]

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use codec::Encode;
use frame_support::BoundedVec;
use zk_pki_primitives::hip::{CanonicalHipProof, HipPlatform, PcrValue};

use crate::tpm2_wire::{
    cmd_certify_body, cmd_create_primary_body, cmd_flush_context, cmd_pcr_read_body,
    cmd_quote_body, ecc_p256_signing_template, extract_ecc_pubkey_sec1,
    extract_quote_pcr_digest, parse_attest_and_signature, parse_create_primary_response,
    parse_pcr_read_response, wrap, TpmResponse, TPM_CC_CERTIFY, TPM_CC_CREATE_PRIMARY,
    TPM_CC_PCR_READ, TPM_CC_QUOTE, TPM_RH_ENDORSEMENT, TPM_ST_NO_SESSIONS, TPM_ST_SESSIONS,
};

const PCR_INDICES: &[u8] = &[0, 1, 4, 7, 11];
const TPM_RM_DEVICE: &str = "/dev/tpmrm0";
/// Response buffer — MAX_RESPONSE_SIZE from Linux TPM driver is 4096
/// bytes. Matches the Windows TBS path for consistency.
const TPM_RESPONSE_BUF: usize = 4096;

/// Character-device transport. One open file per ceremony. Commands
/// are written as a single `write()`; the driver expects the entire
/// command in one syscall and rejects partial writes with EIO. The
/// response comes back on the next `read()` into a buffer sized to
/// `MAX_RESPONSE_SIZE` (4096).
pub struct LinuxTpm(File);

impl LinuxTpm {
    pub fn open() -> Result<Self, String> {
        if !Path::new(TPM_RM_DEVICE).exists() {
            return Err(format!(
                "{} not present — is TPM 2.0 enabled in BIOS/UEFI and the tpm_crb/tpm_tis driver loaded?",
                TPM_RM_DEVICE,
            ));
        }
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(TPM_RM_DEVICE)
            .map_err(|e| {
                format!(
                    "open({}) failed: {} — is the invoking user in the `tss` group?",
                    TPM_RM_DEVICE, e,
                )
            })?;
        Ok(Self(f))
    }

    pub fn submit(&mut self, cmd: &[u8]) -> Result<Vec<u8>, String> {
        // One write() per command — the driver accepts the entire
        // buffer atomically or errors out. A short write on this
        // device is a bug signal, not something to retry.
        self.0
            .write_all(cmd)
            .map_err(|e| format!("write({}) failed: {}", TPM_RM_DEVICE, e))?;
        let mut out = vec![0u8; TPM_RESPONSE_BUF];
        let n = self
            .0
            .read(&mut out)
            .map_err(|e| format!("read({}) failed: {}", TPM_RM_DEVICE, e))?;
        out.truncate(n);
        Ok(out)
    }
}

pub fn run_ceremony(nonce: [u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
    let mut tpm = LinuxTpm::open().map_err(to_err)?;

    // --- 1. Create EK-equivalent signing key under Endorsement ------
    let ek_template = ecc_p256_signing_template();
    let ek_cmd = wrap(
        TPM_ST_SESSIONS,
        TPM_CC_CREATE_PRIMARY,
        &cmd_create_primary_body(TPM_RH_ENDORSEMENT, &ek_template),
    );
    let ek_resp_raw = tpm.submit(&ek_cmd).map_err(to_err)?;
    let ek_resp = TpmResponse::parse(&ek_resp_raw).map_err(to_err)?;
    let ek_body = ek_resp.expect_ok().map_err(to_err)?;
    let (ek_handle, ek_public_blob) = parse_create_primary_response(ek_body).map_err(to_err)?;
    let ek_pub_sec1 = extract_ecc_pubkey_sec1(&ek_public_blob).map_err(to_err)?;

    // --- 2. Create AIK under Endorsement ----------------------------
    let aik_template = ecc_p256_signing_template();
    let aik_cmd = wrap(
        TPM_ST_SESSIONS,
        TPM_CC_CREATE_PRIMARY,
        &cmd_create_primary_body(TPM_RH_ENDORSEMENT, &aik_template),
    );
    let aik_resp_raw = tpm.submit(&aik_cmd).map_err(to_err)?;
    let aik_resp = TpmResponse::parse(&aik_resp_raw).map_err(to_err)?;
    let aik_body = aik_resp.expect_ok().map_err(to_err)?;
    let (aik_handle, aik_public_blob) =
        parse_create_primary_response(aik_body).map_err(to_err)?;
    let aik_pub_sec1 = extract_ecc_pubkey_sec1(&aik_public_blob).map_err(to_err)?;

    // --- 3. Certify AIK with EK-equivalent --------------------------
    let certify_cmd = wrap(
        TPM_ST_SESSIONS,
        TPM_CC_CERTIFY,
        &cmd_certify_body(aik_handle, ek_handle, &[]),
    );
    let certify_resp_raw = tpm.submit(&certify_cmd).map_err(to_err)?;
    let certify_resp = TpmResponse::parse(&certify_resp_raw).map_err(to_err)?;
    let certify_body = certify_resp.expect_ok().map_err(to_err)?;
    let (aik_certify_info, aik_certify_sig, _) =
        parse_attest_and_signature(certify_body).map_err(to_err)?;

    // --- 4. PCR_Read ------------------------------------------------
    let pcr_cmd = wrap(
        TPM_ST_NO_SESSIONS,
        TPM_CC_PCR_READ,
        &cmd_pcr_read_body(PCR_INDICES),
    );
    let pcr_resp_raw = tpm.submit(&pcr_cmd).map_err(to_err)?;
    let pcr_resp = TpmResponse::parse(&pcr_resp_raw).map_err(to_err)?;
    let pcr_body = pcr_resp.expect_ok().map_err(to_err)?;
    let pcr_digests = parse_pcr_read_response(pcr_body).map_err(to_err)?;

    let mut pcr_values_vec = Vec::with_capacity(PCR_INDICES.len());
    for (i, digest) in PCR_INDICES.iter().zip(pcr_digests.iter()) {
        if digest.len() != 32 {
            return Err(format!(
                "PCR {} digest length {} (expected 32)",
                i,
                digest.len()
            )
            .into());
        }
        let mut v = [0u8; 32];
        v.copy_from_slice(digest);
        pcr_values_vec.push(PcrValue { index: *i, value: v });
    }
    let pcr_values: BoundedVec<PcrValue, frame_support::traits::ConstU32<16>> =
        BoundedVec::try_from(pcr_values_vec).map_err(|_| "pcr values > 16")?;

    // --- 5. Quote ---------------------------------------------------
    let quote_cmd = wrap(
        TPM_ST_SESSIONS,
        TPM_CC_QUOTE,
        &cmd_quote_body(aik_handle, &nonce, PCR_INDICES),
    );
    let quote_resp_raw = tpm.submit(&quote_cmd).map_err(to_err)?;
    let quote_resp = TpmResponse::parse(&quote_resp_raw).map_err(to_err)?;
    let quote_body = quote_resp.expect_ok().map_err(to_err)?;
    let (quote_attest, quote_sig, _) = parse_attest_and_signature(quote_body).map_err(to_err)?;
    let pcr_digest = extract_quote_pcr_digest(&quote_attest).map_err(to_err)?;

    // --- 6. Flush the two transient handles. ------------------------
    let _ = tpm.submit(&cmd_flush_context(aik_handle));
    let _ = tpm.submit(&cmd_flush_context(ek_handle));

    // --- 7. Build + emit CanonicalHipProof --------------------------
    let ek_hash = sp_io::hashing::blake2_256(&ek_pub_sec1);
    let proof = CanonicalHipProof {
        platform: HipPlatform::Tpm2Linux,
        ek_hash,
        ek_public: BoundedVec::try_from(ek_pub_sec1).map_err(|_| "ek_pub >128")?,
        aik_public: BoundedVec::try_from(aik_pub_sec1).map_err(|_| "aik_pub >128")?,
        aik_certify_info: BoundedVec::try_from(aik_certify_info)
            .map_err(|_| "aik_certify_info >512")?,
        aik_certify_signature: BoundedVec::try_from(aik_certify_sig)
            .map_err(|_| "aik_certify_sig >256")?,
        pcr_values,
        pcr_digest,
        quote_attest: BoundedVec::try_from(quote_attest)
            .map_err(|_| "quote_attest >512 — grow ConstU32 bound in primitives/hip.rs if real TPMs overflow")?,
        quote_signature: BoundedVec::try_from(quote_sig).map_err(|_| "quote_sig >256")?,
        nonce,
    };

    let encoded = proof.encode();
    println!("=== CANONICAL_HIP_PROOF_SCALE_HEX ===");
    println!("{}", hex::encode(&encoded));
    println!("=== END ===");
    Ok(())
}

fn to_err(s: String) -> Box<dyn std::error::Error> {
    Box::from(s)
}
