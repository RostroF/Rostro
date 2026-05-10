//! High-level ceremony built on top of `tpm2_wire`.
//!
//! Driven from [`main::run`]. Produces a `CanonicalHipProof`,
//! SCALE-encodes it, and prints the hex.

#![cfg(target_os = "windows")]

use crate::tpm2_wire::{
    cmd_certify_body, cmd_create_primary_body, cmd_flush_context, cmd_pcr_read_body,
    cmd_quote_body, ecc_p256_signing_template, extract_ecc_pubkey_sec1,
    extract_quote_pcr_digest, parse_attest_and_signature, parse_create_primary_response,
    parse_pcr_read_response, wrap, TbsContext, TpmResponse, TPM_CC_CERTIFY,
    TPM_CC_CREATE_PRIMARY, TPM_CC_PCR_READ, TPM_CC_QUOTE, TPM_RH_ENDORSEMENT,
    TPM_ST_NO_SESSIONS, TPM_ST_SESSIONS,
};
use codec::Encode;
use frame_support::BoundedVec;
use zk_pki_primitives::hip::{CanonicalHipProof, HipPlatform, PcrValue};

const PCR_INDICES: &[u8] = &[0, 1, 4, 7, 11];

pub fn run_ceremony(nonce: [u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = TbsContext::open().map_err(to_err)?;
    ctx.require_tpm20().map_err(to_err)?;

    // --- 1. Create EK-equivalent signing key under Endorsement ------
    let ek_template = ecc_p256_signing_template();
    let ek_cmd = wrap(
        TPM_ST_SESSIONS,
        TPM_CC_CREATE_PRIMARY,
        &cmd_create_primary_body(TPM_RH_ENDORSEMENT, &ek_template),
    );
    let ek_resp_raw = ctx.submit(&ek_cmd).map_err(to_err)?;
    let ek_resp = TpmResponse::parse(&ek_resp_raw).map_err(to_err)?;
    let ek_body = ek_resp.expect_ok().map_err(to_err)?;
    let (ek_handle, ek_public_blob) = parse_create_primary_response(ek_body).map_err(to_err)?;
    let ek_pub_sec1 = extract_ecc_pubkey_sec1(&ek_public_blob).map_err(to_err)?;

    // --- 2. Create AIK under Endorsement ---------------------------
    let aik_template = ecc_p256_signing_template();
    let aik_cmd = wrap(
        TPM_ST_SESSIONS,
        TPM_CC_CREATE_PRIMARY,
        &cmd_create_primary_body(TPM_RH_ENDORSEMENT, &aik_template),
    );
    let aik_resp_raw = ctx.submit(&aik_cmd).map_err(to_err)?;
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
    let certify_resp_raw = ctx.submit(&certify_cmd).map_err(to_err)?;
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
    let pcr_resp_raw = ctx.submit(&pcr_cmd).map_err(to_err)?;
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
    let quote_resp_raw = ctx.submit(&quote_cmd).map_err(to_err)?;
    let quote_resp = TpmResponse::parse(&quote_resp_raw).map_err(to_err)?;
    let quote_body = quote_resp.expect_ok().map_err(to_err)?;
    // `quote_attest` is the raw TPMS_ATTEST blob. The TPM signed
    // SHA-256 of these bytes under the AIK — the verifier runs the
    // same SHA-256 + verify_prehash path and pins the inner
    // pcrDigest / extraData fields against the redundant
    // `pcr_digest` / `nonce` fields on the canonical proof.
    let (quote_attest, quote_sig, _) = parse_attest_and_signature(quote_body).map_err(to_err)?;
    let pcr_digest = extract_quote_pcr_digest(&quote_attest).map_err(to_err)?;

    // --- 6. Flush the two transient handles. ------------------------
    let _ = ctx.submit(&cmd_flush_context(aik_handle));
    let _ = ctx.submit(&cmd_flush_context(ek_handle));

    // --- 7. Build + emit CanonicalHipProof --------------------------
    let ek_hash = sp_io::hashing::blake2_256(&ek_pub_sec1);
    let proof = CanonicalHipProof {
        platform: HipPlatform::Tpm2Windows,
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
