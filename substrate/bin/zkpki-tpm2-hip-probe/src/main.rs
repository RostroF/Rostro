//! Windows TPM 2.0 HIP proof probe.
//!
//! Runs on Windows against the real TPM via TBS (TPM Base Services).
//! No external C library — the `windows` crate gives us pure-Rust FFI
//! to the system DLLs that ship with Windows 10/11. Produces a
//! `CanonicalHipProof` and prints it SCALE-encoded as hex.
//!
//! # Ceremony
//!
//! 1. Create a TBS context.
//! 2. Create a PRIMARY signing key under the Endorsement hierarchy —
//!    this is the "EK-equivalent" used to certify the AIK. Real EKs
//!    are encryption-only; for AIK↔hardware binding we need a signing
//!    key fixed to the endorsement hierarchy. Both approaches pin the
//!    attesting hardware to its TCG-identity root.
//! 3. Create the AIK — restricted ECC P-256 signing key, also under
//!    the Endorsement hierarchy.
//! 4. `TPM2_Certify` the AIK using the EK-equivalent. Produces
//!    `aik_certify_info` (TPMS_ATTEST) + `aik_certify_signature`.
//! 5. `TPM2_PCR_Read` the SHA-256 bank for slots 0, 1, 4, 7, 11.
//! 6. `TPM2_Quote` over the same PCR selection with the caller-
//!    supplied nonce in qualifyingData. Produces the attest blob
//!    (whose attested portion is the PCR digest) + quote signature.
//! 7. Emit `CanonicalHipProof` as SCALE hex.
//!
//! Because TBS lets us send raw TPM2 command buffers, this binary
//! hand-rolls the wire format per TCG Spec Part 3. That's ~300 lines
//! of byte manipulation but avoids the tpm2-tss C dependency.
//!
//! # Scope caveats
//!
//! - Only Windows. Linux/WSL uses a stub that exits 1 with a pointer
//!   to `pki/WINDOWS_TPM_EK_EXTRACTION.md`.
//! - First-run debugging will likely be needed: the TPM2 wire format
//!   is unforgiving and TBS returns raw TPM2 responses, so any wire-
//!   format mistake surfaces as a `TPM_RC_*` numeric code. The
//!   `tpm2_wire::TpmResponse::rc` helper makes these easy to read.

#[cfg(target_os = "windows")]
mod tpm2_wire;
#[cfg(target_os = "windows")]
mod windows_impl;

use clap::Parser;

#[derive(Parser)]
#[command(
    name = "tpm2-hip-probe",
    about = "Emit a CanonicalHipProof from a local Windows TPM 2.0 device"
)]
struct Cli {
    /// 32-byte nonce, hex-encoded (64 hex chars). Gets embedded into
    /// the quote's `qualifyingData` field. The caller (pallet,
    /// relying party, dotwave) supplies this to bind the quote to a
    /// specific request.
    #[arg(long)]
    nonce: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let nonce_bytes = hex::decode(&cli.nonce)?;
    if nonce_bytes.len() != 32 {
        eprintln!(
            "nonce must be 32 bytes (64 hex chars); got {} bytes",
            nonce_bytes.len()
        );
        std::process::exit(2);
    }
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&nonce_bytes);
    run(nonce)
}

#[cfg(target_os = "windows")]
fn run(nonce: [u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
    windows_impl::run_ceremony(nonce)
}

#[cfg(not(target_os = "windows"))]
fn run(_nonce: [u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!(
        "tpm2-hip-probe is Windows-only. This build target ({}) does \n\
         not compile the TBS ceremony. See \n\
         pki/WINDOWS_TPM_EK_EXTRACTION.md for the Windows path.",
        std::env::consts::OS,
    );
    std::process::exit(1);
}
