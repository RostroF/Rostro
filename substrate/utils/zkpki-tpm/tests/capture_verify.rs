//! Ad-hoc harness — verify a REAL device attestation chain captured off hardware
//! against the production pins (Google roots + KNOWN_MANUFACTURER_INTERMEDIATES).
//!
//! Point `CAPTURE_CHAIN` at a file of hex-encoded DER certs, leaf FIRST, one per line
//! (blank lines and `#` comments ignored):
//!
//!   CAPTURE_CHAIN=/tmp/r5cn_chain.txt \
//!     cargo test -p zk-pki-tpm --test capture_verify -- --nocapture
//!
//! Prints PASS or the exact failing gate, and — for every cert — its subject +
//! blake2_256(SPKI) pin. If the device's manufacturer intermediate isn't whitelisted
//! (`UnknownManufacturer`), the printed intermediate pin is the value to drop into
//! `KNOWN_MANUFACTURER_INTERMEDIATES` (fail-forward).

use x509_cert::{
    der::{Decode, Encode},
    Certificate,
};
use zk_pki_tpm::verify_chain;

fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn verify_captured_chain() {
    let path = match std::env::var("CAPTURE_CHAIN") {
        Ok(p) => p,
        Err(_) => {
            eprintln!("CAPTURE_CHAIN not set — nothing to verify (this harness is manual).");
            return;
        }
    };
    let raw = std::fs::read_to_string(&path).expect("read CAPTURE_CHAIN file");
    let chain: Vec<Vec<u8>> = raw
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(unhex)
        .filter(|b| !b.is_empty())
        .collect();

    println!("\n=== captured chain: {} cert(s) (leaf first) ===", chain.len());
    for (i, der) in chain.iter().enumerate() {
        match Certificate::from_der(der) {
            Ok(c) => {
                let spki = c
                    .tbs_certificate
                    .subject_public_key_info
                    .to_der()
                    .expect("spki der");
                let pin = sp_io::hashing::blake2_256(&spki);
                let role = if i == 0 {
                    "leaf"
                } else if i == chain.len() - 1 {
                    "ROOT"
                } else {
                    "intermediate"
                };
                println!(
                    "  [{i}] {role:12} pin={}  subj={}",
                    hex_lower(&pin),
                    c.tbs_certificate.subject
                );
            }
            Err(e) => println!("  [{i}] UNPARSEABLE: {e}"),
        }
    }

    match verify_chain(&chain) {
        Ok(()) => println!(
            "\n>>> PASS — this device chains to a pinned Google root AND carries a known \
             manufacturer intermediate. It verifies against the strict verifier.\n"
        ),
        Err(e) => println!(
            "\n>>> REJECTED: {e:?}\n    (RootPinMismatch -> add the ROOT pin above; \
             UnknownManufacturer -> add the intermediate pin above to \
             KNOWN_MANUFACTURER_INTERMEDIATES; SignatureVerifyFailed/UnsupportedSignatureAlgorithm \
             -> chain/crypto issue.)\n"
        ),
    }
}

fn hex_lower(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
