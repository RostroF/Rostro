//! Windows AMD fTPM HIP proof fixture
//! Captured from: Lucy (AMD Ryzen laptop, Win11)
//! TPM: AMD firmware TPM, ManufacturerId 0x414D4400, version 3.55.0.5
//! Platform: Windows 11, TBS API via windows-rs 0.58
//! Captured: 2026-04-18 (second capture; corrected signing domain)
//! Nonce: 0101010101010101010101010101010101010101010101010101010101010101
//!
//! **Signing domain:** `quote_attest` is now included in the SCALE
//! payload. The verifier checks `quote_signature` over
//! `SHA-256(quote_attest)` under the AIK — this is what the TPM
//! actually signs via `TPM2_Quote` (a restricted AIK cannot sign a
//! caller-synthesized commitment; only TPM-generated TPMS_ATTEST).
//! The earlier capture used a synthetic-commitment verifier design
//! that real hardware couldn't satisfy and has been replaced.
//!
//! Note: ek_public is an endorsement-hierarchy primary P-256 signing key,
//! not the AMD EK cert key captured earlier. Same hardware trust root
//! (endorsement hierarchy) but different key material. HIP uses
//! AIK-to-AIK comparison across proofs — this is semantically correct.

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

pub fn canonical_hip_proof_bytes() -> Vec<u8> {
    hex_to_bytes(CANONICAL_HIP_PROOF_HEX)
}

pub fn genesis_nonce() -> [u8; 32] {
    [0x01u8; 32]
}

const CANONICAL_HIP_PROOF_HEX: &str = "0000e8273a9b8900347202e1540b3ec5a29c8679a61b0fc11cf7514174bcd5e3b937050104ae4b501bdf8a57123a85d77c9c1812111f9bedcf8dd9ad3e435aae110ef90e3765e7f0dec2c00993e3bba1d49d0140d072a85c0b629006434ad1826be1e9b25d050104ae4b501bdf8a57123a85d77c9c1812111f9bedcf8dd9ad3e435aae110ef90e3765e7f0dec2c00993e3bba1d49d0140d072a85c0b629006434ad1826be1e9b25d3502ff54434780170022000b9488e8786a7e5a6cb0e9dd967171246481caa6e025c43935c7172620250ee5b50000000000013580baaa000000a3000000020100030037000000050022000bd874f0e608ca855fb6f0031bb82c589357f5c5ed13dc9787a2acd9b0ae91f96f0022000b9488e8786a7e5a6cb0e9dd967171246481caa6e025c43935c7172620250ee5b51d013045022100cdd48f8a2afc33e0dde468e46b1403c1b2de800cce13ee76e6d9af92f5f2093e02206c4d0fbc7d8d02ed9e2107cb932e1acf8767c83a4d530e94d0b00ca7213068dc1400be4456370d3d3659b38d2e5abb8d34b327b7bd6cfc59a002b8d444c68280d16101d21f8359fdfe02b254582dd0b730b17dace03a1900fc739e8cb0cf10b59358b30448b5f3681dc26e7ad98dee2110de3d10aafd17614ab885a98e39046daea3e5990719a56856165cc8712965604cba8c5b264c2cbc1e8a9c3736ac187182cbc7139a0b0fe6e8f2110d5d53935c9e7d6f6bf722598b550595aabdc6e4fd2ecdf310f980bee90503f0bb82f9b40589c1a183bcc3e98b349245c9839d1885d16a5cfa33894502ff54434780180022000b9488e8786a7e5a6cb0e9dd967171246481caa6e025c43935c7172620250ee5b500200101010101010101010101010101010101010101010101010101010101010101000000013580baaa000000a30000000201000300370000000500000001000b039308000020bee90503f0bb82f9b40589c1a183bcc3e98b349245c9839d1885d16a5cfa338921013046022100fddbfb232615b147a06073f013586ad6018754417a5c262c3ae850b460632a580221008bfd27a4538aa46603bf5de05879b0a6e8aff721d87df1b29c1badc3caec7ce00101010101010101010101010101010101010101010101010101010101010101";
