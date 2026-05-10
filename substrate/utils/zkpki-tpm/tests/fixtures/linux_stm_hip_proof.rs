//! Linux STM dTPM HIP proof fixture
//! Captured from: Dell Latitude 7430 (work laptop, BIOS 1.37.0) via live-USB Ubuntu 24.04
//! TPM: STMicroelectronics dTPM, ManufacturerId "STM " (0x53544D20), revision 1.38
//! Platform: Linux 6.8.0-110-generic, tpm2-tools 5.7 via /dev/tpmrm0
//! Captured: 2026-04-23
//! Nonce: dbe8ea0867e5f488188a85e34242782033c0317f602a233d1b0d0858f740d516
//!
//! **Ceremony**: produced by `pki/tpm2-hip-probe/capture-linux.sh`
//! (tpm2-tools) and post-processed by the
//! `canonicalize-linux-capture` binary. The ceremony matches the
//! Windows probe's: ECC P-256 signing primary under Endorsement as
//! EK-equivalent + AIK (deterministic derivation — same bytes across
//! both keys, identical to the AMD fTPM fixture's pattern),
//! TPM2_Certify, TPM2_PCR_Read (SHA-256 bank, slots 0/1/4/7/11),
//! TPM2_Quote with the nonce in qualifyingData.
//!
//! **Signing domain**: `quote_attest` is the raw TPMS_ATTEST blob the
//! AIK signed via TPM2_Quote; the verifier checks `quote_signature`
//! over `SHA-256(quote_attest)` under the AIK. Inner pcrDigest +
//! extraData fields are pinned against the canonical proof's
//! redundant fields to catch probe-side tampering of the outer
//! struct.
//!
//! Platform tag on the proof is `HipPlatform::Tpm2Linux`. The
//! verifier dispatches both `Tpm2Windows` and `Tpm2Linux` to the same
//! internal TPM2 verifier — wire format is TCG-spec identical.

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
    [
        0xdb, 0xe8, 0xea, 0x08, 0x67, 0xe5, 0xf4, 0x88, 0x18, 0x8a, 0x85, 0xe3, 0x42, 0x42, 0x78,
        0x20, 0x33, 0xc0, 0x31, 0x7f, 0x60, 0x2a, 0x23, 0x3d, 0x1b, 0x0d, 0x08, 0x58, 0xf7, 0x40,
        0xd5, 0x16,
    ]
}

const CANONICAL_HIP_PROOF_HEX: &str = "00019d64feff1a6a1d77bb4b8349b8bb77510fc7030d3b486d3975fdf5304c499018050104def9d45c1eb989917d277549bee42c8f92a03d3d2bee357f0ee59f5d637e454034e484c474e8f585782f209d1255d1d1925a2ea3fb9708e0eea03113d2ba32b9050104def9d45c1eb989917d277549bee42c8f92a03d3d2bee357f0ee59f5d637e454034e484c474e8f585782f209d1255d1d1925a2ea3fb9708e0eea03113d2ba32b94502ff54434780170022000b240f16cce5f8ff09334e841ffca51002d27ac87ba6316186cdf80043941ec5be000400ff55aa0000000054162111000001a0000000000100010102000000000022000bac4ae902a23422bf2a81ad8b231b1e887bbda47745ba671f32bbca35afa7b5260022000b240f16cce5f8ff09334e841ffca51002d27ac87ba6316186cdf80043941ec5be1901304402201f5aaa8e60706a652066fdb77d4813a6c573f8488244a36a39420d270adc0a9702200f06114ab4716876f64b65537eccaf8bdb9489fd7e0da233135616a0768cf7a214008bf47188ef057302cf7ef47d2113115c3da0c0c20fe3dfc2663c1070a566d9f301df0d20e5069d0f686af8c78aa69fd7010c6695dee620a2ed01009b815c443a0a04d945e8ca048ec63f47ceaae2de4edced3d4eb449af14d29f4a40f976255720d8077156396ea068fd656ae2eba3a1d9685ac47678db2d04e2dd7c99c8add44e983f0b00000000000000000000000000000000000000000000000000000000000000001f476ca6945cb874499e241fc03e8a0c7bde52e09ef60033865b158633d19c134502ff54434780180022000b240f16cce5f8ff09334e841ffca51002d27ac87ba6316186cdf80043941ec5be0020dbe8ea0867e5f488188a85e34242782033c0317f602a233d1b0d0858f740d51600000000541622c8000001a00000000001000101020000000000000001000b0393080000201f476ca6945cb874499e241fc03e8a0c7bde52e09ef60033865b158633d19c131d013045022008e0296d15563c9cb5578b747e91554b24b8582b30560ee5ec02c4178f012c78022100b914399fb91001d9b3083b059f061a77139122e311aac793f62988f51c6d727bdbe8ea0867e5f488188a85e34242782033c0317f602a233d1b0d0858f740d516";
