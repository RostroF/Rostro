// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation
//
// Phase 3 (2026-05-15): polkavm variant routes through the Rostro Tier 2
// signature-verify precompile (ROSTRO_INTRINSIC_ED25519_VERIFY = 122). Host's
// FAST_OP_ECALLI dispatch intercepts the ecalli and runs RFC 8032 Ed25519
// verify natively. javm + wasm32 variants continue to run the pure-Rust
// ed25519-compact crate compiled to their respective bytecodes — they
// remain the control group for the comparison.

#[polkavm_derive::polkavm_import]
extern "C" {
    // ABI: pk_ptr (32B), sig_ptr (64B), msg_ptr, msg_len.
    // Returns 1 if verified, 0 otherwise.
    #[polkavm_import(index = 122)]
    fn rostro_ed25519_verify(pk_ptr: *const u8, sig_ptr: *const u8, msg_ptr: *const u8, msg_len: u32) -> u32;
}

#[polkavm_derive::polkavm_export]
#[no_mangle]
pub extern "C" fn ed25519_verify_bench() -> u32 {
    unsafe {
        rostro_ed25519_verify(
            crate::PUBLIC_KEY_BYTES.as_ptr(),
            crate::SIGNATURE_BYTES.as_ptr(),
            crate::MESSAGE.as_ptr(),
            crate::MESSAGE.len() as u32,
        )
    }
}
