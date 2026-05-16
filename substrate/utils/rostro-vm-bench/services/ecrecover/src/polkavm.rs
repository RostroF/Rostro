// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation
//
// Phase 3 (2026-05-15): polkavm variant routes through ROSTRO_INTRINSIC_
// SECP256K1_RECOVER (= 123). Host's FAST_OP_ECALLI dispatch intercepts the
// ecalli and runs the recovery natively. javm + wasm32 variants keep their
// k256-in-bytecode path as the control group.

#[polkavm_derive::polkavm_import]
extern "C" {
    // ABI: msg_hash_ptr (32B), sig_ptr (65B: r||s||v), out_pk_ptr (64B
    // output buffer for uncompressed X||Y). Returns 1 on success, 0 fail.
    #[polkavm_import(index = 123)]
    fn rostro_secp256k1_recover(hash_ptr: *const u8, sig_ptr: *const u8, out_ptr: *mut u8) -> u32;
}

#[polkavm_derive::polkavm_export]
#[no_mangle]
pub extern "C" fn ecrecover_bench() -> u32 {
    // Build the 65-byte (r || s || v) input.
    let mut sig65 = [0u8; 65];
    sig65[..64].copy_from_slice(&crate::SIGNATURE);
    sig65[64] = crate::RECOVERY_ID;
    let mut out_pk = [0u8; 64];
    unsafe {
        rostro_secp256k1_recover(
            crate::MSG_HASH.as_ptr(),
            sig65.as_ptr(),
            out_pk.as_mut_ptr(),
        )
    }
}
