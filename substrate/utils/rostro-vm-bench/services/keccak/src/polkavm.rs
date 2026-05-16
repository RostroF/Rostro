// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation
//
// Phase 1 (2026-05-14): polkavm variant routes through the Rostro Tier 2
// hashing intrinsic (ROSTRO_INTRINSIC_KECCAK_256 = 121). Host's FAST_OP_ECALLI
// dispatch intercepts the ecalli and runs native Keccak on the message.
// javm + wasm32 variants continue to run pure-Rust sha3::Keccak256 — they
// remain the control group for the comparison.

#[polkavm_derive::polkavm_import]
extern "C" {
    // ABI: msg_ptr, msg_len, out_ptr (32-byte output buffer).
    // Returns 0 on success, 1 on memory-access failure.
    #[polkavm_import(index = 121)]
    fn rostro_keccak_256(msg_ptr: *const u8, msg_len: u32, out_ptr: *mut u8) -> u32;
}

#[polkavm_derive::polkavm_export]
#[no_mangle]
pub extern "C" fn keccak_bench() -> u32 {
    const MSG_LEN: usize = 1024;
    let mut msg = [0u8; MSG_LEN];
    let mut i: usize = 0;
    while i < MSG_LEN {
        msg[i] = (i & 0xFF) as u8;
        i += 1;
    }
    let mut out = [0u8; 32];
    unsafe {
        rostro_keccak_256(msg.as_ptr(), MSG_LEN as u32, out.as_mut_ptr());
    }
    u32::from_le_bytes([out[0], out[1], out[2], out[3]])
}
