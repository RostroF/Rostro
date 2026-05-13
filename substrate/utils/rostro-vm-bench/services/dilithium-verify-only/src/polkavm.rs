// ML-DSA-65 keygen+sign+verify keeps polynomial buffers + matrix A on the
// stack (fips204 is heap-free by design). One full cycle wants ~256 KB.
// Default polkavm stack is too small and the guest traps on stack overflow.
polkavm_derive::min_stack_size!(512 * 1024);

#[polkavm_derive::polkavm_import]
extern "C" {
    // Tier 2 H2 intrinsic — ML-DSA-65 verify, dispatched inline by the RostroVM
    // runtime. Index 110 matches `ROSTRO_INTRINSIC_DILITHIUM_VERIFY` in
    // substrate/external/rostrovm/polkavm/src/interpreter.rs. ABI:
    //   A0 = pubkey_ptr  (1952 bytes — fips204::ml_dsa_65::PK_LEN)
    //   A1 = msg_ptr
    //   A2 = msg_len
    //   A3 = sig_ptr     (3309 bytes — fips204::ml_dsa_65::SIG_LEN)
    //   A4 = ctx_ptr
    //   A5 = ctx_len
    //   returns u32: 1 = verified, 0 = failed
    #[polkavm_import(index = 110)]
    pub fn rostro_dilithium_verify(
        pk: u32,
        msg: u32,
        msg_len: u32,
        sig: u32,
        ctx: u32,
        ctx_len: u32,
    ) -> u32;
}

#[polkavm_derive::polkavm_export]
#[no_mangle]
pub extern "C" fn dilithium_verify_bench() -> u32 {
    crate::dilithium_verify_bench()
}
