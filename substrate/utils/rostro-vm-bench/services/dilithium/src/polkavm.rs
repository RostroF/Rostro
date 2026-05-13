// ML-DSA-65 keygen+sign+verify keeps polynomial buffers + matrix A on the
// stack (fips204 is heap-free by design). One full cycle wants ~256 KB.
// Default polkavm stack is too small and the guest traps on stack overflow.
polkavm_derive::min_stack_size!(512 * 1024);

#[polkavm_derive::polkavm_export]
#[no_mangle]
pub extern "C" fn dilithium_verify_bench() -> u32 {
	crate::dilithium_verify_bench()
}
