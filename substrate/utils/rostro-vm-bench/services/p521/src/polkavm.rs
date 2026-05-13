#[polkavm_derive::polkavm_export]
#[no_mangle]
pub extern "C" fn p521_verify_bench() -> u32 {
	crate::p521_verify_bench()
}
