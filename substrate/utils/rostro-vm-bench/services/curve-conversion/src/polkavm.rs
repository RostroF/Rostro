#[polkavm_derive::polkavm_export]
#[no_mangle]
pub extern "C" fn curve_conversion_bench() -> u32 {
	crate::curve_conversion_bench()
}
