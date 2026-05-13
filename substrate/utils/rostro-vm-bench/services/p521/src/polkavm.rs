#[polkavm_derive::polkavm_import]
extern "C" {
	// Tier 2 H2 intrinsic — P521 ECDSA verify (prehashed). Index 111 matches
	// `ROSTRO_INTRINSIC_P521_ECDSA_VERIFY` in interpreter.rs. ABI:
	//   A0 = vk_ptr      (133B: 0x04 || X(66) || Y(66) uncompressed sec1)
	//   A1 = sig_ptr     (132B: r(66) || s(66))
	//   A2 = prehash_ptr
	//   A3 = prehash_len
	// returns u32: 1 = verified, 0 = failed
	#[polkavm_import(index = 111)]
	pub fn rostro_p521_ecdsa_verify(
		vk: u32,
		sig: u32,
		prehash: u32,
		prehash_len: u32,
	) -> u32;
}

#[polkavm_derive::polkavm_export]
#[no_mangle]
pub extern "C" fn p521_verify_bench() -> u32 {
	crate::p521_verify_bench()
}
