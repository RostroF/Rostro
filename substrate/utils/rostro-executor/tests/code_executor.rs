// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! B6 gate: `RostroCodeExecutor` runs real substrate runtime APIs.
//!
//! Calls `Core_version` on the actual `rostro-runtime` PVM blob via the
//! `ReadRuntimeVersion` / `CodeExecutor` trait surface, decodes the
//! SCALE-encoded result, and asserts the metadata matches what the
//! runtime declares (`spec_name = "rostro"`, etc).
//!
//! `#[ignore]`-gated for the same reason as B5: requires
//! `SUBSTRATE_RUNTIME_TARGET=riscv` at build time so
//! `rostro_runtime::WASM_BINARY` holds a PVM blob.

use codec::Decode;
use rostro_executor::RostroCodeExecutor;
use sp_core::traits::ReadRuntimeVersion;
use sp_state_machine::BasicExternalities;
use sp_version::RuntimeVersion;

fn is_pvm_blob(bytes: &[u8]) -> bool {
	bytes.starts_with(b"PVM\0")
}

#[test]
#[ignore = "requires SUBSTRATE_RUNTIME_TARGET=riscv to build rostro-runtime as PVM"]
fn rostro_code_executor_reads_rostro_runtime_version() {
	let blob = rostro_runtime::WASM_BINARY.expect(
		"rostro-runtime WASM_BINARY missing — rebuild with SUBSTRATE_RUNTIME_TARGET=riscv",
	);
	assert!(is_pvm_blob(blob), "rostro-runtime blob is not PVM format");

	let executor =
		RostroCodeExecutor::<sp_io::SubstrateHostFunctions>::new().expect("construct executor");

	let mut ext = BasicExternalities::default();
	let raw = executor.read_runtime_version(blob, &mut ext).expect("Core_version call");

	let version = RuntimeVersion::decode(&mut &raw[..])
		.expect("decode RuntimeVersion from Core_version's SCALE return");

	assert_eq!(
		version.spec_name.as_ref(),
		"rostro",
		"expected spec_name = \"rostro\", got {:?}",
		version.spec_name
	);
	assert!(
		version.spec_version > 0,
		"spec_version should be non-zero, got {}",
		version.spec_version
	);
	assert!(
		!version.apis.is_empty(),
		"rostro-runtime should declare at least one runtime API"
	);
}
