// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

fn main() {
	// This fixture is only useful as a PVM blob — force the riscv target
	// regardless of what the workspace was invoked with so `cargo test
	// -p rostro-executor` always gets a PVM build to load.
	std::env::set_var("SUBSTRATE_RUNTIME_TARGET", "riscv");

	#[cfg(feature = "std")]
	{
		substrate_wasm_builder::WasmBuilder::new()
			.with_current_project()
			.export_heap_base()
			.import_memory()
			.disable_runtime_version_section_check()
			.build();
	}
}
