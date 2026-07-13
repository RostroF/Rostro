// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

fn main() {
	// wasm-cull W1: this runtime is only useful as a PVM blob — force the
	// riscv target regardless of what the workspace was invoked with, same
	// as the rostro-executor storage-roundtrip fixture. The wasm32 build
	// (and its metadata-hash step, which executed the blob through the
	// removed WasmExecutor) is gone; RostroCodeExecutor is the only
	// consumer.
	std::env::set_var("SUBSTRATE_RUNTIME_TARGET", "riscv");

	#[cfg(feature = "std")]
	{
		substrate_wasm_builder::WasmBuilder::new()
			.with_current_project()
			.export_heap_base()
			.import_memory()
			.build();
	}

	#[cfg(feature = "std")]
	{
		substrate_wasm_builder::WasmBuilder::new()
			.with_current_project()
			.export_heap_base()
			.import_memory()
			.set_file_name("wasm_binary_logging_disabled.rs")
			.enable_feature("disable-logging")
			.build();
	}

	// wasm-cull W2: runtime-upgrade tests need a blob whose `Core_version`
	// reports a bumped spec_version; the wasm-era section-surgery
	// (`sp_version::embed`) cannot produce one for PVM blobs.
	#[cfg(feature = "std")]
	{
		substrate_wasm_builder::WasmBuilder::new()
			.with_current_project()
			.export_heap_base()
			.import_memory()
			.set_file_name("wasm_binary_spec_version_incremented.rs")
			.enable_feature("increment-spec-version")
			.build();
	}
}
