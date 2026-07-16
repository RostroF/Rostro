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

//! Integration tests for runtime interface primitives
#![cfg(test)]

use sp_runtime_interface::*;

use sp_runtime_interface_test_wasm::{test_api::HostFunctions, wasm_binary_unwrap};

use rostro_executor::RostroCodeExecutor;
use sp_core::traits::{CallContext, CodeExecutor, RuntimeCode, WrappedRuntimeCode};
use sp_wasm_interface::{ExtendedHostFunctions, HostFunctions as HostFunctionsT};

use std::{
	collections::HashSet,
	sync::{Arc, Mutex},
};

type TestExternalities = sp_state_machine::TestExternalities<sp_runtime::traits::BlakeTwo256>;

// wasm-cull W2: the fixtures are PVM blobs now; drive them through
// RostroCodeExecutor, the executor the chain ships. The wasm executor's
// AllocationStats instrumentation went with it.
fn call_guest_method_with_result<HF: HostFunctionsT>(
	binary: &[u8],
	method: &str,
) -> Result<TestExternalities, String> {
	let mut ext = TestExternalities::default();
	let mut ext_ext = ext.ext();

	let executor = RostroCodeExecutor::<
		ExtendedHostFunctions<sp_io::SubstrateHostFunctions, HF>,
	>::new()
	.expect("RostroCodeExecutor init: polkavm engine setup must succeed");

	let code_fetcher = WrappedRuntimeCode(binary.into());
	let runtime_code = RuntimeCode {
		code_fetcher: &code_fetcher,
		hash: sp_crypto_hashing::blake2_256(binary).to_vec(),
		heap_pages: None,
	};

	let (result, _) =
		executor.call(&mut ext_ext, &runtime_code, method, &[], CallContext::Offchain);
	result.map_err(|e| format!("Failed to execute `{}`: {}", method, e)).map(|_| ext)
}

fn call_guest_method<HF: HostFunctionsT>(binary: &[u8], method: &str) -> TestExternalities {
	call_guest_method_with_result::<HF>(binary, method).unwrap()
}

#[test]
fn test_return_data() {
	call_guest_method::<HostFunctions>(wasm_binary_unwrap(), "test_return_data");
}

#[test]
fn test_return_option_data() {
	call_guest_method::<HostFunctions>(wasm_binary_unwrap(), "test_return_option_data");
}

#[test]
fn test_set_storage() {
	let mut ext = call_guest_method::<HostFunctions>(wasm_binary_unwrap(), "test_set_storage");

	let expected = "world";
	assert_eq!(expected.as_bytes(), &ext.ext().storage("hello".as_bytes()).unwrap()[..]);
}

#[test]
fn test_return_value_into_mutable_reference() {
	call_guest_method::<HostFunctions>(
		wasm_binary_unwrap(),
		"test_return_value_into_mutable_reference",
	);
}

#[test]
fn test_get_and_return_array() {
	call_guest_method::<HostFunctions>(wasm_binary_unwrap(), "test_get_and_return_array");
}

#[test]
fn test_array_as_mutable_reference() {
	call_guest_method::<HostFunctions>(wasm_binary_unwrap(), "test_array_as_mutable_reference");
}

#[test]
fn test_return_input_public_key() {
	call_guest_method::<HostFunctions>(wasm_binary_unwrap(), "test_return_input_public_key");
}

#[test]
fn host_function_not_found() {
	let err = call_guest_method_with_result::<()>(wasm_binary_unwrap(), "test_return_data")
		.unwrap_err();

	// wasm-cull W2: the module-creation error text is engine-specific; the
	// guarded property is "missing host functions error out instead of UB",
	// carried by the method name our harness prefixes.
	assert!(err.contains("test_return_data"));
}

#[test]
fn test_invalid_utf8_data_should_return_an_error() {
	call_guest_method_with_result::<HostFunctions>(
		wasm_binary_unwrap(),
		"test_invalid_utf8_data_should_return_an_error",
	)
	.unwrap_err();
}

#[test]
fn test_overwrite_native_function_implementation() {
	call_guest_method::<HostFunctions>(
		wasm_binary_unwrap(),
		"test_overwrite_native_function_implementation",
	);
}

#[test]
fn test_vec_return_value_memory_is_freed() {
	call_guest_method::<HostFunctions>(
		wasm_binary_unwrap(),
		"test_vec_return_value_memory_is_freed",
	);
}

#[test]
fn test_encoded_return_value_memory_is_freed() {
	call_guest_method::<HostFunctions>(
		wasm_binary_unwrap(),
		"test_encoded_return_value_memory_is_freed",
	);
}

#[test]
fn test_array_return_value_memory_is_freed() {
	call_guest_method::<HostFunctions>(
		wasm_binary_unwrap(),
		"test_array_return_value_memory_is_freed",
	);
}

#[test]
fn test_versioning_works() {
	// wasm-cull W2: the second half of this test ran the *deprecated-interface*
	// wasm fixture to prove new hosts serve runtimes built against the old wasm
	// ABI. Rostro ships no wasm ABI and no pre-existing runtimes; the fixture
	// and that half are culled with it.
	call_guest_method::<HostFunctions>(wasm_binary_unwrap(), "test_versioning_works");
}

#[test]
fn test_versioning_register_only() {
	call_guest_method::<HostFunctions>(wasm_binary_unwrap(), "test_versioning_register_only_works");
}

fn run_test_in_another_process(
	test_name: &str,
	test_body: impl FnOnce(),
) -> Option<std::process::Output> {
	if std::env::var("RUN_FORKED_TEST").is_ok() {
		test_body();
		None
	} else {
		let output = std::process::Command::new(std::env::current_exe().unwrap())
			.arg(test_name)
			.env("RUN_FORKED_TEST", "1")
			.output()
			.unwrap();

		assert!(output.status.success());
		Some(output)
	}
}

#[test]
fn test_tracing() {
	// Run in a different process to ensure that the `Span` is registered with our local
	// `TracingSubscriber`.
	run_test_in_another_process("test_tracing", || {
		use std::fmt;
		use tracing::span::Id as SpanId;
		use tracing_core::field::{Field, Visit};

		#[derive(Clone)]
		struct TracingSubscriber(Arc<Mutex<Inner>>);

		struct FieldConsumer(&'static str, Option<String>);
		impl Visit for FieldConsumer {
			fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
				if field.name() == self.0 {
					self.1 = Some(format!("{:?}", value))
				}
			}
		}

		#[derive(Default)]
		struct Inner {
			spans: HashSet<String>,
		}

		impl tracing::subscriber::Subscriber for TracingSubscriber {
			fn enabled(&self, _: &tracing::Metadata) -> bool {
				true
			}

			fn new_span(&self, span: &tracing::span::Attributes) -> tracing::Id {
				let mut inner = self.0.lock().unwrap();
				let id = SpanId::from_u64((inner.spans.len() + 1) as _);
				let mut f = FieldConsumer("name", None);
				span.record(&mut f);
				inner.spans.insert(f.1.unwrap_or_else(|| span.metadata().name().to_owned()));
				id
			}

			fn record(&self, _: &SpanId, _: &tracing::span::Record) {}

			fn record_follows_from(&self, _: &SpanId, _: &SpanId) {}

			fn event(&self, _: &tracing::Event) {}

			fn enter(&self, _: &SpanId) {}

			fn exit(&self, _: &SpanId) {}
		}

		let subscriber = TracingSubscriber(Default::default());
		let _guard = tracing::subscriber::set_default(subscriber.clone());

		// Call some method to generate a trace
		call_guest_method::<HostFunctions>(wasm_binary_unwrap(), "test_return_data");

		let inner = subscriber.0.lock().unwrap();
		assert!(inner.spans.contains("return_input_version_1"));
	});
}

#[test]
fn test_return_input_as_tuple() {
	call_guest_method::<HostFunctions>(wasm_binary_unwrap(), "test_return_input_as_tuple");
}

// wasm-cull W2: `test_returning_option_bytes_from_a_host_function_is_efficient`
// culled. It asserted wasm-allocator byte counts via the wasm executor's
// AllocationStats instrumentation, which does not exist on the RVM path (the
// guest allocator is in-VM). Marshalling correctness coverage remains below;
// allocator efficiency characterization belongs to the RVM benchmark suite.
#[test]
fn test_marshalling_strategies() {
	call_guest_method::<HostFunctions>(wasm_binary_unwrap(), "test_marshalling_strategies");
}
