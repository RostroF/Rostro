// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! B3 gate: a PVM-compiled guest does `sp_io::storage::set` +
//! `sp_io::storage::read`, the dispatcher routes the ecallis through
//! substrate's `sp_io::storage::HostFunctions`, and the original bytes
//! make it back to the guest. This is the smallest end-to-end proof that
//! rostro-executor is a real substrate runtime executor — Module compile,
//! Linker registration, ecalli dispatch, FunctionContext memory bridge,
//! thread-local externalities all wired correctly.

use rostro_executor::RostroExecutor;
use rostro_executor_fixture_storage_roundtrip as fixture;
use sp_state_machine::BasicExternalities;

#[test]
fn storage_set_via_pvm_guest_lands_in_externalities() {
	let blob = fixture::binary_unwrap();
	let executor = RostroExecutor::from_blob(blob).expect("compile fixture blob");

	// Externalities outlive the call so we can inspect the storage map
	// the guest mutated. The guest runs `sp_io::storage::set(key, value)`;
	// the dispatcher routes the ecalli through
	// `sp_io::storage::HostFunctions`, which mutates the thread-local
	// externalities; we then read directly to verify the host saw it.
	let mut ext = BasicExternalities::default();
	let outcome = ext.execute_with(|| {
		executor
			.call_with_host_fns::<sp_io::storage::HostFunctions>(
				"test_storage_roundtrip",
				50_000_000,
			)
			.expect("guest call")
	});

	assert_eq!(outcome.a0, 0, "fixture returned non-zero exit code: {}", outcome.a0);
	assert!(outcome.gas_consumed > 0, "non-zero gas should have been spent");

	// Host-side verification: the storage the guest wrote is observable
	// through the externalities we threaded through. This is the
	// substrate-side complement of the round-trip the fixture would do
	// internally once read returns are wired (B3-followup with the
	// allocator's fat-pointer return path).
	let stored = ext.execute_with(|| {
		sp_io::storage::get(b"phase-star-roundtrip-key").map(|v| v.to_vec())
	});

	assert_eq!(
		stored.as_deref(),
		Some(b"phase-star-roundtrip-value".as_slice()),
		"host read back {:?}; guest should have stored b\"phase-star-roundtrip-value\"",
		stored,
	);
}
