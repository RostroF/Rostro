// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! A/B benchmark harness for PVM-family VMs on Rostro-shop-shaped workloads.
//!
//! Phase 3b deliverable for VM research: provides apples-to-apples timing
//! and memory measurements across Wei Tang's `javm` and Parity's `polkavm`
//! crate on workloads matching the Rostro shop sidecar's expected shape
//! (compute + SCALE-encoded chain interaction, no I/O).
//!
//! Workloads planned: sha256/1MB, ed25519 verify, SCALE encode/decode,
//! tight compute loop. All run with mocked host-function IPC (no real
//! socket; constant-time stubs).
//!
//! See the VM-research notes under `/tmp/vm-research/` for the Path A/B/C
//! framing this harness is built to inform.

/// Minimal interface a PVM-family VM must expose to be measured.
///
/// Implementations live in submodules: `javm_runner`, `polkavm_runner`.
/// Each criterion bench under `benches/` instantiates both and runs the
/// same blob + same input on each, producing latency / memory deltas.
pub trait PvmRunner {
	/// Display name for the harness output (e.g., `"javm"`, `"polkavm"`).
	fn name(&self) -> &'static str;

	/// Load a PVM blob, invoke its entrypoint with `input`, return the
	/// produced output bytes. Errors as plain strings; bench harnesses
	/// only need to distinguish success from failure.
	fn run(&mut self, blob: &[u8], input: &[u8]) -> Result<Vec<u8>, String>;
}
