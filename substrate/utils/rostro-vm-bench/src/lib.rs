// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! A/B benchmark harness for RVM (Rostro Virtual Machine) implementations
//! on Rostro-shop-shaped workloads.
//!
//! Phase 3b deliverable for VM research: provides apples-to-apples timing
//! and gas-consumption measurements across Wei Tang's `javm` and Parity's
//! `polkavm` crate on workloads matching the Rostro shop sidecar's expected
//! shape (compute + SCALE-encoded chain interaction, no I/O).
//!
//! Workloads planned: sha256/1MB, ed25519 verify, SCALE encode/decode,
//! tight compute loop. All run with mocked host-function IPC (no real
//! socket; constant-time stubs).
//!
//! See the VM-research notes under `/tmp/vm-research/` for the Path A/B/C
//! framing this harness is built to inform.

pub mod runners;

/// Minimal interface a Rostro Virtual Machine implementation must expose to
/// be measured.
///
/// Implementations live in [`runners`]: [`runners::JavmRunner`],
/// [`runners::PolkaVmRunner`]. Each criterion bench under `benches/`
/// instantiates both and runs the same blob on each, producing latency
/// + gas-consumption deltas.
pub trait RvmRunner {
	/// Display name for the harness output (e.g. `"javm-interpreter"`).
	fn name(&self) -> &'static str;

	/// Run the blob, returning register A0 at halt and gas consumed.
	///
	/// `input` is reserved for workloads that pass data via guest memory;
	/// the scaffolding implementations ignore it for now.
	fn run(&mut self, blob: &[u8], input: &[u8]) -> Result<RunOutput, String>;
}

/// Output of a single RVM run.
///
/// RVM programs return their result via register A0; richer output channels
/// (guest-memory byte buffers, multi-register packing) get added to this
/// struct as workloads need them.
#[derive(Debug, Clone, Copy)]
pub struct RunOutput {
	/// Value of register A0 at program halt.
	pub result_a0: u64,
	/// Gas units consumed (initial gas budget minus remaining).
	pub gas_consumed: u64,
}
