// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! [`RvmRunner`] implementation backed by Parity's `polkavm` crate (0.31.0).

use crate::{RvmRunner, RunOutput};
use super::DEFAULT_GAS_LIMIT;

use polkavm::{
	BackendKind, Config, Engine, GasMeteringKind, InterruptKind, Module, ModuleConfig, RawInstance,
	Reg, SandboxKind,
	rostro_intrinsics::{
		ROSTRO_INTRINSIC_BLAKE2B_256, ROSTRO_INTRINSIC_DILITHIUM_VERIFY,
		ROSTRO_INTRINSIC_ED25519_VERIFY, ROSTRO_INTRINSIC_GOLDILOCKS_ADD,
		ROSTRO_INTRINSIC_GOLDILOCKS_INV, ROSTRO_INTRINSIC_GOLDILOCKS_MUL,
		ROSTRO_INTRINSIC_GOLDILOCKS_SUB, ROSTRO_INTRINSIC_KECCAK_256,
		ROSTRO_INTRINSIC_P521_ECDSA_VERIFY, ROSTRO_INTRINSIC_POSEIDON2_PERM,
		ROSTRO_INTRINSIC_SECP256K1_RECOVER, RostroIntrinsicsCodegen, goldilocks_add_native,
		goldilocks_inv_native, goldilocks_mul_native, goldilocks_sub_native,
		rostro_blake2b_256, rostro_dilithium_verify, rostro_ed25519_verify,
		rostro_keccak_256, rostro_p521_ecdsa_verify_prehash, rostro_poseidon2_permute,
		rostro_secp256k1_recover,
	},
};

/// Read `len` bytes from guest memory at `addr`. Returns `None` if the
/// region is not fully accessible. Treats `len == 0` as an empty slice
/// regardless of `addr` (matches the interpreter's `borrow_or_empty`
/// short-circuit — guest emits dangling pointers like 0x1 for empty
/// `&[u8]`, which would otherwise fail `read_memory`'s region check).
fn read_guest_bytes(inst: &mut RawInstance, addr: u32, len: u32) -> Option<Vec<u8>> {
	if len == 0 {
		Some(Vec::new())
	} else {
		inst.read_memory(addr, len).ok()
	}
}

/// Dispatch a Rostro intrinsic ecalli on the host side.
///
/// The interpreter intercepts these IDs (100..1023) inside `FAST_OP_ECALLI` so
/// they never exit the run loop. The JIT, however, treats ecalli as a run-loop
/// exit point — the harness sees `InterruptKind::Ecalli(N)` and must dispatch
/// the same native body the interpreter uses, otherwise the guest reads garbage
/// from A0 and the JIT disagrees with the interpreter on every intrinsic-using
/// workload (goldilocks_mul, poseidon2_perm, mini_verifier, fri_fold_tree,
/// poly_eval, batch_inverse, …).
///
/// Returns `true` if `n` was a recognized Rostro intrinsic and dispatched;
/// `false` for everything else (unknown / non-Rostro host calls — caller
/// should preserve its existing stub-and-continue behavior).
fn dispatch_rostro_intrinsic(inst: &mut RawInstance, n: u32) -> bool {
	match n {
		ROSTRO_INTRINSIC_GOLDILOCKS_MUL => {
			let a = inst.reg(Reg::A0);
			let b = inst.reg(Reg::A1);
			inst.set_reg(Reg::A0, goldilocks_mul_native(a, b));
			true
		}
		ROSTRO_INTRINSIC_GOLDILOCKS_ADD => {
			let a = inst.reg(Reg::A0);
			let b = inst.reg(Reg::A1);
			inst.set_reg(Reg::A0, goldilocks_add_native(a, b));
			true
		}
		ROSTRO_INTRINSIC_GOLDILOCKS_SUB => {
			let a = inst.reg(Reg::A0);
			let b = inst.reg(Reg::A1);
			inst.set_reg(Reg::A0, goldilocks_sub_native(a, b));
			true
		}
		ROSTRO_INTRINSIC_GOLDILOCKS_INV => {
			let x = inst.reg(Reg::A0);
			inst.set_reg(Reg::A0, goldilocks_inv_native(x));
			true
		}
		ROSTRO_INTRINSIC_P521_ECDSA_VERIFY => {
			// ABI: A0=vk_ptr (133B), A1=sig_ptr (132B), A2=prehash_ptr,
			// A3=prehash_len. Result -> A0 = 1 verified, 0 failed.
			let vk_ptr = inst.reg(Reg::A0) as u32;
			let sig_ptr = inst.reg(Reg::A1) as u32;
			let prehash_ptr = inst.reg(Reg::A2) as u32;
			let prehash_len = inst.reg(Reg::A3) as u32;
			let result: u64 = (|| {
				let vk = inst.read_memory(vk_ptr, 133).ok()?;
				let sig = inst.read_memory(sig_ptr, 132).ok()?;
				let prehash = read_guest_bytes(inst, prehash_ptr, prehash_len)?;
				Some(rostro_p521_ecdsa_verify_prehash(&vk, &sig, &prehash) as u64)
			})()
			.unwrap_or(0);
			inst.set_reg(Reg::A0, result);
			true
		}
		ROSTRO_INTRINSIC_DILITHIUM_VERIFY => {
			// ABI: A0=pk_ptr (1952B), A1=msg_ptr, A2=msg_len, A3=sig_ptr (3309B),
			// A4=ctx_ptr, A5=ctx_len. Result -> A0 = 1 verified, 0 failed.
			let pk_ptr = inst.reg(Reg::A0) as u32;
			let msg_ptr = inst.reg(Reg::A1) as u32;
			let msg_len = inst.reg(Reg::A2) as u32;
			let sig_ptr = inst.reg(Reg::A3) as u32;
			let ctx_ptr = inst.reg(Reg::A4) as u32;
			let ctx_len = inst.reg(Reg::A5) as u32;
			let result: u64 = (|| {
				let pk = inst.read_memory(pk_ptr, 1952).ok()?;
				let sig = inst.read_memory(sig_ptr, 3309).ok()?;
				let msg = read_guest_bytes(inst, msg_ptr, msg_len)?;
				let ctx = read_guest_bytes(inst, ctx_ptr, ctx_len)?;
				Some(rostro_dilithium_verify(&pk, &msg, &sig, &ctx) as u64)
			})()
			.unwrap_or(0);
			inst.set_reg(Reg::A0, result);
			true
		}
		ROSTRO_INTRINSIC_BLAKE2B_256 => {
			// ABI: A0=msg_ptr, A1=msg_len, A2=out_ptr (32B). Result -> A0 = 0
			// on success, 1 on memory-access failure (mirrors interpreter).
			let msg_ptr = inst.reg(Reg::A0) as u32;
			let msg_len = inst.reg(Reg::A1) as u32;
			let out_ptr = inst.reg(Reg::A2) as u32;
			let result: u64 = (|| -> Option<u64> {
				let msg = read_guest_bytes(inst, msg_ptr, msg_len)?;
				let hash = rostro_blake2b_256(&msg);
				inst.write_memory(out_ptr, &hash).ok()?;
				Some(0)
			})()
			.unwrap_or(1);
			inst.set_reg(Reg::A0, result);
			true
		}
		ROSTRO_INTRINSIC_KECCAK_256 => {
			// ABI: same as BLAKE2B_256.
			let msg_ptr = inst.reg(Reg::A0) as u32;
			let msg_len = inst.reg(Reg::A1) as u32;
			let out_ptr = inst.reg(Reg::A2) as u32;
			let result: u64 = (|| -> Option<u64> {
				let msg = read_guest_bytes(inst, msg_ptr, msg_len)?;
				let hash = rostro_keccak_256(&msg);
				inst.write_memory(out_ptr, &hash).ok()?;
				Some(0)
			})()
			.unwrap_or(1);
			inst.set_reg(Reg::A0, result);
			true
		}
		ROSTRO_INTRINSIC_ED25519_VERIFY => {
			// ABI: A0=pk_ptr (32B), A1=sig_ptr (64B), A2=msg_ptr, A3=msg_len.
			// Result -> A0 = 1 verified, 0 failed.
			let pk_ptr = inst.reg(Reg::A0) as u32;
			let sig_ptr = inst.reg(Reg::A1) as u32;
			let msg_ptr = inst.reg(Reg::A2) as u32;
			let msg_len = inst.reg(Reg::A3) as u32;
			let result: u64 = (|| {
				let pk = inst.read_memory(pk_ptr, 32).ok()?;
				let sig = inst.read_memory(sig_ptr, 64).ok()?;
				let msg = read_guest_bytes(inst, msg_ptr, msg_len)?;
				Some(rostro_ed25519_verify(&pk, &sig, &msg) as u64)
			})()
			.unwrap_or(0);
			inst.set_reg(Reg::A0, result);
			true
		}
		ROSTRO_INTRINSIC_SECP256K1_RECOVER => {
			// ABI: A0=hash_ptr (32B), A1=sig_ptr (65B: r||s||v),
			// A2=out_pk_ptr (64B X||Y). Result -> A0 = 1 recovered, 0 failed.
			let hash_ptr = inst.reg(Reg::A0) as u32;
			let sig_ptr = inst.reg(Reg::A1) as u32;
			let out_ptr = inst.reg(Reg::A2) as u32;
			let result: u64 = (|| -> Option<u64> {
				let msg_hash = inst.read_memory(hash_ptr, 32).ok()?;
				let sig = inst.read_memory(sig_ptr, 65).ok()?;
				let mut out_pk = [0u8; 64];
				if !rostro_secp256k1_recover(&msg_hash, &sig, &mut out_pk) {
					return Some(0);
				}
				inst.write_memory(out_ptr, &out_pk).ok()?;
				Some(1)
			})()
			.unwrap_or(0);
			inst.set_reg(Reg::A0, result);
			true
		}
		ROSTRO_INTRINSIC_POSEIDON2_PERM => {
			// ABI: A0=state_ptr (8 little-endian u64s = 64 bytes). In-place
			// permute. Result -> A0 = 0 success, 1 memory-access failure.
			let state_ptr = inst.reg(Reg::A0) as u32;
			let result: u64 = (|| -> Option<u64> {
				let bytes = inst.read_memory(state_ptr, 64).ok()?;
				let mut state = [0u64; 8];
				for i in 0..8 {
					state[i] = u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().ok()?);
				}
				rostro_poseidon2_permute(&mut state);
				let mut out = [0u8; 64];
				for i in 0..8 {
					out[i * 8..(i + 1) * 8].copy_from_slice(&state[i].to_le_bytes());
				}
				inst.write_memory(state_ptr, &out).ok()?;
				Some(0)
			})()
			.unwrap_or(1);
			inst.set_reg(Reg::A0, result);
			true
		}
		_ => false,
	}
}

/// Opaque handle returned by [`PolkaVmRunner::precompile`]. Wraps a fully
/// JIT-compiled (or interpreter-loaded) `polkavm::Module`; subsequent
/// [`PolkaVmRunner::run_compiled`] calls only do instantiate + execute.
pub struct PolkaVmCompiled {
	module: Module,
}

/// RVM runner using `polkavm::Module::instantiate()` + manual register setup.
///
/// Mirrors `grey_bench::run_polkavm_module` so the comparison is apples-to-apples.
/// The engine is built once and reused across `run` calls; modules are rebuilt
/// per call (matches the "compile + execute every iteration" benchmark fairness
/// note from grey-bench).
///
/// Backend selection: use [`PolkaVmRunner::interpreter`] or
/// [`PolkaVmRunner::compiler`] to force a specific backend; [`PolkaVmRunner::new`]
/// uses whatever polkavm's `Config::from_env()` resolves to (typically the
/// compiler when supported, falling back to interpreter).
pub struct PolkaVmRunner {
	engine: Engine,
	gas_limit: i64,
	name: &'static str,
	/// Whether to install `RostroIntrinsicsCodegen` on the ModuleConfig.
	/// Only meaningful for the compiler backend; the interpreter ignores it.
	use_custom_codegen: bool,
	/// Sandbox kind that the engine resolved to. Cached so we don't query
	/// it per `Module::new` call. CustomCodegen needs this to compute
	/// vmctx-relative offsets.
	sandbox_kind: SandboxKind,
}

impl PolkaVmRunner {
	/// Default backend — whatever polkavm's config resolves to.
	pub fn new() -> Result<Self, String> {
		Self::build("polkavm", None)
	}

	/// Force the software interpreter backend.
	pub fn interpreter() -> Result<Self, String> {
		Self::build("polkavm-interpreter", Some(BackendKind::Interpreter))
	}

	/// Force the JIT compiler backend.
	///
	/// On platforms where the compiler backend isn't compiled in,
	/// `Engine::new()` will fail and this returns `Err`.
	pub fn compiler() -> Result<Self, String> {
		Self::build("polkavm-compiler", Some(BackendKind::Compiler))
	}

	pub fn with_gas_limit(mut self, gas: u64) -> Self {
		self.gas_limit = gas as i64;
		self
	}

	fn build(name: &'static str, backend: Option<BackendKind>) -> Result<Self, String> {
		let mut config = Config::from_env().unwrap_or_else(|_| Config::new());
		config.set_allow_experimental(true);
		if let Some(b) = backend {
			config.set_backend(Some(b));
		}
		// Disable sandboxing unless the user opted in via env var. Bench
		// processes don't need OS-level isolation; the in-process VM
		// sandbox is sufficient. Matches grey-bench's pattern.
		if std::env::var_os("POLKAVM_SANDBOXING_ENABLED").is_none() {
			config.set_sandboxing_enabled(false);
		}
		// Default to the Generic sandbox. The Linux sandbox spawns a zygote
		// worker process whose namespace setup times out under WSL2 (see
		// polkavm_compiler_wsl_limitation memory). Generic skips the worker
		// entirely and uses an in-process JIT region, which is what we want
		// for benchmark numbers anyway. The interpreter backend doesn't use
		// a sandbox, so this is a no-op for it. Users who specifically want
		// the Linux sandbox can opt in via `POLKAVM_SANDBOX=linux`.
		if config.sandbox().is_none() {
			config.set_sandbox(Some(SandboxKind::Generic));
		}
		let sandbox_kind = config.sandbox().unwrap_or(SandboxKind::Generic);
		// Install RostroIntrinsicsCodegen only on the compiler backend. The
		// interpreter intercepts intrinsic ecallis inline in run_match and
		// doesn't consult custom_codegen.
		let use_custom_codegen = matches!(backend, Some(BackendKind::Compiler));
		let engine =
			Engine::new(&config).map_err(|e| format!("polkavm Engine::new ({name}): {e}"))?;
		Ok(Self { engine, gas_limit: DEFAULT_GAS_LIMIT as i64, name, use_custom_codegen, sandbox_kind })
	}

	/// Apply the standard module config (gas metering + optional Rostro
	/// intrinsic CustomCodegen on the JIT path). Centralized so `precompile`
	/// and `run` share the wiring.
	fn make_module_config(&self) -> ModuleConfig {
		let mut mc = ModuleConfig::new();
		mc.set_gas_metering(Some(GasMeteringKind::Sync));
		if self.use_custom_codegen {
			mc.set_custom_codegen(RostroIntrinsicsCodegen::new(self.sandbox_kind));
		}
		mc
	}
}

impl PolkaVmRunner {
	/// Compile `blob` into a reusable [`PolkaVmCompiled`] handle. Skip-the-
	/// compile path for steady-state (warm) measurements.
	pub fn precompile(&self, blob: &[u8]) -> Result<PolkaVmCompiled, String> {
		let mc = self.make_module_config();
		let module = Module::new(&self.engine, &mc, blob.to_vec().into())
			.map_err(|e| format!("polkavm Module::new (precompile): {e}"))?;
		Ok(PolkaVmCompiled { module })
	}

	/// Warm-path execute: skips `Module::new` (the compile step). A fresh
	/// instance is still spun up per call so memory state is isolated.
	pub fn run_compiled(
		&mut self,
		compiled: &PolkaVmCompiled,
		_input: &[u8],
	) -> Result<RunOutput, String> {
		let module = &compiled.module;
		let mut inst = module
			.instantiate()
			.map_err(|e| format!("polkavm instantiate: {}", e))?;
		inst.set_gas(self.gas_limit);

		let export =
			module.exports().next().ok_or_else(|| "polkavm: no exports".to_string())?;
		inst.set_next_program_counter(export.program_counter());
		inst.set_reg(Reg::RA, 0xFFFF_0000);
		inst.set_reg(Reg::SP, module.default_sp());

		loop {
			match inst.run() {
				Ok(InterruptKind::Finished) => break,
				Ok(InterruptKind::Ecalli(0)) => break,
				Ok(InterruptKind::Ecalli(n)) => {
					// Try Rostro intrinsics (IDs 100..1023). If unknown,
					// fall through to stub-and-continue (matches prior
					// behavior for non-Rostro host calls).
					let _ = dispatch_rostro_intrinsic(&mut inst, n);
				}
				Ok(InterruptKind::Trap) => return Err("polkavm: trap".to_string()),
				Ok(InterruptKind::NotEnoughGas) =>
					return Err("polkavm: out of gas".to_string()),
				Ok(other) => return Err(format!("polkavm: unexpected interrupt {:?}", other)),
				Err(e) => return Err(format!("polkavm run error: {}", e)),
			}
		}

		let remaining = inst.gas();
		Ok(RunOutput {
			result_a0: inst.reg(Reg::A0),
			gas_consumed: self.gas_limit.saturating_sub(remaining).max(0) as u64,
		})
	}
}

impl RvmRunner for PolkaVmRunner {
	fn name(&self) -> &'static str {
		self.name
	}

	fn run(&mut self, blob: &[u8], _input: &[u8]) -> Result<RunOutput, String> {
		let mc = self.make_module_config();
		let module = Module::new(&self.engine, &mc, blob.to_vec().into())
			.map_err(|e| format!("polkavm Module::new: {}", e))?;

		let mut inst =
			module.instantiate().map_err(|e| format!("polkavm instantiate: {}", e))?;
		inst.set_gas(self.gas_limit);

		let export =
			module.exports().next().ok_or_else(|| "polkavm: no exports".to_string())?;
		inst.set_next_program_counter(export.program_counter());

		// Sentinel return address — when the guest returns to this PC,
		// the run loop sees InterruptKind::Trap and we read A0. Matches
		// grey-bench's convention.
		inst.set_reg(Reg::RA, 0xFFFF_0000);
		inst.set_reg(Reg::SP, module.default_sp());

		loop {
			match inst.run() {
				Ok(InterruptKind::Finished) => break,
				// JAM REPLY (ecalli 0) is a terminal halt — javm's InvocationKernel
				// treats it as `KernelResult::Halt(a0)`. Mirror that here so a
				// JAM-convention blob produces the same observable outcome on
				// both runners. Other ecallis are host calls; for bench workloads
				// they're stubbed (no-op continue).
				Ok(InterruptKind::Ecalli(0)) => break,
				Ok(InterruptKind::Ecalli(n)) => {
					// Try Rostro intrinsics (IDs 100..1023). If unknown,
					// fall through to stub-and-continue (matches prior
					// behavior for non-Rostro host calls).
					let _ = dispatch_rostro_intrinsic(&mut inst, n);
				}
				Ok(InterruptKind::Trap) => return Err("polkavm: trap".to_string()),
				Ok(InterruptKind::NotEnoughGas) =>
					return Err("polkavm: out of gas".to_string()),
				Ok(other) => return Err(format!("polkavm: unexpected interrupt {:?}", other)),
				Err(e) => return Err(format!("polkavm run error: {}", e)),
			}
		}

		let remaining = inst.gas();
		Ok(RunOutput {
			result_a0: inst.reg(Reg::A0),
			gas_consumed: self.gas_limit.saturating_sub(remaining).max(0) as u64,
		})
	}
}
