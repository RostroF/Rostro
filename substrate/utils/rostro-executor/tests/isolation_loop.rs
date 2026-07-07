// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation

//! Executor-isolation throughput harness.
//!
//! Answers one question: with RPC, txpool, and ParityDB all removed,
//! what does one transaction actually cost in the executor + runtime?
//! Feeds real signed `Balances::transfer_keep_alive` extrinsics (sr25519,
//! same workload as the lab floods) from memory in a tight loop:
//!
//!   1. `TaggedTransactionQueue_validate_transaction` — the exact runtime
//!      call every `author_submitExtrinsic` pays on the RPC node.
//!   2. `BlockBuilder_apply_extrinsic` — the per-tx cost of block
//!      authoring / import.
//!
//! State is in-memory `TestExternalities` built from the real
//! gemini-runtime genesis, so the numbers isolate VM + runtime logic
//! from all node-side machinery. Compare against the lab's observed
//! per-tx latency: a large gap means the bottleneck is node-side
//! (RPC/pool/DB), a small gap means it's execution.
//!
//! `#[ignore]`-gated like the B5/B6 tests — needs the riscv blob:
//!
//!   SUBSTRATE_ENABLE_POLKAVM=1 SUBSTRATE_RUNTIME_TARGET=riscv \
//!     cargo test -p rostro-executor --test isolation_loop --release \
//!     -- --ignored --nocapture

use codec::Encode;
use gemini_runtime::{
	Address, BalancesConfig, RuntimeCall, RuntimeGenesisConfig, SignedExtra, UncheckedExtrinsic,
	ROSTO, VERSION,
};
use rostro_executor::RostroCodeExecutor;
use sp_core::traits::{CallContext, CodeExecutor, RuntimeCode, WrappedRuntimeCode};
use sp_keyring::Sr25519Keyring;
use rostro_multi_key::RostroSignature;
use sp_runtime::{
	generic::{Era, SignedPayload},
	transaction_validity::TransactionSource,
	BuildStorage,
};
use std::time::Instant;

/// frame-system genesis seeds `BlockHash(0)` / `ParentHash` with this
/// (`hash69()` in frame/system) — it is the "genesis hash" that
/// `CheckGenesis` / immortal `CheckEra` sign over in a fresh
/// `TestExternalities`.
fn genesis_hash() -> gemini_runtime::Hash {
	[69u8; 32].into()
}

fn signed_transfer(nonce: u32) -> UncheckedExtrinsic {
	let alice = Sr25519Keyring::Alice;
	let dest: Address = Sr25519Keyring::Bob.to_account_id().into();
	let call =
		RuntimeCall::Balances(pallet_balances::Call::transfer_keep_alive { dest, value: ROSTO });

	let extra: SignedExtra = (
		frame_system::CheckNonZeroSender::new(),
		frame_system::CheckSpecVersion::new(),
		frame_system::CheckTxVersion::new(),
		frame_system::CheckGenesis::new(),
		frame_system::CheckEra::from(Era::immortal()),
		frame_system::CheckNonce::from(nonce),
		frame_system::CheckWeight::new(),
		pallet_transaction_payment::ChargeTransactionPayment::from(0),
		frame_metadata_hash_extension::CheckMetadataHash::new(false),
	);
	let payload = SignedPayload::from_raw(
		call.clone(),
		extra.clone(),
		(
			(),
			VERSION.spec_version,
			VERSION.transaction_version,
			genesis_hash(),
			genesis_hash(),
			(),
			(),
			(),
			None,
		),
	);
	let signature = payload.using_encoded(|bytes| alice.sign(bytes));

	UncheckedExtrinsic::new_signed(
		call,
		alice.to_account_id().into(),
		RostroSignature::Sr25519(signature),
		extra,
	)
}

fn test_externalities() -> sp_io::TestExternalities {
	let storage = RuntimeGenesisConfig {
		balances: BalancesConfig {
			balances: vec![(Sr25519Keyring::Alice.to_account_id(), 1_000_000 * ROSTO)],
			..Default::default()
		},
		..Default::default()
	}
	.build_storage()
	.expect("genesis storage");
	sp_io::TestExternalities::new(storage)
}

struct Harness {
	executor: RostroCodeExecutor<sp_io::SubstrateHostFunctions>,
	blob: &'static [u8],
	code_hash: Vec<u8>,
}

impl Harness {
	fn new() -> Self {
		let blob = gemini_runtime::WASM_BINARY.expect(
			"gemini-runtime WASM_BINARY missing — rebuild with SUBSTRATE_RUNTIME_TARGET=riscv",
		);
		assert!(blob.starts_with(b"PVM\0"), "gemini-runtime blob is not PVM format");
		Self {
			executor: RostroCodeExecutor::new().expect("construct executor"),
			blob,
			code_hash: sp_core::hashing::blake2_256(blob).to_vec(),
		}
	}

	fn call(&self, ext: &mut dyn sp_externalities::Externalities, method: &str, data: &[u8]) -> Vec<u8> {
		let wrapped = WrappedRuntimeCode(self.blob.into());
		let runtime_code = RuntimeCode {
			code_fetcher: &wrapped,
			heap_pages: None,
			hash: self.code_hash.clone(),
		};
		let (result, _) = self.executor.call(ext, &runtime_code, method, data, CallContext::Onchain);
		result.unwrap_or_else(|e| panic!("runtime call '{method}' failed: {e}"))
	}
}

fn report(label: &str, times: &mut [u128]) {
	times.sort_unstable();
	let n = times.len();
	let total: u128 = times.iter().sum();
	eprintln!(
		"{label}: n={n} mean={:.3}ms median={:.3}ms min={:.3}ms max={:.3}ms  → {:.0} tx/s single-threaded",
		total as f64 / n as f64 / 1000.0,
		times[n / 2] as f64 / 1000.0,
		times[0] as f64 / 1000.0,
		times[n - 1] as f64 / 1000.0,
		1_000_000.0 / (total as f64 / n as f64),
	);
}

const N: u32 = 200;

#[test]
#[ignore = "requires SUBSTRATE_RUNTIME_TARGET=riscv to build gemini-runtime as PVM"]
fn validate_transaction_tight_loop() {
	let harness = Harness::new();
	let mut ext = test_externalities();
	let mut ext = ext.ext();

	// Pre-build all extrinsics so signing cost stays out of the loop.
	let txs: Vec<Vec<u8>> = (0..N)
		.map(|nonce| {
			(TransactionSource::External, signed_transfer(nonce), genesis_hash()).encode()
		})
		.collect();

	// Warm the module cache (first call pays the one-time compile).
	let t = Instant::now();
	let ret = harness.call(&mut ext, "TaggedTransactionQueue_validate_transaction", &txs[0]);
	eprintln!("first call (cache miss, includes compile): {:?}", t.elapsed());
	assert_valid(&ret);

	let mut times = Vec::with_capacity(N as usize);
	for tx in &txs {
		let t = Instant::now();
		let ret = harness.call(&mut ext, "TaggedTransactionQueue_validate_transaction", tx);
		times.push(t.elapsed().as_micros());
		assert_valid(&ret);
	}
	report("validate_transaction (RPC-submit runtime path)", &mut times);
}

#[test]
#[ignore = "requires SUBSTRATE_RUNTIME_TARGET=riscv to build gemini-runtime as PVM"]
fn apply_extrinsic_tight_loop() {
	let harness = Harness::new();
	let mut ext = test_externalities();
	let mut ext = ext.ext();

	// `Executive::validate_transaction` self-initializes frame_system
	// (number, parent hash) — one throwaway validate puts the state in
	// block context without needing a Sassafras slot-claim digest, which
	// `Core_initialize_block` would demand.
	let seed = (TransactionSource::External, signed_transfer(0), genesis_hash()).encode();
	harness.call(&mut ext, "TaggedTransactionQueue_validate_transaction", &seed);

	let txs: Vec<Vec<u8>> = (0..N).map(|nonce| signed_transfer(nonce).encode()).collect();

	let mut times = Vec::with_capacity(N as usize);
	for tx in &txs {
		let t = Instant::now();
		let ret = harness.call(&mut ext, "BlockBuilder_apply_extrinsic", tx);
		times.push(t.elapsed().as_micros());
		// ApplyExtrinsicResult = Result<Result<(), DispatchError>, TransactionValidityError>
		assert_eq!(ret.first(), Some(&0u8), "apply_extrinsic returned error: 0x{}", hex(&ret));
	}
	report("apply_extrinsic (authoring/import runtime path)", &mut times);
}

/// Parallel scaling: T threads, each with its own in-memory state, all
/// sharing ONE executor (and therefore one module cache + engine — the
/// same sharing shape as sc-service handing executor clones to async
/// tasks). Flat scaling here would mean the executor serializes
/// internally; linear scaling means any single-node ceiling below
/// (cores × single-thread rate) is node-side.
#[test]
#[ignore = "requires SUBSTRATE_RUNTIME_TARGET=riscv to build gemini-runtime as PVM"]
fn parallel_scaling() {
	use std::sync::{Arc, Barrier};

	let harness = Arc::new(Harness::new());

	// Warm the module cache before any threads race on the compile.
	{
		let mut ext = test_externalities();
		let mut ext = ext.ext();
		let seed = (TransactionSource::External, signed_transfer(0), genesis_hash()).encode();
		harness.call(&mut ext, "TaggedTransactionQueue_validate_transaction", &seed);
	}

	let txs: Arc<Vec<Vec<u8>>> = Arc::new(
		(0..N)
			.map(|nonce| {
				(TransactionSource::External, signed_transfer(nonce), genesis_hash()).encode()
			})
			.collect(),
	);

	let mut one_thread_rate = 0f64;
	for threads in [1usize, 2, 4, 8] {
		// Threads build their externalities first, then hit the barrier,
		// so the timed window is pure validate work.
		let barrier = Arc::new(Barrier::new(threads + 1));
		let handles: Vec<_> = (0..threads)
			.map(|_| {
				let harness = Arc::clone(&harness);
				let txs = Arc::clone(&txs);
				let barrier = Arc::clone(&barrier);
				std::thread::spawn(move || {
					let mut ext = test_externalities();
					let mut ext = ext.ext();
					barrier.wait();
					for tx in txs.iter() {
						let ret = harness.call(
							&mut ext,
							"TaggedTransactionQueue_validate_transaction",
							tx,
						);
						assert_valid(&ret);
					}
				})
			})
			.collect();

		barrier.wait();
		let t = Instant::now();
		for handle in handles {
			handle.join().expect("worker thread panicked");
		}
		let elapsed = t.elapsed();
		let total = threads * N as usize;
		let rate = total as f64 / elapsed.as_secs_f64();
		if threads == 1 {
			one_thread_rate = rate;
		}
		eprintln!(
			"threads={threads}: {total} validates in {elapsed:?} → {rate:.0} tx/s aggregate ({:.2}x vs 1 thread)",
			rate / one_thread_rate,
		);
	}
}

/// Discriminator for the parallel plateau: instantiation only, no
/// execution. If this plateaus like `parallel_scaling`, the contention
/// is in per-call instance setup (allocation/zeroing); if it scales,
/// the contention is in interpreted execution itself.
#[test]
#[ignore = "requires SUBSTRATE_RUNTIME_TARGET=riscv to build gemini-runtime as PVM"]
fn parallel_instantiate_scaling() {
	use polkavm::{BackendKind, Config, Engine, Module, ModuleConfig};
	use std::sync::{Arc, Barrier};

	let blob = gemini_runtime::WASM_BINARY.expect("riscv blob");
	let mut config = Config::from_env().unwrap_or_else(|_| Config::new());
	config.set_allow_experimental(true);
	config.set_backend(Some(BackendKind::Interpreter));
	let engine = Engine::new(&config).expect("engine");
	let module =
		Module::new(&engine, &ModuleConfig::new(), blob.to_vec().into()).expect("module");
	let mut linker = polkavm::Linker::<(), String>::new();
	rostro_executor::register_substrate_host_functions::<(), sp_io::SubstrateHostFunctions>(
		&mut linker,
	)
	.expect("host fns");
	let instance_pre = Arc::new(linker.instantiate_pre(&module).expect("instantiate_pre"));

	const ITERS: usize = 2_000;
	let mut one_thread_rate = 0f64;
	for threads in [1usize, 2, 4, 8] {
		let barrier = Arc::new(Barrier::new(threads + 1));
		let handles: Vec<_> = (0..threads)
			.map(|_| {
				let pre = Arc::clone(&instance_pre);
				let barrier = Arc::clone(&barrier);
				std::thread::spawn(move || {
					barrier.wait();
					for _ in 0..ITERS {
						let mut instance = pre.instantiate().expect("instantiate");
						instance.reset_memory().expect("reset");
						std::hint::black_box(&instance);
					}
				})
			})
			.collect();

		barrier.wait();
		let t = Instant::now();
		for handle in handles {
			handle.join().expect("worker thread panicked");
		}
		let elapsed = t.elapsed();
		let total = threads * ITERS;
		let rate = total as f64 / elapsed.as_secs_f64();
		if threads == 1 {
			one_thread_rate = rate;
		}
		eprintln!(
			"threads={threads}: {total} instantiates in {elapsed:?} → {rate:.0}/s aggregate ({:.2}x vs 1 thread)",
			rate / one_thread_rate,
		);
	}
}

/// Second discriminator: fully UNSHARED executors — every thread gets
/// its own engine, module cache, and compiled module, so no executor
/// state is shared at all. If this plateaus like `parallel_scaling`,
/// the wall is the machine (memory bandwidth / SMT / WSL2), not
/// executor-internal sharing.
#[test]
#[ignore = "requires SUBSTRATE_RUNTIME_TARGET=riscv to build gemini-runtime as PVM"]
fn parallel_scaling_unshared() {
	use std::sync::{Arc, Barrier};

	let txs: Arc<Vec<Vec<u8>>> = Arc::new(
		(0..N)
			.map(|nonce| {
				(TransactionSource::External, signed_transfer(nonce), genesis_hash()).encode()
			})
			.collect(),
	);

	let mut one_thread_rate = 0f64;
	for threads in [1usize, 2, 4, 8] {
		let barrier = Arc::new(Barrier::new(threads + 1));
		let handles: Vec<_> = (0..threads)
			.map(|_| {
				let txs = Arc::clone(&txs);
				let barrier = Arc::clone(&barrier);
				std::thread::spawn(move || {
					// Private executor: own engine + module cache. Warm
					// it (per-thread compile) before the barrier.
					let harness = Harness::new();
					let mut ext = test_externalities();
					let mut ext = ext.ext();
					let seed =
						(TransactionSource::External, signed_transfer(0), genesis_hash()).encode();
					harness.call(&mut ext, "TaggedTransactionQueue_validate_transaction", &seed);
					barrier.wait();
					for tx in txs.iter() {
						let ret = harness.call(
							&mut ext,
							"TaggedTransactionQueue_validate_transaction",
							tx,
						);
						assert_valid(&ret);
					}
				})
			})
			.collect();

		barrier.wait();
		let t = Instant::now();
		for handle in handles {
			handle.join().expect("worker thread panicked");
		}
		let elapsed = t.elapsed();
		let total = threads * N as usize;
		let rate = total as f64 / elapsed.as_secs_f64();
		if threads == 1 {
			one_thread_rate = rate;
		}
		eprintln!(
			"threads={threads}: {total} validates in {elapsed:?} → {rate:.0} tx/s aggregate ({:.2}x vs 1 thread)",
			rate / one_thread_rate,
		);
	}
}

/// `TransactionValidity` = `Result<ValidTransaction, TransactionValidityError>`;
/// SCALE `Ok` discriminant is `0`.
fn assert_valid(ret: &[u8]) {
	assert_eq!(ret.first(), Some(&0u8), "validate_transaction rejected the tx: 0x{}", hex(ret));
}

fn hex(bytes: &[u8]) -> String {
	bytes.iter().map(|b| format!("{b:02x}")).collect()
}
