use rostro_vm_bench::{
	runners::{JavmRunner, PolkaVmRunner, WasmtimeRunner},
	service_blobs::{
		BATCH_INVERSE_JAVM_BLOB, BATCH_INVERSE_POLKAVM_BLOB, BATCH_INVERSE_WASM_BLOB,
		BLAKE2B_JAVM_BLOB, BLAKE2B_POLKAVM_BLOB, BLAKE2B_WASM_BLOB,
		FRI_FOLD_TREE_JAVM_BLOB, FRI_FOLD_TREE_LARGE_JAVM_BLOB,
		FRI_FOLD_TREE_LARGE_POLKAVM_BLOB, FRI_FOLD_TREE_LARGE_WASM_BLOB,
		FRI_FOLD_TREE_POLKAVM_BLOB, FRI_FOLD_TREE_WASM_BLOB,
		GOLDILOCKS_MUL_JAVM_BLOB, GOLDILOCKS_MUL_POLKAVM_BLOB, GOLDILOCKS_MUL_WASM_BLOB,
		MINI_VERIFIER_JAVM_BLOB, MINI_VERIFIER_POLKAVM_BLOB, MINI_VERIFIER_WASM_BLOB,
		POLY_EVAL_JAVM_BLOB, POLY_EVAL_POLKAVM_BLOB, POLY_EVAL_WASM_BLOB,
		POSEIDON2_PERM_JAVM_BLOB, POSEIDON2_PERM_POLKAVM_BLOB, POSEIDON2_PERM_WASM_BLOB,
	},
	RvmRunner,
};

// Reference value: blake2b_bench() hashes a 1024-byte msg where msg[i] =
// (i & 0xFF) as u8, then returns the first 4 bytes of the digest as a
// little-endian u32. Compute on host so we can assert the VMs agree.
fn expected() -> u32 {
	use blake2::{
		digest::{consts::U32, Digest},
		Blake2b,
	};
	let mut msg = [0u8; 1024];
	for i in 0..1024 {
		msg[i] = (i & 0xFF) as u8;
	}
	let mut hasher = Blake2b::<U32>::new();
	hasher.update(msg);
	let result = hasher.finalize();
	u32::from_le_bytes([result[0], result[1], result[2], result[3]])
}

fn check_workload(
	name: &str,
	javm: &[u8],
	polkavm: &[u8],
	wasm: &[u8],
	want: Option<u32>,
) {
	println!(
		"\n=== {name} === sizes: javm={}B  polkavm={}B  wasm={}B",
		javm.len(),
		polkavm.len(),
		wasm.len(),
	);
	if let Some(w) = want {
		println!("expected = {w:#010x} ({w})");
	}

	let mut first: Option<u32> = None;
	for (label, res) in [
		("javm-interpreter", run_javm_int(javm)),
		("javm-recompiler", run_javm_rec(javm)),
		("polkavm-interp", run_pvm_int(polkavm)),
		("polkavm-comp", run_pvm_com(polkavm)),
		("wasmtime-cl", run_wt_cl(wasm)),
		("wasmtime-winch", run_wt_w(wasm)),
	] {
		match res {
			Ok(v) => {
				let v32 = v as u32;
				let agreement = match first {
					None => {
						first = Some(v32);
						"FIRST".to_string()
					},
					Some(f) if f == v32 => "AGREE".to_string(),
					Some(f) => format!("DISAGREE (first was {f:#010x})"),
				};
				let vs_want = match want {
					Some(w) if v32 == w => " ✓",
					Some(_) => " ✗",
					None => "",
				};
				println!("{label:>18}: result={:#010x} {} {}", v32, agreement, vs_want);
			},
			Err(e) => println!("{label:>18}: ERR {e}"),
		}
	}
}

fn main() {
	check_workload(
		"blake2b",
		BLAKE2B_JAVM_BLOB,
		BLAKE2B_POLKAVM_BLOB,
		BLAKE2B_WASM_BLOB,
		Some(expected()),
	);
	// mini-verifier has no separate native reference (we'd have to hand-port the
	// algorithm). Cross-VM agreement is the correctness check; AGREE across all
	// six backends means the deterministic accumulator landed on the same value.
	check_workload(
		"goldilocks_mul",
		GOLDILOCKS_MUL_JAVM_BLOB,
		GOLDILOCKS_MUL_POLKAVM_BLOB,
		GOLDILOCKS_MUL_WASM_BLOB,
		None,
	);
	check_workload(
		"poseidon2_perm",
		POSEIDON2_PERM_JAVM_BLOB,
		POSEIDON2_PERM_POLKAVM_BLOB,
		POSEIDON2_PERM_WASM_BLOB,
		None,
	);
	check_workload(
		"mini_verifier",
		MINI_VERIFIER_JAVM_BLOB,
		MINI_VERIFIER_POLKAVM_BLOB,
		MINI_VERIFIER_WASM_BLOB,
		None,
	);
	check_workload(
		"fri_fold_tree",
		FRI_FOLD_TREE_JAVM_BLOB,
		FRI_FOLD_TREE_POLKAVM_BLOB,
		FRI_FOLD_TREE_WASM_BLOB,
		None,
	);
	check_workload(
		"fri_fold_tree_large",
		FRI_FOLD_TREE_LARGE_JAVM_BLOB,
		FRI_FOLD_TREE_LARGE_POLKAVM_BLOB,
		FRI_FOLD_TREE_LARGE_WASM_BLOB,
		None,
	);
	check_workload(
		"poly_eval",
		POLY_EVAL_JAVM_BLOB,
		POLY_EVAL_POLKAVM_BLOB,
		POLY_EVAL_WASM_BLOB,
		None,
	);
	check_workload(
		"batch_inverse",
		BATCH_INVERSE_JAVM_BLOB,
		BATCH_INVERSE_POLKAVM_BLOB,
		BATCH_INVERSE_WASM_BLOB,
		None,
	);
}

fn run_javm_int(b: &[u8]) -> Result<u64, String> {
	JavmRunner::interpreter().run(b, &[]).map(|o| o.result_a0)
}
fn run_javm_rec(b: &[u8]) -> Result<u64, String> {
	#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
	{
		JavmRunner::recompiler().run(b, &[]).map(|o| o.result_a0)
	}
	#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
	{
		Err("javm-recompiler not on this platform".into())
	}
}
fn run_pvm_int(b: &[u8]) -> Result<u64, String> {
	PolkaVmRunner::interpreter()?.run(b, &[]).map(|o| o.result_a0)
}
fn run_pvm_com(b: &[u8]) -> Result<u64, String> {
	PolkaVmRunner::compiler()?.run(b, &[]).map(|o| o.result_a0)
}
fn run_wt_cl(b: &[u8]) -> Result<u64, String> {
	WasmtimeRunner::cranelift()?.run(b, &[]).map(|o| o.result_a0)
}
fn run_wt_w(b: &[u8]) -> Result<u64, String> {
	WasmtimeRunner::winch()?.run(b, &[]).map(|o| o.result_a0)
}
