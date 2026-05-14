// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Rostro Foundation
//
// Cross-compile vendored bench services (services/<name>/) to three guest
// targets: javm, polkavm, and wasm32v1-none. Emits a `guest_blobs.rs` into
// OUT_DIR with `include_bytes!` consts the bench code can load.
//
// Set `SKIP_GUEST_BUILD=1` to skip all three builds (the helpers fall back
// to empty placeholder blobs — useful for `cargo check` cycles that don't
// need to actually execute the blobs).

use std::path::PathBuf;
use std::process::Command;

struct Service {
	/// Subdirectory under `services/` (also the cargo crate dir name).
	dir: &'static str,
	/// `bin_name` argument that build-javm uses to find the produced ELF.
	/// Must match the crate's `[[bin]]` name (or the package name if implicit).
	bin_name: &'static str,
	/// Symbol prefix used in generated `guest_blobs.rs` (e.g. `BLAKE2B`).
	const_prefix: &'static str,
}

const SERVICES: &[Service] = &[
	Service {
		dir: "blake2b",
		bin_name: "rostro-bench-blake2b",
		const_prefix: "BLAKE2B",
	},
	Service {
		dir: "mini-verifier",
		bin_name: "rostro-bench-mini-verifier",
		const_prefix: "MINI_VERIFIER",
	},
	Service {
		dir: "goldilocks-mul",
		bin_name: "rostro-bench-goldilocks-mul",
		const_prefix: "GOLDILOCKS_MUL",
	},
	Service {
		dir: "poseidon2-perm",
		bin_name: "rostro-bench-poseidon2-perm",
		const_prefix: "POSEIDON2_PERM",
	},
	Service {
		dir: "fri-fold-tree",
		bin_name: "rostro-bench-fri-fold-tree",
		const_prefix: "FRI_FOLD_TREE",
	},
	Service {
		dir: "fri-fold-tree-large",
		bin_name: "rostro-bench-fri-fold-tree-large",
		const_prefix: "FRI_FOLD_TREE_LARGE",
	},
	Service {
		dir: "poly-eval",
		bin_name: "rostro-bench-poly-eval",
		const_prefix: "POLY_EVAL",
	},
	Service {
		dir: "batch-inverse",
		bin_name: "rostro-bench-batch-inverse",
		const_prefix: "BATCH_INVERSE",
	},
	Service {
		dir: "ed25519",
		bin_name: "rostro-bench-ed25519",
		const_prefix: "ED25519",
	},
	Service {
		dir: "ecrecover",
		bin_name: "rostro-bench-ecrecover",
		const_prefix: "ECRECOVER",
	},
	Service {
		dir: "keccak",
		bin_name: "rostro-bench-keccak",
		const_prefix: "KECCAK",
	},
	Service {
		dir: "dilithium",
		bin_name: "rostro-bench-dilithium",
		const_prefix: "DILITHIUM",
	},
	Service {
		dir: "dilithium-verify-only",
		bin_name: "rostro-bench-dilithium-verify-only",
		const_prefix: "DILITHIUM_VERIFY_ONLY",
	},
	Service {
		dir: "p521",
		bin_name: "rostro-bench-p521",
		const_prefix: "P521",
	},
	Service {
		dir: "curve-conversion",
		bin_name: "rostro-bench-curve-conversion",
		const_prefix: "CURVE_CONVERSION",
	},
	Service {
		dir: "trace-shapes-suite",
		bin_name: "rostro-bench-trace-shapes-suite",
		const_prefix: "TRACE_SHAPES_SUITE",
	},
];

fn main() {
	let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
	let mut decls = String::new();

	for svc in SERVICES {
		let manifest = format!("services/{}", svc.dir);
		let javm_path = build_javm::build(&manifest, svc.bin_name);
		let pvm_path = build_pvm::build(&manifest);
		let wasm_path = build_wasm32(svc);

		decls.push_str(&format!(
			"pub const {p}_JAVM_BLOB: &[u8] = include_bytes!({:?});\n\
			 pub const {p}_POLKAVM_BLOB: &[u8] = include_bytes!({:?});\n\
			 pub const {p}_WASM_BLOB: &[u8] = include_bytes!({:?});\n",
			javm_path, pvm_path, wasm_path,
			p = svc.const_prefix,
		));
	}

	std::fs::write(format!("{out_dir}/guest_blobs.rs"), decls)
		.expect("write guest_blobs.rs");
}

/// Cross-compile a service crate to `wasm32v1-none` via a nested `cargo build`.
///
/// Uses a separate `CARGO_TARGET_DIR` to avoid deadlocking with the outer
/// build process (mirrors `build-crate`'s pattern).
fn build_wasm32(svc: &Service) -> PathBuf {
	let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
	let svc_dir = PathBuf::from(&manifest_dir).join("services").join(svc.dir);
	let manifest_path = svc_dir.join("Cargo.toml");

	// Watch the source tree so cargo re-runs build.rs when service code changes.
	emit_rerun_for_dir(&svc_dir.join("src"));
	println!("cargo:rerun-if-changed={}", manifest_path.display());

	let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR");
	let target_dir = PathBuf::from(&out_dir).join("wasm32-build");
	let lib_name = svc.bin_name.replace('-', "_");
	let wasm_out = target_dir
		.join("wasm32v1-none")
		.join("release")
		.join(format!("{lib_name}.wasm"));

	if std::env::var("SKIP_GUEST_BUILD").is_ok() {
		if !wasm_out.exists() {
			std::fs::create_dir_all(wasm_out.parent().unwrap()).ok();
			std::fs::write(&wasm_out, b"").ok();
		}
		return wasm_out;
	}

	let status = Command::new("cargo")
		.arg("build")
		.arg("--release")
		.arg("--manifest-path")
		.arg(&manifest_path)
		.arg("--target")
		.arg("wasm32v1-none")
		.arg("--lib")
		.env("CARGO_TARGET_DIR", &target_dir)
		.env("BUILD_CRATE_GUEST_BUILD", "1")
		.status()
		.expect("spawn cargo for wasm32 build");

	assert!(status.success(), "wasm32 build failed for {}", svc.dir);
	assert!(wasm_out.exists(), "wasm32 artifact not at {}", wasm_out.display());
	wasm_out
}

fn emit_rerun_for_dir(dir: &std::path::Path) {
	if let Ok(entries) = std::fs::read_dir(dir) {
		for entry in entries.flatten() {
			let path = entry.path();
			if path.is_dir() {
				emit_rerun_for_dir(&path);
			} else {
				println!("cargo:rerun-if-changed={}", path.display());
			}
		}
	}
}
