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

use std::{
	env,
	path::{Path, PathBuf},
	process,
};

use crate::RuntimeTarget;

// wasm-cull W5: the `metadata-hash` feature (`MetadataExtraInfo`,
// `enable_metadata_hash`) was deleted with the wasm runtime target.

/// Returns the manifest dir from the `CARGO_MANIFEST_DIR` env.
fn get_manifest_dir() -> PathBuf {
	env::var("CARGO_MANIFEST_DIR")
		.expect("`CARGO_MANIFEST_DIR` is always set for `build.rs` files; qed")
		.into()
}

/// First step of the [`WasmBuilder`] to select the project to build.
pub struct WasmBuilderSelectProject {
	/// This parameter just exists to make it impossible to construct
	/// this type outside of this crate.
	_ignore: (),
}

impl WasmBuilderSelectProject {
	/// Use the current project as project for building the WASM binary.
	///
	/// # Panics
	///
	/// Panics if the `CARGO_MANIFEST_DIR` variable is not set. This variable
	/// is always set by `Cargo` in `build.rs` files.
	pub fn with_current_project(self) -> WasmBuilder {
		WasmBuilder {
			rust_flags: Vec::new(),
			file_name: None,
			project_cargo_toml: get_manifest_dir().join("Cargo.toml"),
			features_to_enable: Vec::new(),
		}
	}

	/// Use the given `path` as project for building the WASM binary.
	///
	/// Returns an error if the given `path` does not points to a `Cargo.toml`.
	pub fn with_project(self, path: impl Into<PathBuf>) -> Result<WasmBuilder, &'static str> {
		let path = path.into();

		if path.ends_with("Cargo.toml") && path.exists() {
			Ok(WasmBuilder {
				rust_flags: Vec::new(),
				file_name: None,
				project_cargo_toml: path,
				features_to_enable: Vec::new(),
			})
		} else {
			Err("Project path must point to the `Cargo.toml` of the project")
		}
	}
}

/// The builder for building a wasm binary.
///
/// The builder itself is separated into multiple structs to make the setup type safe.
///
/// Building a wasm binary:
///
/// 1. Call [`WasmBuilder::new`] to create a new builder.
/// 2. Select the project to build using the methods of [`WasmBuilderSelectProject`].
/// 3. Set additional `RUST_FLAGS` or a different name for the file containing the WASM code using
///    methods of [`WasmBuilder`].
/// 4. Build the WASM binary using [`Self::build`].
pub struct WasmBuilder {
	/// Flags that should be appended to `RUST_FLAGS` env variable.
	rust_flags: Vec<String>,
	/// The name of the file that is being generated in `OUT_DIR`.
	///
	/// Defaults to `wasm_binary.rs`.
	file_name: Option<String>,
	/// The path to the `Cargo.toml` of the project that should be built
	/// for wasm.
	project_cargo_toml: PathBuf,
	/// Features that should be enabled when building the wasm binary.
	features_to_enable: Vec<String>,
}

impl WasmBuilder {
	/// Create a new instance of the builder.
	pub fn new() -> WasmBuilderSelectProject {
		WasmBuilderSelectProject { _ignore: () }
	}

	/// Build the WASM binary using the recommended default values.
	///
	/// This is the same as calling:
	/// ```no_run
	/// substrate_wasm_builder::WasmBuilder::new()
	///    .with_current_project()
	///    .import_memory()
	///    .export_heap_base()
	///    .build();
	/// ```
	pub fn build_using_defaults() {
		WasmBuilder::new()
			.with_current_project()
			.import_memory()
			.export_heap_base()
			.build();
	}

	/// Init the wasm builder with the recommended default values.
	///
	/// In contrast to [`Self::build_using_defaults`] it does not build the WASM binary directly.
	///
	/// This is the same as calling:
	/// ```no_run
	/// substrate_wasm_builder::WasmBuilder::new()
	///    .with_current_project()
	///    .import_memory()
	///    .export_heap_base();
	/// ```
	pub fn init_with_defaults() -> Self {
		WasmBuilder::new().with_current_project().import_memory().export_heap_base()
	}

	/// Enable exporting `__heap_base` as global variable in the WASM binary.
	///
	/// This was only used by the removed wasm runtime target and is a no-op now. It is kept so
	/// that existing `build.rs` files continue to compile.
	pub fn export_heap_base(self) -> Self {
		self
	}

	/// Set the name of the file that will be generated in `OUT_DIR`.
	///
	/// This file needs to be included to get access to the build WASM binary.
	///
	/// If this function is not called, `file_name` defaults to `wasm_binary.rs`
	pub fn set_file_name(mut self, file_name: impl Into<String>) -> Self {
		self.file_name = Some(file_name.into());
		self
	}

	/// Instruct the linker to import the memory into the WASM binary.
	///
	/// This was only used by the removed wasm runtime target and is a no-op now. It is kept so
	/// that existing `build.rs` files continue to compile.
	pub fn import_memory(self) -> Self {
		self
	}

	/// Append the given `flag` to `RUST_FLAGS`.
	///
	/// `flag` is appended as is, so it needs to be a valid flag.
	pub fn append_to_rust_flags(mut self, flag: impl Into<String>) -> Self {
		self.rust_flags.push(flag.into());
		self
	}

	/// Enable the given feature when building the wasm binary.
	///
	/// `feature` needs to be a valid feature that is defined in the project `Cargo.toml`.
	pub fn enable_feature(mut self, feature: impl Into<String>) -> Self {
		self.features_to_enable.push(feature.into());
		self
	}

	/// Disable the check for the `runtime_version` wasm section.
	///
	/// The `runtime_version` section check only applied to the removed wasm runtime target, so
	/// this is a no-op now. It is kept so that existing `build.rs` files continue to compile.
	pub fn disable_runtime_version_section_check(self) -> Self {
		self
	}

	/// Build the WASM binary.
	pub fn build(self) {
		let target = RuntimeTarget::new();

		let out_dir = PathBuf::from(env::var("OUT_DIR").expect("`OUT_DIR` is set by cargo!"));
		let file_path =
			out_dir.join(self.file_name.clone().unwrap_or_else(|| "wasm_binary.rs".into()));

		if check_skip_build() {
			// If we skip the build, we still want to make sure to be called when an env variable
			// changes
			generate_rerun_if_changed_instructions();

			provide_dummy_wasm_binary_if_not_exist(&file_path);

			return;
		}

		build_project(
			target,
			file_path,
			self.project_cargo_toml,
			self.rust_flags.join(" "),
			self.features_to_enable,
			self.file_name,
		);

		// As last step we need to generate our `rerun-if-changed` stuff. If a build fails, we don't
		// want to spam the output!
		generate_rerun_if_changed_instructions();
	}
}

/// Generate the name of the skip build environment variable for the current crate.
fn generate_crate_skip_build_env_name() -> String {
	format!(
		"SKIP_{}_WASM_BUILD",
		env::var("CARGO_PKG_NAME")
			.expect("Package name is set")
			.to_uppercase()
			.replace('-', "_"),
	)
}

/// Checks if the build of the WASM binary should be skipped.
fn check_skip_build() -> bool {
	env::var(crate::SKIP_BUILD_ENV).is_ok() ||
		env::var(generate_crate_skip_build_env_name()).is_ok() ||
		// If we are running in docs.rs, let's skip building.
		// https://docs.rs/about/builds#detecting-docsrs
		env::var("DOCS_RS").is_ok()
}

/// Provide a dummy WASM binary if there doesn't exist one.
fn provide_dummy_wasm_binary_if_not_exist(file_path: &Path) {
	if !file_path.exists() {
		crate::write_file_if_changed(
			file_path,
			"pub const WASM_BINARY_PATH: Option<&str> = None;\
			 pub const WASM_BINARY: Option<&[u8]> = None;\
			 pub const WASM_BINARY_BLOATY: Option<&[u8]> = None;",
		);
	}
}

/// Generate the `rerun-if-changed` instructions for cargo to make sure that the WASM binary is
/// rebuilt when needed.
fn generate_rerun_if_changed_instructions() {
	// Make sure that the `build.rs` is called again if one of the following env variables changes.
	println!("cargo:rerun-if-env-changed={}", crate::SKIP_BUILD_ENV);
	println!("cargo:rerun-if-env-changed={}", crate::FORCE_WASM_BUILD_ENV);
	println!("cargo:rerun-if-env-changed={}", generate_crate_skip_build_env_name());
}

/// Build the currently built project as wasm binary.
///
/// The current project is determined by using the `CARGO_MANIFEST_DIR` environment variable.
///
/// `file_name` - The name + path of the file being generated. The file contains the
/// constant `WASM_BINARY`, which contains the built wasm binary.
///
/// `project_cargo_toml` - The path to the `Cargo.toml` of the project that should be built.
///
/// `default_rustflags` - Default `RUSTFLAGS` that will always be set for the build.
///
/// `features_to_enable` - Features that should be enabled for the project.
///
/// `wasm_binary_name` - The optional runtime blob name. If `None`, the project name will be
/// used.
fn build_project(
	target: RuntimeTarget,
	file_name: PathBuf,
	project_cargo_toml: PathBuf,
	default_rustflags: String,
	features_to_enable: Vec<String>,
	wasm_binary_name: Option<String>,
) {
	// Init jobserver as soon as possible
	crate::wasm_project::get_jobserver();
	let cargo_cmd = match crate::prerequisites::check(target) {
		Ok(cmd) => cmd,
		Err(err_msg) => {
			eprintln!("{err_msg}");
			process::exit(1);
		},
	};

	let bloaty = crate::wasm_project::create_and_compile(
		target,
		&project_cargo_toml,
		&default_rustflags,
		cargo_cmd,
		features_to_enable,
		wasm_binary_name,
	);

	// wasm-cull W5: the compact/compressed wasm variants were deleted with the wasm runtime
	// target; the riscv blob was always emitted uncompacted, so both constants point to it.
	let (wasm_binary, wasm_binary_bloaty) =
		(bloaty.bloaty_path_escaped(), bloaty.bloaty_path_escaped());

	crate::write_file_if_changed(
		file_name,
		format!(
			r#"
				pub const WASM_BINARY_PATH: Option<&str> = Some("{wasm_binary_path}");
				pub const WASM_BINARY: Option<&[u8]> = Some(include_bytes!("{wasm_binary}"));
				pub const WASM_BINARY_BLOATY: Option<&[u8]> = Some(include_bytes!("{wasm_binary_bloaty}"));
			"#,
			wasm_binary_path = wasm_binary,
			wasm_binary = wasm_binary,
			wasm_binary_bloaty = wasm_binary_bloaty,
		),
	);
}
