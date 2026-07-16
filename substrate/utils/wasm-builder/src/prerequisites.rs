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

use crate::{write_file_if_changed, CargoCommand, CargoCommandVersioned, RuntimeTarget};

use console::style;
use std::{fs, path::PathBuf, process::Command};

use tempfile::tempdir;

// wasm-cull W5: the wasm toolchain checks (`check_wasm_toolchain_installed` and
// its sysroot/target-installed probing) were deleted with the wasm runtime target.

/// Colorizes an error message, if color output is enabled.
fn colorize_error_message(message: &str) -> String {
	if super::color_output_enabled() {
		style(message).red().bold().to_string()
	} else {
		message.into()
	}
}

/// Checks that all prerequisites are installed.
///
/// Returns the versioned cargo command on success.
pub(crate) fn check(target: RuntimeTarget) -> Result<CargoCommandVersioned, String> {
	let cargo_command = crate::get_cargo_command(target);

	if !cargo_command.supports_substrate_runtime_env(target) {
		return Err(colorize_error_message(
			"Cannot compile a RISC-V runtime: no compatible Rust compiler found!\n\
			 Install a toolchain from here and try again: https://github.com/paritytech/rustc-rv32e-toolchain/",
		));
	}

	let dummy_crate = DummyCrate::new(&cargo_command, target, false);
	let version = dummy_crate.get_rustc_version();
	Ok(CargoCommandVersioned::new(cargo_command, version))
}

pub(crate) struct DummyCrate<'a> {
	cargo_command: &'a CargoCommand,
	temp: tempfile::TempDir,
	manifest_path: PathBuf,
	target: RuntimeTarget,
	ignore_target: bool,
}

impl<'a> DummyCrate<'a> {
	/// Creates a minimal dummy crate.
	pub(crate) fn new(
		cargo_command: &'a CargoCommand,
		target: RuntimeTarget,
		ignore_target: bool,
	) -> Self {
		let temp = tempdir().expect("Creating temp dir does not fail; qed");
		let project_dir = temp.path();
		fs::create_dir_all(project_dir.join("src")).expect("Creating src dir does not fail; qed");

		let manifest_path = project_dir.join("Cargo.toml");
		write_file_if_changed(
			&manifest_path,
			r#"
						[package]
						name = "dummy-crate"
						version = "1.0.0"
						edition = "2021"

						[workspace]
					"#,
		);

		write_file_if_changed(
			project_dir.join("src/main.rs"),
			"#![allow(missing_docs)] fn main() {}",
		);

		DummyCrate { cargo_command, temp, manifest_path, target, ignore_target }
	}

	fn prepare_command(&self, subcommand: &str) -> Command {
		let mut cmd = self.cargo_command.command();
		// Chdir to temp to avoid including project's .cargo/config.toml
		// by accident - it can happen in some CI environments.
		cmd.current_dir(&self.temp);
		cmd.arg(subcommand);
		if !self.ignore_target {
			cmd.arg(format!("--target={}", self.target.rustc_target()));
		}
		cmd.args(&["--manifest-path", &self.manifest_path.display().to_string()]);

		if super::color_output_enabled() {
			cmd.arg("--color=always");
		}

		// manually set the `CARGO_TARGET_DIR` to prevent a cargo deadlock
		let target_dir = self.temp.path().join("target").display().to_string();
		cmd.env("CARGO_TARGET_DIR", &target_dir);

		// Make sure the host's flags aren't used here, e.g. if an alternative linker is specified
		// in the RUSTFLAGS then the check we do here will break unless we clear these.
		cmd.env_remove("CARGO_ENCODED_RUSTFLAGS");
		cmd.env_remove("RUSTFLAGS");
		// Make sure if we're called from within a `build.rs` the host toolchain won't override a
		// rustup toolchain we've picked.
		cmd.env_remove("RUSTC");
		cmd
	}

	fn get_rustc_version(&self) -> String {
		let mut run_cmd = self.prepare_command("rustc");
		run_cmd.args(&["-q", "--", "--version"]);
		run_cmd
			.output()
			.ok()
			.and_then(|o| String::from_utf8(o.stdout).ok())
			.unwrap_or_else(|| "unknown rustc version".into())
	}

}
