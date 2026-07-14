// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Runtime-executor trait vocabulary for the client stack.
//!
//! wasm-cull W4: the wasm execution engines are gone. `WasmExecutor`
//! (wasmtime-backed) and `NativeElseWasmExecutor` were deleted together
//! with the `wasmtime-backend` feature; `RostroCodeExecutor`
//! (`rostro-executor`, RostroVM) is the only runtime executor. What
//! remains here is the executor-facing trait vocabulary and error types
//! the client stack is written against: [`RuntimeVersionOf`], the
//! [`error`] module, and the host-function re-exports.

#![warn(missing_docs)]

pub use codec::Codec;
#[doc(hidden)]
pub use sp_core::traits::Externalities;
pub use sp_version::{NativeVersion, RuntimeVersion};
#[doc(hidden)]
pub use sp_wasm_interface;
pub use sp_wasm_interface::HostFunctions;

pub use rc_executor_common::error;

/// Extracts the runtime version of a given runtime code.
pub trait RuntimeVersionOf {
	/// Extract [`RuntimeVersion`] of the given `runtime_code`.
	fn runtime_version(
		&self,
		ext: &mut dyn Externalities,
		runtime_code: &sp_core::traits::RuntimeCode,
	) -> error::Result<RuntimeVersion>;
}
