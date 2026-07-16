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

//! A set of common definitions that are needed for defining execution engines.

#![warn(missing_docs)]
#![deny(unused_crate_dependencies)]

// wasm-cull W4: `runtime_blob` (wasm module parsing via wasm-instrument),
// `wasm_runtime` (WasmModule/WasmInstance engine traits + heap-alloc
// strategies) and `util` were deleted with the wasm executors — RostroVM
// blobs are the only runtime format and `rostro-executor` owns their
// loading. The error vocabulary the client stack shares is what remains.
// The `ROSTRO_DISABLE_POLKAVM` escape hatch is gone with the dual
// dispatch: there is no wasm path left to fall back to.
pub mod error;
