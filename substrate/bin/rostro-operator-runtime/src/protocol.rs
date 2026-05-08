// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Wire types for the parent ↔ sidecar IPC protocol. SCALE-encoded;
//! length-prefixed by the framing layer in `main.rs`.
//!
//! v1 supports two commands. The richer command set (typed args
//! invocation, signature requests, store ops) comes in subsequent
//! versions. Discriminants are stable; new commands append.

use codec::{Decode, Encode};

/// Command sent from parent to sidecar.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum Command {
	/// Smoke test. Sidecar responds with [`Response::Pong`] echoing
	/// the same nonce. No WASM involvement.
	Ping(u64),

	/// Invoke an exported WASM function that takes no arguments and
	/// returns a `u32`. Returns [`Response::InvokeOk`] on success or
	/// [`Response::InvokeErr`] with a stringified failure reason.
	Invoke {
		/// Name of the WASM export to call.
		method: String,
	},
}

/// Response sent from sidecar back to parent.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum Response {
	/// Echo of [`Command::Ping`]'s nonce.
	Pong(u64),

	/// WASM invocation completed; `value` is the function's `u32`
	/// return value.
	InvokeOk { value: u32 },

	/// WASM invocation failed (export missing, trap, type mismatch,
	/// etc.). `reason` is a human-readable diagnostic; the sidecar
	/// process itself stays alive for the next command.
	InvokeErr { reason: String },
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn ping_roundtrip() {
		let c = Command::Ping(0xDEADBEEF_CAFEBABE);
		let bytes = c.encode();
		assert_eq!(Command::decode(&mut &bytes[..]).unwrap(), c);
	}

	#[test]
	fn invoke_roundtrip() {
		let c = Command::Invoke { method: "ping".into() };
		let bytes = c.encode();
		assert_eq!(Command::decode(&mut &bytes[..]).unwrap(), c);
	}

	#[test]
	fn pong_roundtrip() {
		let r = Response::Pong(42);
		let bytes = r.encode();
		assert_eq!(Response::decode(&mut &bytes[..]).unwrap(), r);
	}

	#[test]
	fn invoke_ok_roundtrip() {
		let r = Response::InvokeOk { value: 0x1234_5678 };
		let bytes = r.encode();
		assert_eq!(Response::decode(&mut &bytes[..]).unwrap(), r);
	}

	#[test]
	fn invoke_err_roundtrip() {
		let r = Response::InvokeErr { reason: "no such export".into() };
		let bytes = r.encode();
		assert_eq!(Response::decode(&mut &bytes[..]).unwrap(), r);
	}
}
