// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! `rostro-operator-runtime` — operator-private WASM sidecar.
//!
//! Phase 8 step 1.
//!
//! Loads the operator's private WASM blob from a local file path,
//! hosts it via wasmtime, and runs a synchronous SCALE-framed
//! request/response loop on stdin (commands in) / stdout
//! (responses out). The parent process — typically `gemini-node`,
//! optionally a test harness or installer — drives the sidecar
//! through that loop. stderr is reserved for log output (via
//! `env_logger`); never write protocol bytes there.
//!
//! ## Why stdin/stdout instead of Unix sockets at v1
//!
//! Unix-domain sockets are the natural production transport on
//! Linux/macOS but require named-pipe equivalent plumbing on
//! Windows, and the protocol logic is identical regardless of the
//! transport. Stdin/stdout is portable, lets the parent attach
//! `Stdio::piped()` from any platform, and is easy to drive in
//! tests by spawning the binary with `Command::new`. A future
//! revision adds an optional `--socket <path>` flag that swaps
//! the transport without changing the protocol.
//!
//! ## Wire frame format
//!
//! `[u32-le length][SCALE-encoded payload]`
//!
//! Length-prefixed SCALE frames. Commands flow in from stdin;
//! responses flow out to stdout. Single-request-at-a-time semantics
//! — the protocol is synchronous, the loop reads one frame, runs
//! the command (which may call into WASM), writes one frame, and
//! repeats. EOF on stdin terminates the loop with exit code 0.
//!
//! ## What's in v1
//!
//! - [`Command::Ping`] / [`Response::Pong`]: liveness smoke test, no
//!   WASM involvement.
//! - [`Command::Invoke`]: call an exported WASM function that takes
//!   no arguments and returns a `u32`. Host function `rostro::log`
//!   is bound during instantiation; the WASM can call it to emit
//!   strings to the sidecar's stderr.
//!
//! ## What's NOT in v1
//!
//! - Typed argument passing (just `Invoke { method }` for now;
//!   richer ABI is `InvokeWithArgs { method, args }` in v2 with a
//!   memory-allocator convention between host and WASM).
//! - Sidecar-private storage (sqlite-backed `store_get` / `store_put`
//!   host functions).
//! - Signature requests (the host function that asks gemini-node to
//!   sign payloads with the operator's key — needs the IPC channel
//!   reversed so the sidecar can issue requests, not just respond).
//! - HTTP egress with allowlist.
//! - Crash isolation policy (currently a panic in WASM bubbles up to
//!   the Rust runtime; richer recovery comes with the request/response
//!   error types in v2).

use clap::Parser;
use codec::{Decode, Encode};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

mod protocol;
mod runtime;

use protocol::{Command, Response};
use runtime::OperatorRuntime;

#[derive(Parser, Debug)]
#[command(
	name = "rostro-operator-runtime",
	version,
	about = "Sidecar process hosting an operator's private WASM blob."
)]
struct Args {
	/// Path to the operator's WASM blob. Loaded once at startup.
	#[arg(long)]
	operator_wasm: PathBuf,
}

fn main() -> ExitCode {
	let _ = env_logger::Builder::from_env(
		env_logger::Env::default().default_filter_or("info"),
	)
	.try_init();

	let args = Args::parse();
	let runtime = match OperatorRuntime::load(&args.operator_wasm) {
		Ok(r) => r,
		Err(e) => {
			log::error!("failed to load operator WASM at {}: {}", args.operator_wasm.display(), e);
			return ExitCode::FAILURE;
		},
	};

	log::info!("rostro-operator-runtime ready; operator WASM loaded from {}", args.operator_wasm.display());

	if let Err(e) = run_loop(runtime) {
		log::error!("sidecar loop terminated with error: {}", e);
		return ExitCode::FAILURE;
	}
	ExitCode::SUCCESS
}

fn run_loop(mut runtime: OperatorRuntime) -> Result<(), Box<dyn std::error::Error>> {
	let mut stdin = std::io::stdin().lock();
	let mut stdout = std::io::stdout().lock();
	loop {
		let frame = match read_frame(&mut stdin)? {
			Some(b) => b,
			None => return Ok(()), // clean EOF
		};
		let cmd = Command::decode(&mut &frame[..])
			.map_err(|e| format!("protocol decode error: {e}"))?;
		let resp = handle(&mut runtime, cmd);
		write_frame(&mut stdout, &resp.encode())?;
	}
}

fn handle(runtime: &mut OperatorRuntime, cmd: Command) -> Response {
	match cmd {
		Command::Ping(nonce) => Response::Pong(nonce),
		Command::Invoke { method } => match runtime.invoke_no_args(&method) {
			Ok(value) => Response::InvokeOk { value },
			Err(e) => Response::InvokeErr { reason: e.to_string() },
		},
	}
}

fn read_frame<R: Read>(r: &mut R) -> std::io::Result<Option<Vec<u8>>> {
	let mut len_buf = [0u8; 4];
	match r.read_exact(&mut len_buf) {
		Ok(()) => {},
		Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
		Err(e) => return Err(e),
	}
	let len = u32::from_le_bytes(len_buf) as usize;
	let mut payload = vec![0u8; len];
	r.read_exact(&mut payload)?;
	Ok(Some(payload))
}

fn write_frame<W: Write>(w: &mut W, payload: &[u8]) -> std::io::Result<()> {
	let len = u32::try_from(payload.len()).map_err(|_| {
		std::io::Error::new(std::io::ErrorKind::InvalidInput, "response > u32 max")
	})?;
	w.write_all(&len.to_le_bytes())?;
	w.write_all(payload)?;
	w.flush()
}
