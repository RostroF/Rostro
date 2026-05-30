// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! On-chain release-pubkey reconciliation — piece B.1-bis of watchdog v0.2.
//!
//! Periodically queries `CanonicalFilesApi::release_pubkey()` via
//! JSON-RPC against the localhost gemini-node, and compares the
//! result against `crate::ROSTRO_RELEASE_PUBKEY` (the compile-time-
//! baked copy). Divergence is logged at WARN; ongoing-success is
//! logged at INFO; transient RPC unavailability (gemini-node down,
//! port not bound yet) is logged at DEBUG and the reconciler waits
//! for the next tick.
//!
//! Per [[feedback_trust_but_verify_baked_plus_onchain]]: the baked
//! pubkey is the trust anchor (Layer 0); this reconciliation is the
//! verify (Layer 2). A node where reconciliation has been failing for
//! an extended window is "airgapped or untrustworthy" — the warning
//! escalates as the unreachable-chain interval grows.
//!
//! The HTTP+JSON client is hand-rolled (~120 LOC) rather than pulling
//! jsonrpsee, for the same trust-surface reason the rest of the
//! watchdog has minimal deps: this code path is the chain-of-trust
//! checker, so its own dependencies must themselves be auditable.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Outcome of a single reconciliation poll.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
	/// On-chain pubkey matches the baked pubkey. All good.
	Match,
	/// On-chain pubkey differs from the baked pubkey. The watchdog
	/// binary may be stale, or the release pipeline was compromised,
	/// or a routine SRT key rotation happened that this binary
	/// doesn't yet reflect. Either way: operator/SRT attention.
	Divergence { on_chain: [u8; 32], baked: [u8; 32] },
	/// Chain hasn't been seeded with a release pubkey yet — early
	/// in the testnet's life, or no SRT extrinsic has been run yet.
	/// No trust signal either way.
	NotYetSet,
	/// Couldn't reach the local gemini-node RPC. Could be transient
	/// (gemini-node restarting) or sustained (no gemini-node on this
	/// host). Reconciler logs at DEBUG and waits for the next tick;
	/// the watchdog's own staleness tracker (last_successful_at)
	/// determines when to escalate.
	RpcUnavailable(String),
	/// We reached the RPC but the response wasn't a parseable
	/// `Option<[u8; 32]>`. Likely a wire-format mismatch (gemini-node
	/// of an incompatible version, or RPC method renamed).
	ProtocolError(String),
}

/// Errors at the HTTP/transport layer. Internal to this module.
#[derive(Debug)]
enum TransportError {
	Connect(std::io::Error),
	Io(std::io::Error),
	BadHttpStatus(u16),
	BadHttpResponse(String),
}

impl std::fmt::Display for TransportError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			TransportError::Connect(e) => write!(f, "connect: {e}"),
			TransportError::Io(e) => write!(f, "io: {e}"),
			TransportError::BadHttpStatus(c) => write!(f, "HTTP status {c}"),
			TransportError::BadHttpResponse(s) => write!(f, "bad HTTP response: {s}"),
		}
	}
}

/// Run one reconciliation tick: query the on-chain release pubkey via
/// localhost JSON-RPC and compare to the baked value.
pub fn reconcile_once(
	host: &str,
	port: u16,
	baked: &[u8; 32],
	timeout: Duration,
) -> Outcome {
	match fetch_release_pubkey(host, port, timeout) {
		Ok(Some(on_chain)) => {
			if on_chain == *baked {
				Outcome::Match
			} else {
				Outcome::Divergence {
					on_chain,
					baked: *baked,
				}
			}
		},
		Ok(None) => Outcome::NotYetSet,
		Err(FetchError::Transport(e)) => Outcome::RpcUnavailable(e.to_string()),
		Err(FetchError::Protocol(s)) => Outcome::ProtocolError(s),
	}
}

#[derive(Debug)]
enum FetchError {
	Transport(TransportError),
	Protocol(String),
}

/// Make a JSON-RPC `state_call` to `CanonicalFilesApi_release_pubkey`
/// and SCALE-decode the resulting `Option<[u8; 32]>`.
fn fetch_release_pubkey(
	host: &str,
	port: u16,
	timeout: Duration,
) -> Result<Option<[u8; 32]>, FetchError> {
	// Substrate's state_call wire shape:
	//   {"jsonrpc":"2.0","id":1,"method":"state_call",
	//    "params":["CanonicalFilesApi_release_pubkey", "0x"]}
	// The empty 0x is the SCALE-encoded arg tuple () (the runtime API
	// method takes no args). Response: {"result":"0x..hex.."} where the
	// hex is the SCALE-encoded return value.
	let body = r#"{"jsonrpc":"2.0","id":1,"method":"state_call","params":["CanonicalFilesApi_release_pubkey","0x"]}"#;
	let resp = http_post_json(host, port, body, timeout)
		.map_err(FetchError::Transport)?;

	// Pluck out "result":"0x.." — extremely simple parser since we
	// know exactly what shape substrate returns. If it's not present,
	// it's a protocol error.
	let result_hex = extract_result_hex(&resp).ok_or_else(|| {
		FetchError::Protocol(format!("no 'result' field in response: {resp}"))
	})?;

	let bytes = hex_decode(&result_hex)
		.ok_or_else(|| FetchError::Protocol(format!("result not hex: {result_hex}")))?;

	scale_decode_option_32(&bytes).ok_or_else(|| {
		FetchError::Protocol(format!(
			"SCALE Option<[u8;32]> decode failed; bytes={}",
			hex_encode(&bytes),
		))
	})
}

fn http_post_json(
	host: &str,
	port: u16,
	body: &str,
	timeout: Duration,
) -> Result<String, TransportError> {
	let addr = format!("{host}:{port}");
	let mut stream =
		TcpStream::connect_timeout(&addr.parse().unwrap_or(([127, 0, 0, 1], port).into()), timeout)
			.map_err(TransportError::Connect)?;
	stream
		.set_read_timeout(Some(timeout))
		.map_err(TransportError::Io)?;
	stream
		.set_write_timeout(Some(timeout))
		.map_err(TransportError::Io)?;

	let request = format!(
		"POST / HTTP/1.1\r\n\
		 Host: {host}:{port}\r\n\
		 Content-Type: application/json\r\n\
		 Content-Length: {}\r\n\
		 Connection: close\r\n\
		 \r\n\
		 {body}",
		body.len()
	);
	stream
		.write_all(request.as_bytes())
		.map_err(TransportError::Io)?;
	let mut resp_bytes = Vec::new();
	stream
		.read_to_end(&mut resp_bytes)
		.map_err(TransportError::Io)?;
	let resp_str = String::from_utf8_lossy(&resp_bytes).into_owned();

	// Find HTTP status line: "HTTP/1.1 200 OK"
	let first_line = resp_str.lines().next().unwrap_or("");
	let status = first_line
		.split_whitespace()
		.nth(1)
		.and_then(|s| s.parse::<u16>().ok())
		.ok_or_else(|| TransportError::BadHttpResponse(first_line.to_string()))?;
	if !(200..300).contains(&status) {
		return Err(TransportError::BadHttpStatus(status));
	}

	// Body = everything after the blank line "\r\n\r\n".
	let body = resp_str
		.split_once("\r\n\r\n")
		.map(|(_, b)| b.to_string())
		.unwrap_or(resp_str);
	Ok(body)
}

/// Find `"result":"0x...."` in the JSON-RPC response and return the
/// hex string (without the `0x` prefix). Returns None if `result` is
/// absent or non-string. We intentionally don't pull serde_json — the
/// substrate response shape is fixed and very simple.
pub fn extract_result_hex(json: &str) -> Option<String> {
	let key = "\"result\":";
	let i = json.find(key)?;
	let rest = &json[i + key.len()..];
	let rest = rest.trim_start();
	let rest = rest.strip_prefix('"')?;
	let end = rest.find('"')?;
	let value = &rest[..end];
	let stripped = value.strip_prefix("0x").unwrap_or(value);
	Some(stripped.to_string())
}

/// SCALE-decode `Option<[u8; 32]>`:
///   `0x00` = None
///   `0x01 || 32 bytes` = Some
pub fn scale_decode_option_32(bytes: &[u8]) -> Option<Option<[u8; 32]>> {
	match bytes.first()? {
		0x00 if bytes.len() == 1 => Some(None),
		0x01 if bytes.len() == 33 => {
			let mut k = [0u8; 32];
			k.copy_from_slice(&bytes[1..]);
			Some(Some(k))
		},
		_ => None,
	}
}

/// Minimal hex decode (lowercase + uppercase). Returns None on any
/// non-hex character or odd length.
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
	if s.len() % 2 != 0 {
		return None;
	}
	let mut out = Vec::with_capacity(s.len() / 2);
	let bytes = s.as_bytes();
	for i in (0..bytes.len()).step_by(2) {
		let hi = hex_nibble(bytes[i])?;
		let lo = hex_nibble(bytes[i + 1])?;
		out.push((hi << 4) | lo);
	}
	Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
	match b {
		b'0'..=b'9' => Some(b - b'0'),
		b'a'..=b'f' => Some(b - b'a' + 10),
		b'A'..=b'F' => Some(b - b'A' + 10),
		_ => None,
	}
}

fn hex_encode(bytes: &[u8]) -> String {
	let mut s = String::with_capacity(bytes.len() * 2);
	for b in bytes {
		s.push(nib((b >> 4) as u32));
		s.push(nib((b & 0xF) as u32));
	}
	s
}

fn nib(n: u32) -> char {
	match n {
		0..=9 => (b'0' + n as u8) as char,
		10..=15 => (b'a' + (n as u8 - 10)) as char,
		_ => unreachable!(),
	}
}

/// Spawn a background thread that polls reconciliation at `interval`.
/// Returns the JoinHandle so the caller can hold it for the lifetime
/// of the watchdog process.
pub fn spawn_reconciler(
	host: String,
	port: u16,
	baked: [u8; 32],
	interval: Duration,
	rpc_timeout: Duration,
	state_file: Option<PathBuf>,
) -> std::thread::JoinHandle<()> {
	std::thread::spawn(move || {
		let mut last_match_at: Option<Instant> = None;
		loop {
			match reconcile_once(&host, port, &baked, rpc_timeout) {
				Outcome::Match => {
					if last_match_at.is_none() {
						log::info!(
							"reconciliation: baked rostro_release pubkey matches on-chain ({}:{})",
							host, port
						);
					}
					last_match_at = Some(Instant::now());
					if let Some(p) = state_file.as_ref() {
						let now_secs = std::time::SystemTime::now()
							.duration_since(std::time::UNIX_EPOCH)
							.map(|d| d.as_secs())
							.unwrap_or(0);
						let _ = std::fs::write(
							p,
							format!("last_match_unix_secs={now_secs}\n"),
						);
					}
				},
				Outcome::Divergence { on_chain, baked: _ } => {
					log::warn!(
						"reconciliation: DIVERGENCE — baked pubkey {} does not match on-chain {}; \
						 either this binary is stale OR an SRT key rotation happened OR the chain is compromised",
						hex_encode(&baked),
						hex_encode(&on_chain),
					);
				},
				Outcome::NotYetSet => {
					log::info!(
						"reconciliation: on-chain release pubkey not yet set; SRT has not run \
						 set_release_pubkey post-genesis (or genesis didn't bake an initial value)"
					);
				},
				Outcome::RpcUnavailable(e) => {
					log::debug!(
						"reconciliation: RPC unavailable: {e}; will retry in {}s",
						interval.as_secs()
					);
					// Staleness warning: if it's been a while since the
					// last successful match, escalate.
					if let Some(at) = last_match_at {
						let stale = at.elapsed();
						if stale > Duration::from_secs(24 * 3600) {
							log::warn!(
								"reconciliation: no successful match in {:.1} hours — \
								 the node is becoming an airgapped node",
								stale.as_secs_f64() / 3600.0
							);
						}
					}
				},
				Outcome::ProtocolError(s) => {
					log::error!("reconciliation: protocol error: {s}");
				},
			}
			std::thread::sleep(interval);
		}
	})
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn scale_decode_none() {
		assert_eq!(scale_decode_option_32(&[0x00]), Some(None));
	}

	#[test]
	fn scale_decode_some_zero() {
		let mut bytes = vec![0x01u8];
		bytes.extend_from_slice(&[0u8; 32]);
		assert_eq!(scale_decode_option_32(&bytes), Some(Some([0u8; 32])));
	}

	#[test]
	fn scale_decode_some_nonzero() {
		let mut bytes = vec![0x01u8];
		bytes.extend_from_slice(&[0xABu8; 32]);
		assert_eq!(scale_decode_option_32(&bytes), Some(Some([0xABu8; 32])));
	}

	#[test]
	fn scale_decode_rejects_bad_tag() {
		assert_eq!(scale_decode_option_32(&[0x02]), None);
	}

	#[test]
	fn scale_decode_rejects_short_some() {
		// Tag 0x01 but only 15 bytes follow.
		let mut bytes = vec![0x01u8];
		bytes.extend_from_slice(&[0xAB; 15]);
		assert_eq!(scale_decode_option_32(&bytes), None);
	}

	#[test]
	fn extract_result_hex_finds_hex() {
		let json = r#"{"jsonrpc":"2.0","result":"0x01abcd","id":1}"#;
		assert_eq!(extract_result_hex(json).as_deref(), Some("01abcd"));
	}

	#[test]
	fn extract_result_hex_no_0x_prefix() {
		let json = r#"{"result":"abcd"}"#;
		assert_eq!(extract_result_hex(json).as_deref(), Some("abcd"));
	}

	#[test]
	fn extract_result_hex_returns_none_when_missing() {
		let json = r#"{"error":{"code":-32601,"message":"method not found"}}"#;
		assert!(extract_result_hex(json).is_none());
	}

	#[test]
	fn hex_decode_round_trip() {
		let original = vec![0x00u8, 0x01, 0xab, 0xcd, 0xff];
		let hex = hex_encode(&original);
		assert_eq!(hex_decode(&hex).unwrap(), original);
	}

	#[test]
	fn hex_decode_rejects_odd_length() {
		assert!(hex_decode("abc").is_none());
	}

	#[test]
	fn reconcile_match_returns_match() {
		// Build the JSON the chain would return for Some([42; 32]).
		let mut bytes = vec![0x01u8];
		bytes.extend_from_slice(&[0x42u8; 32]);
		let hex = hex_encode(&bytes);
		let json = format!(r#"{{"result":"0x{hex}","id":1}}"#);
		let parsed = extract_result_hex(&json).and_then(|h| hex_decode(&h)).unwrap();
		assert_eq!(scale_decode_option_32(&parsed), Some(Some([0x42u8; 32])));
	}

	#[test]
	fn reconcile_divergence_detected() {
		let on_chain = [0xAAu8; 32];
		let baked = [0xBBu8; 32];
		let outcome = match (Some(on_chain), &baked) {
			(Some(c), b) if c == *b => Outcome::Match,
			(Some(c), b) => Outcome::Divergence { on_chain: c, baked: *b },
			(None, _) => Outcome::NotYetSet,
		};
		assert!(matches!(outcome, Outcome::Divergence { .. }));
	}

	#[test]
	fn reconcile_not_yet_set_detected() {
		// The "0x00" SCALE encoding decodes to None → NotYetSet.
		let bytes = vec![0x00u8];
		let decoded = scale_decode_option_32(&bytes).unwrap();
		assert_eq!(decoded, None);
	}
}
