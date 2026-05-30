// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Build-time bake of the `rostro_release` ed25519 pubkey into the
//! watchdog binary.
//!
//! Source key file path comes from the `ROSTRO_RELEASE_KEY_PATH` env
//! var; defaults to the lab key at `~/rostro-testnet-lab/keys/rostro_release.pub`
//! when unset (developer convenience).
//!
//! The source file is the standard SSH `ssh-ed25519 <base64> <comment>`
//! format (what `ssh-keygen` and `ssh-keygen -y` emit). We decode the
//! base64 portion, peel off the SSH length-prefixed framing
//! (`ssh-ed25519` algo name + 32-byte raw pubkey), and write the raw
//! 32 bytes to `$OUT_DIR/rostro_release_pubkey.bin` for the watchdog
//! source to `include_bytes!()`.
//!
//! Per the trust model in [[feedback_trust_but_verify_baked_plus_onchain]]:
//! this is the LAYER 0 compile-time trust anchor. The watchdog's
//! recovery path verifies SRT-signed release manifests against this
//! pubkey. The chain's on-chain `ReleasePubkey` is the LAYER 2
//! verification reference the runtime reconciliation thread checks
//! the baked copy against periodically.

use std::path::PathBuf;

fn main() {
	println!("cargo:rerun-if-env-changed=ROSTRO_RELEASE_KEY_PATH");

	let key_path = match std::env::var("ROSTRO_RELEASE_KEY_PATH") {
		Ok(p) => PathBuf::from(p),
		Err(_) => {
			// Default to the lab pubkey checked into the offline
			// `~/rostro-testnet-lab/` lab dir. Mainnet builds set
			// the env var to the production pubkey.
			let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
			PathBuf::from(home).join("rostro-testnet-lab/keys/rostro_release.pub")
		},
	};

	println!("cargo:rerun-if-changed={}", key_path.display());

	let raw = std::fs::read_to_string(&key_path).unwrap_or_else(|e| {
		panic!(
			"failed to read ROSTRO_RELEASE_KEY_PATH={}: {e}\n  \
			 set ROSTRO_RELEASE_KEY_PATH to a valid `ssh-ed25519` pubkey file \
			 (output of `ssh-keygen -t ed25519 -f rostro_release`).",
			key_path.display(),
		)
	});

	let pubkey_bytes = parse_ssh_ed25519_pubkey(&raw).unwrap_or_else(|e| {
		panic!(
			"failed to parse {} as ssh-ed25519 pubkey: {e}",
			key_path.display(),
		)
	});

	let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR set by cargo");
	let out_path = PathBuf::from(out_dir).join("rostro_release_pubkey.bin");
	std::fs::write(&out_path, &pubkey_bytes).unwrap_or_else(|e| {
		panic!("failed to write baked pubkey to {}: {e}", out_path.display())
	});

	// Help debug-time inspection: emit a build-time pretty-printer of
	// the SHA256 fingerprint so anyone running `cargo build` sees
	// which key the binary will be baked with.
	let fingerprint = sha256_hex(&pubkey_bytes);
	println!(
		"cargo:warning=baking rostro_release pubkey from {} \
		 (SHA256(raw 32 bytes) = {})",
		key_path.display(),
		fingerprint,
	);
}

/// Parse the standard `ssh-ed25519 <base64> <comment>` line into the raw
/// 32-byte ed25519 public key.
///
/// SSH wraps ed25519 pubkeys as:
///   u32_be(len) || b"ssh-ed25519"  // 4 + 11 = 15 bytes
///   u32_be(len=32) || <32-byte-pubkey>  // 4 + 32 = 36 bytes
/// Total: 51 bytes when base64-decoded.
fn parse_ssh_ed25519_pubkey(content: &str) -> Result<[u8; 32], String> {
	let line = content.lines().next().ok_or("empty file")?;
	let mut parts = line.split_whitespace();
	let algo = parts.next().ok_or("missing algo field")?;
	if algo != "ssh-ed25519" {
		return Err(format!("unsupported algo {algo}; expected ssh-ed25519"));
	}
	let b64 = parts.next().ok_or("missing base64 field")?;

	let raw = base64_decode(b64).ok_or("malformed base64")?;
	// Frame: u32_be(11) | b"ssh-ed25519" | u32_be(32) | 32 bytes
	if raw.len() < 4 + 11 + 4 + 32 {
		return Err(format!("decoded SSH pubkey too short: {} bytes", raw.len()));
	}
	let mut p = 0usize;
	let algo_len = u32::from_be_bytes(raw[p..p + 4].try_into().unwrap()) as usize;
	p += 4;
	if algo_len != 11 || &raw[p..p + algo_len] != b"ssh-ed25519" {
		return Err("SSH pubkey framing mismatch (algo name)".to_string());
	}
	p += algo_len;
	let key_len = u32::from_be_bytes(raw[p..p + 4].try_into().unwrap()) as usize;
	p += 4;
	if key_len != 32 || raw.len() < p + 32 {
		return Err(format!("SSH pubkey raw len = {key_len}; expected 32"));
	}
	let mut out = [0u8; 32];
	out.copy_from_slice(&raw[p..p + 32]);
	Ok(out)
}

/// Minimal RFC 4648 base64 decoder. Accepts both `+/=` and URL-safe
/// `-_=` alphabets. Returns `None` on any decoding error.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
	let trimmed: String = s.chars().filter(|c| !c.is_whitespace()).collect();
	let s = trimmed.trim_end_matches('=');
	let mut out = Vec::with_capacity(s.len() * 3 / 4);
	let mut accum: u32 = 0;
	let mut bits: u32 = 0;
	for c in s.chars() {
		let v = match c {
			'A'..='Z' => (c as u32) - ('A' as u32),
			'a'..='z' => (c as u32) - ('a' as u32) + 26,
			'0'..='9' => (c as u32) - ('0' as u32) + 52,
			'+' | '-' => 62,
			'/' | '_' => 63,
			_ => return None,
		};
		accum = (accum << 6) | v;
		bits += 6;
		if bits >= 8 {
			bits -= 8;
			out.push((accum >> bits) as u8);
			accum &= (1 << bits) - 1;
		}
	}
	Some(out)
}

/// SHA256 hex digest of a byte slice. Used only for the build-time
/// human-visible fingerprint warning — not load-bearing for trust.
fn sha256_hex(bytes: &[u8]) -> String {
	let digest = sha256(bytes);
	let mut s = String::with_capacity(64);
	for b in digest.iter() {
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

// Pure-Rust SHA-256 (FIPS 180-4). Used in the build script ONLY to
// emit a human-readable fingerprint of the baked pubkey at build
// time. Not security-critical (the build-time output isn't part of
// the runtime trust chain); just gives operators a way to verify
// "yes, this binary has the key I expect."
fn sha256(input: &[u8]) -> [u8; 32] {
	let k: [u32; 64] = [
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
		0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
		0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
		0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
		0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
		0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
		0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
		0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
		0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
	];
	let mut h: [u32; 8] = [
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
		0x1f83d9ab, 0x5be0cd19,
	];

	let mut msg = input.to_vec();
	let bit_len = (input.len() as u64).wrapping_mul(8);
	msg.push(0x80);
	while msg.len() % 64 != 56 {
		msg.push(0);
	}
	msg.extend_from_slice(&bit_len.to_be_bytes());

	for chunk in msg.chunks(64) {
		let mut w = [0u32; 64];
		for (i, word) in chunk.chunks(4).enumerate() {
			w[i] = u32::from_be_bytes(word.try_into().unwrap());
		}
		for i in 16..64 {
			let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
			let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
			w[i] = w[i - 16]
				.wrapping_add(s0)
				.wrapping_add(w[i - 7])
				.wrapping_add(s1);
		}
		let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
			(h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
		for i in 0..64 {
			let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
			let ch = (e & f) ^ (!e & g);
			let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(k[i]).wrapping_add(w[i]);
			let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
			let mj = (a & b) ^ (a & c) ^ (b & c);
			let t2 = s0.wrapping_add(mj);
			hh = g;
			g = f;
			f = e;
			e = d.wrapping_add(t1);
			d = c;
			c = b;
			b = a;
			a = t1.wrapping_add(t2);
		}
		h[0] = h[0].wrapping_add(a);
		h[1] = h[1].wrapping_add(b);
		h[2] = h[2].wrapping_add(c);
		h[3] = h[3].wrapping_add(d);
		h[4] = h[4].wrapping_add(e);
		h[5] = h[5].wrapping_add(f);
		h[6] = h[6].wrapping_add(g);
		h[7] = h[7].wrapping_add(hh);
	}
	let mut out = [0u8; 32];
	for (i, word) in h.iter().enumerate() {
		out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
	}
	out
}
