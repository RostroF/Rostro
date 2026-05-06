// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Parser for the EIP-4844 trusted-setup transcript format used by
//! `ethereum/c-kzg-4844`.
//!
//! ## Format
//!
//! The file is plain text, line-delimited:
//!
//! ```text
//! line 1:                     N_G1            (decimal: "4096")
//! line 2:                     N_G2            (decimal: "65")
//! lines 3..3+N_G1:            G1 Lagrange     (96 hex chars / 48 bytes each)
//! lines 3+N_G1..3+N_G1+N_G2:  G2 monomial     (192 hex chars / 96 bytes each)
//! lines 3+N_G1+N_G2..end:     G1 monomial     (96 hex chars / 48 bytes each)
//! ```
//!
//! Sassafras consumes **monomial** form. This parser exposes the
//! monomial G1 and G2 powers; the Lagrange section is read past but not
//! returned (we have no use for it).
//!
//! Each hex line decodes to a BLS12-381 compressed point in IETF/RFC
//! 9380 encoding — exactly the format [`crate::decode_ietf_g1`] /
//! [`crate::decode_ietf_g2`] consume. End-to-end ground truth: every
//! point in this file gets parsed into an arkworks affine, re-encoded
//! through our codec, and the bytes must match the input exactly.

use crate::{
	decode_ietf_g1, decode_ietf_g2, encode_ietf_g1, encode_ietf_g2, Error, G1_COMPRESSED_LEN,
	G2_COMPRESSED_LEN,
};

use ark_bls12_381::{G1Affine, G2Affine};

/// Parsed EIP-4844 transcript with the monomial-form powers Sassafras needs.
#[derive(Debug)]
pub struct EthereumTrustedSetup {
	/// Monomial G1 powers `g, g^τ, g^τ^2, ...` (count matches the G1 header).
	pub powers_in_g1_monomial: Vec<G1Affine>,
	/// Monomial G2 powers `h, h^τ` (count matches the G2 header).
	pub powers_in_g2_monomial: Vec<G2Affine>,
}

/// Errors produced while parsing the transcript file.
#[derive(Debug, thiserror::Error)]
pub enum TranscriptError {
	/// Header missing or malformed.
	#[error("malformed header: expected two integer lines (n_g1, n_g2) at the top of the file")]
	MalformedHeader,
	/// File contains fewer lines than the headers promise.
	#[error("truncated file: header says n_g1={n_g1}, n_g2={n_g2} but file has {actual_data_lines} data lines (need at least {required})")]
	Truncated {
		/// G1 count from header.
		n_g1: usize,
		/// G2 count from header.
		n_g2: usize,
		/// Total non-header lines actually present.
		actual_data_lines: usize,
		/// Lines required: 2 * n_g1 + n_g2 (Lagrange + Monomial G1, Monomial G2).
		required: usize,
	},
	/// Hex line has wrong length for its expected point type.
	#[error("line {line_no}: expected {expected_chars} hex chars, got {actual_chars}")]
	WrongLineLength {
		/// 1-indexed line number for diagnostic.
		line_no: usize,
		/// Expected hex character count.
		expected_chars: usize,
		/// Actual hex character count.
		actual_chars: usize,
	},
	/// Hex decode failure on a specific line.
	#[error("line {line_no}: invalid hex character at position {position}")]
	InvalidHex {
		/// 1-indexed line number for diagnostic.
		line_no: usize,
		/// Byte offset within the line where the bad nibble appears.
		position: usize,
	},
	/// Underlying point-decode failure (codec rejected the bytes).
	#[error("line {line_no}: point decode failed: {source}")]
	PointDecode {
		/// 1-indexed line number for diagnostic.
		line_no: usize,
		/// Underlying codec error.
		#[source]
		source: Error,
	},
}

/// Parse an EIP-4844 trusted-setup file.
///
/// Returns the monomial G1 + G2 powers. Skips over the Lagrange G1
/// section (read but not returned) since it's not used for ring-VRF
/// proofs.
pub fn parse_eip4844_setup(file_contents: &str) -> Result<EthereumTrustedSetup, TranscriptError> {
	let mut lines = file_contents.lines().enumerate();

	let (line1_no, line1) = lines.next().ok_or(TranscriptError::MalformedHeader)?;
	let n_g1: usize = line1.trim().parse().map_err(|_| TranscriptError::MalformedHeader)?;
	let _ = line1_no;

	let (line2_no, line2) = lines.next().ok_or(TranscriptError::MalformedHeader)?;
	let n_g2: usize = line2.trim().parse().map_err(|_| TranscriptError::MalformedHeader)?;
	let _ = line2_no;

	let required = 2 * n_g1 + n_g2;
	let mut data_lines: Vec<(usize, &str)> =
		lines.map(|(idx, line)| (idx + 1, line)).collect();
	if data_lines.len() < required {
		return Err(TranscriptError::Truncated {
			n_g1,
			n_g2,
			actual_data_lines: data_lines.len(),
			required,
		});
	}
	data_lines.truncate(required);

	// Section 1: G1 Lagrange (n_g1 lines). Skip — we only want monomial.
	let lagrange_g1_section = &data_lines[..n_g1];
	for (line_no, line) in lagrange_g1_section {
		validate_hex_line_len(*line_no, line, G1_COMPRESSED_LEN * 2)?;
	}

	// Section 2: G2 monomial (n_g2 lines).
	let g2_section = &data_lines[n_g1..n_g1 + n_g2];
	let mut powers_in_g2_monomial = Vec::with_capacity(n_g2);
	for (line_no, line) in g2_section {
		let bytes = decode_hex_line_g2(*line_no, line)?;
		let point = decode_ietf_g2(&bytes)
			.map_err(|source| TranscriptError::PointDecode { line_no: *line_no, source })?;
		powers_in_g2_monomial.push(point);
	}

	// Section 3: G1 monomial (n_g1 lines).
	let g1_section = &data_lines[n_g1 + n_g2..];
	let mut powers_in_g1_monomial = Vec::with_capacity(n_g1);
	for (line_no, line) in g1_section {
		let bytes = decode_hex_line_g1(*line_no, line)?;
		let point = decode_ietf_g1(&bytes)
			.map_err(|source| TranscriptError::PointDecode { line_no: *line_no, source })?;
		powers_in_g1_monomial.push(point);
	}

	Ok(EthereumTrustedSetup { powers_in_g1_monomial, powers_in_g2_monomial })
}

/// Verify that re-encoding every point in a parsed transcript through
/// our codec produces byte-identical output to the original transcript
/// bytes. This is the "we agree with the IETF spec on every actual
/// Ethereum-ceremony point" ground-truth check.
///
/// Returns the count of bytes-identical lines on success.
pub fn verify_byte_identical_round_trip(file_contents: &str) -> Result<usize, TranscriptError> {
	let mut lines = file_contents.lines().enumerate();
	let (_, line1) = lines.next().ok_or(TranscriptError::MalformedHeader)?;
	let n_g1: usize = line1.trim().parse().map_err(|_| TranscriptError::MalformedHeader)?;
	let (_, line2) = lines.next().ok_or(TranscriptError::MalformedHeader)?;
	let n_g2: usize = line2.trim().parse().map_err(|_| TranscriptError::MalformedHeader)?;

	let data_lines: Vec<(usize, &str)> =
		lines.map(|(idx, line)| (idx + 1, line)).collect();

	let mut verified = 0usize;

	// Lagrange G1 section: also IETF-encoded, also subject to the same
	// codec contract. Verify these too.
	for (line_no, line) in &data_lines[..n_g1] {
		let bytes = decode_hex_line_g1(*line_no, line)?;
		let point = decode_ietf_g1(&bytes)
			.map_err(|source| TranscriptError::PointDecode { line_no: *line_no, source })?;
		let re_encoded = encode_ietf_g1(&point);
		assert_eq!(
			bytes, re_encoded,
			"line {line_no}: IETF G1 round-trip diverged — codec disagrees with EIP-4844 transcript"
		);
		verified += 1;
	}

	// G2 monomial.
	for (line_no, line) in &data_lines[n_g1..n_g1 + n_g2] {
		let bytes = decode_hex_line_g2(*line_no, line)?;
		let point = decode_ietf_g2(&bytes)
			.map_err(|source| TranscriptError::PointDecode { line_no: *line_no, source })?;
		let re_encoded = encode_ietf_g2(&point);
		assert_eq!(
			bytes, re_encoded,
			"line {line_no}: IETF G2 round-trip diverged — codec disagrees with EIP-4844 transcript"
		);
		verified += 1;
	}

	// G1 monomial.
	for (line_no, line) in &data_lines[n_g1 + n_g2..n_g1 + n_g2 + n_g1] {
		let bytes = decode_hex_line_g1(*line_no, line)?;
		let point = decode_ietf_g1(&bytes)
			.map_err(|source| TranscriptError::PointDecode { line_no: *line_no, source })?;
		let re_encoded = encode_ietf_g1(&point);
		assert_eq!(
			bytes, re_encoded,
			"line {line_no}: IETF G1 (monomial) round-trip diverged — codec disagrees with EIP-4844 transcript"
		);
		verified += 1;
	}

	Ok(verified)
}

// ─── Hex helpers ──────────────────────────────────────────────────────────

fn validate_hex_line_len(
	line_no: usize,
	line: &str,
	expected_chars: usize,
) -> Result<(), TranscriptError> {
	if line.len() != expected_chars {
		return Err(TranscriptError::WrongLineLength {
			line_no,
			expected_chars,
			actual_chars: line.len(),
		});
	}
	Ok(())
}

fn decode_hex_line_g1(line_no: usize, line: &str) -> Result<[u8; G1_COMPRESSED_LEN], TranscriptError> {
	validate_hex_line_len(line_no, line, G1_COMPRESSED_LEN * 2)?;
	let mut out = [0u8; G1_COMPRESSED_LEN];
	hex_decode_into(line_no, line, &mut out)?;
	Ok(out)
}

fn decode_hex_line_g2(line_no: usize, line: &str) -> Result<[u8; G2_COMPRESSED_LEN], TranscriptError> {
	validate_hex_line_len(line_no, line, G2_COMPRESSED_LEN * 2)?;
	let mut out = [0u8; G2_COMPRESSED_LEN];
	hex_decode_into(line_no, line, &mut out)?;
	Ok(out)
}

fn hex_decode_into(line_no: usize, hex: &str, out: &mut [u8]) -> Result<(), TranscriptError> {
	let bytes = hex.as_bytes();
	for (i, dst) in out.iter_mut().enumerate() {
		let hi = hex_nibble(bytes[2 * i])
			.ok_or(TranscriptError::InvalidHex { line_no, position: 2 * i })?;
		let lo = hex_nibble(bytes[2 * i + 1])
			.ok_or(TranscriptError::InvalidHex { line_no, position: 2 * i + 1 })?;
		*dst = (hi << 4) | lo;
	}
	Ok(())
}

fn hex_nibble(b: u8) -> Option<u8> {
	match b {
		b'0'..=b'9' => Some(b - b'0'),
		b'a'..=b'f' => Some(b - b'a' + 10),
		b'A'..=b'F' => Some(b - b'A' + 10),
		_ => None,
	}
}
