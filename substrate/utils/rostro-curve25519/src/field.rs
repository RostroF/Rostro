// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Curve25519 base-field arithmetic (`F_p`, `p = 2^255 - 19`) as a
//! non-native foreign field over Goldilocks.
//!
//! ## Representation
//!
//! Per the locked Goldilocks packing convention
//! (`pop_air_goldilocks_packing_convention.md`), each Goldilocks
//! trace cell holds at most one u32. A Curve25519 base-field element
//! is therefore encoded as **8 × u32 limbs, little-endian**:
//!
//! ```text
//!   value = limb[0] + limb[1]·2^32 + limb[2]·2^64 + ... + limb[7]·2^224
//! ```
//!
//! This is the EXACT representation used in trace columns. A future
//! Edwards25519 point AIR reserves 8 trace columns per coordinate (32
//! per point in extended (X, Y, Z, T) form) plus the working
//! intermediates for each operation.
//!
//! ## Why u32 limbs and not u51 / u64
//!
//! `curve25519-dalek` uses 5 × u51 limbs (radix-51) for fast multiply
//! by exploiting 64-bit machine words. We can't: Goldilocks elements
//! safely hold u32-shaped values but a u64 (or any value > 2^32) risks
//! mod-p wraparound for some byte patterns (the silent-soundness-break
//! footgun the packing convention was locked to prevent). u32 limbs
//! plus lookup-based range checks (`rostro-range-check`) is the right
//! tradeoff for soundness.
//!
//! ## Status
//!
//! Module scaffold + constants + reference encoder/decoder against
//! `curve25519-dalek`'s `Scalar` and `FieldElement`. Constraint-side
//! AIRs land in subsequent commits.

use alloc::vec::Vec;

/// Number of u32 limbs in a Curve25519 base-field element (256 bits / 32 = 8).
pub const FIELD_NUM_LIMBS: usize = 8;

/// `p = 2^255 - 19`, the Curve25519 base-field prime, encoded as 8 ×
/// little-endian u32 limbs. Pinned at compile time so the constraint
/// constants are auditable directly from this file.
///
/// `p_LE_bytes = ED FF FF FF  FF FF FF FF  FF FF FF FF  FF FF FF FF
///               FF FF FF FF  FF FF FF FF  FF FF FF FF  FF FF FF 7F`
///
/// limb[0] = 0xFFFFFFED  (least significant)
/// limb[1..=6] = 0xFFFFFFFF
/// limb[7] = 0x7FFFFFFF  (high bit clear: 2^255 - 1 - 18)
pub const P_LIMBS: [u32; FIELD_NUM_LIMBS] = [
	0xFFFF_FFED,
	0xFFFF_FFFF,
	0xFFFF_FFFF,
	0xFFFF_FFFF,
	0xFFFF_FFFF,
	0xFFFF_FFFF,
	0xFFFF_FFFF,
	0x7FFF_FFFF,
];

/// `p - 1` as 8 × little-endian u32 limbs. Used for canonical-form
/// rejection (a value v is in canonical form iff v < p ≡ v ≤ p - 1).
pub const P_MINUS_ONE_LIMBS: [u32; FIELD_NUM_LIMBS] = [
	0xFFFF_FFEC, // 0xFFFF_FFED - 1
	0xFFFF_FFFF,
	0xFFFF_FFFF,
	0xFFFF_FFFF,
	0xFFFF_FFFF,
	0xFFFF_FFFF,
	0xFFFF_FFFF,
	0x7FFF_FFFF,
];

/// Encode a 32-byte little-endian field element into 8 u32 limbs (LE).
/// Pure deterministic byte→limb conversion; not constraint-side.
#[inline]
pub fn bytes_to_limbs(bytes: &[u8; 32]) -> [u32; FIELD_NUM_LIMBS] {
	let mut limbs = [0u32; FIELD_NUM_LIMBS];
	for (i, chunk) in bytes.chunks_exact(4).enumerate() {
		limbs[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
	}
	limbs
}

/// Inverse of [`bytes_to_limbs`].
#[inline]
pub fn limbs_to_bytes(limbs: &[u32; FIELD_NUM_LIMBS]) -> [u8; 32] {
	let mut bytes = [0u8; 32];
	for (i, limb) in limbs.iter().enumerate() {
		let lb = limb.to_le_bytes();
		bytes[i * 4..(i + 1) * 4].copy_from_slice(&lb);
	}
	bytes
}

/// Test whether a limb representation is in canonical form, i.e.,
/// strictly less than `p`. Pure-Rust (oracle/witness side); the AIR's
/// canonical-form constraint enforces the same predicate via subtraction
/// + range checks.
///
/// Returns `true` iff `value < p`.
pub fn is_canonical(limbs: &[u32; FIELD_NUM_LIMBS]) -> bool {
	// Compare from most significant limb downward.
	for i in (0..FIELD_NUM_LIMBS).rev() {
		match limbs[i].cmp(&P_LIMBS[i]) {
			core::cmp::Ordering::Less => return true,
			core::cmp::Ordering::Greater => return false,
			core::cmp::Ordering::Equal => {}
		}
	}
	// limbs == p exactly → not canonical (equal not less).
	false
}

/// Convenience: pack a list of u32 limbs into a `Vec<u32>` for use in
/// trace builders. Non-circuit; just buffer plumbing.
pub fn limbs_to_vec(limbs: &[u32; FIELD_NUM_LIMBS]) -> Vec<u32> {
	limbs.to_vec()
}

// ─── Witness-side modular arithmetic ───────────────────────────────────────
//
// These functions compute (a op b) mod p in pure Rust. They are NOT the
// constraint side — the AIR's constraint set enforces the same equations
// limb-wise with carry/borrow witnesses + range-check lookups. These
// helpers are what dotwave and the prover use to GENERATE the trace
// values that the AIR then verifies; the oracle tests cross-check both
// the helpers and (eventually) the constraint set against a num-bigint
// reference impl over the same modulus.
//
// Soundness rationale: every output here is bounded < p before return
// (canonical form), so calling code can compose `add(add(a, b), c)`
// without intermediate overflow concerns. The conditional-subtract step
// is the only branching primitive; everything else is straight-line
// limb-wise arithmetic that fits in Goldilocks-friendly u32 ranges.

/// Modular addition over `F_p` with `p = 2^255 - 19`.
///
/// Computes `(a + b) mod p` in canonical form. Both inputs must already
/// be canonical (`a < p` and `b < p`); this is the precondition the AIR's
/// canonical-form check enforces upstream. Output is canonical.
///
/// Witness shape this function generates (for the future AIR's trace):
/// - `raw_sum[0..8]` — limb-wise sum before reduction
/// - `raw_carry[0..7]` — carry chain bits from limb-wise add (each ∈ {0, 1})
/// - `t ∈ {0, 1}` — whether one conditional subtraction of p was needed
/// - `borrow[0..7]` — borrow chain bits if t == 1 (each ∈ {0, 1})
/// - `c[0..8]` — the reduced output
///
/// The AIR proves `a + b == c + t * p` limb-wise + canonical form of c.
pub fn add(a: &[u32; FIELD_NUM_LIMBS], b: &[u32; FIELD_NUM_LIMBS]) -> [u32; FIELD_NUM_LIMBS] {
	let raw_sum = wide_add(a, b);
	reduce_wide_once(&raw_sum)
}

/// Modular subtraction over `F_p`. Computes `(a - b) mod p` in
/// canonical form. Both inputs must be canonical.
///
/// Implementation: if `a >= b`, return `a - b`. Else, return `p - (b - a)`.
/// The AIR proves `a == c + b - t * p` (or equivalently `a + t * p == c + b`)
/// where `t ∈ {0, 1}` is whether the addition of p was needed.
pub fn sub(a: &[u32; FIELD_NUM_LIMBS], b: &[u32; FIELD_NUM_LIMBS]) -> [u32; FIELD_NUM_LIMBS] {
	if cmp(a, b) != core::cmp::Ordering::Less {
		// a >= b: simple limb-wise subtraction, result already canonical.
		wide_sub_no_borrow(a, b)
	} else {
		// a < b: compute (p - b) + a, which is canonical because
		// p - b > 0 (since b < p) and (p - b) + a < p (since a < b < p,
		// so a + (p - b) < p - b + b = p).
		let p_minus_b = wide_sub_no_borrow(&P_LIMBS, b);
		let raw = wide_add(&p_minus_b, a);
		// raw < p by the bound above, but defensively reduce.
		reduce_wide_once(&raw)
	}
}

/// Compare two limb representations as integers. Returns `Less`,
/// `Equal`, or `Greater`.
pub fn cmp(a: &[u32; FIELD_NUM_LIMBS], b: &[u32; FIELD_NUM_LIMBS]) -> core::cmp::Ordering {
	for i in (0..FIELD_NUM_LIMBS).rev() {
		match a[i].cmp(&b[i]) {
			core::cmp::Ordering::Equal => {}
			other => return other,
		}
	}
	core::cmp::Ordering::Equal
}

/// Wide sum: `a + b` as a 9-limb result (8 sum limbs + 1 top carry bit).
/// No reduction — the caller's responsibility. Used internally by
/// [`add`].
#[inline]
fn wide_add(
	a: &[u32; FIELD_NUM_LIMBS],
	b: &[u32; FIELD_NUM_LIMBS],
) -> [u32; FIELD_NUM_LIMBS + 1] {
	let mut out = [0u32; FIELD_NUM_LIMBS + 1];
	let mut carry: u64 = 0;
	for i in 0..FIELD_NUM_LIMBS {
		let s = u64::from(a[i]) + u64::from(b[i]) + carry;
		out[i] = s as u32;
		carry = s >> 32;
	}
	out[FIELD_NUM_LIMBS] = carry as u32;
	out
}

/// Limb-wise subtraction `a - b` assuming `a >= b` (no overall borrow).
/// Panics in debug if `a < b`. Used by [`sub`].
#[inline]
fn wide_sub_no_borrow(
	a: &[u32; FIELD_NUM_LIMBS],
	b: &[u32; FIELD_NUM_LIMBS],
) -> [u32; FIELD_NUM_LIMBS] {
	debug_assert!(
		cmp(a, b) != core::cmp::Ordering::Less,
		"wide_sub_no_borrow precondition: a >= b",
	);
	let mut out = [0u32; FIELD_NUM_LIMBS];
	let mut borrow: i64 = 0;
	for i in 0..FIELD_NUM_LIMBS {
		let d = i64::from(a[i]) - i64::from(b[i]) - borrow;
		if d < 0 {
			out[i] = (d + (1i64 << 32)) as u32;
			borrow = 1;
		} else {
			out[i] = d as u32;
			borrow = 0;
		}
	}
	debug_assert_eq!(borrow, 0, "wide_sub_no_borrow: a >= b precondition violated");
	out
}

/// Conditionally subtract `p` once from a 9-limb wide value if it's
/// `>= p`. Returns canonical 8-limb result.
///
/// The "once" matters: callers of this function (currently just [`add`])
/// guarantee the input is at most `2*p - 2`, so a single conditional
/// subtraction suffices. For multi-step compositions that could exceed
/// `2*p`, callers must reduce intermediately.
fn reduce_wide_once(wide: &[u32; FIELD_NUM_LIMBS + 1]) -> [u32; FIELD_NUM_LIMBS] {
	// Extract the lower 8 limbs and compare against p.
	let mut low = [0u32; FIELD_NUM_LIMBS];
	low.copy_from_slice(&wide[..FIELD_NUM_LIMBS]);
	let top = wide[FIELD_NUM_LIMBS];

	// If top carry is nonzero, the value is >= 2^256 > p, so we MUST subtract p.
	// If top is zero but low >= p, also subtract.
	let must_subtract = top != 0 || cmp(&low, &P_LIMBS) != core::cmp::Ordering::Less;

	if !must_subtract {
		return low;
	}

	// Compute low - p, with the top carry contributing 2^256 worth of
	// value. Since p ≈ 2^255, and worst-case wide value is 2 * (p - 1) ≈
	// 2^256 - 2, subtracting p once brings it below p.
	// We handle the top carry by treating it as an extra 2^256 - p added
	// to low; equivalently, subtract p once treating the value as if it
	// wraps mod 2^256.

	// Limb-wise: out = low + (2^256 - p) mod 2^256, but only if the wide
	// value would be >= p. Equivalently: out = low - p where p is
	// borrowed from the implicit 2^256 (top carry). The math:
	//   wide = top * 2^256 + low
	//   if wide >= p: out = wide - p
	//                     = top * 2^256 + low - p
	//   if top == 0: out = low - p (since low >= p)
	//   if top == 1: out = 2^256 + low - p = low + (2^256 - p)
	//                    = low + (19 + (2^32-1 over higher limbs))  -- this
	//                    is the standard "reduce 2^255 - 19" trick.
	let mut out = [0u32; FIELD_NUM_LIMBS];
	let mut borrow: i64 = 0;
	for i in 0..FIELD_NUM_LIMBS {
		let d = i64::from(low[i]) - i64::from(P_LIMBS[i]) - borrow;
		if d < 0 {
			out[i] = (d + (1i64 << 32)) as u32;
			borrow = 1;
		} else {
			out[i] = d as u32;
			borrow = 0;
		}
	}
	// Final consistency: top - borrow MUST equal 0 (the value was
	// indeed >= p, so the subtraction balances).
	debug_assert_eq!(i64::from(top) - borrow, 0, "reduce_wide_once: balance check failed");
	out
}

/// Modular reduction of a canonical-or-near-canonical limb vector.
/// Returns `v` if already canonical, else `v - p`. Used after operations
/// that produce a near-canonical intermediate (e.g., conditional adds).
pub fn reduce(v: &[u32; FIELD_NUM_LIMBS]) -> [u32; FIELD_NUM_LIMBS] {
	let mut wide = [0u32; FIELD_NUM_LIMBS + 1];
	wide[..FIELD_NUM_LIMBS].copy_from_slice(v);
	reduce_wide_once(&wide)
}

/// Negation in the field: `-v mod p`. Equals `0` if `v == 0`, else `p - v`.
pub fn neg(v: &[u32; FIELD_NUM_LIMBS]) -> [u32; FIELD_NUM_LIMBS] {
	if v.iter().all(|&x| x == 0) {
		return [0u32; FIELD_NUM_LIMBS];
	}
	wide_sub_no_borrow(&P_LIMBS, v)
}

/// Test whether the limb representation is zero. Constant-time-irrelevant
/// (this is the prover/oracle side, not the AIR).
#[inline]
pub fn is_zero(v: &[u32; FIELD_NUM_LIMBS]) -> bool {
	v.iter().all(|&x| x == 0)
}

// ─── Modular multiplication / squaring / inversion (witness-side) ──────────
//
// These functions compute `(a op b) mod p` in pure Rust for any of:
// `mul(a, b) = (a * b) mod p`, `square(a) = (a * a) mod p`, and
// `inv(v) = v^(p-2) mod p` (Fermat's little theorem inversion).
//
// The implementation uses schoolbook multiplication on u32 limbs to
// produce a 16-limb wide product, then a simple long-division reduction
// modulo p. This is the OBLIVIOUS oracle path: not optimized for speed,
// just for clarity + correctness. The AIR's witness builder will use
// this same helper to generate trace values, and the production
// `FieldMulAir` (when it lands) uses Barrett or Montgomery reduction
// constraints to enforce the same `wide == q * p + c` algebraic relation.

/// Schoolbook multiplication: returns the 16-limb wide product as
/// 16 × u32 limbs (LE). No reduction. Used as an oracle for the AIR.
pub(crate) fn wide_mul(
	a: &[u32; FIELD_NUM_LIMBS],
	b: &[u32; FIELD_NUM_LIMBS],
) -> [u32; 2 * FIELD_NUM_LIMBS] {
	let mut out = [0u32; 2 * FIELD_NUM_LIMBS];
	// Column-major schoolbook. Each (i, j) partial product a[i] * b[j]
	// lands at column position i + j with carry into i + j + 1.
	for i in 0..FIELD_NUM_LIMBS {
		let mut carry: u64 = 0;
		for j in 0..FIELD_NUM_LIMBS {
			let pos = i + j;
			let product = u64::from(a[i]) * u64::from(b[j]);
			let acc = u64::from(out[pos]) + (product & 0xFFFF_FFFFu64) + carry;
			out[pos] = acc as u32;
			carry = (acc >> 32) + (product >> 32);
		}
		// Propagate the final carry into out[i + FIELD_NUM_LIMBS] and beyond.
		let mut pos = i + FIELD_NUM_LIMBS;
		while carry != 0 {
			let acc = u64::from(out[pos]) + carry;
			out[pos] = acc as u32;
			carry = acc >> 32;
			pos += 1;
		}
	}
	out
}

/// Reduce a 16-limb wide value modulo `p` using long division.
///
/// Oracle-only: O(limb_count^2) instead of the O(limb_count) Barrett
/// reduction the AIR will use. Suitable for tests; not for production
/// hot paths.
fn reduce_wide_mod_p(wide: &[u32; 2 * FIELD_NUM_LIMBS]) -> [u32; FIELD_NUM_LIMBS] {
	// Convert to bytes and use a portable big-integer reduction. This is
	// the simplest correct path; the production AIR computes the
	// reduction differently (witnessed quotient + Barrett constraints).
	let mut bytes = [0u8; 4 * 2 * FIELD_NUM_LIMBS];
	for (i, limb) in wide.iter().enumerate() {
		bytes[i * 4..(i + 1) * 4].copy_from_slice(&limb.to_le_bytes());
	}
	// Compute `wide mod p` by repeated subtraction of `p << k`. The wide
	// value is at most ~2^512; p is ~2^255; so worst case ~256 iterations
	// of subtraction. Plenty fast for tests.
	let mut acc = bytes;
	loop {
		// Find the highest bit of acc.
		let mut hi_byte = 4 * 2 * FIELD_NUM_LIMBS;
		while hi_byte > 0 && acc[hi_byte - 1] == 0 {
			hi_byte -= 1;
		}
		if hi_byte == 0 {
			// acc is zero; return.
			return [0u32; FIELD_NUM_LIMBS];
		}
		let hi_bit_in_byte = 7 - acc[hi_byte - 1].leading_zeros() as usize;
		let total_bits = (hi_byte - 1) * 8 + hi_bit_in_byte + 1;
		if total_bits < 256 {
			break;
		}
		// Shift p up to align with the top bit of acc, then subtract.
		let shift = total_bits - 256;
		let p_bytes = {
			let mut pb = [0u8; 4 * 2 * FIELD_NUM_LIMBS];
			let p_le = limbs_to_bytes(&P_LIMBS);
			pb[..32].copy_from_slice(&p_le);
			pb
		};
		let shifted = shift_left_bytes(&p_bytes, shift);
		// If shifted > acc, drop down one position (we overshot).
		if cmp_bytes_le(&shifted, &acc) == core::cmp::Ordering::Greater {
			let lower = shift_left_bytes(&p_bytes, shift - 1);
			acc = sub_bytes_le(&acc, &lower);
		} else {
			acc = sub_bytes_le(&acc, &shifted);
		}
	}
	// Final step: ensure acc < p.
	let mut out = [0u32; FIELD_NUM_LIMBS];
	for (i, limb) in out.iter_mut().enumerate() {
		let chunk = &acc[i * 4..(i + 1) * 4];
		*limb = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
	}
	if !is_canonical(&out) {
		out = wide_sub_no_borrow(&out, &P_LIMBS);
	}
	out
}

/// Shift a little-endian byte buffer left by `bits` bits.
fn shift_left_bytes(
	bytes: &[u8; 4 * 2 * FIELD_NUM_LIMBS],
	bits: usize,
) -> [u8; 4 * 2 * FIELD_NUM_LIMBS] {
	let mut out = [0u8; 4 * 2 * FIELD_NUM_LIMBS];
	let byte_shift = bits / 8;
	let bit_shift = bits % 8;
	for i in 0..(4 * 2 * FIELD_NUM_LIMBS) {
		if i + byte_shift >= 4 * 2 * FIELD_NUM_LIMBS {
			break;
		}
		let lo = u16::from(bytes[i]) << bit_shift;
		out[i + byte_shift] |= lo as u8;
		if i + byte_shift + 1 < 4 * 2 * FIELD_NUM_LIMBS {
			out[i + byte_shift + 1] |= (lo >> 8) as u8;
		}
	}
	out
}

/// Compare two LE byte buffers as integers.
fn cmp_bytes_le(
	a: &[u8; 4 * 2 * FIELD_NUM_LIMBS],
	b: &[u8; 4 * 2 * FIELD_NUM_LIMBS],
) -> core::cmp::Ordering {
	for i in (0..(4 * 2 * FIELD_NUM_LIMBS)).rev() {
		match a[i].cmp(&b[i]) {
			core::cmp::Ordering::Equal => {}
			other => return other,
		}
	}
	core::cmp::Ordering::Equal
}

/// Subtract two LE byte buffers (assumes a >= b).
fn sub_bytes_le(
	a: &[u8; 4 * 2 * FIELD_NUM_LIMBS],
	b: &[u8; 4 * 2 * FIELD_NUM_LIMBS],
) -> [u8; 4 * 2 * FIELD_NUM_LIMBS] {
	let mut out = [0u8; 4 * 2 * FIELD_NUM_LIMBS];
	let mut borrow: i16 = 0;
	for i in 0..(4 * 2 * FIELD_NUM_LIMBS) {
		let d: i16 = i16::from(a[i]) - i16::from(b[i]) - borrow;
		if d < 0 {
			out[i] = (d + 256) as u8;
			borrow = 1;
		} else {
			out[i] = d as u8;
			borrow = 0;
		}
	}
	out
}

/// Modular multiplication over `F_p`: returns `(a * b) mod p` in
/// canonical form. Both inputs must be canonical.
pub fn mul(a: &[u32; FIELD_NUM_LIMBS], b: &[u32; FIELD_NUM_LIMBS]) -> [u32; FIELD_NUM_LIMBS] {
	let wide = wide_mul(a, b);
	reduce_wide_mod_p(&wide)
}

/// Modular squaring over `F_p`: `(a * a) mod p`.
pub fn square(a: &[u32; FIELD_NUM_LIMBS]) -> [u32; FIELD_NUM_LIMBS] {
	mul(a, a)
}

/// Modular inverse via Fermat's little theorem: `v^(p-2) mod p`.
///
/// Returns `0` if `v == 0` (no inverse exists; documented behavior).
/// Otherwise returns the multiplicative inverse such that
/// `v * inv(v) == 1 (mod p)`.
///
/// Implementation: square-and-multiply over the 254 set bits of
/// `p - 2`. `p - 2 = 2^255 - 21`, binary `0111...11101011` with the
/// low bit pattern `...1011` from the `-21` correction.
pub fn inv(v: &[u32; FIELD_NUM_LIMBS]) -> [u32; FIELD_NUM_LIMBS] {
	if is_zero(v) {
		return [0u32; FIELD_NUM_LIMBS];
	}
	// p - 2 = 2^255 - 21. Compute its bits, MSB to LSB, and run
	// square-and-multiply.
	let p_minus_two_bits = p_minus_two_bits_msb_first();
	let mut result_init = false;
	let mut result = [0u32; FIELD_NUM_LIMBS];
	for bit in p_minus_two_bits {
		if result_init {
			result = square(&result);
		}
		if bit {
			if !result_init {
				result = *v;
				result_init = true;
			} else {
				result = mul(&result, v);
			}
		}
	}
	result
}

/// Bits of `p - 2 = 2^255 - 21` from MSB to LSB. 255 bits total; the
/// MSB is bit position 254 (since p < 2^255 so bit 255 is 0).
///
/// `bits[0]` = bit 254 (= 1), `bits[1]` = bit 253 (= 1), ...,
/// `bits[254]` = bit 0 (= 1, since 0xEB has its low bit set).
fn p_minus_two_bits_msb_first() -> [bool; 255] {
	// p - 2 = 2^255 - 21, LE bytes: [0xEB, 0xFF * 30, 0x7F]
	let mut bytes = limbs_to_bytes(&P_LIMBS);
	bytes[0] -= 2;
	let mut bits = [false; 255];
	for i in 0..255 {
		// MSB at index 0 corresponds to bit position 254 (= 2^254).
		let bit_position = 254 - i;
		let byte_idx = bit_position / 8;
		let bit_in_byte = bit_position % 8;
		bits[i] = (bytes[byte_idx] >> bit_in_byte) & 1 == 1;
	}
	bits
}

/// `√(-1) mod p`, the canonical positive square root of -1 in `F_p`.
///
/// Matches `curve25519_dalek::backend::serial::u32::constants::SQRT_M1`.
/// Used by Ristretto255 encode/decode and by hash-to-curve.
///
/// Hex (LE bytes, byte 0 first):
/// `b0 a0 0e 4a 27 1b ee c4 78 e4 2f ad 06 18 43 2f
///  a7 d7 fb 3d 99 00 4d 2b 0b df c1 4f 80 24 83 2b`
pub const SQRT_M1_LIMBS: [u32; FIELD_NUM_LIMBS] = [
	0x4A0E_A0B0,
	0xC4EE_1B27,
	0xAD2F_E478,
	0x2F43_1806,
	0x3DFB_D7A7,
	0x2B4D_0099,
	0x4FC1_DF0B,
	0x2B83_2480,
];

/// Modular exponentiation by an MSB-first bit sequence.
///
/// Returns `base^e mod p` where `e` is encoded as the bit slice
/// `exp_bits` from MSB to LSB. Used by [`pow_p_minus_5_div_8`] and
/// (privately) by [`inv`]'s underlying square-and-multiply chain.
///
/// Handles the leading-zero case by treating any leading zero bits as
/// "not yet initialized" — equivalent to skipping over them.
pub fn pow(base: &[u32; FIELD_NUM_LIMBS], exp_bits: &[bool]) -> [u32; FIELD_NUM_LIMBS] {
	if is_zero(base) {
		// 0^0 == 1 in our convention (matches num-bigint); 0^e == 0 for e > 0.
		let any_one = exp_bits.iter().any(|&b| b);
		if !any_one {
			let mut one = [0u32; FIELD_NUM_LIMBS];
			one[0] = 1;
			return one;
		}
		return [0u32; FIELD_NUM_LIMBS];
	}

	let mut result_init = false;
	let mut result = [0u32; FIELD_NUM_LIMBS];
	for &bit in exp_bits {
		if result_init {
			result = square(&result);
		}
		if bit {
			if !result_init {
				result = *base;
				result_init = true;
			} else {
				result = mul(&result, base);
			}
		}
	}
	if !result_init {
		// All zero bits — return 1.
		let mut one = [0u32; FIELD_NUM_LIMBS];
		one[0] = 1;
		return one;
	}
	result
}

/// `base^((p - 5) / 8) mod p`, the exponent that powers the Ristretto
/// `sqrt_ratio_m1` routine.
///
/// `(p - 5) / 8 = 2^252 - 3`. Bit layout: 250 ones from positions 2..=251,
/// then bit 251 (the MSB of this exponent) — that is, the value's
/// binary form is `0x0FFFFFFF...FD` (252 bits long with low two bits
/// `01`). We walk MSB to LSB.
pub fn pow_p_minus_5_div_8(base: &[u32; FIELD_NUM_LIMBS]) -> [u32; FIELD_NUM_LIMBS] {
	// (p - 5) / 8 = 2^252 - 3. LE bytes:
	//   [0xFD, 0xFF, 0xFF, ..., 0xFF (28 bytes), 0x0F, 0x00, 0x00, 0x00]
	// = byte 0: 0xFD, bytes 1..=30: 0xFF, byte 31: 0x0F.
	// Bit width = 252 (high bit at position 251).
	let mut bytes = [0xFFu8; 32];
	bytes[0] = 0xFD;
	bytes[31] = 0x0F;
	let mut bits = [false; 252];
	for i in 0..252 {
		let bit_position = 251 - i;
		let byte_idx = bit_position / 8;
		let bit_in_byte = bit_position % 8;
		bits[i] = (bytes[byte_idx] >> bit_in_byte) & 1 == 1;
	}
	pow(base, &bits)
}

/// Returns `true` iff the canonical limb encoding of `v` has its
/// least-significant bit set. By the Ristretto255 / RFC 9380 sign
/// convention, this is the meaning of "negative" for a field element.
///
/// Requires `v` already reduced (call [`reduce`] first if uncertain).
pub fn is_negative(v: &[u32; FIELD_NUM_LIMBS]) -> bool {
	(v[0] & 1) == 1
}

/// Conditional negate: returns `-v mod p` if `cond`, else `v`.
pub fn cond_neg(v: &[u32; FIELD_NUM_LIMBS], cond: bool) -> [u32; FIELD_NUM_LIMBS] {
	if cond {
		neg(v)
	} else {
		*v
	}
}

/// Ristretto255 / `sqrt_ratio_i` per the curve25519-dalek convention.
///
/// Computes `sqrt(u / v)` over `F_p` when `u/v` is a square, or a
/// well-defined fallback value when it is not. The boolean return
/// is `true` iff `u/v` is a (possibly zero) square; the field-element
/// return is meaningful only when `true`, but is deterministic
/// regardless.
///
/// Algorithm (Ristretto draft, § F.6 / dalek `sqrt_ratio_i`):
/// ```text
///   v3 = v² · v
///   v7 = v³ · (v²)² = v^7
///   r  = u · v3 · (u · v7)^((p-5)/8)
///   check = v · r²
///
///   correct_sign       = (check ==  u)
///   flipped_sign       = (check == -u)
///   flipped_sign_i     = (check == -u · √-1)
///
///   if flipped_sign  or flipped_sign_i: r ← r · √-1
///   if r is "negative" (LSB == 1):     r ← -r
///
///   was_square = correct_sign or flipped_sign
/// ```
///
/// Returns `(was_square, r)`. The conventional "canonical positive"
/// root is selected via the `is_negative` flip — this matches
/// dalek's `sqrt_ratio_i` exactly.
pub fn sqrt_ratio_m1(
	u: &[u32; FIELD_NUM_LIMBS],
	v: &[u32; FIELD_NUM_LIMBS],
) -> (bool, [u32; FIELD_NUM_LIMBS]) {
	let v2 = square(v);
	let v3 = mul(&v2, v);
	let v4 = square(&v2);
	let v7 = mul(&v4, &v3);

	let u_v3 = mul(u, &v3);
	let u_v7 = mul(u, &v7);
	let u_v7_pow = pow_p_minus_5_div_8(&u_v7);
	let mut r = mul(&u_v3, &u_v7_pow);

	let r_sq = square(&r);
	let check = mul(v, &r_sq);

	let neg_u = neg(u);
	let neg_u_i = mul(&neg_u, &SQRT_M1_LIMBS);

	let correct_sign = check == *u;
	let flipped_sign = check == neg_u;
	let flipped_sign_i = check == neg_u_i;

	if flipped_sign || flipped_sign_i {
		r = mul(&r, &SQRT_M1_LIMBS);
	}

	if is_negative(&r) {
		r = neg(&r);
	}

	let was_square = correct_sign || flipped_sign;
	(was_square, r)
}
