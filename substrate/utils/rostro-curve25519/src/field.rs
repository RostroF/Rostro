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
