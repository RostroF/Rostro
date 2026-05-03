// Copyright (C) Parity Technologies (UK) Ltd.
// This file is part of Polkadot.

// Polkadot is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Polkadot is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Polkadot.  If not, see <http://www.gnu.org/licenses/>.

//! XCM utils for internal use.

use crate::MAX_INSTRUCTIONS_TO_DECODE;

use alloc::vec::Vec;
use codec::{decode_vec_with_len, Compact, Decode};

environmental::environmental!(instructions_count: u8);

/// Decode a `vec` of XCM instructions.
///
/// This function keeps track of nested XCM instructions and enforces a total limit of
/// `MAX_INSTRUCTIONS_TO_DECODE`.
pub fn decode_xcm_instructions<I: codec::Input, T: Decode>(
	input: &mut I,
) -> Result<Vec<T>, codec::Error> {
	instructions_count::using_once(&mut 0, || {
		let vec_len: u32 = <Compact<u32>>::decode(input)?.into();
		instructions_count::with(|count| {
			// SECURITY: previously this was `count.saturating_add(vec_len as u8)`. The
			// `as u8` cast silently truncated `vec_len`, so any multiple of 256 wrapped
			// to 0, leaving `count` unchanged and bypassing the
			// `MAX_INSTRUCTIONS_TO_DECODE` bound entirely. Reject lengths that don't
			// fit in `u8`, and reject the running total exceeding the bound BEFORE
			// performing the cast, so attacker-chosen values like 256, 65_536, 2^30
			// can no longer slip past the check.
			let vec_len_u8: u8 = u8::try_from(vec_len)
				.map_err(|_| codec::Error::from("Max instructions exceeded"))?;
			let prev = count
				.checked_add(vec_len_u8)
				.ok_or(codec::Error::from("Max instructions exceeded"))?;
			if prev > MAX_INSTRUCTIONS_TO_DECODE {
				return Err(codec::Error::from("Max instructions exceeded"));
			}
			*count = prev;
			Ok(())
		})
		.unwrap_or(Err(codec::Error::from("Error calling `instructions_count::with()`")))?;
		let decoded_instructions = decode_vec_with_len(input, vec_len as usize)?;
		Ok(decoded_instructions)
	})
}
