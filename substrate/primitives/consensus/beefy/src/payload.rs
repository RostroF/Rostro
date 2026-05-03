// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use alloc::{vec, vec::Vec};
use codec::{Decode, DecodeWithMemTracking, Encode};
use scale_info::TypeInfo;
use rp_runtime::traits::Block;

/// Id of different payloads in the [`crate::Commitment`] data.
pub type BeefyPayloadId = [u8; 2];

/// Registry of all known [`BeefyPayloadId`].
pub mod known_payloads {
	use crate::BeefyPayloadId;

	/// A [`Payload`](super::Payload) identifier for Merkle Mountain Range root hash.
	///
	/// Encoded value should contain a [`crate::MmrRootHash`] type (i.e. 32-bytes hash).
	pub const MMR_ROOT_ID: BeefyPayloadId = *b"mh";
}

/// A BEEFY payload type allowing for future extensibility of adding additional kinds of payloads.
///
/// The idea is to store a vector of SCALE-encoded values with an extra identifier.
/// Identifiers MUST be sorted by the [`BeefyPayloadId`] to allow efficient lookup of expected
/// value. Duplicated identifiers are disallowed. It's okay for different implementations to only
/// support a subset of possible values.
#[derive(
	Decode,
	DecodeWithMemTracking,
	Encode,
	Debug,
	PartialEq,
	Eq,
	Clone,
	Ord,
	PartialOrd,
	Hash,
	TypeInfo,
)]
pub struct Payload(Vec<(BeefyPayloadId, Vec<u8>)>);

impl Payload {
	/// Construct a new payload given an initial value
	pub fn from_single_entry(id: BeefyPayloadId, value: Vec<u8>) -> Self {
		Self(vec![(id, value)])
	}

	/// Returns a raw payload under given `id`.
	///
	/// If the [`BeefyPayloadId`] is not found in the payload `None` is returned.
	pub fn get_raw(&self, id: &BeefyPayloadId) -> Option<&Vec<u8>> {
		let index = self.0.binary_search_by(|probe| probe.0.cmp(id)).ok()?;
		Some(&self.0[index].1)
	}

	/// Returns all the raw payloads under given `id`.
	pub fn get_all_raw<'a>(
		&'a self,
		id: &'a BeefyPayloadId,
	) -> impl Iterator<Item = &'a Vec<u8>> + 'a {
		self.0
			.iter()
			.filter_map(move |probe| if &probe.0 != id { return None } else { Some(&probe.1) })
	}

	/// Returns a decoded payload value under given `id`.
	///
	/// In case the value is not there, or it cannot be decoded `None` is returned.
	pub fn get_decoded<T: Decode>(&self, id: &BeefyPayloadId) -> Option<T> {
		self.get_raw(id).and_then(|raw| T::decode(&mut &raw[..]).ok())
	}

	/// Returns all decoded payload values under given `id`.
	pub fn get_all_decoded<'a, T: Decode>(
		&'a self,
		id: &'a BeefyPayloadId,
	) -> impl Iterator<Item = Option<T>> + 'a {
		self.get_all_raw(id).map(|raw| T::decode(&mut &raw[..]).ok())
	}

	/// Push a `Vec<u8>` with a given id into the payload vec.
	///
	/// If `id` already exists, its value is **replaced**. Duplicate identifiers are
	/// disallowed per the type's contract; previously this method appended unconditionally
	/// and let callers ship a non-canonical payload, where `get_raw` (binary search) and
	/// `get_all_raw` (linear scan) would resolve the duplicate to different entries — a
	/// port-induced bug class where two reasonable verifier implementations of the same
	/// payload disagree on which value is canonical.
	///
	/// Returns self to allow for daisy chaining.
	pub fn push_raw(mut self, id: BeefyPayloadId, value: Vec<u8>) -> Self {
		if let Some(existing) = self.0.iter_mut().find(|(probe, _)| *probe == id) {
			existing.1 = value;
		} else {
			self.0.push((id, value));
		}
		self.0.sort_by_key(|(id, _)| *id);
		self
	}

	/// Verify the canonical-form invariants: identifiers are sorted strictly ascending
	/// (which implies no duplicates).
	///
	/// `Decode` does not enforce this — callers reading `Payload` from untrusted sources
	/// (across-the-wire BEEFY commitments, bridge messages, light-client inputs) MUST
	/// call `is_canonical` before trusting any `get_raw` / `get_decoded` lookup, otherwise
	/// a malicious encoder can ship a payload where `get_raw` and `get_all_raw` resolve
	/// duplicate ids differently.
	pub fn is_canonical(&self) -> bool {
		self.0.windows(2).all(|w| w[0].0 < w[1].0)
	}
}

/// Trait for custom BEEFY payload providers.
pub trait PayloadProvider<B: Block> {
	/// Provide BEEFY payload if available for `header`.
	fn payload(&self, header: &B::Header) -> Option<Payload>;
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn payload_methods_work_as_expected() {
		let id1: BeefyPayloadId = *b"hw";
		let msg1: String = "1. Hello World!".to_string();
		let id2: BeefyPayloadId = *b"yb";
		let msg2: String = "2. Yellow Board!".to_string();
		let id3: BeefyPayloadId = *b"cs";
		let msg3: String = "3. Cello Cord!".to_string();

		let payload = Payload::from_single_entry(id1, msg1.encode())
			.push_raw(id2, msg2.encode())
			.push_raw(id3, msg3.encode());

		assert_eq!(payload.get_decoded(&id1), Some(msg1));
		assert_eq!(payload.get_decoded(&id2), Some(msg2));
		assert_eq!(payload.get_raw(&id3), Some(&msg3.encode()));
		assert_eq!(payload.get_raw(&known_payloads::MMR_ROOT_ID), None);
	}

	#[test]
	fn push_raw_replaces_duplicate_ids() {
		// Per the type contract, identifiers must be unique. `push_raw` previously
		// appended unconditionally and let two entries with the same id coexist —
		// `get_raw` (binary search) and `get_all_raw` (linear scan) would resolve
		// the duplicate to different entries. After the fix, `push_raw` overwrites
		// in place. This test pins both invariants: only one entry remains, and
		// it carries the *latest* value.
		let id: BeefyPayloadId = *b"hw";
		let payload = Payload::from_single_entry(id, b"first".to_vec())
			.push_raw(id, b"second".to_vec())
			.push_raw(id, b"third".to_vec());

		// Single entry survives — `get_all_raw` agrees with `get_raw`.
		let all: Vec<_> = payload.get_all_raw(&id).collect();
		assert_eq!(all.len(), 1, "duplicate ids must collapse to one entry");
		assert_eq!(payload.get_raw(&id), Some(&b"third".to_vec()), "last write wins");
		assert_eq!(all[0], &b"third".to_vec());
		assert!(payload.is_canonical(), "after collapse, payload is canonical");
	}

	#[test]
	fn is_canonical_detects_unsorted_and_duplicate_wire_form() {
		// `Payload`'s `Decode` impl is derived and does NOT enforce canonicality.
		// A malicious wire-form (or a buggy encoder) can ship duplicates or
		// out-of-order ids. Encoded as a `Vec<(BeefyPayloadId, Vec<u8>)>` we can
		// construct that directly with `Decode::decode` from a hand-crafted SCALE
		// blob, but here we exercise the cheaper proxy: build an unsorted Vec via
		// the public push helpers (which DO sort) then mutate the inner Vec via a
		// round-trip through encode/decode of the underlying tuple-vector type.
		let id1: BeefyPayloadId = *b"aa";
		let id2: BeefyPayloadId = *b"bb";

		// Sorted, unique → canonical.
		let canonical = Payload::from_single_entry(id1, vec![1])
			.push_raw(id2, vec![2]);
		assert!(canonical.is_canonical());

		// Decode an unsorted wire-form directly: ids in descending order.
		let unsorted_bytes = vec![(id2, vec![2u8]), (id1, vec![1u8])].encode();
		let decoded = Payload::decode(&mut &unsorted_bytes[..]).expect("decodes");
		assert!(!decoded.is_canonical(), "out-of-order ids must be rejected by is_canonical");

		// Decode a wire-form with duplicates.
		let dup_bytes = vec![(id1, vec![1u8]), (id1, vec![99u8])].encode();
		let decoded = Payload::decode(&mut &dup_bytes[..]).expect("decodes");
		assert!(!decoded.is_canonical(), "duplicate ids must be rejected by is_canonical");
	}
}
