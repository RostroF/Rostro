// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Native host operations for the sassafras ring-VRF.
//!
//! **Rostro divergence from upstream Substrate.**
//!
//! Building the [`vrf::RingVerifierKey`] for an authority set is a
//! fixed-domain MSM over the KZG URS: ~65ms native, ~5s under the RVM
//! interpreter (which is hard-pinned by the Cannae threat model — no
//! JIT in the node). The rebuild fires exactly when an epoch enacts a
//! *changed* authority set, i.e. inside `on_initialize` of the first
//! block after an NPoS era election alters the set. In-VM that exceeds
//! the block-proposal deadline, so the era-boundary block can never be
//! sealed and the chain livelocks (observed live; docs/NPOS.md). The
//! runtime therefore delegates construction to the host through this
//! interface. Hard cutover: there is no in-VM fallback path.
//!
//! Node binaries executing the runtime must register
//! [`HostFunctions`] with their executor (gemini-node does; so does the
//! chain-spec genesis builder via the `EHF` parameter — genesis also
//! derives the ring verifier when authorities arrive via session
//! genesis).

use alloc::vec::Vec;
use sp_runtime_interface::{
	pass_by::{AllocateAndReturnByCodec, PassFatPointerAndRead},
	runtime_interface,
};

pub use sassafras_ring::ring_verifier_key;
#[cfg(feature = "std")]
pub use sassafras_ring::HostFunctions;

/// Ring-VRF operations that must run natively.
#[runtime_interface]
pub trait SassafrasRing {
	/// Build the SCALE-serialized [`vrf::RingVerifierKey`] for the given
	/// authority set against a SCALE-serialized [`vrf::RingContext`].
	///
	/// `pks` is the concatenation of 32-byte bandersnatch public keys in
	/// authority order (keys that fail to deserialize as curve points are
	/// replaced by the ring padding point, mirroring
	/// `RingContext::verifier_key` semantics). Returns `None` when either
	/// input fails to decode.
	fn ring_verifier_key(
		ctx: PassFatPointerAndRead<&[u8]>,
		pks: PassFatPointerAndRead<&[u8]>,
	) -> AllocateAndReturnByCodec<Option<Vec<u8>>> {
		use crate::vrf;
		use codec::{Decode, Encode};
		use sp_core::{bandersnatch::Public, crypto::ByteArray};

		let ctx = vrf::RingContext::decode(&mut &ctx[..]).ok()?;
		if pks.len() % 32 != 0 {
			return None;
		}
		let publics: Vec<Public> =
			pks.chunks_exact(32).map(|c| Public::from_slice(c).expect("32 bytes; qed")).collect();
		Some(ctx.verifier_key(&publics).encode())
	}
}
