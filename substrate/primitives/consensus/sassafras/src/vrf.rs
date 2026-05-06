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

//! Utilities related to VRF input, pre-output and signatures.

use crate::{Randomness, TicketBody, TicketId};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use codec::Encode;
use sp_consensus_slots::Slot;

pub use sp_core::bandersnatch::{
	ring_vrf::{RingProver, RingVerifier, RingVerifierKey, RingVrfSignature},
	vrf::{VrfInput, VrfPreOutput, VrfSignData, VrfSignature},
};

/// Ring size (aka authorities count) for Sassafras consensus.
///
/// **Rostro divergence from upstream Substrate (was 1024).**
///
/// This is the *maximum* number of active validators per epoch the
/// ring-VRF can accommodate, baked into the KZG URS at genesis. Picking
/// it is a one-time chain-spec decision; raising it later requires a
/// runtime upgrade with a fresh ceremony at the larger degree, since
/// you cannot extend a published KZG SRS to higher powers without
/// knowing the trapdoor τ.
///
/// Rostro picks **512** for v1 (vs. Polkadot's 1024) because:
///
/// 1. The required URS size is `pcs_domain_size(R) = 3 *
///    piop_domain_size(R) + 1`, where `piop_domain_size` is the next
///    power of two after `R + 4 + 252` (252 = bandersnatch scalar bit
///    size). For R=512 that's 3073 G1 powers; for R=1024 it's 6145.
/// 2. Ethereum's EIP-4844 KZG ceremony output (the largest publicly
///    available BLS12-381 ceremony, ~141k contributors) provides 4096
///    G1 powers — sufficient for R=512 with headroom, insufficient for
///    R=1024.
/// 3. Sovereign chains in this validator-economics class (NPoS, low
///    hundreds to mid-hundreds of active validators) sit comfortably
///    inside R=512. Polkadot's R=1024 was sized for their 1000+
///    validators-per-era target, which is a Polkadot-scale parameter.
/// 4. If Rostro grows past this ceiling years from now, the runtime
///    upgrade path is real: re-ceremony at higher degree, ticket-pool
///    flush across the boundary, validator-key rotation as needed.
///
/// A future Rostro fork that targets Polkadot-class validator counts
/// would change this constant + run a larger ceremony. Code that
/// references `RING_SIZE` directly (rather than hard-coding 512 or
/// 1024) automatically scales.
pub const RING_SIZE: usize = 512;

/// Bandersnatch VRF [`RingContext`] specialization for Sassafras using [`RING_SIZE`].
pub type RingContext = sp_core::bandersnatch::ring_vrf::RingContext<RING_SIZE>;

/// Input for slot claim
pub fn slot_claim_input(randomness: &Randomness, slot: Slot, epoch: u64) -> VrfInput {
	let v = [b"sassafras-ticket", randomness.as_slice(), &slot.to_le_bytes(), &epoch.to_le_bytes()]
		.concat();
	VrfInput::new(&v[..])
}

/// Signing-data to claim slot ownership during block production.
pub fn slot_claim_sign_data(randomness: &Randomness, slot: Slot, epoch: u64) -> VrfSignData {
	let v = [b"sassafras-ticket", randomness.as_slice(), &slot.to_le_bytes(), &epoch.to_le_bytes()]
		.concat();
	VrfSignData::new(&v[..], &[])
}

/// VRF input to generate the ticket id.
pub fn ticket_id_input(randomness: &Randomness, attempt: u32, epoch: u64) -> VrfInput {
	let v =
		[b"sassafras-ticket", randomness.as_slice(), &attempt.to_le_bytes(), &epoch.to_le_bytes()]
			.concat();
	VrfInput::new(&v[..])
}

/// Data to be signed via ring-vrf.
pub fn ticket_body_sign_data(ticket_body: &TicketBody, ticket_id_input: VrfInput) -> VrfSignData {
	VrfSignData { vrf_input: ticket_id_input, aux_data: ticket_body.encode() }
}

/// Make ticket-id from the given VRF pre-output.
///
/// Pre-output should have been obtained from the input directly using the vrf
/// secret key or from the vrf signature pre-output.
pub fn make_ticket_id(preout: &VrfPreOutput) -> TicketId {
	let bytes: [u8; 16] = preout.make_bytes()[..16].try_into().unwrap();
	u128::from_le_bytes(bytes)
}
