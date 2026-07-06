// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Test accounts for the Rostro hybrid (ed25519 + SLH-DSA-SHA2-128f)
//! consensus scheme. Mirrors the ed25519 keyring, except publics are
//! derived from the `//name` pairs rather than pinned as constants
//! (the hybrid public embeds an SLH-DSA key; deriving keeps exactly one
//! source of truth, the one-seed HKDF expansion).

pub use sp_core::rostro_hybrid;

use crate::ParseKeyringError;
#[cfg(feature = "std")]
use sp_core::rostro_hybrid::Signature;
use sp_core::{
	rostro_hybrid::{Pair, Public},
	ByteArray, Pair as PairT,
};

extern crate alloc;
use alloc::{format, str::FromStr, string::String, vec::Vec};

/// Set of test accounts.
#[derive(
	Debug, Clone, Copy, PartialEq, Eq, Hash, strum::Display, strum::EnumIter, Ord, PartialOrd,
)]
pub enum Keyring {
	Alice,
	Bob,
	Charlie,
	Dave,
	Eve,
	Ferdie,
	AliceStash,
	BobStash,
	CharlieStash,
	DaveStash,
	EveStash,
	FerdieStash,
	One,
	Two,
}

impl Keyring {
	pub fn from_public(who: &Public) -> Option<Keyring> {
		Self::iter().find(|&k| &Public::from(k) == who)
	}

	pub fn from_raw_public(who: [u8; 64]) -> Option<Keyring> {
		Self::from_public(&Public::from_raw(who))
	}

	pub fn to_raw_public(self) -> [u8; 64] {
		*Public::from(self).as_array_ref()
	}

	pub fn to_raw_public_vec(self) -> Vec<u8> {
		Public::from(self).to_raw_vec()
	}

	#[cfg(feature = "std")]
	pub fn sign(self, msg: &[u8]) -> Signature {
		Pair::from(self).sign(msg)
	}

	pub fn pair(self) -> Pair {
		Pair::from_string(&format!("//{}", <&'static str>::from(self)), None)
			.expect("static values are known good; qed")
	}

	/// Returns an iterator over all test accounts.
	pub fn iter() -> impl Iterator<Item = Keyring> {
		<Self as strum::IntoEnumIterator>::iter()
	}

	pub fn public(self) -> Public {
		Public::from(self)
	}

	pub fn to_seed(self) -> String {
		format!("//{}", self)
	}

	pub fn well_known() -> impl Iterator<Item = Keyring> {
		Self::iter().take(12)
	}

	pub fn invulnerable() -> impl Iterator<Item = Keyring> {
		Self::iter().take(6)
	}
}

impl From<Keyring> for &'static str {
	fn from(k: Keyring) -> Self {
		match k {
			Keyring::Alice => "Alice",
			Keyring::Bob => "Bob",
			Keyring::Charlie => "Charlie",
			Keyring::Dave => "Dave",
			Keyring::Eve => "Eve",
			Keyring::Ferdie => "Ferdie",
			Keyring::AliceStash => "Alice//stash",
			Keyring::BobStash => "Bob//stash",
			Keyring::CharlieStash => "Charlie//stash",
			Keyring::DaveStash => "Dave//stash",
			Keyring::EveStash => "Eve//stash",
			Keyring::FerdieStash => "Ferdie//stash",
			Keyring::One => "One",
			Keyring::Two => "Two",
		}
	}
}

impl FromStr for Keyring {
	type Err = ParseKeyringError;

	fn from_str(s: &str) -> Result<Self, <Self as FromStr>::Err> {
		match s {
			"Alice" | "alice" => Ok(Keyring::Alice),
			"Bob" | "bob" => Ok(Keyring::Bob),
			"Charlie" | "charlie" => Ok(Keyring::Charlie),
			"Dave" | "dave" => Ok(Keyring::Dave),
			"Eve" | "eve" => Ok(Keyring::Eve),
			"Ferdie" | "ferdie" => Ok(Keyring::Ferdie),
			"Alice//stash" | "alice//stash" => Ok(Keyring::AliceStash),
			"Bob//stash" | "bob//stash" => Ok(Keyring::BobStash),
			"Charlie//stash" | "charlie//stash" => Ok(Keyring::CharlieStash),
			"Dave//stash" | "dave//stash" => Ok(Keyring::DaveStash),
			"Eve//stash" | "eve//stash" => Ok(Keyring::EveStash),
			"Ferdie//stash" | "ferdie//stash" => Ok(Keyring::FerdieStash),
			"One" | "one" => Ok(Keyring::One),
			"Two" | "two" => Ok(Keyring::Two),
			_ => Err(ParseKeyringError),
		}
	}
}

impl From<Keyring> for Public {
	fn from(k: Keyring) -> Self {
		k.pair().public()
	}
}

impl From<Keyring> for Pair {
	fn from(k: Keyring) -> Self {
		k.pair()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use sp_core::crypto::Pair as _;

	#[test]
	fn should_work() {
		assert!(Keyring::Alice.public() != Keyring::Bob.public());
		let msg = b"I am Alice!";
		let sig = Keyring::Alice.sign(msg);
		assert!(Pair::verify(&sig, msg, &Keyring::Alice.public()));
		assert!(!Pair::verify(&sig, msg, &Keyring::Bob.public()));
		assert!(!Pair::verify(&sig, b"I am not Alice!", &Keyring::Alice.public()));
	}
}
