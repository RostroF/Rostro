// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Implementation of the `insert` subcommand

use crate::{
	utils, with_crypto_scheme, CryptoScheme, Error, KeystoreParams, SharedParams, SubstrateCli,
};
use clap::Parser;
use rc_keystore::LocalKeystore;
use rc_service::config::{BasePath, KeystoreConfig};
use sp_core::crypto::{KeyTypeId, SecretString};
use sp_keystore::KeystorePtr;

/// The `insert` command
#[derive(Debug, Clone, Parser)]
#[command(name = "insert", about = "Insert a key to the keystore of a node.")]
pub struct InsertKeyCmd {
	/// The secret key URI.
	/// If the value is a file, the file content is used as URI.
	/// If not given, you will be prompted for the URI.
	#[arg(long)]
	suri: Option<String>,

	/// Key type, examples: "gran", or "imon".
	#[arg(long)]
	key_type: String,

	#[allow(missing_docs)]
	#[clap(flatten)]
	pub shared_params: SharedParams,

	#[allow(missing_docs)]
	#[clap(flatten)]
	pub keystore_params: KeystoreParams,

	/// The cryptography scheme that should be used to generate the key out of the given URI.
	///
	/// Not needed for the node's key types: it is DERIVED from `--key-type`
	/// (`gran`/`chnl` → rostro-hybrid, `sass` → bandersnatch) and refused if
	/// it contradicts the derivation. Unknown key types default to
	/// rostro-hybrid; pass a scheme explicitly for classical keys.
	#[arg(long, value_name = "SCHEME", value_enum, ignore_case = true)]
	pub scheme: Option<CryptoScheme>,
}

/// The scheme a key will actually be generated with, after deriving from
/// the key type. Bandersnatch (Sassafras) is insert-only and has no
/// [`CryptoScheme`] variant: it must never be reachable by flag, only by
/// key-type derivation.
enum ResolvedScheme {
	Classical(CryptoScheme),
	RostroHybrid,
	Bandersnatch,
}

/// Derive the scheme from the key type; an explicit `--scheme` may only
/// agree. This makes "insert gran as ed25519" (the pre-hybrid legacy
/// pattern) unrepresentable rather than a silent misconfiguration — a
/// node that voted fine but could never authenticate its validator
/// channel.
fn resolve_scheme(
	key_type: &str,
	explicit: Option<CryptoScheme>,
) -> Result<ResolvedScheme, Error> {
	let refuse = |required: &str| {
		Err(Error::Input(format!(
			"key type `{key_type}` is always {required}; omit --scheme (it is \
			 derived from the key type)",
		)))
	};
	match key_type {
		"gran" | "chnl" => match explicit {
			None | Some(CryptoScheme::RostroHybrid) => Ok(ResolvedScheme::RostroHybrid),
			Some(_) => refuse("rostro-hybrid"),
		},
		"sass" => match explicit {
			None => Ok(ResolvedScheme::Bandersnatch),
			Some(_) => refuse("bandersnatch"),
		},
		_ => Ok(match explicit {
			None | Some(CryptoScheme::RostroHybrid) => ResolvedScheme::RostroHybrid,
			Some(scheme) => ResolvedScheme::Classical(scheme),
		}),
	}
}

impl InsertKeyCmd {
	/// Run the command
	pub fn run<C: SubstrateCli>(&self, cli: &C) -> Result<(), Error> {
		let resolved = resolve_scheme(&self.key_type, self.scheme)?;
		let suri = utils::read_uri(self.suri.as_ref())?;
		let base_path = self
			.shared_params
			.base_path()?
			.unwrap_or_else(|| BasePath::from_project("", "", &C::executable_name()));
		let chain_id = self.shared_params.chain_id(self.shared_params.is_dev());
		let chain_spec = cli.load_spec(&chain_id)?;
		let config_dir = base_path.config_dir(chain_spec.id());

		let (keystore, public) = match self.keystore_params.keystore_config(&config_dir)? {
			KeystoreConfig::Path { path, password } => {
				// The hybrid and bandersnatch schemes have no MultiSigner
				// identity, so they bypass the generic scheme macro.
				let public: Vec<u8> = match resolved {
					ResolvedScheme::RostroHybrid =>
						to_raw_vec::<sp_core::rostro_hybrid::Pair>(&suri, password.clone())?,
					ResolvedScheme::Bandersnatch =>
						to_raw_vec::<sp_core::bandersnatch::Pair>(&suri, password.clone())?,
					ResolvedScheme::Classical(scheme) =>
						with_crypto_scheme!(scheme, to_vec(&suri, password.clone()))?,
				};
				let keystore: KeystorePtr = LocalKeystore::open(path, password)?.into();
				(keystore, public)
			},
			_ => unreachable!("keystore_config always returns path and password; qed"),
		};

		let key_type =
			KeyTypeId::try_from(self.key_type.as_str()).map_err(|_| Error::KeyTypeInvalid)?;

		keystore
			.insert(key_type, &suri, &public[..])
			.map_err(|_| Error::KeystoreOperation)?;

		Ok(())
	}
}

fn to_vec<P: sp_core::Pair>(uri: &str, pass: Option<SecretString>) -> Result<Vec<u8>, Error> {
	let p = utils::pair_from_suri::<P>(uri, pass)?;
	Ok(p.public().as_ref().to_vec())
}

fn to_raw_vec<P: sp_core::Pair>(uri: &str, pass: Option<SecretString>) -> Result<Vec<u8>, Error> {
	use sp_core::crypto::ByteArray as _;
	let p = utils::pair_from_suri::<P>(uri, pass)?;
	Ok(p.public().to_raw_vec())
}

#[cfg(test)]
mod tests {
	use super::*;
	use rc_service::{ChainSpec, ChainType, GenericChainSpec, NoExtension};
	use sp_core::{sr25519::Pair, ByteArray, Pair as _};
	use sp_keystore::Keystore;
	use tempfile::TempDir;

	struct Cli;

	impl SubstrateCli for Cli {
		fn impl_name() -> String {
			"test".into()
		}

		fn impl_version() -> String {
			"2.0".into()
		}

		fn description() -> String {
			"test".into()
		}

		fn support_url() -> String {
			"test.test".into()
		}

		fn copyright_start_year() -> i32 {
			2021
		}

		fn author() -> String {
			"test".into()
		}

		fn load_spec(&self, _: &str) -> std::result::Result<Box<dyn ChainSpec>, String> {
			let builder =
				GenericChainSpec::<NoExtension, ()>::builder(Default::default(), NoExtension::None);
			Ok(Box::new(
				builder
					.with_name("test")
					.with_id("test_id")
					.with_chain_type(ChainType::Development)
					.with_genesis_config_patch(Default::default())
					.build(),
			))
		}
	}

	fn open_test_keystore(path: &TempDir) -> LocalKeystore {
		LocalKeystore::open(path.path().join("chains").join("test_id").join("keystore"), None)
			.unwrap()
	}

	#[test]
	fn insert_with_custom_base_path() {
		let path = TempDir::new().unwrap();
		let path_str = format!("{}", path.path().display());
		let (key, uri, _) = Pair::generate_with_phrase(None);

		let inspect = InsertKeyCmd::parse_from(&[
			"insert-key",
			"-d",
			&path_str,
			"--key-type",
			"test",
			"--suri",
			&uri,
			"--scheme=sr25519",
		]);
		assert!(inspect.run(&Cli).is_ok());

		let keystore = open_test_keystore(&path);
		assert!(keystore.has_keys(&[(key.public().to_raw_vec(), KeyTypeId(*b"test"))]));
	}

	#[test]
	fn gran_derives_rostro_hybrid_without_scheme_flag() {
		let path = TempDir::new().unwrap();
		let path_str = format!("{}", path.path().display());

		let cmd = InsertKeyCmd::parse_from(&[
			"insert-key", "-d", &path_str, "--key-type", "gran", "--suri", "//Alice",
		]);
		assert!(cmd.run(&Cli).is_ok());

		let keystore = open_test_keystore(&path);
		let direct = sp_core::rostro_hybrid::Pair::from_string("//Alice", None).unwrap();
		// The full 64-byte hybrid public must be on disk — a 32-byte
		// (ed25519-era) gran key is invisible to the hybrid probe and
		// leaves the validator channel dead while finality still works.
		assert_eq!(
			keystore.rostro_hybrid_public_keys(KeyTypeId(*b"gran")),
			vec![direct.public().into()],
		);
	}

	#[test]
	fn gran_with_classical_scheme_is_refused() {
		let path = TempDir::new().unwrap();
		let path_str = format!("{}", path.path().display());

		for scheme in ["--scheme=ed25519", "--scheme=sr25519"] {
			let cmd = InsertKeyCmd::parse_from(&[
				"insert-key", "-d", &path_str, "--key-type", "gran", "--suri", "//Alice", scheme,
			]);
			assert!(cmd.run(&Cli).is_err(), "gran must refuse {scheme}");
		}
		// Explicitly naming the derived scheme is allowed (harmless).
		let cmd = InsertKeyCmd::parse_from(&[
			"insert-key",
			"-d",
			&path_str,
			"--key-type",
			"gran",
			"--suri",
			"//Alice",
			"--scheme=rostro-hybrid",
		]);
		assert!(cmd.run(&Cli).is_ok());
	}

	#[test]
	fn sass_derives_bandersnatch_and_refuses_any_scheme_flag() {
		let path = TempDir::new().unwrap();
		let path_str = format!("{}", path.path().display());

		let cmd = InsertKeyCmd::parse_from(&[
			"insert-key", "-d", &path_str, "--key-type", "sass", "--suri", "//Alice",
		]);
		assert!(cmd.run(&Cli).is_ok());

		let keystore = open_test_keystore(&path);
		let direct = sp_core::bandersnatch::Pair::from_string("//Alice", None).unwrap();
		assert!(keystore.has_keys(&[(direct.public().to_raw_vec(), KeyTypeId(*b"sass"))]));

		// Bandersnatch has no CryptoScheme variant, so ANY explicit
		// scheme contradicts the derivation — including rostro-hybrid.
		let cmd = InsertKeyCmd::parse_from(&[
			"insert-key",
			"-d",
			&path_str,
			"--key-type",
			"sass",
			"--suri",
			"//Alice",
			"--scheme=rostro-hybrid",
		]);
		assert!(cmd.run(&Cli).is_err());
	}

	#[test]
	fn unknown_key_type_defaults_to_rostro_hybrid() {
		let path = TempDir::new().unwrap();
		let path_str = format!("{}", path.path().display());

		let cmd = InsertKeyCmd::parse_from(&[
			"insert-key", "-d", &path_str, "--key-type", "test", "--suri", "//Alice",
		]);
		assert!(cmd.run(&Cli).is_ok());

		let keystore = open_test_keystore(&path);
		assert_eq!(keystore.rostro_hybrid_public_keys(KeyTypeId(*b"test")).len(), 1);
	}
}
