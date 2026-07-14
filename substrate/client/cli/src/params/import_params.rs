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

use crate::params::{DatabaseParams, PruningParams};
use clap::{Args, ValueEnum};

/// Parameters for block import.
#[derive(Debug, Clone, Args)]
pub struct ImportParams {
	#[allow(missing_docs)]
	#[clap(flatten)]
	pub pruning_params: PruningParams,

	#[allow(missing_docs)]
	#[clap(flatten)]
	pub database_params: DatabaseParams,

	/// Specify the state cache size.
	///
	/// Providing `0` will disable the cache.
	#[arg(long, value_name = "Bytes", default_value_t = 1024 * 1024 * 1024)]
	pub trie_cache_size: usize,

	/// Warm up the trie cache.
	///
	/// No warmup if flag is not present. Using flag without value chooses non-blocking warmup.
	#[arg(long, value_name = "STRATEGY", value_enum, num_args = 0..=1, default_missing_value = "non-blocking")]
	pub warm_up_trie_cache: Option<TrieCacheWarmUpStrategy>,
}

/// Warmup strategy for the trie cache.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum TrieCacheWarmUpStrategy {
	/// Warm up the cache in a non-blocking way.
	#[clap(name = "non-blocking")]
	NonBlocking,
	/// Warm up the cache in a blocking way (not recommended for production use).
	///
	/// When enabled, the trie cache warm-up will block the node startup until complete.
	/// This is not recommended for production use as it can significantly delay node startup.
	/// Only enable this option for testing or debugging purposes.
	#[clap(name = "blocking")]
	Blocking,
}

impl From<TrieCacheWarmUpStrategy> for rc_service::config::TrieCacheWarmUpStrategy {
	fn from(strategy: TrieCacheWarmUpStrategy) -> Self {
		match strategy {
			TrieCacheWarmUpStrategy::NonBlocking => {
				rc_service::config::TrieCacheWarmUpStrategy::NonBlocking
			},
			TrieCacheWarmUpStrategy::Blocking => {
				rc_service::config::TrieCacheWarmUpStrategy::Blocking
			},
		}
	}
}

impl ImportParams {
	/// Specify the trie cache maximum size.
	pub fn trie_cache_maximum_size(&self) -> Option<usize> {
		if self.trie_cache_size == 0 {
			None
		} else {
			Some(self.trie_cache_size)
		}
	}

	/// Specify if we should warm up the trie cache.
	pub fn warm_up_trie_cache(&self) -> Option<TrieCacheWarmUpStrategy> {
		self.warm_up_trie_cache
	}

}

