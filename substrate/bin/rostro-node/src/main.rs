// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Rostro solochain node — entry point.

#![warn(missing_docs)]

mod chain_spec;
mod cli;
mod command;
mod rpc;
mod service;

fn main() -> rc_cli::Result<()> {
	command::run()
}
