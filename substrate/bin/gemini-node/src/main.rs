// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Gemini node — Sassafras + GRANDPA over gemini-runtime. Phase Ring
//! R3.6 testbed binary.

#![warn(missing_docs)]

mod chain_spec;
mod cli;
mod command;
mod policy_refresh;
mod role;
mod rpc;
mod service;

fn main() -> rc_cli::Result<()> {
	command::run()
}
