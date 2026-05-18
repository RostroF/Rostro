// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Gemini node — Sassafras + GRANDPA over gemini-runtime. Phase Ring
//! R3.6 testbed binary.

#![warn(missing_docs)]

mod active_authority_set;
mod attest_asker;
mod attest_protocol;
mod canonical_fetch_client;
mod canonical_fetch_protocol;
mod chain_spec;
mod chat_fetch_protocol;
mod chat_rpc;
mod chat_stripe_protocol;
mod cli;
mod command;
mod connect_gate;
mod file_check;
mod policy_refresh;
mod role;
mod rpc;
mod service;
mod ticket_submitter;
mod validator_channel;

fn main() -> rc_cli::Result<()> {
	command::run()
}
