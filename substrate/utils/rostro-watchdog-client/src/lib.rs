// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Client for the Rostro watchdog Unix-domain-socket protocol.
//!
//! v0.1 = advisory client. A consumer (gemini-node, in production) opens a
//! single persistent connection at startup, then drives the heartbeat
//! probe via [`HeartbeatMonitor`]; on missed beats it invokes the
//! caller-supplied `on_dead` callback (typically: trigger graceful node
//! shutdown). [`WatchdogClient::sign`] and [`WatchdogClient::get_pubkey`]
//! are exposed for future use but the v0.1 node does NOT yet route
//! libp2p identity signing through them — that's the v0.2 effort and
//! needs vendored libp2p-identity.
//!
//! Linux only, mirroring the server. Single connection, mutex-serialised
//! request/reply over the byte stream; no internal worker thread.

pub mod client;
pub mod monitor;

pub use client::{ClientError, WatchdogClient, SOCKET_ENV_VAR};
pub use monitor::HeartbeatMonitor;

// Re-export the wire-protocol types so consumers don't need to depend on
// `rostro-watchdog` directly.
pub use rostro_watchdog::{ErrorCode, FrameError, Op, SignKind};
