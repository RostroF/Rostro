// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! `rostro-watchdog` v0.1 — long-lived host-side trust process for Rostro
//! nodes.
//!
//! Per the `host-process-topology` memory, the watchdog is the long-lived
//! trust root that parents `rostro-supervisor` (which parents
//! `gemini-node`). It holds the node's libp2p identity key out-of-process,
//! signs over a Unix-domain socket on a typed `sign_kind` whitelist, and
//! emits a heartbeat counter the node uses to gate its libp2p sessions.
//!
//! v0.1 scope (weak form):
//!   * Linux only.
//!   * Ephemeral Ed25519 key in process RAM. No TPM seal.
//!   * Libp2p identity surface only — no validator session keys, no
//!     canonical-files heal absorption, no compile-from-source fallback.
//!   * On supervisor non-zero exit, watchdog logs and exits cleanly. The
//!     full recovery cascade is v0.2.
//!
//! The protocol-decode / signer / heartbeat / dispatch layers are sans-IO
//! and unit-testable; `server` wires them up to a
//! `std::os::unix::net::UnixListener` accept loop with `SO_PEERCRED`-gated
//! per-connection serving.

pub mod frame;
pub mod heartbeat;
pub mod proto;
#[cfg(target_os = "linux")]
pub mod server;
pub mod sign_kind;
pub mod signer;
pub mod staging_watcher;
pub mod supervisor;

pub use frame::{Frame, FrameError, Op, FRAME_VERSION, MAX_FRAME_BODY_LEN};
pub use heartbeat::HeartbeatCounter;
pub use proto::{dispatch, ErrorCode};
#[cfg(target_os = "linux")]
pub use server::{default_socket_path, Server, ServerConfig};
pub use sign_kind::{SignKind, SignKindError, DOMAIN_PREFIX};
pub use signer::{SignerError, WatchdogSigner, PUBKEY_LEN, SIGNATURE_LEN};
pub use staging_watcher::{
	blake2_256, hex_encode as hex_encode_hash, process_staged_file, read_sidecar_hash,
	RotateOutcome,
};
#[cfg(target_os = "linux")]
pub use staging_watcher::run_inotify_loop;
pub use supervisor::spawn_supervisor;
