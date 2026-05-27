// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! `rostro-watchdog-monitor` — heartbeat-driven sidecar.
//!
//! Apache-2.0 binary that drives the watchdog heartbeat probe and
//! SIGTERMs a target PID (typically gemini-node) when the watchdog dies.
//! Spawned by `rostro-supervisor` alongside `gemini-node` when
//! `ROSTRO_WATCHDOG_SOCKET` is set; lets the v0.1 kill-watchdog cascade
//! work end-to-end without adding any lines to GPL3 gemini-node.
//!
//! Lifecycle:
//!   1. Parse args; resolve socket path (from `--socket` or env).
//!   2. Connect to watchdog. If connect fails at startup, signal the
//!      target anyway — a missing watchdog at boot is the same failure
//!      mode as a watchdog that died at second 0.
//!   3. Spawn the heartbeat monitor with
//!      `on_dead = kill(target_pid, SIGTERM)`.
//!   4. Block until the monitor exits, then exit cleanly.

use clap::Parser;
use rostro_watchdog_client::{HeartbeatMonitor, WatchdogClient};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "rostro-watchdog-monitor",
    version,
    about = "Heartbeat-driven sidecar that SIGTERMs a target PID when the Rostro watchdog dies."
)]
struct Args {
    /// PID to send SIGTERM to when the watchdog dies (typically
    /// gemini-node's PID, supplied by rostro-supervisor).
    #[arg(long)]
    target_pid: i32,

    /// Path to the watchdog UDS. Defaults to
    /// `$ROSTRO_WATCHDOG_SOCKET`.
    #[arg(long)]
    socket: Option<PathBuf>,

    /// Heartbeat probe interval, in seconds.
    #[arg(long, default_value_t = 30)]
    interval_secs: u64,

    /// Consecutive missed heartbeats tolerated before SIGTERM.
    #[arg(long, default_value_t = 3)]
    miss_budget: u32,
}

fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();

    let target_pid = args.target_pid;
    log::info!("rostro-watchdog-monitor up; target_pid={target_pid}");

    let client = match resolve_client(&args) {
        Ok(c) => c,
        Err(e) => {
            log::warn!(
                "watchdog absent at startup ({e}); signaling target_pid={target_pid} and exiting",
            );
            send_sigterm(target_pid);
            return ExitCode::SUCCESS;
        }
    };
    log::info!(
        "connected to watchdog at {}; probe every {}s, miss budget {}",
        client.socket_path().display(),
        args.interval_secs,
        args.miss_budget,
    );

    let handle = HeartbeatMonitor::spawn(
        Arc::new(client),
        Duration::from_secs(args.interval_secs),
        args.miss_budget,
        move || {
            log::error!(
                "watchdog heartbeat miss budget exhausted; SIGTERM target_pid={target_pid}",
            );
            send_sigterm(target_pid);
        },
    );

    match handle.join() {
        Ok(()) => {
            log::info!("monitor exited; sidecar done");
            ExitCode::SUCCESS
        }
        Err(panic) => {
            log::error!("monitor thread panicked: {panic:?}");
            ExitCode::from(1)
        }
    }
}

fn resolve_client(args: &Args) -> Result<WatchdogClient, rostro_watchdog_client::ClientError> {
    match &args.socket {
        Some(path) => WatchdogClient::connect(path),
        None => WatchdogClient::connect_from_env(),
    }
}

#[cfg(target_os = "linux")]
fn send_sigterm(pid: i32) {
    // SAFETY: libc::kill is always safe to call; ESRCH on an already-
    // reaped target is benign and is what we expect when gemini-node
    // exited on its own.
    let rc = unsafe { libc::kill(pid, libc::SIGTERM) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) {
            log::info!("target_pid={pid} already gone (ESRCH); nothing to signal");
        } else {
            log::warn!("kill({pid}, SIGTERM) failed: {err}");
        }
    } else {
        log::info!("sent SIGTERM to target_pid={pid}");
    }
}

#[cfg(not(target_os = "linux"))]
fn send_sigterm(_pid: i32) {}
