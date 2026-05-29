// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! `rostro-watchdog` binary — v0.1.
//!
//! Lifecycle:
//!   1. Generate a fresh Ed25519 libp2p identity into a `WatchdogSigner`.
//!   2. Bind a Unix-domain socket at `--socket` (defaults to
//!      `$XDG_RUNTIME_DIR/rostro-watchdog-<pid>.sock`).
//!   3. Start the UDS server on a background thread; it serves
//!      `Sign` / `Heartbeat` / `GetPubkey` requests on a per-connection
//!      loop, gated by `SO_PEERCRED` against the watchdog's UID.
//!   4. Install a `SIGTERM` / `SIGINT` forwarder that relays to the
//!      supervisor's PID once it's stored.
//!   5. Spawn `--supervisor <path>` with the socket path handed down via
//!      `ROSTRO_WATCHDOG_SOCKET` (supervisor passes it through to
//!      gemini-node via standard env inheritance).
//!   6. Wait for the supervisor; propagate its exit code.
//!   7. Unlink the socket on clean exit (best effort).
//!
//! Explicitly NOT in v0.1:
//!   * No `PR_SET_PDEATHSIG` cascade (half-cascade orphans gemini-node —
//!     see `supervisor.rs` module docs).
//!   * Heartbeat-driven cert renewal.
//!   * Supervisor non-zero exit → recovery cascade.
//!   * UDS server is gated to `--supervisor`-present runs; running the
//!     watchdog alone exits immediately after logging the pubkey.

use clap::Parser;
use rostro_watchdog::{
    default_socket_path, spawn_supervisor, HeartbeatCounter, Server, ServerConfig,
    WatchdogSigner,
};
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use std::thread;

static SUPERVISOR_PID: AtomicI32 = AtomicI32::new(-1);

#[derive(Parser, Debug)]
#[command(
    name = "rostro-watchdog",
    version,
    about = "Long-lived host-side trust process for Rostro nodes (v0.1)."
)]
struct Args {
    /// Path to the Unix-domain socket the node connects to for signing
    /// and heartbeats. Defaults to
    /// `$XDG_RUNTIME_DIR/rostro-watchdog-<pid>.sock`, falling back to
    /// `/tmp/rostro-watchdog-<pid>.sock` when XDG is unset.
    #[arg(long)]
    socket: Option<PathBuf>,

    /// Path to the `rostro-supervisor` binary the watchdog will parent.
    /// If omitted, the watchdog logs its pubkey and exits cleanly (UDS
    /// server requires `--supervisor`).
    #[arg(long)]
    supervisor: Option<PathBuf>,

    /// Path to the `rostro-watchdog-monitor` sidecar binary. When set,
    /// the watchdog hands it to the supervisor via
    /// `ROSTRO_WATCHDOG_MONITOR_BINARY`; the supervisor then spawns the
    /// monitor alongside gemini-node. When unset, no monitor runs and
    /// kill-watchdog only takes the network down via cert TTL when that
    /// machinery ships.
    #[arg(long)]
    monitor_binary: Option<PathBuf>,

    /// Directory the heal pipeline stages new canonical bytes into.
    /// Watchdog inotifies this dir (Linux only); on a closed-write of
    /// `<name>.new` it reads the sidecar `<name>.new.expected_hash`,
    /// re-hashes the staged bytes, and renames into
    /// `--canonical-dir` on hash match. Required together with
    /// `--canonical-dir`. When unset, the staging watcher is disabled.
    #[arg(long)]
    canonical_staging_dir: Option<PathBuf>,

    /// Directory holding the canonical foundation files (typically
    /// `--sandbox-ro-path` from the supervisor's perspective). The
    /// staging watcher rotates validated `<name>.new` files from
    /// `--canonical-staging-dir` into this directory. Required when
    /// `--canonical-staging-dir` is set.
    #[arg(long)]
    canonical_dir: Option<PathBuf>,

    /// Arguments passed through to the supervisor. Use `--` to separate:
    /// `rostro-watchdog --supervisor /path/to/sup -- --child /path/to/node`.
    #[arg(last = true, allow_hyphen_values = true)]
    supervisor_args: Vec<OsString>,
}

fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();

    let signer = Arc::new(WatchdogSigner::generate());
    let heartbeat = Arc::new(HeartbeatCounter::new());

    log::info!(
        "rostro-watchdog v0.1 up. libp2p identity pubkey = {}",
        hex_lower(&signer.public_key()),
    );

    let Some(supervisor_path) = args.supervisor else {
        log::info!(
            "--supervisor not provided; UDS server is gated to supervisor-present runs. exiting cleanly."
        );
        return ExitCode::SUCCESS;
    };

    let socket_path = args.socket.unwrap_or_else(default_socket_path);
    let server = match Server::bind(
        ServerConfig {
            socket_path: socket_path.clone(),
            require_uid: Some(current_uid()),
        },
        signer.clone(),
        heartbeat.clone(),
    ) {
        Ok(s) => s,
        Err(e) => {
            log::error!("failed to bind UDS at {}: {e}", socket_path.display());
            return ExitCode::from(127);
        }
    };
    log::info!("UDS listening at {}", socket_path.display());

    let _server_thread = thread::spawn(move || {
        if let Err(e) = server.run() {
            log::error!("watchdog server thread exited: {e}");
        }
    });

    // Staging watcher: validates + rotates staged canonical files (the
    // piece-A heal-pipeline responsibility migrated from supervisor).
    // Requires both --canonical-staging-dir and --canonical-dir; either
    // missing → watcher disabled (dev mode where heal stages adjacent
    // to canonical and the watcher would be redundant).
    let staging_watch = match (
        args.canonical_staging_dir.as_ref(),
        args.canonical_dir.as_ref(),
    ) {
        (Some(staging), Some(canonical)) => {
            if let Err(e) = std::fs::create_dir_all(staging) {
                log::warn!(
                    "could not create --canonical-staging-dir {}: {e}; watcher disabled",
                    staging.display(),
                );
                None
            } else {
                Some((staging.clone(), canonical.clone()))
            }
        },
        (None, None) => None,
        (Some(_), None) => {
            log::warn!(
                "--canonical-staging-dir set without --canonical-dir; staging watcher disabled"
            );
            None
        },
        (None, Some(_)) => {
            log::warn!(
                "--canonical-dir set without --canonical-staging-dir; staging watcher disabled"
            );
            None
        },
    };
    let _staging_thread = staging_watch.map(|(staging, canonical)| {
        thread::spawn(move || {
            #[cfg(target_os = "linux")]
            {
                if let Err(e) = rostro_watchdog::run_inotify_loop(&staging, &canonical) {
                    log::error!("staging watcher exited: {e}");
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (&staging, &canonical);
                log::warn!("staging watcher: only implemented on Linux");
            }
        })
    });

    install_signal_forwarder();

    log::info!(
        "spawning supervisor {} ({} extra arg{})",
        supervisor_path.display(),
        args.supervisor_args.len(),
        if args.supervisor_args.len() == 1 { "" } else { "s" },
    );

    let mut child = match spawn_supervisor(
        &supervisor_path,
        &args.supervisor_args,
        Some(&socket_path),
        args.monitor_binary.as_deref(),
    ) {
        Ok(c) => c,
        Err(e) => {
            log::error!("failed to spawn supervisor: {e}");
            let _ = std::fs::remove_file(&socket_path);
            return ExitCode::from(127);
        }
    };

    SUPERVISOR_PID.store(child.id() as i32, Ordering::Relaxed);
    log::info!("supervisor pid = {}", child.id());

    let status = child.wait();

    let _ = std::fs::remove_file(&socket_path);

    match status {
        Ok(s) => match s.code() {
            Some(0) => {
                log::info!("supervisor exited cleanly");
                ExitCode::SUCCESS
            }
            Some(code) => {
                log::warn!("supervisor exited with code {code}");
                ExitCode::from(code.clamp(0, 255) as u8)
            }
            None => {
                log::warn!("supervisor terminated by signal: {s:?}");
                ExitCode::from(1)
            }
        },
        Err(e) => {
            log::error!("wait() on supervisor failed: {e}");
            ExitCode::from(127)
        }
    }
}

#[cfg(target_os = "linux")]
fn current_uid() -> u32 {
    // SAFETY: getuid is always defined and has no side effects.
    unsafe { libc::getuid() }
}

#[cfg(not(target_os = "linux"))]
fn current_uid() -> u32 {
    0
}

#[cfg(target_os = "linux")]
extern "C" fn forward_signal(sig: libc::c_int) {
    let pid = SUPERVISOR_PID.load(Ordering::Relaxed);
    if pid > 0 {
        // SAFETY: libc::kill is async-signal-safe. ESRCH on a reaped PID
        // is deliberately ignored; PID reuse is bounded by the kernel
        // PID-space wrap and effectively never triggers in a single
        // watchdog run.
        unsafe {
            libc::kill(pid, sig);
        }
    }
}

#[cfg(target_os = "linux")]
fn install_signal_forwarder() {
    let handler: extern "C" fn(libc::c_int) = forward_signal;
    // SAFETY: signal-handler registration is async-signal-safe. Installed
    // once at startup before spawning the supervisor; handler is a no-op
    // while SUPERVISOR_PID stays at -1.
    unsafe {
        libc::signal(libc::SIGTERM, handler as libc::sighandler_t);
        libc::signal(libc::SIGINT, handler as libc::sighandler_t);
    }
}

#[cfg(not(target_os = "linux"))]
fn install_signal_forwarder() {}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(nibble(b >> 4));
        s.push(nibble(b & 0x0F));
    }
    s
}

fn nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + (n - 10)) as char,
        _ => unreachable!(),
    }
}
