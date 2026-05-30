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
    default_socket_path, recovery, recovery_state::RecoveryState, spawn_supervisor,
    HeartbeatCounter, Server, ServerConfig, WatchdogSigner, ROSTRO_RELEASE_PUBKEY,
};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

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

    /// Directory holding the canonical-cache (heal-source) bytes
    /// plus the SRT-signed `manifest.txt` + `manifest.txt.sig`. The
    /// piece-B recovery path reads from here when the supervisor
    /// exits non-zero: it verifies the manifest signature against
    /// the compile-time-baked `ROSTRO_RELEASE_PUBKEY`, hashes the
    /// canonical-cache files against the manifest's SHA256 entries,
    /// and stages the verified bytes into `--canonical-staging-dir`
    /// for the staging watcher to commit. When unset, recovery is
    /// disabled and supervisor non-zero exits propagate directly to
    /// systemd.
    #[arg(long)]
    canonical_files_dir: Option<PathBuf>,

    /// Maximum supervisor-failure recovery attempts before the
    /// watchdog gives up and propagates the failure to systemd.
    /// Counter persists across watchdog restarts via
    /// `--recovery-state-file`. Default 3 — covers transient
    /// gemini-node panic loops without hiding a permanently broken
    /// canonical-cache.
    #[arg(long, default_value_t = 3)]
    max_recovery_attempts: u32,

    /// Path to the watchdog's persisted recovery-counter state file.
    /// Defaults to `<canonical-staging-dir>/.watchdog-recovery-state`
    /// when staging is configured; otherwise unset and counter does
    /// not persist (degrades to per-watchdog-lifetime cap).
    #[arg(long)]
    recovery_state_file: Option<PathBuf>,

    /// Maximum wall-clock seconds to wait for the staging watcher to
    /// commit a recovered file into `--canonical-dir` before
    /// respawning the supervisor. If the wait times out the watchdog
    /// still respawns — the supervisor's child will catch the
    /// remaining mismatch and re-enter the swap-and-restart loop.
    /// Default 30s.
    #[arg(long, default_value_t = 30)]
    recovery_settle_timeout_secs: u64,

    /// Localhost RPC host the reconciliation thread queries for the
    /// on-chain `rostro_release` pubkey (B.1-bis). Defaults to
    /// `127.0.0.1`; lab + production use the same host since
    /// reconciliation is loopback-only.
    #[arg(long, default_value = "127.0.0.1")]
    reconcile_rpc_host: String,

    /// Localhost RPC port the reconciliation thread queries.
    /// Defaults to substrate's `9944`. When 0, reconciliation is
    /// disabled.
    #[arg(long, default_value_t = 9944)]
    reconcile_rpc_port: u16,

    /// Interval (seconds) between reconciliation polls. Default 300
    /// (5 minutes) — long enough that a healthy node generates very
    /// little RPC traffic, short enough to surface divergence
    /// within a sensible operator-attention window.
    #[arg(long, default_value_t = 300)]
    reconcile_interval_secs: u64,

    /// Per-poll RPC timeout (seconds). Default 5.
    #[arg(long, default_value_t = 5)]
    reconcile_rpc_timeout_secs: u64,

    /// Path to a file the reconciler touches on each successful
    /// match (with `last_match_unix_secs=<seconds>`). Operators can
    /// use this for monitoring "how long since reconciliation last
    /// succeeded" via filesystem inspection. Defaults to
    /// `<canonical-staging-dir>/.watchdog-reconciliation-state` when
    /// staging is configured; otherwise no file is written.
    #[arg(long)]
    reconcile_state_file: Option<PathBuf>,

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

    // Reconciliation thread (piece B.1-bis): periodically polls the
    // localhost gemini-node RPC for the on-chain `rostro_release`
    // pubkey and compares against the compile-time-baked value.
    // Disabled when --reconcile-rpc-port=0 (e.g. when the watchdog
    // runs without a local gemini-node).
    if args.reconcile_rpc_port != 0 {
        let reconcile_state_path: Option<PathBuf> = args
            .reconcile_state_file
            .clone()
            .or_else(|| {
                args.canonical_staging_dir
                    .as_ref()
                    .map(|d| d.join(".watchdog-reconciliation-state"))
            });
        let host = args.reconcile_rpc_host.clone();
        let port = args.reconcile_rpc_port;
        let interval = std::time::Duration::from_secs(args.reconcile_interval_secs);
        let rpc_timeout =
            std::time::Duration::from_secs(args.reconcile_rpc_timeout_secs);
        log::info!(
            "spawning reconciliation thread: {}:{} every {}s",
            host,
            port,
            interval.as_secs()
        );
        let _reconcile_thread = rostro_watchdog::reconciliation::spawn_reconciler(
            host,
            port,
            *ROSTRO_RELEASE_PUBKEY,
            interval,
            rpc_timeout,
            reconcile_state_path,
        );
    }

    // Resolve recovery-state file path. Defaults to a sibling of the
    // staging dir (where the watchdog has unconditional write access)
    // unless explicitly set. When neither flag points anywhere
    // writable, the counter degrades to per-watchdog-lifetime — still
    // bounded, just doesn't survive a watchdog kill.
    let recovery_state_path: Option<PathBuf> = args.recovery_state_file.clone().or_else(|| {
        args.canonical_staging_dir
            .as_ref()
            .map(|d| d.join(".watchdog-recovery-state"))
    });

    let mut recovery_state = recovery_state_path
        .as_deref()
        .map(RecoveryState::load)
        .unwrap_or_default();

    if args.canonical_files_dir.is_some() {
        log::info!(
            "piece-B recovery armed: canonical_files_dir={} max_attempts={} state_file={} recovery_attempts={}/{}",
            args.canonical_files_dir.as_ref().unwrap().display(),
            args.max_recovery_attempts,
            recovery_state_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "(ephemeral)".to_string()),
            recovery_state.recovery_attempts,
            args.max_recovery_attempts,
        );
    }

    let settle_timeout = Duration::from_secs(args.recovery_settle_timeout_secs);

    // The recovery loop. On clean supervisor exit (code 0) → watchdog
    // exits 0. On non-zero exit AND recovery is configured AND counter
    // is under the cap → run recovery, wait for staging_watcher to
    // commit, respawn supervisor. Otherwise → propagate non-zero exit.
    loop {
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
        SUPERVISOR_PID.store(-1, Ordering::Relaxed);

        match status {
            Ok(s) => match s.code() {
                Some(0) => {
                    log::info!("supervisor exited cleanly");
                    // Reset the persisted recovery counter — supervisor
                    // ran long enough to shut down cleanly, so the
                    // canonical-cache is no longer in a "stuck" state.
                    if recovery_state.recovery_attempts > 0 {
                        recovery_state.recovery_attempts = 0;
                        if let Some(p) = recovery_state_path.as_deref() {
                            let _ = recovery_state.save_and_mirror(p);
                        }
                    }
                    let _ = std::fs::remove_file(&socket_path);
                    return ExitCode::SUCCESS;
                },
                Some(code) => {
                    log::warn!("supervisor exited with code {code}");
                    // Only attempt recovery if a canonical-files-dir
                    // is configured AND a canonical-dir (target) is
                    // configured AND a canonical-staging-dir is
                    // configured. Otherwise we have no place to stage
                    // recovered bytes; just propagate.
                    if let (Some(files), Some(canonical), Some(staging)) = (
                        args.canonical_files_dir.as_ref(),
                        args.canonical_dir.as_ref(),
                        args.canonical_staging_dir.as_ref(),
                    ) {
                        if recovery_state.recovery_attempts >= args.max_recovery_attempts {
                            log::error!(
                                "max_recovery_attempts={} exhausted (persisted); watchdog giving up",
                                args.max_recovery_attempts,
                            );
                            let _ = std::fs::remove_file(&socket_path);
                            return ExitCode::from(code.clamp(0, 255) as u8);
                        }
                        recovery_state.recovery_attempts = recovery_state
                            .recovery_attempts
                            .saturating_add(1);
                        if let Some(p) = recovery_state_path.as_deref() {
                            let _ = recovery_state.save_and_mirror(p);
                        }
                        log::info!(
                            "running recovery cascade (attempt {} of {})",
                            recovery_state.recovery_attempts,
                            args.max_recovery_attempts,
                        );
                        match recovery::run(files, canonical, staging, ROSTRO_RELEASE_PUBKEY) {
                            Ok(recovery::RecoveryOutcome::Staged { count, files: staged_files }) => {
                                log::info!(
                                    "recovery staged {count} file(s): {}; waiting for staging-watcher to commit",
                                    staged_files.join(", "),
                                );
                                wait_for_staging_commit(
                                    canonical,
                                    staging,
                                    &staged_files,
                                    settle_timeout,
                                );
                                // Fall through to top of loop → respawn supervisor.
                                continue;
                            },
                            Ok(recovery::RecoveryOutcome::AlreadyInSync) => {
                                log::warn!(
                                    "recovery says cache and bin already match — supervisor failure isn't a binary issue; \
                                     propagating exit"
                                );
                                let _ = std::fs::remove_file(&socket_path);
                                return ExitCode::from(code.clamp(0, 255) as u8);
                            },
                            Err(e) => {
                                log::error!(
                                    "recovery cascade FAILED: {e}; refusing to respawn with untrusted state, \
                                     propagating original exit code {code}",
                                );
                                let _ = std::fs::remove_file(&socket_path);
                                return ExitCode::from(code.clamp(0, 255) as u8);
                            },
                        }
                    } else {
                        // Recovery not configured; propagate as before.
                        let _ = std::fs::remove_file(&socket_path);
                        return ExitCode::from(code.clamp(0, 255) as u8);
                    }
                },
                None => {
                    log::warn!("supervisor terminated by signal: {s:?}");
                    let _ = std::fs::remove_file(&socket_path);
                    return ExitCode::from(1);
                },
            },
            Err(e) => {
                log::error!("wait() on supervisor failed: {e}");
                let _ = std::fs::remove_file(&socket_path);
                return ExitCode::from(127);
            },
        }
    }
}

/// After recovery::run stages files, poll the canonical-dir to confirm
/// staging_watcher has committed each rotation before respawning the
/// supervisor. Avoids the race where the new supervisor's gemini-node
/// boots, hashes a still-stale bin, and re-enters the heal flow
/// unnecessarily.
fn wait_for_staging_commit(
    canonical_dir: &Path,
    staging_dir: &Path,
    staged_files: &[String],
    timeout: Duration,
) {
    let deadline = Instant::now() + timeout;
    let poll = Duration::from_millis(100);
    loop {
        let all_done = staged_files.iter().all(|name| {
            // Staging_watcher consumes the .new file (renames it
            // away). When the staging dir no longer contains a .new
            // file for this name, the commit is done.
            let staged_path = staging_dir.join(format!("{name}.new"));
            !staged_path.exists()
        });
        if all_done {
            log::info!("recovery: staging_watcher finished committing all rotations");
            return;
        }
        if Instant::now() >= deadline {
            log::warn!(
                "recovery: staging_watcher did not commit within {}s; respawning anyway",
                timeout.as_secs(),
            );
            return;
        }
        thread::sleep(poll);
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
