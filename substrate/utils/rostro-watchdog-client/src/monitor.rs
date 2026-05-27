// SPDX-License-Identifier: Apache-2.0

//! `HeartbeatMonitor` — background thread that drives the watchdog's
//! heartbeat probe on a fixed cadence. After `miss_budget` consecutive
//! failures, invokes the caller-supplied `on_dead` callback exactly once
//! and exits.
//!
//! Typical wiring in gemini-node: `on_dead` triggers the existing
//! graceful-shutdown path (same one Phase Z uses for active-set drop).
//! Tearing down libp2p sessions cleanly is preferred over a hard exit —
//! the supervisor sees a clean exit and doesn't attempt a Pattern A
//! restart that would only fail again (no watchdog → no libp2p
//! identity).

use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::client::WatchdogClient;

pub struct HeartbeatMonitor;

impl HeartbeatMonitor {
    /// Spawn a background thread that probes the watchdog every
    /// `interval`. After `miss_budget` consecutive failed probes,
    /// invokes `on_dead` (once) and returns. Returns the `JoinHandle`
    /// so callers can join in tests; in production the thread is
    /// expected to outlive the call site and run until `on_dead` fires.
    pub fn spawn(
        client: Arc<WatchdogClient>,
        interval: Duration,
        miss_budget: u32,
        on_dead: impl FnOnce() + Send + 'static,
    ) -> JoinHandle<()> {
        thread::spawn(move || run_loop(client, interval, miss_budget, on_dead))
    }
}

fn run_loop(
    client: Arc<WatchdogClient>,
    interval: Duration,
    miss_budget: u32,
    on_dead: impl FnOnce() + Send + 'static,
) {
    let mut misses: u32 = 0;
    let mut on_dead = Some(on_dead);
    loop {
        thread::sleep(interval);
        match client.heartbeat() {
            Ok(counter) => {
                if misses > 0 {
                    log::info!(
                        "watchdog heartbeat recovered (counter={counter}, after {misses} miss{})",
                        if misses == 1 { "" } else { "es" },
                    );
                } else {
                    log::debug!("watchdog heartbeat ok (counter={counter})");
                }
                misses = 0;
            }
            Err(e) => {
                misses = misses.saturating_add(1);
                log::warn!("watchdog heartbeat failed ({misses}/{miss_budget}): {e}");
                if misses >= miss_budget {
                    log::error!(
                        "watchdog heartbeat exceeded miss budget ({miss_budget}); invoking on_dead",
                    );
                    if let Some(cb) = on_dead.take() {
                        cb();
                    }
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rostro_watchdog::{HeartbeatCounter, Server, ServerConfig, WatchdogSigner};
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

    fn tmp_socket() -> PathBuf {
        let n = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!(
            "rostro-wd-client-monitor-{}-{}.sock",
            std::process::id(),
            n
        ))
    }

    /// Bind a raw `UnixListener` that accepts one connection, serves
    /// exactly one synthetic `HeartbeatReply`, then drops the stream so
    /// the client sees EOF on the next request. Used to drive the
    /// monitor's failure path deterministically.
    fn serve_one_heartbeat_then_disconnect(path: PathBuf) -> thread::JoinHandle<()> {
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 64];
            let _ = stream.read(&mut buf);
            // Hand-build a HeartbeatReply: body_len=10 (1 version + 1 op + 8 counter),
            // version=1, op=0x81, counter=1.
            let mut reply = Vec::with_capacity(14);
            reply.extend_from_slice(&10u32.to_be_bytes());
            reply.push(1);
            reply.push(0x81);
            reply.extend_from_slice(&1u64.to_be_bytes());
            let _ = stream.write_all(&reply);
            // Drop stream → client read returns 0 / EOF.
        })
    }

    #[test]
    fn fires_on_dead_after_server_disconnects() {
        let path = tmp_socket();
        let _server = serve_one_heartbeat_then_disconnect(path.clone());
        thread::sleep(Duration::from_millis(20));

        let client = Arc::new(WatchdogClient::connect(&path).unwrap());
        let dead = Arc::new(AtomicBool::new(false));
        let dead_for_cb = dead.clone();

        // 30ms interval, 2-miss budget → first probe succeeds (server
        // serves it), then disconnect → next 2 probes fail → on_dead.
        let _monitor = HeartbeatMonitor::spawn(
            client,
            Duration::from_millis(30),
            2,
            move || dead_for_cb.store(true, Ordering::SeqCst),
        );

        for _ in 0..60 {
            if dead.load(Ordering::SeqCst) {
                break;
            }
            thread::sleep(Duration::from_millis(30));
        }
        let _ = std::fs::remove_file(&path);
        assert!(dead.load(Ordering::SeqCst), "on_dead never fired");
    }

    #[test]
    fn does_not_fire_while_server_is_responsive() {
        let path = tmp_socket();
        let signer = Arc::new(WatchdogSigner::generate());
        let hb = Arc::new(HeartbeatCounter::new());
        let server = Server::bind(
            ServerConfig { socket_path: path.clone(), require_uid: None },
            signer,
            hb,
        )
        .unwrap();
        let _server_thread = thread::spawn(move || {
            let _ = server.run();
        });
        thread::sleep(Duration::from_millis(20));

        let client = Arc::new(WatchdogClient::connect(&path).unwrap());
        let dead = Arc::new(AtomicBool::new(false));
        let dead_for_cb = dead.clone();
        let _monitor = HeartbeatMonitor::spawn(
            client,
            Duration::from_millis(20),
            3,
            move || dead_for_cb.store(true, Ordering::SeqCst),
        );

        // Run for ~200ms. With 20ms interval that's ~10 ticks; no
        // misses expected → on_dead must not fire.
        thread::sleep(Duration::from_millis(200));
        assert!(!dead.load(Ordering::SeqCst), "on_dead fired against a live server");
    }
}
