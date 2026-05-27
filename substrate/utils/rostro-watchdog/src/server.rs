// SPDX-License-Identifier: Apache-2.0

//! Unix-domain-socket server.
//!
//! Binds a UDS at the configured path, accepts one connection at a time,
//! validates the peer's UID via `SO_PEERCRED`, then serves the watchdog
//! protocol (see [`crate::proto`]) until the peer disconnects, looping
//! back to accept the next connection. v0.1 expects a single client
//! (gemini-node); sequential serving keeps the implementation
//! tokio-free.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::frame::{Frame, FrameError};
use crate::heartbeat::HeartbeatCounter;
use crate::proto;
use crate::signer::WatchdogSigner;

#[cfg(target_os = "linux")]
use std::os::unix::net::{UnixListener, UnixStream};

pub struct ServerConfig {
    /// Where to bind the socket. Caller must ensure the parent
    /// directory exists and is writable.
    pub socket_path: PathBuf,
    /// If `Some`, only accept connections from this UID; reject others
    /// with `PermissionDenied`. Set to the watchdog's own UID in
    /// production; `None` is only useful for tests.
    pub require_uid: Option<u32>,
}

#[cfg(target_os = "linux")]
pub struct Server {
    listener: UnixListener,
    socket_path: PathBuf,
    require_uid: Option<u32>,
    signer: Arc<WatchdogSigner>,
    heartbeat: Arc<HeartbeatCounter>,
}

#[cfg(target_os = "linux")]
impl Server {
    pub fn bind(
        config: ServerConfig,
        signer: Arc<WatchdogSigner>,
        heartbeat: Arc<HeartbeatCounter>,
    ) -> io::Result<Self> {
        // Best-effort unlink of any stale socket at this path. If a
        // *live* server is bound here, the subsequent `bind` will fail
        // with EADDRINUSE — the right outcome, since we shouldn't run
        // two watchdogs on the same path.
        let _ = std::fs::remove_file(&config.socket_path);
        let listener = UnixListener::bind(&config.socket_path)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&config.socket_path, std::fs::Permissions::from_mode(0o600))?;
        Ok(Self {
            listener,
            socket_path: config.socket_path,
            require_uid: config.require_uid,
            signer,
            heartbeat,
        })
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Block-accept-and-serve in a loop. Returns only on fatal accept
    /// errors; per-connection errors are logged and the loop continues.
    pub fn run(&self) -> io::Result<()> {
        loop {
            let (stream, _addr) = match self.listener.accept() {
                Ok(p) => p,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            if let Err(e) = self.handle_connection(stream) {
                log::warn!("watchdog: client error: {e}");
            }
        }
    }

    /// Serve exactly one connection then return. Useful for tests.
    pub fn accept_one(&self) -> io::Result<()> {
        let (stream, _addr) = self.listener.accept()?;
        self.handle_connection(stream)
    }

    fn handle_connection(&self, mut stream: UnixStream) -> io::Result<()> {
        if let Some(required) = self.require_uid {
            check_peer_uid(&stream, required)?;
        }
        log::info!("watchdog: client connected");

        let mut buf: Vec<u8> = Vec::with_capacity(4096);
        let mut tmp = vec![0u8; 4096];
        loop {
            let n = stream.read(&mut tmp)?;
            if n == 0 {
                log::info!("watchdog: client disconnected");
                return Ok(());
            }
            buf.extend_from_slice(&tmp[..n]);

            loop {
                let consumed = match Frame::decode(&buf) {
                    Ok((frame, rest)) => {
                        let c = buf.len() - rest.len();
                        let mut reply = Vec::with_capacity(128);
                        proto::dispatch(&frame, &self.signer, &self.heartbeat, &mut reply);
                        stream.write_all(&reply)?;
                        c
                    }
                    Err(FrameError::Incomplete) => break,
                    Err(e) => {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string()));
                    }
                };
                buf.drain(..consumed);
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for Server {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

#[cfg(target_os = "linux")]
fn check_peer_uid(stream: &UnixStream, required: u32) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `getsockopt` writes at most `len` bytes into `cred`;
    // `cred` is a fully-initialized `libc::ucred` so any partial write
    // is benign.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if cred.uid != required {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("peer uid {} != required {}", cred.uid, required),
        ));
    }
    Ok(())
}

/// `$XDG_RUNTIME_DIR/rostro-watchdog-<pid>.sock`, falling back to
/// `/tmp/rostro-watchdog-<pid>.sock` when XDG is unset.
pub fn default_socket_path() -> PathBuf {
    let pid = std::process::id();
    let dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    dir.join(format!("rostro-watchdog-{pid}.sock"))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::frame::Op;
    use crate::sign_kind::SignKind;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::thread;
    use std::time::Duration;

    static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

    fn tmp_socket() -> PathBuf {
        let n = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!(
            "rostro-watchdog-test-{}-{}.sock",
            std::process::id(),
            n
        ))
    }

    fn start_server(
        signer: Arc<WatchdogSigner>,
        hb: Arc<HeartbeatCounter>,
    ) -> (PathBuf, thread::JoinHandle<()>) {
        let path = tmp_socket();
        let server = Server::bind(
            ServerConfig { socket_path: path.clone(), require_uid: None },
            signer,
            hb,
        )
        .unwrap();
        let handle = thread::spawn(move || {
            let _ = server.accept_one();
        });
        // Give the server a beat to enter accept().
        thread::sleep(Duration::from_millis(20));
        (path, handle)
    }

    fn read_one_frame(stream: &mut UnixStream) -> Vec<u8> {
        let mut len_bytes = [0u8; 4];
        stream.read_exact(&mut len_bytes).unwrap();
        let body_len = u32::from_be_bytes(len_bytes) as usize;
        let mut full = Vec::with_capacity(4 + body_len);
        full.extend_from_slice(&len_bytes);
        full.resize(4 + body_len, 0);
        stream.read_exact(&mut full[4..]).unwrap();
        full
    }

    #[test]
    fn heartbeat_round_trip_over_uds() {
        let signer = Arc::new(WatchdogSigner::generate());
        let hb = Arc::new(HeartbeatCounter::new());
        let (path, handle) = start_server(signer.clone(), hb.clone());

        let mut client = UnixStream::connect(&path).unwrap();
        let mut req = Vec::new();
        Frame::new(Op::Heartbeat, &[]).encode_into(&mut req).unwrap();
        client.write_all(&req).unwrap();

        let resp = read_one_frame(&mut client);
        let (frame, _) = Frame::decode(&resp).unwrap();
        assert_eq!(frame.op, Op::HeartbeatReply);
        assert_eq!(frame.payload, &1u64.to_be_bytes());
        assert_eq!(hb.current(), 1);

        drop(client);
        handle.join().unwrap();
    }

    #[test]
    fn get_pubkey_round_trip_over_uds() {
        let signer = Arc::new(WatchdogSigner::generate());
        let expected_pk = signer.public_key();
        let hb = Arc::new(HeartbeatCounter::new());
        let (path, handle) = start_server(signer, hb);

        let mut client = UnixStream::connect(&path).unwrap();
        let mut req = Vec::new();
        Frame::new(Op::GetPubkey, &[]).encode_into(&mut req).unwrap();
        client.write_all(&req).unwrap();

        let resp = read_one_frame(&mut client);
        let (frame, _) = Frame::decode(&resp).unwrap();
        assert_eq!(frame.op, Op::GetPubkeyReply);
        assert_eq!(frame.payload, &expected_pk[..]);

        drop(client);
        handle.join().unwrap();
    }

    #[test]
    fn sign_round_trip_over_uds() {
        let signer = Arc::new(WatchdogSigner::generate());
        let payload_bytes = b"noise prologue";
        let expected_sig = signer
            .sign_kind(SignKind::NoiseHandshake, payload_bytes)
            .unwrap();
        let hb = Arc::new(HeartbeatCounter::new());
        let (path, handle) = start_server(signer, hb);

        let mut client = UnixStream::connect(&path).unwrap();
        let mut sign_payload = vec![SignKind::NoiseHandshake as u8];
        sign_payload.extend_from_slice(payload_bytes);
        let mut req = Vec::new();
        Frame::new(Op::Sign, &sign_payload).encode_into(&mut req).unwrap();
        client.write_all(&req).unwrap();

        let resp = read_one_frame(&mut client);
        let (frame, _) = Frame::decode(&resp).unwrap();
        assert_eq!(frame.op, Op::SignReply);
        assert_eq!(frame.payload, &expected_sig[..]);

        drop(client);
        handle.join().unwrap();
    }

    #[test]
    fn unlinks_socket_on_drop() {
        let path = tmp_socket();
        {
            let server = Server::bind(
                ServerConfig { socket_path: path.clone(), require_uid: None },
                Arc::new(WatchdogSigner::generate()),
                Arc::new(HeartbeatCounter::new()),
            )
            .unwrap();
            assert!(server.socket_path().exists());
        }
        assert!(!path.exists());
    }

    #[test]
    fn default_socket_path_uses_xdg_when_set() {
        // The actual path depends on XDG_RUNTIME_DIR at runtime; just
        // confirm the function produces a path with the right shape and
        // doesn't panic.
        let p = default_socket_path();
        let s = p.to_string_lossy();
        assert!(s.contains("rostro-watchdog-"));
        assert!(s.ends_with(".sock"));
    }
}
