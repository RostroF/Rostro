// SPDX-License-Identifier: Apache-2.0

//! `WatchdogClient` — owns a single persistent UDS connection to the
//! watchdog; serialises request/reply RPCs through a mutex.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rostro_watchdog::{Frame, FrameError, Op, SignKind, MAX_FRAME_BODY_LEN};

/// Environment variable the watchdog uses to hand the UDS path down to
/// the supervisor + node. Mirrors the constant in `rostro-watchdog`'s
/// `supervisor` module; duplicated here so client consumers don't pull
/// the supervisor module just to read an env var name.
pub const SOCKET_ENV_VAR: &str = "ROSTRO_WATCHDOG_SOCKET";

pub struct WatchdogClient {
    stream: Mutex<UnixStream>,
    socket_path: PathBuf,
}

impl core::fmt::Debug for WatchdogClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WatchdogClient")
            .field("socket_path", &self.socket_path)
            .finish_non_exhaustive()
    }
}

impl WatchdogClient {
    /// Open a connection to the watchdog at `path`.
    pub fn connect(path: impl AsRef<Path>) -> Result<Self, ClientError> {
        let path = path.as_ref();
        let stream = UnixStream::connect(path)?;
        Ok(Self { stream: Mutex::new(stream), socket_path: path.to_path_buf() })
    }

    /// Open a connection using the path in `$ROSTRO_WATCHDOG_SOCKET`. The
    /// canonical startup path for gemini-node.
    pub fn connect_from_env() -> Result<Self, ClientError> {
        let path = std::env::var_os(SOCKET_ENV_VAR).ok_or(ClientError::EnvNotSet)?;
        Self::connect(PathBuf::from(path))
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Send `Heartbeat`; return the watchdog's monotone counter after
    /// the tick.
    pub fn heartbeat(&self) -> Result<u64, ClientError> {
        let reply = self.round_trip(&Frame::new(Op::Heartbeat, &[]), Op::HeartbeatReply)?;
        if reply.len() != 8 {
            return Err(ClientError::PayloadSize { got: reply.len(), expected: 8 });
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&reply);
        Ok(u64::from_be_bytes(buf))
    }

    /// Send `GetPubkey`; return the watchdog's 32-byte Ed25519 pubkey.
    pub fn get_pubkey(&self) -> Result<[u8; 32], ClientError> {
        let reply = self.round_trip(&Frame::new(Op::GetPubkey, &[]), Op::GetPubkeyReply)?;
        if reply.len() != 32 {
            return Err(ClientError::PayloadSize { got: reply.len(), expected: 32 });
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&reply);
        Ok(buf)
    }

    /// Send `Sign(kind, payload)`; return the 64-byte Ed25519 signature.
    /// The watchdog domain-separates the signed bytes by `kind`, so a
    /// signature produced under one kind structurally cannot be replayed
    /// under another.
    pub fn sign(&self, kind: SignKind, payload: &[u8]) -> Result<[u8; 64], ClientError> {
        let mut req_payload = Vec::with_capacity(1 + payload.len());
        req_payload.push(kind as u8);
        req_payload.extend_from_slice(payload);
        let reply = self.round_trip(&Frame::new(Op::Sign, &req_payload), Op::SignReply)?;
        if reply.len() != 64 {
            return Err(ClientError::PayloadSize { got: reply.len(), expected: 64 });
        }
        let mut buf = [0u8; 64];
        buf.copy_from_slice(&reply);
        Ok(buf)
    }

    fn round_trip(&self, req: &Frame, expected: Op) -> Result<Vec<u8>, ClientError> {
        let mut stream = self.stream.lock().expect("watchdog client mutex poisoned");

        let mut req_buf = Vec::with_capacity(req.encoded_len());
        req.encode_into(&mut req_buf)?;
        stream.write_all(&req_buf)?;

        let mut len_bytes = [0u8; 4];
        stream.read_exact(&mut len_bytes)?;
        let body_len = u32::from_be_bytes(len_bytes) as usize;
        if body_len > MAX_FRAME_BODY_LEN {
            return Err(ClientError::Frame(FrameError::TooLarge(body_len)));
        }

        let mut full = Vec::with_capacity(4 + body_len);
        full.extend_from_slice(&len_bytes);
        full.resize(4 + body_len, 0);
        stream.read_exact(&mut full[4..])?;
        let (frame, _rest) = Frame::decode(&full)?;

        match frame.op {
            op if op == expected => Ok(frame.payload.to_vec()),
            Op::Error => {
                let code = frame.payload.first().copied().unwrap_or(0);
                Err(ClientError::Protocol(code))
            }
            other => Err(ClientError::UnexpectedOp { got: other, expected }),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("environment variable {SOCKET_ENV_VAR} is not set")]
    EnvNotSet,
    #[error("watchdog returned protocol error code 0x{0:02x}")]
    Protocol(u8),
    #[error("watchdog returned unexpected op {got:?}, expected {expected:?}")]
    UnexpectedOp { got: Op, expected: Op },
    #[error("frame: {0}")]
    Frame(#[from] FrameError),
    #[error("reply payload size {got}, expected {expected}")]
    PayloadSize { got: usize, expected: usize },
}

#[cfg(test)]
mod tests {
    use super::*;
    use rostro_watchdog::{HeartbeatCounter, Server, ServerConfig, WatchdogSigner};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

    fn tmp_socket() -> PathBuf {
        let n = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!(
            "rostro-wd-client-test-{}-{}.sock",
            std::process::id(),
            n
        ))
    }

    struct ServerFixture {
        path: PathBuf,
        signer: Arc<WatchdogSigner>,
        heartbeat: Arc<HeartbeatCounter>,
        _thread: thread::JoinHandle<()>,
    }

    fn start_server() -> ServerFixture {
        let path = tmp_socket();
        let signer = Arc::new(WatchdogSigner::generate());
        let heartbeat = Arc::new(HeartbeatCounter::new());
        let server = Server::bind(
            ServerConfig { socket_path: path.clone(), require_uid: None },
            signer.clone(),
            heartbeat.clone(),
        )
        .unwrap();
        let thread = thread::spawn(move || {
            let _ = server.run();
        });
        thread::sleep(Duration::from_millis(20));
        ServerFixture { path, signer, heartbeat, _thread: thread }
    }

    #[test]
    fn heartbeat_returns_incremented_counter() {
        let fix = start_server();
        let client = WatchdogClient::connect(&fix.path).unwrap();
        assert_eq!(client.heartbeat().unwrap(), 1);
        assert_eq!(client.heartbeat().unwrap(), 2);
        assert_eq!(client.heartbeat().unwrap(), 3);
        assert_eq!(fix.heartbeat.current(), 3);
    }

    #[test]
    fn get_pubkey_matches_server_signer() {
        let fix = start_server();
        let client = WatchdogClient::connect(&fix.path).unwrap();
        assert_eq!(client.get_pubkey().unwrap(), fix.signer.public_key());
    }

    #[test]
    fn sign_round_trip_matches_local_signature() {
        let fix = start_server();
        let client = WatchdogClient::connect(&fix.path).unwrap();
        let payload = b"libp2p noise prologue bytes";
        let sig = client.sign(SignKind::NoiseHandshake, payload).unwrap();
        let expected = fix.signer.sign_kind(SignKind::NoiseHandshake, payload).unwrap();
        assert_eq!(sig, expected);
    }

    #[test]
    fn sign_empty_payload_returns_protocol_error() {
        let fix = start_server();
        let client = WatchdogClient::connect(&fix.path).unwrap();
        let err = client.sign(SignKind::NoiseHandshake, &[]).unwrap_err();
        match err {
            // Server's handle_sign sees req_payload = [kind] (1 byte), splits
            // into kind=NoiseHandshake + payload=[]; signer.sign_kind rejects
            // empty payload → ErrorCode::InvalidPayload (0x02).
            ClientError::Protocol(0x02) => {}
            other => panic!("expected Protocol(0x02 InvalidPayload), got {other:?}"),
        }
    }

    #[test]
    fn connect_to_missing_path_returns_io_err() {
        let bogus = std::env::temp_dir().join("rostro-watchdog-does-not-exist-XXXXX.sock");
        let _ = std::fs::remove_file(&bogus);
        let err = WatchdogClient::connect(&bogus).unwrap_err();
        assert!(matches!(err, ClientError::Io(_)));
    }

    #[test]
    fn many_requests_through_one_connection() {
        let fix = start_server();
        let client = WatchdogClient::connect(&fix.path).unwrap();
        for i in 1..=10 {
            assert_eq!(client.heartbeat().unwrap(), i);
        }
        assert_eq!(client.get_pubkey().unwrap(), fix.signer.public_key());
        assert_eq!(fix.heartbeat.current(), 10);
    }
}
