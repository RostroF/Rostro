// SPDX-License-Identifier: Apache-2.0

//! Spawn `rostro-supervisor` as a child of the watchdog.
//!
//! v0.1 deliberately does NOT install `PR_SET_PDEATHSIG` on the
//! supervisor. The cascade would only kill the supervisor — gemini-node
//! is the supervisor's child, and the supervisor does not currently set
//! `PR_SET_PDEATHSIG` on it. SIGKILL'ing the supervisor would leave
//! gemini-node orphaned inside its Cannae sandbox with no Pattern A
//! supervision, no exit reaping, and a leaked cgroup. A half-cascade is
//! worse than no cascade.
//!
//! On watchdog abrupt death (SIGKILL), the supervisor + gemini-node tree
//! keeps running on cached credentials. When the short-TTL attestation
//! cert machinery ships, the network organically drops the node via
//! missing renewal — the design intent in `watchdog-tpm-seal`. For
//! graceful watchdog shutdown (SIGTERM / SIGINT), `main.rs` installs a
//! signal forwarder that relays the signal to the supervisor PID.
//!
//! v0.2 will land a full cascade by adding `PR_SET_PDEATHSIG` (or
//! cgroup-atomic-kill) at every layer — that's a cross-branch effort
//! touching rostro-supervisor and rostro-node-sandbox.

use std::ffi::OsStr;
use std::io;
use std::path::Path;
use std::process::{Child, Command};

/// Environment variable the watchdog uses to hand the UDS path down to
/// the supervisor (which passes it through to gemini-node via standard
/// env inheritance).
pub const SOCKET_ENV_VAR: &str = "ROSTRO_WATCHDOG_SOCKET";

/// Environment variable carrying the path to the `rostro-watchdog-monitor`
/// sidecar binary. The supervisor reads this and, when both this var and
/// [`SOCKET_ENV_VAR`] are set, spawns the sidecar alongside gemini-node
/// so the kill-watchdog cascade works end-to-end without any GPL3 lines
/// landing in gemini-node itself.
pub const MONITOR_BINARY_ENV_VAR: &str = "ROSTRO_WATCHDOG_MONITOR_BINARY";

pub fn spawn_supervisor<I, S>(
    path: &Path,
    args: I,
    socket_path: Option<&Path>,
    monitor_binary: Option<&Path>,
) -> io::Result<Child>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut cmd = Command::new(path);
    cmd.args(args);
    if let Some(p) = socket_path {
        cmd.env(SOCKET_ENV_VAR, p);
    }
    if let Some(p) = monitor_binary {
        cmd.env(MONITOR_BINARY_ENV_VAR, p);
    }
    cmd.spawn()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn skip_if_missing(p: &Path) -> bool {
        if !p.exists() {
            eprintln!("skipping: {} not present", p.display());
            return true;
        }
        false
    }

    #[test]
    fn spawn_true_succeeds() {
        let path = PathBuf::from("/bin/true");
        if skip_if_missing(&path) {
            return;
        }
        let mut child = spawn_supervisor(&path, std::iter::empty::<&OsStr>(), None, None).unwrap();
        let status = child.wait().unwrap();
        assert!(status.success());
    }

    #[test]
    fn spawn_false_propagates_failure() {
        let path = PathBuf::from("/bin/false");
        if skip_if_missing(&path) {
            return;
        }
        let mut child = spawn_supervisor(&path, std::iter::empty::<&OsStr>(), None, None).unwrap();
        let status = child.wait().unwrap();
        assert!(!status.success());
        assert_eq!(status.code(), Some(1));
    }

    #[test]
    fn spawn_nonexistent_returns_err() {
        let path = PathBuf::from("/nonexistent/rostro-supervisor-binary-XXXXX");
        let result = spawn_supervisor(&path, std::iter::empty::<&OsStr>(), None, None);
        assert!(result.is_err());
    }

    #[test]
    fn spawn_passes_args_through() {
        let path = PathBuf::from("/bin/sh");
        if skip_if_missing(&path) {
            return;
        }
        let mut child = spawn_supervisor(&path, ["-c", "exit 42"], None, None).unwrap();
        let status = child.wait().unwrap();
        assert_eq!(status.code(), Some(42));
    }

    #[test]
    fn socket_env_var_handed_to_child() {
        let path = PathBuf::from("/bin/sh");
        if skip_if_missing(&path) {
            return;
        }
        let socket = PathBuf::from("/tmp/rostro-watchdog-supervisor-env-test.sock");
        let mut child = spawn_supervisor(
            &path,
            ["-c", &format!("test \"$ROSTRO_WATCHDOG_SOCKET\" = \"{}\"", socket.display())],
            Some(&socket),
            None,
        )
        .unwrap();
        let status = child.wait().unwrap();
        assert!(status.success(), "child saw wrong env var");
    }
}
