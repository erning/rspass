//! Detached daemon launcher.
//!
//! Called by `agent start` and `agent add` when the socket isn't already
//! responding. Uses the current executable's path so the daemon binary is
//! always the one the user just ran — no PATH-lookup surprises.

use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use thiserror::Error;

use crate::agent::client;

#[derive(Debug, Error)]
pub enum SpawnError {
    #[error("failed to locate current executable: {0}")]
    Exe(#[source] std::io::Error),
    #[error("failed to spawn daemon: {0}")]
    Spawn(#[source] std::io::Error),
    #[error("daemon did not become ready within {0:?}")]
    Timeout(Duration),
}

const READY_TIMEOUT: Duration = Duration::from_secs(5);

/// Idempotent: if a daemon is already alive, return immediately. Otherwise
/// fork `rspass __agent-daemon` with stdin/stdout/stderr detached to
/// /dev/null, call `setsid` in the child via `pre_exec` so it survives the
/// parent terminal, and wait for the socket to start responding.
pub fn ensure_running() -> Result<(), SpawnError> {
    if client::is_agent_alive() {
        return Ok(());
    }

    let exe = std::env::current_exe().map_err(SpawnError::Exe)?;
    let mut cmd = Command::new(exe);
    cmd.arg("__agent-daemon")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: `pre_exec` closures must be async-signal-safe. `setsid` is.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd.spawn().map_err(SpawnError::Spawn)?;

    let deadline = Instant::now() + READY_TIMEOUT;
    while Instant::now() < deadline {
        if client::is_agent_alive() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(SpawnError::Timeout(READY_TIMEOUT))
}
