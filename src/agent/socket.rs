//! Socket path resolution and peer identity checks.
//!
//! Path precedence per docs/DESIGN.md §8:
//! 1. `$RSPASS_AGENT_SOCK` — explicit override.
//! 2. `$XDG_RUNTIME_DIR/rspass/agent.sock` — per-user runtime dir.
//! 3. `$TMPDIR/rspass-agent.$UID/agent.sock` — macOS default and Linux
//!    fallback for systemd-less environments.
//! 4. None of the above set → error; the caller surfaces an exit 1 with a
//!    hint to set `RSPASS_AGENT_SOCK`, `XDG_RUNTIME_DIR`, or `TMPDIR`.

use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SocketError {
    #[error("agent socket path is undefined: set RSPASS_AGENT_SOCK, XDG_RUNTIME_DIR, or TMPDIR")]
    NoPath,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub fn socket_path() -> Result<PathBuf, SocketError> {
    Ok(socket_path_with_source()?.path)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketPathSource {
    Explicit,
    RuntimeDir,
    TmpDir,
}

#[derive(Debug)]
pub struct SocketPath {
    pub path: PathBuf,
    pub source: SocketPathSource,
}

pub fn socket_path_with_source() -> Result<SocketPath, SocketError> {
    resolve(nonempty, self_uid)
}

fn resolve<F, G>(lookup: F, uid: G) -> Result<SocketPath, SocketError>
where
    F: Fn(&str) -> Option<String>,
    G: FnOnce() -> u32,
{
    if let Some(explicit) = lookup("RSPASS_AGENT_SOCK") {
        return Ok(SocketPath {
            path: PathBuf::from(explicit),
            source: SocketPathSource::Explicit,
        });
    }
    if let Some(xdg) = lookup("XDG_RUNTIME_DIR") {
        return Ok(SocketPath {
            path: PathBuf::from(xdg).join("rspass").join("agent.sock"),
            source: SocketPathSource::RuntimeDir,
        });
    }
    if let Some(tmp) = lookup("TMPDIR") {
        let uid = uid();
        return Ok(SocketPath {
            path: PathBuf::from(tmp)
                .join(format!("rspass-agent.{uid}"))
                .join("agent.sock"),
            source: SocketPathSource::TmpDir,
        });
    }
    Err(SocketError::NoPath)
}

fn nonempty(var: &str) -> Option<String> {
    match std::env::var(var) {
        Ok(s) if !s.is_empty() => Some(s),
        _ => None,
    }
}

/// Read the peer's UID on a connected unix-domain stream.
///
/// Uses `SO_PEERCRED` on Linux and `getpeereid` on macOS.
pub fn peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    use std::os::fd::AsRawFd;
    let fd = stream.as_raw_fd();

    #[cfg(target_os = "linux")]
    {
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let r = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred) as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if r != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(cred.uid)
    }

    #[cfg(target_os = "macos")]
    {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        let r = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
        if r != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(uid)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = fd;
        compile_error!("peer_uid is only implemented for Linux and macOS");
    }
}

pub fn self_uid() -> u32 {
    unsafe { libc::getuid() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Build a closure that mimics `env::var` using an in-memory map. Keeps
    /// the tests safe to run in parallel (no global env mutation).
    fn env_from(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        move |name| map.get(name).filter(|s| !s.is_empty()).cloned()
    }

    #[test]
    fn tmpdir_fallback_when_only_tmpdir_set() {
        let p = resolve(env_from(&[("TMPDIR", "/tmp-test")]), || 1234).unwrap();
        assert_eq!(
            p.path,
            PathBuf::from("/tmp-test/rspass-agent.1234/agent.sock")
        );
        assert_eq!(p.source, SocketPathSource::TmpDir);
    }

    #[test]
    fn xdg_beats_tmpdir() {
        let p = resolve(
            env_from(&[
                ("TMPDIR", "/tmp-test"),
                ("XDG_RUNTIME_DIR", "/run/user/1000"),
            ]),
            || 1234,
        )
        .unwrap();
        assert_eq!(p.path, PathBuf::from("/run/user/1000/rspass/agent.sock"));
        assert_eq!(p.source, SocketPathSource::RuntimeDir);
    }

    #[test]
    fn explicit_beats_all() {
        let p = resolve(
            env_from(&[
                ("RSPASS_AGENT_SOCK", "/tmp/custom.sock"),
                ("XDG_RUNTIME_DIR", "/run/user/1000"),
                ("TMPDIR", "/tmp-test"),
            ]),
            || 1234,
        )
        .unwrap();
        assert_eq!(p.path, PathBuf::from("/tmp/custom.sock"));
        assert_eq!(p.source, SocketPathSource::Explicit);
    }

    #[test]
    fn empty_string_is_ignored() {
        let p = resolve(
            env_from(&[
                ("RSPASS_AGENT_SOCK", ""),
                ("XDG_RUNTIME_DIR", "/run/user/1000"),
            ]),
            || 1234,
        )
        .unwrap();
        assert_eq!(p.path, PathBuf::from("/run/user/1000/rspass/agent.sock"));
        assert_eq!(p.source, SocketPathSource::RuntimeDir);
    }

    #[test]
    fn no_path_when_nothing_set() {
        let err = resolve(env_from(&[]), || 1234).unwrap_err();
        assert!(matches!(err, SocketError::NoPath));
    }
}
