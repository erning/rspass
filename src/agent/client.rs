//! Thin synchronous client for the rspass agent.
//!
//! `Client` holds one UnixStream and serializes a single round-trip per
//! `request` call. Agent socket discovery follows `socket::socket_path`.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use thiserror::Error;

use crate::agent::proto::{Request, Response};
use crate::agent::socket::{self, SocketError};

#[derive(Debug, Error)]
pub enum ClientError {
    #[error(transparent)]
    Socket(#[from] SocketError),
    #[error("agent not running at {0}")]
    NotRunning(PathBuf),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("bad response from agent: {0}")]
    BadResponse(String),
}

pub struct Client {
    stream: UnixStream,
    pub socket: PathBuf,
}

impl Client {
    /// Connect if the agent is up, returning `None` when it isn't so callers
    /// can fall through to a non-agent code path without raising an error.
    pub fn connect_existing() -> Option<Self> {
        let path = socket::socket_path().ok()?;
        if !path.exists() {
            return None;
        }
        let stream = UnixStream::connect(&path).ok()?;
        Some(Client {
            stream,
            socket: path,
        })
    }

    /// Connect with a hard requirement: error if the agent isn't running.
    pub fn connect() -> Result<Self, ClientError> {
        let path = socket::socket_path()?;
        let stream =
            UnixStream::connect(&path).map_err(|_| ClientError::NotRunning(path.clone()))?;
        Ok(Client {
            stream,
            socket: path,
        })
    }

    pub fn request(&mut self, req: &Request) -> Result<Response, ClientError> {
        let line =
            serde_json::to_string(req).map_err(|e| ClientError::BadResponse(e.to_string()))?;
        self.stream.write_all(line.as_bytes())?;
        self.stream.write_all(b"\n")?;
        self.stream.flush()?;
        let mut reader = BufReader::new(&self.stream);
        let mut resp = String::new();
        let n = reader.read_line(&mut resp)?;
        if n == 0 {
            return Err(ClientError::BadResponse("agent closed connection".into()));
        }
        serde_json::from_str(&resp).map_err(|e| ClientError::BadResponse(e.to_string()))
    }
}

/// Ping `status` to determine whether the daemon is alive and healthy.
pub fn is_agent_alive() -> bool {
    match Client::connect_existing() {
        None => false,
        Some(mut c) => c.request(&Request::Status).map(|r| r.ok).unwrap_or(false),
    }
}
