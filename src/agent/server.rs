//! Agent daemon main loop. Listens on a unix-domain socket, handles JSON-line
//! requests, holds unlocked identities in memory until `Stop` or `Remove`.
//!
//! Identity storage (in-memory only, never persisted):
//! - keyed by the absolute path the identity was added from
//! - value is a list of `BoxIdentity` (one file can legitimately contain
//!   multiple age secret keys) plus the derived x25519 public keys for the
//!   `list` response

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use base64::Engine;
use zeroize::Zeroizing;

use crate::agent::proto::{
    MAX_CIPHERTEXT_BYTES, Request, Response, read_request, write_response,
};
use crate::agent::socket::{self, SocketError, peer_uid, self_uid};
use crate::identity::BoxIdentity;

struct IdentityEntry {
    identities: Vec<BoxIdentity>,
    pubkeys: Vec<String>,
}

pub struct Agent {
    identities: HashMap<PathBuf, IdentityEntry>,
}

impl Agent {
    fn new() -> Self {
        Self {
            identities: HashMap::new(),
        }
    }
}

/// Entry point invoked by the hidden `__agent-daemon` subcommand.
///
/// Step 6 runs in the foreground; step 7's spawn helper will detach (fork,
/// setsid, close stdio) before calling into this function.
pub fn run() -> Result<(), RunError> {
    let socket_path = socket::socket_path()?;
    ensure_parent_dir(&socket_path)?;

    // Idempotent start: if a live daemon is already listening, exit 0.
    if is_alive(&socket_path) {
        tracing::info!("agent already running at {}", socket_path.display());
        return Ok(());
    }

    // Remove any stale socket file left by a previous unclean shutdown. This
    // is safe only after `is_alive` has confirmed nothing is listening.
    let _ = std::fs::remove_file(&socket_path);

    let listener = UnixListener::bind(&socket_path).map_err(RunError::Bind)?;
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
        .map_err(RunError::Bind)?;
    tracing::info!("agent listening at {}", socket_path.display());

    let mut agent = Agent::new();
    let expected_uid = self_uid();

    for incoming in listener.incoming() {
        let stream = match incoming {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("accept failed: {e}");
                continue;
            }
        };
        if let Err(e) = verify_peer(&stream, expected_uid) {
            tracing::warn!("rejecting connection: {e}");
            continue;
        }
        match handle_connection(&mut agent, stream) {
            Ok(ShouldStop::No) => {}
            Ok(ShouldStop::Yes) => {
                tracing::info!("stop requested; shutting down");
                break;
            }
            Err(e) => tracing::warn!("connection error: {e}"),
        }
    }

    let _ = std::fs::remove_file(&socket_path);
    Ok(())
}

fn verify_peer(stream: &UnixStream, expected_uid: u32) -> Result<(), String> {
    let got = peer_uid(stream).map_err(|e| format!("peer_uid: {e}"))?;
    if got != expected_uid {
        return Err(format!("uid mismatch (expected {expected_uid}, got {got})"));
    }
    Ok(())
}

fn ensure_parent_dir(socket_path: &Path) -> Result<(), RunError> {
    let parent = socket_path
        .parent()
        .ok_or(RunError::NoParentDir)?;
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder.create(parent).map_err(RunError::CreateDir)?;
    // Re-apply 0700 in case the dir pre-existed with looser permissions.
    let perm = std::fs::Permissions::from_mode(0o700);
    std::fs::set_permissions(parent, perm).map_err(RunError::CreateDir)?;
    Ok(())
}

fn is_alive(socket_path: &Path) -> bool {
    if !socket_path.exists() {
        return false;
    }
    let Ok(mut stream) = UnixStream::connect(socket_path) else {
        return false;
    };
    // Send a status request and expect a valid JSON reply.
    if serde_json::to_writer(&mut stream, &serde_json::json!({"op": "status"})).is_err() {
        return false;
    }
    if stream.write_all(b"\n").is_err() {
        return false;
    }
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).is_ok() && line.contains("\"ok\"")
}

enum ShouldStop {
    Yes,
    No,
}

fn handle_connection(
    agent: &mut Agent,
    stream: UnixStream,
) -> std::io::Result<ShouldStop> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    let req = match read_request(&mut reader)? {
        Some(r) => r,
        None => return Ok(ShouldStop::No),
    };
    let (resp, stop) = dispatch(agent, req);
    write_response(&mut writer, &resp)?;
    Ok(if stop { ShouldStop::Yes } else { ShouldStop::No })
}

fn dispatch(agent: &mut Agent, req: Request) -> (Response, bool) {
    match req {
        Request::Add {
            path,
            identity_data,
        } => (handle_add(agent, path, identity_data), false),
        Request::Remove { path } => (handle_remove(agent, path), false),
        Request::List => (handle_list(agent), false),
        Request::Decrypt {
            ciphertext,
            context,
        } => (handle_decrypt(agent, ciphertext, context), false),
        Request::Status => (handle_status(agent), false),
        Request::Stop => (Response::ok(), true),
    }
}

fn handle_add(agent: &mut Agent, path: String, identity_data: String) -> Response {
    let path = PathBuf::from(path);
    let identities = match age::IdentityFile::from_buffer(std::io::Cursor::new(
        identity_data.as_bytes(),
    )) {
        Ok(f) => match f.into_identities() {
            Ok(v) => v,
            Err(e) => return Response::err("parse_failed", format!("{e:?}")),
        },
        Err(e) => return Response::err("parse_failed", format!("{e}")),
    };
    if identities.is_empty() {
        return Response::err("empty_identity", "no identities parsed from data");
    }
    let pubkeys = derive_x25519_pubkeys(&identity_data);
    if agent.identities.contains_key(&path) {
        tracing::warn!("overwriting existing entry at {}", path.display());
    }
    agent.identities.insert(
        path,
        IdentityEntry {
            identities,
            pubkeys,
        },
    );
    Response::ok()
}

fn derive_x25519_pubkeys(identity_data: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in identity_data.lines() {
        let line = line.trim();
        if let Some(stripped) = line.strip_prefix("AGE-SECRET-KEY-1") {
            let full = format!("AGE-SECRET-KEY-1{stripped}");
            if let Ok(id) = full.parse::<age::x25519::Identity>() {
                out.push(id.to_public().to_string());
            }
        }
    }
    out
}

fn handle_remove(agent: &mut Agent, path: String) -> Response {
    let path = PathBuf::from(path);
    if agent.identities.remove(&path).is_some() {
        Response::ok()
    } else {
        Response::err("not_found", format!("no identity at {}", path.display()))
    }
}

fn handle_list(agent: &Agent) -> Response {
    let mut entries: Vec<_> = agent
        .identities
        .iter()
        .map(|(path, entry)| {
            serde_json::json!({
                "path": path.display().to_string(),
                "pubkeys": entry.pubkeys,
            })
        })
        .collect();
    entries.sort_by(|a, b| {
        a["path"]
            .as_str()
            .cmp(&b["path"].as_str())
    });
    Response::ok_with(serde_json::json!({ "identities": entries }))
}

fn handle_decrypt(
    agent: &Agent,
    ciphertext_b64: String,
    context: Option<String>,
) -> Response {
    let ciphertext =
        match base64::engine::general_purpose::STANDARD.decode(ciphertext_b64.as_bytes()) {
            Ok(b) => b,
            Err(e) => return Response::err("bad_base64", format!("{e}")),
        };
    if ciphertext.len() > MAX_CIPHERTEXT_BYTES {
        return Response::err(
            "too_large",
            format!(
                "ciphertext is {} bytes, limit is {MAX_CIPHERTEXT_BYTES}",
                ciphertext.len()
            ),
        );
    }
    if let Some(c) = &context {
        tracing::info!("decrypt request for context={:?}", c);
    }

    if agent.identities.is_empty() {
        return Response::err("no_matching_identity", "no identities loaded");
    }

    // Flatten all loaded identities into &dyn Identity for age::Decryptor.
    let mut all: Vec<&dyn age::Identity> = Vec::new();
    for entry in agent.identities.values() {
        for id in &entry.identities {
            all.push(id.as_ref());
        }
    }

    let decryptor = match age::Decryptor::new(&ciphertext[..]) {
        Ok(d) => d,
        Err(e) => return Response::err("not_age", format!("{e}")),
    };
    let mut reader = match decryptor.decrypt(all.into_iter()) {
        Ok(r) => r,
        Err(age::DecryptError::NoMatchingKeys) => {
            return Response::err("no_matching_identity", "no matching identity");
        }
        Err(e) => return Response::err("decrypt_failed", format!("{e}")),
    };
    let mut plaintext = Zeroizing::new(Vec::new());
    if let Err(e) = reader.read_to_end(&mut plaintext) {
        return Response::err("decrypt_failed", format!("{e}"));
    }
    let encoded = base64::engine::general_purpose::STANDARD.encode(&plaintext[..]);
    Response::ok_with(serde_json::json!({ "plaintext": encoded }))
}

fn handle_status(agent: &Agent) -> Response {
    Response::ok_with(serde_json::json!({
        "pid": std::process::id(),
        "identity_count": agent.identities.len(),
        "key_count": agent.identities.values().map(|e| e.pubkeys.len()).sum::<usize>(),
    }))
}

#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error(transparent)]
    Socket(#[from] SocketError),
    #[error("socket has no parent dir")]
    NoParentDir,
    #[error("failed to create socket parent dir: {0}")]
    CreateDir(#[source] std::io::Error),
    #[error("failed to bind socket: {0}")]
    Bind(#[source] std::io::Error),
}

