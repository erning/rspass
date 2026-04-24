//! `rspass agent {start,stop,status,ls,add,rm}`.
//!
//! Each subcommand is a thin wrapper over the `agent::client` + `agent::spawn`
//! modules plus one helper for bundling identity data to send over the
//! protocol. The no-arg `add` case implements DESIGN.md §8 "agent add (无参)
//! 流程" with per-identity summaries and graceful skip/cancel semantics.

use std::path::{Path, PathBuf};

use clap::Subcommand;

use crate::agent::client::{Client, ClientError};
use crate::agent::proto::{Request, Response};
use crate::agent::spawn;
use crate::config::{self, Config};
use crate::error::RspassError;
use crate::identity::{self, IdentityError, Loaded};
use crate::tty::{self, TtyError};

#[derive(Subcommand, Debug)]
pub enum Op {
    /// Start the agent daemon. Idempotent.
    Start,
    /// Ask the running agent to exit. No-op when not running.
    Stop,
    /// Report whether the agent is running and how many identities it holds.
    Status,
    /// List loaded identity files and their public keys.
    Ls,
    /// Add an identity. `PATH` may be omitted to load all configured
    /// identities in sequence.
    Add { path: Option<String> },
    /// Remove an identity by file path.
    Rm { path: String },
}

pub fn run(config: &Config, op: Op) -> Result<(), RspassError> {
    match op {
        Op::Start => start(),
        Op::Stop => stop(),
        Op::Status => status(),
        Op::Ls => ls(),
        Op::Add { path: Some(p) } => add_one(&p),
        Op::Add { path: None } => add_all(config),
        Op::Rm { path } => rm(&path),
    }
}

fn start() -> Result<(), RspassError> {
    spawn::ensure_running().map_err(|e| RspassError::Agent(e.to_string()))
}

fn stop() -> Result<(), RspassError> {
    match Client::connect_existing() {
        None => {
            eprintln!("rspass: agent not running");
            Ok(())
        }
        Some(mut c) => {
            let resp = c.request(&Request::Stop).map_err(agent_err)?;
            check_ok(resp)
        }
    }
}

fn status() -> Result<(), RspassError> {
    match Client::connect_existing() {
        None => {
            println!("not running");
            Ok(())
        }
        Some(mut c) => {
            let socket = c.socket.clone();
            let resp = c.request(&Request::Status).map_err(agent_err)?;
            if !resp.ok {
                return Err(RspassError::Agent(
                    resp.error.unwrap_or_else(|| "status failed".into()),
                ));
            }
            println!("running");
            println!("  socket: {}", socket.display());
            if let Some(d) = resp.data {
                if let Some(pid) = d.get("pid").and_then(|v| v.as_u64()) {
                    println!("  pid: {pid}");
                }
                if let Some(n) = d.get("identity_count").and_then(|v| v.as_u64()) {
                    println!("  identities: {n}");
                }
                if let Some(k) = d.get("key_count").and_then(|v| v.as_u64()) {
                    println!("  keys: {k}");
                }
            }
            Ok(())
        }
    }
}

fn ls() -> Result<(), RspassError> {
    match Client::connect_existing() {
        None => {
            eprintln!("rspass: agent not running");
            Ok(())
        }
        Some(mut c) => {
            let resp = c.request(&Request::List).map_err(agent_err)?;
            if !resp.ok {
                return Err(RspassError::Agent(
                    resp.error.unwrap_or_else(|| "list failed".into()),
                ));
            }
            let entries = resp
                .data
                .as_ref()
                .and_then(|d| d.get("identities"))
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if entries.is_empty() {
                println!("(no identities loaded)");
                return Ok(());
            }
            for entry in entries {
                let path = entry
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                println!("{path}");
                if let Some(pks) = entry.get("pubkeys").and_then(|v| v.as_array()) {
                    for pk in pks {
                        if let Some(s) = pk.as_str() {
                            println!("  {s}");
                        }
                    }
                }
            }
            Ok(())
        }
    }
}

fn add_one(path: &str) -> Result<(), RspassError> {
    spawn::ensure_running().map_err(|e| RspassError::Agent(e.to_string()))?;
    let abs = absolute_path(path)?;
    let identity_data = match build_identity_data(&abs)? {
        AddOutcome::Ready(data) => data,
        AddOutcome::Skipped => {
            eprintln!("rspass: skipped {}", abs.display());
            return Ok(());
        }
    };
    send_add(&abs, &identity_data)?;
    Ok(())
}

fn add_all(config: &Config) -> Result<(), RspassError> {
    spawn::ensure_running().map_err(|e| RspassError::Agent(e.to_string()))?;
    let total = config.identities.len();
    if total == 0 {
        eprintln!("rspass: no identities configured");
        return Ok(());
    }
    println!("Loading {total} identities from config...");
    let mut loaded = 0;
    let mut skipped = 0;
    let mut failed = 0;
    for (i, id_ref) in config.identities.iter().enumerate() {
        let idx = i + 1;
        let abs = match config::expand_path(id_ref)
            .map_err(RspassError::from)
            .and_then(|s| absolute_path(&s))
        {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[{idx}/{total}] skipping {id_ref}: {e}");
                skipped += 1;
                continue;
            }
        };
        println!("[{idx}/{total}] {}", abs.display());
        match build_identity_data(&abs) {
            Ok(AddOutcome::Ready(data)) => match send_add(&abs, &data) {
                Ok(()) => loaded += 1,
                Err(e) => {
                    eprintln!("  {e}");
                    failed += 1;
                }
            },
            Ok(AddOutcome::Skipped) => skipped += 1,
            Err(RspassError::PassphraseCancelled) => {
                eprintln!("  cancelled, aborting remaining identities");
                return Err(RspassError::PassphraseCancelled);
            }
            Err(e) => {
                eprintln!("  {e}");
                failed += 1;
            }
        }
    }
    println!("loaded {loaded}/{total} (skipped {skipped}, failed {failed})");
    if loaded == 0 {
        return Err(RspassError::Agent(
            "no identities loaded".into(),
        ));
    }
    Ok(())
}

fn rm(path: &str) -> Result<(), RspassError> {
    let abs = absolute_path(path)?;
    match Client::connect_existing() {
        None => {
            eprintln!("rspass: agent not running");
            Err(RspassError::Agent("agent not running".into()))
        }
        Some(mut c) => {
            let resp = c
                .request(&Request::Remove {
                    path: abs.display().to_string(),
                })
                .map_err(agent_err)?;
            if !resp.ok {
                return Err(RspassError::Agent(
                    resp.error.unwrap_or_else(|| "remove failed".into()),
                ));
            }
            Ok(())
        }
    }
}

enum AddOutcome {
    Ready(String),
    Skipped,
}

/// Classify the identity file at `path` and produce the identity text to
/// send to the daemon. For scrypt files this involves a passphrase prompt
/// with the retry/skip/cancel semantics from DESIGN.md §7.
fn build_identity_data(path: &Path) -> Result<AddOutcome, RspassError> {
    match identity::load(path)? {
        Loaded::Plaintext(_) => {
            let data = std::fs::read_to_string(path).map_err(RspassError::Io)?;
            Ok(AddOutcome::Ready(data))
        }
        Loaded::Scrypt { path: p } => prompt_and_unlock(&p),
    }
}

fn prompt_and_unlock(path: &Path) -> Result<AddOutcome, RspassError> {
    loop {
        let label = format!("Passphrase for {}", path.display());
        let pass = match tty::prompt_passphrase(&label) {
            Ok(p) => p,
            Err(TtyError::Cancelled) => return Err(RspassError::PassphraseCancelled),
            Err(TtyError::Io(e)) => return Err(RspassError::Io(e)),
        };
        if pass.is_empty() {
            return Ok(AddOutcome::Skipped);
        }
        match identity::unlock_scrypt_to_text(path, pass.as_str()) {
            Ok(text) => return Ok(AddOutcome::Ready((*text).clone())),
            Err(IdentityError::WrongPassphrase(_)) => {
                eprintln!("  wrong passphrase, retry (empty input to skip)");
                continue;
            }
            Err(e) => return Err(e.into()),
        }
    }
}

fn send_add(path: &Path, identity_data: &str) -> Result<(), RspassError> {
    let mut c = Client::connect().map_err(agent_err)?;
    let resp = c
        .request(&Request::Add {
            path: path.display().to_string(),
            identity_data: identity_data.to_string(),
        })
        .map_err(agent_err)?;
    check_ok(resp)
}

fn check_ok(resp: Response) -> Result<(), RspassError> {
    if resp.ok {
        Ok(())
    } else {
        Err(RspassError::Agent(
            resp.error.unwrap_or_else(|| "agent error".into()),
        ))
    }
}

fn absolute_path(s: &str) -> Result<PathBuf, RspassError> {
    let p = PathBuf::from(s);
    std::path::absolute(&p).map_err(RspassError::Io)
}

fn agent_err(e: ClientError) -> RspassError {
    RspassError::Agent(e.to_string())
}
