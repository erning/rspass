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
use crate::identity::{self, IdentityError, Kind};
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
/// send to the daemon. For scrypt and encrypted-SSH files this prompts for a
/// passphrase with the retry/skip/cancel semantics from DESIGN.md §7; the
/// daemon only ever receives unencrypted identity material (age native,
/// unencrypted SSH PEM, or the unlocked inner of a scrypt blob).
fn build_identity_data(path: &Path) -> Result<AddOutcome, RspassError> {
    let data = std::fs::read(path).map_err(RspassError::Io)?;
    match identity::classify(&data) {
        Kind::Scrypt => prompt_and_unlock_scrypt(path),
        Kind::Ssh => build_ssh_identity_data(path, &data),
        Kind::Native => {
            let text = String::from_utf8(data).map_err(|e| {
                RspassError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
            })?;
            Ok(AddOutcome::Ready(text))
        }
    }
}

fn prompt_and_unlock_scrypt(path: &Path) -> Result<AddOutcome, RspassError> {
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

/// Handle an OpenSSH private key. Unencrypted keys pass through unchanged.
/// Encrypted keys are decrypted on the CLI side (so the daemon, which has no
/// tty, never has to prompt) and re-serialised as unencrypted OpenSSH PEM
/// via the `ssh-key` crate.
fn build_ssh_identity_data(path: &Path, data: &[u8]) -> Result<AddOutcome, RspassError> {
    let key = ssh_key::PrivateKey::from_openssh(data).map_err(|e| {
        RspassError::from(IdentityError::Parse(path.to_path_buf(), e.to_string()))
    })?;
    if !key.is_encrypted() {
        let text = String::from_utf8(data.to_vec()).map_err(|e| {
            RspassError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })?;
        return Ok(AddOutcome::Ready(text));
    }
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
        match key.decrypt(pass.as_bytes()) {
            Ok(decrypted) => {
                let pem = decrypted
                    .to_openssh(ssh_key::LineEnding::LF)
                    .map_err(|e| {
                        RspassError::from(IdentityError::Parse(
                            path.to_path_buf(),
                            format!("failed to re-encode SSH key: {e}"),
                        ))
                    })?;
                return Ok(AddOutcome::Ready((*pem).clone()));
            }
            Err(_) => {
                eprintln!("  wrong passphrase, retry (empty input to skip)");
                continue;
            }
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

#[cfg(test)]
mod tests {
    //! The prompt branch of `build_ssh_identity_data` needs a real tty, so
    //! it's covered by integration tests. These unit tests pin down the
    //! ssh-key round-trip we rely on: the encrypted fixture decrypts with
    //! the known passphrase, and the re-encoded PEM is unencrypted and
    //! parses again as an unencrypted age SSH identity.

    const SSH_PLAIN: &[u8] = include_bytes!("../../tests/fixtures/ssh_ed25519");
    const SSH_ENCRYPTED: &[u8] = include_bytes!("../../tests/fixtures/ssh_ed25519_encrypted");

    #[test]
    fn ssh_key_recognises_unencrypted_fixture() {
        let key = ssh_key::PrivateKey::from_openssh(SSH_PLAIN).unwrap();
        assert!(!key.is_encrypted());
    }

    #[test]
    fn ssh_key_round_trip_decrypts_and_reserialises() {
        let encrypted = ssh_key::PrivateKey::from_openssh(SSH_ENCRYPTED).unwrap();
        assert!(encrypted.is_encrypted());
        let decrypted = encrypted.decrypt(b"testpass").expect("decrypt");
        assert!(!decrypted.is_encrypted());
        let pem = decrypted.to_openssh(ssh_key::LineEnding::LF).unwrap();
        // Re-encoded PEM must be parseable by age's ssh path as unencrypted.
        match age::ssh::Identity::from_buffer(
            std::io::Cursor::new(pem.as_bytes()),
            Some("round-trip".into()),
        )
        .unwrap()
        {
            age::ssh::Identity::Unencrypted(_) => {}
            age::ssh::Identity::Encrypted(_) => {
                panic!("re-encoded key still reports as encrypted")
            }
            age::ssh::Identity::Unsupported(_) => panic!("age rejected re-encoded key"),
        }
    }

    #[test]
    fn ssh_key_decrypt_rejects_wrong_passphrase() {
        let encrypted = ssh_key::PrivateKey::from_openssh(SSH_ENCRYPTED).unwrap();
        assert!(encrypted.decrypt(b"not-the-right-pass").is_err());
    }
}
