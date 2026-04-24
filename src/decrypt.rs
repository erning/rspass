//! Shared decrypt-with-fallback used by both `show` and `edit`.
//!
//! Order of attempts (docs/DESIGN.md §§7–9):
//! 1. If the agent is reachable, send `Decrypt{ciphertext, context}` first.
//!    - `ok` → return plaintext.
//!    - `no_matching_identity` or any transport error → fall through.
//!    - Failures here **never** trigger exit 4: `show` / `edit` treat the
//!      agent as an optimization, not a requirement (docs/DESIGN.md §11).
//! 2. Local identities from `config.identities`, in order. Agent-loaded paths
//!    are skipped for prompt-bearing identities. Prompt semantics:
//!    - empty input → skip to the next identity
//!    - EOF (Ctrl+D) → `RspassError::PassphraseCancelled` → exit 3
//!    - wrong passphrase → "wrong passphrase, skipping <path>" then continue

use std::collections::HashSet;
use std::path::PathBuf;

use base64::Engine;
use zeroize::Zeroizing;

use crate::agent::client::Client;
use crate::agent::proto::Request;
use crate::config::{self, Config};
use crate::crypto::{self, CryptoError};
use crate::error::RspassError;
use crate::identity::{self, IdentityError, Kind, Loaded};
use crate::tty::{self, TtyError};

pub fn with_identities_and_prompts(
    config: &Config,
    ciphertext: &[u8],
    context: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>, RspassError> {
    // 1. Try the agent.
    if let Some(pt) = try_agent_decrypt(ciphertext, context) {
        return Ok(pt);
    }

    // 2. Collect the set of paths the agent has already loaded so we don't
    //    re-prompt for their passphrases in the local fallback.
    let agent_paths = fetch_agent_paths();

    // 3. Local fallback, preserving config order so prompt behaviour remains
    // predictable when multiple encrypted identities are configured.
    for id_ref in &config.identities {
        let path = match config::expand_path(id_ref) {
            Ok(s) => PathBuf::from(s),
            Err(e) => {
                tracing::warn!("skipping identity {id_ref:?}: path expansion failed: {e}");
                continue;
            }
        };
        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::debug!("skipping identity {id_ref:?}: {e}");
                continue;
            }
            Err(e) => return Err(RspassError::Io(e)),
        };

        match identity::classify(&data) {
            Kind::Scrypt => {
                if agent_paths.contains(&path) {
                    continue;
                }
                let label = format!("Passphrase for {}", path.display());
                let passphrase = match tty::prompt_passphrase(&label) {
                    Ok(p) => p,
                    Err(TtyError::Cancelled) => return Err(RspassError::PassphraseCancelled),
                    Err(TtyError::Io(e)) => return Err(RspassError::Io(e)),
                };
                if passphrase.is_empty() {
                    continue;
                }
                match identity::unlock_scrypt(&path, passphrase.as_str()) {
                    Ok(ids) => match crypto::decrypt(ciphertext, &ids) {
                        Ok(pt) => return Ok(pt),
                        Err(CryptoError::NoMatchingIdentity) => continue,
                        Err(e) => return Err(e.into()),
                    },
                    Err(IdentityError::WrongPassphrase(p)) => {
                        eprintln!("rspass: wrong passphrase, skipping {}", p.display());
                        continue;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            Kind::Ssh => {
                let encrypted = ssh_key::PrivateKey::from_openssh(&data)
                    .map(|k| k.is_encrypted())
                    .unwrap_or(false);
                if encrypted && agent_paths.contains(&path) {
                    continue;
                }
                let ids = match identity::load(&path) {
                    Ok(Loaded::Plaintext(ids)) => ids,
                    Ok(Loaded::Scrypt { .. }) => unreachable!("classified as SSH"),
                    Err(e) => {
                        tracing::warn!("skipping identity {id_ref:?}: {e}");
                        continue;
                    }
                };
                match crypto::decrypt(ciphertext, &ids) {
                    Ok(pt) => return Ok(pt),
                    Err(CryptoError::NoMatchingIdentity) => continue,
                    Err(e) if encrypted => {
                        eprintln!("rspass: wrong passphrase, skipping {}", path.display());
                        tracing::debug!("encrypted SSH identity failed: {e}");
                        continue;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            Kind::Native => {
                let ids = match identity::load(&path) {
                    Ok(Loaded::Plaintext(ids)) => ids,
                    Ok(Loaded::Scrypt { .. }) => unreachable!("classified as native"),
                    Err(e) => {
                        tracing::warn!("skipping identity {id_ref:?}: {e}");
                        continue;
                    }
                };
                match crypto::decrypt(ciphertext, &ids) {
                    Ok(pt) => return Ok(pt),
                    Err(CryptoError::NoMatchingIdentity) => continue,
                    Err(e) => return Err(e.into()),
                }
            }
        }
    }

    Err(RspassError::Crypto(CryptoError::NoMatchingIdentity))
}

/// Send one `decrypt` op to the agent. Returns `Some(plaintext)` on success;
/// any error — connection failure, no_matching_identity, malformed response —
/// yields `None` so the caller falls through to the local identity path.
fn try_agent_decrypt(ciphertext: &[u8], context: Option<&str>) -> Option<Zeroizing<Vec<u8>>> {
    let mut client = Client::connect_existing()?;
    let req = Request::Decrypt {
        ciphertext: base64::engine::general_purpose::STANDARD.encode(ciphertext),
        context: context.map(str::to_string),
    };
    let resp = match client.request(&req) {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!("agent decrypt rpc failed: {e}");
            return None;
        }
    };
    if !resp.ok {
        tracing::debug!(
            "agent decrypt returned error code={:?} msg={:?}",
            resp.code,
            resp.error
        );
        return None;
    }
    let b64 = resp
        .data
        .as_ref()
        .and_then(|d| d.get("plaintext"))
        .and_then(|v| v.as_str())?;
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    Some(Zeroizing::new(bytes))
}

/// Fetch the set of identity file paths currently loaded in the agent, used
/// to dedup local scrypt prompts. Returns an empty set if the agent is not
/// running or the list request fails — the caller's behaviour stays correct
/// (no dedup, just no help from the agent either).
fn fetch_agent_paths() -> HashSet<PathBuf> {
    let Some(mut client) = Client::connect_existing() else {
        return HashSet::new();
    };
    let Ok(resp) = client.request(&Request::List) else {
        return HashSet::new();
    };
    if !resp.ok {
        return HashSet::new();
    }
    let Some(entries) = resp
        .data
        .as_ref()
        .and_then(|d| d.get("identities"))
        .and_then(|v| v.as_array())
    else {
        return HashSet::new();
    };
    entries
        .iter()
        .filter_map(|e| e.get("path").and_then(|v| v.as_str()).map(PathBuf::from))
        .collect()
}
