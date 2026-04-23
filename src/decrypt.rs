//! Shared decrypt-with-fallback used by both `show` and `edit`.
//!
//! Order of attempts (DESIGN.md §§7–9):
//! 1. If the agent is reachable, send `Decrypt{ciphertext, context}` first.
//!    - `ok` → return plaintext.
//!    - `no_matching_identity` or any transport error → fall through.
//!    - Failures here **never** trigger exit 4: `show` / `edit` treat the
//!      agent as an optimization, not a requirement (DESIGN.md §11).
//! 2. Plaintext identities from `config.identities` (no prompt).
//! 3. scrypt / encrypted SSH identities from `config.identities`, skipping
//!    any whose file path is already loaded in the agent (dedup based on the
//!    agent's `list` snapshot). Prompt semantics:
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
use crate::identity::{self, BoxIdentity, IdentityError, Loaded};
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

    // 3. Local fallback.
    let (mut plaintext_ids, scrypt_paths) = classify_identities(config);
    let scrypt_paths: Vec<PathBuf> = scrypt_paths
        .into_iter()
        .filter(|p| !agent_paths.contains(p))
        .collect();

    if !plaintext_ids.is_empty() {
        match crypto::decrypt(ciphertext, &plaintext_ids) {
            Ok(pt) => return Ok(pt),
            Err(CryptoError::NoMatchingIdentity) => {}
            Err(e) => return Err(e.into()),
        }
    }

    for path in scrypt_paths {
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
            Ok(new_ids) => {
                plaintext_ids.extend(new_ids);
                match crypto::decrypt(ciphertext, &plaintext_ids) {
                    Ok(pt) => return Ok(pt),
                    Err(CryptoError::NoMatchingIdentity) => continue,
                    Err(e) => return Err(e.into()),
                }
            }
            Err(IdentityError::WrongPassphrase(p)) => {
                eprintln!("rspass: wrong passphrase, skipping {}", p.display());
                continue;
            }
            Err(e) => return Err(e.into()),
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
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .ok()?;
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

/// Walk `config.identities` once, splitting into a plaintext identity pool
/// and a list of scrypt-protected files whose unlocking is deferred to a
/// passphrase prompt. Malformed entries are logged at warn and skipped.
fn classify_identities(config: &Config) -> (Vec<BoxIdentity>, Vec<PathBuf>) {
    let mut plaintext: Vec<BoxIdentity> = Vec::new();
    let mut scrypt_paths: Vec<PathBuf> = Vec::new();
    for id_ref in &config.identities {
        let expanded = match config::expand_path(id_ref) {
            Ok(s) => PathBuf::from(s),
            Err(e) => {
                tracing::warn!("skipping identity {id_ref:?}: path expansion failed: {e}");
                continue;
            }
        };
        match identity::load(&expanded) {
            Ok(Loaded::Plaintext(mut ids)) => plaintext.append(&mut ids),
            Ok(Loaded::Scrypt { path }) => scrypt_paths.push(path),
            Err(e) => {
                tracing::warn!("skipping identity {id_ref:?}: {e}");
            }
        }
    }
    (plaintext, scrypt_paths)
}
