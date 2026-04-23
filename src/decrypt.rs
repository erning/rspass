//! Shared decrypt-with-fallback used by both `show` and `edit`.
//!
//! Implements the fallback chain from DESIGN.md §7:
//! 1. Try plaintext identities (no prompt).
//! 2. For each scrypt identity in config order, prompt passphrase and retry
//!    decryption against the accumulating identity pool.
//!
//! Prompt semantics:
//! - empty input → skip to the next identity
//! - EOF (Ctrl+D) → `RspassError::PassphraseCancelled` → exit 3
//! - wrong passphrase → "wrong passphrase, skipping <path>" then continue
//!
//! The returned plaintext is in a `Zeroizing` wrapper that clears on drop.

use std::path::PathBuf;

use zeroize::Zeroizing;

use crate::config::{self, Config};
use crate::crypto::{self, CryptoError};
use crate::error::RspassError;
use crate::identity::{self, BoxIdentity, IdentityError, Loaded};
use crate::tty::{self, TtyError};

pub fn with_identities_and_prompts(
    config: &Config,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, RspassError> {
    let (mut plaintext_ids, scrypt_paths) = classify_identities(config);

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
