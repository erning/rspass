use std::fs;
use std::io::Write;
use std::path::PathBuf;

use crate::config::{self, Config};
use crate::crypto::{self, CryptoError};
use crate::error::RspassError;
use crate::identity::{self, BoxIdentity, IdentityError, Loaded};
use crate::path::{self, Resolved};
use crate::tty::{self, TtyError};

/// `rspass show <PATH>`: resolve, decrypt, and print a secret.
///
/// Fallback chain per DESIGN.md §7:
/// 1. All plaintext identities from `config.identities`: try a decrypt first
///    (no prompt cost). age's stanza matching means unrelated identities
///    incur no real work.
/// 2. scrypt-protected identities, in `config.identities` order: prompt the
///    passphrase, unlock the identity file, then re-attempt the decrypt
///    against the accumulating identity pool.
///    - empty input  → skip this identity
///    - Ctrl+D / EOF → exit 3 via `RspassError::PassphraseCancelled`
///    - wrong pass   → log + continue to the next identity
/// 3. If every identity is exhausted, exit 2.
pub fn run(config: &Config, input: &str) -> Result<(), RspassError> {
    let resolved = path::resolve(config, input)?;
    let ciphertext = read_secret(&resolved, input)?;
    let (mut plaintext_ids, scrypt_paths) = classify_identities(config);

    if !plaintext_ids.is_empty() {
        match crypto::decrypt(&ciphertext, &plaintext_ids) {
            Ok(pt) => return emit(&pt),
            Err(CryptoError::NoMatchingIdentity) => {} // fall through
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
            // DESIGN.md §7: empty input = skip to next identity; never sent to age.
            continue;
        }
        match identity::unlock_scrypt(&path, passphrase.as_str()) {
            Ok(new_ids) => {
                plaintext_ids.extend(new_ids);
                match crypto::decrypt(&ciphertext, &plaintext_ids) {
                    Ok(pt) => return emit(&pt),
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

fn read_secret(resolved: &Resolved, input: &str) -> Result<Vec<u8>, RspassError> {
    fs::read(&resolved.age_file).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            RspassError::SecretNotFound(input.to_string())
        } else {
            RspassError::Io(e)
        }
    })
}

fn emit(plaintext: &[u8]) -> Result<(), RspassError> {
    std::io::stdout().write_all(plaintext)?;
    Ok(())
}

/// Walk `config.identities` once, classifying each entry as either a batch
/// of plaintext identities or a scrypt-protected file path. Malformed entries
/// are logged and skipped; the command continues with what it has.
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
