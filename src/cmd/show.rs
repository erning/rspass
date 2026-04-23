use std::fs;
use std::io::Write;
use std::path::PathBuf;

use crate::config::{self, Config};
use crate::crypto;
use crate::error::RspassError;
use crate::identity::{self, BoxIdentity, Loaded};
use crate::path;

/// `rspass show <PATH>`: resolve, decrypt, and print a secret.
///
/// Step 3 uses only plaintext identities from the config; scrypt-protected
/// identities are skipped with a debug log and become usable in step 4.
pub fn run(config: &Config, input: &str) -> Result<(), RspassError> {
    let resolved = path::resolve(config, input)?;
    let ciphertext = fs::read(&resolved.age_file).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            RspassError::SecretNotFound(input.to_string())
        } else {
            RspassError::Io(e)
        }
    })?;
    let identities = load_plaintext_identities(config);
    let plaintext = crypto::decrypt(&ciphertext, &identities)?;
    std::io::stdout().write_all(&plaintext)?;
    Ok(())
}

/// Walk `config.identities`, expand each path, and return the concatenation of
/// all plaintext age identities (possibly multiple per file). scrypt-protected
/// files are deferred to step 4 (logged at debug). Malformed entries are
/// logged and skipped rather than aborting the whole command.
fn load_plaintext_identities(config: &Config) -> Vec<BoxIdentity> {
    let mut out: Vec<BoxIdentity> = Vec::new();
    for id_ref in &config.identities {
        let expanded = match config::expand_path(id_ref) {
            Ok(s) => PathBuf::from(s),
            Err(e) => {
                tracing::warn!("skipping identity {id_ref:?}: path expansion failed: {e}");
                continue;
            }
        };
        match identity::load(&expanded) {
            Ok(Loaded::Plaintext(mut ids)) => out.append(&mut ids),
            Ok(Loaded::Scrypt { path }) => {
                tracing::debug!(
                    "skipping scrypt-protected identity {}: step 4 adds tty prompt support",
                    path.display()
                );
            }
            Err(e) => {
                tracing::warn!("skipping identity {id_ref:?}: {e}");
            }
        }
    }
    out
}
