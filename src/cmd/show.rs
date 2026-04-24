use std::fs;
use std::io::Write;

use crate::config::Config;
use crate::decrypt;
use crate::error::RspassError;
use crate::path;

/// `rspass show <PATH>`: resolve, decrypt, and print a secret.
///
/// Decryption goes through the shared fallback chain in
/// [`crate::decrypt::with_identities_and_prompts`] so `show` and `edit` behave
/// identically when reading existing secrets.
pub fn run(config: &Config, input: &str) -> Result<(), RspassError> {
    let resolved = path::resolve(config, input)?;
    let store_root = fs::canonicalize(&resolved.store_root).map_err(RspassError::Io)?;
    let age_file = fs::canonicalize(&resolved.age_file).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            RspassError::SecretNotFound(input.to_string())
        } else {
            RspassError::Io(e)
        }
    })?;
    if !age_file.starts_with(&store_root) {
        return Err(RspassError::PathEscape(resolved.age_file));
    }
    let ciphertext = fs::read(&age_file).map_err(RspassError::Io)?;
    let plaintext = decrypt::with_identities_and_prompts(config, &ciphertext, Some(input))?;
    std::io::stdout().write_all(&plaintext)?;
    Ok(())
}
