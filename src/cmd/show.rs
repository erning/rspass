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
    let ciphertext = fs::read(&resolved.age_file).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            RspassError::SecretNotFound(input.to_string())
        } else {
            RspassError::Io(e)
        }
    })?;
    let plaintext = decrypt::with_identities_and_prompts(config, &ciphertext)?;
    std::io::stdout().write_all(&plaintext)?;
    Ok(())
}
