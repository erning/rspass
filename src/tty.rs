use age::Callbacks;
use age::secrecy::SecretString;
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Error)]
pub enum TtyError {
    #[error("passphrase entry cancelled")]
    Cancelled,
    #[error("tty io: {0}")]
    Io(#[from] std::io::Error),
}

/// [`age::Callbacks`] implementation that routes `request_passphrase` through
/// [`prompt_passphrase`]. Used to wrap encrypted SSH identities so the
/// passphrase is only requested when age actually tries to unwrap a matching
/// stanza. Follows the same pattern as rage's `UiCallbacks`.
#[derive(Clone, Copy, Debug, Default)]
pub struct TtyCallbacks;

impl Callbacks for TtyCallbacks {
    fn display_message(&self, message: &str) {
        eprintln!("rspass: {message}");
    }

    fn confirm(&self, _message: &str, _yes: &str, _no: Option<&str>) -> Option<bool> {
        None
    }

    fn request_public_string(&self, _description: &str) -> Option<String> {
        None
    }

    fn request_passphrase(&self, description: &str) -> Option<SecretString> {
        match prompt_passphrase(description) {
            Ok(s) if s.is_empty() => None,
            Ok(s) => Some(SecretString::from(s.as_str().to_string())),
            Err(_) => None,
        }
    }
}

/// Read a passphrase from the controlling tty (or stdin when piped), with
/// echo disabled.
///
/// Returns `Ok(Zeroizing<String>)` for any successful read, **including empty
/// input**. The caller interprets emptiness per docs/DESIGN.md §7: "empty input =
/// skip the current identity, try the next"; rspass never forwards an empty
/// string to age as a passphrase.
///
/// EOF (Ctrl+D at the prompt) maps to `TtyError::Cancelled`, which the CLI
/// surface converts to exit code 3. Ctrl+C is handled by the kernel's default
/// SIGINT disposition and terminates the process before rspass sees it.
pub fn prompt_passphrase(label: &str) -> Result<Zeroizing<String>, TtyError> {
    match rpassword::prompt_password(format!("{label}: ")) {
        Ok(s) => Ok(Zeroizing::new(s)),
        Err(e) => {
            if matches!(
                e.kind(),
                std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::Interrupted
            ) {
                Err(TtyError::Cancelled)
            } else {
                Err(TtyError::Io(e))
            }
        }
    }
}
