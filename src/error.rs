use thiserror::Error;

/// Top-level error type for the rspass CLI.
///
/// Each variant maps to a DESIGN.md §11 exit code via [`RspassError::exit_code`].
/// `anyhow` is used internally for contextual wrapping but never surfaces
/// directly at the CLI boundary.
#[derive(Debug, Error)]
pub enum RspassError {
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    #[error("path expansion failed: {0}")]
    Expansion(#[from] crate::config::ExpansionError),
    #[error(transparent)]
    Path(#[from] crate::path::PathError),
    #[error(transparent)]
    Recipients(#[from] crate::recipients::RecipientError),
    #[error(transparent)]
    Identity(#[from] crate::identity::IdentityError),
    #[error(transparent)]
    Crypto(#[from] crate::crypto::CryptoError),
    #[error(transparent)]
    Tty(#[from] crate::tty::TtyError),
    #[error("secret not found: {0}")]
    SecretNotFound(String),
    #[error("passphrase entry cancelled")]
    PassphraseCancelled,
    #[error("editor exited non-zero")]
    EditorFailed,
    #[error("target path escaped store root: {0}")]
    PathEscape(std::path::PathBuf),
    #[error("agent error: {0}")]
    Agent(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl RspassError {
    /// Map the error to its DESIGN.md §11 exit code.
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Crypto(crate::crypto::CryptoError::NoMatchingIdentity) => 2,
            Self::PassphraseCancelled => 3,
            Self::Agent(_) => 4,
            _ => 1,
        }
    }
}
