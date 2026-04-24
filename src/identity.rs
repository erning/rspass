use std::io::Read;
use std::path::{Path, PathBuf};

use thiserror::Error;

pub type BoxIdentity = Box<dyn age::Identity>;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("failed to open identity {0}: {1}")]
    Open(PathBuf, #[source] std::io::Error),
    #[error("failed to parse identity {0}: {1}")]
    Parse(PathBuf, String),
    #[error("wrong passphrase for identity {0}")]
    WrongPassphrase(PathBuf),
}

/// An identity source that has been opened and classified.
pub enum Loaded {
    /// A plaintext age identity file, or an unencrypted SSH private key, has
    /// been parsed and is ready for immediate use.
    Plaintext(Vec<BoxIdentity>),
    /// The file is scrypt-protected and requires a passphrase to unlock via
    /// the tty prompt.
    Scrypt {
        #[allow(dead_code)]
        path: PathBuf,
    },
}

/// File-level classification used by both the CLI-side `load` and the
/// daemon-side identity install path, so the two always agree on how to route
/// a given blob.
#[derive(Debug, PartialEq, Eq)]
pub enum Kind {
    /// scrypt-wrapped age identity file (needs a passphrase to unlock).
    Scrypt,
    /// OpenSSH / PEM-style private key. `age::IdentityFile` does not parse
    /// these; route them through `age::ssh::Identity::from_buffer`.
    Ssh,
    /// Plaintext age identity file (`AGE-SECRET-KEY-1…` / plugin entries).
    Native,
}

/// Classify an identity source by its leading bytes.
pub fn classify(data: &[u8]) -> Kind {
    if data.starts_with(b"age-encryption.org/v1") {
        return Kind::Scrypt;
    }
    if looks_like_ssh_private_key(data) {
        return Kind::Ssh;
    }
    Kind::Native
}

/// Check whether the first non-blank, non-comment line is a PEM-style
/// `-----BEGIN ... PRIVATE KEY-----` header (OpenSSH or legacy RSA/DSA/EC).
fn looks_like_ssh_private_key(data: &[u8]) -> bool {
    for line in data.split(|b| *b == b'\n') {
        let line = trim_ascii_ws(line);
        if line.is_empty() || line.starts_with(b"#") {
            continue;
        }
        return line.starts_with(b"-----BEGIN ") && line.ends_with(b" PRIVATE KEY-----");
    }
    false
}

fn trim_ascii_ws(mut s: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = s
        && first.is_ascii_whitespace()
    {
        s = rest;
    }
    while let [rest @ .., last] = s
        && last.is_ascii_whitespace()
    {
        s = rest;
    }
    s
}

/// Read the file, classify it, and return a `Loaded`.
pub fn load(path: &Path) -> Result<Loaded, IdentityError> {
    let data = std::fs::read(path).map_err(|e| IdentityError::Open(path.to_path_buf(), e))?;
    match classify(&data) {
        Kind::Scrypt => Ok(Loaded::Scrypt {
            path: path.to_path_buf(),
        }),
        Kind::Ssh => load_ssh(path, &data).map(|id| Loaded::Plaintext(vec![id])),
        Kind::Native => load_native(path, &data).map(Loaded::Plaintext),
    }
}

fn load_ssh(path: &Path, data: &[u8]) -> Result<BoxIdentity, IdentityError> {
    let id = age::ssh::Identity::from_buffer(
        std::io::Cursor::new(data),
        Some(path.display().to_string()),
    )
    .map_err(|e| IdentityError::Parse(path.to_path_buf(), e.to_string()))?;
    if let age::ssh::Identity::Unsupported(_) = &id {
        return Err(IdentityError::Parse(
            path.to_path_buf(),
            "unsupported SSH key type".to_string(),
        ));
    }
    // Both Unencrypted and Encrypted get wrapped: the callbacks only fire at
    // decrypt time, so unencrypted keys pay nothing for the wrapper.
    Ok(Box::new(id.with_callbacks(crate::tty::TtyCallbacks)))
}

fn load_native(path: &Path, data: &[u8]) -> Result<Vec<BoxIdentity>, IdentityError> {
    let id_file = age::IdentityFile::from_buffer(std::io::Cursor::new(data))
        .map_err(|e| IdentityError::Parse(path.to_path_buf(), e.to_string()))?;
    id_file
        .into_identities()
        .map_err(|e| IdentityError::Parse(path.to_path_buf(), format!("{e:?}")))
}

/// Decrypt an scrypt-protected identity file with the given passphrase and
/// return the plaintext body (an age identity file that may contain one or
/// more `AGE-SECRET-KEY-1...` lines).
///
/// A wrong passphrase surfaces as [`IdentityError::WrongPassphrase`] so the
/// caller can continue on to the next identity. A malformed file surfaces as
/// [`IdentityError::Parse`] and should abort.
pub fn unlock_scrypt_to_text(
    path: &Path,
    passphrase: &str,
) -> Result<zeroize::Zeroizing<String>, IdentityError> {
    let ciphertext = std::fs::read(path).map_err(|e| IdentityError::Open(path.to_path_buf(), e))?;
    let decryptor = age::Decryptor::new(&ciphertext[..])
        .map_err(|e| IdentityError::Parse(path.to_path_buf(), e.to_string()))?;
    let secret = age::secrecy::SecretString::from(passphrase.to_string());
    let scrypt_id = age::scrypt::Identity::new(secret);
    let mut reader = decryptor
        .decrypt(std::iter::once(&scrypt_id as &dyn age::Identity))
        .map_err(|e| match e {
            age::DecryptError::DecryptionFailed
            | age::DecryptError::NoMatchingKeys
            | age::DecryptError::KeyDecryptionFailed => {
                IdentityError::WrongPassphrase(path.to_path_buf())
            }
            other => IdentityError::Parse(path.to_path_buf(), other.to_string()),
        })?;
    let mut plaintext = Vec::new();
    reader
        .read_to_end(&mut plaintext)
        .map_err(|e| IdentityError::Open(path.to_path_buf(), e))?;
    let text = String::from_utf8(plaintext)
        .map_err(|e| IdentityError::Parse(path.to_path_buf(), e.to_string()))?;
    Ok(zeroize::Zeroizing::new(text))
}

/// Convenience: unlock scrypt and parse the resulting text as identities.
/// Used by local decrypt fallback.
pub fn unlock_scrypt(path: &Path, passphrase: &str) -> Result<Vec<BoxIdentity>, IdentityError> {
    let text = unlock_scrypt_to_text(path, passphrase)?;
    let id_file = age::IdentityFile::from_buffer(std::io::Cursor::new(text.as_bytes()))
        .map_err(|e| IdentityError::Parse(path.to_path_buf(), e.to_string()))?;
    let ids = id_file
        .into_identities()
        .map_err(|e| IdentityError::Parse(path.to_path_buf(), format!("{e:?}")))?;
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::ExposeSecret;
    use tempfile::tempdir;

    #[test]
    fn detects_plaintext_identity() {
        let dir = tempdir().unwrap();
        let id = age::x25519::Identity::generate();
        let path = dir.path().join("id.txt");
        std::fs::write(
            &path,
            format!(
                "# public key: {}\n{}\n",
                id.to_public(),
                id.to_string().expose_secret()
            ),
        )
        .unwrap();
        match load(&path).unwrap() {
            Loaded::Plaintext(v) => assert_eq!(v.len(), 1),
            Loaded::Scrypt { .. } => panic!("expected Plaintext, got Scrypt"),
        }
    }

    #[test]
    fn detects_multiple_keys_in_one_file() {
        let dir = tempdir().unwrap();
        let id1 = age::x25519::Identity::generate();
        let id2 = age::x25519::Identity::generate();
        let path = dir.path().join("id.txt");
        std::fs::write(
            &path,
            format!(
                "{}\n{}\n",
                id1.to_string().expose_secret(),
                id2.to_string().expose_secret()
            ),
        )
        .unwrap();
        match load(&path).unwrap() {
            Loaded::Plaintext(v) => assert_eq!(v.len(), 2),
            Loaded::Scrypt { .. } => panic!("expected Plaintext, got Scrypt"),
        }
    }

    #[test]
    fn detects_scrypt_file_by_header() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("id.txt");
        std::fs::write(
            &path,
            b"age-encryption.org/v1\n...rest of armored age blob...\n",
        )
        .unwrap();
        match load(&path).unwrap() {
            Loaded::Scrypt { path: p } => assert_eq!(p, path),
            Loaded::Plaintext(_) => panic!("expected Scrypt, got Plaintext"),
        }
    }

    fn expect_err<T>(r: Result<T, IdentityError>) -> IdentityError {
        match r {
            Ok(_) => panic!("expected error"),
            Err(e) => e,
        }
    }

    #[test]
    fn reports_open_error_for_missing_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nonexistent.txt");
        assert!(matches!(expect_err(load(&path)), IdentityError::Open(_, _)));
    }

    #[test]
    fn reports_parse_error_for_garbage() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bad.txt");
        std::fs::write(&path, b"this is not an age identity file at all\n").unwrap();
        assert!(matches!(
            expect_err(load(&path)),
            IdentityError::Parse(_, _)
        ));
    }

    fn write_scrypt_wrapped_identity(path: &Path, inner: &age::x25519::Identity, passphrase: &str) {
        use std::io::Write;
        let inner_text = format!("{}\n", inner.to_string().expose_secret());
        let secret = age::secrecy::SecretString::from(passphrase.to_string());
        let mut recipient = age::scrypt::Recipient::new(secret);
        // Keep the work factor low so tests run fast (default ~1s on
        // modern hardware). Factor 2 is plenty for correctness checks.
        recipient.set_work_factor(2);
        let r: &dyn age::Recipient = &recipient;
        let encryptor = age::Encryptor::with_recipients(std::iter::once(r)).unwrap();
        let mut ct = Vec::new();
        let mut w = encryptor.wrap_output(&mut ct).unwrap();
        w.write_all(inner_text.as_bytes()).unwrap();
        w.finish().unwrap();
        std::fs::write(path, ct).unwrap();
    }

    #[test]
    fn unlock_scrypt_round_trip() {
        let dir = tempdir().unwrap();
        let inner = age::x25519::Identity::generate();
        let path = dir.path().join("id.scrypt");
        write_scrypt_wrapped_identity(&path, &inner, "test-pass-XYZ");

        // load() must classify as Scrypt (header sniff, no passphrase needed).
        match load(&path).unwrap() {
            Loaded::Scrypt { path: p } => assert_eq!(p, path),
            Loaded::Plaintext(_) => panic!("expected Scrypt classification"),
        }

        // Right passphrase unlocks.
        let ids = unlock_scrypt(&path, "test-pass-XYZ").unwrap();
        assert_eq!(ids.len(), 1);

        // Wrong passphrase surfaces WrongPassphrase (not Parse or Open).
        assert!(matches!(
            expect_err(unlock_scrypt(&path, "not-the-right-pass")),
            IdentityError::WrongPassphrase(_)
        ));
    }

    // Test-only SSH keys (ed25519), generated via ssh-keygen. Both are safe
    // to commit: the plain one was never used for anything, and the encrypted
    // one uses the fixed passphrase "testpass" (value asserted below).
    const SSH_PLAIN: &[u8] = include_bytes!("../tests/fixtures/ssh_ed25519");
    const SSH_ENCRYPTED: &[u8] = include_bytes!("../tests/fixtures/ssh_ed25519_encrypted");

    #[test]
    fn classifier_distinguishes_three_kinds() {
        assert_eq!(classify(b"age-encryption.org/v1\nxxxx"), Kind::Scrypt);
        assert_eq!(classify(SSH_PLAIN), Kind::Ssh);
        assert_eq!(classify(SSH_ENCRYPTED), Kind::Ssh);
        assert_eq!(classify(b"# comment\nAGE-SECRET-KEY-1ABC\n"), Kind::Native);
        // Blank lines and `#` comments before the PEM header must still
        // classify as SSH.
        assert_eq!(
            classify(b"\n# some ssh key\n-----BEGIN OPENSSH PRIVATE KEY-----\n"),
            Kind::Ssh
        );
    }

    #[test]
    fn loads_unencrypted_ssh_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("id_ed25519");
        std::fs::write(&path, SSH_PLAIN).unwrap();
        match load(&path).unwrap() {
            Loaded::Plaintext(v) => assert_eq!(v.len(), 1),
            Loaded::Scrypt { .. } => panic!("expected Plaintext for SSH key"),
        }
    }

    #[test]
    fn loads_encrypted_ssh_key_via_callback_wrapper() {
        // Encrypted SSH keys now load successfully: the passphrase prompt is
        // deferred to decrypt time via the TtyCallbacks wrapper. We can only
        // confirm classification + successful wrap here; the prompt path is
        // covered by integration tests that can drive a real tty.
        let dir = tempdir().unwrap();
        let path = dir.path().join("id_ed25519");
        std::fs::write(&path, SSH_ENCRYPTED).unwrap();
        match load(&path).unwrap() {
            Loaded::Plaintext(v) => assert_eq!(v.len(), 1),
            Loaded::Scrypt { .. } => panic!("expected Plaintext for encrypted SSH"),
        }
    }

    #[test]
    fn rejects_unknown_pem_block_as_parse_error() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("weird.pem");
        // Not a recognised SSH key type — ssh::Identity::from_buffer should
        // refuse to parse it, surfacing as Parse (not EncryptedSshUnsupported).
        std::fs::write(
            &path,
            b"-----BEGIN FUNKY PRIVATE KEY-----\ngibberish\n-----END FUNKY PRIVATE KEY-----\n",
        )
        .unwrap();
        let err = expect_err(load(&path));
        assert!(matches!(err, IdentityError::Parse(_, _)), "got {err:?}");
    }
}
