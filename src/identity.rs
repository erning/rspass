use std::fs::File;
use std::io::{BufReader, Read};
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
    /// A plaintext age identity file (and/or SSH private keys without a
    /// passphrase) has been parsed and is ready for immediate use.
    Plaintext(Vec<BoxIdentity>),
    /// The file is scrypt-protected and requires a passphrase to unlock.
    /// Step 4 wires this up via the tty prompt.
    Scrypt { path: PathBuf },
}

/// Read the file header and classify the identity source.
///
/// A scrypt-encrypted age file begins with the literal header line
/// `age-encryption.org/v1`; any other content is treated as a plaintext
/// age identity file (which may contain multiple `AGE-SECRET-KEY-1...`
/// lines as well as SSH private key blocks).
pub fn load(path: &Path) -> Result<Loaded, IdentityError> {
    if is_scrypt_identity(path)? {
        return Ok(Loaded::Scrypt {
            path: path.to_path_buf(),
        });
    }
    load_plaintext(path).map(Loaded::Plaintext)
}

fn is_scrypt_identity(path: &Path) -> Result<bool, IdentityError> {
    let data = std::fs::read(path).map_err(|e| IdentityError::Open(path.to_path_buf(), e))?;
    Ok(data.starts_with(b"age-encryption.org/v1"))
}

fn load_plaintext(path: &Path) -> Result<Vec<BoxIdentity>, IdentityError> {
    let file = File::open(path).map_err(|e| IdentityError::Open(path.to_path_buf(), e))?;
    let reader = BufReader::new(file);
    let id_file = age::IdentityFile::from_buffer(reader)
        .map_err(|e| IdentityError::Parse(path.to_path_buf(), e.to_string()))?;
    let ids = id_file
        .into_identities()
        .map_err(|e| IdentityError::Parse(path.to_path_buf(), format!("{e:?}")))?;
    Ok(ids)
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
    let ciphertext =
        std::fs::read(path).map_err(|e| IdentityError::Open(path.to_path_buf(), e))?;
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
        std::fs::write(&path, b"age-encryption.org/v1\n...rest of armored age blob...\n").unwrap();
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
        assert!(matches!(
            expect_err(load(&path)),
            IdentityError::Open(_, _)
        ));
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

    fn write_scrypt_wrapped_identity(
        path: &Path,
        inner: &age::x25519::Identity,
        passphrase: &str,
    ) {
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
}
