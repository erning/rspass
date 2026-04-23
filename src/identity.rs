use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};

use thiserror::Error;

pub type BoxIdentity = Box<dyn age::Identity>;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("failed to open identity {0}: {1}")]
    Open(PathBuf, #[source] std::io::Error),
    #[error("failed to parse identity {0}: {1}")]
    Parse(PathBuf, String),
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
}
