use std::io::{Read, Write};

use thiserror::Error;
use zeroize::Zeroizing;

use crate::identity::BoxIdentity;
use crate::recipients::BoxRecipient;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("not a valid age encrypted file: {0}")]
    NotAge(String),
    #[error("no matching identity")]
    NoMatchingIdentity,
    #[error("crypto io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("crypto error: {0}")]
    Other(String),
}

/// Decrypt an age ciphertext using the provided identities.
///
/// age internally matches identity public keys against the file's stanzas, so
/// callers can pass more identities than will actually be used without paying
/// real decryption cost for mismatches.
///
/// The returned plaintext is wrapped in `Zeroizing` so the buffer is cleared
/// on drop.
pub fn decrypt(
    ciphertext: &[u8],
    identities: &[BoxIdentity],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let decryptor =
        age::Decryptor::new(ciphertext).map_err(|e| CryptoError::NotAge(e.to_string()))?;
    let iter = identities.iter().map(|b| b.as_ref() as &dyn age::Identity);
    let mut reader = decryptor.decrypt(iter).map_err(|e| match e {
        age::DecryptError::NoMatchingKeys => CryptoError::NoMatchingIdentity,
        other => CryptoError::Other(other.to_string()),
    })?;
    let mut plaintext = Vec::new();
    reader.read_to_end(&mut plaintext)?;
    Ok(Zeroizing::new(plaintext))
}

/// Encrypt `plaintext` for `recipients` and return the binary age ciphertext.
///
/// Binary output only — no ASCII armor (DESIGN.md §10). Callers write the
/// result to `.age` files atomically via the `edit` command's write flow.
pub fn encrypt(plaintext: &[u8], recipients: &[BoxRecipient]) -> Result<Vec<u8>, CryptoError> {
    if recipients.is_empty() {
        return Err(CryptoError::Other("no recipients".into()));
    }
    let iter = recipients.iter().map(|b| b.as_ref());
    let encryptor = age::Encryptor::with_recipients(iter)
        .map_err(|e| CryptoError::Other(e.to_string()))?;
    let mut out = Vec::new();
    let mut writer = encryptor.wrap_output(&mut out)?;
    writer.write_all(plaintext)?;
    writer.finish()?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn encrypt_to_bytes(plaintext: &[u8], recipient: age::x25519::Recipient) -> Vec<u8> {
        let r: &dyn age::Recipient = &recipient;
        let encryptor = age::Encryptor::with_recipients(std::iter::once(r)).unwrap();
        let mut out = Vec::new();
        let mut writer = encryptor.wrap_output(&mut out).unwrap();
        writer.write_all(plaintext).unwrap();
        writer.finish().unwrap();
        out
    }

    #[test]
    fn round_trip_single_identity() {
        let id = age::x25519::Identity::generate();
        let pubkey = id.to_public();
        let ct = encrypt_to_bytes(b"hello rspass", pubkey);
        let identities: Vec<BoxIdentity> = vec![Box::new(id)];
        let pt = decrypt(&ct, &identities).unwrap();
        assert_eq!(&pt[..], b"hello rspass");
    }

    #[test]
    fn no_matching_identity_errors_cleanly() {
        let encrypt_id = age::x25519::Identity::generate();
        let decrypt_id = age::x25519::Identity::generate();
        let ct = encrypt_to_bytes(b"payload", encrypt_id.to_public());
        let identities: Vec<BoxIdentity> = vec![Box::new(decrypt_id)];
        let err = decrypt(&ct, &identities).unwrap_err();
        assert!(matches!(err, CryptoError::NoMatchingIdentity));
    }

    #[test]
    fn garbage_ciphertext_errors_as_not_age() {
        let id = age::x25519::Identity::generate();
        let identities: Vec<BoxIdentity> = vec![Box::new(id)];
        let err = decrypt(b"this is not an age file\n", &identities).unwrap_err();
        assert!(matches!(err, CryptoError::NotAge(_)));
    }

    #[test]
    fn finds_right_identity_from_many() {
        let wrong1 = age::x25519::Identity::generate();
        let right = age::x25519::Identity::generate();
        let wrong2 = age::x25519::Identity::generate();
        let ct = encrypt_to_bytes(b"precise payload", right.to_public());
        let identities: Vec<BoxIdentity> =
            vec![Box::new(wrong1), Box::new(right), Box::new(wrong2)];
        let pt = decrypt(&ct, &identities).unwrap();
        assert_eq!(&pt[..], b"precise payload");
    }
}
