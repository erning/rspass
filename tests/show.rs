//! End-to-end test for `rspass show` with plaintext identities.
//!
//! Uses the age crate to set up an encrypted file in a scratch vault, then
//! invokes the compiled binary and asserts round-trip correctness.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::str::FromStr;

use age::secrecy::ExposeSecret;
use tempfile::tempdir;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rspass"))
}

struct Scratch {
    _dir: tempfile::TempDir,
    xdg_config_home: PathBuf,
    config_dir: PathBuf,
    vault: PathBuf,
    identity_path: PathBuf,
}

fn setup() -> (Scratch, age::x25519::Identity) {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let xdg_config_home = root.join("config");
    let config_dir = xdg_config_home.join("rspass");
    let vault = root.join("vault");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::create_dir_all(&vault).unwrap();

    let identity = age::x25519::Identity::generate();
    let pubkey = identity.to_public();
    let identity_path = config_dir.join("id.txt");
    std::fs::write(
        &identity_path,
        format!(
            "# public key: {}\n{}\n",
            pubkey,
            identity.to_string().expose_secret()
        ),
    )
    .unwrap();

    std::fs::write(
        config_dir.join("config.yaml"),
        format!(
            "mounts:\n  \"\": {}\nidentities:\n  - {}\n",
            vault.display(),
            identity_path.display()
        ),
    )
    .unwrap();

    std::fs::write(vault.join(".age-recipients"), format!("{pubkey}\n")).unwrap();

    (
        Scratch {
            _dir: dir,
            xdg_config_home,
            config_dir,
            vault,
            identity_path,
        },
        identity,
    )
}

fn encrypt_into_vault(
    scratch: &Scratch,
    identity: &age::x25519::Identity,
    rel: &str,
    plaintext: &[u8],
) {
    let pubkey = identity.to_public();
    let r: &dyn age::Recipient = &pubkey;
    let encryptor = age::Encryptor::with_recipients(std::iter::once(r)).unwrap();
    let target = scratch.vault.join(format!("{rel}.age"));
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    let mut ct = Vec::new();
    let mut writer = encryptor.wrap_output(&mut ct).unwrap();
    writer.write_all(plaintext).unwrap();
    writer.finish().unwrap();
    std::fs::write(&target, ct).unwrap();
}

fn run_rspass(scratch: &Scratch, args: &[&str]) -> std::process::Output {
    Command::new(bin())
        .args(args)
        .env("XDG_CONFIG_HOME", &scratch.xdg_config_home)
        .env_remove("HOME") // force the binary to rely on XDG_CONFIG_HOME
        .output()
        .expect("spawn rspass")
}

#[test]
fn show_round_trips_plaintext_identity() {
    let (scratch, identity) = setup();
    let plaintext = b"hunter2\n";
    encrypt_into_vault(&scratch, &identity, "api/test", plaintext);

    let out = run_rspass(&scratch, &["show", "api/test"]);
    assert!(
        out.status.success(),
        "exit={:?}\nstdout={}\nstderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert_eq!(out.stdout, plaintext);
}

#[test]
fn show_missing_secret_exits_1() {
    let (scratch, _id) = setup();
    let out = run_rspass(&scratch, &["show", "api/missing"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("secret not found"));
}

#[test]
fn show_no_matching_identity_exits_2() {
    let (scratch, _id) = setup();
    // Encrypt to a different (throwaway) identity; the configured identity
    // won't be able to decrypt.
    let other = age::x25519::Identity::generate();
    let pubkey = other.to_public();
    let r: &dyn age::Recipient = &pubkey;
    let encryptor = age::Encryptor::with_recipients(std::iter::once(r)).unwrap();
    let mut ct = Vec::new();
    let mut writer = encryptor.wrap_output(&mut ct).unwrap();
    writer.write_all(b"unreachable\n").unwrap();
    writer.finish().unwrap();
    std::fs::write(scratch.vault.join("locked.age"), ct).unwrap();

    let out = run_rspass(&scratch, &["show", "locked"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("no matching identity"));
}

#[test]
fn show_rejects_secret_reached_through_symlink_escape() {
    let (scratch, identity) = setup();
    let outside = scratch.xdg_config_home.parent().unwrap().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    encrypt_into_vault_like(&outside, &identity, "secret", b"outside\n");
    std::os::unix::fs::symlink(&outside, scratch.vault.join("link")).unwrap();

    let out = run_rspass(&scratch, &["show", "link/secret"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("escaped store root"),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn show_skips_encrypted_ssh_identity_after_wrong_passphrase_and_uses_next_identity() {
    let (scratch, _identity) = setup();
    let ssh_key_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("ssh_ed25519_encrypted");
    let ssh_private =
        ssh_key::PrivateKey::from_openssh(std::fs::read(&ssh_key_path).unwrap()).unwrap();
    let ssh_public = ssh_private.public_key().to_openssh().unwrap();
    let unlocked = ssh_private
        .decrypt(b"testpass")
        .unwrap()
        .to_openssh(ssh_key::LineEnding::LF)
        .unwrap();
    let unlocked_path = scratch.config_dir.join("ssh_unlocked");
    std::fs::write(&unlocked_path, unlocked.as_bytes()).unwrap();

    std::fs::write(
        scratch.config_dir.join("config.yaml"),
        format!(
            "mounts:\n  \"\": {}\nidentities:\n  - {}\n  - {}\n",
            scratch.vault.display(),
            ssh_key_path.display(),
            unlocked_path.display()
        ),
    )
    .unwrap();

    let ssh_recipient = age::ssh::Recipient::from_str(&ssh_public).unwrap();
    let recipients: Vec<&dyn age::Recipient> = vec![&ssh_recipient];
    let encryptor = age::Encryptor::with_recipients(recipients.into_iter()).unwrap();
    let mut ct = Vec::new();
    let mut writer = encryptor.wrap_output(&mut ct).unwrap();
    writer.write_all(b"fallback works\n").unwrap();
    writer.finish().unwrap();
    std::fs::write(scratch.vault.join("ssh-fallback.age"), ct).unwrap();

    let mut child = Command::new(bin())
        .args(["show", "ssh-fallback"])
        .env("XDG_CONFIG_HOME", &scratch.xdg_config_home)
        .env_remove("HOME")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rspass");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"wrong-passphrase\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();

    assert!(
        out.status.success(),
        "exit={:?}\nstdout={}\nstderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert_eq!(out.stdout, b"fallback works\n");
}

fn encrypt_into_vault_like(
    dir: &std::path::Path,
    identity: &age::x25519::Identity,
    rel: &str,
    plaintext: &[u8],
) {
    let pubkey = identity.to_public();
    let r: &dyn age::Recipient = &pubkey;
    let encryptor = age::Encryptor::with_recipients(std::iter::once(r)).unwrap();
    let target = dir.join(format!("{rel}.age"));
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    let mut ct = Vec::new();
    let mut writer = encryptor.wrap_output(&mut ct).unwrap();
    writer.write_all(plaintext).unwrap();
    writer.finish().unwrap();
    std::fs::write(&target, ct).unwrap();
}

/// Silence unused-field warnings (`_dir` / `config_dir` / `identity_path`
/// keep the scratch directory alive and are accessed by tests via `scratch.*`).
#[allow(dead_code)]
fn _keep_fields(s: Scratch) {
    let _ = (s.config_dir, s.identity_path);
}
