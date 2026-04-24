//! End-to-end test for `rspass show` with plaintext identities.
//!
//! Uses the age crate to set up an encrypted file in a scratch vault, then
//! invokes the compiled binary and asserts round-trip correctness.

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

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

/// Silence unused-field warnings (`_dir` / `config_dir` / `identity_path`
/// keep the scratch directory alive and are accessed by tests via `scratch.*`).
#[allow(dead_code)]
fn _keep_fields(s: Scratch) {
    let _ = (s.config_dir, s.identity_path);
}
