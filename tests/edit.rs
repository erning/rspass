//! End-to-end tests for `rspass edit` covering both new-file creation and
//! modification of an existing secret.
//!
//! The editor is mocked via a small shell script that either writes known
//! bytes to `$1` (simulating "user typed and saved") or exits non-zero.

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
    vault: PathBuf,
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
            vault,
        },
        identity,
    )
}

/// Build a shell script that, when run as `$EDITOR <tempfile>`, writes
/// `payload` to the tempfile. Caller passes the scratch dir so the script
/// survives only as long as the test.
fn mock_editor_that_writes(dir: &std::path::Path, payload: &str) -> PathBuf {
    let script = dir.join("mock-editor.sh");
    std::fs::write(
        &script,
        format!("#!/bin/sh\nprintf %s {} > \"$1\"\n", shell_escape(payload)),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    script
}

fn shell_escape(s: &str) -> String {
    // Single-quote, doubling any internal single quotes the posix way.
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn run_rspass(scratch: &Scratch, editor: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(bin())
        .args(args)
        .env("XDG_CONFIG_HOME", &scratch.xdg_config_home)
        .env_remove("HOME")
        .env("EDITOR", editor)
        .env_remove("VISUAL")
        .output()
        .expect("spawn rspass")
}

#[test]
fn edit_creates_new_secret() {
    let (scratch, _id) = setup();
    let scratch_dir = scratch.xdg_config_home.parent().unwrap().to_path_buf();
    let editor = mock_editor_that_writes(&scratch_dir, "s3cret-value\n");

    let out = run_rspass(&scratch, &editor, &["edit", "api/new"]);
    assert!(
        out.status.success(),
        "exit={:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );

    // The encrypted file should exist and show should round-trip it.
    let age_file = scratch.vault.join("api/new.age");
    assert!(age_file.is_file(), "{age_file:?} not created");

    let show = run_rspass(&scratch, &editor, &["show", "api/new"]);
    assert!(show.status.success());
    assert_eq!(show.stdout, b"s3cret-value\n");
}

#[test]
fn edit_modifies_existing_secret() {
    let (scratch, _id) = setup();
    let scratch_dir = scratch.xdg_config_home.parent().unwrap().to_path_buf();

    // First create a secret by editing.
    let editor1 = mock_editor_that_writes(&scratch_dir, "original\n");
    let out = run_rspass(&scratch, &editor1, &["edit", "notes"]);
    assert!(out.status.success());

    // Now edit again with a new payload.
    let editor2 = mock_editor_that_writes(&scratch_dir, "updated payload\nline 2\n");
    let out = run_rspass(&scratch, &editor2, &["edit", "notes"]);
    assert!(out.status.success());

    // Show reflects the latest write.
    let show = run_rspass(&scratch, &editor2, &["show", "notes"]);
    assert!(show.status.success());
    assert_eq!(show.stdout, b"updated payload\nline 2\n");
}

#[test]
fn edit_no_changes_is_noop() {
    let (scratch, _id) = setup();
    let scratch_dir = scratch.xdg_config_home.parent().unwrap().to_path_buf();

    // Create the secret with known content.
    let editor1 = mock_editor_that_writes(&scratch_dir, "stable\n");
    run_rspass(&scratch, &editor1, &["edit", "api/k"]);
    let original = std::fs::read(scratch.vault.join("api/k.age")).unwrap();
    let original_mtime = std::fs::metadata(scratch.vault.join("api/k.age"))
        .unwrap()
        .modified()
        .unwrap();

    // Sleep briefly to ensure mtime resolution would show a change.
    std::thread::sleep(std::time::Duration::from_millis(10));

    // Editor writes exactly the same bytes → rspass must print "no changes"
    // and not touch the file.
    let editor2 = mock_editor_that_writes(&scratch_dir, "stable\n");
    let out = run_rspass(&scratch, &editor2, &["edit", "api/k"]);
    assert!(out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("no changes"),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let after = std::fs::read(scratch.vault.join("api/k.age")).unwrap();
    let after_mtime = std::fs::metadata(scratch.vault.join("api/k.age"))
        .unwrap()
        .modified()
        .unwrap();
    assert_eq!(original, after, "ciphertext bytes must be unchanged");
    assert_eq!(
        original_mtime, after_mtime,
        "file must not have been rewritten"
    );
}

#[test]
fn edit_editor_nonzero_exit_preserves_tempfile() {
    let (scratch, _id) = setup();
    let scratch_dir = scratch.xdg_config_home.parent().unwrap().to_path_buf();

    // Editor that refuses to save (exits non-zero).
    let script = scratch_dir.join("failing-editor.sh");
    std::fs::write(&script, "#!/bin/sh\nexit 1\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

    let out = run_rspass(&scratch, &script, &["edit", "api/bad"]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("editor") && stderr.contains("preserved"),
        "stderr missing preservation notice: {stderr}"
    );
    // The .age file must not have been created.
    assert!(!scratch.vault.join("api/bad.age").exists());
}

#[test]
fn edit_rejects_existing_secret_reached_through_symlink_escape_before_editor() {
    let (scratch, identity) = setup();
    let scratch_dir = scratch.xdg_config_home.parent().unwrap().to_path_buf();
    let outside = scratch_dir.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    encrypt_to_file(&outside.join("secret.age"), &identity, b"outside\n");
    std::os::unix::fs::symlink(&outside, scratch.vault.join("link")).unwrap();

    let marker = scratch_dir.join("editor-ran");
    let script = scratch_dir.join("marker-editor.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\ntouch {}\nprintf changed > \"$1\"\n",
            marker.display()
        ),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

    let out = run_rspass(&scratch, &script, &["edit", "link/secret"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("escaped store root"),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!marker.exists(), "editor should not have been launched");
}

fn encrypt_to_file(path: &std::path::Path, identity: &age::x25519::Identity, plaintext: &[u8]) {
    let pubkey = identity.to_public();
    let r: &dyn age::Recipient = &pubkey;
    let encryptor = age::Encryptor::with_recipients(std::iter::once(r)).unwrap();
    let mut ct = Vec::new();
    let mut writer = encryptor.wrap_output(&mut ct).unwrap();
    writer.write_all(plaintext).unwrap();
    writer.finish().unwrap();
    std::fs::write(path, ct).unwrap();
}
