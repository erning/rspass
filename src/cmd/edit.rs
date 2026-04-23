use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;
use std::process::Command;

use tempfile::TempDir;
use zeroize::Zeroizing;

use crate::config::Config;
use crate::crypto;
use crate::decrypt;
use crate::error::RspassError;
use crate::path::{self, Resolved};
use crate::recipients;

/// `rspass edit <PATH>`: decrypt-or-empty, spawn $EDITOR on a tempfile, and
/// re-encrypt on save. Follows DESIGN.md §9.2 exactly:
///
/// - `$EDITOR` → `$VISUAL` → `vi` fallback
/// - tempfile named after the secret's basename (preserves extension for
///   editor syntax highlighting) inside a 0700 TempDir, file mode 0600
/// - no-change short-circuit without touching disk
/// - `mkdir -p` of missing parent dirs at mode 0700 (existing dirs untouched),
///   with a post-mkdir canonical-containment check against the store root
/// - atomic write: same-dir `.<target>.tmp.<pid>` (O_WRONLY|O_CREAT|O_EXCL,
///   0600), fsync, rename, fsync parent dir
///
/// Error-recovery: on editor non-zero exit, encrypt failure, or atomic-write
/// failure, the editor tempfile is **preserved** and its path printed so the
/// user can recover unsaved work. On success or no-change, the TempDir is
/// cleaned up (best-effort; not a secure wipe).
pub fn run(config: &Config, input: &str) -> Result<(), RspassError> {
    let resolved = path::resolve(config, input)?;

    // Step 1: load existing plaintext or start empty.
    let existing = load_existing(config, &resolved, input)?;

    // Step 2: resolve recipients via walk-up from parent(target). Canonicalize
    // the store root so the walk can defensively reject escapes.
    let store_root = fs::canonicalize(&resolved.store_root).map_err(RspassError::Io)?;
    let recipients = recipients::load_for(&resolved.age_file, &store_root)?;

    // Step 3: write the plaintext to a tempfile inside a 0700 TempDir.
    let tempdir = TempDir::with_prefix("rspass-edit-")?;
    let basename = resolved
        .age_file
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("secret")
        .to_string();
    let tempfile_path = tempdir.path().join(&basename);
    write_with_mode_0600(&tempfile_path, &existing)?;

    // Step 4: spawn the editor.
    let editor = pick_editor();
    let status = Command::new(&editor)
        .arg(&tempfile_path)
        .status()
        .map_err(RspassError::Io)?;
    if !status.success() {
        preserve_tempfile(tempdir, "editor exited non-zero");
        return Err(RspassError::EditorFailed);
    }

    // Step 5: read back the possibly-modified buffer.
    let modified = fs::read(&tempfile_path)?;
    if modified == *existing {
        eprintln!("rspass: no changes");
        return Ok(());
    }

    // Step 6: ensure parent directory exists and remains inside the store.
    if let Some(parent) = resolved.age_file.parent() {
        create_dir_all_0700(parent)?;
        let canonical_parent = fs::canonicalize(parent).map_err(RspassError::Io)?;
        if !canonical_parent.starts_with(&store_root) {
            preserve_tempfile(tempdir, "target parent escaped store root");
            return Err(RspassError::PathEscape(parent.to_path_buf()));
        }
    }

    // Step 7: encrypt with the walk-up recipients.
    let ciphertext = match crypto::encrypt(&modified, &recipients) {
        Ok(ct) => ct,
        Err(e) => {
            preserve_tempfile(tempdir, "encrypt failed");
            return Err(e.into());
        }
    };

    // Step 8: atomic write same-dir tmp → rename → fsync parent.
    if let Err(e) = atomic_write(&resolved.age_file, &ciphertext) {
        preserve_tempfile(tempdir, "atomic write failed");
        return Err(e);
    }

    // Step 9: success. TempDir drop will unlink the plaintext tempfile.
    Ok(())
}

fn load_existing(
    config: &Config,
    resolved: &Resolved,
    input: &str,
) -> Result<Zeroizing<Vec<u8>>, RspassError> {
    match fs::read(&resolved.age_file) {
        Ok(ct) => decrypt::with_identities_and_prompts(config, &ct),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let _ = input; // kept for parity with show's error message
            Ok(Zeroizing::new(Vec::new()))
        }
        Err(e) => Err(RspassError::Io(e)),
    }
}

fn write_with_mode_0600(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(contents)?;
    f.sync_all()?;
    Ok(())
}

fn pick_editor() -> String {
    std::env::var("EDITOR")
        .or_else(|_| std::env::var("VISUAL"))
        .unwrap_or_else(|_| "vi".to_string())
}

/// Recursively create missing directories, assigning mode 0700 only to levels
/// this call creates. Existing directories are left untouched (the store root
/// itself was created by the user and may legitimately have different perms).
fn create_dir_all_0700(path: &Path) -> std::io::Result<()> {
    if path.exists() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        create_dir_all_0700(parent)?;
    }
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e),
    }
}

fn atomic_write(target: &Path, contents: &[u8]) -> Result<(), RspassError> {
    let parent = target
        .parent()
        .ok_or_else(|| RspassError::Io(std::io::Error::other("target has no parent")))?;
    let base = target
        .file_name()
        .ok_or_else(|| RspassError::Io(std::io::Error::other("target has no file name")))?
        .to_string_lossy();
    let pid = std::process::id();
    let tmp = parent.join(format!(".{base}.tmp.{pid}"));

    // Ensure any stale tmp from an aborted previous run is removed before
    // O_EXCL open; same PID guarantees no concurrent writer inside this
    // process.
    let _ = fs::remove_file(&tmp);

    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(contents)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, target)?;
    // fsync the parent dir so the rename is durable.
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn preserve_tempfile(dir: TempDir, reason: &str) {
    let leaked = dir.keep();
    eprintln!(
        "rspass: {reason}; editor tempfile preserved at {}",
        leaked.display()
    );
}
