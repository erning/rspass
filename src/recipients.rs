use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use age::Recipient;
use thiserror::Error;

pub type BoxRecipient = Box<dyn Recipient>;

#[derive(Debug, Error)]
pub enum RecipientError {
    #[error("no .age-recipients found for {target:?} (walked up to store root {store_root:?})")]
    NotFound {
        target: PathBuf,
        store_root: PathBuf,
    },
    #[error("failed to read {0}: {1}")]
    Io(PathBuf, #[source] std::io::Error),
    #[error("{path}:{line}: invalid recipient: {reason}")]
    BadRecipient {
        path: PathBuf,
        line: usize,
        reason: String,
    },
}

/// Walk up from `parent(target)` to `store_root` inclusive, and return the
/// parsed recipients from the first `.age-recipients` file found.
///
/// Per DESIGN.md section 6 this is **override-not-inherit**: the first file
/// found along the walk wins; parent files are not merged in. Directories
/// that want the parent's recipients simply don't create a local file.
///
/// `target` need not exist. `store_root` is canonicalized internally so
/// callers don't have to worry about symlink chains like macOS's
/// `/var/folders/...` → `/private/var/folders/...`.
pub fn load_for(target: &Path, store_root: &Path) -> Result<Vec<BoxRecipient>, RecipientError> {
    let store_root_canon =
        fs::canonicalize(store_root).map_err(|e| RecipientError::Io(store_root.to_path_buf(), e))?;
    let start = target.parent().unwrap_or(target);
    let (content, path) = walk_up(start, &store_root_canon)?;
    parse(&content, &path)
}

fn walk_up(from: &Path, store_root: &Path) -> Result<(String, PathBuf), RecipientError> {
    // Canonicalize the starting dir so its prefix relationship with `store_root`
    // (which the caller must pass canonicalized) is symbolic-link-agnostic.
    // If `from` doesn't exist yet (edit's new-file case), walk up to the
    // nearest existing ancestor and canonicalize that; the pre-existing
    // portion of the path is all we need for the walk since anything below
    // it cannot hold an `.age-recipients` file.
    let mut cur = from.to_path_buf();
    while !cur.exists() {
        match cur.parent() {
            Some(p) => cur = p.to_path_buf(),
            None => {
                return Err(RecipientError::NotFound {
                    target: from.to_path_buf(),
                    store_root: store_root.to_path_buf(),
                });
            }
        }
    }
    let mut cur = fs::canonicalize(&cur).map_err(|e| RecipientError::Io(cur, e))?;

    loop {
        // Defensive bound: never walk above the store root, even if `from`
        // pointed outside it due to a caller bug.
        if !cur.starts_with(store_root) {
            break;
        }
        let candidate = cur.join(".age-recipients");
        match fs::read_to_string(&candidate) {
            Ok(s) => return Ok((s, candidate)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(RecipientError::Io(candidate, e)),
        }
        if cur == store_root {
            break;
        }
        match cur.parent() {
            Some(p) => cur = p.to_path_buf(),
            None => break,
        }
    }
    Err(RecipientError::NotFound {
        target: from.to_path_buf(),
        store_root: store_root.to_path_buf(),
    })
}

fn parse(content: &str, path: &Path) -> Result<Vec<BoxRecipient>, RecipientError> {
    let mut out: Vec<BoxRecipient> = Vec::new();
    for (idx, raw) in content.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let rec = parse_line(line).map_err(|reason| RecipientError::BadRecipient {
            path: path.to_path_buf(),
            line: idx + 1,
            reason,
        })?;
        out.push(rec);
    }
    Ok(out)
}

fn parse_line(line: &str) -> Result<BoxRecipient, String> {
    if line.starts_with("age1") {
        // age X25519 pubkeys never contain whitespace, so everything after
        // the first token is treated as a trailing comment / note and
        // discarded. This keeps rspass's `.age-recipients` tolerant of
        // lines like `age1xyz # alice@laptop`, a convention gopass and
        // many wrappers rely on.
        let token = line.split_whitespace().next().unwrap_or("");
        let r = age::x25519::Recipient::from_str(token).map_err(|e| e.to_string())?;
        Ok(Box::new(r))
    } else if line.starts_with("ssh-ed25519 ") || line.starts_with("ssh-rsa ") {
        // SSH public keys encode their own whitespace-separated comment
        // (e.g. `user@host`) after the base64 blob, so the whole line
        // must reach age::ssh::Recipient::from_str unmodified. That also
        // means `#`-style tail comments are *not* supported on SSH lines;
        // use a preceding `#`-only line for any notes.
        //
        // `age::ssh::ParseRecipientKeyError` is not Display, so use Debug.
        let r = age::ssh::Recipient::from_str(line).map_err(|e| format!("{e:?}"))?;
        Ok(Box::new(r))
    } else {
        let kind = line.split_whitespace().next().unwrap_or("");
        Err(format!("unknown recipient type {kind:?}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn gen_age_pubkey() -> String {
        let id = age::x25519::Identity::generate();
        id.to_public().to_string()
    }

    #[test]
    fn finds_file_in_same_dir_as_target() {
        let dir = tempdir().unwrap();
        let store = dir.path();
        let sub = store.join("a/b");
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join(".age-recipients"), gen_age_pubkey()).unwrap();
        let target = sub.join("secret.age");
        let recs = load_for(&target, store).unwrap();
        assert_eq!(recs.len(), 1);
    }

    #[test]
    fn walks_up_to_ancestor() {
        let dir = tempdir().unwrap();
        let store = dir.path();
        fs::create_dir_all(store.join("a/b/c")).unwrap();
        fs::write(store.join("a/.age-recipients"), gen_age_pubkey()).unwrap();
        let target = store.join("a/b/c/secret.age");
        let recs = load_for(&target, store).unwrap();
        assert_eq!(recs.len(), 1);
    }

    #[test]
    fn walks_up_to_store_root_inclusive() {
        let dir = tempdir().unwrap();
        let store = dir.path();
        fs::create_dir_all(store.join("a/b")).unwrap();
        fs::write(store.join(".age-recipients"), gen_age_pubkey()).unwrap();
        let target = store.join("a/b/secret.age");
        let recs = load_for(&target, store).unwrap();
        assert_eq!(recs.len(), 1);
    }

    #[test]
    fn first_match_wins_override_not_inherit() {
        let dir = tempdir().unwrap();
        let store = dir.path();
        let sub = store.join("a/b");
        fs::create_dir_all(&sub).unwrap();
        // Parent has one key; child has a different single key. Child wins entirely.
        let parent_key = gen_age_pubkey();
        let child_key = gen_age_pubkey();
        fs::write(store.join(".age-recipients"), &parent_key).unwrap();
        fs::write(sub.join(".age-recipients"), &child_key).unwrap();
        let target = sub.join("secret.age");
        let recs = load_for(&target, store).unwrap();
        // Can't compare Box<dyn Recipient> directly; check count for override
        assert_eq!(recs.len(), 1);
    }

    fn expect_err<T>(r: Result<T, RecipientError>) -> RecipientError {
        match r {
            Ok(_) => panic!("expected error, got Ok"),
            Err(e) => e,
        }
    }

    #[test]
    fn not_found_when_nothing_in_tree() {
        let dir = tempdir().unwrap();
        let store = dir.path();
        fs::create_dir_all(store.join("a/b")).unwrap();
        let target = store.join("a/b/secret.age");
        let err = expect_err(load_for(&target, store));
        assert!(matches!(err, RecipientError::NotFound { .. }));
    }

    #[test]
    fn does_not_look_above_store_root() {
        let dir = tempdir().unwrap();
        let outer = dir.path();
        let store = outer.join("store");
        fs::create_dir_all(store.join("a")).unwrap();
        // Recipients file lives OUTSIDE the store root; must not be used.
        fs::write(outer.join(".age-recipients"), gen_age_pubkey()).unwrap();
        let target = store.join("a/secret.age");
        let err = expect_err(load_for(&target, &store));
        assert!(matches!(err, RecipientError::NotFound { .. }));
    }

    #[test]
    fn target_does_not_have_to_exist() {
        // edit can create new secrets; parent of target may or may not exist,
        // but recipients lookup should still work as long as some ancestor has
        // .age-recipients.
        let dir = tempdir().unwrap();
        let store = dir.path();
        fs::write(store.join(".age-recipients"), gen_age_pubkey()).unwrap();
        let target = store.join("nonexistent/secret.age");
        let recs = load_for(&target, store).unwrap();
        assert_eq!(recs.len(), 1);
    }

    #[test]
    fn parse_skips_blanks_and_comments() {
        let pub1 = gen_age_pubkey();
        let pub2 = gen_age_pubkey();
        let content = format!(
            "# header comment\n\n  # indented comment\n{pub1}\n\n{pub2}\n# trailing\n"
        );
        let dir = tempdir().unwrap();
        let store = dir.path();
        fs::write(store.join(".age-recipients"), &content).unwrap();
        let target = store.join("x.age");
        let recs = load_for(&target, store).unwrap();
        assert_eq!(recs.len(), 2);
    }

    #[test]
    fn parse_rejects_garbage_with_line_number() {
        let pub1 = gen_age_pubkey();
        let content = format!("# header\n{pub1}\ngarbage-line\n");
        let dir = tempdir().unwrap();
        let store = dir.path();
        fs::write(store.join(".age-recipients"), &content).unwrap();
        let target = store.join("x.age");
        match expect_err(load_for(&target, store)) {
            RecipientError::BadRecipient { line, .. } => assert_eq!(line, 3),
            other => panic!("expected BadRecipient, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_unknown_prefix() {
        let content = "ed25519-cert-v01 AAA...\n";
        let dir = tempdir().unwrap();
        let store = dir.path();
        fs::write(store.join(".age-recipients"), content).unwrap();
        let target = store.join("x.age");
        let err = expect_err(load_for(&target, store));
        assert!(matches!(err, RecipientError::BadRecipient { .. }));
    }

    #[test]
    fn parse_empty_recipients_file_is_ok_but_empty() {
        // An empty or comments-only file is not itself an error; it yields
        // zero recipients. Encryption with zero recipients would fail later,
        // but that's encoder's concern. Here we just verify parse succeeds.
        let content = "# only comments\n\n# and blanks\n";
        let dir = tempdir().unwrap();
        let store = dir.path();
        fs::write(store.join(".age-recipients"), content).unwrap();
        let target = store.join("x.age");
        let recs = load_for(&target, store).unwrap();
        assert!(recs.is_empty());
    }

    #[test]
    fn age_recipient_accepts_tail_comment() {
        let pubkey = gen_age_pubkey();
        let content = format!("{pubkey}   # alice@laptop\n");
        let dir = tempdir().unwrap();
        let store = dir.path();
        fs::write(store.join(".age-recipients"), content).unwrap();
        let target = store.join("x.age");
        let recs = load_for(&target, store).unwrap();
        assert_eq!(recs.len(), 1);
    }

    #[test]
    fn age_recipient_accepts_non_hash_tail_text() {
        // First whitespace-delimited token is the key; anything after is
        // discarded, even without a `#`.
        let pubkey = gen_age_pubkey();
        let content = format!("{pubkey} erning production backup\n");
        let dir = tempdir().unwrap();
        let store = dir.path();
        fs::write(store.join(".age-recipients"), content).unwrap();
        let target = store.join("x.age");
        let recs = load_for(&target, store).unwrap();
        assert_eq!(recs.len(), 1);
    }

    #[test]
    fn ssh_ed25519_recipient_parses() {
        // A known-good ssh-ed25519 public key (deterministic from a fixed seed,
        // generated with ssh-keygen). Comment tail is part of the line and must
        // be handled by age's SSH recipient parser.
        let ssh_line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJNlE4qC5Jb2P7rRr4Rc3gkxQ8EXxBcjJ8RKZYf6ZqVL test@rspass";
        let dir = tempdir().unwrap();
        let store = dir.path();
        fs::write(store.join(".age-recipients"), ssh_line).unwrap();
        let target = store.join("x.age");
        let recs = load_for(&target, store).unwrap();
        assert_eq!(recs.len(), 1);
    }
}
