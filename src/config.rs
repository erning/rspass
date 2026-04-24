use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub mounts: HashMap<String, String>,
    #[serde(default)]
    pub identities: Vec<String>,
    #[serde(default)]
    pub include: Vec<String>,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("config file not found: {0}")]
    NotFound(PathBuf),
    #[error("failed to read {0}: {1}")]
    Io(PathBuf, #[source] std::io::Error),
    #[error("failed to parse {0}: {1}")]
    Parse(PathBuf, #[source] serde_yaml_ng::Error),
    #[error("invalid mount key {0:?}: {1}")]
    InvalidMount(String, &'static str),
    #[error("include file not found: {0}")]
    IncludeNotFound(PathBuf),
    #[error("failed to expand include entry {0:?}: {1}")]
    IncludeExpand(String, #[source] ExpansionError),
    #[error("invalid glob {0:?}: {1}")]
    IncludeGlob(String, #[source] glob::PatternError),
    #[error("nested include is not allowed in {0}")]
    NestedInclude(PathBuf),
    #[error("failed to expand path {1:?} in {0}: {2}")]
    PathExpand(PathBuf, String, #[source] ExpansionError),
}

#[derive(Debug, Error)]
pub enum ExpansionError {
    #[error("undefined variable ${{{0}}}")]
    UndefinedVar(String),
    #[error("unterminated ${{")]
    UnterminatedVar,
    #[error("invalid variable name: {0:?}")]
    InvalidVarName(String),
    #[error("cannot expand `~`: HOME not set")]
    NoHome,
}

impl Config {
    pub fn load() -> Result<Self, ConfigError> {
        Self::load_from(&default_path())
    }

    /// Parse the main config at `path` and merge any files listed in its
    /// `include:` field. See docs/DESIGN.md §5 for load order and merge rules.
    pub fn load_from(path: &Path) -> Result<Self, ConfigError> {
        let mut main = load_raw(path)?;
        let includes = std::mem::take(&mut main.include);
        if includes.is_empty() {
            return Ok(main);
        }
        let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
        let mut visited: HashSet<PathBuf> = HashSet::new();
        if let Ok(canon) = fs::canonicalize(path) {
            visited.insert(canon);
        }
        let mut seen_identities: HashSet<String> = main.identities.iter().cloned().collect();
        for entry in &includes {
            for resolved in resolve_include_entry(entry, base_dir)? {
                let canon = match fs::canonicalize(&resolved) {
                    Ok(c) => c,
                    Err(_) => return Err(ConfigError::IncludeNotFound(resolved)),
                };
                if !visited.insert(canon.clone()) {
                    continue;
                }
                let piece = load_raw(&canon)?;
                if !piece.include.is_empty() {
                    return Err(ConfigError::NestedInclude(canon));
                }
                merge_piece(&mut main, piece, &mut seen_identities);
            }
        }
        Ok(main)
    }
}

fn load_raw(path: &Path) -> Result<Config, ConfigError> {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ConfigError::NotFound(path.to_path_buf()));
        }
        Err(e) => return Err(ConfigError::Io(path.to_path_buf(), e)),
    };
    let mut cfg: Config =
        serde_yaml_ng::from_slice(&bytes).map_err(|e| ConfigError::Parse(path.to_path_buf(), e))?;
    let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
    for value in cfg.mounts.values_mut() {
        *value = anchor_path(value, base_dir, path)?;
    }
    for id in &mut cfg.identities {
        *id = anchor_path(id, base_dir, path)?;
    }
    for key in cfg.mounts.keys() {
        if let Err(msg) = validate_mount_key(key) {
            return Err(ConfigError::InvalidMount(key.clone(), msg));
        }
    }
    Ok(cfg)
}

/// Resolve a `mounts` value or `identities` entry: first run `expand_path`
/// (`~`, `${VAR}`, escapes per §5), then anchor any still-relative result to
/// `base_dir` — the directory of the config file the value was declared in.
/// This gives `include:`-loaded files file-local path semantics, matching how
/// `include:` itself resolves entries against the main config's directory.
/// The result is also lexically normalized so `conf.d/../stores/ai` collapses
/// to `stores/ai`.
fn anchor_path(value: &str, base_dir: &Path, source: &Path) -> Result<String, ConfigError> {
    let expanded = expand_path(value)
        .map_err(|e| ConfigError::PathExpand(source.to_path_buf(), value.to_string(), e))?;
    let p = Path::new(&expanded);
    let joined = if p.is_absolute() {
        p.to_path_buf()
    } else {
        base_dir.join(p)
    };
    Ok(normalize_path(&joined).to_string_lossy().into_owned())
}

/// Lexically collapse `.` and `..` components without touching the filesystem.
/// Symlinks are *not* followed — that would require the path to exist and is
/// the wrong semantics for mount targets that may be created later.
///
/// Behaves like Go's `filepath.Clean`: `a/./b` → `a/b`, `a/b/../c` → `a/c`,
/// `..` at the root is dropped (`/..` → `/`), trailing `..` on a relative
/// path is preserved (`..` → `..`, `a/../..` → `..`).
fn normalize_path(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => match out.components().next_back() {
                Some(Component::Normal(_)) => {
                    out.pop();
                }
                Some(Component::RootDir | Component::Prefix(_)) => {
                    // Can't ascend above the root; drop the `..`.
                }
                Some(Component::ParentDir) | None => {
                    // Start of a relative path or already-accumulated `..`s;
                    // keep stacking so `../foo` stays `../foo`.
                    out.push("..");
                }
                Some(Component::CurDir) => unreachable!("CurDir filtered above"),
            },
            other => out.push(other.as_os_str()),
        }
    }
    if out.as_os_str().is_empty() {
        out.push(".");
    }
    out
}

fn resolve_include_entry(entry: &str, base_dir: &Path) -> Result<Vec<PathBuf>, ConfigError> {
    let expanded =
        expand_path(entry).map_err(|e| ConfigError::IncludeExpand(entry.to_string(), e))?;
    let candidate = Path::new(&expanded);
    let absolute: PathBuf = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        base_dir.join(candidate)
    };
    if has_glob_meta(&expanded) {
        let pattern = absolute.to_string_lossy();
        let matches =
            glob::glob(&pattern).map_err(|e| ConfigError::IncludeGlob(entry.to_string(), e))?;
        let mut out: Vec<PathBuf> = matches.filter_map(Result::ok).collect();
        out.sort();
        Ok(out)
    } else {
        if !absolute.exists() {
            return Err(ConfigError::IncludeNotFound(absolute));
        }
        Ok(vec![absolute])
    }
}

fn has_glob_meta(s: &str) -> bool {
    s.chars().any(|c| matches!(c, '*' | '?' | '['))
}

/// Merge one included `Config` into the accumulator with first-wins semantics.
/// `seen_identities` holds the raw (unexpanded) identity strings already
/// present in `acc` — identities are deduped syntactically, which is enough
/// for typical include use but won't catch two distinct spellings of the same
/// file (e.g. `~/id.txt` vs `${HOME}/id.txt`).
fn merge_piece(acc: &mut Config, piece: Config, seen_identities: &mut HashSet<String>) {
    for (k, v) in piece.mounts {
        if acc.mounts.contains_key(&k) {
            tracing::debug!("ignoring duplicate mount key {k:?} from included file");
            continue;
        }
        acc.mounts.insert(k, v);
    }
    for id in piece.identities {
        if seen_identities.insert(id.clone()) {
            acc.identities.push(id);
        }
    }
}

/// Default config file location: `$XDG_CONFIG_HOME/rspass/config.yaml`
/// falling back to `~/.config/rspass/config.yaml`.
pub fn default_path() -> PathBuf {
    if let Some(xdg) = env::var_os("XDG_CONFIG_HOME")
        && !xdg.is_empty()
    {
        return PathBuf::from(xdg).join("rspass").join("config.yaml");
    }
    dirs::home_dir()
        .unwrap_or_default()
        .join(".config")
        .join("rspass")
        .join("config.yaml")
}

fn validate_mount_key(key: &str) -> Result<(), &'static str> {
    if key.is_empty() {
        return Ok(());
    }
    if key.starts_with('/') {
        return Err("must not start with `/`");
    }
    if key.ends_with('/') {
        return Err("must not end with `/`");
    }
    for comp in key.split('/') {
        if comp.is_empty() {
            return Err("must not contain empty components");
        }
        if comp == "." || comp == ".." {
            return Err("must not contain `.` or `..`");
        }
    }
    Ok(())
}

/// Expand `~`, `~/`, `${VAR}`, `\~`, `\$` per docs/DESIGN.md §5.
///
/// Only the leading `~` or `\~` is interpreted as the tilde marker;
/// `~` elsewhere is literal. `${VAR}` anywhere is expanded from the
/// environment. A bare backslash that does not precede `~` or `$` is
/// emitted as-is (there is no `\\` escape).
pub fn expand_path(input: &str) -> Result<String, ExpansionError> {
    expand_path_with(input, |name| env::var(name).ok(), dirs::home_dir())
}

pub fn expand_path_with(
    input: &str,
    lookup: impl Fn(&str) -> Option<String>,
    home: Option<PathBuf>,
) -> Result<String, ExpansionError> {
    let after_tilde = expand_tilde(input, home.as_deref())?;
    expand_vars(&after_tilde, &lookup)
}

fn expand_tilde(input: &str, home: Option<&Path>) -> Result<String, ExpansionError> {
    // `\~...` at the start means a literal `~` with the rest kept intact.
    if let Some(rest) = input.strip_prefix("\\~") {
        return Ok(format!("~{rest}"));
    }
    if let Some(rest) = input.strip_prefix("~/") {
        let home = home.ok_or(ExpansionError::NoHome)?;
        let mut out = home.to_string_lossy().into_owned();
        out.push('/');
        out.push_str(rest);
        return Ok(out);
    }
    if input == "~" {
        let home = home.ok_or(ExpansionError::NoHome)?;
        return Ok(home.to_string_lossy().into_owned());
    }
    Ok(input.to_string())
}

fn expand_vars(
    input: &str,
    lookup: &impl Fn(&str) -> Option<String>,
) -> Result<String, ExpansionError> {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'\\' && i + 1 < bytes.len() {
            let next = bytes[i + 1];
            if next == b'~' || next == b'$' {
                out.push(next as char);
                i += 2;
                continue;
            }
        }
        if c == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            let mut j = i + 2;
            while j < bytes.len() && bytes[j] != b'}' {
                j += 1;
            }
            if j == bytes.len() {
                return Err(ExpansionError::UnterminatedVar);
            }
            let name = &input[i + 2..j];
            if !is_valid_var_name(name) {
                return Err(ExpansionError::InvalidVarName(name.to_string()));
            }
            let val = lookup(name).ok_or_else(|| ExpansionError::UndefinedVar(name.to_string()))?;
            out.push_str(&val);
            i = j + 1;
            continue;
        }
        out.push(c as char);
        i += 1;
    }
    Ok(out)
}

fn is_valid_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_lookup<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name: &str| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.to_string())
        }
    }

    fn home() -> Option<PathBuf> {
        Some(PathBuf::from("/home/tester"))
    }

    #[test]
    fn expand_tilde_alone() {
        let got = expand_path_with("~", |_| None, home()).unwrap();
        assert_eq!(got, "/home/tester");
    }

    #[test]
    fn expand_tilde_slash() {
        let got = expand_path_with("~/foo/bar", |_| None, home()).unwrap();
        assert_eq!(got, "/home/tester/foo/bar");
    }

    #[test]
    fn expand_tilde_with_no_slash_after_is_literal() {
        // `~foo` is not supported; should pass through untouched
        let got = expand_path_with("~foo", |_| None, home()).unwrap();
        assert_eq!(got, "~foo");
    }

    #[test]
    fn escaped_leading_tilde_is_literal() {
        let got = expand_path_with("\\~/foo", |_| None, home()).unwrap();
        assert_eq!(got, "~/foo");
    }

    #[test]
    fn escaped_tilde_only() {
        let got = expand_path_with("\\~", |_| None, home()).unwrap();
        assert_eq!(got, "~");
    }

    #[test]
    fn expand_var() {
        let lookup = make_lookup(&[("HOME", "/abs/home")]);
        let got = expand_path_with("${HOME}/foo", lookup, None).unwrap();
        assert_eq!(got, "/abs/home/foo");
    }

    #[test]
    fn escaped_dollar_is_literal() {
        let got = expand_path_with("\\${HOME}/x", |_| None, None).unwrap();
        assert_eq!(got, "${HOME}/x");
    }

    #[test]
    fn undefined_var_errors() {
        let err = expand_path_with("${MISSING}/x", |_| None, None).unwrap_err();
        assert!(matches!(err, ExpansionError::UndefinedVar(n) if n == "MISSING"));
    }

    #[test]
    fn unterminated_var_errors() {
        let err = expand_path_with("${HOME/x", |_| None, None).unwrap_err();
        assert!(matches!(err, ExpansionError::UnterminatedVar));
    }

    #[test]
    fn invalid_var_name_errors() {
        let err = expand_path_with("${1BAD}/x", |_| None, None).unwrap_err();
        assert!(matches!(err, ExpansionError::InvalidVarName(_)));
    }

    #[test]
    fn double_backslash_before_tilde() {
        // `\\~` → pos 0 `\` not followed by ~/$ → emit `\` → pos 1 `\~` → emit `~` → `\~`
        let got = expand_path_with("\\\\~", |_| None, home()).unwrap();
        assert_eq!(got, "\\~");
    }

    #[test]
    fn mid_string_escaped_tilde() {
        let got = expand_path_with("abc\\~def", |_| None, None).unwrap();
        assert_eq!(got, "abc~def");
    }

    #[test]
    fn lone_backslash_passes_through() {
        let got = expand_path_with("foo\\bar", |_| None, None).unwrap();
        assert_eq!(got, "foo\\bar");
    }

    #[test]
    fn trailing_backslash_passes_through() {
        let got = expand_path_with("foo\\", |_| None, None).unwrap();
        assert_eq!(got, "foo\\");
    }

    #[test]
    fn multiple_vars() {
        let lookup = make_lookup(&[("A", "alpha"), ("B", "beta")]);
        let got = expand_path_with("${A}/x/${B}", lookup, None).unwrap();
        assert_eq!(got, "alpha/x/beta");
    }

    #[test]
    fn validate_mount_key_accepts_normal() {
        assert!(validate_mount_key("").is_ok());
        assert!(validate_mount_key("work").is_ok());
        assert!(validate_mount_key("team/shared").is_ok());
        assert!(validate_mount_key("a/b/c").is_ok());
    }

    #[test]
    fn validate_mount_key_rejects_bad() {
        assert!(validate_mount_key("/work").is_err());
        assert!(validate_mount_key("work/").is_err());
        assert!(validate_mount_key("a//b").is_err());
        assert!(validate_mount_key("a/./b").is_err());
        assert!(validate_mount_key("a/../b").is_err());
    }

    #[test]
    fn parse_empty_yaml() {
        let cfg: Config = serde_yaml_ng::from_str("").unwrap();
        assert!(cfg.mounts.is_empty());
        assert!(cfg.identities.is_empty());
    }

    #[test]
    fn parse_full_yaml() {
        let yaml = r#"
mounts:
  "": ~/.local/share/rspass
  "work": ~/work-secrets
identities:
  - ~/.config/rspass/id.txt
  - ~/.config/rspass/work.txt
"#;
        let cfg: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(cfg.mounts.len(), 2);
        assert_eq!(
            cfg.mounts.get("").map(String::as_str),
            Some("~/.local/share/rspass")
        );
        assert_eq!(cfg.identities.len(), 2);
    }

    #[test]
    fn reject_unknown_field() {
        let yaml = "mounts: {}\nbogus: true\n";
        let err = serde_yaml_ng::from_str::<Config>(yaml).unwrap_err();
        assert!(err.to_string().contains("bogus"));
    }

    mod include {
        use super::*;
        use tempfile::tempdir;

        fn write(dir: &Path, name: &str, content: &str) -> PathBuf {
            let p = dir.join(name);
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(&p, content).unwrap();
            p
        }

        #[test]
        fn merges_mounts_and_identities() {
            let dir = tempdir().unwrap();
            write(
                dir.path(),
                "extra.yaml",
                "mounts:\n  team: /shared\nidentities:\n  - /id/team.txt\n",
            );
            let main = write(
                dir.path(),
                "config.yaml",
                "include:\n  - extra.yaml\nmounts:\n  \"\": /root\nidentities:\n  - /id/main.txt\n",
            );
            let cfg = Config::load_from(&main).unwrap();
            assert_eq!(cfg.mounts.get(""), Some(&"/root".to_string()));
            assert_eq!(cfg.mounts.get("team"), Some(&"/shared".to_string()));
            assert_eq!(cfg.identities, vec!["/id/main.txt", "/id/team.txt"]);
            assert!(cfg.include.is_empty(), "include should be consumed");
        }

        #[test]
        fn relative_path_anchored_at_main_dir() {
            let dir = tempdir().unwrap();
            write(dir.path(), "sub/extra.yaml", "mounts:\n  x: /a\n");
            let main = write(dir.path(), "config.yaml", "include:\n  - sub/extra.yaml\n");
            let cfg = Config::load_from(&main).unwrap();
            assert_eq!(cfg.mounts.get("x"), Some(&"/a".to_string()));
        }

        #[test]
        fn glob_sorted_and_first_wins() {
            let dir = tempdir().unwrap();
            // 10-* is loaded before 20-*, so its value for `shared` wins.
            write(
                dir.path(),
                "conf.d/10-a.yaml",
                "mounts:\n  shared: /first\n",
            );
            write(
                dir.path(),
                "conf.d/20-b.yaml",
                "mounts:\n  shared: /second\n",
            );
            let main = write(dir.path(), "config.yaml", "include:\n  - conf.d/*.yaml\n");
            let cfg = Config::load_from(&main).unwrap();
            assert_eq!(cfg.mounts.get("shared"), Some(&"/first".to_string()));
        }

        #[test]
        fn glob_zero_matches_is_ok() {
            let dir = tempdir().unwrap();
            fs::create_dir_all(dir.path().join("conf.d")).unwrap();
            let main = write(
                dir.path(),
                "config.yaml",
                "include:\n  - conf.d/*.yaml\nmounts:\n  \"\": /root\n",
            );
            let cfg = Config::load_from(&main).unwrap();
            assert_eq!(cfg.mounts.get(""), Some(&"/root".to_string()));
        }

        #[test]
        fn literal_missing_errors() {
            let dir = tempdir().unwrap();
            let main = write(
                dir.path(),
                "config.yaml",
                "include:\n  - no-such-file.yaml\n",
            );
            let err = Config::load_from(&main).unwrap_err();
            assert!(
                matches!(err, ConfigError::IncludeNotFound(_)),
                "got {err:?}"
            );
        }

        #[test]
        fn mounts_first_wins_main_beats_include() {
            let dir = tempdir().unwrap();
            write(dir.path(), "extra.yaml", "mounts:\n  work: /from-include\n");
            let main = write(
                dir.path(),
                "config.yaml",
                "include:\n  - extra.yaml\nmounts:\n  work: /from-main\n",
            );
            let cfg = Config::load_from(&main).unwrap();
            assert_eq!(cfg.mounts.get("work"), Some(&"/from-main".to_string()));
        }

        #[test]
        fn identities_dedup_preserves_first_order() {
            let dir = tempdir().unwrap();
            write(
                dir.path(),
                "extra.yaml",
                "identities:\n  - /id/b.txt\n  - /id/c.txt\n",
            );
            let main = write(
                dir.path(),
                "config.yaml",
                "include:\n  - extra.yaml\nidentities:\n  - /id/a.txt\n  - /id/b.txt\n",
            );
            let cfg = Config::load_from(&main).unwrap();
            assert_eq!(cfg.identities, vec!["/id/a.txt", "/id/b.txt", "/id/c.txt"]);
        }

        #[test]
        fn rejects_nested_include() {
            let dir = tempdir().unwrap();
            write(dir.path(), "leaf.yaml", "mounts: {}\n");
            write(dir.path(), "extra.yaml", "include:\n  - leaf.yaml\n");
            let main = write(dir.path(), "config.yaml", "include:\n  - extra.yaml\n");
            let err = Config::load_from(&main).unwrap_err();
            assert!(matches!(err, ConfigError::NestedInclude(_)), "got {err:?}");
        }

        #[test]
        fn duplicate_include_file_skipped() {
            let dir = tempdir().unwrap();
            // Same file reached twice: once via literal, once via glob. The
            // second visit must be silently skipped; otherwise the second
            // attempt to append the same identity would be a no-op only
            // because of dedup — but mounts would also duplicate-log. We
            // verify the merged result is identical to a single include.
            write(dir.path(), "conf.d/one.yaml", "mounts:\n  x: /v\n");
            let main = write(
                dir.path(),
                "config.yaml",
                "include:\n  - conf.d/one.yaml\n  - conf.d/*.yaml\n",
            );
            let cfg = Config::load_from(&main).unwrap();
            assert_eq!(cfg.mounts.get("x"), Some(&"/v".to_string()));
            assert_eq!(cfg.mounts.len(), 1);
        }

        #[test]
        fn include_entry_accepts_absolute_path() {
            let dir = tempdir().unwrap();
            write(dir.path(), "extra.yaml", "mounts:\n  y: /yv\n");
            let main = write(
                dir.path(),
                "config.yaml",
                &format!(
                    "include:\n  - {}\n",
                    dir.path().join("extra.yaml").display()
                ),
            );
            let cfg = Config::load_from(&main).unwrap();
            assert_eq!(cfg.mounts.get("y"), Some(&"/yv".to_string()));
        }

        #[test]
        fn include_field_accepted_by_parser() {
            // `deny_unknown_fields` must still allow `include`.
            let yaml = "include:\n  - a.yaml\nmounts: {}\n";
            let cfg: Config = serde_yaml_ng::from_str(yaml).unwrap();
            assert_eq!(cfg.include, vec!["a.yaml"]);
        }
    }

    mod relative_paths {
        use super::*;
        use tempfile::tempdir;

        fn write(dir: &Path, name: &str, content: &str) -> PathBuf {
            let p = dir.join(name);
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(&p, content).unwrap();
            p
        }

        #[test]
        fn relative_mount_anchors_to_config_dir() {
            let dir = tempdir().unwrap();
            let main = write(dir.path(), "config.yaml", "mounts:\n  work: store/work\n");
            let cfg = Config::load_from(&main).unwrap();
            let expected = dir.path().join("store/work").to_string_lossy().into_owned();
            assert_eq!(cfg.mounts.get("work"), Some(&expected));
        }

        #[test]
        fn relative_identity_anchors_to_config_dir() {
            let dir = tempdir().unwrap();
            let main = write(dir.path(), "config.yaml", "identities:\n  - keys/id.txt\n");
            let cfg = Config::load_from(&main).unwrap();
            let expected = dir
                .path()
                .join("keys/id.txt")
                .to_string_lossy()
                .into_owned();
            assert_eq!(cfg.identities, vec![expected]);
        }

        #[test]
        fn absolute_paths_are_unchanged() {
            let dir = tempdir().unwrap();
            let main = write(
                dir.path(),
                "config.yaml",
                "mounts:\n  work: /abs/store\nidentities:\n  - /abs/id.txt\n",
            );
            let cfg = Config::load_from(&main).unwrap();
            assert_eq!(cfg.mounts.get("work"), Some(&"/abs/store".to_string()));
            assert_eq!(cfg.identities, vec!["/abs/id.txt".to_string()]);
        }

        #[test]
        fn tilde_expansion_still_yields_absolute() {
            // Skip if HOME isn't set (unlikely in tests but be safe).
            let Some(home) = dirs::home_dir() else {
                return;
            };
            let dir = tempdir().unwrap();
            let main = write(dir.path(), "config.yaml", "mounts:\n  w: ~/work\n");
            let cfg = Config::load_from(&main).unwrap();
            let expected = home.join("work").to_string_lossy().into_owned();
            assert_eq!(cfg.mounts.get("w"), Some(&expected));
        }

        #[test]
        fn parent_dir_segments_are_collapsed() {
            // The original ask: a config at .../conf.d/foo.yaml referencing
            // ../stores/ai should land at .../stores/ai with no `..` left
            // in the resolved path.
            let dir = tempdir().unwrap();
            write(
                dir.path(),
                "conf.d/work.yaml",
                "mounts:\n  ai: ../stores/ai\n",
            );
            let main = write(
                dir.path(),
                "config.yaml",
                "include:\n  - conf.d/work.yaml\n",
            );
            let cfg = Config::load_from(&main).unwrap();
            let resolved = cfg.mounts.get("ai").expect("ai mount");
            assert!(
                !resolved.contains("/.."),
                "expected normalized path, got {resolved}"
            );
            assert!(resolved.ends_with("/stores/ai"), "got {resolved}");
        }

        #[test]
        fn absolute_paths_with_dots_are_normalized() {
            let dir = tempdir().unwrap();
            let main = write(
                dir.path(),
                "config.yaml",
                "mounts:\n  m: /abs/./store/../canonical\n",
            );
            let cfg = Config::load_from(&main).unwrap();
            assert_eq!(cfg.mounts.get("m"), Some(&"/abs/canonical".to_string()));
        }

        #[test]
        fn included_file_anchors_to_its_own_dir_not_main_dir() {
            // Main config in dir/, included file in dir/sub/. The included
            // file's relative `mounts` value must resolve under dir/sub, not
            // under dir/, even though the load was kicked off from dir/.
            //
            // load_from canonicalizes the included file's path before
            // load_raw runs, so on macOS the anchor is `/private/var/...`
            // even though the tempdir reports `/var/...`. Compare against
            // the canonical form to keep the test portable.
            let dir = tempdir().unwrap();
            let extra = write(
                dir.path(),
                "sub/extra.yaml",
                "mounts:\n  team: store/team\n",
            );
            let main = write(dir.path(), "config.yaml", "include:\n  - sub/extra.yaml\n");
            let cfg = Config::load_from(&main).unwrap();
            let expected = fs::canonicalize(&extra)
                .unwrap()
                .parent()
                .unwrap()
                .join("store/team")
                .to_string_lossy()
                .into_owned();
            assert_eq!(cfg.mounts.get("team"), Some(&expected));
        }
    }
}
