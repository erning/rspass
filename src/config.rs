use std::collections::HashMap;
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

    pub fn load_from(path: &Path) -> Result<Self, ConfigError> {
        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(ConfigError::NotFound(path.to_path_buf()));
            }
            Err(e) => return Err(ConfigError::Io(path.to_path_buf(), e)),
        };
        let cfg: Config = serde_yaml_ng::from_slice(&bytes)
            .map_err(|e| ConfigError::Parse(path.to_path_buf(), e))?;
        for key in cfg.mounts.keys() {
            if let Err(msg) = validate_mount_key(key) {
                return Err(ConfigError::InvalidMount(key.clone(), msg));
            }
        }
        Ok(cfg)
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

/// Expand `~`, `~/`, `${VAR}`, `\~`, `\$` per DESIGN.md §5.
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
}
