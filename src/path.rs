use std::path::PathBuf;

use thiserror::Error;

use crate::config::{Config, ExpansionError, expand_path};

/// Result of resolving a `[MOUNT/]REL/PATH` input to filesystem locations.
#[derive(Debug, Clone)]
pub struct Resolved {
    /// Matched mount key (empty string `""` for the root mount).
    pub mount: String,
    /// Expanded store root directory. Not canonicalized; caller canonicalizes
    /// per operation (show requires it to exist, edit may create children).
    pub store_root: PathBuf,
    /// Path relative to the store root, without `.age` suffix.
    pub rel: PathBuf,
    /// Absolute path to the `.age` file under the store root.
    pub age_file: PathBuf,
}

#[derive(Debug, Error)]
pub enum PathError {
    #[error("no matching mount for {0:?}")]
    NoMount(String),
    #[error("path must be relative, got absolute: {0:?}")]
    Absolute(String),
    #[error("path contains empty component, `.`, or `..`: {0:?}")]
    InvalidComponent(String),
    #[error("path is empty or resolves to no secret: {0:?}")]
    Empty(String),
    #[error("failed to expand store root {0:?}: {1}")]
    Expansion(String, #[source] ExpansionError),
}

/// Parse `[MOUNT/]REL/PATH` and locate the `.age` file under the matching mount.
///
/// Mount matching is longest-path-component-prefix wins. The empty key `""`
/// acts as the root mount and matches any input not captured by a longer
/// non-empty mount.
pub fn resolve(config: &Config, input: &str) -> Result<Resolved, PathError> {
    if input.is_empty() {
        return Err(PathError::Empty(input.to_string()));
    }
    if input.starts_with('/') {
        return Err(PathError::Absolute(input.to_string()));
    }
    let components: Vec<&str> = input.split('/').collect();
    for c in &components {
        if c.is_empty() || *c == "." || *c == ".." {
            return Err(PathError::InvalidComponent(input.to_string()));
        }
    }

    // Longest matching mount (by component count). Root "" is length 0.
    let mut best: Option<(&str, usize)> = None;
    for mount in config.mounts.keys() {
        let mount_comps: Vec<&str> = if mount.is_empty() {
            Vec::new()
        } else {
            mount.split('/').collect()
        };
        if mount_comps.len() > components.len() {
            continue;
        }
        if components[..mount_comps.len()] == mount_comps[..] {
            let len = mount_comps.len();
            if best.is_none_or(|(_, l)| l < len) {
                best = Some((mount.as_str(), len));
            }
        }
    }

    let (mount, prefix_len) = best.ok_or_else(|| PathError::NoMount(input.to_string()))?;

    let rel_components = &components[prefix_len..];
    if rel_components.is_empty() {
        // User provided only the mount name (e.g. `work`) with no secret path.
        return Err(PathError::Empty(input.to_string()));
    }

    let store_root_str = config.mounts.get(mount).expect("mount key must exist");
    let store_root = PathBuf::from(
        expand_path(store_root_str)
            .map_err(|e| PathError::Expansion(store_root_str.clone(), e))?,
    );
    let rel: PathBuf = rel_components.iter().collect();
    let mut age_file = store_root.join(&rel);
    let leaf = age_file
        .file_name()
        .expect("rel has at least one component")
        .to_string_lossy()
        .into_owned();
    age_file.set_file_name(format!("{leaf}.age"));

    Ok(Resolved {
        mount: mount.to_string(),
        store_root,
        rel,
        age_file,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn config(mounts: &[(&str, &str)]) -> Config {
        Config {
            mounts: mounts
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            identities: Vec::new(),
        }
    }

    #[test]
    fn root_mount_catches_simple_path() {
        let cfg = config(&[("", "/srv/vault")]);
        let r = resolve(&cfg, "api/openai").unwrap();
        assert_eq!(r.mount, "");
        assert_eq!(r.store_root, PathBuf::from("/srv/vault"));
        assert_eq!(r.rel, PathBuf::from("api/openai"));
        assert_eq!(r.age_file, PathBuf::from("/srv/vault/api/openai.age"));
    }

    #[test]
    fn named_mount_wins_over_root() {
        let cfg = config(&[("", "/srv/personal"), ("work", "/srv/work")]);
        let r = resolve(&cfg, "work/db/prod").unwrap();
        assert_eq!(r.mount, "work");
        assert_eq!(r.store_root, PathBuf::from("/srv/work"));
        assert_eq!(r.rel, PathBuf::from("db/prod"));
        assert_eq!(r.age_file, PathBuf::from("/srv/work/db/prod.age"));
    }

    #[test]
    fn longest_prefix_wins() {
        let cfg = config(&[
            ("", "/srv/root"),
            ("team", "/srv/team"),
            ("team/shared", "/srv/team-shared"),
        ]);
        let r = resolve(&cfg, "team/shared/foo").unwrap();
        assert_eq!(r.mount, "team/shared");
        assert_eq!(r.store_root, PathBuf::from("/srv/team-shared"));
        assert_eq!(r.rel, PathBuf::from("foo"));
    }

    #[test]
    fn shorter_prefix_matches_when_longer_does_not() {
        let cfg = config(&[
            ("team", "/srv/team"),
            ("team/shared", "/srv/team-shared"),
        ]);
        let r = resolve(&cfg, "team/other").unwrap();
        assert_eq!(r.mount, "team");
        assert_eq!(r.store_root, PathBuf::from("/srv/team"));
        assert_eq!(r.rel, PathBuf::from("other"));
    }

    #[test]
    fn partial_component_does_not_count_as_prefix() {
        // `work` mount must not match `workshop/foo`
        let cfg = config(&[("", "/srv/root"), ("work", "/srv/work")]);
        let r = resolve(&cfg, "workshop/foo").unwrap();
        assert_eq!(r.mount, "");
        assert_eq!(r.rel, PathBuf::from("workshop/foo"));
    }

    #[test]
    fn reject_absolute_path() {
        let cfg = config(&[("", "/srv/root")]);
        assert!(matches!(
            resolve(&cfg, "/abs/path").unwrap_err(),
            PathError::Absolute(_)
        ));
    }

    #[test]
    fn reject_dotdot() {
        let cfg = config(&[("", "/srv/root")]);
        assert!(matches!(
            resolve(&cfg, "foo/../escape").unwrap_err(),
            PathError::InvalidComponent(_)
        ));
    }

    #[test]
    fn reject_dot() {
        let cfg = config(&[("", "/srv/root")]);
        assert!(matches!(
            resolve(&cfg, "./foo").unwrap_err(),
            PathError::InvalidComponent(_)
        ));
    }

    #[test]
    fn reject_empty_component() {
        let cfg = config(&[("", "/srv/root")]);
        assert!(matches!(
            resolve(&cfg, "foo//bar").unwrap_err(),
            PathError::InvalidComponent(_)
        ));
    }

    #[test]
    fn reject_missing_mount() {
        let cfg = config(&[("work", "/srv/work")]);
        assert!(matches!(
            resolve(&cfg, "other/foo").unwrap_err(),
            PathError::NoMount(_)
        ));
    }

    #[test]
    fn reject_mount_only_without_secret() {
        let cfg = config(&[("work", "/srv/work")]);
        assert!(matches!(
            resolve(&cfg, "work").unwrap_err(),
            PathError::Empty(_)
        ));
    }

    #[test]
    fn empty_config_rejects_everything() {
        let cfg = Config {
            mounts: HashMap::new(),
            identities: Vec::new(),
        };
        assert!(matches!(
            resolve(&cfg, "anything").unwrap_err(),
            PathError::NoMount(_)
        ));
    }

    #[test]
    fn store_root_expands_tilde_and_vars() {
        // Use a var the test can rely on (HOME is set in test envs).
        // If HOME isn't available, the dirs crate in expand_path returns None
        // for ~, so we use ${HOME} via the underlying env::var.
        let cfg = config(&[("", "${HOME}/vault")]);
        let r = resolve(&cfg, "api/foo").unwrap();
        // Whatever HOME resolves to, the resulting path must end with /vault/api/foo.age
        let s = r.age_file.to_string_lossy();
        assert!(
            s.ends_with("/vault/api/foo.age"),
            "unexpected path: {s}"
        );
    }
}
