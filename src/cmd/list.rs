//! `rspass list [PREFIX]` — gopass-style tree listing of the store.
//!
//! Output mimics `gopass list`:
//! - Top label `rspass`, mounts become first-level branches annotated with
//!   their resolved absolute path: `├── <mount> (<abs path>)`. Root mount
//!   (`""` key) is rendered as `. (<abs path>)` so the label column stays
//!   visually consistent with named mounts.
//! - 4-char indent per depth: `│   ` for continuing columns, `    ` for the
//!   last branch's continuation.
//! - `├── ` / `└── ` for branches.
//! - Directories end with `/`; secret files have their `.age` suffix
//!   stripped.
//! - Hidden files (leading `.`) are omitted, so `.age-recipients`, `.git/`,
//!   and similar book-keeping never appears in the output.
//!
//! With `PREFIX`, the prefix is resolved to `(mount, subpath)` using the
//! same longest-component-prefix rule as `path::resolve`, and only that
//! subtree is rendered with `PREFIX/ (<abs path>)` as the root label.
//!
//! ## Colour
//!
//! When stdout is a tty and `NO_COLOR` is unset, mount labels render in
//! bold green; the top `rspass` header and every directory node (including
//! the PREFIX root label) render in bold blue, matching gopass and the
//! classic `ls --color` convention for directories. Secret names render in
//! the terminal's default colour. Tree connectors stay default. Piped /
//! redirected output is never coloured, so integration tests that scrape
//! `.output()` see plain ASCII.

use std::fs;
use std::path::{Path, PathBuf};

use crate::config::{self, Config};
use crate::error::RspassError;
use crate::path::PathError;

pub fn run(config: &Config, prefix: Option<&str>) -> Result<(), RspassError> {
    let style = Style::detect();
    match prefix {
        None | Some("") => {
            let branches = build_all_mount_branches(config)?;
            render_top("rspass", &branches, &style);
        }
        Some(p) => {
            let branch = build_prefix_branch(config, p)?;
            render_single(&branch, &style);
        }
    }
    Ok(())
}

/// ANSI styling for tty output.
///
/// Auto-detects: enabled when stdout is a tty and `NO_COLOR` is unset or
/// empty (per https://no-color.org/). `Style::plain()` forces off for tests.
struct Style {
    enabled: bool,
}

impl Style {
    fn detect() -> Self {
        use std::io::IsTerminal;
        let no_color = std::env::var_os("NO_COLOR")
            .is_some_and(|v| !v.is_empty());
        Self {
            enabled: !no_color && std::io::stdout().is_terminal(),
        }
    }

    #[cfg(test)]
    fn plain() -> Self {
        Self { enabled: false }
    }

    #[cfg(test)]
    fn forced() -> Self {
        Self { enabled: true }
    }

    /// Mount / store label: bold green.
    fn store(&self, s: &str) -> String {
        self.paint("\x1b[1;32m", s)
    }

    /// Directory name or PREFIX root label: bold blue, matching gopass and
    /// the classic `ls --color` convention for directories.
    fn dir(&self, s: &str) -> String {
        self.paint("\x1b[1;34m", s)
    }

    fn paint(&self, code: &str, s: &str) -> String {
        if self.enabled {
            format!("{code}{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
}

/// Top-level row under the `rspass` header: one per mount (no-arg case) or
/// one for the resolved prefix (with-arg case).
struct Branch {
    label: String,
    children: Vec<Node>,
}

fn build_all_mount_branches(config: &Config) -> Result<Vec<Branch>, RspassError> {
    if config.mounts.is_empty() {
        eprintln!("rspass: no mounts configured");
        return Ok(Vec::new());
    }
    let mut mounts: Vec<(&String, &String)> = config.mounts.iter().collect();
    // Root mount ("") sorts before any named mount by string order.
    mounts.sort_by(|a, b| a.0.cmp(b.0));

    let mut branches = Vec::with_capacity(mounts.len());
    for (name, path_str) in mounts {
        let mount_root = expand_mount_path(path_str)?;
        let label = if name.is_empty() {
            format!(". ({})", mount_root.display())
        } else {
            format!("{} ({})", name, mount_root.display())
        };
        let children = if mount_root.is_dir() {
            collect_children(&mount_root)?
        } else {
            Vec::new()
        };
        branches.push(Branch { label, children });
    }
    Ok(branches)
}

fn build_prefix_branch(config: &Config, prefix: &str) -> Result<Branch, RspassError> {
    let normalized = prefix.trim_end_matches('/');
    // Empty normalized means caller passed "/" or "///"; behave like no-arg.
    // We don't return early to list_all here because run() already handles
    // Some("") before we get called; non-empty prefix that trims to empty
    // (e.g. "/" alone) is rejected by path validation below.
    let (_mount, mount_path, rel) = resolve_dir_prefix(config, normalized)?;
    let start = if rel.as_os_str().is_empty() {
        mount_path
    } else {
        mount_path.join(&rel)
    };
    if !start.exists() {
        return Err(RspassError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("not a directory: {normalized}"),
        )));
    }
    if !start.is_dir() {
        return Err(RspassError::Io(std::io::Error::other(format!(
            "{normalized} is not a directory; use `rspass show` for a single secret"
        ))));
    }
    Ok(Branch {
        label: format!("{normalized}/ ({})", start.display()),
        children: collect_children(&start)?,
    })
}

fn render_top(top_label: &str, branches: &[Branch], style: &Style) {
    // The top `rspass` label is the root of the whole tree, semantically a
    // directory, so it wears the same bold-blue as directory nodes.
    println!("{}", style.dir(top_label));
    let last_idx = branches.len().saturating_sub(1);
    for (i, branch) in branches.iter().enumerate() {
        let is_last = i == last_idx;
        let connector = if is_last { "└── " } else { "├── " };
        let child_prefix = if is_last { "    " } else { "│   " };
        println!("{connector}{}", style.store(&branch.label));
        render_children(&branch.children, child_prefix, style);
    }
}

/// Render a single `Branch` as the root (no `rspass` wrapper). Used by the
/// PREFIX form of `list`, matching `gopass list <prefix>` which prints the
/// prefix itself as the tree root without the tool name above it.
fn render_single(branch: &Branch, style: &Style) {
    println!("{}", style.dir(&branch.label));
    render_children(&branch.children, "", style);
}

/// Same matching rule as `path::resolve`, but allows empty trailing `rel`
/// (a prefix that happens to name a whole mount) and does not require the
/// final component to be a file.
fn resolve_dir_prefix(
    config: &Config,
    input: &str,
) -> Result<(String, PathBuf, PathBuf), RspassError> {
    if input.starts_with('/') {
        return Err(PathError::Absolute(input.to_string()).into());
    }
    let components: Vec<&str> = input.split('/').collect();
    for c in &components {
        if c.is_empty() || *c == "." || *c == ".." {
            return Err(PathError::InvalidComponent(input.to_string()).into());
        }
    }

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
    let (mount_name, prefix_len) =
        best.ok_or_else(|| PathError::NoMount(input.to_string()))?;
    let store_root_str = config.mounts.get(mount_name).expect("mount key must exist");
    let store_root = expand_mount_path(store_root_str)?;
    let rel: PathBuf = components[prefix_len..].iter().collect();
    Ok((mount_name.to_string(), store_root, rel))
}

fn expand_mount_path(path_str: &str) -> Result<PathBuf, RspassError> {
    Ok(PathBuf::from(config::expand_path(path_str)?))
}

struct Node {
    name: String,
    is_dir: bool,
    children: Vec<Node>,
}

fn collect_children(dir: &Path) -> Result<Vec<Node>, RspassError> {
    let mut nodes: Vec<Node> = Vec::new();
    let entries = match fs::read_dir(dir) {
        Ok(it) => it,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(RspassError::Io(e)),
    };
    for entry in entries {
        let entry = entry.map_err(RspassError::Io)?;
        let fname = entry.file_name();
        let fname_str = fname.to_string_lossy();
        // Skip hidden files (.age-recipients, .git, ...).
        if fname_str.starts_with('.') {
            continue;
        }
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.is_dir() {
            let sub_children = collect_children(&entry.path())?;
            // Omit empty directories (nothing useful under them) — matches
            // gopass behaviour where a dir with no secrets doesn't clutter
            // the listing.
            if sub_children.is_empty() {
                continue;
            }
            nodes.push(Node {
                name: fname_str.into_owned(),
                is_dir: true,
                children: sub_children,
            });
        } else if meta.is_file()
            && let Some(stripped) = fname_str.strip_suffix(".age")
        {
            nodes.push(Node {
                name: stripped.to_string(),
                is_dir: false,
                children: Vec::new(),
            });
        }
    }
    // Directories before files? gopass groups directories first. Keep
    // alphabetical overall but dirs-first so common prefixes read naturally.
    nodes.sort_by(|a, b| match (a.is_dir, b.is_dir) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.name.cmp(&b.name),
    });
    Ok(nodes)
}

fn render_children(children: &[Node], prefix: &str, style: &Style) {
    let last_idx = children.len().saturating_sub(1);
    for (i, child) in children.iter().enumerate() {
        let is_last = i == last_idx;
        let connector = if is_last { "└── " } else { "├── " };
        let painted = if child.is_dir {
            style.dir(&format!("{}/", child.name))
        } else {
            child.name.clone()
        };
        println!("{prefix}{connector}{painted}");
        let child_prefix =
            format!("{prefix}{}", if is_last { "    " } else { "│   " });
        render_children(&child.children, &child_prefix, style);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn style_plain_passes_through() {
        let s = Style::plain();
        assert_eq!(s.dir("api/"), "api/");
        assert_eq!(s.store("work (/path)"), "work (/path)");
    }

    #[test]
    fn style_forced_wraps_in_ansi() {
        let s = Style::forced();
        assert_eq!(s.dir("api/"), "\x1b[1;34mapi/\x1b[0m");
        assert_eq!(s.store("work (/path)"), "\x1b[1;32mwork (/path)\x1b[0m");
    }
}
