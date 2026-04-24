use std::process::Command;

fn main() {
    let sha = git(&["rev-parse", "--short=7", "HEAD"]).unwrap_or_else(|| "unknown".to_string());
    // `diff-index` only reports changes to tracked files, so untracked
    // scratch files (e.g. .claude/, editor backups) don't taint the build.
    let dirty = match git_status(&["diff-index", "--quiet", "HEAD", "--"]) {
        Some(false) => "-dirty",
        _ => "",
    };
    println!("cargo:rustc-env=GIT_SHA={sha}{dirty}");

    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");
    if let Some(head) = git(&["symbolic-ref", "-q", "HEAD"]) {
        println!("cargo:rerun-if-changed=.git/{head}");
    }
}

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    Some(s)
}

/// Like `git`, but for commands whose exit status is the result (e.g.
/// `diff-index --quiet`: 0 = clean, 1 = dirty). Returns `Some(true)` for
/// success, `Some(false)` for non-zero exit, `None` if git isn't available.
fn git_status(args: &[&str]) -> Option<bool> {
    let status = Command::new("git").args(args).status().ok()?;
    Some(status.success())
}
