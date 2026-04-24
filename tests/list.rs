//! End-to-end test for `rspass list [PREFIX]` gopass-style tree output.

use std::path::PathBuf;
use std::process::Command;

use age::secrecy::ExposeSecret;
use tempfile::tempdir;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rspass"))
}

#[allow(dead_code)] // vault/work kept alive via _dir, accessed only during setup
struct Env {
    _dir: tempfile::TempDir,
    xdg_config_home: PathBuf,
    vault: PathBuf,
    work: PathBuf,
}

fn setup_multi_mount() -> Env {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let xdg_config_home = root.join("config");
    let config_dir = xdg_config_home.join("rspass");
    let vault = root.join("vault");
    let work = root.join("work-secrets");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::create_dir_all(&vault).unwrap();
    std::fs::create_dir_all(&work).unwrap();

    let identity = age::x25519::Identity::generate();
    let pubkey = identity.to_public();
    let id_path = config_dir.join("id.txt");
    std::fs::write(
        &id_path,
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
            "mounts:\n  \"\": {}\n  work: {}\nidentities:\n  - {}\n",
            vault.display(),
            work.display(),
            id_path.display()
        ),
    )
    .unwrap();

    // Put an .age-recipients so edits work (not needed by list itself but
    // keeps the fixture realistic).
    std::fs::write(vault.join(".age-recipients"), format!("{pubkey}\n")).unwrap();
    std::fs::write(work.join(".age-recipients"), format!("{pubkey}\n")).unwrap();

    // Seed some encrypted files directly (list doesn't care about content).
    write_dummy_age(&vault.join("notes.age"));
    std::fs::create_dir_all(vault.join("api")).unwrap();
    write_dummy_age(&vault.join("api/openai.age"));
    write_dummy_age(&vault.join("api/anthropic.age"));
    std::fs::create_dir_all(vault.join("db")).unwrap();
    write_dummy_age(&vault.join("db/prod.age"));

    write_dummy_age(&work.join("token.age"));

    // Also drop some noise that list must ignore.
    std::fs::create_dir_all(vault.join(".git")).unwrap();
    std::fs::write(vault.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    std::fs::create_dir_all(vault.join("empty_dir")).unwrap();

    Env {
        _dir: dir,
        xdg_config_home,
        vault,
        work,
    }
}

fn write_dummy_age(path: &std::path::Path) {
    // The list command only inspects filenames, so any content works.
    std::fs::write(path, b"dummy").unwrap();
}

fn run(env: &Env, args: &[&str]) -> std::process::Output {
    Command::new(bin())
        .args(args)
        .env("XDG_CONFIG_HOME", &env.xdg_config_home)
        .env_remove("HOME")
        .env_remove("XDG_RUNTIME_DIR")
        .output()
        .expect("spawn rspass")
}

fn stdout_of(o: &std::process::Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[test]
fn list_without_arg_prints_all_mounts_alphabetically() {
    let env = setup_multi_mount();
    let out = run(&env, &["list"]);
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = stdout_of(&out);

    // Top label is "rspass".
    assert!(
        stdout.starts_with("rspass\n"),
        "expected top label `rspass`, got:\n{stdout}"
    );

    // Root mount rendered as `├── . (<path>)` (not last since `work` follows).
    let root_line = format!("├── . ({})", env.vault.display());
    assert!(
        stdout.contains(&root_line),
        "missing `{root_line}` in:\n{stdout}"
    );

    // work mount rendered as `└── work (<path>)` (last).
    let work_line = format!("└── work ({})", env.work.display());
    assert!(
        stdout.contains(&work_line),
        "missing `{work_line}` in:\n{stdout}"
    );

    // Ordering: root mount appears before work mount.
    let root_pos = stdout.find(&root_line).unwrap();
    let work_pos = stdout.find(&work_line).unwrap();
    assert!(root_pos < work_pos, "root mount should precede work");

    // Structure under root mount. Root is not-last so its children use the
    // `│   ` continuation prefix.
    for expected in [
        "│   ├── api/",
        "│   │   ├── anthropic",
        "│   │   └── openai",
        "│   ├── db/",
        "│   │   └── prod",
        "│   └── notes",
    ] {
        assert!(
            stdout.contains(expected),
            "missing `{expected}` in:\n{stdout}"
        );
    }

    // Structure under work mount (last, so `    ` continuation).
    assert!(
        stdout.contains("    └── token"),
        "work subtree missing: \n{stdout}"
    );

    // Nothing hidden: no .age suffix on leaves, no .git, no empty_dir.
    assert!(!stdout.contains("notes.age"));
    assert!(!stdout.contains(".git"));
    assert!(!stdout.contains("empty_dir"));
}

#[test]
fn list_with_prefix_narrows_to_subtree() {
    let env = setup_multi_mount();
    let out = run(&env, &["list", "api"]);
    assert!(out.status.success());
    let stdout = stdout_of(&out);

    // PREFIX form: no `rspass` wrapper, prefix is itself the root label.
    let header = format!("api/ ({})\n", env.vault.join("api").display());
    assert!(stdout.starts_with(&header), "got:\n{stdout}");
    assert!(stdout.contains("├── anthropic"));
    assert!(stdout.contains("└── openai"));
    // Sibling directories from root mount must not appear.
    assert!(!stdout.contains("db/"));
    assert!(!stdout.contains("notes"));
    // Must not carry the top wrapper.
    assert!(
        !stdout.contains("rspass"),
        "PREFIX form must not include `rspass` top"
    );
}

#[test]
fn list_with_mount_prefix_lists_whole_mount() {
    let env = setup_multi_mount();
    let out = run(&env, &["list", "work"]);
    assert!(out.status.success());
    let stdout = stdout_of(&out);
    let header = format!("work/ ({})\n", env.work.display());
    assert!(stdout.starts_with(&header), "got:\n{stdout}");
    assert!(stdout.contains("└── token"));
    assert!(!stdout.contains("rspass"));
}

#[test]
fn ls_alias_works() {
    let env = setup_multi_mount();
    let out_list = run(&env, &["list"]);
    let out_ls = run(&env, &["ls"]);
    assert!(out_list.status.success() && out_ls.status.success());
    assert_eq!(stdout_of(&out_list), stdout_of(&out_ls));
}

#[test]
fn list_with_trailing_slash_in_prefix_is_allowed() {
    let env = setup_multi_mount();
    let a = run(&env, &["list", "api"]);
    let b = run(&env, &["list", "api/"]);
    assert!(a.status.success() && b.status.success());
    assert_eq!(stdout_of(&a), stdout_of(&b));
}

#[test]
fn list_missing_prefix_errors() {
    let env = setup_multi_mount();
    let out = run(&env, &["list", "api/missing/subpath"]);
    // Secret-like prefix that doesn't exist as a directory → exit 1.
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn list_on_empty_store() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let xdg = root.join("config");
    let cfg_dir = xdg.join("rspass");
    let vault = root.join("vault");
    std::fs::create_dir_all(&cfg_dir).unwrap();
    std::fs::create_dir_all(&vault).unwrap();
    std::fs::write(
        cfg_dir.join("config.yaml"),
        format!("mounts:\n  \"\": {}\n", vault.display()),
    )
    .unwrap();

    let out = Command::new(bin())
        .args(["list"])
        .env("XDG_CONFIG_HOME", &xdg)
        .env_remove("HOME")
        .output()
        .unwrap();
    assert!(out.status.success());
    // Empty store still prints the `rspass` top and the single root mount line.
    let stdout = stdout_of(&out);
    assert!(stdout.starts_with("rspass\n"), "got:\n{stdout}");
    assert!(
        stdout.contains(&format!("└── . ({})", vault.display())),
        "got:\n{stdout}"
    );
}
