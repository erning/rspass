//! End-to-end test for the user-facing `rspass agent ...` subcommands.
//!
//! Exercises the start / ls / add / rm / stop flow via the binary, using a
//! scratch socket path so we don't interfere with a real user agent.

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use age::secrecy::ExposeSecret;
use tempfile::tempdir;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rspass"))
}

struct Env {
    _dir: tempfile::TempDir,
    xdg_config_home: PathBuf,
    socket: PathBuf,
}

fn setup() -> (Env, PathBuf, age::x25519::Identity) {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let xdg_config_home = root.join("config");
    let config_dir = xdg_config_home.join("rspass");
    let socket = root.join("agent.sock");
    std::fs::create_dir_all(&config_dir).unwrap();

    let identity = age::x25519::Identity::generate();
    let id_path = config_dir.join("id.txt");
    std::fs::write(
        &id_path,
        format!(
            "# public key: {}\n{}\n",
            identity.to_public(),
            identity.to_string().expose_secret()
        ),
    )
    .unwrap();

    std::fs::write(
        config_dir.join("config.yaml"),
        format!(
            "mounts:\n  \"\": {}\nidentities:\n  - {}\n",
            root.join("vault").display(),
            id_path.display()
        ),
    )
    .unwrap();

    (
        Env {
            _dir: dir,
            xdg_config_home,
            socket,
        },
        id_path,
        identity,
    )
}

fn run(env: &Env, args: &[&str]) -> std::process::Output {
    Command::new(bin())
        .args(args)
        .env("XDG_CONFIG_HOME", &env.xdg_config_home)
        .env("RSPASS_AGENT_SOCK", &env.socket)
        .env_remove("XDG_RUNTIME_DIR")
        .env_remove("TMPDIR")
        .env_remove("HOME")
        .output()
        .expect("spawn rspass")
}

fn wait_for_stop(socket: &std::path::Path, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match UnixStream::connect(socket) {
            Err(_) => return,
            Ok(mut s) => {
                // Old daemon might still be in the process of closing —
                // push it along with a status probe.
                let _ = s.write_all(b"{\"op\":\"status\"}\n");
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    }
}

#[test]
fn start_ls_add_rm_stop_flow() {
    let (env, id_path, identity) = setup();

    // Initially not running.
    let st = run(&env, &["agent", "status"]);
    assert!(st.status.success());
    assert!(String::from_utf8_lossy(&st.stdout).contains("not running"));

    // Start.
    let out = run(&env, &["agent", "start"]);
    assert!(
        out.status.success(),
        "start failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Status now shows running.
    let st = run(&env, &["agent", "status"]);
    let stdout = String::from_utf8_lossy(&st.stdout);
    assert!(stdout.contains("running"), "status stdout: {stdout}");

    // ls shows empty.
    let ls = run(&env, &["agent", "ls"]);
    assert!(
        String::from_utf8_lossy(&ls.stdout).contains("(no identities loaded)"),
        "ls stdout: {}",
        String::from_utf8_lossy(&ls.stdout)
    );

    // Add the plaintext identity explicitly by path.
    let add = run(&env, &["agent", "add", id_path.to_str().unwrap()]);
    assert!(
        add.status.success(),
        "add failed: stderr={}",
        String::from_utf8_lossy(&add.stderr)
    );

    // ls now shows it.
    let ls = run(&env, &["agent", "ls"]);
    let stdout = String::from_utf8_lossy(&ls.stdout);
    let expected_pubkey = identity.to_public().to_string();
    assert!(
        stdout.contains(&expected_pubkey),
        "ls missing expected pubkey {expected_pubkey}: {stdout}"
    );

    // Remove.
    let rm = run(&env, &["agent", "rm", id_path.to_str().unwrap()]);
    assert!(rm.status.success());

    let ls = run(&env, &["agent", "ls"]);
    assert!(
        String::from_utf8_lossy(&ls.stdout).contains("(no identities loaded)"),
        "ls should be empty after rm"
    );

    // Stop and wait for socket to go away.
    let stop = run(&env, &["agent", "stop"]);
    assert!(stop.status.success());
    wait_for_stop(&env.socket, Duration::from_secs(3));

    let st = run(&env, &["agent", "status"]);
    assert!(String::from_utf8_lossy(&st.stdout).contains("not running"));
}

#[test]
fn add_no_arg_loads_all_plaintext_identities() {
    let (env, id_path, identity) = setup();

    // Add from config with no PATH argument.
    let out = run(&env, &["agent", "add"]);
    assert!(
        out.status.success(),
        "stderr={}\nstdout={}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout),
    );

    let ls = run(&env, &["agent", "ls"]);
    let stdout = String::from_utf8_lossy(&ls.stdout);
    assert!(stdout.contains(&identity.to_public().to_string()));
    assert!(stdout.contains(id_path.to_str().unwrap()));

    let _ = run(&env, &["agent", "stop"]);
    wait_for_stop(&env.socket, Duration::from_secs(3));
}

#[test]
fn start_is_idempotent() {
    let (env, _id_path, _id) = setup();

    let out1 = run(&env, &["agent", "start"]);
    assert!(out1.status.success());
    let out2 = run(&env, &["agent", "start"]);
    assert!(out2.status.success());

    // Only one daemon should be running; status should succeed.
    let st = run(&env, &["agent", "status"]);
    assert!(String::from_utf8_lossy(&st.stdout).contains("running"));

    let _ = run(&env, &["agent", "stop"]);
    wait_for_stop(&env.socket, Duration::from_secs(3));
}
