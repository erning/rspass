//! Verify that `rspass show` prefers the agent for decryption and falls back
//! cleanly when the agent is absent.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use age::secrecy::ExposeSecret;
use tempfile::tempdir;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rspass"))
}

struct Env {
    _dir: tempfile::TempDir,
    xdg_config_home: PathBuf,
    vault: PathBuf,
    socket: PathBuf,
    identity_path: PathBuf,
}

fn setup() -> (Env, age::x25519::Identity) {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let xdg_config_home = root.join("config");
    let config_dir = xdg_config_home.join("rspass");
    let vault = root.join("vault");
    let socket = root.join("agent.sock");
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
        Env {
            _dir: dir,
            xdg_config_home,
            vault,
            socket,
            identity_path,
        },
        identity,
    )
}

fn encrypt_into(
    vault: &std::path::Path,
    identity: &age::x25519::Identity,
    rel: &str,
    plaintext: &[u8],
) {
    let pubkey = identity.to_public();
    let r: &dyn age::Recipient = &pubkey;
    let encryptor = age::Encryptor::with_recipients(std::iter::once(r)).unwrap();
    let mut ct = Vec::new();
    let mut w = encryptor.wrap_output(&mut ct).unwrap();
    w.write_all(plaintext).unwrap();
    w.finish().unwrap();
    let target = vault.join(format!("{rel}.age"));
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&target, ct).unwrap();
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

struct Daemon(Child);
impl Daemon {
    fn start(env: &Env) -> Self {
        let mut child = Command::new(bin())
            .arg("__agent-daemon")
            .env("RSPASS_AGENT_SOCK", &env.socket)
            .env_remove("XDG_RUNTIME_DIR")
            .env_remove("TMPDIR")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn daemon");
        // Wait for socket.
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if env.socket.exists() {
                return Daemon(child);
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let _ = child.kill();
        let _ = child.wait();
        panic!("daemon socket never appeared");
    }
}
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn show_uses_agent_when_available() {
    let (env, identity) = setup();
    let plaintext = b"agent-served-secret\n";
    encrypt_into(&env.vault, &identity, "api/test", plaintext);

    let _daemon = Daemon::start(&env);

    // Pre-load the identity into the agent.
    let add = run(&env, &["agent", "add", env.identity_path.to_str().unwrap()]);
    assert!(
        add.status.success(),
        "agent add failed: {}",
        String::from_utf8_lossy(&add.stderr)
    );

    // Now `show` should succeed via the agent. We can't easily observe *that*
    // the agent path was taken without instrumentation, but at minimum it
    // must still produce the right plaintext.
    let show = run(&env, &["show", "api/test"]);
    assert!(
        show.status.success(),
        "show failed: {}",
        String::from_utf8_lossy(&show.stderr)
    );
    assert_eq!(show.stdout, plaintext);
}

#[test]
fn show_falls_back_when_agent_has_no_matching_identity() {
    let (env, identity) = setup();
    let plaintext = b"fallback-works\n";
    encrypt_into(&env.vault, &identity, "api/fallback", plaintext);

    let _daemon = Daemon::start(&env);
    // Do NOT add any identity to the agent. The agent will return
    // no_matching_identity, and show must fall through to local identities
    // from config and still succeed.
    let show = run(&env, &["show", "api/fallback"]);
    assert!(
        show.status.success(),
        "show failed: stderr={}",
        String::from_utf8_lossy(&show.stderr)
    );
    assert_eq!(show.stdout, plaintext);
}

#[test]
fn show_still_works_without_agent() {
    let (env, identity) = setup();
    let plaintext = b"no-agent-needed\n";
    encrypt_into(&env.vault, &identity, "api/direct", plaintext);

    // No daemon spawned → connect_existing returns None → direct local path.
    let show = run(&env, &["show", "api/direct"]);
    assert!(show.status.success());
    assert_eq!(show.stdout, plaintext);
}
