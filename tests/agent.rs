//! End-to-end test for the agent daemon. Spawns the binary under a scratch
//! socket path, talks to it via the JSON-line protocol, then stops it.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use age::secrecy::ExposeSecret;
use base64::Engine;
use tempfile::tempdir;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rspass"))
}

struct Daemon {
    child: Child,
    socket: PathBuf,
    _dir: tempfile::TempDir,
}

impl Daemon {
    fn start() -> Self {
        let dir = tempdir().unwrap();
        let socket = dir.path().join("agent.sock");
        let child = Command::new(bin())
            .arg("__agent-daemon")
            .env("RSPASS_AGENT_SOCK", &socket)
            .env_remove("XDG_RUNTIME_DIR")
            .env_remove("TMPDIR")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn daemon");
        wait_for_socket(&socket, Duration::from_secs(5));
        Daemon {
            child,
            socket,
            _dir: dir,
        }
    }

    fn rpc(&self, json: serde_json::Value) -> serde_json::Value {
        let mut stream = UnixStream::connect(&self.socket).expect("connect socket");
        let line = serde_json::to_string(&json).unwrap() + "\n";
        stream.write_all(line.as_bytes()).unwrap();
        let mut reader = BufReader::new(stream);
        let mut resp = String::new();
        reader.read_line(&mut resp).unwrap();
        serde_json::from_str(&resp).expect("valid JSON response")
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        // Best-effort: send stop, then kill if still alive.
        let _ = self.rpc(serde_json::json!({"op": "stop"}));
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn wait_for_socket(path: &std::path::Path, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() && UnixStream::connect(path).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("agent socket did not appear at {path:?}");
}

#[test]
fn status_on_fresh_daemon_is_ok_with_zero_identities() {
    let d = Daemon::start();
    let r = d.rpc(serde_json::json!({"op": "status"}));
    assert_eq!(r["ok"], true);
    assert_eq!(r["data"]["identity_count"], 0);
    assert_eq!(r["data"]["key_count"], 0);
}

#[test]
fn add_list_remove_roundtrip() {
    let d = Daemon::start();

    let id = age::x25519::Identity::generate();
    let pubkey = id.to_public().to_string();
    let identity_text = format!("{}\n", id.to_string().expose_secret());

    let add = d.rpc(serde_json::json!({
        "op": "add",
        "path": "/tmp/test-id.txt",
        "identity_data": identity_text,
    }));
    assert_eq!(add["ok"], true, "add response: {add}");

    let list = d.rpc(serde_json::json!({"op": "list"}));
    assert_eq!(list["ok"], true);
    let identities = list["data"]["identities"].as_array().unwrap();
    assert_eq!(identities.len(), 1);
    assert_eq!(identities[0]["path"], "/tmp/test-id.txt");
    let pubkeys = identities[0]["pubkeys"].as_array().unwrap();
    assert_eq!(pubkeys.len(), 1);
    assert_eq!(pubkeys[0], pubkey);

    let rm = d.rpc(serde_json::json!({
        "op": "remove",
        "path": "/tmp/test-id.txt",
    }));
    assert_eq!(rm["ok"], true);

    let list2 = d.rpc(serde_json::json!({"op": "list"}));
    assert_eq!(list2["data"]["identities"].as_array().unwrap().len(), 0);

    let rm_again = d.rpc(serde_json::json!({
        "op": "remove",
        "path": "/tmp/test-id.txt",
    }));
    assert_eq!(rm_again["ok"], false);
    assert_eq!(rm_again["code"], "not_found");
}

#[test]
fn decrypt_with_loaded_identity() {
    let d = Daemon::start();

    let id = age::x25519::Identity::generate();
    let pubkey = id.to_public();
    let identity_text = format!("{}\n", id.to_string().expose_secret());

    // Encrypt a small secret to `id`.
    let plaintext = b"agent-decrypted";
    let r: &dyn age::Recipient = &pubkey;
    let encryptor = age::Encryptor::with_recipients(std::iter::once(r)).unwrap();
    let mut ct = Vec::new();
    let mut w = encryptor.wrap_output(&mut ct).unwrap();
    w.write_all(plaintext).unwrap();
    w.finish().unwrap();
    let ct_b64 = base64::engine::general_purpose::STANDARD.encode(&ct);

    // Try decrypt before adding → no_matching_identity.
    let no = d.rpc(serde_json::json!({
        "op": "decrypt",
        "ciphertext": ct_b64,
    }));
    assert_eq!(no["ok"], false);
    assert_eq!(no["code"], "no_matching_identity");

    // Add the identity, then decrypt succeeds.
    d.rpc(serde_json::json!({
        "op": "add",
        "path": "/scratch/id.txt",
        "identity_data": identity_text,
    }));
    let ok = d.rpc(serde_json::json!({
        "op": "decrypt",
        "ciphertext": ct_b64,
        "context": "scratch/secret",
    }));
    assert_eq!(ok["ok"], true);
    let got_b64 = ok["data"]["plaintext"].as_str().unwrap();
    let got = base64::engine::general_purpose::STANDARD
        .decode(got_b64)
        .unwrap();
    assert_eq!(got, plaintext);
}

#[test]
fn decrypt_rejects_garbage_base64() {
    let d = Daemon::start();
    let r = d.rpc(serde_json::json!({
        "op": "decrypt",
        "ciphertext": "not-valid-base64-!!!",
    }));
    assert_eq!(r["ok"], false);
    assert_eq!(r["code"], "bad_base64");
}

#[test]
fn unknown_op_closes_cleanly() {
    let d = Daemon::start();
    // Send a malformed JSON (bad op); the daemon's read_request fails and
    // the connection is dropped without a response, but the daemon stays up.
    let mut stream = UnixStream::connect(&d.socket).unwrap();
    stream.write_all(b"{\"op\":\"nope\"}\n").unwrap();
    drop(stream);
    // Subsequent requests still work.
    let r = d.rpc(serde_json::json!({"op": "status"}));
    assert_eq!(r["ok"], true);
}
