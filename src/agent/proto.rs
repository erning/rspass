//! JSON-line wire protocol for the rspass agent daemon.
//!
//! One request per line, one response per line, UTF-8. Fields follow
//! docs/DESIGN.md §8.
//!
//! ```jsonc
//! {"op": "add", "path": "/abs/path", "identity_data": "AGE-SECRET-KEY-1..."}
//! {"op": "remove", "path": "/abs/path"}
//! {"op": "list"}
//! {"op": "decrypt", "ciphertext": "<base64>", "context": "work/db/prod"}
//! {"op": "status"}
//! {"op": "stop"}
//! ```
//!
//! All responses share the envelope `{ok, data?, error?, code?}`.

use std::io::{BufRead, Write};

use serde::{Deserialize, Serialize};

/// Upper bound on the base64-encoded ciphertext accepted by `decrypt`.
/// docs/DESIGN.md §8: "daemon 也对 ciphertext 设大小上限（默认 16 MiB）".
/// Applied to the *decoded* byte length.
pub const MAX_CIPHERTEXT_BYTES: usize = 16 * 1024 * 1024;

/// Maximum length of a single JSON request line read from the wire.
/// Slightly larger than MAX_CIPHERTEXT_BYTES after base64 overhead, giving
/// headroom for JSON framing.
pub const MAX_REQUEST_LINE_BYTES: usize = MAX_CIPHERTEXT_BYTES * 2 + 4096;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Add {
        path: String,
        identity_data: String,
    },
    Remove {
        path: String,
    },
    List,
    Decrypt {
        /// Base64-encoded age ciphertext.
        ciphertext: String,
        /// Optional secret path label for the agent log. Never validated;
        /// the safety model does not depend on it (docs/DESIGN.md §8).
        #[serde(default)]
        context: Option<String>,
    },
    Status,
    Stop,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub code: Option<String>,
}

impl Response {
    pub fn ok() -> Self {
        Self {
            ok: true,
            data: None,
            error: None,
            code: None,
        }
    }

    pub fn ok_with(data: serde_json::Value) -> Self {
        Self {
            ok: true,
            data: Some(data),
            error: None,
            code: None,
        }
    }

    pub fn err(code: &str, message: impl Into<String>) -> Self {
        Self {
            ok: false,
            data: None,
            error: Some(message.into()),
            code: Some(code.into()),
        }
    }
}

/// Read a single newline-terminated JSON request. Returns `Ok(None)` when the
/// peer closes the connection without sending anything.
pub fn read_request(reader: &mut impl BufRead) -> std::io::Result<Option<Request>> {
    let mut line = String::new();
    let n = read_line_capped(reader, &mut line, MAX_REQUEST_LINE_BYTES)?;
    if n == 0 {
        return Ok(None);
    }
    serde_json::from_str(line.trim_end_matches(['\r', '\n']))
        .map(Some)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Like [`BufRead::read_line`] but bails with `InvalidData` if `limit` bytes
/// are consumed without hitting a newline, to protect the daemon from a
/// malicious client sending an unbounded stream.
fn read_line_capped(
    reader: &mut impl BufRead,
    buf: &mut String,
    limit: usize,
) -> std::io::Result<usize> {
    let mut total = 0;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(total);
        }
        let (consumed, done) = match available.iter().position(|&b| b == b'\n') {
            Some(idx) => (idx + 1, true),
            None => (available.len(), false),
        };
        if total + consumed > limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request line too long",
            ));
        }
        let chunk = &available[..consumed];
        match std::str::from_utf8(chunk) {
            Ok(s) => buf.push_str(s),
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "non-utf8 request",
                ));
            }
        }
        reader.consume(consumed);
        total += consumed;
        if done {
            return Ok(total);
        }
    }
}

pub fn write_response(writer: &mut impl Write, resp: &Response) -> std::io::Result<()> {
    let s = serde_json::to_string(resp)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    writer.write_all(s.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn request_roundtrip_add() {
        let json = r#"{"op":"add","path":"/a","identity_data":"AGE-SECRET-KEY-1"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert!(matches!(
            req,
            Request::Add { ref path, ref identity_data }
                if path == "/a" && identity_data == "AGE-SECRET-KEY-1"
        ));
    }

    #[test]
    fn request_roundtrip_decrypt_with_and_without_context() {
        let with = r#"{"op":"decrypt","ciphertext":"AAA","context":"work/x"}"#;
        let without = r#"{"op":"decrypt","ciphertext":"AAA"}"#;
        assert!(matches!(
            serde_json::from_str::<Request>(with).unwrap(),
            Request::Decrypt {
                context: Some(_),
                ..
            }
        ));
        assert!(matches!(
            serde_json::from_str::<Request>(without).unwrap(),
            Request::Decrypt { context: None, .. }
        ));
    }

    #[test]
    fn request_roundtrip_simple_ops() {
        assert!(matches!(
            serde_json::from_str::<Request>(r#"{"op":"list"}"#).unwrap(),
            Request::List
        ));
        assert!(matches!(
            serde_json::from_str::<Request>(r#"{"op":"status"}"#).unwrap(),
            Request::Status
        ));
        assert!(matches!(
            serde_json::from_str::<Request>(r#"{"op":"stop"}"#).unwrap(),
            Request::Stop
        ));
    }

    #[test]
    fn response_encoding_shapes() {
        let ok_empty = Response::ok();
        let s = serde_json::to_string(&ok_empty).unwrap();
        assert_eq!(s, r#"{"ok":true}"#);

        let ok_data = Response::ok_with(serde_json::json!({"identities": []}));
        let s = serde_json::to_string(&ok_data).unwrap();
        assert!(s.starts_with(r#"{"ok":true,"data":"#));

        let err = Response::err("no_matching_identity", "no matching");
        let s = serde_json::to_string(&err).unwrap();
        assert!(s.contains(r#""ok":false"#));
        assert!(s.contains(r#""code":"no_matching_identity""#));
    }

    #[test]
    fn read_line_refuses_oversized_payload() {
        let big = "a".repeat(MAX_REQUEST_LINE_BYTES + 100);
        let mut cursor = Cursor::new(big.as_bytes().to_vec());
        let err = read_request(&mut cursor).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn read_line_returns_none_on_empty_stream() {
        let mut cursor: Cursor<Vec<u8>> = Cursor::new(Vec::new());
        let got = read_request(&mut cursor).unwrap();
        assert!(got.is_none());
    }

    #[test]
    fn rejects_unknown_op() {
        let json = r#"{"op":"launch_missiles"}"#;
        let err = serde_json::from_str::<Request>(json).unwrap_err();
        assert!(
            err.to_string().contains("launch_missiles")
                || err.to_string().contains("unknown variant")
        );
    }
}
