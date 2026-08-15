//! Operator-facing spec for the SFTP backend plugin.
//!
//! One binding = one operation = one MCP tool (or resource). `op: list`
//! lists a directory, `op: get` reads a file, `op: put` writes a file — the
//! target path comes from the call arguments (with `..` rejected), joined
//! under the operator-configured `root`.

use serde::Deserialize;

use crate::surface::Surface;

/// The file operation a binding performs.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum SftpOp {
    /// List a directory's entries.
    #[default]
    List,
    /// Read a file's contents.
    Get,
    /// Write a file (content from the `content`/`text` argument).
    Put,
}

impl SftpOp {
    pub fn as_str(self) -> &'static str {
        match self {
            SftpOp::List => "list",
            SftpOp::Get => "get",
            SftpOp::Put => "put",
        }
    }
}

/// Operator-facing spec the gateway serializes when calling
/// `register_profile`. Mirrors `SftpBackendConfig` in the gateway crate.
// NOTE: intentionally NOT #[serde(deny_unknown_fields)] — the gateway injects
// the reserved `__mcpg_secret_refs` hint key into this spec at register_profile
// (secret-rotation scoping); denying unknown fields would reject it. The
// operator-facing schema is closed on the gateway-side *BackendConfig instead.
#[derive(Debug, Clone, Deserialize)]
pub struct SftpBackendSpec {
    /// The operation (default `list`).
    #[serde(default)]
    pub op: SftpOp,

    /// SSH host. Operator-configured.
    pub host: String,

    /// SSH port (default 22).
    #[serde(default = "default_port")]
    pub port: u16,

    /// SSH login user.
    pub username: String,

    /// SSH password — a literal, or `${env.X}` / `vault://…` resolved at
    /// config load. (Public-key auth is a follow-on; v1 is password auth.)
    pub password: String,

    /// Base directory the caller-supplied path is joined under (default `""`
    /// = the login's default directory). The caller path may not contain
    /// `..` segments.
    #[serde(default)]
    pub root: String,

    /// Expected server host-key fingerprint (`SHA256:…`). When set, the
    /// connection is rejected unless the server key matches.
    #[serde(default)]
    pub host_key_sha256: Option<String>,

    /// Accept any (unverified) server host key. Dev/test only — leave `false`
    /// in production and set `host_key_sha256` instead. With neither set the
    /// connection fails closed.
    #[serde(default)]
    pub accept_unknown_host_key: bool,

    /// Cap on bytes read (`get`) / written (`put`) (default 10 MiB).
    #[serde(default = "default_max_bytes")]
    pub max_bytes: usize,

    /// Per-call timeout (ms) for connect + auth + the operation (default
    /// 15 s).
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,

    /// Which MCP surface the binding serves (default `tool` — list/get/put
    /// tools, unchanged). `resource` exposes the `root`/`path` directory as
    /// MCP resources (`resources/list` + `resources/read`).
    #[serde(default)]
    pub surface: Surface,

    /// Resource URI template for `surface: resource`; `{path}` is replaced by
    /// each file's path under `root` (default `sftp://{path}`). A static value
    /// may also pin a single resource. Only valid with `surface: resource`.
    #[serde(default)]
    pub uri: Option<String>,
}

fn default_port() -> u16 {
    22
}
fn default_max_bytes() -> usize {
    10 * 1024 * 1024
}
fn default_timeout_ms() -> u64 {
    15_000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_defaults_to_list() {
        assert_eq!(SftpOp::default(), SftpOp::List);
    }

    #[test]
    fn spec_applies_defaults() {
        let spec: SftpBackendSpec = serde_json::from_value(serde_json::json!({
            "host": "sftp.example.com",
            "username": "svc",
            "password": "${env.SFTP_PW}",
        }))
        .unwrap();
        assert_eq!(spec.op, SftpOp::List);
        assert_eq!(spec.port, 22);
        assert_eq!(spec.root, "");
        assert!(!spec.accept_unknown_host_key);
        assert_eq!(spec.max_bytes, 10 * 1024 * 1024);
        assert_eq!(spec.timeout_ms, 15_000);
        assert_eq!(spec.surface, Surface::Tool);
        assert!(spec.uri.is_none());
    }

    #[test]
    fn parses_resource_surface() {
        let spec: SftpBackendSpec = serde_json::from_value(serde_json::json!({
            "op": "get", "host": "h", "username": "u", "password": "p",
            "surface": "resource", "uri": "sftp://inbox/{path}",
        }))
        .unwrap();
        assert_eq!(spec.surface, Surface::Resource);
        assert_eq!(spec.uri.as_deref(), Some("sftp://inbox/{path}"));
    }

    #[test]
    fn parses_get_and_put() {
        let get: SftpBackendSpec = serde_json::from_value(serde_json::json!({
            "op": "get", "host": "h", "username": "u", "password": "p",
        }))
        .unwrap();
        assert_eq!(get.op, SftpOp::Get);
        let put: SftpBackendSpec = serde_json::from_value(serde_json::json!({
            "op": "put", "host": "h", "username": "u", "password": "p", "root": "/upload",
        }))
        .unwrap();
        assert_eq!(put.op, SftpOp::Put);
        assert_eq!(put.root, "/upload");
    }
}
