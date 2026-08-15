//! SFTP machinery: SSH connect + auth + open the SFTP subsystem, the three
//! operations (list / get / put), and directory-entry → JSON projection.

use std::sync::Arc;

use russh::client::{AuthResult, Handle};
use russh_sftp::client::SftpSession;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Per-connection settings (clone-cheap).
#[derive(Clone)]
pub struct SftpConn {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub host_key_sha256: Option<String>,
    pub accept_unknown_host_key: bool,
}

/// russh client handler — host-key verification only.
struct ClientHandler {
    expected_fingerprint: Option<String>,
    accept_any: bool,
}

impl russh::client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        if self.accept_any {
            return Ok(true);
        }
        if let Some(expected) = &self.expected_fingerprint {
            let actual = server_public_key
                .fingerprint(russh::keys::ssh_key::HashAlg::Sha256)
                .to_string();
            return Ok(&actual == expected);
        }
        // Fail closed: neither a pinned fingerprint nor accept-any.
        Ok(false)
    }
}

/// Connect, authenticate (password), and open an SFTP session. The returned
/// [`Handle`] owns the connection task and must be kept alive while the
/// session is used.
async fn open_session(conn: &SftpConn) -> Result<(Handle<ClientHandler>, SftpSession), String> {
    let config = Arc::new(russh::client::Config::default());
    let handler = ClientHandler {
        expected_fingerprint: conn.host_key_sha256.clone(),
        accept_any: conn.accept_unknown_host_key,
    };
    let mut handle = russh::client::connect(config, (conn.host.as_str(), conn.port), handler)
        .await
        .map_err(|e| format!("SSH connect failed: {e}"))?;

    let auth = handle
        .authenticate_password(conn.username.clone(), conn.password.clone())
        .await
        .map_err(|e| format!("SSH auth failed: {e}"))?;
    if !matches!(auth, AuthResult::Success) {
        return Err("SSH authentication rejected (bad username/password or host key)".to_owned());
    }

    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("SSH channel open failed: {e}"))?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| format!("SFTP subsystem request failed: {e}"))?;
    let sftp = SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| format!("SFTP session init failed: {e}"))?;
    Ok((handle, sftp))
}

/// Resolve the caller path under `root`, rejecting `..` traversal.
pub fn resolve_path(root: &str, caller: &str) -> Result<String, String> {
    if caller.split('/').any(|seg| seg == "..") {
        return Err("path must not contain '..' segments".to_owned());
    }
    let caller = caller.trim_start_matches('/');
    if root.trim().is_empty() {
        Ok(if caller.is_empty() {
            ".".to_owned()
        } else {
            caller.to_owned()
        })
    } else {
        let root = root.trim_end_matches('/');
        Ok(if caller.is_empty() {
            root.to_owned()
        } else {
            format!("{root}/{caller}")
        })
    }
}

/// List a directory's entries.
pub async fn list(conn: &SftpConn, path: &str) -> Result<Vec<Value>, String> {
    let (_handle, sftp) = open_session(conn).await?;
    let dir = sftp
        .read_dir(path)
        .await
        .map_err(|e| format!("SFTP list '{path}' failed: {e}"))?;
    let entries = dir.map(entry_to_json).collect();
    Ok(entries)
}

/// Read a file's contents (capped at `max_bytes`).
pub async fn get(conn: &SftpConn, path: &str, max_bytes: usize) -> Result<Vec<u8>, String> {
    let (_handle, sftp) = open_session(conn).await?;
    let file = sftp
        .open(path)
        .await
        .map_err(|e| format!("SFTP open '{path}' failed: {e}"))?;
    // Read one extra byte to detect a file that exceeds the cap.
    let mut buf = Vec::new();
    let mut limited = file.take(max_bytes as u64 + 1);
    limited
        .read_to_end(&mut buf)
        .await
        .map_err(|e| format!("SFTP read '{path}' failed: {e}"))?;
    if buf.len() > max_bytes {
        return Err(format!("file exceeds max_bytes ({max_bytes})"));
    }
    Ok(buf)
}

/// Write a file (truncate/create). Returns the byte count.
pub async fn put(conn: &SftpConn, path: &str, content: &[u8]) -> Result<usize, String> {
    let (_handle, sftp) = open_session(conn).await?;
    let mut file = sftp
        .create(path)
        .await
        .map_err(|e| format!("SFTP create '{path}' failed: {e}"))?;
    file.write_all(content)
        .await
        .map_err(|e| format!("SFTP write '{path}' failed: {e}"))?;
    file.flush()
        .await
        .map_err(|e| format!("SFTP flush '{path}' failed: {e}"))?;
    file.shutdown()
        .await
        .map_err(|e| format!("SFTP close '{path}' failed: {e}"))?;
    Ok(content.len())
}

/// Project a directory entry to JSON.
fn entry_to_json(entry: russh_sftp::client::fs::DirEntry) -> Value {
    let meta = entry.metadata();
    let kind = if meta.is_dir() {
        "dir"
    } else if meta.is_symlink() {
        "symlink"
    } else {
        "file"
    };
    json!({
        "name": entry.file_name(),
        "type": kind,
        "size": meta.size,
        "permissions": meta.permissions,
        "mtime": meta.mtime,
    })
}

/// Decode file bytes for the envelope: UTF-8 text when valid, else base64.
pub fn decode_content(data: &[u8]) -> Value {
    match std::str::from_utf8(data) {
        Ok(s) => json!({ "text": s }),
        Err(_) => {
            use base64::Engine as _;
            json!({ "base64": base64::engine::general_purpose::STANDARD.encode(data) })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_rejects_traversal() {
        assert!(resolve_path("", "../etc/passwd").is_err());
        assert!(resolve_path("/home/svc", "a/../../b").is_err());
    }

    #[test]
    fn resolve_joins_under_root() {
        assert_eq!(
            resolve_path("/upload", "report.csv").unwrap(),
            "/upload/report.csv"
        );
        assert_eq!(
            resolve_path("/upload/", "/report.csv").unwrap(),
            "/upload/report.csv"
        );
        assert_eq!(resolve_path("", "sub/file").unwrap(), "sub/file");
        assert_eq!(resolve_path("", "").unwrap(), ".");
        assert_eq!(resolve_path("/data", "").unwrap(), "/data");
    }

    #[test]
    fn decode_text_vs_base64() {
        assert_eq!(decode_content(b"hello")["text"], json!("hello"));
        assert_eq!(decode_content(&[0xff, 0xfe])["base64"], json!("//4="));
    }
}
