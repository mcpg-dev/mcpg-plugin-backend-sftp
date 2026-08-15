//! `watch_strategy` entity (`sftp_dir_poll`) — POLLING directory-change watch.
//!
//! SFTP has no native change-push channel, so this strategy LISTS a directory
//! on a cadence and signals a change whenever the listing's content changes (a
//! file added, removed, or modified). The cursor is a deterministic FINGERPRINT
//! of the listing — each entry rendered as `name|size|mtime`, sorted, joined —
//! so the comparison is order-independent and stable across ticks. The poll
//! thread, the cursor diff, the stop signal, and the opaque handle round-trip
//! all live in the shared [`mcpg_plugin_sdk::watch`] helper; this entity only
//! supplies the per-tick `poll` closure.
//!
//! SFTP (russh) is async and per-call: a connection is opened, listed, and
//! dropped each tick. The helper's loop is synchronous, so a single
//! current-thread tokio runtime is built once in [`watch`] and moved into the
//! closure; each tick `block_on`s one connect + list (sequential ticks, so a
//! single-thread runtime is enough). Connect / list failures map to the
//! closure's `Err(String)` — the helper logs and retries on the next tick.

use std::sync::Arc;
use std::time::Duration;

use mcpg_plugin_protocol::backend::WatchError;
use mcpg_plugin_protocol::{PluginManifest, firstparty_manifest};
use mcpg_plugin_sdk::HostHandle;
use mcpg_plugin_sdk::ffi::{SyncWatchStrategyPlugin, WatchHandleBox};
use mcpg_plugin_sdk::watch::{cancel_polling_watch, spawn_polling_watch};
use serde::Deserialize;
use serde_json::Value;

use crate::sftp::{self, SftpConn};

pub const PLUGIN_ID: &str = "dev.mcpg.backend.sftp";

/// The strategy discriminator this entity handles.
pub const WATCH_KIND: &str = "sftp_dir_poll";

/// Default poll cadence when `interval_ms` is omitted (1 minute).
fn default_interval_ms() -> u64 {
    60_000
}

/// Default per-tick connect + list budget when `timeout_ms` is omitted
/// (10 seconds).
fn default_timeout_ms() -> u64 {
    10_000
}

fn default_port() -> u16 {
    22
}

/// Per-watch spec: the SFTP connection fields (mirroring the backend's
/// connection shape) plus the directory `path` under `root` to watch and the
/// poll cadence. The connection is carried per-watch (not at plugin level), so
/// a watcher is self-contained.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WatchSpec {
    /// SSH host. Operator-configured.
    host: String,
    /// SSH port (default 22).
    #[serde(default = "default_port")]
    port: u16,
    /// SSH login user.
    username: String,
    /// SSH password — a literal, or `${env.X}` / `vault://…` resolved at config
    /// load. Per-caller `cred://` is rejected.
    password: String,
    /// Base directory the watched `path` is joined under (default `""` = the
    /// login's default directory).
    #[serde(default)]
    root: String,
    /// The directory under `root` to watch (default `""` = `root` itself). May
    /// not contain `..` segments.
    #[serde(default)]
    path: String,
    /// Expected server host-key fingerprint (`SHA256:…`). When set, the
    /// connection is rejected unless the server key matches.
    #[serde(default)]
    host_key_sha256: Option<String>,
    /// Accept any (unverified) server host key. Dev/test only.
    #[serde(default)]
    accept_unknown_host_key: bool,
    /// Poll cadence in milliseconds (default 60000; floored by the SDK helper).
    #[serde(default = "default_interval_ms")]
    interval_ms: u64,
    /// Per-tick connect + list budget in milliseconds (default 10000).
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
}

/// `watch_strategy` entity. Stateless beyond its manifest — every watcher's
/// connection + directory arrive on the per-watch spec.
pub struct SftpWatchCdylib {
    manifest: PluginManifest,
}

impl SftpWatchCdylib {
    /// Infallible cdylib factory. `config_json` + host are ignored — the watch
    /// carries no plugin-level config (the connection + directory arrive via
    /// the per-watch spec).
    pub fn from_host_config(_config_json: &str, _host: HostHandle) -> Self {
        Self {
            manifest: firstparty_manifest! {
                id: "dev.mcpg.backend.sftp",
                name: "SFTP Directory Poll Watch Strategy",
                class: WatchStrategy,
            },
        }
    }
}

/// Build a deterministic fingerprint of a directory listing. Each entry is
/// rendered as `name|size|mtime`; the lines are SORTED then joined by `\n`, so
/// the result is order-independent (the server's listing order does not matter)
/// and changes iff a file is added, removed, or modified (size/mtime move).
fn fingerprint_listing(entries: &[Value]) -> String {
    let mut lines: Vec<String> = entries
        .iter()
        .map(|e| {
            let name = e.get("name").and_then(Value::as_str).unwrap_or("");
            let size = e.get("size").map(value_scalar).unwrap_or_default();
            let mtime = e.get("mtime").map(value_scalar).unwrap_or_default();
            format!("{name}|{size}|{mtime}")
        })
        .collect();
    lines.sort();
    lines.join("\n")
}

/// Render a JSON scalar to a stable string for the fingerprint. Strings yield
/// their bare value; everything else its JSON rendering; null/missing yields the
/// empty string.
fn value_scalar(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

impl SyncWatchStrategyPlugin for SftpWatchCdylib {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn kind(&self) -> &str {
        WATCH_KIND
    }

    fn watch(
        &self,
        resource_uri: &str,
        spec: &Value,
        emit_event: Box<dyn Fn(&str) + Send + Sync + 'static>,
    ) -> Result<WatchHandleBox, WatchError> {
        let parsed: WatchSpec =
            serde_json::from_value(spec.clone()).map_err(|e| WatchError::InvalidSpec {
                message: format!("invalid sftp_dir_poll watch spec: {e}"),
            })?;

        let invalid = |m: String| WatchError::InvalidSpec { message: m };
        if parsed.host.trim().is_empty() {
            return Err(invalid("host must not be empty".into()));
        }
        if parsed.username.trim().is_empty() {
            return Err(invalid("username must not be empty".into()));
        }
        if parsed.password.is_empty() {
            return Err(invalid("password must not be empty".into()));
        }
        if parsed.password.starts_with("cred://") {
            return Err(invalid(
                "password must not be a cred:// URI — per-caller credentials are unsupported; \
                 use ${env.X} / vault:// (resolved at config load)"
                    .into(),
            ));
        }
        if parsed.timeout_ms == 0 {
            return Err(invalid("timeout_ms must be greater than 0".into()));
        }
        // Fail closed on host-key verification: require a pinned fingerprint OR
        // an explicit accept-any opt-in — matching the backend register guard.
        if parsed.host_key_sha256.is_none() && !parsed.accept_unknown_host_key {
            return Err(invalid(
                "host key verification not configured — set host_key_sha256 (SHA256:…) or, for \
                 dev only, accept_unknown_host_key: true"
                    .into(),
            ));
        }
        // Reuse the backend's path-traversal guard (rejects `..` segments) so a
        // watcher can never escape `root`.
        let resolved = sftp::resolve_path(&parsed.root, &parsed.path).map_err(invalid)?;

        let conn = SftpConn {
            host: parsed.host,
            port: parsed.port,
            username: parsed.username,
            password: parsed.password,
            host_key_sha256: parsed.host_key_sha256,
            accept_unknown_host_key: parsed.accept_unknown_host_key,
        };

        // One current-thread runtime, moved into the closure: ticks are
        // sequential, so a single-thread runtime is enough to `block_on` each
        // connect + list.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| WatchError::Subscribe {
                message: format!("sftp_dir_poll: tokio runtime init failed: {e}"),
            })?;

        let timeout = Duration::from_millis(parsed.timeout_ms);
        let conn = Arc::new(conn);

        // Initial connect probe: a connect/list failure here means the watcher
        // could never establish a baseline, so fail the subscription rather than
        // spawn a thread that only ever logs retries.
        rt.block_on(async {
            tokio::time::timeout(timeout, sftp::list(&conn, &resolved))
                .await
                .map_err(|_| "initial sftp list timed out".to_owned())
                .and_then(|r| r)
        })
        .map_err(|message| WatchError::Subscribe {
            message: format!("sftp_dir_poll: initial connect/list failed: {message}"),
        })?;

        let poll = move || -> Result<Option<String>, String> {
            let entries = rt.block_on(async {
                tokio::time::timeout(timeout, sftp::list(&conn, &resolved))
                    .await
                    .map_err(|_| "sftp list timed out".to_owned())
                    .and_then(|r| r)
            })?;
            Ok(Some(fingerprint_listing(&entries)))
        };

        Ok(spawn_polling_watch(
            resource_uri,
            Duration::from_millis(parsed.interval_ms),
            emit_event,
            poll,
        ))
    }

    fn cancel(&self, watch_handle: WatchHandleBox) {
        cancel_polling_watch(watch_handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn stub_host() -> HostHandle {
        // SAFETY: `stub_host_ref` returns a process-static no-op host ref; the
        // factory ignores the host entirely.
        #[allow(unsafe_code)]
        unsafe {
            HostHandle::from_ffi(mcpg_plugin_sdk::testing::stub_host_ref())
        }
    }

    fn plugin() -> SftpWatchCdylib {
        SftpWatchCdylib::from_host_config("", stub_host())
    }

    fn emit_noop() -> Box<dyn Fn(&str) + Send + Sync + 'static> {
        Box::new(|_| {})
    }

    #[test]
    fn manifest_and_kind_are_correct() {
        use mcpg_plugin_protocol::PluginClass;
        let p = plugin();
        let m = SyncWatchStrategyPlugin::manifest(&p);
        assert_eq!(m.id, PLUGIN_ID);
        assert_eq!(m.plugin_class, PluginClass::WatchStrategy);
        assert_eq!(p.kind(), WATCH_KIND);
    }

    #[test]
    fn spec_parses_with_defaults() {
        let parsed: WatchSpec = serde_json::from_value(json!({
            "host": "sftp.example.com",
            "username": "svc",
            "password": "${env.SFTP_PW}",
            "accept_unknown_host_key": true,
        }))
        .unwrap();
        assert_eq!(parsed.port, 22);
        assert_eq!(parsed.root, "");
        assert_eq!(parsed.path, "");
        assert_eq!(parsed.interval_ms, 60_000);
        assert_eq!(parsed.timeout_ms, 10_000);
        assert!(parsed.host_key_sha256.is_none());
    }

    #[test]
    fn spec_parses_overrides() {
        let parsed: WatchSpec = serde_json::from_value(json!({
            "host": "h",
            "port": 2222,
            "username": "u",
            "password": "p",
            "root": "/data",
            "path": "incoming",
            "host_key_sha256": "SHA256:abc",
            "interval_ms": 30_000,
            "timeout_ms": 5_000,
        }))
        .unwrap();
        assert_eq!(parsed.port, 2222);
        assert_eq!(parsed.root, "/data");
        assert_eq!(parsed.path, "incoming");
        assert_eq!(parsed.host_key_sha256.as_deref(), Some("SHA256:abc"));
        assert_eq!(parsed.interval_ms, 30_000);
        assert_eq!(parsed.timeout_ms, 5_000);
    }

    #[test]
    fn unknown_field_is_invalid_spec() {
        let p = plugin();
        assert!(matches!(
            p.watch(
                "sftp://incoming",
                &json!({
                    "host": "h",
                    "username": "u",
                    "password": "p",
                    "accept_unknown_host_key": true,
                    "bogus": true,
                }),
                emit_noop(),
            ),
            Err(WatchError::InvalidSpec { .. })
        ));
    }

    #[test]
    fn traversal_path_is_invalid_spec() {
        let p = plugin();
        assert!(matches!(
            p.watch(
                "sftp://incoming",
                &json!({
                    "host": "h",
                    "username": "u",
                    "password": "p",
                    "accept_unknown_host_key": true,
                    "path": "../etc",
                }),
                emit_noop(),
            ),
            Err(WatchError::InvalidSpec { .. })
        ));
    }

    #[test]
    fn cred_password_is_invalid_spec() {
        let p = plugin();
        assert!(matches!(
            p.watch(
                "sftp://incoming",
                &json!({
                    "host": "h",
                    "username": "u",
                    "password": "cred://vault/sftp",
                    "accept_unknown_host_key": true,
                }),
                emit_noop(),
            ),
            Err(WatchError::InvalidSpec { .. })
        ));
    }

    #[test]
    fn unconfigured_host_key_is_invalid_spec() {
        let p = plugin();
        assert!(matches!(
            p.watch(
                "sftp://incoming",
                &json!({ "host": "h", "username": "u", "password": "p" }),
                emit_noop(),
            ),
            Err(WatchError::InvalidSpec { .. })
        ));
    }

    #[test]
    fn fingerprint_is_stable_and_order_independent() {
        let a = vec![
            json!({ "name": "a.txt", "size": 10, "mtime": 100 }),
            json!({ "name": "b.txt", "size": 20, "mtime": 200 }),
        ];
        // Same entries, reversed listing order → identical fingerprint.
        let b = vec![
            json!({ "name": "b.txt", "size": 20, "mtime": 200 }),
            json!({ "name": "a.txt", "size": 10, "mtime": 100 }),
        ];
        assert_eq!(fingerprint_listing(&a), fingerprint_listing(&b));
    }

    #[test]
    fn fingerprint_changes_on_add_remove_modify() {
        let base = vec![
            json!({ "name": "a.txt", "size": 10, "mtime": 100 }),
            json!({ "name": "b.txt", "size": 20, "mtime": 200 }),
        ];
        let base_fp = fingerprint_listing(&base);

        // A file added.
        let added = vec![
            json!({ "name": "a.txt", "size": 10, "mtime": 100 }),
            json!({ "name": "b.txt", "size": 20, "mtime": 200 }),
            json!({ "name": "c.txt", "size": 30, "mtime": 300 }),
        ];
        assert_ne!(base_fp, fingerprint_listing(&added));

        // A file removed.
        let removed = vec![json!({ "name": "a.txt", "size": 10, "mtime": 100 })];
        assert_ne!(base_fp, fingerprint_listing(&removed));

        // A file modified (size + mtime moved).
        let modified = vec![
            json!({ "name": "a.txt", "size": 11, "mtime": 101 }),
            json!({ "name": "b.txt", "size": 20, "mtime": 200 }),
        ];
        assert_ne!(base_fp, fingerprint_listing(&modified));
    }
}
