//! `watch_strategy` entity (`sftp_dir_poll`): a directory on an SFTP server
//! as an inventory.
//!
//! SFTP has no change-push channel, so the strategy lists the directory
//! (and its subdirectories with `recursive`) every `interval_ms`. A resource
//! watch gets one change per listing that changed anything; an MCP Events
//! source gets each file created, modified or deleted as the shared
//! `object.changed` event, through the SDK's inventory helper, which also
//! resumes after a restart. Each listing opens one connection, walks, and
//! drops it.

use std::time::Duration;

use mcpg_plugin_protocol::backend::WatchError;
use mcpg_plugin_protocol::{PluginManifest, firstparty_manifest};
use mcpg_plugin_sdk::HostHandle;
use mcpg_plugin_sdk::ffi::{SyncWatchStrategyPlugin, WatchHandleBox};
use mcpg_plugin_sdk::inventory::{
    DirItem, InventoryOptions, InventoryStart, Pattern, WalkOptions, acknowledge_inventory_watch,
    cancel_inventory_watch, defaults, spawn_inventory_watch, walk,
};
use serde::Deserialize;
use serde_json::Value;

use crate::sftp::{self, SftpConn, SftpLister};

pub const PLUGIN_ID: &str = "dev.mcpg.backend.sftp";

/// The strategy discriminator this entity handles.
pub const WATCH_KIND: &str = "sftp_dir_poll";

/// Default listing cadence when `interval_ms` is omitted (1 minute).
fn default_interval_ms() -> u64 {
    60_000
}

/// Default budget of one listing when `timeout_ms` is omitted (10 seconds).
fn default_timeout_ms() -> u64 {
    10_000
}

fn default_port() -> u16 {
    22
}

/// Per-watch spec: the SFTP connection fields (mirroring the backend's
/// connection shape), the directory under `root` to watch, and how it is
/// listed. The connection is carried per watch, so a watcher is
/// self-contained.
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
    /// SSH password: a literal, `${env.X}`, `${secret.X}` or `vault://…`,
    /// resolved before the watch starts. Per-caller `cred://` is rejected.
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
    /// Listing cadence in milliseconds (default 60000, at least 250).
    #[serde(default = "default_interval_ms")]
    interval_ms: u64,
    /// Budget of one listing in milliseconds (default 10000).
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
    /// List the subdirectories too.
    #[serde(default)]
    recursive: bool,
    /// Keep only the files whose path relative to the directory matches
    /// this glob (`*.csv`, `**/*.json`).
    #[serde(default)]
    pattern: Option<String>,
    /// Most files listed (default 10000).
    #[serde(default = "defaults::max_files")]
    max_files: usize,
    /// `now` (default): the files there at a first start are the baseline;
    /// `existing`: each is reported as created.
    #[serde(default)]
    start_at: InventoryStart,
    /// Largest snapshot of the listing an event carries (default 131072).
    #[serde(default = "defaults::snapshot_bytes")]
    snapshot_bytes: usize,
    /// Most changes emitted ahead of the gateway's acknowledgements.
    #[serde(default = "defaults::max_in_flight")]
    max_in_flight: usize,
    /// How long a change waits for its acknowledgement (default 60000).
    #[serde(default = "defaults::ack_timeout_ms")]
    ack_timeout_ms: u64,
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

/// Run one step of a listing on `rt`, failing when the listing's `deadline`
/// passes.
fn within<T>(
    rt: &tokio::runtime::Runtime,
    deadline: tokio::time::Instant,
    step: impl Future<Output = Result<T, String>>,
) -> Result<T, String> {
    rt.block_on(async {
        tokio::time::timeout_at(deadline, step)
            .await
            .map_err(|_| "sftp listing timed out".to_owned())?
    })
}

/// One listing entry as the inventory reads it; `None` for an entry that is
/// neither a file nor a directory.
fn dir_item(entry: &Value) -> Option<DirItem> {
    let name = entry.get("name").and_then(Value::as_str)?.to_owned();
    let is_dir = match entry.get("type").and_then(Value::as_str) {
        Some("dir") => true,
        Some("file") => false,
        _ => return None,
    };
    Some(DirItem {
        name,
        is_dir,
        size: entry.get("size").and_then(Value::as_u64),
        modified_at_ms: entry
            .get("mtime")
            .and_then(Value::as_i64)
            .map(|secs| secs.saturating_mul(1_000)),
    })
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
        let (spec, resume) = mcpg_plugin_protocol::take_watch_resume(spec);
        let parsed: WatchSpec =
            serde_json::from_value(spec).map_err(|e| WatchError::InvalidSpec {
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
                 use ${env.X} / ${secret.X} / vault:// (resolved before the watch starts)"
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
        if !(1..=100_000).contains(&parsed.max_files) {
            return Err(invalid("max_files must be 1 to 100000".into()));
        }
        let pattern = parsed
            .pattern
            .as_deref()
            .map(Pattern::new)
            .transpose()
            .map_err(|e| invalid(format!("pattern: {e}")))?;
        // Reuse the backend's path-traversal guard (rejects `..` segments) so a
        // watcher can never escape `root`.
        let resolved = sftp::resolve_path(&parsed.root, &parsed.path).map_err(invalid)?;
        let location = format!(
            "sftp://{}:{}/{}",
            parsed.host,
            parsed.port,
            resolved.trim_start_matches('/')
        );

        let conn = SftpConn {
            host: parsed.host,
            port: parsed.port,
            username: parsed.username,
            password: parsed.password,
            host_key_sha256: parsed.host_key_sha256,
            accept_unknown_host_key: parsed.accept_unknown_host_key,
        };
        // One current-thread runtime, moved into the listing: listings are
        // sequential, so a single-thread runtime is enough.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| WatchError::Subscribe {
                message: format!("sftp_dir_poll: tokio runtime init failed: {e}"),
            })?;
        let timeout = Duration::from_millis(parsed.timeout_ms);
        let walk_options = WalkOptions {
            recursive: parsed.recursive,
            pattern,
            max_files: parsed.max_files,
            max_dirs: defaults::max_dirs(),
        };
        // A server that cannot be reached now is listed again at the next
        // interval: the source is not lost to a transient outage.
        let list = move || {
            // The session drops inside the runtime that drives it.
            let _runtime = rt.enter();
            let deadline = tokio::time::Instant::now() + timeout;
            let lister = within(&rt, deadline, SftpLister::open(&conn, &resolved))?;
            walk(&walk_options, |dir| {
                let entries = within(&rt, deadline, lister.list(dir))?;
                Ok(entries.iter().filter_map(dir_item).collect())
            })
        };

        spawn_inventory_watch(
            resource_uri,
            InventoryOptions {
                store: "sftp".into(),
                location,
                interval: Duration::from_millis(parsed.interval_ms),
                start: parsed.start_at,
                snapshot_bytes: parsed.snapshot_bytes,
                max_in_flight: parsed.max_in_flight,
                ack_timeout: Duration::from_millis(parsed.ack_timeout_ms),
            },
            resume,
            emit_event,
            list,
        )
    }

    fn acknowledge(&self, watch_handle: &WatchHandleBox, position: &Value) {
        acknowledge_inventory_watch(watch_handle, position);
    }

    fn cancel(&self, watch_handle: WatchHandleBox) {
        cancel_inventory_watch(watch_handle);
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

    fn refused(spec: Value) -> String {
        match plugin().watch("sftp://incoming", &spec, emit_noop()) {
            Err(WatchError::InvalidSpec { message }) => message,
            Err(other) => panic!("not a spec error: {other:?}"),
            Ok(handle) => {
                plugin().cancel(handle);
                panic!("accepted {spec}");
            }
        }
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
        assert!(!parsed.recursive);
        assert_eq!(parsed.max_files, 10_000);
        assert_eq!(parsed.start_at, InventoryStart::Now);
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
            "recursive": true,
            "pattern": "**/*.csv",
            "start_at": "existing",
        }))
        .unwrap();
        assert_eq!(parsed.port, 2222);
        assert_eq!(parsed.root, "/data");
        assert_eq!(parsed.path, "incoming");
        assert_eq!(parsed.host_key_sha256.as_deref(), Some("SHA256:abc"));
        assert_eq!(parsed.interval_ms, 30_000);
        assert!(parsed.recursive);
        assert_eq!(parsed.start_at, InventoryStart::Existing);
    }

    #[test]
    fn a_bad_spec_is_refused_before_anything_connects() {
        let base = json!({ "host": "h", "username": "u", "password": "p", "accept_unknown_host_key": true });
        let with = |extra: Value| {
            let mut spec = base.clone();
            for (k, v) in extra.as_object().unwrap() {
                spec[k] = v.clone();
            }
            spec
        };
        assert!(refused(with(json!({ "bogus": true }))).contains("unknown field"));
        assert!(refused(with(json!({ "path": "../etc" }))).contains(".."));
        assert!(refused(with(json!({ "password": "cred://vault/sftp" }))).contains("cred://"));
        assert!(
            refused(json!({ "host": "h", "username": "u", "password": "p" })).contains("host key")
        );
        assert!(refused(with(json!({ "pattern": "[a" }))).contains("pattern"));
        assert!(refused(with(json!({ "max_files": 0 }))).contains("max_files"));
        assert!(refused(with(json!({ "interval_ms": 10 }))).contains("interval_ms"));
    }

    #[test]
    fn an_unreachable_server_is_listed_again_not_a_failed_watch() {
        let handle = plugin()
            .watch(
                "mcpg-event://inbox",
                &json!({
                    "host": "127.0.0.1",
                    "port": 1,
                    "username": "u",
                    "password": "p",
                    "accept_unknown_host_key": true,
                    "timeout_ms": 200,
                    "interval_ms": 250,
                }),
                emit_noop(),
            )
            .expect("the watch starts and retries in the background");
        std::thread::sleep(Duration::from_millis(300));
        plugin().cancel(handle);
    }

    #[test]
    fn listing_entries_become_files_and_directories() {
        assert_eq!(
            dir_item(&json!({ "name": "a.csv", "type": "file", "size": 10, "mtime": 100 })),
            Some(DirItem {
                name: "a.csv".into(),
                is_dir: false,
                size: Some(10),
                modified_at_ms: Some(100_000),
            })
        );
        assert!(
            dir_item(&json!({ "name": "sub", "type": "dir" }))
                .unwrap()
                .is_dir
        );
        assert_eq!(dir_item(&json!({ "name": "l", "type": "symlink" })), None);
    }
}
