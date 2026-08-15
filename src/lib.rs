//! SFTP (SSH file transfer) backend binding plugin for mcpg.
//!
//! Implements [`SftpBackendPlugin`] — `BackendPlugin` for `kind: "sftp"`.
//! `op: list` lists a directory, `op: get` reads a file, `op: put` writes a
//! file, over SSH (russh + russh-sftp). The target path comes from the call
//! arguments (with `..` rejected), joined under the operator-configured
//! `root`. Structurally mirrors the soap/ldap/mssql/amqp/email backends;
//! protocol machinery lives in [`sftp`] + [`envelope`].

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use mcpg_plugin_protocol::audit::{AuditEvent, AuditOutcome};
use mcpg_plugin_protocol::types::PluginIdentity;
use mcpg_plugin_protocol::{
    BackendError, BackendHost, BackendPlugin, BackendRequest, BackendResponse, PluginManifest,
    ResourcePage, firstparty_manifest,
};
use mcpg_plugin_sdk::HostHandle;
use serde_json::{Value, json};
use tokio::sync::RwLock;
use tracing::debug;

/// cdylib sync bridge.
pub mod cdylib;
mod envelope;
mod sftp;
mod surface;
mod types;
/// `watch_strategy` directory-poll entity (kind `sftp_dir_poll`).
pub mod watch;

use envelope::{SftpOutcome, build_result_envelope, classify_error};
use sftp::SftpConn;
pub use types::{SftpBackendSpec, SftpOp};

/// Embedded plugin descriptor.
pub const BINDING_DESCRIPTOR_YAML: &str = include_str!("../plugin.yaml");

// --------------------------------------------------------------------- obs

fn audit_action_for_outcome(label: &str) -> Option<&'static str> {
    match label {
        "timeout" => Some("dev.mcpg.backend.sftp.request_timeout"),
        "transport_error" => Some("dev.mcpg.backend.sftp.request_failed"),
        "sftp_error" => Some("dev.mcpg.backend.sftp.operation_rejected"),
        "invalid_spec" => Some("dev.mcpg.backend.sftp.request_failed"),
        _ => None,
    }
}

fn rfc3339_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn synthetic_system_identity() -> PluginIdentity {
    PluginIdentity {
        kind: "system".into(),
        trust_level: "verified".into(),
        subject_id: Some("dev.mcpg.backend.sftp".into()),
        auth_provider: None,
        issuer: None,
        roles: vec![],
        groups: vec![],
        scopes: vec![],
        attributes: Default::default(),
    }
}

fn finalize_payload(envelope: Value) -> Result<BackendResponse, BackendError> {
    let payload = serde_json::to_vec(&envelope).map_err(|e| BackendError::Transport {
        message: format!("SFTP plugin envelope serialization failed: {e}"),
    })?;
    Ok(BackendResponse {
        payload,
        truncated: false,
    })
}

fn extract_put_content(args: &Value) -> Result<Vec<u8>, String> {
    if let Some(b64) = args.get("content").and_then(|v| v.as_str()) {
        use base64::Engine as _;
        return base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| format!("'content' is not valid base64: {e}"));
    }
    if let Some(text) = args.get("text").and_then(|v| v.as_str()) {
        return Ok(text.as_bytes().to_vec());
    }
    Err("put requires a 'content' (base64) or 'text' argument".to_owned())
}

// ------------------------------------------------------------------ plugin

/// Per-binding SFTP runtime. Cheap to clone; SSH connect per call.
#[derive(Clone)]
struct SftpProfile {
    op: SftpOp,
    conn: SftpConn,
    root: String,
    max_bytes: usize,
    timeout: Duration,
    surface: surface::Surface,
    uri_template: String,
    static_uri: Option<String>,
}

/// `BackendPlugin` implementation for `kind: "sftp"`.
pub struct SftpBackendPlugin {
    manifest: PluginManifest,
    profiles: RwLock<BTreeMap<String, SftpProfile>>,
    host_handle: OnceLock<HostHandle>,
}

impl Default for SftpBackendPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl SftpBackendPlugin {
    #[must_use]
    pub fn new() -> Self {
        Self {
            manifest: firstparty_manifest! {
                id: "dev.mcpg.backend.sftp",
                name: "SFTP Binding",
                class: Backend,
            },
            profiles: RwLock::new(BTreeMap::new()),
            host_handle: OnceLock::new(),
        }
    }

    pub fn set_host_handle(&self, host: HostHandle) -> bool {
        self.host_handle.set(host).is_ok()
    }

    fn host_handle(&self) -> Option<&HostHandle> {
        self.host_handle.get()
    }

    async fn emit_host_observability(
        &self,
        backend_name: &str,
        outcome_label: &'static str,
        reason: Option<&str>,
        identity: Option<&PluginIdentity>,
        request_id: &str,
        duration: Duration,
    ) {
        let Some(host) = self.host_handle() else {
            return;
        };
        host.histogram(
            "mcpg_sftp_backend_latency_seconds",
            duration.as_secs_f64(),
            &[("outcome", outcome_label)],
        );
        host.counter(
            "mcpg_sftp_backend_calls_total",
            1,
            &[("outcome", outcome_label)],
        );
        if let Some(action) = audit_action_for_outcome(outcome_label) {
            let actor = identity.cloned().unwrap_or_else(synthetic_system_identity);
            let mut details = json!({
                "backend": backend_name,
                "duration_ms": duration.as_millis() as u64,
                "outcome": outcome_label,
                "alias": host.alias(),
            });
            if let Some(reason) = reason {
                details
                    .as_object_mut()
                    .expect("json object")
                    .insert("reason".into(), Value::String(reason.to_owned()));
            }
            let event = AuditEvent {
                event_id: format!("sftp-{}-{}", request_id, duration.as_nanos()),
                occurred_at: rfc3339_now(),
                actor,
                action: action.to_owned(),
                resource: Some(format!("sftp-binding://{backend_name}")),
                outcome: AuditOutcome::Failure,
                request_id: Some(request_id.to_owned()),
                node_id: None,
                details,
                prev_event_hash: None,
            };
            let host_for_audit = host.clone();
            if let Err(join_err) = tokio::task::spawn_blocking(move || {
                let _ = host_for_audit.audit_event(event);
            })
            .await
            {
                debug!(target: "mcpg::sftp::host_handle", error = %join_err, "audit spawn_blocking failed");
            }
        }
    }
}

impl std::fmt::Debug for SftpBackendPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SftpBackendPlugin")
            .field("id", &self.manifest.id)
            .finish()
    }
}

#[async_trait]
impl BackendPlugin for SftpBackendPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn kind(&self) -> &str {
        "sftp"
    }

    async fn register_profile(
        &self,
        backend_name: &str,
        spec: &Value,
        _host: Arc<dyn BackendHost>,
    ) -> Result<(), BackendError> {
        let parsed: SftpBackendSpec =
            serde_json::from_value(spec.clone()).map_err(|e| BackendError::InvalidSpec {
                message: format!("SFTP binding spec: {e}"),
            })?;

        let invalid = |m: String| BackendError::InvalidSpec { message: m };
        if parsed.host.trim().is_empty() {
            return Err(invalid("host must not be empty".into()));
        }
        if parsed.username.trim().is_empty() {
            return Err(invalid("username must not be empty".into()));
        }
        if parsed.password.is_empty() {
            return Err(invalid(
                "password must not be empty (v1 is password auth)".into(),
            ));
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
        if parsed.max_bytes == 0 {
            return Err(invalid("max_bytes must be greater than 0".into()));
        }
        // Surface coherence: `uri` is only meaningful on the resource surface;
        // a static/template `uri` on a tool binding is a config mistake worth a
        // fail-closed rejection rather than a silent no-op.
        if parsed.uri.is_some() && parsed.surface != surface::Surface::Resource {
            return Err(invalid(format!(
                "`uri` is only valid with `surface: resource` (this binding is `surface: {}`)",
                parsed.surface.as_str()
            )));
        }
        if let Some(u) = &parsed.uri
            && u.trim().is_empty()
        {
            return Err(invalid("`uri` must not be empty".into()));
        }
        // Fail closed on host-key verification: require a pinned fingerprint
        // OR an explicit accept-any opt-in.
        if parsed.host_key_sha256.is_none() && !parsed.accept_unknown_host_key {
            return Err(invalid(
                "host key verification not configured — set host_key_sha256 (SHA256:…) or, for \
                 dev only, accept_unknown_host_key: true"
                    .into(),
            ));
        }

        debug!(
            backend = %backend_name,
            op = parsed.op.as_str(),
            host = %parsed.host,
            "registered SFTP binding profile"
        );

        // A `uri` that carries no `{path}` placeholder pins a single static
        // resource; one with `{path}` is the per-file template. Unset → the
        // default `sftp://{path}` template.
        let (uri_template, static_uri) = match parsed.uri {
            Some(u) if u.contains("{path}") => (u, None),
            Some(u) => (u.clone(), Some(u)),
            None => (surface::DEFAULT_URI_TEMPLATE.to_owned(), None),
        };

        self.profiles.write().await.insert(
            backend_name.to_owned(),
            SftpProfile {
                op: parsed.op,
                conn: SftpConn {
                    host: parsed.host,
                    port: parsed.port,
                    username: parsed.username,
                    password: parsed.password,
                    host_key_sha256: parsed.host_key_sha256,
                    accept_unknown_host_key: parsed.accept_unknown_host_key,
                },
                root: parsed.root,
                max_bytes: parsed.max_bytes,
                timeout: Duration::from_millis(parsed.timeout_ms),
                surface: parsed.surface,
                uri_template,
                static_uri,
            },
        );
        Ok(())
    }

    async fn execute(
        &self,
        backend_name: &str,
        request: BackendRequest,
    ) -> Result<BackendResponse, BackendError> {
        let started = Instant::now();
        let request_id = request.request_id.clone();
        let identity = request.identity.clone();
        let host_span = self.host_handle().map(|h| {
            h.span(
                "sftp_backend.execute",
                json!({ "backend": backend_name, "request_id": request_id }),
            )
        });

        let profile = {
            let guard = self.profiles.read().await;
            match guard.get(backend_name).cloned() {
                Some(p) => p,
                None => {
                    let err = BackendError::ProfileNotFound {
                        backend_name: backend_name.to_owned(),
                    };
                    self.emit_host_observability(
                        backend_name,
                        "profile_not_found",
                        Some(&err.to_string()),
                        identity.as_ref(),
                        &request_id,
                        started.elapsed(),
                    )
                    .await;
                    drop(host_span);
                    return Err(err);
                }
            }
        };

        let tool_name = request
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("mcpg-tool-name"))
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| backend_name.to_owned());

        let arguments: Value = if request.payload.is_empty() {
            json!({})
        } else {
            serde_json::from_slice(&request.payload).unwrap_or(Value::Null)
        };
        // On the resource surface a `resources/read` carries the resource URI
        // (or a pinned static `uri`); map it back to a file path through the
        // template. The tool surface reads the bare `path` argument.
        let resource_uri = if profile.surface == surface::Surface::Resource {
            surface::resolve_resource_path(
                &profile.uri_template,
                profile.static_uri.as_deref(),
                &arguments,
            )
        } else {
            None
        };
        let path_arg = resource_uri.clone().unwrap_or_else(|| {
            arguments
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned()
        });

        // The resource surface always reads a single file regardless of the
        // binding's declared `op`.
        let effective_op = if profile.surface == surface::Surface::Resource {
            SftpOp::Get
        } else {
            profile.op
        };

        // Connect + run, bounded by the per-call timeout.
        let work = async {
            if profile.surface == surface::Surface::Resource && resource_uri.is_none() {
                return Err(
                    "resource surface requires a `uri` (set a static `uri` on the \
                            binding or invoke via a resources/read request)"
                        .to_owned(),
                );
            }
            if matches!(effective_op, SftpOp::Get | SftpOp::Put) && path_arg.trim().is_empty() {
                return Err(format!(
                    "op '{}' requires a 'path' argument",
                    effective_op.as_str()
                ));
            }
            let resolved = sftp::resolve_path(&profile.root, &path_arg)?;
            match effective_op {
                SftpOp::List => {
                    sftp::list(&profile.conn, &resolved)
                        .await
                        .map(|entries| SftpOutcome {
                            entries: Some(entries),
                            ..Default::default()
                        })
                }
                SftpOp::Get => sftp::get(&profile.conn, &resolved, profile.max_bytes)
                    .await
                    .map(|data| SftpOutcome {
                        size: Some(data.len()),
                        content: Some(sftp::decode_content(&data)),
                        ..Default::default()
                    }),
                SftpOp::Put => {
                    let content = extract_put_content(&arguments)?;
                    if content.len() > profile.max_bytes {
                        return Err(format!("content exceeds max_bytes ({})", profile.max_bytes));
                    }
                    sftp::put(&profile.conn, &resolved, &content)
                        .await
                        .map(|n| SftpOutcome {
                            written: Some(n),
                            ..Default::default()
                        })
                }
            }
        };
        let result = match tokio::time::timeout(profile.timeout, work).await {
            Ok(r) => r,
            Err(_) => Err("SFTP operation timed out".to_owned()),
        };

        let (envelope, outcome_label, audit_reason): (Value, &'static str, Option<String>) =
            match result {
                // On the resource surface the gateway decoder requires a
                // surface-shaped `{contents:[…]}` body; the tool surface keeps
                // the historical structured-content envelope.
                Ok(outcome) if profile.surface == surface::Surface::Resource => {
                    let uri = resource_uri
                        .as_deref()
                        .map(|p| surface::uri_for_path(&profile.uri_template, p))
                        .unwrap_or_default();
                    let content = outcome
                        .content
                        .clone()
                        .unwrap_or_else(|| json!({ "text": "" }));
                    (
                        surface::resource_contents_body(&uri, &path_arg, &content),
                        "ok",
                        None,
                    )
                }
                Ok(outcome) => (
                    build_result_envelope(
                        &tool_name,
                        backend_name,
                        profile.op.as_str(),
                        &profile.conn.host,
                        &path_arg,
                        Some(&outcome),
                        started.elapsed().as_millis(),
                        None,
                        None,
                    ),
                    "ok",
                    None,
                ),
                Err(message) => {
                    let downstream = classify_error(&message);
                    let lower = message.to_ascii_lowercase();
                    let label = if lower.contains("timed out") || lower.contains("timeout") {
                        "timeout"
                    } else if downstream["kind"] == json!("transport_error") {
                        "transport_error"
                    } else {
                        "sftp_error"
                    };
                    let env = build_result_envelope(
                        &tool_name,
                        backend_name,
                        profile.op.as_str(),
                        &profile.conn.host,
                        &path_arg,
                        None,
                        started.elapsed().as_millis(),
                        Some(&downstream),
                        Some(&message),
                    );
                    (env, label, Some(message))
                }
            };

        self.emit_host_observability(
            backend_name,
            outcome_label,
            audit_reason.as_deref(),
            identity.as_ref(),
            &request_id,
            started.elapsed(),
        )
        .await;
        drop(host_span);
        finalize_payload(envelope)
    }

    fn audit_metadata(&self, _backend_name: &str) -> serde_json::Map<String, Value> {
        let mut map = serde_json::Map::new();
        map.insert("sftp.transport".to_owned(), json!("plugin"));
        map
    }

    /// Enumerate resources for `resources/list`: list the binding's `root`
    /// directory and project each regular file into a resource (URI from the
    /// `uri` template, name = filename, mimeType from the extension). Only
    /// resource-surface bindings list; tool bindings inherit the empty page.
    /// SFTP returns directory listings whole, so a single page carries them all
    /// (`next_cursor == None`); the `cursor` argument is therefore unused.
    async fn list_resources(
        &self,
        backend_name: &str,
        _cursor: Option<&str>,
    ) -> Result<ResourcePage, BackendError> {
        let profile = {
            let guard = self.profiles.read().await;
            guard
                .get(backend_name)
                .cloned()
                .ok_or_else(|| BackendError::ProfileNotFound {
                    backend_name: backend_name.to_owned(),
                })?
        };
        if profile.surface != surface::Surface::Resource {
            return Ok(ResourcePage::empty());
        }
        let dir = sftp::resolve_path(&profile.root, "")
            .map_err(|message| BackendError::InvalidSpec { message })?;
        let entries = tokio::time::timeout(profile.timeout, sftp::list(&profile.conn, &dir))
            .await
            .map_err(|_| BackendError::Transport {
                message: "SFTP list_resources timed out".to_owned(),
            })?
            .map_err(|message| BackendError::Transport { message })?;
        Ok(surface::entries_to_resource_page(
            &entries,
            &profile.root,
            &profile.uri_template,
        ))
    }

    /// Return completion candidates for a `{path}` template variable: list the
    /// `root` directory and keep the filenames that start with `prefix`.
    /// Non-resource bindings inherit the empty list.
    async fn complete_template_variable(
        &self,
        backend_name: &str,
        _variable_name: &str,
        prefix: &str,
        _config: &Value,
        _context: &BTreeMap<String, String>,
    ) -> Result<Vec<String>, BackendError> {
        let profile = {
            let guard = self.profiles.read().await;
            guard
                .get(backend_name)
                .cloned()
                .ok_or_else(|| BackendError::ProfileNotFound {
                    backend_name: backend_name.to_owned(),
                })?
        };
        if profile.surface != surface::Surface::Resource {
            return Ok(vec![]);
        }
        let dir = sftp::resolve_path(&profile.root, "")
            .map_err(|message| BackendError::InvalidSpec { message })?;
        let entries = tokio::time::timeout(profile.timeout, sftp::list(&profile.conn, &dir))
            .await
            .map_err(|_| BackendError::Transport {
                message: "SFTP complete_template_variable timed out".to_owned(),
            })?
            .map_err(|message| BackendError::Transport { message })?;
        Ok(surface::entries_to_completion_values(&entries, prefix, 100))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_op_host() -> Arc<dyn BackendHost> {
        Arc::new(NoOpHost)
    }

    fn minimal_spec() -> Value {
        json!({
            "op": "list",
            "host": "sftp.example.com",
            "username": "svc",
            "password": "${env.SFTP_PW}",
            "accept_unknown_host_key": true,
        })
    }

    #[test]
    fn kind_is_sftp() {
        assert_eq!(SftpBackendPlugin::new().kind(), "sftp");
    }

    #[tokio::test]
    async fn register_accepts_minimal_spec() {
        let plugin = SftpBackendPlugin::new();
        plugin
            .register_profile("files", &minimal_spec(), no_op_host())
            .await
            .expect("register");
        let profiles = plugin.profiles.read().await;
        assert_eq!(profiles.get("files").unwrap().op, SftpOp::List);
    }

    #[tokio::test]
    async fn register_rejects_unconfigured_host_key() {
        let plugin = SftpBackendPlugin::new();
        let mut spec = minimal_spec();
        spec.as_object_mut()
            .unwrap()
            .remove("accept_unknown_host_key");
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("no host key policy");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn register_rejects_cred_password() {
        let plugin = SftpBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["password"] = json!("cred://vault/sftp");
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("cred password");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn register_accepts_resource_surface() {
        let plugin = SftpBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["op"] = json!("get");
        spec["surface"] = json!("resource");
        spec["uri"] = json!("sftp://inbox/{path}");
        plugin
            .register_profile("inbox", &spec, no_op_host())
            .await
            .expect("register resource surface");
        let profiles = plugin.profiles.read().await;
        let p = profiles.get("inbox").unwrap();
        assert_eq!(p.surface, surface::Surface::Resource);
        assert_eq!(p.uri_template, "sftp://inbox/{path}");
        assert!(p.static_uri.is_none());
    }

    #[tokio::test]
    async fn register_rejects_uri_on_tool_surface() {
        let plugin = SftpBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["uri"] = json!("sftp://{path}");
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("uri on tool surface");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn list_resources_empty_for_tool_surface() {
        let plugin = SftpBackendPlugin::new();
        plugin
            .register_profile("files", &minimal_spec(), no_op_host())
            .await
            .expect("register");
        let page = BackendPlugin::list_resources(&plugin, "files", None)
            .await
            .expect("list_resources");
        assert!(page.resources.is_empty());
        assert!(page.next_cursor.is_none());
    }

    #[tokio::test]
    async fn complete_template_variable_empty_for_tool_surface() {
        let plugin = SftpBackendPlugin::new();
        plugin
            .register_profile("files", &minimal_spec(), no_op_host())
            .await
            .expect("register");
        let got = BackendPlugin::complete_template_variable(
            &plugin,
            "files",
            "path",
            "re",
            &json!({}),
            &BTreeMap::new(),
        )
        .await
        .expect("complete");
        assert!(got.is_empty());
    }

    #[tokio::test]
    async fn execute_unknown_profile_is_profile_not_found() {
        let plugin = SftpBackendPlugin::new();
        let req = BackendRequest {
            payload: vec![],
            headers: vec![],
            request_id: "rq-1".into(),
            session_id: None,
            identity: None,
            idempotency: None,
        };
        let err = plugin.execute("missing", req).await.expect_err("missing");
        assert!(matches!(err, BackendError::ProfileNotFound { .. }));
    }

    struct NoOpHost;

    #[async_trait]
    impl BackendHost for NoOpHost {
        async fn invoke_tool(
            &self,
            _ctx: &mcpg_plugin_protocol::BackendInvocationContext,
            _tool_name: &str,
            _args: &serde_json::Value,
        ) -> Result<serde_json::Value, mcpg_plugin_protocol::BackendHostError> {
            Err(mcpg_plugin_protocol::BackendHostError::NotImplemented)
        }
    }
}
