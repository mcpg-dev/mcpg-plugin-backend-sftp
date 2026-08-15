//! MCP surface shaping for the SFTP backend's resource binding.
//!
//! A binding is a tool by default; the operator may instead place it under
//! `mcp.capabilities.resources[]` / `resource_templates[]`. The gateway routes
//! those reads to the same `execute()` path but applies a strict decoder over
//! the response body — `{contents:[…]}` for `resources/read`. The tool surface
//! keeps the raw envelope byte-for-byte.
//!
//! On the resource surface each file under the binding's `root`/`path` directory
//! is one MCP resource: its URI is the operator's `uri` template with `{path}`
//! filled by the file's path, its name is the filename, its `mimeType` is a
//! best-effort guess from the extension, and `size` rides along as the
//! description. A `resources/read` carries the requested resource URI as a
//! top-level `uri` argument (the gateway materializes it from the read request);
//! the binding maps it back to a file path through the same template.

use mcpg_plugin_protocol::{ListedResource, ResourcePage};
use serde::Deserialize;
use serde_json::{Value, json};

/// Default URI template — `{path}` is replaced by the file path under `root`.
pub const DEFAULT_URI_TEMPLATE: &str = "sftp://{path}";

/// Which MCP surface a binding serves. `Tool` (default) keeps the historical
/// tool-shaped envelope byte-for-byte; `Resource` reshapes a `get` into the
/// `resources/read` body the gateway decoder requires and exposes the `root`
/// directory listing through `list_resources`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    /// Tool surface — unchanged envelope.
    #[default]
    Tool,
    /// `resources/read` surface — `{contents:[{uri,mimeType,text|blob}]}`.
    Resource,
}

impl Surface {
    /// Stable label for diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            Surface::Tool => "tool",
            Surface::Resource => "resource",
        }
    }
}

/// Fill a URI template's `{path}` placeholder with a concrete file path.
pub fn uri_for_path(template: &str, path: &str) -> String {
    template.replace("{path}", path)
}

/// Recover the file path from a resource URI produced by `template`. When the
/// URI carries the template's literal prefix (everything before `{path}`) the
/// remainder is the path; otherwise the whole URI is treated as the path so a
/// hand-pinned static `uri` still resolves.
pub fn path_from_uri(template: &str, uri: &str) -> String {
    if let Some((prefix, _)) = template.split_once("{path}")
        && let Some(rest) = uri.strip_prefix(prefix)
    {
        return rest.to_owned();
    }
    uri.to_owned()
}

/// Best-effort IANA media type from a file path's extension. Returns `None`
/// when the extension is unknown so the resource omits `mimeType` rather than
/// guessing wrong.
pub fn mime_for_path(path: &str) -> Option<&'static str> {
    let ext = path
        .rsplit('/')
        .next()?
        .rsplit_once('.')?
        .1
        .to_ascii_lowercase();
    let m = match ext.as_str() {
        "txt" | "log" => "text/plain",
        "json" => "application/json",
        "csv" => "text/csv",
        "xml" => "application/xml",
        "yaml" | "yml" => "application/yaml",
        "html" | "htm" => "text/html",
        "md" => "text/markdown",
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "zip" => "application/zip",
        "gz" => "application/gzip",
        "tar" => "application/x-tar",
        _ => return None,
    };
    Some(m)
}

/// Project a directory listing (the `entries` JSON from [`crate::sftp::list`])
/// into a [`ResourcePage`]: one resource per regular file (directories and
/// symlinks are skipped — only files are readable). The resource URI is the
/// `uri` template with `{path}` filled by the file's path joined under
/// `dir_path`, the name is the filename, the `mimeType` is guessed from the
/// extension, and the byte size rides along as the description. Entries missing
/// a `name` are skipped — a malformed listing never poisons the whole surface.
/// SFTP directory listings are returned whole, so the page is never truncated
/// (`next_cursor == None`).
pub fn entries_to_resource_page(
    entries: &[Value],
    dir_path: &str,
    uri_template: &str,
) -> ResourcePage {
    let mut resources: Vec<ListedResource> = Vec::with_capacity(entries.len());
    for entry in entries {
        let Value::Object(obj) = entry else { continue };
        if obj.get("type").and_then(Value::as_str) != Some("file") {
            continue;
        }
        let Some(name) = obj.get("name").and_then(Value::as_str) else {
            continue;
        };
        let file_path = join_under(dir_path, name);
        let description = obj
            .get("size")
            .and_then(Value::as_u64)
            .map(|n| format!("{n} bytes"));
        resources.push(ListedResource {
            uri: uri_for_path(uri_template, &file_path),
            name: Some(name.to_owned()),
            description,
            mime_type: mime_for_path(name).map(str::to_owned),
        });
    }
    ResourcePage {
        resources,
        next_cursor: None,
    }
}

/// Extract completion candidates for a `{path}` prefix from a directory
/// listing: filenames (files and directories both — a caller may be navigating
/// toward a subdirectory) that start with `prefix`, capped at `max`.
pub fn entries_to_completion_values(entries: &[Value], prefix: &str, max: usize) -> Vec<String> {
    let mut out = Vec::with_capacity(entries.len().min(max));
    for entry in entries {
        if out.len() >= max {
            break;
        }
        if let Value::Object(obj) = entry
            && let Some(name) = obj.get("name").and_then(Value::as_str)
            && name.starts_with(prefix)
        {
            out.push(name.to_owned());
        }
    }
    out
}

/// Resolve the file path for a `resources/read`: a static binding `uri` wins
/// (mapped back through the template), otherwise the gateway-supplied `uri`
/// argument, otherwise a bare `path` argument. Returns `None` when none is
/// available so the caller can surface a clean error envelope instead of
/// emitting a decoder-invalid `{contents}` body.
pub fn resolve_resource_path(
    template: &str,
    static_uri: Option<&str>,
    arguments: &Value,
) -> Option<String> {
    if let Some(u) = static_uri
        && !u.trim().is_empty()
    {
        return Some(path_from_uri(template, u));
    }
    if let Some(u) = arguments
        .get("uri")
        .and_then(Value::as_str)
        .filter(|u| !u.trim().is_empty())
    {
        return Some(path_from_uri(template, u));
    }
    arguments
        .get("path")
        .and_then(Value::as_str)
        .filter(|p| !p.trim().is_empty())
        .map(str::to_owned)
}

/// Wrap a fetched file into the `resources/read` contract body —
/// `{contents:[{uri, mimeType, text|blob}]}`. `content` is the
/// [`crate::sftp::decode_content`] projection (`{text}` for UTF-8, `{base64}`
/// otherwise); a base64 body becomes the MCP `blob` field. The `mimeType` is
/// guessed from the URI's path.
pub fn resource_contents_body(uri: &str, path: &str, content: &Value) -> Value {
    let mut entry = serde_json::Map::new();
    entry.insert("uri".into(), json!(uri));
    if let Some(mime) = mime_for_path(path) {
        entry.insert("mimeType".into(), json!(mime));
    }
    if let Some(text) = content.get("text").and_then(Value::as_str) {
        entry.insert("text".into(), json!(text));
    } else if let Some(b64) = content.get("base64").and_then(Value::as_str) {
        entry.insert("blob".into(), json!(b64));
    } else {
        // Unrecognized projection — emit an empty text body rather than a
        // decoder-invalid entry with neither `text` nor `blob`.
        entry.insert("text".into(), json!(""));
    }
    json!({ "contents": [Value::Object(entry)] })
}

/// Join `name` under `dir` for the resource URI's `{path}`. An empty `dir`
/// (the login's default directory) yields the bare filename.
fn join_under(dir: &str, name: &str) -> String {
    let dir = dir.trim_end_matches('/');
    if dir.is_empty() || dir == "." {
        name.to_owned()
    } else {
        format!("{dir}/{name}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn surface_default_is_tool() {
        assert_eq!(Surface::default(), Surface::Tool);
    }

    #[test]
    fn surface_parses_snake_case() {
        let s: Surface = serde_json::from_value(json!("resource")).unwrap();
        assert_eq!(s, Surface::Resource);
        let s: Surface = serde_json::from_value(json!("tool")).unwrap();
        assert_eq!(s, Surface::Tool);
    }

    #[test]
    fn uri_template_fills_path() {
        assert_eq!(
            uri_for_path("sftp://{path}", "inbox/a.txt"),
            "sftp://inbox/a.txt"
        );
        assert_eq!(
            uri_for_path("files://drop/{path}", "a.csv"),
            "files://drop/a.csv"
        );
    }

    #[test]
    fn path_recovers_from_uri() {
        assert_eq!(
            path_from_uri("sftp://{path}", "sftp://inbox/a.txt"),
            "inbox/a.txt"
        );
        assert_eq!(
            path_from_uri("files://drop/{path}", "files://drop/a.csv"),
            "a.csv"
        );
        // A URI without the template prefix is treated as the whole path.
        assert_eq!(path_from_uri("sftp://{path}", "other://x"), "other://x");
    }

    #[test]
    fn mime_guessed_from_extension() {
        assert_eq!(mime_for_path("report.csv"), Some("text/csv"));
        assert_eq!(mime_for_path("a/b/data.json"), Some("application/json"));
        assert_eq!(mime_for_path("noext"), None);
        assert_eq!(mime_for_path("archive.unknownext"), None);
    }

    fn listing() -> Vec<Value> {
        vec![
            json!({ "name": "report.csv", "type": "file", "size": 4096, "mtime": 1 }),
            json!({ "name": "notes.txt", "type": "file", "size": 12, "mtime": 2 }),
            json!({ "name": "subdir", "type": "dir", "size": 0, "mtime": 3 }),
            json!({ "name": "link", "type": "symlink", "size": 0, "mtime": 4 }),
            json!({ "type": "file", "size": 9 }), // missing name → skipped
        ]
    }

    #[test]
    fn list_resources_shapes_files_only() {
        let page = entries_to_resource_page(&listing(), "/inbox", "sftp://{path}");
        assert_eq!(page.resources.len(), 2);
        let r0 = &page.resources[0];
        assert_eq!(r0.uri, "sftp:///inbox/report.csv");
        assert_eq!(r0.name.as_deref(), Some("report.csv"));
        assert_eq!(r0.mime_type.as_deref(), Some("text/csv"));
        assert_eq!(r0.description.as_deref(), Some("4096 bytes"));
        assert_eq!(page.resources[1].uri, "sftp:///inbox/notes.txt");
        assert!(page.next_cursor.is_none());
    }

    #[test]
    fn list_resources_empty_root_uses_bare_name() {
        let page = entries_to_resource_page(&listing(), "", "sftp://{path}");
        assert_eq!(page.resources[0].uri, "sftp://report.csv");
    }

    #[test]
    fn completion_filters_by_prefix_and_caps() {
        let entries = vec![
            json!({ "name": "report.csv", "type": "file" }),
            json!({ "name": "readme.md", "type": "file" }),
            json!({ "name": "notes.txt", "type": "file" }),
            json!({ "name": "reports", "type": "dir" }),
        ];
        let got = entries_to_completion_values(&entries, "re", 10);
        assert_eq!(got, vec!["report.csv", "readme.md", "reports"]);
        let capped = entries_to_completion_values(&entries, "re", 1);
        assert_eq!(capped, vec!["report.csv"]);
    }

    #[test]
    fn resolve_path_static_uri_wins() {
        let args = json!({ "uri": "sftp://from-arg.txt" });
        assert_eq!(
            resolve_resource_path("sftp://{path}", Some("sftp://static.txt"), &args).as_deref(),
            Some("static.txt")
        );
    }

    #[test]
    fn resolve_path_falls_back_to_arg_uri_then_path() {
        let args = json!({ "uri": "sftp://inbox/a.txt" });
        assert_eq!(
            resolve_resource_path("sftp://{path}", None, &args).as_deref(),
            Some("inbox/a.txt")
        );
        let args = json!({ "path": "inbox/b.txt" });
        assert_eq!(
            resolve_resource_path("sftp://{path}", None, &args).as_deref(),
            Some("inbox/b.txt")
        );
        assert_eq!(
            resolve_resource_path("sftp://{path}", None, &json!({})),
            None
        );
        assert_eq!(
            resolve_resource_path("sftp://{path}", Some("  "), &json!({})),
            None
        );
    }

    #[test]
    fn resource_body_text_shape() {
        let body = resource_contents_body("sftp://a.txt", "a.txt", &json!({ "text": "hi" }));
        let contents = body["contents"].as_array().expect("contents array");
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0]["uri"], json!("sftp://a.txt"));
        assert_eq!(contents[0]["text"], json!("hi"));
        assert_eq!(contents[0]["mimeType"], json!("text/plain"));
        assert!(contents[0].get("blob").is_none());
    }

    #[test]
    fn resource_body_blob_shape() {
        let body = resource_contents_body("sftp://a.png", "a.png", &json!({ "base64": "//4=" }));
        let contents = body["contents"].as_array().expect("contents array");
        assert_eq!(contents[0]["blob"], json!("//4="));
        assert_eq!(contents[0]["mimeType"], json!("image/png"));
        assert!(contents[0].get("text").is_none());
    }
}
