# `mcpg-plugin-backend-sftp`

SFTP (SSH file transfer) backend binding plugin for mcpg (`kind: sftp`).
Lists a directory, reads a file, or writes a file over SSH (russh +
russh-sftp) as MCP **tools** and **resources**.

Part of the legacy → MCP bridge suite. FTP
(`suppaftp`) and SMB (`pavao`) are deferred follow-ons.

## How it works

One binding = one operation = one MCP tool (or resource):

| `op` | Behaviour | Returns |
|---|---|---|
| `list` (default) | List a directory's entries. | `{ entries, count }` |
| `get` | Read a file (capped at `max_bytes`). | `{ content, size }` |
| `put` | Write a file from the `content` (base64) / `text` argument. | `{ written }` |

The target path comes from the call's `path` argument, joined under the
operator-configured `root` — `..` segments are **rejected** before any SSH
call, so a caller cannot escape `root`. Connections use russh's pure-Rust SSH
crypto (no OpenSSL); a connection is opened per call.

## Configuration

| Field | Type | Default | Notes |
|---|---|---|---|
| `op` | `list`\|`get`\|`put` | `list` | The operation. |
| `host` | string (required) | — | SSH host. Operator-configured. |
| `port` | int | `22` | SSH port. |
| `username` | string (required) | — | SSH login user. |
| `password` | string (required) | — | Resolved via the gateway secret-resolver (`${env.X}` / `vault://…`). Per-caller `cred://` is **not** supported. (Public-key auth is a follow-on.) |
| `root` | string | `""` | Base dir the caller path joins under (`""` = the login's default dir). |
| `host_key_sha256` | string | — | Expected server host-key fingerprint (`SHA256:…`). |
| `accept_unknown_host_key` | bool | `false` | Accept any host key — **dev only**. With neither this nor `host_key_sha256`, registration fails closed. |
| `max_bytes` | int | `10485760` | Cap on bytes read (`get`) / written (`put`). |
| `timeout_ms` | int | `15000` | connect + auth + operation timeout. |
| `surface` | `tool`\|`resource` | `tool` | `tool` = list/get/put tools (unchanged). `resource` = expose files as MCP resources. |
| `uri` | string | `sftp://{path}` | Resource URI template (`surface: resource` only); `{path}` is each file's path under `root`. A value with no `{path}` pins a single static resource. |

### As a list/get tool

```yaml
mcp:
  capabilities:
    tools:
      - name: dropbox.read
        description: Read a file from the partner drop directory.
        input_schema:
          type: object
          properties: { path: { type: string } }
          required: [path]
        backend:
          kind: sftp
          op: get
          host: "sftp.partner.example.com"
          username: "svc-mcpg"
          password: "${env.SFTP_PASSWORD}"
          host_key_sha256: "SHA256:abc123…"      # pin the server key
          root: "/outbound"
```

### As a put tool

```yaml
      backend:
        kind: sftp
        op: put
        host: "sftp.partner.example.com"
        username: "svc-mcpg"
        password: "${env.SFTP_PASSWORD}"
        host_key_sha256: "SHA256:abc123…"
        root: "/inbound"
        # the tool's `content` (base64) or `text` argument becomes the file body
```

### As resources (browse an inbox directory)

Set `surface: resource` to expose the files under `root` as MCP **resources**.
`resources/list` enumerates the directory (one resource per regular file —
directories and symlinks are skipped); `resources/read` fetches a file's body;
`{path}` completions come from the same directory listing.

```yaml
mcp:
  capabilities:
    resource_templates:
      - name: partner-inbox
        description: Files dropped in the partner inbox.
        uri_template: "sftp://inbox/{path}"
        backend:
          kind: sftp
          surface: resource              # files-as-resources
          uri: "sftp://inbox/{path}"     # {path} = each file's path under root
          host: "sftp.partner.example.com"
          username: "svc-mcpg"
          password: "${env.SFTP_PASSWORD}"
          host_key_sha256: "SHA256:abc123…"
          root: "/inbound/inbox"
```

A `resources/read` returns the MCP resource-contents shape:

```jsonc
{
  "contents": [
    {
      "uri": "sftp://inbox/report.csv",
      "mimeType": "text/csv",            // best-effort from the extension
      "text": "id,name\n1,alpha\n"       // UTF-8 → text; binary → base64 `blob`
    }
  ]
}
```

The default `surface: tool` keeps the list/get/put **tools** exactly as below.

## Response envelope

```jsonc
{
  "toolName": "dropbox.list",
  "profile":  "dropbox.list",
  "request":  { "op": "list", "host": "sftp.partner.example.com", "path": "" },
  "response": {                       // op: list
    "entries": [ { "name": "report.csv", "type": "file", "size": 4096,
                   "permissions": 33188, "mtime": 1717977600 } ],
    "count": 1, "content": null, "size": null, "written": null, "durationMs": 80
  },
  "downstreamError": null,            // non-null ⇒ isError:true (sftp_error / transport_error)
  "downstreamErrors": [],
  "error": null
}
```

`op: get` populates `content` (`{text}` / `{base64}`) + `size`; `op: put`
populates `written`.

## Security

- **Path-traversal defense.** The caller `path` is joined under `root` with
  `..` segments rejected before any SSH call.
- **Host-key verification fails closed.** Registration requires a pinned
  `host_key_sha256` or an explicit `accept_unknown_host_key: true` (dev only)
  — there is no silent trust-on-first-use.
- **No plaintext secrets.** The `password` resolves through the gateway
  secret-resolver; per-caller `cred://` is rejected.
- **Size cap.** `get`/`put` are bounded by `max_bytes`.
- **Pure-Rust SSH.** russh — no OpenSSL / native-tls.

## Directory watch (`watch_strategy`, kind `sftp_dir_poll`)

A second entity watches a directory **by polling**. SFTP has no native
change-push channel, so the watcher lists the directory on a cadence and
compares each listing with the last one the gateway stored. A resource watch
gets `notifications/resources/updated` when a file is added, removed, or
modified; an MCP Events source gets each such file as the shared
`object.changed` event (see MCP Events, "Files and objects").

Each watcher carries its own connection plus the directory to watch:

| Field | Type | Default | Notes |
|---|---|---|---|
| `host` | string (required) | — | SSH host. |
| `port` | int | `22` | SSH port. |
| `username` | string (required) | — | SSH login user. |
| `password` | string (required) | — | Resolved via the gateway secret-resolver (`${env.X}` / `vault://…`). `cred://` is rejected. |
| `root` | string | `""` | Base dir the watched `path` joins under. |
| `path` | string | `""` | Directory under `root` to watch (`""` = `root`). `..` segments are **rejected**. |
| `host_key_sha256` | string | — | Pinned server host-key fingerprint (`SHA256:…`). |
| `accept_unknown_host_key` | bool | `false` | Accept any host key — **dev only**. With neither this nor `host_key_sha256`, the watch is rejected. |
| `interval_ms` | int | `60000` | Listing cadence (at least 250 ms). |
| `timeout_ms` | int | `10000` | Budget of one listing: connect and every directory. |
| `recursive` | bool | `false` | Go into subdirectories, at most 1000 of them. |
| `pattern` | string | — | Keep only the files whose path relative to the directory matches this glob: `*` stays in a directory, `**` crosses them (`**/*.csv`). |
| `max_files` | int | `10000` | Most files listed (1 to 100000); past it the first in path order are kept, with a warning. |
| `start_at` | `now` \| `existing` | `now` | `now`: the files there at a first start are the baseline. `existing`: each is reported as created. |
| `snapshot_bytes` | int | `131072` | Largest snapshot of the listing an event carries, for an exact restart (at most 196608). |
| `max_in_flight` | int | `256` | Most changes emitted ahead of the gateway's acknowledgements (1 to 1000). |
| `ack_timeout_ms` | int | `60000` | How long a change waits for its acknowledgement before it is offered again. |

Each listing opens one connection, lists `path` (and its subdirectories),
and drops the connection. Keys are file paths relative to `path`, with `/`
between parts; `location` is `sftp://host:port/<directory>`, without
credentials. A directory that cannot be listed fails the whole listing, and
the next interval tries again, so a part that cannot be read is never
reported as deleted. An unreachable server does not fail the watch: it is
listed again at the next interval. SFTP reports a file's time to the second,
so an overwrite that keeps the size within the same second is not seen.

As a resource watch:

```yaml
mcp:
  capabilities:
    resources:
      - uri: sftp://partner/incoming
        name: Partner drop directory
        watch:
          strategy:
            type: plugin
            kind: sftp_dir_poll
            host: "sftp.partner.example.com"
            username: "svc-mcpg"
            password: "${env.SFTP_PASSWORD}"
            host_key_sha256: "SHA256:abc123…"
            root: "/outbound"
            path: "incoming"
            interval_ms: 30000
```

As an MCP Events source, each file as `object.changed`:

```yaml
mcp:
  capabilities:
    events:
      - name: partner.drops
        description: A CSV arrived in, changed in, or left the partner's drop folder.
        source:
          watch:
            strategy:
              type: plugin
              kind: sftp_dir_poll
              host: "sftp.partner.example.com"
              username: "svc-mcpg"
              password: "${env.SFTP_PASSWORD}"
              host_key_sha256: "SHA256:abc123…"
              root: "/outbound"
              path: "incoming"
              recursive: true
              pattern: "**/*.csv"
            event_type: object.changed
```

## Build / test

```bash
cargo build  -p mcpg-plugin-backend-sftp
cargo test   -p mcpg-plugin-backend-sftp                              # unit tests
cargo test   -p mcpg-plugin-backend-sftp --features integration-tests # atmoz/sftp (docker)
cargo clippy -p mcpg-plugin-backend-sftp --all-targets -- -D warnings
```

## Scope / deferred

- **Public-key auth** — v1 is password auth; key auth is a follow-on.
- **Recursive / streaming transfers, rename/mkdir/rm** — v1 is single-file
  `list` / `get` / `put`.
- **Connection pooling** — v1 connects per call (SSH handshake per op).
