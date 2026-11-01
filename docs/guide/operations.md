<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) OpenEdge Labs -->
# Operations

## Logs

wedge writes two kinds of log lines to standard error (the systemd journal
under systemd, `C:\ProgramData\wedge\logs\wedge.log` for the Windows service):

- **Access log**: one line per request, target `wedge::access`, with client
  address, TLS flag, method, path, HTTP version, host, status, bytes,
  duration and user agent. The query string is never logged (it often holds
  tokens), and every field is escaped so a request cannot forge log lines.
- **Error log**: everything else (startup, reloads, upstream failures,
  warnings).

Control them with environment variables:

| Variable | Effect |
|---|---|
| `RUST_LOG=info,rustls=error` | the default (TLS library warnings about client mistakes are hidden; a client could otherwise add one per connection) |
| `RUST_LOG=info,wedge::access=off` | error log only |
| `RUST_LOG=warn,wedge::access=info` | access log plus warnings |
| `RUST_LOG=debug` | detailed, including TLS handshake failures |
| `WEDGE_LOG_FORMAT=json` | one JSON object per line, for log shippers |

With systemd: `systemctl edit wedge`, then add
`Environment=WEDGE_LOG_FORMAT=json` under `[Service]`.

## Metrics

Metrics are served by a separate admin listener, off by default:

```toml
[server.admin]
listen = "127.0.0.1:9900"
allow = ["127.0.0.0/8", "::1"]    # the default: loopback only
```

`GET http://127.0.0.1:9900/metrics` returns Prometheus text. Clients outside
`allow` are disconnected before any HTTP is read, and requests whose `Host`
is not an IP address or `localhost` get 421, so a web page cannot reach the
admin listener by pointing a DNS name at 127.0.0.1. Keep the admin listener
on loopback or a management network; wedge warns if it is not on loopback,
and refuses to share an address with a public listener.

| Metric | Type | Labels |
|---|---|---|
| `wedge_http_requests_total` | counter | `vhost`, `method`, `status` (class: `2xx`, `4xx`, ...) |
| `wedge_http_request_duration_seconds` | histogram | `vhost` |
| `wedge_connections_open` | gauge | |
| `wedge_connections_total` | counter | `tls` |
| `wedge_tls_handshake_failures_total` | counter | |
| `wedge_upstream_requests_total` | counter | `upstream`, `outcome` (`ok`, `connect_error`, `error`, `timeout`) |
| `wedge_upstream_server_up` | gauge | `upstream`, `server` |
| `wedge_build_info` | gauge | `version` |

Label values come from your configuration or from fixed sets, never from the
request, so a client cannot create unlimited series. Requests that matched no
vhost are counted under `vhost="-"`. Counters restart from zero after a
reload.

Prometheus scrape configuration:

```yaml
scrape_configs:
  - job_name: wedge
    static_configs:
      - targets: ["127.0.0.1:9900"]
```

## Reload

Three ways to reload the configuration without dropping connections:

| How | Where |
|---|---|
| `systemctl reload wedge` (sends SIGHUP) | Linux with systemd |
| `rc-service wedge reload` | Alpine / OpenRC |
| `sc.exe control wedge paramchange` | Windows service |
| `wedge reload -c wedge.toml` | anywhere, through the admin listener |

`wedge reload` needs a token on the admin listener. Store it in a file only
root and wedge can read, and reference it:

```toml
[server.admin]
listen = "127.0.0.1:9900"
token = "file:/etc/wedge/admin-token"
```

```sh
sudo sh -c 'head -c 32 /dev/urandom | base64 > /etc/wedge/admin-token'
sudo chown root:wedge /etc/wedge/admin-token && sudo chmod 640 /etc/wedge/admin-token
wedge reload -c /etc/wedge/wedge.toml
```

The same endpoint is `POST /-/reload` with `Authorization: Bearer <token>`.
Without a token, HTTP reload is off (404).

A reload reads and validates everything, loads certificates and checks
document roots, then swaps the new configuration in at once. Requests in
progress finish with the configuration they started with. If anything fails,
wedge keeps serving the old configuration and reports why
(`422` with the reason for `wedge reload`). Reloads are serialized and limited
to one per second. Listeners, `[server.limits]`, `[server.admin]` and
`[server.debug]` cannot change on reload; restart for those.

## Limits

The defaults are safe for a server on the internet. Raise them only for a
reason:

```toml
[server.limits]
header_timeout_secs = 10      # time to receive a request head (and the TLS handshake)
idle_timeout_secs = 60        # a connection with no traffic is closed
request_timeout_secs = 30     # time to produce a response head
shutdown_grace_secs = 30      # time in-flight requests get on shutdown
max_connections = 1024        # further clients wait in the kernel backlog
max_header_bytes = 16384      # request head size (431 above it)
max_headers = 100             # header count (431 above it)
max_uri_bytes = 8192          # request target length (414 above it)
h2_max_concurrent_streams = 100
```

Slow clients (slowloris), header floods, oversized URIs and HTTP/2 stream
floods (including rapid reset) are cut off by these limits.
