<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) Alingan Patra -->
# Troubleshooting

Start with `wedge check-config -c <file>`: most problems are configuration
errors, and it reports all of them at once.

## wedge does not start

| Message | Cause and fix |
|---|---|
| `configuration does not match the schema: /path: ...` | A key is misspelt, has the wrong type or is out of range. The JSON pointer shows where; see the [reference](configuration-reference.md). |
| `secrets must be references: "env:NAME" or "file:/path"` | A secret (key, token) was written inline. Put it in a file or environment variable and reference it. |
| `cannot listen on 0.0.0.0:80: permission denied` | Ports below 1024 need privileges. The systemd unit and the container grant `CAP_NET_BIND_SERVICE`; when running by hand use a port above 1024. |
| `cannot listen on ...: address in use` | Another program uses the port: `ss -ltnp` (Linux) or `Get-NetTCPConnection -State Listen` (Windows). |
| `document root of vhost "x" is not accessible` | The folder does not exist, or the `wedge` user cannot read it. |
| `vhost "x": ... KeyMismatch` | The private key does not belong to the certificate. |
| `vhost "x": file:...: not a valid PEM private key` | The file is not PEM, or is encrypted. wedge needs an unencrypted key file readable only by root and wedge. |
| `listen_tls is set but no vhost has a [vhost.tls] certificate` | Add a certificate to at least one vhost, or remove `listen_tls`. |
| `... is not under Program Files` (Windows service install) | Copy `wedge.exe` to `C:\Program Files\wedge\` first. |

## Requests fail

| Status | Meaning |
|---|---|
| `400 Bad Request` | Missing or malformed `Host`, a path with `..` or encoded separators, both `Content-Length` and `Transfer-Encoding`, or a malformed chunked body. |
| `404 Not Found` | No such file, a hidden file, a directory without `index.html`, or a proxy-only vhost with no matching route. |
| `405 Method Not Allowed` | Static vhosts accept only GET, HEAD and OPTIONS. |
| `413 Payload Too Large` | A body on a static route, or larger than the route's `max_body_bytes`. |
| `414 URI Too Long` / `431 Request Header Fields Too Large` | Over `max_uri_bytes`, `max_header_bytes` or `max_headers`. |
| `421 Misdirected Request` | No vhost claims the host and there is no `default_vhost`; or on HTTPS, the `Host` does not match the certificate's vhost. |
| `502 Bad Gateway` | The upstream refused the connection or sent an invalid response. The error log names the server. |
| `503 Service Unavailable` | No upstream server is healthy, or the request took longer than `request_timeout_secs`. |
| `504 Gateway Timeout` | The upstream did not answer within `response_timeout_secs`. |

## TLS problems

- *Browser says the certificate is for a different site*: the client's name
  matches no vhost with a certificate, so the `default_vhost`'s certificate
  was used. Check `hosts` and the certificate's names; wedge warns at startup
  about names a certificate does not cover.
- *Handshake fails right away*: the client offers only TLS 1.0/1.1 or weak
  ciphers (wedge offers TLS 1.2+ with forward-secret AEAD ciphers only), or
  `min_version = "1.3"` excludes it.
- Run with `RUST_LOG=debug` to log each handshake failure with its reason.

## Reload did not take effect

`wedge reload` and `systemctl reload` report errors to the log
(`journalctl -u wedge`); the old configuration keeps serving. A message such
as `server.listen cannot change on reload` means a restart is needed.

## Seeing exactly what happens

Turn on the [debug capture](debug-capture.md) on a test system: it records
each request at every layer, with the source file that handled each step.
