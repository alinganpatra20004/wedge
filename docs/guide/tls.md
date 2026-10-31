<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) Alingan Patra -->
# TLS and HTTPS

wedge terminates TLS itself with rustls: TLS 1.2 and 1.3 only, forward-secret
AEAD cipher suites only, no renegotiation, no compression. There is nothing to
switch off to make it safe.

## A certificate per site

TLS listeners are separate from plain ones. Each vhost that should be served
over HTTPS gets a certificate; wedge picks it from the name the client sends
(SNI), using the same exact and wildcard rules as `hosts`:

```toml
[server]
listen = ["0.0.0.0:80"]
listen_tls = ["0.0.0.0:443"]
default_vhost = "main"

[[vhost]]
name = "main"
root = "/srv/main"
hosts = ["example.com", "www.example.com"]

[vhost.tls]
cert = "file:/etc/wedge/tls/example.com.fullchain.pem"
key = "file:/etc/wedge/tls/example.com.key"

[[vhost]]
name = "blog"
root = "/srv/blog"
hosts = ["blog.example.com"]

[vhost.tls]
cert = "file:/etc/wedge/tls/blog.example.com.fullchain.pem"
key = "file:/etc/wedge/tls/blog.example.com.key"
```

- `cert` is the PEM chain, leaf certificate first (the "fullchain" file most
  certificate authorities and ACME clients produce).
- `key` is the PEM private key (PKCS#8, PKCS#1 or SEC1). Keep it readable by
  the `wedge` user only: `chmod 640`, owned by `root:wedge`. On Unix, wedge
  warns at startup if the key file is readable by others.
- Both are secret references (`file:` or `env:`), never inline PEM.

At startup wedge checks that each key matches its certificate (a mismatch is
an error) and warns if a vhost's host names are not covered by its
certificate.

A client that sends no SNI, or a name no vhost claims, gets the
`default_vhost`'s certificate; if that vhost has none, the handshake fails.

### The Host must match the certificate

On a TLS connection, the `Host` of every request must belong to the vhost
whose certificate was presented. Otherwise wedge answers
`421 Misdirected Request`, which tells browsers that reuse HTTP/2 connections
to open a new one. This prevents domain fronting and cross-site confusion.

## Minimum version

```toml
[server.tls]
min_version = "1.3"   # default "1.2"
```

## HSTS and the HTTP to HTTPS redirect

On TLS responses wedge sends `Strict-Transport-Security: max-age=31536000`
(one year) by default; it is never sent over plain HTTP. Plain-HTTP requests
can be redirected to HTTPS per vhost:

```toml
[server]
listen = ["0.0.0.0:80"]
listen_tls = ["0.0.0.0:443"]

[[vhost]]
name = "main"
root = "/srv/main"
hosts = ["example.com"]

[vhost.tls]
cert = "file:/etc/wedge/tls/example.com.fullchain.pem"
key = "file:/etc/wedge/tls/example.com.key"
hsts_max_age_secs = 31536000      # 0 turns HSTS off
hsts_include_subdomains = false   # only if every subdomain serves HTTPS
redirect_http = true              # http://... gets 308 to https://...
```

The redirect keeps the path and query. Its host is the request's host only if
that name belongs to the vhost; otherwise wedge uses the vhost's first host
name, so a forged `Host` cannot turn it into an open redirect.

## Security headers

Every response gets `X-Content-Type-Options: nosniff`,
`X-Frame-Options: SAMEORIGIN` and
`Referrer-Policy: strict-origin-when-cross-origin`. Add, replace or remove
headers per vhost; an empty value removes a default:

```toml
[[vhost]]
name = "app"
root = "/srv/app"
hosts = ["app.example.com"]

[vhost.headers]
"Content-Security-Policy" = "default-src 'self'"
"Permissions-Policy" = "camera=(), microphone=()"
"X-Frame-Options" = ""            # allow framing for this site
```

Headers that wedge computes or that control message framing
(`Content-Length`, `Content-Type`, `ETag`, `Strict-Transport-Security`,
`Transfer-Encoding`, ...) cannot be set here; the configuration check says
which.

## Renewing certificates

Replace the files and reload (`systemctl reload wedge` or `wedge reload`).
The new certificates are loaded and checked before they are used; if one is
broken, wedge keeps the old ones and logs why. Automatic certificates (ACME)
are planned for a later release.
