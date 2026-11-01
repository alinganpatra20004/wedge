<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) OpenEdge Labs -->
# Security

wedge is built to be safe without tuning: memory-safe Rust with no `unsafe`
code in wedge itself, TLS through rustls, strict request parsing, and limits
on everything a client controls. The design decisions and the threats they
answer are in the [threat model](../security/threat-model.md), with the test
that verifies each mitigation. Test and scan results for each release are in
the [verification log](../security/verification.md).

## Checklist for a public server

- [ ] Run the packaged service (systemd unit, OpenRC script or Windows
      service), never as root or LocalSystem.
- [ ] Keep `/etc/wedge` owned by root, readable by the `wedge` group only;
      private keys `chmod 640`.
- [ ] Serve HTTPS, with `redirect_http = true` and HSTS (on by default).
- [ ] Set browser security headers that fit your site in `[vhost.headers]`
      (see [Response headers](#response-headers)).
- [ ] Set `default_vhost` deliberately, or leave it unset so unknown hosts
      get 421.
- [ ] Keep the admin listener on loopback; if you need remote metrics, use a
      private network and a narrow `allow` list.
- [ ] Store the admin token and keys as `file:` references with tight
      permissions; never inline.
- [ ] Leave `[server.debug]` off. Never enable `log_secrets` on a production
      system.
- [ ] Run upstream applications on loopback or a private network; list a
      front load balancer in `trusted_proxies` only if it really is one.
- [ ] Verify downloads with `SHA256SUMS` (and `gh attestation verify`), and
      upgrade when a release fixes a security issue.

## Defaults that protect you

| Area | Default |
|---|---|
| Paths | no traversal, no hidden files, no directory listing, no symlinks |
| TLS | 1.2+ only, AEAD + forward secrecy only, no 0-RTT, no session tickets |
| Requests | header, URI, connection and time limits; bodies only on proxy routes |
| Responses | `nosniff`, `X-Frame-Options`, `Referrer-Policy`, HSTS on HTTPS; no `Server` header |
| Logs | no query strings, escaped fields, secrets never logged |
| Proxy | fixed IP:port upstreams, forged forwarding headers replaced, generic error pages |
| Admin | off; loopback only; token required for reload |

## Response headers

Every response gets `X-Content-Type-Options: nosniff`,
`X-Frame-Options: SAMEORIGIN` and
`Referrer-Policy: strict-origin-when-cross-origin`, plus HSTS over HTTPS.
Policies that depend on what a site loads are not on by default, because a
wrong one breaks pages. The configuration installed with each package sets a
strict version for the bundled welcome page; start from it:

```toml
[server]
listen = ["127.0.0.1:8080"]

[[vhost]]
name = "site"
root = "www"

[vhost.headers]
"Content-Security-Policy" = "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'"
"Permissions-Policy" = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
"Cross-Origin-Resource-Policy" = "same-origin"
```

| Header | Effect | Loosen it when |
|---|---|---|
| `Content-Security-Policy` | the browser loads scripts, styles, images and frames only from this site; blocks injected scripts (XSS) | the site uses a CDN, inline scripts or styles, or analytics: add those sources (for example `script-src 'self' https://cdn.example.com`) |
| `Permissions-Policy` | the page cannot use the camera, microphone, location, payment or USB APIs | the site really needs one of them |
| `Cross-Origin-Resource-Policy` | other sites cannot embed this site's images, scripts or fonts | you serve assets to other sites: use `cross-origin` |

Check a policy in the browser's developer console before deploying it, or
send it first as `Content-Security-Policy-Report-Only`. A value of `""`
removes a default header for a vhost. Proxied responses keep the headers
the application sets.

## Reporting a vulnerability

Please report security problems privately, as described in
[SECURITY.md](../../SECURITY.md). Do not open a public issue.
