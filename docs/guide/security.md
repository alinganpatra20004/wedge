<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) Alingan Patra -->
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
- [ ] Add a `Content-Security-Policy` that fits your site in
      `[vhost.headers]`.
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

## Reporting a vulnerability

Please report security problems privately, as described in
[SECURITY.md](../../SECURITY.md). Do not open a public issue.
