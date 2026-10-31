# wedge threat model

Method: STRIDE per trust boundary, mapped to OWASP Top 10 (2021) and ASVS 4.0.3
Level 2. Each phase adds a section before implementation; mitigations link to
the tests that enforce them. Status values: planned, implemented, verified.

## System overview

```
 client ──(untrusted network)──▶ listener ──▶ HTTP parser (hyper)
                                              │
                                              ▼
                                   vhost router ──▶ static file handler ──▶ filesystem (document roots)
                                              └──▶ reverse proxy ──▶ upstreams      (Phase 4)
 operator ──▶ wedge.toml + conf.d/ ──▶ config loader (Phase 1)
```

Trust boundaries:

1. **Network → server.** Every byte from clients is hostile.
2. **Server → filesystem.** Only files inside a vhost's document root may be read.
3. **Operator → config.** The operator is trusted, but config files may be
   world-readable, so they must not contain secrets.
4. **Server → upstreams** (Phase 4). Upstream responses are semi-trusted.

## Phase 1: configuration

| Threat | STRIDE | OWASP / ASVS | Mitigation | Status |
|---|---|---|---|---|
| Secrets committed or leaked through config files | I | A02, A05 / V6.4.1, V14.1.3 | `SecretRef` accepts only `env:`/`file:` references; inline values rejected | verified (`secret::tests`) |
| Secret values leaked in error messages or logs | I | A09 / V7.1.1 | Redacted `Debug`; errors name the reference only; schema pattern errors omit values | verified (`secret::tests`, `schema::tests`, `secret_ref` fuzz target) |
| Typos silently disable a security setting | T | A05 / V14.1.1 | Unknown keys rejected (schema `additionalProperties: false` and `deny_unknown_fields`) | verified |
| Oversized or malformed config exhausts memory or crashes | D | A05 / V5.1 | 1 MiB file cap, 64 KiB secret cap, UTF-8 check; parser fuzzed | verified (`config_parse` fuzz target) |

## Phase 2: HTTP/1.1 + HTTP/2 static server

| # | Threat | STRIDE | OWASP / ASVS | Mitigation | Status |
|---|---|---|---|---|---|
| T2.1 | Path traversal (`../`, encoded `%2e%2e`, backslashes, NUL, absolute paths, Windows drive letters and ADS `file::$DATA`) reads files outside the root | I | A01 / V12.3.1, V12.3.2 | Decode once, reject NUL, reject any `..` segment, backslash or drive prefix; join with root; canonicalize; require the canonical path to start with the canonical root | verified (`path::tests`, `tests/files.rs`) |
| T2.2 | Symlink inside the root points outside it | I | A01 / V12.3.1 | Canonical-prefix check after resolving symlinks; option `follow_symlinks = false` (default) | verified (`path::tests`, `tests/files.rs`) |
| T2.3 | Directory listing exposes files | I | A05 / V12.5.1 | No directory listing; directories serve `index.html` or 404 | verified (`path::tests`, `tests/files.rs`) |
| T2.4 | Hidden files (`.git`, `.env`, `.htpasswd`) served | I | A05 / V12.5.1 | Any path segment starting with `.` returns 404 (except `/.well-known/`) | verified (`path::tests`, `tests/files.rs`) |
| T2.5 | Slowloris / slow body / idle keep-alive exhausts connections | D | A05 / V11.1.4 | Header read timeout, socket idle timeout (covers clients that send nothing), request timeout, max concurrent connections | verified (`tests/server.rs`: slowloris, idle client, connection cap) |
| T2.6 | Oversized headers, many headers, long URIs | D | A05 / V13.1.3 | Max header bytes (16 KiB), max header count (100), max URI length (8 KiB): 431/414 responses | verified (`tests/server.rs`: 414, 431 size, 431 count) |
| T2.7 | Request bodies on a static server | D | A05 | Static handler accepts only GET/HEAD/OPTIONS; body limit 0 for static routes; 405 otherwise | verified (`request_body_on_static_route_is_413_and_closes`; other methods 405 with `Allow`) |
| T2.8 | HTTP/2 floods (rapid reset CVE-2023-44487, SETTINGS/PING floods, stream exhaustion) | D | A06 / V11.1.4 | hyper ≥1.0 with h2 mitigations; `max_concurrent_streams` 100; cap pending resets; keep deps current (cargo-audit) | implemented: h2 max streams 100, pending-reset cap 20, local-error-reset cap 256, header list cap; flood tests in Phase 7 |
| T2.9 | Request smuggling (CL+TE, duplicate CL, obs-fold) | T | A04 / V13.1 | hyper parses framing; wedge rejects any Transfer-Encoding (400 + close) while no route takes a body; revisit in Phase 4 | verified (`ambiguous_framing_is_rejected`) |
| T2.10 | Range-request abuse (many overlapping ranges) | D | A05 | Support a single range only; multi-range returns full body or 416 | verified (`path::tests`, `tests/files.rs`) |
| T2.11 | Response header injection or open redirect through request paths and file names | T | A03, A01 / V5.3, V5.1.5 | No user input in headers except the directory redirect `Location`, which is built from the validated path with empty and `.` segments dropped, so it is always a same-origin path (never `//host/`) | verified (`directories_redirect_and_never_list`); open redirect via `//dir` found and fixed in the Phase 2 gate |
| T2.12 | MIME sniffing / XSS through uploaded HTML | T | A03, A05 / V14.4 | `X-Content-Type-Options: nosniff`; explicit Content-Type from extension map; default `application/octet-stream` | verified (`path::tests`, `tests/files.rs`) |
| T2.13 | Information disclosure in errors (paths, versions) | I | A05 / V7.4.1 | Generic error bodies; no `Server` version by default; filesystem paths only in server logs | implemented: generic status bodies, no Server header |
| T2.14 | Log injection (CR/LF, ANSI escapes in request line) | R, T | A09 / V7.3.1 | Structured logs; escape control characters, quotes and backslashes in logged fields; cap each field at 512 bytes; never log the query string | verified (`escape_neutralizes_log_injection`) |
| T2.15 | Unbounded compression work (zip bomb on our side) | D | A05 | Compress only on-the-fly for files under a size cap and for compressible types; prefer pre-compressed `.br`/`.gz` | implemented: only pre-compressed `.br`/`.gz` variants are served; no on-the-fly compression |
| T2.16 | Host header used for vhost routing is spoofed | S | A01 | Unknown Host → default vhost (explicitly configured) or 421; Host is never used to build file paths | verified (`vhost::tests`, `host_routing_over_the_wire`) |

## Phase 3: TLS termination and security headers

New trust boundary: the TLS handshake. Before it completes, wedge has only
the ClientHello (SNI, ALPN, offered versions and cipher suites), all of it
attacker-controlled. New asset: each vhost's private key.

Design: TLS listeners are separate (`server.listen_tls`). Each vhost may carry
`[vhost.tls]` with `cert` and `key` given as `env:`/`file:` references (never
inline). A custom resolver picks the certificate from SNI using the same
exact/wildcard rules as Host routing, falling back to the default vhost.
rustls with the ring provider is the only TLS stack.

| # | Threat | STRIDE | OWASP / ASVS | Mitigation | Status |
|---|---|---|---|---|---|
| T3.1 | Downgrade to TLS 1.0/1.1, SSLv3 or weak ciphers (POODLE, BEAST, SWEET32, RC4, export, RSA key exchange without forward secrecy) | I, T | A02 / V9.1.2, V9.1.3 | rustls implements only TLS 1.2 and 1.3, with AEAD suites and (EC)DHE key exchange only; `server.tls.min_version` (`"1.2"` default, `"1.3"` allowed) cannot go lower | verified (`known_bad_client_hellos_get_no_server_hello`: TLS 1.0/1.1, RC4/3DES/export-only, SSLv2; `tls12_is_allowed_by_default_and_refused_when_min_is_13`) |
| T3.2 | Private key leaked through config, logs, errors or core dumps | I | A02, A05 / V6.4.1, V6.4.2 | Key only by `env:`/`file:` reference; the secret buffer is zeroized after parsing; errors name the reference, never the content; on Unix a warning if the key file is group- or world-readable; `panic = "abort"` | verified (`bad_keys_fail_startup_without_leaking_key_material`, `no_error_kind_echoes_values`); found in 3.1: schema errors echoed whole tables, now masked |
| T3.3 | Wrong certificate served: SNI for vhost A returns B's certificate, or a vhost has no certificate covering its names | S | A02, A07 / V9.1.1 | Resolver is built from the same host table as the router; at startup each vhost's hosts are checked against its certificate's SAN (webpki); mismatches are startup warnings, and a key that does not match its certificate is a startup error | verified (`sni_selects_each_vhost_certificate`, key mismatch in `bad_keys_fail_startup_without_leaking_key_material`); SAN warning implemented |
| T3.4 | SNI/Host confusion (domain fronting, misrouting over a coalesced HTTP/2 connection): handshake for A, then `Host: B` | S, T | A01 / V9.1.1 | On TLS connections the vhost chosen by Host must be the vhost whose certificate was served; otherwise 421 Misdirected Request (RFC 9110 §15.5.20), which tells HTTP/2 clients to open a new connection | verified (`host_must_match_the_sni_vhost`) |
| T3.5 | Handshake exhaustion: slow ClientHello, or many connections that never finish the handshake | D | A05 / V11.1.4 | Handshake bounded by `header_timeout_secs`; it runs inside the connection task, so the accept loop never blocks; it counts against `max_connections`; idle timeout applies to the raw socket | verified (`silent_and_plaintext_clients_are_dropped`) |
| T3.6 | Malformed or oversized ClientHello or TLS records crash the server or exhaust memory | D | A06 / V5.1 | rustls (memory-safe; caps message sizes) parses all records; errors close only that connection and are logged at debug level, so floods do not flood the log | implemented (rustls); handshake fuzzing and floods in Phase 7 |
| T3.7 | Cross-protocol attacks (ALPACA): a TLS connection meant for another service is accepted | S | A05 | ALPN `h2` and `http/1.1` only; a client offering ALPN with no overlap is refused with `no_application_protocol` | verified (`alpn_negotiates_h2_and_refuses_other_protocols`) |
| T3.8 | 0-RTT replay of early data | T | A04 | Early data disabled (rustls default `max_early_data_size = 0`); session tickets off; TLS 1.3 resumption uses a bounded in-memory session cache | implemented (rustls defaults kept; no ticketer, no early data) |
| T3.9 | TLS renegotiation and compression attacks (CRIME, renegotiation DoS) | I, D | A02 | Not implemented by rustls | implemented (by construction) |
| T3.10 | Plaintext HTTP on the TLS port or TLS on the plaintext port | D | A05 | Handshake fails and the connection closes; covered by the handshake timeout | verified (`silent_and_plaintext_clients_are_dropped`) |
| T3.11 | Protocol downgrade by an active attacker: user reaches `http://` and stays on it (SSL stripping) | T, I | A02, A05 / V9.1.1, V14.4.5 | HSTS on TLS responses (default `max-age=31536000`, configurable, never sent over plain HTTP as RFC 6797 requires); optional HTTP→HTTPS redirect per vhost | verified (`security_headers_everywhere_and_hsts_only_over_tls`, `http_redirects_to_https_without_open_redirect`); redirect is opt-in per vhost (`redirect_http`) |
| T3.12 | HTTPS redirect abused as an open redirect through a spoofed Host | T | A01 / V5.1.5 | The redirect host is the request host only if it matches one of the vhost's configured names; otherwise the vhost's first exact host; with neither, no redirect | verified (`http_redirects_to_https_without_open_redirect`) |
| T3.13 | Clickjacking, MIME sniffing, referrer leakage on served content | T, I | A05 / V14.4.3 to V14.4.7 | Default headers `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy: strict-origin-when-cross-origin`; per-vhost `headers` table to add or override, for example a CSP; names and values validated at startup (no CR/LF) | verified (`security_headers_everywhere_and_hsts_only_over_tls`, `header_rules`); framing and computed headers are reserved |
| T3.14 | Expired or soon-to-expire certificate causes an outage | D | A05 | Out of scope for 3.x: certificate expiry metric in Phase 5, renewal with ACME later | planned (Phase 5) |

## Phase 4: Reverse proxy

New trust boundary: server → upstreams. Upstream responses are semi-trusted:
the operator chose the upstream, but the application behind it may be buggy or
compromised. New capability: request bodies, which reach only proxy routes.

Design: `[[upstream]]` groups list servers as IP:port values only; there is no
DNS lookup at runtime. A vhost maps path prefixes to an upstream with
`[[vhost.proxy]]`. wedge parses every request and builds a new one for the
upstream with its HTTP client (HTTP/1.1, pooled connections), so raw client
bytes never reach an upstream. Round-robin over healthy servers; active health
checks (`GET <health_path>`) and passive marking on connect failure.
Not in v1: TLS to upstreams, WebSocket/`Upgrade` tunnelling, HTTP/2 to
upstreams.

| # | Threat | STRIDE | OWASP / ASVS | Mitigation | Status |
|---|---|---|---|---|---|
| T4.1 | SSRF: client steers the proxy to an internal host (absolute-form target, `Host`, `CONNECT`, path tricks such as `//evil/` or `@`) | S, I | A10 / V5.2.6, V12.6.1 | Destination is fixed by config: IP:port per server, no DNS; the upstream URI is built from the configured address and the normalized path only; `CONNECT` and other methods outside the route's list get 405; `Host` only selects the vhost | verified (`path_confusion_and_tunnels_are_refused`: absolute-form, CONNECT, TRACE) |
| T4.2 | Operator mistake points an upstream at cloud metadata or a non-unicast address | I | A10, A05 | Config rejects unspecified, multicast and broadcast addresses; startup warning for link-local (169.254.0.0/16, fe80::/10), which includes cloud metadata endpoints | verified (`proxy_and_upstream_rules`); link-local warning implemented |
| T4.3 | DNS rebinding of upstream names | S | A10 | Upstreams are IP literals; no runtime resolution | verified (`proxy_and_upstream_rules`: host names rejected) |
| T4.4 | Request smuggling / desync between wedge and the upstream (CL.TE, TE.CL, TE.TE, obs-fold, duplicate Content-Length) | T | A04 / V13.1 | hyper parses client framing strictly: conflicting Content-Length values are rejected, and with both Content-Length and Transfer-Encoding it honours Transfer-Encoding and drops Content-Length (a request that still carries both is refused with 400); static routes reject any Transfer-Encoding (T2.9); wedge re-serializes the request with its own framing; `Transfer-Encoding` from the client is never forwarded as a header | verified (`smuggled_requests_never_reach_the_upstream`: CL.TE, TE.TE, duplicate Content-Length; malformed chunked body gives 400) |
| T4.5 | Hop-by-hop header abuse: `Connection: X-Forwarded-For` drops a security header before the upstream sees it; `Upgrade` or `TE` reach the upstream | T | A04, A05 / V13.1 | Remove `Connection`, `Keep-Alive`, `Proxy-Connection`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`, `Proxy-Authorization` and every header named in `Connection`, in both directions, before adding wedge's own headers | verified (`hop_by_hop_headers_are_stripped_both_ways`, `hop_by_hop_and_connection_named_headers_are_removed`) |
| T4.6 | Spoofed client identity: client sends its own `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Real-IP` or `Forwarded` to bypass IP allow-lists or forge the scheme | S | A01, A07 / V1.4, V13.1 | Those headers from the client are removed and replaced with values from the connection; an incoming `X-Forwarded-For` is kept and appended to only when the peer is in `server.trusted_proxies` | verified (`spoofed_forwarding_headers_are_replaced`: untrusted replaced, trusted chain extended) |
| T4.7 | Body exhaustion: huge or endless uploads, slow uploads | D | A05 / V11.1.4, V13.1.3 | Bodies only on proxy routes; `max_body_bytes` per route (default 10 MiB) enforced while streaming (413); request timeout covers slow uploads | verified (`request_bodies_are_forwarded_within_the_limit`: declared and chunked) |
| T4.8 | Slow or dead upstream ties up connections | D | A05 / V11.1.4 | Connect timeout, response-header timeout, idle timeout on response bodies; failures give 502/504; the connection cap still applies | verified (`slow_upstream_times_out`, `stalled_response_bodies_are_cut_off`) |
| T4.9 | Upstream errors leak internals (stack traces in 5xx bodies, upstream addresses in wedge's error pages) | I | A05 / V7.4.1 | wedge's own 502/503/504 bodies are generic and never name the upstream; upstream addresses appear only in logs; upstream bodies pass through unchanged (the application owns them) | verified (`dead_servers_fail_over_and_errors_are_generic`) |
| T4.10 | Upstream response header injection or framing confusion reaching the client | T | A03, A04 | hyper parses the upstream response strictly; hop-by-hop headers are removed (T4.5); wedge re-frames the response | verified (`malformed_upstream_responses_become_502`: bad header name, obs-fold, duplicate Content-Length, non-HTTP) |
| T4.11 | Health checks or retries amplify load or replay non-idempotent requests | D, T | A04 | Health checks use a fixed interval and timeout; a request is retried on another server only when the connection failed before any bytes were sent, and only for GET, HEAD and OPTIONS | verified (`dead_servers_fail_over_and_errors_are_generic`, `health_checks_take_failing_servers_out`) |
| T4.13 | Path confusion: `/api/../admin` or `/api/%2e%2e/admin` matches the `/api/` route in wedge but the upstream resolves it to `/admin` | T, E | A01 / V12.3.1 | Proxied paths are decoded once for checking; any `.` or `..` segment, encoded `/` or `\`, or NUL gives 400; the original encoded path is forwarded unchanged | verified (`proxy_paths`, `path_confusion_and_tunnels_are_refused`) |
| T4.12 | Security headers from wedge clobber the application's own (for example a stricter CSP) | T | A05 / V14.4 | On proxied responses default security headers are added only when absent; headers set explicitly in `[vhost.headers]` still override; HSTS rules unchanged | verified (`application_security_headers_win_over_defaults`) |

## Phase 5: Operations

New surfaces: an admin listener (metrics and reload), configuration reload
while serving, OS service integration, and an opt-in debug capture log.

Design: `[server.admin]` is off unless configured. When on, it is a separate
listener (default `127.0.0.1:9900`) that serves `GET /metrics` (Prometheus
text format) and `POST /-/reload`. Clients must come from `allow` (default
loopback only). Reload also needs `Authorization: Bearer <token>`, where
`token` is a secret reference. `SIGHUP` on Unix and `wedge reload` (which
calls the admin endpoint) trigger the same reload. A reload builds a
complete new state off to the side (config, certificates, upstreams) and
swaps it in only if everything succeeded. Listen addresses, the admin
settings and the debug capture flags need a restart.

| # | Threat | STRIDE | OWASP / ASVS | Mitigation | Status |
|---|---|---|---|---|---|
| T5.1 | Metrics reveal internals (vhost names, upstream addresses, error rates) to the internet | I | A01, A05 / V14.3 | Admin listener is separate from public listeners, off by default, loopback by default; IP `allow` list checked before anything else; config rejects an admin address that is also a public listener; startup warning when bound to a non-loopback address | verified (`disallowed_clients_get_no_http_at_all`, `metrics_count_requests_and_connections`, `admin_address_cannot_be_a_public_listener`); non-loopback warning implemented |
| T5.2 | Metric label explosion exhausts memory (attacker-chosen Host, path or method as labels) | D | A05 / V11.1.4 | Labels come only from config (vhost and upstream names) or fixed sets (method buckets, status classes); request data is never a label | verified (`labels_are_bounded_and_escaped`) |
| T5.3 | Unauthorized reload (local process, browser CSRF to localhost, DNS rebinding to 127.0.0.1) | E, T | A01, A07 / V4.1.1, V13.2.3 | Reload needs `POST` plus a bearer token compared in constant time; token by secret reference only; no CORS, so browsers cannot send the header cross-origin; `Host` must be an IP literal or `localhost` (defeats DNS rebinding) | verified (`admin_rejects_rebinding_hosts_and_other_routes`, `reload_needs_the_token`: missing, wrong, prefix and longer tokens, GET, rebinding Host) |
| T5.4 | A bad config or certificate applied by reload takes the server down, or leaves it half-updated | D, T | A05, A08 / V14.1.1 | Validate and build the whole new state first; swap atomically; on any error keep serving the old state and log why; in-flight requests finish on the state they started with | verified (`reload_applies_good_config_and_keeps_old_on_errors`: parse error, missing root); metrics counters restart from zero after a reload |
| T5.5 | Reload flood or concurrent reloads race | D | A04 | One reload at a time (a lock); further requests wait or get 409; reload is rate-limited to one per second | verified (`restart_only_settings_and_rate_limit`: 429 within one second); 409 for a concurrent reload implemented, not separately tested |
| T5.6 | Reload silently weakens security (for example, turns on debug capture or `log_secrets`, or moves the admin listener) | T, E | A05 / V14.1.1 | Listeners, admin settings and all `[server.debug]` settings are restart-only; a reload that changes them is refused with a clear error | verified (`restart_only_settings_and_rate_limit`); listeners, `[server.admin]` and `[server.limits]` are restart-only; `[server.debug]` joins them in 5.4 |
| T5.7 | Service runs with more privilege than needed (root/LocalSystem); a compromise owns the host | E | A05 / V14.1.2 | systemd unit: dedicated `wedge` user, `CAP_NET_BIND_SERVICE` only, `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`, `RestrictAddressFamilies`, `LimitCORE=0`; Windows service: virtual account `NT SERVICE\wedge`, not LocalSystem | planned |
| T5.8 | Service install leaves config or keys writable by the service account | T, I | A05 / V14.1.3 | Install docs and packages: config and keys owned by root (Windows: Administrators), readable by the service account, not writable; key files mode 0600/0640 | planned |
| T5.9 | Debug capture log exposes sensitive data at rest (bodies, cookies, tokens; all of it when `log_secrets` is on) | I | A02, A09 / V7.1.1, V8.3.4 | Off by default; restart-only; credentials redacted unless `log_secrets`; file created owner-only (0600; Windows: owner ACL only); loud startup warning repeated every hour while on; docs mark it "never in production" | planned |
| T5.10 | Debug capture fills the disk or slows the server | D | A05 | Per-request byte cap, file size cap and rotation count; capture writes go through a bounded queue and are dropped (and counted) when it is full | planned |
| T5.11 | Packet capture (`tcp_headers`) records other processes' traffic, or needs a privilege that widens the attack surface | I, E | A01, A05 | BPF filter limited to wedge's own listen ports; optional build feature; needs CAP_NET_RAW or admin, which the docs say to grant only for the debugging session; if capture cannot start, wedge continues without it | planned |
| T5.12 | Capture log injection (control characters, fake log lines) | T | A09 / V7.3.1 | Captured bytes are written as hex plus escaped ASCII, never raw | planned |

## Residual risks and assumptions

- The OS, filesystem permissions and the operator's account are trusted. wedge
  should run as an unprivileged user; packaging (Phase 6) will set this up.
- Third-party crates (hyper, h2, rustls, tokio) are trusted but monitored with
  cargo-audit and cargo-deny on every push and weekly.
- A private key stays in process memory while the server runs; rustls owns
  that copy. Anyone who can read wedge's memory (root, a debugger, a core
  dump) can read the key. Run wedge as a dedicated user with core dumps
  disabled.
- No post-quantum key exchange: the ring provider does not implement ML-KEM,
  so recorded TLS traffic could be decrypted by a future quantum computer
  ("harvest now, decrypt later"). Offering `X25519MLKEM768` needs the
  aws-lc-rs provider, which would change the "ring only" decision in the
  project spec.
- Phase 7 will test these mitigations against the built binary and record the
  results in `assessment-report.md`.
