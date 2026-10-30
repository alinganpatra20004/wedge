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

## Residual risks and assumptions

- The OS, filesystem permissions and the operator's account are trusted. wedge
  should run as an unprivileged user; packaging (Phase 6) will set this up.
- Third-party crates (hyper, h2, rustls, tokio) are trusted but monitored with
  cargo-audit and cargo-deny on every push and weekly.
- A private key stays in process memory while the server runs; rustls owns
  that copy. Anyone who can read wedge's memory (root, a debugger, a core
  dump) can read the key. Run wedge as a dedicated user with core dumps
  disabled.
- Phase 7 will test these mitigations against the built binary and record the
  results in `assessment-report.md`.
