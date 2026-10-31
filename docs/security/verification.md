# Verification log

Results of each phase's security gate. Only measured results are recorded;
the full assessment of the released build follows in Phase 7
(`assessment-report.md`). Threat IDs refer to [threat-model.md](threat-model.md).

## Phase 2 gate (commit 62df93e, 2026-10-30)

| Check | Tool | Result |
|---|---|---|
| Lints and tests | rustfmt, clippy `-D warnings`, `cargo test` | pass |
| Known vulnerabilities | cargo-audit 0.22.2, cargo-deny 0.20.2 | no advisories |
| Static analysis | Semgrep 1.182.1 (`p/rust` + `.semgrep.yml`) | no findings |
| Fuzzing, 300 s per target, Docker `rust:1-bookworm`, nightly | cargo-fuzz | no crashes: `config_parse` 276,033 runs, `request_path` 1,994,604, `secret_ref` 40,811,616 |
| Threat model review | manual, T2.1 to T2.16 against code | 1 finding: open redirect via `//dir` (T2.11), fixed in 62df93e with a regression test |

## Phase 3 gate (commit 74e2efe, 2026-10-30)

| Check | Tool | Result |
|---|---|---|
| Lints and tests | rustfmt, clippy `-D warnings`, `cargo test` (10 TLS wire tests) | pass on Linux, Windows, macOS; MSRV 1.80 `cargo check` passes |
| Known vulnerabilities | cargo-audit 0.22.2, cargo-deny 0.20.2 | no advisories after pinning `time` 0.3.47 (RUSTSEC-2026-0009; test-only dependency) |
| Static analysis | Semgrep 1.182.1 | no findings |
| TLS configuration | testssl.sh 3.2.4 against the release build in a Linux container (non-root, read-only, no capabilities), ECDSA P-256 self-signed test certificate | see below |

testssl.sh results for the server:

- Protocols: SSLv2, SSLv3, TLS 1.0 and TLS 1.1 not offered; TLS 1.2 and 1.3 offered (T3.1).
- Ciphers: only forward-secret AEAD suites; no NULL, aNULL, EXPORT, LOW, 3DES,
  RC4 or non-FS suites; server cipher order. Curves: X25519, P-256, P-384.
- Vulnerability checks, all "not vulnerable": Heartbleed, CCS, Ticketbleed,
  ROBOT, secure renegotiation, CRIME, BREACH (no HTTP compression), POODLE,
  SWEET32, FREAK, DROWN, LOGJAM, BEAST, LUCKY13, Winshock, RC4.
- ALPN: `h2` and `http/1.1`; no NPN (T3.7).
- Resumption: session IDs only, no session tickets (T3.8).
- Headers: HSTS 31,536,000 s (T3.11); `X-Frame-Options`,
  `X-Content-Type-Options`, `Referrer-Policy` present (T3.13); no `Server`
  banner (T2.13).
- Plain HTTP with `redirect_http`: 308 to `https://<vhost>:8443/<path>?<query>`.

Findings:

| Finding | Severity (testssl) | Status |
|---|---|---|
| Certificate self-signed, expires in < 30 days, no CRL/OCSP; overall grade "T" | CRITICAL / HIGH | Test certificate only; not a server defect. Re-test with a CA-issued certificate in Phase 7. |
| No post-quantum key exchange (KEM) offered | LOW | Residual: the ring provider has no ML-KEM; see residual risks in the threat model. |
| No DNS CAA record | LOW | Not applicable to a test host name. |

Also observed: the startup warning for a group- or world-readable key file
fires (T3.2), and an unreadable key file stops startup with an error that
names the reference only.

## Phase 4 gate (commit 7a08f06, 2026-10-31)

| Check | Tool | Result |
|---|---|---|
| Lints and tests | rustfmt, clippy `-D warnings`, `cargo test` (12 proxy wire tests with real upstreams) | pass on Linux, Windows, macOS; MSRV 1.80 `cargo check` passes |
| Known vulnerabilities | cargo-audit 0.22.2, cargo-deny 0.20.2 | no advisories |
| Static analysis | Semgrep 1.182.1 | 1 finding (`expect()` in the new fuzz helper, project rule `wedge-no-unwrap-in-lib`), fixed; then no findings |
| Fuzzing, 300 s per target, Docker `rust:1-bookworm`, nightly | cargo-fuzz | no crashes: `config_parse` 319,558 runs, `proxy_request` 1,088,832 (new), `request_path` 1,683,567, `secret_ref` 42,965,013 |
| Threat model | T4.1 to T4.13 | all verified by named tests |

Defects found by the new tests during Phase 4 and fixed before the gate:

- A malformed chunked request body was reported as 502 (upstream error);
  it is the client's error and now gives 400 (`smuggled_requests_never_reach_the_upstream`).
- A request still carrying both Content-Length and Transfer-Encoding on a
  proxy route is now refused with 400 (T4.4).
- Two listeners on port 0 were rejected as duplicates by config validation.

Known limitations (documented, not defects): no TLS to upstreams, no
WebSocket/`Upgrade` tunnelling, HTTP/1.1 only to upstreams.

## Phase 5 gate (commit 3962bce, 2026-10-31)

| Check | Tool | Result |
|---|---|---|
| Lints and tests | rustfmt, clippy `-D warnings`, `cargo test` (admin, reload, capture and CLI wire tests) | pass on Linux, Windows, macOS; MSRV 1.80 `cargo check` passes; new `packet-capture` job (libpcap-dev) passes |
| Known vulnerabilities | cargo-audit 0.22.2, cargo-deny 0.20.2 | no advisories; licenses clean with and without `packet-capture` |
| Static analysis | Semgrep 1.182.1 | 1 finding: `rust.lang.security.current-exe` in `wedge service install`; fixed in b020e27 (install refuses a binary outside Program Files unless `--allow-unprotected-path`); then no findings |
| Fuzzing, 300 s per target, Docker `rust:1-bookworm`, nightly | cargo-fuzz | no crashes: `config_parse` 216,084 runs, `proxy_request` 569,639, `request_path` 980,434, `secret_ref` 41,241,620 |
| systemd unit | systemd 252 `systemd-analyze verify` / `security` (Debian 12 container) | verify passes; exposure 1.6 "OK" |
| Packet capture | live run as root in Debian 12 container | full handshake, data and FIN segments recorded with seq/ack/flags/window; credential absent from the log |
| Capture log on Windows | real binary on this host | redaction in parsed and raw views; file ACL `OWNER RIGHTS:(F)` only |

Not yet tested (needs the user):

- `wedge service install` / `uninstall` on a real Windows machine (needs an
  elevated prompt). Code paths compile and run in CI; the refusal path for an
  unprotected binary location was exercised.

Known limitations: metrics counters restart from zero after a reload; the
409 response for a concurrent reload is implemented but not separately
tested; capture queue overflow is implemented but not separately tested.

## Container smoke test of the v0.1.0 release candidate (2026-10-31)

Subject: `wedge-0.1.0-oci-amd64.tar` from release dry run 41193421743
(commit b54a18b; later commits change only docs and the MSI script), SHA-256
checked against its `SHA256SUMS`. Docker Desktop 26.1.1, Linux containers.
The server ran as user 65532 with `--read-only --cap-drop ALL
--security-opt no-new-privileges`, config and site mounted read-only:
default and `blog.localhost` vhosts, a TLS vhost (self-signed P-256 test
certificate), an `api.localhost` proxy route to a second wedge container,
and the admin listener with a reload token from an environment variable.

| Check | Tool | Result |
|---|---|---|
| Functional, 45 checks | curl 8.10.1 (`curlimages/curl`) | 45/45 pass: h1 and h2c, vhosts, unknown and bad Host, 404 for missing, hidden and directory paths, traversal (`../`, `%2e%2e`, `%2f`, `%5c`, NUL) 400, range 206/416, ETag 304, gzip with `Vary`, 405/204/413/400 (TE+CL), URI 414, header 431, security headers, no HSTS on plain HTTP, TLS with h2 via ALPN and HSTS, TLS 1.1 and unknown SNI refused, proxied GET, route boundary 404, proxy body 413, proxied traversal 400, metrics, admin Host 421, reload 401/405/200, serving after reload |
| Upstream health | wedge health checks | upstream marked down while its health file was missing, back up within one interval once it existed |
| Image scan | Trivy 0.56.2 (vuln, secret, misconfig) | no findings; but 0 packages detected: the binary is not built with `cargo auditable`, so dependency coverage comes from cargo-audit/cargo-deny on `Cargo.lock` (Phase 7.1 adds auditable builds) |
| TLS | testssl.sh 3.2 | TLS 1.2 and 1.3 only; no protocol or cipher vulnerabilities; grade T and the chain, revocation and CAA findings come from the self-signed test certificate; "no KEMs offered" (LOW) is the known post-quantum residual |
| Web scan | OWASP ZAP 2.15.0 baseline | 0 failures, 63 passes, 4 warnings: CSP not set (Medium) and Permissions-Policy not set (Low), both site-specific and settable per vhost in `[vhost.headers]`; cacheable content (informational, expected for static files); ZAP version notice |

No high or critical finding in the server. Notes for Phase 7: consider an
opt-in default CSP / Permissions-Policy, and rerun the scans with auditable
binaries and a current ZAP.

Harness notes: the TLS key had to be owned by the container user (0600,
uid 65532); while it was not, wedge refused to start with a clear error.
POST with a body on a static route is 413 by design (T2.7, static routes
take no body); a 16 KiB URI exceeds the 16 KiB header buffer and gets 431
before the 8 KiB URI limit (414) applies.
