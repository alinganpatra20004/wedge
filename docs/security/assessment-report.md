# wedge security assessment

Assessment of the released build product (Phase 7), mapped to the OWASP Top
10 (2021) and OWASP ASVS 4.0.3 level 2. Residual risk is listed, not hidden.
This report is filled in as each step completes; a section marked
"pending" has not been run yet.

## Scope

- Release v0.1.0 (tag at commit 0f1f4d0), the release pipeline, and the
  fixes made during this assessment (commits e8c8486 to 61e3406).
- Artifacts: Linux (gnu and musl, x86_64 and aarch64), Windows x86_64 and
  macOS binaries, .deb and .rpm packages, the MSI, the OCI images.
- Out of scope: the hosts wedge runs on, upstream applications behind the
  proxy, site content.

## Method and tools

Black-box tests ran against the release container image in Docker; white-
box review covered the code, the dependency tree and the CI workflows. Each
fix got a regression test and was re-tested against a rebuilt image.

| Area | Tools |
|---|---|
| Supply chain | cargo-audit 0.22.2, cargo-deny 0.20.2, cargo-auditable 0.7.7, cargo-cyclonedx 0.5.9, Trivy 0.56.2 |
| Static | clippy (Rust 1.99.1, pedantic and restriction lints), Semgrep 1.182.1, cargo-geiger 0.14.0 |
| Dynamic | OWASP ZAP 2.15.0 baseline and 2.17.0 full scan, nikto 2.5.0, testssl.sh 3.2, curl 8.10.1, raw-socket scripts |
| Robustness | Python 3.12 attack scripts (sockets, h2 4.1.0), cargo-fuzz with libFuzzer (nightly) |

Severity: CVSS 3.1 base score where a network attack exists, otherwise a
judgement of impact and likelihood, stated per finding.

## OWASP Top 10 (2021) coverage

| Category | What was tested | Findings |
|---|---|---|
| A01 Broken access control | traversal (104 payloads, fuzzing), hidden files, directory listing, symlinks, vhost/SNI binding, admin allow list and token | none |
| A02 Cryptographic failures | testssl (protocols, ciphers, known attacks), TLS config, capture redaction | F-10 |
| A03 Injection | ZAP active rules (SQL, OS command, XSS, CRLF, format string), header injection via path | none (wedge runs no interpreter; CR/LF never reaches headers) |
| A04 Insecure design | arithmetic and indexing review, panic paths (`panic = "abort"`) | F-04 |
| A05 Security misconfiguration | default headers, Host validation, limits, shipped configs | F-01, F-02, F-07, F-08, F-09 |
| A06 Vulnerable components | cargo-audit on lockfile and binaries, Trivy on image and SBOM | none |
| A07 Identification and authentication | admin token (constant-time compare, 401/405/421), no other authentication in scope | none |
| A08 Software and data integrity | signatures, attestations, SBOM, CI action pinning | F-03, F-05 |
| A09 Logging and monitoring | log flooding, log injection (escaped fields), secrets in logs | F-06, F-10 |
| A10 SSRF | proxy targets fixed by config, absolute-form and `@` targets, CONNECT | none |

## Summary

| Step | Status | High/critical findings |
|---|---|---|
| 7.1 Supply chain | done | none |
| 7.2 Static analysis | done | none (2 findings fixed: F-04 Low, F-05 Medium) |
| 7.3 Dynamic testing | done | none (3 Low findings fixed: F-06 to F-08; F-01, F-02 mitigated) |
| 7.4 Robustness | done | none (F-09 Medium and F-10 Medium fixed) |

Ten findings: 0 critical, 0 high, 4 medium, 6 low. Eight are fixed with
regression tests and re-tested on a rebuilt image; two (F-01, F-02) are
mitigated in every shipped configuration and left to the site by design.
All fixes ship in v0.1.1. The release workflow at f07d829 (dry run
41221400158) passes with the new artifact scans as release gates.

## 7.1 Supply chain

Method: every release binary is now built with `cargo auditable`, so the
exact dependency set is embedded in the shipped file and can be checked
without the source tree. The release workflow scans the built artifacts and
fails on any finding.

| Check | Tool and version | Result |
|---|---|---|
| Advisories, licenses, bans, sources on `Cargo.lock` | cargo-deny 0.20.2, cargo-audit 0.22.2 (1,395 advisories) | advisories ok, bans ok, licenses ok, sources ok; no advisories |
| Dependencies embedded in the binaries | cargo-auditable 0.7.7 | all 7 release binaries carry the list: 167 crates (Linux, macOS), 179 (Windows) |
| Built binaries | cargo-audit 0.22.2 `audit bin` | no advisories on any of the 7 binaries (release dry run 41207580524) |
| Container images (amd64, arm64) | Trivy 0.56.2, vuln and secret scanners, HIGH/CRITICAL blocks | Rust binary detected in both images; no findings |
| SBOM | cargo-cyclonedx 0.5.9, CycloneDX 1.5, all targets | 204 components; Trivy reads 205 packages from it, no vulnerabilities |

Before this step, Trivy found 0 packages in the `scratch` image (nothing to
match against), so the v0.1.0 image scan was not evidence of anything. The
v0.1.0 binaries themselves are not auditable; their dependency set is the
`Cargo.lock` at the tag, which cargo-audit and cargo-deny checked.

The SBOM is published as `wedge-<version>.cdx.json` with its own checksum,
Sigstore signature and build provenance attestation (OWASP A06, A08; ASVS
V10.3, V14.2).

## 7.2 Static analysis

| Check | Tool and version | Result |
|---|---|---|
| Lints beyond the CI set | clippy (Rust 1.99.1) `pedantic` plus `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `arithmetic_side_effects`, `as_conversions`, `unreachable`, `todo`, `exit` on library and binary code | 99 warnings. No unwrap, expect or panic. The 56 arithmetic, indexing and cast warnings were reviewed one by one (see below); 1 defect (F-04). The rest are documentation and style lints |
| Pattern rules | Semgrep 1.182.1, `p/rust`, `p/owasp-top-ten`, project rules | Rust code: no findings. Workflows: 35 x `github-actions-mutable-action-tag` (F-05). 2 partial-parse warnings (a shell snippet in release.yml, a `case` in scripts/test-package.sh); the rest of each file was scanned |
| `unsafe` in wedge | `unsafe_code = "forbid"` (workspace lints), grep | none; the compiler rejects any |
| `unsafe` in dependencies | cargo-geiger 0.14.0 | wedge, wedge-core, wedge-config: 0. Dependency tree (165 crates): 19,897 unsafe expressions used, mostly in tokio (2,376), memchr, hashbrown, aho-corasick/regex, parking_lot, bytes, socket2; widely used, maintained crates. `vsimd` and `zmij` arrive through jsonschema and serde_json and only process the administrator's config file, never network input (jsonschema already has default features off). cargo-geiger exits 1 only for 204 "file never scanned" warnings on data files |

Review of the arithmetic and indexing warnings. Release builds abort on panic
(`panic = "abort"`), so a reachable panic would stop the whole server; each
site was checked for remote reachability:

- Byte ranges (`files.rs`): `requested_range` guarantees `start <= end < len`
  before `end - start + 1`.
- Percent decoding (`path.rs`): indexes are bounded by the loop condition and
  `get()`; hex arithmetic is on matched digit ranges.
- Round robin (`proxy.rs`): an empty pool yields an empty range, so the
  modulo never runs; config validation also requires servers.
- Metrics: the vhost table always has the catch-all `-` series, so
  `len() - 1` cannot underflow; method and status indexes are clamped.
- Capture redactor: all slice bounds come from searches in the same slice.
- **Upstream failure clock (`proxy.rs`, F-04):** `now_ms() - last_failure_ms`
  could underflow when a concurrent request recorded a failure after the
  clock was read. Release builds wrapped to a huge gap, so a server that had
  just failed was retried at once (no-health-check pools only); debug builds
  panicked. Fixed with `saturating_sub` (and `saturating_add` on the failure
  counter) in 99a904d; regression test
  `a_failure_recorded_after_now_keeps_the_server_down` panics on the old code.

**Workflow actions (F-05):** every action was referenced by a movable tag
(`@v4`). Whoever controls an action's tag controls code in the release job,
which holds the GPG key secret and the Sigstore/attestation identity
(OWASP A08). All actions are now pinned to full commit SHAs with the version
in a comment, `dtolnay/rust-toolchain` takes the toolchain as an input, and
Dependabot proposes updates (99a904d). CI, Security and release dry run
41210521524 pass with the pins.

## 7.3 Dynamic testing

Target: the release image built by dry run 41210521524 (commit 99a904d),
then rebuilt at 52b2bb3 and 61e3406 to re-test the fixes. Docker Desktop
26.1.1 (Linux containers); wedge ran as user 65532 with `--read-only
--cap-drop ALL --security-opt no-new-privileges`, with a default and a
`blog.localhost` vhost, a TLS vhost, an `api.localhost` proxy route to a
second wedge container, and the admin listener with a token.

| Check | Tool and version | Result |
|---|---|---|
| Functional baseline | curl 8.10.1, 45 checks | 45/45 on every image |
| Active web scan, HTTP and HTTPS | OWASP ZAP 2.17.0 `zap-full-scan` (spider plus active rules: injection, traversal, XSS, SSRF, CRLF, overflow, format string and others) | 0 failures, 140 rules passed on each; warnings: CSP, Permissions-Policy, Cross-Origin-Resource-Policy missing (F-01, F-02). On the shipped image at 61e3406: 0 failures, 142 passed, 1 warning (COEP, accepted, see residual risks) |
| Server scan | nikto 2.5.0, 625 requests | HTTP: header advice only (CSP, Permissions-Policy; HSTS correctly absent on plain HTTP; `X-Frame-Options` called deprecated in favour of CSP `frame-ancestors`, which the shipped CSP now sets); no banner. HTTPS: nikto sends the IP address as SNI, which TLS forbids; wedge refuses the handshake by design (T3.4), so nikto's HTTPS coverage is limited to that; ZAP and testssl cover the TLS listener. Exposed F-06 |
| TLS | testssl.sh 3.2 | TLS 1.2 and 1.3 only, no protocol or cipher vulnerabilities; certificate findings (self-signed, name, CRL/OCSP, CAA) come from the test certificate; no KEMs offered (residual) |
| Traversal and header abuse | 104 payloads (curl, raw requests with nc) against static and proxy routes: `../` in plain, `%2e`, double, overlong UTF-8, `%u`, fullwidth and backslash forms; NUL, `::$DATA`, trailing dot and space; absolute-form targets; CR/LF injection; duplicate, empty and malformed Host | no file content or upstream response leaked; no header injection. Exposed F-07 and F-08 |

Fixed and re-tested on the rebuilt image:

- **F-06:** every TLS handshake with an IP address as SNI made rustls log a
  WARN line, so any client could add a log line per connection. The default
  filter is now `info,rustls=error`; wedge logs handshake failures at debug
  and counts them in `wedge_tls_handshake_failures_total`. Verified: 5 such
  handshakes, 0 log lines, counter incremented.
- **F-07:** a Host header with an out-of-range port (`localhost:99999`,
  `[::1]:99999`) was routed. RFC 9110 requires 400 for an invalid Host;
  now 400. Absolute-form targets with userinfo (`http://user@host/`) are now
  400 too (RFC 9110 4.2.4).
- **F-08:** `/page.html/` served the file. Its relative URLs then resolved
  against `/page.html/`, which enables path-relative style sheet confusion;
  now 404.
- **F-01, F-02 (and CORP):** the configurations installed by every package,
  the container image and the examples now set `Content-Security-Policy`,
  `Permissions-Policy` and `Cross-Origin-Resource-Policy` for the default
  page; the guide explains each and when to loosen it. The server's built-in
  defaults stay unchanged, because a wrong policy breaks sites.

Test-setup notes (not defects): the duplicate-Host case first showed 200
because curl merges repeated `-H Host`; a raw request gets 400. `/INDEX.HTML`
returned 200 because the test site was a Windows folder mounted into Docker
(case-insensitive). A client that half-closes its write side right after
the request gets no response; that is hyper's default HTTP/1 behaviour.

## 7.4 Robustness

Limit tests ran from a Python 3.12 client container against the hardened
wedge container (default limits: 10 s request head, 60 s idle, 30 s
response, 1,024 connections, 16 KiB head, 100 headers), while a second
client made a normal request every 0.5 s. An attack passes only if wedge
enforces the limit and that normal client stays served. Final run on the
image built at f07d829:

| Attack | Result |
|---|---|
| Slowloris: 300 connections trickling header lines | all closed within 12.2 s; normal client 24/24 served, worst 0.06 s |
| 200 connections that send nothing | all closed at 10.0 s (was 60 s, F-09); normal client unaffected |
| 1,100 silent connections (over the 1,024 cap), then a normal request | served after 4.8 s (was 57.8 s before F-09) |
| Connection flood, 1,200 connections | extra clients wait in the kernel backlog; normal requests during and after: 200 |
| 101 and 1,000 headers; endless header bytes; one 20 KiB header | 431 each |
| 100 MB declared body to a static route | 413 at once, connection closed (body not read) |
| 10 MB declared and 10 MB chunked body to a proxy route (limit 1 KiB) | 413 at once |
| Slow upload, 1 byte/s, through the proxy to an upstream that reads bodies | ended at 30.0 s with 504 (response timeout) |
| HTTP/2: 500 concurrent streams on one connection (limit 100) | excess streams reset by wedge; server keeps serving |
| HTTP/2 rapid reset (CVE-2023-44487): streams opened and cancelled in a loop | attacker connection closed at once; normal client unaffected |

wedge's memory stayed between 14 and 40 MiB throughout.

**F-09 (Medium, CVSS 3.1 5.3, AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L):**
hyper's header timer starts with the first byte, so a plain-HTTP (or admin)
connection that never sent anything held its connection slot until the
idle timeout. 1,100 such connections, from one client and with almost no
traffic, made a normal request wait 57.8 s, and reopening them kept the
server unavailable. A new connection must now become readable within the
shorter of the header and idle timeouts; TLS connections were already
bounded by the handshake timeout. Fixed in f07d829 with two regression
tests (`silent_connection_is_closed_after_header_timeout`,
`silent_connections_do_not_lock_out_clients`).

**F-10 (Medium):** found while writing the header fuzz target. The capture
log holds back a partial line until its newline and released it unredacted
once it passed 8 KiB. Header lines may be up to 16 KiB and arrive in
TCP-sized reads, so an `Authorization` or `Cookie` value over 8 KiB, or a
long query string, was written in clear text. Only relevant when
`[server.debug] read_packet` is on (off by default, with warnings), but
redaction is the feature's promise (T5.9). An over-long line is now judged
by its start, redacted, and the rest dropped up to its newline. Fixed in
d1981c2 with a regression test that splits a 9 KB token into 1,400-byte
reads; the new `request_headers` fuzz target checks it for arbitrary splits.

Fuzzing: the five targets ran for 15 minutes each, three times the gate
runs of Phases 2 to 5 (Docker `rust:1-bookworm`, nightly, cargo-fuzz,
libFuzzer `-max_len=8192`, code at f07d829). No crashes, no artifacts.

| Target | What it checks | Runs |
|---|---|---|
| `config_parse` | TOML and JSON Schema validation of arbitrary config text | 212,779 |
| `proxy_request` | proxy path check and header sanitiser (no traversal, no forged forwarding headers) | 509,934 |
| `request_headers` (new) | Host normalization, Range bounds, capture redaction under arbitrary read splits | 344,110 |
| `request_path` | static path parser (no escape from the root, no hidden files) | 2,132,500 |
| `secret_ref` | `env:` / `file:` secret reference parsing | 86,764,121 |

## Findings

| ID | Title | Severity | OWASP / ASVS | Status |
|---|---|---|---|---|
| F-01 | No Content-Security-Policy header by default | Medium (ZAP 10038) | A05 / V14.4.3 | mitigated 61e3406: set in every shipped configuration; built-in default stays off (site-specific); guide section "Response headers" |
| F-02 | No Permissions-Policy (or Cross-Origin-Resource-Policy) header by default | Low (ZAP 10063, 90004) | A05 / V14.4 | mitigated 61e3406: as F-01 |
| F-03 | v0.1.0 MSI and SHA256SUMS have no build provenance attestation | Low | A08 / V10.3.2 | fixed for later releases (release.yml); v0.1.0 relies on checksum and Sigstore signature |
| F-04 | Upstream failure clock underflow: just-failed server retried at once | Low (CVSS 3.1 3.1, AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L) | A04 / V11.1 | fixed 99a904d, regression test |
| F-05 | CI actions referenced by mutable tags | Medium | A08 / V10.3.2, V14.2.4 | fixed 99a904d (SHA pins, Dependabot) |
| F-06 | Any client can add a rustls WARN log line per TLS handshake | Low | A09 / V7.1 | fixed 52b2bb3 (default filter `info,rustls=error`), verified on the image |
| F-07 | Host with an invalid port, and absolute-form userinfo, accepted | Low | A05 / V5.1 | fixed 52b2bb3, unit tests, verified on the image |
| F-08 | File served when named as a directory (`/page.html/`) | Low | A05 / V14.4 | fixed 52b2bb3, integration test, verified on the image |
| F-09 | Silent connections hold slots until the idle timeout (lock-out) | Medium (CVSS 3.1 5.3) | A05 / V11.1.4 (T2.5) | fixed f07d829, 2 tests, verified in Docker (57.8 s to 4.8 s) |
| F-10 | Capture log released credential lines over 8 KiB unredacted | Medium | A02, A09 / V7.1.1 (T5.9) | fixed d1981c2, regression test, fuzz target |

## Residual risks

- Connection exhaustion is bounded, not eliminated: one client can still
  hold all `max_connections` slots for up to the header timeout (10 s) at a
  time, or for up to the response timeout with slow uploads to a proxy
  route. There is no per-client connection limit yet; behind a load
  balancer or on a public host, lower the timeouts or put a per-IP limit in
  front.

- No Cross-Origin-Embedder-Policy / Cross-Origin-Opener-Policy by default
  (ZAP 90004, Low). They only matter for pages that need cross-origin
  isolation (for example `SharedArrayBuffer`) and block cross-origin
  embedding, so they are left to the site; settable in `[vhost.headers]`.

- No post-quantum key exchange: the ring provider has no ML-KEM (testssl:
  "no KEMs offered"). Moving to aws-lc-rs is a project decision.
- Windows binaries and the MSI are not Authenticode-signed until SignPath
  Foundation approval; macOS binaries are not notarized.
