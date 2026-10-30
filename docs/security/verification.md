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
