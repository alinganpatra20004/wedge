# wedge security assessment

Assessment of the released build product (Phase 7), mapped to the OWASP Top
10 (2021) and OWASP ASVS 4.0.3 level 2. Residual risk is listed, not hidden.
This report is filled in as each step completes; a section marked
"pending" has not been run yet.

## Scope

- Release v0.1.0 (tag at commit 0f1f4d0) and the release pipeline as of
  commit e8c8486.
- Artifacts: Linux (gnu and musl, x86_64 and aarch64), Windows x86_64 and
  macOS binaries, .deb and .rpm packages, the MSI, the OCI images.
- Out of scope: the hosts wedge runs on, upstream applications behind the
  proxy, site content.

## Summary

| Step | Status | High/critical findings |
|---|---|---|
| 7.1 Supply chain | done | none |
| 7.2 Static analysis | pending | |
| 7.3 Dynamic testing | pending (baseline from the v0.1.0 smoke test below) | |
| 7.4 Robustness | pending | |

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

## Findings

| ID | Title | Severity | OWASP / ASVS | Status |
|---|---|---|---|---|
| F-01 | No Content-Security-Policy header by default | Medium (ZAP 10038) | A05 / V14.4.3 | open: site-specific by design; settable per vhost in `[vhost.headers]`; an opt-in default is considered in 7.3 |
| F-02 | No Permissions-Policy header by default | Low (ZAP 10063) | A05 / V14.4 | open: as F-01 |
| F-03 | v0.1.0 MSI and SHA256SUMS have no build provenance attestation | Low | A08 / V10.3.2 | fixed for later releases (release.yml); v0.1.0 relies on checksum and Sigstore signature |

## Residual risks

- No post-quantum key exchange: the ring provider has no ML-KEM (testssl:
  "no KEMs offered"). Moving to aws-lc-rs is a project decision.
- Windows binaries and the MSI are not Authenticode-signed until SignPath
  Foundation approval; macOS binaries are not notarized.
