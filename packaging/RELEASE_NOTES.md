<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) Alingan Patra -->
First release of **wEdge** (`wedge`), a web and application server in Rust.

## Highlights

- HTTP/1.1 and HTTP/2; static files with virtual hosts, ETag, ranges and
  pre-compressed Brotli/gzip; path traversal protection.
- TLS 1.2/1.3 with rustls, a certificate per vhost (SNI), HSTS, HTTP to HTTPS
  redirects, security headers.
- Reverse proxy with round-robin upstreams, health checks, safe forwarding
  headers, body limits and timeouts.
- Prometheus metrics, hot configuration reload, systemd / OpenRC / Windows
  service, opt-in debug capture.
- One `wedge.toml` plus `conf.d/`, validated against a JSON Schema; secrets by
  reference only.

## Downloads

| File | For |
|---|---|
| `wedge-0.1.0-x86_64.msi` | Windows installer (service, PATH, docs) |
| `wedge-0.1.0-x86_64-pc-windows-msvc.zip` | Windows, portable |
| `wedge_0.1.0-1_{amd64,arm64}.deb` | Debian, Ubuntu, Kali |
| `wedge-0.1.0-1.{x86_64,aarch64}.rpm` | Fedora, RHEL and compatible |
| `wedge-0.1.0-{x86_64,aarch64}-unknown-linux-musl.tar.gz` | any Linux (static) |
| `wedge-0.1.0-{x86_64,aarch64}-unknown-linux-gnu.tar.gz` | Linux with glibc 2.17+ |
| `wedge-0.1.0-{aarch64,x86_64}-apple-darwin.tar.gz` | macOS |
| `wedge-0.1.0-oci-{amd64,arm64}.tar` | container image (`docker load -i`) |
| `wedge-0.1.0.cdx.json` | software bill of materials (CycloneDX 1.5) |

Install guides: <https://github.com/alinganpatra20004/wedge/blob/main/docs/install/README.md>.
Every package and archive contains the user guide (Markdown and HTML).

## Verifying

```sh
sha256sum --ignore-missing -c SHA256SUMS
gh attestation verify <file> --repo alinganpatra20004/wedge
cosign verify-blob <file> --bundle <file>.sigstore.json \
  --certificate-identity-regexp 'https://github.com/alinganpatra20004/wedge/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The .deb and .rpm packages are GPG-signed with the key in
`wedge-release.asc` (fingerprint
`B84A 920D B6B5 11E6 46B1 24FD 983E F3CD D108 E023`):
`sudo rpm --import wedge-release.asc && rpm -K <file>.rpm`.

## Known limitations

- The Windows executable and installer are not yet Authenticode-signed
  (signing through SignPath Foundation is pending approval), so Windows shows
  an "unknown publisher" prompt. macOS binaries are not notarized.
- No TLS to upstreams, WebSocket tunnelling or HTTP/2 to upstreams yet.
- Windows and macOS install guides are marked "untested" until run on a
  real machine; the MSI is tested on a GitHub-hosted Windows runner.
- The security assessment of this release (SBOM, image and dynamic scans,
  extended fuzzing) follows; results will be published in
  `docs/security/assessment-report.md`.
