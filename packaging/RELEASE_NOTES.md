<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) Alingan Patra -->
Security update for **wEdge** (`wedge`) 0.1.0, from the security assessment
of the first release ([report](https://github.com/alinganpatra20004/wedge/blob/main/docs/security/assessment-report.md)).
No high or critical issues were found. Upgrading is recommended.

## Security fixes

- **Connection slots held by silent clients (Medium).** A plain-HTTP
  connection that never sent a byte kept its slot until the 60 s idle
  timeout; enough of them made other clients wait up to a minute. New
  connections must now start their request within the header timeout
  (10 s by default).
- **Debug capture log redaction (Medium).** With `[server.debug]
  read_packet` on, credential headers or query strings longer than 8 KiB
  could be written to the capture log unredacted. They are now redacted.
  Capture is off by default.
- **Request validation (Low).** A `Host` header with an out-of-range port,
  and absolute-form targets with `user@`, now get 400; a file requested
  with a trailing slash (`/page.html/`) now gets 404.
- **Log flooding (Low).** TLS clients that send an IP address as the server
  name no longer produce a warning line per connection; such handshakes are
  logged at debug level and counted in `wedge_tls_handshake_failures_total`.
- **Proxy health (Low).** A just-failed upstream could be retried at once
  when two requests raced; fixed.

## Other changes

- The installed configurations set `Content-Security-Policy`,
  `Permissions-Policy` and `Cross-Origin-Resource-Policy` for the bundled
  welcome page. See "Response headers" in the security guide for your own
  site. An edited `wedge.toml` is never overwritten (the .deb/.rpm update
  it only if unchanged; the Windows installer never replaces it), so copy
  the `[vhost.headers]` block from `examples/wedge.toml` if you want it.
- Binaries embed their dependency list (`cargo auditable`), and each release
  includes a CycloneDX SBOM (`wedge-0.1.1.cdx.json`), so `cargo audit bin`
  and `trivy` can check what you run.
- Release workflow actions are pinned to commit SHAs; the MSI, SBOM and
  `SHA256SUMS` now have build provenance attestations.

## Downloads

| File | For |
|---|---|
| `wedge-0.1.1-x86_64.msi` | Windows installer (service, PATH, docs) |
| `wedge-0.1.1-x86_64-pc-windows-msvc.zip` | Windows, portable |
| `wedge_0.1.1-1_{amd64,arm64}.deb` | Debian, Ubuntu, Kali |
| `wedge-0.1.1-1.{x86_64,aarch64}.rpm` | Fedora, RHEL and compatible |
| `wedge-0.1.1-{x86_64,aarch64}-unknown-linux-musl.tar.gz` | any Linux (static) |
| `wedge-0.1.1-{x86_64,aarch64}-unknown-linux-gnu.tar.gz` | Linux with glibc 2.17+ |
| `wedge-0.1.1-{aarch64,x86_64}-apple-darwin.tar.gz` | macOS |
| `wedge-0.1.1-oci-{amd64,arm64}.tar` | container image (`docker load -i`) |
| `wedge-0.1.1.cdx.json` | software bill of materials (CycloneDX 1.5) |

Install guides: <https://github.com/alinganpatra20004/wedge/blob/main/docs/install/README.md>.
Every package and archive contains the user guide (Markdown and HTML).

## Verifying

```sh
sha256sum --ignore-missing -c SHA256SUMS
gh attestation verify <file> --repo alinganpatra20004/wedge
cosign verify-blob <file> --bundle <file>.sigstore.json \
  --certificate-identity-regexp 'https://github.com/alinganpatra20004/wedge/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
cargo audit bin wedge    # inside an unpacked archive
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
- No per-client connection limit: one client can still occupy all
  connection slots for up to the header timeout at a time.
- Windows and macOS install guides are marked "untested" until run on a
  real machine; the MSI is tested on a GitHub-hosted Windows runner.
